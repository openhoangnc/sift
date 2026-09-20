#!/usr/bin/env python3
"""Watch what a running Sift is holding, and say what grew.

Polls `/control/debug/memory` and keeps the first sample.  Each line is a
snapshot; the table at the end is first against last, sorted by how much each
number moved.  The resident size is the symptom, and every other row is a
suspect: a count that climbs with it is where the memory went, and a run where
nothing but the resident size moves is the allocator holding a peak rather than
anything here still holding the memory.

	scripts/memwatch.py -u http://pihome:3180 -p secret -i 5m

Ctrl-C prints the table and stops.  It needs nothing but Python 3.
"""

import argparse
import base64
import json
import signal
import sys
import time
import urllib.error
import urllib.request

# The columns of the running table, as dotted paths into the response.  A path
# that the server does not report -- an older build, or a process outside a
# cgroup -- is left out of the header rather than printed empty.
COLUMNS = [
    ("rss", "process.rss", "bytes"),
    ("anon", "cgroup.anon", "bytes"),
    ("peak", "process.peak_rss", "bytes"),
    ("lists", "filters.list_bytes", "bytes"),
    ("exprs", "filters.compiled_expressions", "count"),
    ("cache", "cache.entries", "count"),
    ("slots", "cache.eviction_slots", "count"),
    ("names", "stats.live_domains", "count"),
    ("clients", "clients.runtime", "count"),
    ("marks", "server.probe_marks", "count"),
]


def flatten(obj, prefix=""):
    """Every numeric leaf of the response, by dotted path."""
    out = {}
    for k, v in obj.items():
        path = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, path + "."))
        elif isinstance(v, bool):
            continue
        elif isinstance(v, (int, float)):
            out[path] = v
    return out


def get(url, auth):
    req = urllib.request.Request(url, headers={"Authorization": "Basic " + auth})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def human(n, kind="bytes"):
    """A number narrow enough for a column."""
    if kind != "bytes":
        return f"{n:,}"

    n = float(n)
    for unit in ("B", "K", "M", "G"):
        if abs(n) < 1024 or unit == "G":
            return f"{n:,.1f}{unit}" if unit != "B" else f"{n:,.0f}B"
        n /= 1024
    return f"{n:.1f}G"


def duration(secs):
    """A span of seconds, as the interval argument spells one."""
    secs = int(secs)
    if secs < 3600:
        return f"{secs // 60}m{secs % 60:02d}s"

    return f"{secs // 3600}h{secs % 3600 // 60:02d}m"


def parse_interval(s):
    """Accepts 300, 300s, 5m or 1h."""
    units = {"s": 1, "m": 60, "h": 3600}
    if s and s[-1] in units:
        return float(s[:-1]) * units[s[-1]]

    return float(s)


def kind_of(key):
    """Whether a path's number is bytes or a count."""
    tail = ("rss", "anon", "file", "bytes", "current", "peak", "max", "slab", "sock")

    return "bytes" if key.endswith(tail) else "count"


def report(first, last, elapsed):
    """First against last: what moved, largest relative change first.

    `uptime` is the window rather than a suspect, so it is the heading and not
    a row.  Everything that did not move is one line at the end: on a watch
    that ran overnight the point is the short list at the top, and a long tail
    of zeroes buries it.
    """
    if first is None or last is None or first is last:
        return

    was_rss, now_rss = first.get("process.rss"), last.get("process.rss")
    moved_rss = ""
    if was_rss and now_rss:
        moved_rss = f", resident {human(was_rss)} -> {human(now_rss)} ({human(now_rss - was_rss)})"

    print(f"\nover {duration(elapsed)}{moved_rss}:\n")

    moved, still = [], []
    for key, was in first.items():
        now = last.get(key)
        if key == "uptime" or now is None:
            continue

        delta = now - was
        if delta == 0:
            still.append(key)
            continue

        # Ranked by relative change, so a count of 40 that trebled is not
        # buried under a byte count that moved by a percent.
        moved.append((abs(delta) / was if was else 1.0, key, was, now, delta))

    if not moved:
        print("  nothing moved.")
    else:
        width = max(len(m[1]) for m in moved)
        for _, key, was, now, delta in sorted(moved, reverse=True):
            kind = kind_of(key)
            pct = f"{delta / was * 100:+.1f}%" if was else "     new"
            print(
                f"  {key:<{width}}  {human(was, kind):>10} -> {human(now, kind):>10}"
                f"  {human(delta, kind):>10}  {pct:>8}"
            )

    if still:
        print(f"\n  unchanged: {', '.join(sorted(still))}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-u", "--url", default="http://127.0.0.1:3000", help="the server's base URL")
    ap.add_argument("-n", "--user", default="admin", help="the web interface user")
    ap.add_argument("-p", "--password", default="test123", help="that user's password")
    ap.add_argument("-i", "--interval", default="5m", help="between samples: 30s, 5m, 1h")
    ap.add_argument("-c", "--count", type=int, default=0, help="samples to take, 0 for no limit")
    ap.add_argument("--once", action="store_true", help="print one snapshot in full and stop")
    args = ap.parse_args()

    auth = base64.b64encode(f"{args.user}:{args.password}".encode()).decode()
    url = args.url.rstrip("/") + "/control/debug/memory"

    try:
        snap = get(url, auth)
    except urllib.error.HTTPError as e:
        # 404 is the useful one: it says the server is older than the endpoint.
        sys.exit(f"{url}: {e.code} {e.reason}")
    except OSError as e:
        sys.exit(f"{url}: {e}")

    if args.once:
        print(json.dumps(snap, indent=2))
        return

    interval = parse_interval(args.interval)
    columns = [(head, path, kind) for head, path, kind in COLUMNS if path in flatten(snap)]

    print(f"{url}, every {duration(interval)}, from an uptime of {duration(snap['uptime'])}\n")
    print(f"  {'time':>8}  " + "  ".join(f"{head:>9}" for head, _, _ in columns))

    first = flatten(snap)
    last = first
    started = snap["uptime"]

    def finish(*_):
        report(first, last, last.get("uptime", started) - started)
        sys.exit(0)

    signal.signal(signal.SIGINT, finish)

    taken = 0
    while True:
        flat = flatten(snap)
        last = flat
        row = "  ".join(
            f"{human(flat[path], kind):>9}" for _, path, kind in columns
        )
        print(f"  {time.strftime('%H:%M:%S'):>8}  {row}", flush=True)

        taken += 1
        if args.count and taken >= args.count:
            break

        time.sleep(interval)
        try:
            snap = get(url, auth)
        except (urllib.error.HTTPError, OSError) as e:
            # A server that is restarting is not a reason to lose the run.
            print(f"  {time.strftime('%H:%M:%S'):>8}  unreachable: {e}", flush=True)
            continue

    finish()


if __name__ == "__main__":
    main()
