#!/usr/bin/env python3
"""Compare `$dnsrewrite` handling between a Go AdGuardHome and sift.

`$dnsrewrite` is the one modifier whose *exceptions* have semantics of their
own: `@@||host^$dnsrewrite=…` does not rewrite anything, it removes matching
rewrites from the set, and which ones it removes depends on its value and on
whether either rule is `$important`. Reading urlfilter's source is not enough
to get it right — two details only a running server shows are that an
exception with no value removes rewrites of *any* value (so does `=NOERROR`,
which parses to the same thing), and that the comparison is by the parsed
value rather than the text.

For each case this sets the user rules on both servers, asks
`/control/filtering/check_host` and sends a real query, then compares the
verdict, the rules cited and the answer.

Like `ratelimit_diff.py`, this changes a setting to do its work: it replaces
the user rules and puts the originals back when it is done, including on
failure.
"""

import argparse
import base64
import json
import subprocess
import sys
import urllib.error
import urllib.request

# Each case is (name, rules). The comment is what a running v0.107.79
# answered when these were captured.
CASES = [
    # A rewrite with no exception beside it.
    ("baseline", ["||a.example^$dnsrewrite=1.2.3.4"]),
    # An exception with no value removes every rewrite for the host.
    ("exception-empty", ["||a.example^$dnsrewrite=1.2.3.4", "@@||a.example^$dnsrewrite"]),
    # An exception naming the same value removes it.
    ("exception-value", ["||a.example^$dnsrewrite=1.2.3.4", "@@||a.example^$dnsrewrite=1.2.3.4"]),
    # And leaves the rewrites it does not name.
    ("exception-one-of-two", [
        "||a.example^$dnsrewrite=1.2.3.4",
        "||a.example^$dnsrewrite=5.6.7.8",
        "@@||a.example^$dnsrewrite=1.2.3.4",
    ]),
    # An ordinary exception does not touch an $important rewrite.
    ("important-vs-empty", ["||a.example^$dnsrewrite=1.2.3.4,important", "@@||a.example^$dnsrewrite"]),
    ("important-vs-value", ["||a.example^$dnsrewrite=1.2.3.4,important", "@@||a.example^$dnsrewrite=1.2.3.4"]),
    # An $important exception does.
    ("important-exception", ["||a.example^$dnsrewrite=1.2.3.4,important", "@@||a.example^$dnsrewrite,important"]),
    ("important-exception-value", [
        "||a.example^$dnsrewrite=1.2.3.4,important",
        "@@||a.example^$dnsrewrite=1.2.3.4,important",
    ]),
    # An exception is never a rewrite of its own.
    ("exception-alone", ["@@||a.example^$dnsrewrite=1.2.3.4"]),
    # `=NOERROR` is the same value as none at all, so it removes an address.
    ("exception-noerror", ["||a.example^$dnsrewrite=1.2.3.4", "@@||a.example^$dnsrewrite=NOERROR"]),
    # The value is compared parsed, not as text.
    ("exception-long-form", ["||a.example^$dnsrewrite=NOERROR;A;1.2.3.4", "@@||a.example^$dnsrewrite=1.2.3.4"]),
    ("exception-cname", ["||a.example^$dnsrewrite=b.example", "@@||a.example^$dnsrewrite=b.example"]),
    # The exception only has to match the host.
    ("exception-broader", ["||a.example^$dnsrewrite=1.2.3.4", "@@||example^$dnsrewrite"]),
    ("exception-other-host", ["||a.example^$dnsrewrite=1.2.3.4", "@@||other.example^$dnsrewrite"]),
    # A plain allowlist rule is not a rewrite exception.
    ("plain-allowlist", ["||a.example^$dnsrewrite=1.2.3.4", "@@||a.example^"]),
    # A rewrite with no value answers NOERROR and nothing else.
    ("no-value", ["||a.example^$dnsrewrite"]),
    ("empty-value", ["||a.example^$dnsrewrite="]),
    ("noerror-value", ["||a.example^$dnsrewrite=NOERROR"]),
    # And does not suppress an address beside it.
    ("noerror-and-address", ["||a.example^$dnsrewrite=1.2.3.4", "||a.example^$dnsrewrite=NOERROR"]),
    # Other answers.
    ("rcode", ["||a.example^$dnsrewrite=REFUSED"]),
    ("long-form", ["||a.example^$dnsrewrite=NOERROR;A;1.2.3.4"]),
    ("cname", ["||a.example^$dnsrewrite=b.example"]),
    # A rewrite of the host to itself is dropped.
    ("cname-to-itself", ["||a.example^$dnsrewrite=a.example"]),
]

# Cases this build is known to answer differently, with the reason. Reported,
# not failed on: see "Found comparing `$dnsrewrite` against a running build"
# in TASK.md.
KNOWN = {
    "cname": "a CNAME rewrite is not followed here, so the status is NOERROR where Go resolves the target and answers its status",
}

HOST = "a.example"


def api(base, path, auth, data=None):
    req = urllib.request.Request(
        base + path,
        data=json.dumps(data).encode() if data is not None else None,
        headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"},
        method="POST" if data is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        body = r.read().decode()

    return json.loads(body) if body.strip().startswith(("{", "[")) else body


def query(port, name):
    """The status and answer records a real query gets."""
    out = subprocess.run(
        ["dig", "@127.0.0.1", "-p", str(port), name, "A",
         "+noall", "+answer", "+comments", "+timeout=3", "+tries=1"],
        capture_output=True, text=True,
    ).stdout
    status = next(
        (l.split("status: ")[1].split(",")[0] for l in out.splitlines() if "status:" in l),
        "NO-REPLY",
    )
    answers = [" ".join(l.split()[3:]) for l in out.splitlines() if l and not l.startswith(";")]

    return status, answers


def observe(base, port, auth, rules):
    api(base, "/control/filtering/set_rules", auth, {"rules": rules})
    check = api(base, f"/control/filtering/check_host?name={HOST}", auth)
    status, answers = query(port, HOST)

    return {
        "reason": check.get("reason"),
        "rules": sorted(r.get("text", "") for r in (check.get("rules") or [])),
        "status": status,
        "answers": answers,
    }


def user_rules(base, auth):
    return api(base, "/control/filtering/status", auth).get("user_rules") or []


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--go", default="http://127.0.0.1:14080")
    ap.add_argument("--rust", default="http://127.0.0.1:14081")
    ap.add_argument("--go-dns-port", type=int, default=14053)
    ap.add_argument("--rust-dns-port", type=int, default=14054)
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="test123")
    args = ap.parse_args()

    auth = base64.b64encode(f"{args.user}:{args.password}".encode()).decode()
    saved = {}
    failures, known = [], []

    try:
        for base in (args.go, args.rust):
            saved[base] = user_rules(base, auth)

        for name, rules in CASES:
            go = observe(args.go, args.go_dns_port, auth, rules)
            rs = observe(args.rust, args.rust_dns_port, auth, rules)

            if go == rs:
                print(f"  ok        {name}")
                continue

            if name in KNOWN:
                known.append(name)
                print(f"  known     {name}: {KNOWN[name]}")
                continue

            failures.append(name)
            print(f"  MISMATCH  {name}")
            for rule in rules:
                print(f"      rule: {rule}")
            print(f"      go  : {go}")
            print(f"      rust: {rs}")
    finally:
        for base, rules in saved.items():
            try:
                api(base, "/control/filtering/set_rules", auth, {"rules": rules})
            except urllib.error.URLError as e:
                print(f"  WARNING: could not restore user rules on {base}: {e}", file=sys.stderr)

    print(f"\n{len(CASES) - len(failures) - len(known)} of {len(CASES)} cases agree, "
          f"{len(known)} known divergence(s), {len(failures)} failure(s)")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
