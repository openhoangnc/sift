# Configuration

Sift reads and writes `AdGuardHome.yaml` at `schema_version: 34`, the
same file AdGuard Home v0.107.79 uses, with the same keys in the same order.
Anything not covered here behaves as AdGuard Home's
[configuration reference][ref] describes.

[ref]: https://adguard-dns.io/kb/adguard-home/configuration/

## Upstreams

`dns.upstream_dns` holds one upstream per line. The same syntax is accepted in
**Settings → DNS settings → Upstream DNS servers**.

| Form | Meaning |
|---|---|
| `94.140.14.140` | plain DNS over UDP |
| `94.140.14.140:53` | plain DNS over UDP, explicit port |
| `udp://unfiltered.adguard-dns.com` | plain DNS over UDP, by hostname |
| `tcp://94.140.14.140` | plain DNS over TCP |
| `tls://unfiltered.adguard-dns.com` | DNS-over-TLS |
| `https://unfiltered.adguard-dns.com/dns-query` | DNS-over-HTTPS |
| `h3://unfiltered.adguard-dns.com/dns-query` | DNS-over-HTTPS, HTTP/3 only |
| `quic://unfiltered.adguard-dns.com` | DNS-over-QUIC |
| `# a comment` | ignored |

`sdns://` stamps are **not** resolved: DNSCrypt is not implemented. Such an
upstream is reported at startup and skipped rather than silently failing.

How the listed upstreams are used is set by `dns.upstream_mode`:

- `load_balance` (the default) queries one server at a time, weighted towards
  the servers with the fewest failures and the lowest average latency;
- `parallel` queries every server at once and takes the first answer;
- `fastest_addr` waits for every server, measures the TCP connect time to each
  returned address, and answers with the fastest.

`dns.bootstrap_dns` resolves the hostnames of encrypted upstreams, and must be
plain IP addresses. `dns.fallback_dns` is used when the upstreams do not
answer.

### Upstreams for domains

An upstream prefixed with a bracketed domain list applies only to those
domains:

```
[/example.local/]94.140.14.140
```

Several addresses may follow one list, and they are used together according to
the upstream mode:

```
[/example.local/]94.140.14.140 2a10:50c0::1:ff
```

Rules that follow:

- the list matches the domain **and its subdomains**, so `[/example.local/]`
  covers `host.example.local`;
- several domains may share one upstream — `[/a.test/b.test/]1.1.1.1`;
- an empty list, `[//]`, matches **unqualified names only** — names with no
  dot in them, such as `nas` — not every domain;
- `[/example.local/]#` means "use the ordinary upstreams for this domain",
  which is how you carve an exception out of a broader rule;
- the most specific matching list wins.

### upstream_dns_file

`dns.upstream_dns_file` names a file holding the same lines, one per row. Its
contents are **appended** to `dns.upstream_dns` rather than replacing them, so
a script can maintain part of the list without rewriting `AdGuardHome.yaml`.
Blank lines and lines starting with `#` are skipped, and a file that cannot be
read is a warning at startup rather than a failure.

The file is re-read on every reload, and its **contents** — not its name —
decide whether the upstream pools are rebuilt, so rewriting it with the same
lines costs nothing.

## Password reset

Web interface accounts live in `users` in `AdGuardHome.yaml`, each with a
bcrypt hash of its password:

```yaml
users:
  - name: admin
    password: $2y$10$...
```

There is no endpoint that resets a forgotten password — by design, since
anything that could would be reachable by whoever forgot it. Reset it by
editing the file:

1. Stop the server.
2. Generate a bcrypt hash of the new password. Any bcrypt implementation will
   do; `htpasswd` from `apache2-utils` is the usual one:

   ```bash
   htpasswd -B -n -b admin 'your new password'
   ```

   That prints `admin:$2y$05$...`. Take the part after the colon.
3. Put it in `users[].password`, keeping the quotes off and the `$` characters
   intact.
4. Start the server and sign in.

To start over instead, delete the whole `users` list. The server then reports
itself unconfigured and serves the setup wizard again, keeping every other
setting.

Sessions issued before the change stay valid until they expire; delete
`<work>/data/sessions.db` to invalidate them all at once.

## Ports

| Port | Protocol | What listens |
|---|---|---|
| 53 | TCP, UDP | DNS |
| 80 | TCP | web interface |
| 443 | TCP, UDP | web interface over TLS, DNS-over-HTTPS, HTTP/3 |
| 853 | TCP, UDP | DNS-over-TLS, DNS-over-QUIC |
| 3000 | TCP | the setup wizard's alternative port |
| 5443 | TCP, UDP | DNSCrypt in AdGuard Home; unused here |
| 6060 | TCP | pprof in AdGuard Home; unused here |

Changing a listener's **port** needs a restart. The TLS **certificate** does
not: `/control/tls/configure` takes effect on the next handshake.

## When memory climbs

Nothing listens on 6060 here, and `http.pprof` in the config file is kept and
not acted on. What replaces it is `GET /control/debug/memory`, which needs
only a signed-in session and reports, as JSON, what the process is holding:
the resident size and its high-water mark, the container's own `memory.current`
and `memory.stat`, and a count for every structure inside the server — the
cached answers and the bytes they take, the compiled expressions against the
ceiling they are kept under, the names counted in the hour of statistics in
progress, the buffered query-log entries, the discovered clients, and the
per-address tables the rate limiter and the connection probe keep.

```
curl -su admin:<password> http://localhost:3000/control/debug/memory
```

Two snapshots an hour apart are the useful thing: the count that grew between
them is where the memory went. `scripts/memwatch.py` in the source tree takes
them on a timer and prints what moved.

A resident size that climbs for the first hours of an installation's life and
then settles is normal — the filter lists are loaded once, the response cache
fills to `dns.cache_size`, and the hour of statistics is as large as the names
asked for in it. A number that keeps climbing days later is worth reporting,
with the output of that endpoint attached.
