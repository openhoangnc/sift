# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

**Sift** is a Rust backend for AdGuard Home, built as a **drop-in
replacement** for the Go binary of release **v0.107.79**. It reads and writes
the same config file, the same on-disk data, serves the same HTTP API, and
ships in a Docker image with the same runtime contract. The web interface under
`web/client` is this project's own: React, TypeScript and ECharts against the
same control API, with the excluded features left out.

The binary reports its **own** version — `sift_core::VERSION`, from the
workspace version, starting at v0.2.0. `sift_core::AGH_COMPAT_VERSION` records
the AdGuard Home release the formats are matched against; that is what every
compatibility claim in the tree means, not the reported version.

The overriding constraint is **compatibility, not elegance**. Where a format or
a behaviour looks odd, it is almost certainly odd because Go does it that way,
and changing it breaks a real user's installation. Read the comments before
"fixing" anything in a serialiser, a wire format or an API response shape.

## Where things are written down

- **`docs/`** — the documentation the web interface links to: FAQ,
  configuration, clients, encryption, privacy. A behaviour described there is a
  promise; check it against the code before repeating it.
- **`TASK.md`** — what is done, what is not, and the deliberate deviations.
  **Read it before starting work, and update it when work lands**: it is the
  handoff between sessions, and it is only worth anything if it stays true.
- `README.md` — what this is, and what was measured against the Go build.
- `NOTICE.md` — what came from AdGuard, and how to regenerate it.
- This file — how to work in the repository.

## The drop-in contract

What "drop-in" means, concretely. Changing any of these breaks an existing
installation.

| Surface | Contract |
|---|---|
| Config file | `AdGuardHome.yaml`, `schema_version: 34`, field order significant |
| Binary path | `/opt/adguardhome/AdGuardHome` |
| Docker CMD | `--no-check-update -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/work` |
| Work dir | `<work>/data/{querylog.json,querylog.json.1,stats.db,sessions.db,filters/,userfilters/}` |
| Query log | JSON lines, keys `T,QH,QT,QC,CP,IP,Result,Elapsed,Upstream,Answer,…` |
| Statistics | bbolt file, one bucket per hour named by big-endian `u64`, value a gob `unitDB` under key `[0]` |
| HTTP API | upstream's 81 paths under `/control/*`, all routed, plus two of ours |
| Sessions | `<work>/data/sessions.db`, bucket `sessions-2`, 16-byte token key |
| Web interface | single-page app served from the embedded filesystem at `/` |
| Version | **not** part of the contract: this build reports its own, not v0.107.79 |
| Ports | 53 tcp/udp, 67–68 udp, 80, 443 tcp/udp, 853 tcp/udp, 3000, 5443, 6060 |

## Commands

```bash
cargo build --release            # fast to build and to run
cargo build --profile dist       # fat LTO, panic=abort, stripped: ~10.7 MB
cargo test --workspace           # 788 tests, no network or Go build needed
cargo clippy --workspace --all-targets
```

Running one test or one crate:

```bash
cargo test -p sift-filter                          # one crate
cargo test -p sift-filter --lib engine             # one module's tests
cargo test -p sift-filter --test differential      # one integration test file
cargo test -p sift-config reproduces_the_reference -- --exact --nocapture
```

Tests that need outbound network are `#[ignore]`d:

```bash
cargo test -p sift-dns --test live -- --ignored     # real DoT/DoH upstreams
```

Running the server:

```bash
cargo run --release -- --no-check-update -c ./AdGuardHome.yaml -w ./work
```

Rebuilding the web interface — needs Node:

```bash
scripts/build-frontend.sh         # web/client -> web/build, brotli-compressed
```

Packaging a built binary the way a release does, and installing it:

```bash
scripts/package.sh target/dist/AdGuardHome linux arm64 dist
scripts/install.sh -v -b <base-url>     # -b points at an unpublished build
```

Cross-implementation verification — needs `upstream/` and a Go toolchain:

```bash
scripts/verify.sh                 # builds Go, starts both, runs every comparison
```

## Getting the reference implementation

`upstream/` is **gitignored**: it holds a checkout of AdGuard Home itself, used
as the oracle and to build the web interface. `cargo test` does not need it —
every in-repo test runs against committed fixtures. `scripts/verify.sh` and
`scripts/build-frontend.sh` do.

```bash
git clone --branch v0.107.79 https://github.com/AdguardTeam/AdGuardHome.git upstream
```

## How compatibility work is done here

Capture behaviour from a **running** AdGuard Home; do not infer it from its
source. Every divergence found so far was invisible in the source and obvious
the moment two servers were compared:

- patterns without a URL prefix match the bare hostname, not `http://<host>`;
- every filtering pattern is compiled case-insensitively;
- an allowlist match is still the query's recorded verdict;
- `/control/querylog/config` reports its interval in **milliseconds**, while
  the legacy `/control/querylog_info` reports **days**;
- a plain entry in `dns.blocked_hosts` matches that name and *nothing else* —
  not its subdomains — while `||name^` matches the subdomains too;
- a response is shaped to the request before it is sent: no signatures and no
  `AD` for a client that did not ask, and an OPT record only when the request
  carried one, on the request's own terms.

The comparison harnesses live in `tests/compat/`:

- `api_diff.py` — response *shapes* of both servers, live. Each endpoint
  declares the status a GET should produce, so two servers failing the same way
  is a failure, not a match.
- `dns_diff.py` — DNS answers from both servers over A and AAAA.
- `ddr_diff.py` — that `_dns.resolver.arpa` is answered by the server being
  asked rather than forwarded, and that the rest of `resolver.arpa` is not.
- `ratelimit_diff.py` — that both servers limit a burst of datagrams and neither
  limits a connection. The only harness that changes a setting: the limit has to
  be on to be visible, so it sets `ratelimit` through the API and puts the old
  value back, which is why `verify.sh` runs it last of the DNS comparisons.
- `truncate_diff.py` — that an oversized UDP answer is cut to what the client
  advertised, with the truncation bit set, and that a stream transport is not
  cut at all. A property rather than the bytes: each server caches its own copy
  of an upstream's answer and a TXT set arrives in a different order each time,
  so *how many* records fit is not a fact about the server.
- `dnssec_diff.py` — the *shape* of both servers' answers to the same question
  asked five ways: which record types are in each section, the `AD` bit, and
  what the OPT record says. Contents are not compared, because a CDN may
  legitimately answer the two differently — but it cannot make one of them
  volunteer an `RRSIG` nobody asked for.
- `dnsrewrite_diff.py` — `$dnsrewrite` and, the part that needed a running
  server to get right, its exceptions: `@@||host^$dnsrewrite=…` removes
  matching rewrites rather than applying one, an exception with no value (and
  `=NOERROR`, which parses to the same thing) removes rewrites of *any* value,
  and the comparison is by the parsed value rather than the text. It replaces
  the user rules to do that and puts the originals back, so `verify.sh` runs
  it beside `ratelimit_diff.py` after everything that changes nothing.
- `gob-oracle/` — a small Go program that encodes and decodes the statistics
  unit with Go's own `encoding/gob`, so the Rust codec is checked against the
  implementation it must interoperate with.
- `dropin.sh` — the migration itself. It configures a real
  `adguard/adguardhome` container, generates traffic, swaps this image in
  underneath it on the same volume, swaps back, and has the Go build read
  everything this one wrote. It needs Docker and both images, nothing else:

  ```bash
  tests/compat/dropin.sh                          # the published image
  tests/compat/dropin.sh sift:local        # one you just built
  ```

  What it checks is that **nothing on the volume has to change**: the config
  file is untouched, sessions issued by either build are honoured by the
  other, and the statistics and query log continue rather than reset. Run it
  after anything that touches an on-disk format, a file mode, or the image.

Committed fixtures under `tests/fixtures/` were all captured from a real
instance: the reference config, 43 query-log lines (one per distinct entry
shape), a real `stats.db`, gob payloads, and the 179,334-rule AdGuard DNS
filter with the verdict Go gave for 4,190 domains.

## Architecture

Ten crates, layered so nothing depends upwards:

```
sift-core                        Go-compatible primitives: durations, byte sizes,
                                filtering reasons, Go's JSON time format, the
                                weekly schedule
sift-config    -> core           AdGuardHome.yaml, schema 34, a YAML emitter that
                                reproduces Go yaml.v3's output, and the
                                migrations from every older schema
sift-filter    -> core, config   rule parser and matcher, list storage,
                                blocked-services catalogue, safe-search rules
sift-dns       -> core, filter   wire codec, cache, upstreams, listeners, EDNS,
                                DNS64, DDR, client registry, and the resolver
                                that orders every step
sift-querylog  -> core           querylog.json
sift-bolt                        a minimal bbolt reader and writer
sift-gob                         Go `gob` for the statistics unit
sift-stats     -> core, bolt,    collection, aggregation, persistence
                 gob
sift-api       -> all, bolt      the control API, the embedded web interface, the
                                HTTP/3 listener, session storage
sift   -> all            the binary: CLI, wiring, supervision, client
                                discovery, ipset, logging, OS settings, service
                                control
```

`sift-api` and `sift-filter` deliberately hold no HTTP client. Downloading filter
lists is injected by the binary through the `ListFetcher` trait in
`sift-api/src/state.rs`, and pushing config changes into the running server goes
through `Reloader` in the same file. That is why `sift-filter::lists::Manager`
exposes `apply_fetched` rather than a `refresh` that downloads.

### The request path

`sift-dns/src/resolver.rs` is the file to read first. The **order** of its steps
is observable behaviour copied from `internal/dnsforward`:

1. a request without exactly one question gets `FORMERR`;
2. `ANY` is refused with `NOTIMP` when `refuse_any` is set;
3. an access-blocked host is **dropped** on UDP and `REFUSED` on TCP — silence
   on a datagram transport is deliberate, so a spoofed source gains no
   amplification;
4. DDR (`_dns.resolver.arpa`) is answered locally — always, when `handle_ddr`
   is on: forwarding it means the client is handed the *upstream's* designated
   resolvers;
5. rewrites apply *even when protection is off*;
6. filtering, in upstream's order: blocklists, then blocked services, then
   safe search — upstream checks safe browsing and parental control between
   the last two, and this build does neither. An allowlist match sets the
   verdict but still resolves, and short-circuits everything after it;
7. `AAAA` suppression;
8. a private `PTR` is routed to the local resolvers or answered `NXDOMAIN`;
9. cache;
10. upstream — which is where the client subnet, the DNSSEC `DO` bit,
    request coalescing, `bogus_nxdomain` and DNS64 live.

Every one of those paths returns through one closure, `finish`, which calls
`msg::shape_to_request` and, for plain UDP alone, `msg::truncate`: whatever is
about to be sent is cut back to what the client asked for — no DNSSEC records
and no `AD` bit for a request without `DO`, an OPT record only when the request
carried one, and no more bytes than it said it could take. It is deliberately
the last step and deliberately in one place, and it runs *before* the query log
and the statistics observe the outcome, so what is recorded is what the client
was sent — a running Go build's `querylog.json` holds the truncated answer too.
Upstream splits the same work between `processDNSSECAfterResponse` and
dnsproxy's `scrub`.

Truncation is plain UDP's alone: every other transport here carries a length of
its own. The limit is `max(512, what the request advertised)`, upstream's
`dnsSize` — with one deliberate difference for a request that carries no OPT
record at all, which `TASK.md` records under *Deliberate deviations*.

Which settings apply is decided *before* step 1, by `Resolver::effective`: a
persistent client that does not use the global settings overrides the filtering
toggles, its own blocked services and its own safe search.

### Things that look wrong but are not

- **Config field order is the file format.** Upstream warns against reordering,
  and the emitter preserves declaration order. Adding a field in the wrong
  place changes the file a user diffs.
- **`sift-config`'s YAML emitter is hand-written** because Go's yaml.v3 indents
  sequences under their key and prefers single quotes, and no Rust YAML crate
  does both. `reproduces_the_reference_config_byte_for_byte` guards it.
- **`NetworkRule` is 56 bytes and that is load-bearing.** A real list holds
  ~180,000 of them. When the modifiers were stored inline the struct was 296
  bytes and the engine used *more* memory than Go.
  `crates/sift-filter/tests/sizes.rs` fails if the layout regresses.
- **Reserved filter list IDs** match upstream's `rulelist.APIID`: `0` custom
  rules, `-1` the system hosts file, `-2` blocked services. The resolver maps
  these to the reason the web UI expects.
- **Byte-identical `gob` output is not a goal.** Go's own encoder does not
  reproduce its own bytes for the same value, because type-definition order
  depends on how the types were first walked. The bar is that each side decodes
  the other.
- **The binary target is named `AdGuardHome`**, so `module_path!` reports that,
  not the package name. A log filter spelled `sift=info` compiles and
  matches nothing; `crates/sift/src/main.rs` has a test guarding this.
- **The blocked-services schedule is inverted.** A day range says when the
  block is *paused*, not when it applies, so an empty schedule blocks around
  the clock. `sift-core/src/schedule.rs` exposes `blocks_at` for that reason.
- **Blocked services are a separate engine** from the blocklists, so the
  schedule can pause them per request without rebuilding anything.
- **`sift-dns/src/probe.rs` counts silence, not rate.** A source is refused
  only after connecting repeatedly without a single query being answered, and
  one answered query clears its record. Rate is the wrong measure here and
  `ratelimit_diff.py` guards why: a NAT with a hundred clients behind it is
  busy and legitimate, and the last build that limited streams by rate cut
  every one of them off. It runs before the TLS handshake, because the
  handshake is the cost being avoided.
- **A protection pause is a deadline, not a timer.**
  `filtering.protection_disabled_until` holds the moment protection comes
  back, so the pause means the same thing across a restart, and
  `AppState::expire_protection_pause` ends it. That runs on its own
  one-second task in `main.rs` rather than in `maintenance`, which ticks once
  a minute — the shortest pause the interface offers is thirty seconds.
- **`dns.blocked_hosts` holds rules, not names**, and an `@@` exception in it
  *blocks*. Upstream's `isBlockedHost` keeps only "something matched" from its
  engine and throws the match itself away, so an exception rule refuses the
  query like any other. `sift-dns/src/blocked.rs` reproduces that deliberately,
  and its tests record what a running Go build answered for each form.
- **`-s run` is not a control action.** Upstream's own generated unit is
  `ExecStart=/opt/AdGuardHome/AdGuardHome "-s" "run"`, so `main` recognises
  `service::RUN` and starts the server instead of handing it to
  `service::run`. A build that refused it could not take over an existing
  installation at all.
- **The working directory defaults to the binary's directory**, not the
  process's current one — upstream's `initWorkingDir`. The unit `-s install`
  writes passes no `-w`, and an init system runs a service from a directory of
  its own. Reading the current directory instead wrote a fresh default config
  next to wherever systemd happened to start it, which looks exactly like an
  upgrade that lost every setting.
- **`--version` starts with `Sift,` and not `AdGuard Home,`.** It is the only
  thing that tells an installer which of the two binaries is sitting in
  `/opt/AdGuardHome/AdGuardHome`, and the version is explicitly not part of
  the drop-in contract.
- **Patterns are sliced by character, not by byte.** Upstream's `escapePipes`
  takes the first and last bytes, which in Go cannot fail; here the same
  indices split a multi-byte character and abort the process. A real
  subscribed list whose first line carries a UTF-8 byte-order mark was enough
  to do it. `escape_inner_pipes` walks characters, which gives the same answer
  for every input because `|` is ASCII.
- **The config is read before the tokio runtime starts.** Two of the things it
  decides — where the log goes and which user to run as — must be settled while
  the process is still single-threaded, because `setuid` acts on the calling
  thread on Linux.

## Build speed

The workspace is split so `cargo` parallelises across crates. Dependencies are
built at `opt-level = 2` even in debug so they are paid for once; our own crates
stay unoptimised with line-tables-only debug info. An incremental rebuild after
touching one file is roughly 8 seconds. Prefer a hand-written implementation to
a new dependency when the need is narrow — that is why `sift-bolt`, `sift-gob`
and the HTTPS fetch in `crates/sift/src/fetch.rs` exist.

## The web interface

**Two paths are ours, not upstream's.** `GET /control/filtering/catalogue`
serves the known-blocklists catalogue that AdGuard Home bundles in its own
client. Serving it keeps `web/client` free of AdGuard's material, which is what
`NOTICE.md` claims; the interface falls back to the custom-address form if it
ever answers 404. Adding a path is safe for the drop-in contract because the
two builds never serve the same interface.

`GET /control/debug/memory` is the other, and nothing in the web interface asks
for it. It reports the resident size, the high-water mark and the cgroup's own
numbers, then a count for every structure in the process that has ever grown
here — the compiled expressions against their ceiling, the cache's entries
against its eviction slots, the live hour's names apart from the finished
hours', the runtime client table, the per-address tables. Both leaks recorded
in `TASK.md` were found by watching a container and reasoning about which
structure the climb belonged to; this is that evidence, gathered directly.
`scripts/memwatch.py` polls it and prints what moved between the first sample
and the last, so a subsystem that grew is named rather than guessed at. It
reports counts rather than estimated bytes, because only the response cache
knows its own size, and a count standing still while the resident size climbs
is just as much of an answer.

**Two response fields are ours too**: `/control/version.json` carries
`check_failed` and `autoupdate_blocked_by`, so the interface can tell "up to
date" from "nobody answered" from "found one, cannot install it".

**One query parameter is ours too**: `/control/querylog` takes `filter_id`,
which keeps only the entries a rule from that list matched, so the query log's
list filter works across the whole log rather than the page in hand. It is
parsed leniently — a value that is not a number is ignored — so a request
upstream would have answered never becomes a 400.

What that catalogue carries is **half AdGuard's and half ours**, and the split
matters when editing it:

- theirs — the list names, categories, homepages and addresses, imported from
  upstream's generated `filters.ts`;
- ours — `scripts/blocklist-notes.json`: a tag set and a note per list, the
  country each regional one serves, a rule count **measured** by downloading
  each list, and `_add` for lists upstream does not carry.

`scripts/import-blocklists.py --measure` merges them and refuses to write the
blob if a list 404s, comes back empty, has no note, carries a tag outside the
closed vocabulary, or names a country not declared in `_countries`. A
two-letter tag *is* a country: the interface derives its flag from the code
(the two regional-indicator symbols are the flag), so no icon set ships. Four tests in
`sift-filter/src/blocklists.rs` re-check the committed blob, including that
each list's size tag agrees with its measured count — the one claim a reader
cannot verify by eye.

**The sources live in `web/client`**: React 19 and TypeScript, routed with
react-router, charted with ECharts, built by Vite. Those four are the entire
runtime dependency list — there is no state library, no component library, no
CSS framework and no test runner. Nothing of AdGuard's is in it: not their
code, not their design, and not their wording. It is **English only**, which
is a decision rather than an omission — see `TASK.md`.

```
src/api/        types.ts mirrors the control API's shapes; index.ts is one
                function per endpoint; client.ts is the only place fetch is called
src/app/        the shell: routes, sidebar, top bar, and the status/profile
                every page reads
src/components/ the primitives — Card, Field, Check, Modal, Table, toasts — the
                icon set, and the ECharts wrapper
src/lib/        theme, formatting, and the data-loading hooks
src/pages/      one file per route
src/entries/    main.tsx, login.tsx, install.tsx: the three documents
```

There is **no store**. What the whole app needs — the server status, the
profile, the protection toggle — is in `src/app/context.tsx`; everything else
belongs to the page that loaded it, through `useAsync` in `src/lib/hooks.ts`.
A page loads, edits a local draft and saves; it does not synchronise with
anything.

Five things about how it is built and served:

- **Three documents, three builds.** `index.html`, `login.html` and
  `install.html` are built one at a time by `build.mjs`, not as one multi-entry
  build. They must not share a chunk: `sift-api`'s `is_public_page` serves an
  asset without a session only when its basename starts with `login.`, so a
  hoisted vendor chunk is answered **401** to exactly the visitor who needs the
  login form. `ENTRIES` in `vite.config.ts` says so too.
- **The output names are the contract.** Bundles land in `static/` — which is
  what `ui.rs` treats as content-addressed and serves `immutable` — under the
  entry's own name, so `static/login.<hash>.js` and nothing else.
- **Brotli only, no gzip on the wire.** The stored form is `.br`; a client that
  accepts `br` gets those bytes, and anything else is decompressed on the way
  out. Over plain HTTP most browsers still advertise only gzip, so those
  clients pay a decompression — affordable only because of the caching above.
- **Every response carries an `ETag`** — the stored file's SHA-256, per
  *representation*: the compressed and decompressed forms must not share one,
  or a cache hands the wrong bytes to the wrong client.
- **Hash routing, deliberately.** Signed out, the server redirects `/` to the
  login form but answers any other path 401 — so a bookmarked `/settings` under
  a browser router would be a blank 401 rather than a sign-in prompt. The paths
  are the old interface's, and `main.tsx` rewrites a bare `#settings` from an
  older bookmark to `#/settings`.

**Strings are written where they are shown.** There is no catalogue and no
`t()`: a label is a literal in the component that renders it. Two rules keep
that from drifting — say what a setting *does* rather than restating its name,
and do not reach for AdGuard's phrasing, which is theirs.

Working on the frontend:

```bash
cd web/client
npm install
npm run dev        # port 5173, proxying /control to 127.0.0.1:3000
npm run typecheck  # tsc --noEmit; CI-clean, keep it that way
npm run build      # the three builds, into web/build
```

`npm run dev` needs a server to talk to; `SIFT_API=http://host:port npm run dev`
points it somewhere other than the default.

The build is committed under `web/build`, **brotli**-compressed (1.3 MB of
assets to 0.4 MB in the binary), and embedded by `sift-api/src/ui.rs`. Rebuild it with `scripts/build-frontend.sh` after **any**
change under `web/client` — the committed output is what ships, and a source
change nobody built is invisible.

**Responsive down to 375px**, and tested there rather than assumed. Three
things carry most of it:

- `table.stack` turns the query log's five columns into a card per row, and
  `table.rows` turns any other table into labelled lines, each cell naming
  itself from its `data-label`.
- Both fire below **1000px**, not at a phone width. The constraint is the
  *content column*, which the sidebar takes 232px out of whenever it is not a
  drawer — a table that needs 620px is already scrolling sideways in a 900px
  window.
- The sidebar becomes a drawer below 860px, with a backdrop that closes it,
  and `.wide-only` drops a label whose button still reads as an icon.

A page that grows a horizontal scrollbar is a bug, and so is a `.table-wrap`
that scrolls: check `scrollWidth` against `clientWidth` on both.

One trap worth knowing: **`input[type='text']` does not match `<input>`**. An
input with no `type` attribute is a text input, and selecting on the attribute
missed every one of them, leaving half the forms with a field a third of the
width of the one below it. The stylesheet selects by what a control is *not*.

## Housekeeping

`rust-toolchain.toml` pins the compiler; the code needs edition 2024,
let-chains, `Option::is_none_or` and `u64::is_multiple_of`. CI enforces
`cargo fmt --all --check` and a clippy run with `-D warnings`, and both are
clean — keep them that way rather than adding `allow`s.

This is a derivative work of a GPL-3.0 project and redistributes AdGuard's
compiled frontend, their services catalogue and captured fixtures. `NOTICE.md`
records what came from where; update it when adding anything else of theirs.

## Encrypted listeners

DNS-over-TLS, DNS-over-HTTPS, DNS-over-QUIC and HTTP/3 are served. Five things
about how they fit:

- **DoH shares the router with the web interface**, because upstream serves
  both on the HTTPS port. `routes::router(state, secure)` takes whether the
  listener is encrypted; DoH answers over plain HTTP only when
  `http.doh.insecure_enabled` is set, so an operator cannot expose queries by
  accident.
- **DoH goes through `sift_dns::server::Server::handle`**, not straight to the
  resolver, so it gets the same rate limiting, access control, query log and
  statistics as UDP and TCP. Anything added to that path applies to DoH for
  free; anything that bypasses it silently does not.
- **DoQ reuses the same framing.** A query arrives on its own bidirectional
  stream carrying the two-byte length prefix that TCP and DoT use, so only the
  transport differs. `Proto` is exhaustively matched in the query-log mapping,
  so adding a transport there fails the build until it is given a name.
- **HTTP/3 is a fourth listener on the HTTPS port**, over UDP rather than TCP,
  and it hands requests to the same `Router`. `sift-api/src/http3.rs` inserts
  `ConnectInfo` itself, because nothing does it for a hand-driven router.
- **The certificate is reloadable.** The listeners are built around
  `tls::Reloadable`, a `ResolvesServerCert` that reads from a shared slot, so
  `/control/tls/configure` takes effect on the next handshake. Listener *ports*
  still need a restart.

`tests/compat/dns-oracle` is the check that matters: it drives AdGuard's own
dnsproxy client against a listener, with the certificate verified rather than
skipped.

## Three exclusions, all deliberate

DHCP, DNSCrypt, and safe browsing with parental control are decisions, not
gaps. Each refuses clearly where a user would notice, and `TASK.md` records the
reasoning for each.

**DHCP.** The API reports the feature off and refuses every change, so the
interface cannot store settings nothing acts on. Two things follow that are
easy to get wrong:

- **`DhcpConfig` in `sift-config` stays.** The config file must round-trip byte
  for byte, and a user switching back to the Go build keeps their settings.
  Deleting the model breaks the golden test in `sift-config/src/file.rs`.
- **`dhcp_status` must not echo the stored config.** Reporting a stored
  `enabled: true` tells the interface a server is running when none is.

**DNSCrypt.** No listener, and an `sdns://` upstream is reported at startup and
skipped. It is the only protocol left that needs cryptography the tree does not
already carry, and a mistake in it fails silently.

**Safe browsing and parental control.** No hash-prefix lookups, and no
`hashprefix` module: the only thing in the tree that sent anything derived from
a user's query to a third party is gone. `/control/safebrowsing/status` and
`/control/parental/status` answer `enabled: false` whatever the config holds,
and `enable`/`disable` answer 501 — the DHCP shape, for the DHCP reason. Three
things follow:

- **The six config fields stay**, for the reason `DhcpConfig` does; they are
  marked "Kept, not acted on" in `sift-config/src/model.rs`.
- **`Reason::FilteredSafeBrowsing`, `FilteredParental` and their statistics
  counterparts stay too.** They are on-disk formats: a query log and a
  `stats.db` written by the Go build still have to read, and
  `/control/querylog`'s `blocked_safebrowsing` and `blocked_parental` filters
  still select those entries.
- **`clients_update` carries the two per-client toggles across.** They are no
  longer in `ClientJson`, so replacing the stored client wholesale would clear
  a value the operator set under AdGuard Home.

## Replacing the binary

Two things do it, and they are the same steps in two places.

**`scripts/install.sh`**, the `curl | sh` installer, when a machine is being
set up or the operator is at a shell. It finds the directory from the
installed unit rather than assuming `/opt`, takes over an installed AdGuard
Home in place, never rewrites an existing unit file, and puts the old binary
back if the service does not stay up for eight seconds.

**`POST /control/update`**, from the web interface, implemented by
`crates/sift/src/update.rs`. The directories are upstream's — the release is
unpacked into `<work>/agh-update-<version>` and the previous binary and config
land in `<work>/agh-backup` — so a user who has pressed AdGuard Home's button
finds the same files. Two steps are ours, and both exist because the failure
they prevent is a resolver that no longer starts: the archive is checked
against the published `checksums.txt`, and the downloaded binary is run twice
before anything moves, once for its version and once over the real config with
`--check-config`. The binary is replaced by renaming, never by writing over
the running file.

`can_autoupdate` is answered by the binary, not by the announcement: false
inside a container (the image is the unit of update there), false when the
executable's directory is read-only, and false when a restart could not bind
the ports the configuration uses — upstream asks the same question in
`setAllowedToAutoUpdate`. `SelfUpdater::update_blocker` answers it as a
*reason* rather than a bool, and `version.json` carries that reason as
`autoupdate_blocked_by` alongside `check_failed`, both ours: a missing Install
button and a check that never reached GitHub look identical otherwise, and the
interface has to be able to say which it is. `status::pending_update` is the guard on what gets
installed: the version the announcement named, and only when it is **strictly
newer**, because every build from `main` is ahead of the newest release and
inequality alone would offer a downgrade and take it.

`--no-check-update` switches the whole thing off. The Docker `CMD` passes it;
the unit `-s install` writes does **not**, as upstream's does not — writing it
in unconditionally switched the check off for every natively installed server,
and with it the button.

`SIFT_VERSION_URL` and `SIFT_RELEASES_URL` move the announcement and the
archives somewhere else, for a mirror or for testing an unpublished build.
The checksum still has to match, so neither is a way to install other bytes.

## Scope, and keeping it honest

Endpoints for unimplemented features answer **501** rather than pretending to
succeed — keep it that way. A setting that silently does nothing is worse than
one that reports it cannot: blocked services and the hosts file were both
stored, exposed through the API and ignored by the resolver for a while, which
looked like working features from the UI.

When something lands, move it in `TASK.md` and say how it was verified. When
something turns out to be deliberate rather than missing, record it under the
exclusions or the deviations there instead of leaving it to be rediscovered.
