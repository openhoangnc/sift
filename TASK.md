# Task tracker

Work status for Sift, against AdGuard Home **v0.107.79**.

Legend: **[x]** done and verified · **[~]** partial, see the note · **[ ]** not started

Verification claims below are reproducible with `scripts/verify.sh` and
`cargo test --workspace` (740 tests).

---

## Summary

| Area | State |
|---|---|
| Config file | done, byte-identical to Go · migrates schema 0–33 |
| Filtering engine | done, every verdict matches Go on the real list |
| DNS (plain UDP/TCP) | done |
| Upstreams | plain UDP/TCP, DoT, DoH, DoH/3, DoQ done · DNSCrypt **out of scope** |
| Query log | done, byte-identical |
| Statistics | done, `stats.db` interoperable both ways |
| HTTP API | all 81 upstream paths routed · 69 implemented, 12 refuse by design · two paths and one parameter added |
| Web interface | rewritten in `web/client`, built to `web/build`, embedded |
| Docker | done, same runtime contract |
| DHCP | **out of scope** — API reports it off and refuses changes |
| Safe browsing / parental control | **out of scope** — API reports them off and refuses changes |
| Encrypted inbound listeners | DoT, DoH, HTTP/3 and DoQ done · DNSCrypt **out of scope** |
| Safe search | done |
| Clients | persistent settings, ClientID, ARP/rDNS/WHOIS/hosts discovery |
| Operations | logging, rotation, pidfile, privileges, service install |
| Installer | `scripts/install.sh`: installs, upgrades, and takes over AdGuard Home |
| Self-update | done — `POST /control/update` replaces the binary and restarts |
| Version reported | this project's own, from the workspace version — v0.10.0 |

---

## Done

### Configuration
- [x] `AdGuardHome.yaml` schema 34: full model, field order preserved
- [x] YAML emitter reproducing Go yaml.v3's style — sequence indentation,
      single-quote preference, `""` for the empty string, `[]`/`{}` inline
- [x] Byte-identical round-trip against a config a real instance wrote
- [x] Byte-identical output after the same API changes applied to both servers
- [x] Atomic save (write to a sibling temp file, then rename, mode 0600)
- [x] Default config written on first run
- [x] A newer schema version is refused rather than misread
- [x] **Migration from every older schema**, a port of `internal/configmigrate`:
      all 34 steps, including the ones that are easy to get backwards — a
      statistics interval of zero becomes *disabled* with a one-day interval,
      and a bare `.` in an ignore list becomes `|.^`. The upgraded file is
      written back, as upstream does

### Filtering engine
- [x] Adblock rule parser: `||domain^`, `|`, `^`, `*`, `@@` exceptions, `/regex/`
- [x] Hosts-file rules, including address-family selection for A/AAAA
- [x] Modifiers: `$important`, `$badfilter`, `$dnstype`, `$client`, `$ctag`,
      `$denyallow`, `$dnsrewrite` and its `@@` exceptions; HTTP-only modifiers
      accepted and ignored
- [x] Pattern → regex translation mirroring urlfilter, including the two
      details that decide real results: bare patterns match the **hostname**
      rather than the pseudo-URL, and every pattern is case-insensitive
- [x] Indexed lookup: domain suffix walk, Aho–Corasick shortcut prefilter,
      scan list for the remainder
- [x] Rule priority matching upstream: whitelist+important, important,
      whitelist, then specifier count
- [x] Separate allowlist engine that short-circuits
- [x] **Verified**: 4,190 domains against the real 179,334-rule AdGuard DNS
      filter — every verdict matches Go; 99.2% also cite the same rule
- [x] Memory layout guarded at 56 bytes per rule (`tests/sizes.rs`)
- [x] Legacy DNS rewrites, including wildcards and the `A`/`AAAA` suppressors
- [x] Blocked services, enforced from the bundled 139-service catalogue
- [x] Blocked-services **schedule**: the weekly pause windows are honoured, in
      the configured time zone, globally and per client
- [x] System hosts file, when `hostsfile_enabled` is set
- [x] Filter list storage in `data/filters/<id>.txt`, download and refresh
- [x] **Safe search**, from AdGuard's own rule files for Bing, DuckDuckGo,
      Ecosia, Google, Pixabay, Yandex and YouTube, global and per client

### DNS
- [x] Plain DNS over UDP and TCP, with TCP connection reuse and idle timeout
- [x] Truncation handling, both directions
- [x] Upstreams: plain UDP, TCP, DNS-over-TLS, DNS-over-HTTPS, DNS-over-QUIC,
      and DNS-over-HTTPS carried by HTTP/3 (`use_http3_upstreams`, falling
      back to HTTP/2 when a server does not speak it, and remembering that it
      had to)
- [x] **Upstream connections are kept**, not built per query: one multiplexed
      HTTP/2 connection per DoH address, one QUIC connection per DoQ and
      HTTP/3 address with a 20 s keep-alive under a 30 s idle timeout, and a
      checkout pool for DoT and TCP. Every reply is checked against the
      question that was asked before its connection is reused, as dnsproxy's
      `validateResponse` does. Measured against Quad9 and AdGuard, p50 per
      query: DoT 157.6 → 47.8 ms, DoH 162.7 → 54.2 ms, DoQ 160.9 → 55.3 ms,
      HTTP/3 162.9 → 53.9 ms, TCP 102.0 → 51.9 ms, with plain UDP flat at
      ~53 ms throughout as the control
- [x] `upstream_dns_file`, read afresh on each reload
- [x] The upstream pools are rebuilt when the settings behind them change, so
      an upstream edited through the interface takes effect without a restart
      — see *Found auditing the DNS settings page* below
- [x] Bootstrap resolution for encrypted upstreams' hostnames
- [x] Upstream specification syntax including `[/domain/]` groups and the `#`
      deferral form
- [x] Upstream modes: load balance (latency-ranked), parallel, fastest address
- [x] Fallback resolvers
- [x] Response cache: sized in bytes, sharded, TTL bounds, keyed on the EDNS
      `DO` bit so a validating client is never served a stripped answer.
      Entries are packed and charged what they occupy — see *The response
      cache, packed*
- [x] **Optimistic caching**: an expired entry still inside
      `cache_optimistic_max_age` is served at once, stamped with
      `cache_optimistic_answer_ttl`, and fetched again out of band. Measured
      answer-for-answer against the Go build — see *Found optimising the
      upstream query path* below
- [x] Blocking modes: default, custom IP, NXDOMAIN, null IP, REFUSED —
      including the negative-caching SOA's exact field values
- [x] Rate limiting per client subnet, with an exemption list — on UDP only, as
      upstream does, because a client that completed a handshake has already
      proved the address it claims
- [x] Access control: allowed and disallowed clients
- [x] Blocked hosts dropped on UDP, REFUSED on TCP
- [x] **EDNS Client Subnet**: the client's address masked to /24 or /56, or a
      configured one; never a loopback or private address, and recorded in the
      query log's `ECS` field
- [x] **DNSSEC**: the `DO` bit is set on upstream queries when `enable_dnssec`
      is on, so a validating client below this server receives signatures — and
      every answer is shaped back to what the client asked for on the way out,
      which is the part that was missing; see *Found debugging a Mac that could
      not resolve Cloudflare* below
- [x] **DNS64** synthesis (RFC 6147): an empty `AAAA` answer is retried as `A`
      and mapped into the NAT64 prefix, with the Well-Known Prefix as default
- [x] **`bogus_nxdomain`**: an answer inside a configured network becomes
      `NXDOMAIN`
- [x] **DDR** (`handle_ddr`): `_dns.resolver.arpa` is answered here, and never
      forwarded — with `SVCB` records for the encrypted listeners that are
      actually running, DoT only when the certificate names an IP address as
      upstream requires, and empty when there is nothing to advertise; see
      *Found comparing answer shapes* below for why the empty case matters
- [x] **Duplicate-request coalescing** (`pending_requests`): identical
      questions in flight share one upstream exchange, keyed by question and
      client subnet
- [x] **`max_goroutines`** as a bound on requests handled at once
- [x] **Private reverse DNS**: a `PTR` for a locally-served address goes to
      `local_ptr_upstreams` — or the resolvers the operating system is
      configured with, when none are named — and is answered `NXDOMAIN` rather
      than forwarded when `use_private_ptr_resolvers` is off
- [x] **`ipset`** and **`ipset_file`**: resolved addresses are added to the
      named sets, with a cache so a repeat costs nothing
- [x] **Verified**: 2,046 names over A and AAAA against Go — no verdict differs

### Encryption
- [x] Certificate and key loading, inline or from a path, with the conflict
      upstream rejects
- [x] Chain verification against the trusted roots, reported as a warning while
      still serving — a self-signed certificate works and says so
- [x] `GET /control/tls/status`, `POST /control/tls/validate`,
      `POST /control/tls/configure`
- [x] **DNS-over-TLS listener**
- [x] **DNS-over-HTTPS listener**, GET and POST, with the ClientID path segment
- [x] **DNS-over-QUIC listener** (RFC 9250), one query per bidirectional
      stream, served concurrently on a shared connection
- [x] **HTTP/3** (`serve_http3`): the web interface and DNS-over-HTTPS over
      QUIC on the HTTPS port, sharing the router with the TCP listener
- [x] HTTPS for the web interface, sharing the port with DoH as upstream does
- [x] DoH refused over plain HTTP unless `insecure_enabled` is set
- [x] **`force_https`**: the plain listener redirects to the HTTPS port,
      leaving `/dns-query` alone because a DoH client follows no redirect
- [x] **Certificate reload without a restart**: the listeners are given a
      resolver rather than a certificate, so one replaced through
      `/control/tls/configure` is served on the next handshake
- [x] **Renewal on disk is picked up**: when the certificate or key is read
      from a path, the files are compared against what is being served on the
      maintenance tick, and a changed pair installed for the next handshake —
      an ACME client rewrites them on its own schedule and nothing in the
      config moves when it does. A pair caught half-written replaces nothing
      and is retried a minute later; a certificate inside a week of expiry
      with nothing renewing it is reported hourly, and an expired one as an
      error
- [x] **Verified**: AdGuard's own dnsproxy client, with full certificate
      verification, resolves through all three listeners; the query log records
      them as `dot`, `doh` and `doq`; `/control/tls/status` matches Go field for
      field with the same certificate loaded
- [x] **Verified**: a running server serving one certificate over HTTPS and
      DoT, its files overwritten underneath it — the certificate alone first,
      which was refused as a mismatched pair while the old one kept being
      served, then the key, after which both listeners handed out the new
      certificate on the next handshake without a restart
- [x] **The encrypted addresses reach `/control/status`**: upstream's
      `getDNSAddresses` appends `https://…/dns-query`, `tls://…` and `quic://…`
      to `dns_addresses` once encryption is on and `tls.server_name` is set,
      and its web interface builds the whole DNS privacy section by filtering
      that field by scheme. This build reported only the plain addresses, so
      every such client was told encryption was unconfigured on a server
      happily serving DoT. The list is derived per request from the settings,
      so a port changed through `/control/tls/configure` is reported before
      the restart that moves the listener
- [x] **The setup guide answers without a server name too**: the listeners run
      whether or not `tls.server_name` is set — they serve whatever the
      certificate covers — so the guide falls back to the certificate's first
      DNS name and says where the name came from, rather than claiming
      encryption is unconfigured. It spells out any port that is not the
      scheme's own, and offers Apple's DNS-over-TLS profile only for a
      listener left on 853, which is the only one that profile can describe
- [x] **A ClientID and an HTTPS port in the setup guide**, beside the host
      name: they rewrite the three encrypted addresses and the Android Private
      DNS line, and ride into the Apple profiles through `client_id=` and
      `port=` on `/control/apple/{doh,dot}.mobileconfig` — the ClientID as a
      path segment under DNS-over-HTTPS and as a label below the server name
      under DNS-over-TLS, which is how each listener reads one back, and the
      port only into the HTTPS profile, since Apple's `ServerName` carries a
      host and no port at all. The endpoint applies the
      listeners' own `is_valid_client_id`, so a profile cannot carry an
      identifier the server would ignore, and the guide says which of the two
      forms the settings can actually deliver: the SNI label only registers
      below `tls.server_name`, and only with a certificate covering it.
      Verified against a running build — a profile's own DoH URL and DoT
      server name each arrived in the query log as `kids-tablet`

### Clients
- [x] Persistent clients matched by address, subnet, MAC or ClientID, most
      specific first
- [x] Per-client settings actually applied: filtering, safe search, blocked
      services and their schedule, and exclusion from the query log or the
      statistics
- [x] **ClientID** from the DoH path segment and from the name a DoT or DoQ
      client asks for — only the label directly below the server's own name, so
      an unrelated name cannot claim an identifier
- [x] **Discovery**: the system hosts file, the ARP table (`/proc/net/arp` or
      `arp -an`), reverse DNS through this server's own resolver, and WHOIS for
      addresses outside the local networks
- [x] `/control/clients` reports discovered clients as `auto_clients`, and the
      query log carries the name in `client_info`
- [x] **`trusted_proxies`**: `X-Forwarded-For` is honoured only from a listed
      proxy, so a client cannot claim another's address — and with it another
      client's settings

### Storage
- [x] `querylog.json`: exact JSON shape, in-memory buffer, reverse chunked
      reads for the API
- [x] Query log rotation on `querylog.interval`, decided from the first
      record in the file as upstream's `checkAndRotate` does
- [x] **Verified**: 43 real log lines re-encode byte for byte
- [x] Query log search by name, address, client name and ClientID, and the
      `older_than` cursor
- [x] Statistics: hourly units, upstream's result categories and quirks
- [x] One live hour held in full, finished hours held in the top-N form
      they are stored in, as `internal/stats` holds them
- [x] `sift-bolt`: bbolt reader and writer
- [x] `sift-gob`: Go `gob` for the statistics unit
- [x] **Session persistence** in `sessions.db`, in the layout the Go build
      uses, so a restart does not sign everyone out and either build reads the
      other's file
- [x] **Verified**: Go reads a `stats.db` this writes and reports the same
      counts; this reads a `stats.db` Go wrote

### HTTP API and interface
- [x] All 81 upstream paths routed
- [x] **One path added**: `GET /control/filtering/catalogue`, the 66 vetted
      blocklists the picker offers — the 64 AdGuard bundles in its client,
      and two of ours. Serving it rather than bundling it keeps
      `web/client` free of AdGuard's material — see *Deliberate deviations*
- [x] **A second path added**: `GET /control/debug/memory`, what the process
      is holding and where — the resident size and the cgroup's own numbers
      beside a count for every structure that has ever grown here. Nothing in
      the web interface asks for it; it is for watching a container, which is
      how both of the leaks below were found. `scripts/memwatch.py` polls it
      and prints what moved
- [x] **One parameter added**: `filter_id` on `GET /control/querylog`, keeping
      only the entries a rule from that list matched, so the query log's list
      filter works across the whole log rather than the page in hand. Parsed
      leniently, so a value that is not a number is ignored rather than
      answered 400
- [x] **A wildcard listen address is reported as the addresses it answers
      on.** `bind_hosts: [0.0.0.0]` is the default, and `/control/status`
      reported it verbatim, so the setup guide's "This server answers on" card
      offered `0.0.0.0:53` — the one thing on that page nobody can type into a
      router. Expanded per entry and to its own family, loopback and
      link-local left out, and kept whole if the interfaces cannot be read so
      the card is never empty. Upstream's `getDNSAddrs` does the same from
      `aghnet.CollectAllIfacesAddrs`
- [x] **The update state is always visible.** "Up to date", a check that never
      reached GitHub, and a release found but not installable all rendered as
      nothing at all, which from the operator's seat is a server that cannot
      update itself. The profile menu now says which of the three it is and
      offers **Check for updates**; `version.json` carries `check_failed` and
      `autoupdate_blocked_by` to say so, both ours
- [x] **The query log says which list matched, and filters by it.** The
      details modal names the list under each matched rule, and a second
      dropdown beside the verdict one narrows the log to a single list —
      custom rules, any subscribed blocklist or allowlist, blocked services or
      the hosts file. Reserved identifiers are named from `rulelist.APIID`;
      anything else falls back to `List <id>`, so a rule from a list that has
      since been removed still reads
- [x] **Protection can be paused for a set time**, and the pause actually
      ends: 30 seconds, a minute, ten minutes, an hour, or until tomorrow.
      Stored as a deadline in `filtering.protection_disabled_until`, so it
      survives a restart; a one-second task turns protection back on when it
      passes
- [x] **Every catalogue list validated**: all 66 downloaded and counted, all
      answered 200 with rules in them, from 15 rules (Dandelion Sprout's Game
      Console list) to 2,567,728 (HaGeZi's Threat Intelligence Feeds, 50 MB).
      `scripts/import-blocklists.py --measure` is the check, and it refuses to
      write the catalogue when one fails
- [x] **Tagged and annotated**: a tag set and a written note per list, both
      this project's, so the picker answers "which one do I want?" rather than
      listing 66 names. The size tag is derived from the measured count, so it
      cannot drift; the interface filters by tag
- [x] **The nine tags that carry a decision are coloured** — `starter` green,
      `malware`/`phishing`/`scam`/`crypto-mining` red, `strict`/`huge` amber,
      `security`/`bypass` blue — and sort ahead of the grey ones. Colour is
      meaning and the ring is selection, on one `--tone` pair, so a selected
      red chip stays red rather than becoming the accent
- [x] **Country tags**, drawn as flags: 15 countries across 19 regional lists,
      in their own row of chips. The flag is derived from the ISO code rather
      than shipped — the two regional-indicator symbols that spell `vn` *are*
      the Vietnamese flag — so no icon set is carried
- [x] **hostsVN added**, the Vietnamese list upstream's registry does not
      carry. `_add` in the notes file is the mechanism, and such a list is
      validated and measured on the same terms as an imported one
- [x] **kboghdady's YouTube Ads Blocklist added**, through the same `_add`.
      15,869 ad-serving hostnames, tagged `strict`: ads and videos come from
      the same `googlevideo.com` names, so the list is the trade a TV owner
      makes rather than a safe default
- [x] Sessions: `agh_session` cookie, HTTP Basic
- [x] Login rate limiting, on the form *and* on the Basic credentials
      every endpoint accepts: `auth_attempts` failures from an address
      within a minute start a `block_auth_min` block, answered 429 with
      `Retry-After`
- [x] The gate covers the pages as well as `/control`, so a signed-out
      browser is redirected to `/login.html` rather than handed a
      dashboard it cannot load
- [x] Setup wizard reachable before a user exists
- [x] **Verified**: response shapes match Go for all 25 endpoints the UI loads
- [x] Web interface written in `web/client` — React 19, TypeScript,
      react-router 7 and ECharts 6, built by Vite; four runtime dependencies,
      no store and no CSS framework. Twelve routes, the login form and the
      setup wizard. See *The web interface, rewritten*
- [x] Built to `web/build` and embedded brotli-compressed, served with content
      negotiation, immutable caching for hashed assets and `304` revalidation
      for the rest
- [x] Version check: `/control/version.json` fetches this project's latest
      GitHub release, caches it for eight hours, honours `--no-check-update`,
      and reports `can_autoupdate` truthfully — see *Replacing its own binary*
- [x] The update banner offers **Install** where the server says it would
      work, and waits for the restarted server before reloading the page

### Packaging and operations
- [x] CLI accepting every flag the Go binary documents
- [x] Docker image with upstream's runtime contract, verified against a config
      and data directory a Go instance produced
- [x] **Published image**: `.github/workflows/docker.yml` builds `linux/amd64`
      and `linux/arm64` on native runners, pushes each by digest, and joins
      them into one multi-architecture tag on `ghcr.io/openhoangnc/sift`.
      A prune step keeps the newest three releases and their per-architecture
      children — resolved from each kept index rather than counted, because
      deleting a child breaks `docker pull` for that architecture. Attestations
      are off (`provenance: false`) so every manifest in the package is either
      an index or a child of one. Verified on the first two runs: tagging
      `v0.107.79` on the commit `main` had just built moved every tag onto the
      new index, and the prune correctly reaped the old index and its two
      children.
- **A `sha-` tag names a commit, not a set of bytes.** `BUILD_DATE` is a build
      argument, so rebuilding the same commit produces a different digest; the
      new index takes the tags and the old one is then pruned as untagged. Pin
      a digest, not a tag, if the bytes have to be identical across a redeploy.
- [x] **CI is `workflow_dispatch` only.** Formatting, lints, the test suite and
      the differential against a cloned AdGuard Home all run locally with
      `cargo test --workspace` and `scripts/verify.sh`, so paying for them on
      every push buys nothing. Run `ci.yml` from the Actions tab before cutting
      a release tag.
- [x] Graceful shutdown persisting the query log, statistics and sessions
- [x] **`--logfile`** and the `log` block: a file, with rotation on
      `max_size`, `max_backups`, `max_age` and `compress`, or `syslog` over the
      local socket
- [x] **`--pidfile`**, written at start and removed at exit
- [x] **Privilege dropping**: `os.group`, `os.user` and `os.rlimit_nofile`,
      applied before the runtime starts so every thread is covered
- [x] **`-s install|uninstall|start|stop|restart|reload|status`**: a systemd
      unit on Linux, a launchd property list on macOS, naming this binary and
      the paths this invocation used
- [x] **`-s run`**: what an init system passes to run the server in the
      foreground. Upstream's own generated unit is
      `ExecStart=/opt/AdGuardHome/AdGuardHome "-s" "run"`, so a build that
      refused it could not be dropped into an existing installation at all —
      systemd would restart it for ever. Found by reading a real installed
      unit, not the flag list
- [x] **The working directory defaults to the binary's own directory**, as
      upstream's `initWorkingDir` does, rather than to the process's current
      one. The unit `-s install` writes passes no `-w`, and an init system
      runs a service from a directory of its own — the one on the machine this
      was tested against sets `WorkingDirectory=/home/hoang`. Taking the
      current directory instead read a
      config file nobody had put there and wrote a fresh default beside it,
      which from the outside looks exactly like an upgrade that lost every
      setting
- [x] **`--version` names this build**: `Sift, version v0.6.0 (drop-in for
      AdGuard Home v0.107.79)`. Upstream prints `AdGuard Home, version
      v0.107.79`; the first word differs on purpose, because an installer
      looking at a binary both projects call `AdGuardHome` has this line and
      nothing else to tell them apart
- [x] **Release archives**: `.github/workflows/release.yml` builds
      `linux_amd64`, `linux_arm64`, `linux_armv7`, `darwin_amd64` and
      `darwin_arm64` on a tag push and attaches them to the release with a
      `checksums.txt` and a `version.txt`. Every Linux build is statically
      linked against musl, so one archive per architecture runs on any
      distribution however old its glibc. `scripts/package.sh` builds the
      archive, in CI and by hand alike, in AdGuard Home's own layout —
      `AdGuardHome/AdGuardHome` — so unpacking one with `tar -C /opt` lands
      the binary where their installer would have put it
- [x] **`scripts/install.sh`**, the `curl | sh` installer, modelled on
      upstream's and differing in the three places where being a drop-in
      changes the right thing to do:
      - an existing installation is **upgraded**, not refused. Upstream's
        script demands `-r` and then deletes the directory; this one replaces
        the binary and touches nothing else
      - an existing **AdGuard Home is taken over in place**, since both builds
        read and write the same files under the same names. The Go binary is
        kept as `AdGuardHome.bak` and the rollback is printed
      - the installed version is compared against the release on offer, so
        running it twice does nothing the second time
      It also finds the directory from the installed unit rather than assuming
      `/opt`, verifies the archive against `checksums.txt`, and runs the
      downloaded binary once before the running server is touched — an
      archive for the wrong architecture fails then rather than after the swap.
      An existing unit file is never rewritten: it is the operator's, and both
      builds take the same arguments

---

### Replacing its own binary

**Done.** `POST /control/update` downloads the release
`/control/version.json` last reported, checks it, puts it in place of the
running binary and restarts into it. `crates/sift/src/update.rs` is the
implementation; `crates/sift-api` holds no HTTP client and no knowledge of
where the binary lives, so the work is injected through `SelfUpdater` the way
`ListFetcher` and `Reloader` already were.

The directories are upstream's, because the files it leaves behind are ones a
user may already have: `<work>/agh-update-<version>` for the download, removed
afterwards, and `<work>/agh-backup` holding the binary it replaced and a copy
of `AdGuardHome.yaml`.

Two steps are ours, and both exist because the failure they prevent is a
resolver that no longer starts:

- the archive is checked against the `checksums.txt` published beside it;
- the unpacked binary is **run twice** before anything moves — once for its
  version, and once over the real configuration with `--check-config`.

The binary is replaced by renaming, never by writing over the running file: an
executable cannot be written to while it is running, and a half-written one is
worse than an old one. If the second rename fails the first is undone.

**The path to restart into is captured at startup**, not asked for afterwards.
On Linux `current_exe` reads `/proc/self/exe`, which names the *inode* that is
running — and the update has just moved that inode into `agh-backup`. Asking
after the swap therefore answers the backup's path, and starting it puts the
old binary straight back: the version on disk changes, the process keeps its
id, systemd counts no restart, and `/control/status` still reports the old
version. It was found by watching exactly that happen. Upstream keeps the path
for the same reason; see AdGuard Home issue 4735.

Verified in a systemd container: `can_autoupdate` is **false** inside Docker
and the endpoint refuses with 400; with the container marker removed it
answers 200, and the server comes back on the new version under the **same
process id with no restart counted** — which is what an `execve` in place
looks like — with the previous binary and an identical copy of the config in
`agh-backup` and the update directory gone.

`can_autoupdate` is answered by the binary rather than by the announcement,
and is **false**:

- inside a container — the image is the unit of update there, and a binary
  replaced inside a running one is discarded by the next `docker run`;
- when the executable's directory cannot be written to, which is checked by
  writing to it rather than by reading mode bits;
- when the configuration binds a port below 1024 and the process is not root.
  Upstream asks the same question in `setAllowedToAutoUpdate`, for the same
  reason: an update that leaves the resolver unable to bind 53 is worse than
  no update.

**Only a strictly newer release is installed.** `status::pending_update` is
the guard, and it is the reason `is_newer` exists: the announcement is the
newest *published* release, so every build from `main` is ahead of it, and
comparing for inequality would offer a downgrade and take it. The endpoint
takes no version from its caller at all.

- `GET`/`POST /control/version.json` fetches
  `https://api.github.com/repos/openhoangnc/sift/releases/latest`,
  caches the answer for eight hours, and re-fetches on `recheck_now`.
- `--no-check-update` reports the feature as `disabled`, nothing is fetched,
  and the update endpoint refuses. The Docker `CMD` passes it, because there
  the image is what gets updated. The unit `-s install` writes **does not**,
  as upstream's does not: writing it in unconditionally switched the check off
  for every natively installed server, and with it the button, which has
  nothing to offer without a check.
- `SIFT_VERSION_URL` and `SIFT_RELEASES_URL` move the announcement and the
  archives, for a private mirror or for testing a build that is not published
  yet. Neither is a way to install other bytes: the checksum still has to
  match.

`parse_version` accepts **two** documents: GitHub's, which names the version
`tag_name` and the page `html_url`, and the flat `version`/`announcement_url`
shape AdGuard's own announcement server serves — so pointing the checker at a
hand-written `version.json` keeps working. A repository with no release yet
answers 404, the fetch fails, and the handler reports the running version as
`new_version`, which the interface reads as "nothing newer".

**Why not AdGuard's announcement server any more.** It was the source while
this build reported `v0.107.79`. Now that it reports its own version, that
server would announce an AdGuard Home release as an update to Sift —
permanently, and naming something this binary could not become.

---

## Deliberate exclusions

Not missing work: decisions, with reasons. Each is refused clearly rather than
accepted and quietly ignored.

### DHCP

**This build will not serve DHCP.** Run DHCP on your router or a dedicated
service.

- `GET /control/dhcp/status` always reports `enabled: false` with empty ranges
  and no leases, whatever the config file holds. Echoing a stored
  `enabled: true` would tell the interface a server is running when nothing
  serves leases.
- `GET /control/dhcp/interfaces` returns `{}`.
- Every endpoint that would change DHCP settings answers **501** with a message
  saying so: `set_config`, `find_active_dhcp`, `add_static_lease`,
  `remove_static_lease`, `update_static_lease`, `reset`, `reset_leases`.
- The `dhcp:` section of `AdGuardHome.yaml` is still **read and written
  unchanged**. It has to be, for the file to round-trip byte for byte, and it
  means someone switching back to the Go build keeps their settings. Do not
  delete the model.

501 is what upstream's own API documents for a build without DHCP support, so
the web interface already knows how to present it.

### DNSCrypt

**This build serves no DNSCrypt listener and uses no `sdns://` upstream.**
Unlike DHCP, nothing about the API changes: `port_dnscrypt` and
`dnscrypt_config_file` round-trip through the config file untouched,
`/control/tls/status` reports them as stored, and no endpoint refuses anything.
The port is simply never bound, and a `sdns://` upstream is reported at startup
and skipped.

Why it was excluded rather than scheduled:

- It is the only remaining protocol that needs cryptography this project does
  not already have. DoT, DoH and DoQ came almost free once rustls and quinn
  were in the tree; DNSCrypt needs X25519 key exchange, Ed25519 signing and
  either XSalsa20-Poly1305 or XChaCha20-Poly1305, none of them present.
- On top of the primitives it needs a signed-certificate protocol served over
  DNS — client magic, resolver magic, padding rules — and a
  `dnscrypt_config_file` matching AdGuard's own format, including provider key
  material. Their Go library is roughly 4,400 lines.
- A mistake in key handling or nonce reuse is a silent security failure, not a
  visible bug, and this project has no way to test for one the way it tests
  everything else — by comparing against a running Go build.
- The protocols it would sit alongside all work, so a deployment that needs
  DNSCrypt can front sift with `dnscrypt-proxy`.

Note that DNSCrypt is **not** a dead protocol: AdGuard's own provider list at
<https://adguard-dns.io/kb/general/dns-providers/> still publishes DNSCrypt
addresses and `sdns://` stamps for AdGuard DNS, Quad9, OpenDNS, CleanBrowsing
and others. The exclusion is about the cost and risk of implementing it here,
not about nobody using it. If that trade changes, this is a session on its own,
with the Go implementation as an oracle throughout.

### Safe browsing and parental control

**This build makes no hash-prefix lookups.** Both were implemented, verified
against the reference vectors and against a running family resolver, and have
now been removed along with `sift-dns/src/hashprefix.rs`. Block malware,
phishing or adult content with a filter list instead; the catalogue under
**Filters** carries lists for each.

Why they went rather than stayed:

- They were the only thing in the tree that sent anything derived from a user's
  query to a third party. The hostname itself never left — that is the point of
  the protocol — but a two-byte prefix of each parent label's SHA-256 went to
  AdGuard for every name that reached that step, which made a resolver that
  otherwise talks only to the upstreams its operator chose depend on somebody
  else's policy for every unblocked query.
- Both sat on the hot path. A bucket the cache did not hold cost a round trip
  to `family.adguard-dns.com` **before** the query could be answered, and that
  resolver is neither this project's to run nor its to test against.
- What they blocked is data this project does not control and cannot pin. Two
  of the three defects ever found in the module were AdGuard's set changing
  under a test, not a bug in the code.
- The same verdicts are available locally, from lists the operator subscribes
  to and can see the contents of.

What the removal deliberately did **not** touch:

- `GET /control/safebrowsing/status` and `/control/parental/status` stay
  routed and answer `enabled: false` whatever the config file holds, for the
  same reason `dhcp_status` does not echo its stored section. `enable` and
  `disable` answer **501** with a message saying what to use instead.
- The six config fields — `safebrowsing_enabled`, `parental_enabled`, the two
  block hosts and the two cache sizes — are still read and written unchanged,
  and so is each persistent client's pair. `POST /control/clients/update`
  carries a client's two toggles across rather than clearing them, because the
  API no longer carries the fields and the replacement would otherwise drop
  what an AdGuard Home operator had set. Someone switching back keeps
  everything.
- `Reason::FilteredSafeBrowsing`, `Reason::FilteredParental` and their
  statistics counterparts stay. They are on-disk formats: a `querylog.json` and
  a `stats.db` written by the Go build still have to read, the query log still
  labels such an entry, and `/control/querylog`'s `blocked_safebrowsing` and
  `blocked_parental` filters still select them.

The dashboard lost two of its four series with them, and the statistics
response kept all four fields — the shape is upstream's, and the counters can
still be non-zero for hours the Go build recorded.

## Found by running the image, and fixed

The first end-to-end pass over the published container — the setup wizard in a
browser, then every API surface and the DNS path — turned up nine defects that
no unit test covered. Each now has one. They are recorded here because the
shape of the mistakes is worth keeping, not because the work is outstanding.

- **Nobody could log in.** `POST /control/login` answered 401 to correct
  credentials. The auth gate's allowlist was spelled in full paths
  (`/control/login`), but `Router::nest` strips the prefix before middleware
  layered on the inner router sees it, so the comparison never matched and the
  only unauthenticated route was closed. The wizard hid it: `needs_install()`
  opens everything, so a fresh instance worked right up until it had a user.
  `sift-api/tests/gate.rs` drives the assembled router, which is the only place
  the seam exists.

- **The first launch opened on a dashboard.** Upstream's `postInstallHandler`
  redirects everything outside `/install.` and `/assets/` to `install.html`
  until a user exists; its `preInstallHandler` then answers 403 for the wizard
  once one does. Neither existed here, so a new install showed an empty
  dashboard, and a configured server still served a wizard that could be run
  over it again. The wizard's own endpoints now 404 once configured, as
  upstream's do by never being registered.

- **`+00:00` where Go writes `Z`.** Go's `Z07:00` prints `Z` whenever the
  *offset* is zero; `format_zoned` also required the zone to be
  `TimeZone::UTC` by identity. The container resolves its zone by name, so
  every timestamp the image produced diverged — including the `T` field of
  `querylog.json`, which is supposed to be byte-identical. The golden fixtures
  were captured at `+07:00` and never exercised it. Checked against the Go
  toolchain: `Etc/UTC` and a wintertime `Europe/London` both render `Z`.

- **A partial request body was a 422.** `PUT /control/safesearch/settings`
  rejected a body missing any flag, where Go's `encoding/json` leaves an
  omitted field at its zero value and answers 200. Every API request type now
  carries `#[serde(default)]` for the same reason.

- **A blocked client was cut off rather than refused.** Upstream drops only on
  UDP and DNSCrypt, where a spoofed source would make the answer
  amplification; every connected transport gets `REFUSED`. Returning nothing
  on TCP, DoT, DoH and DoQ closed the connection instead, which `dig +tcp`
  reports as `communications error: end of file`. The blocked-*host* path had
  this right; the blocked-*client* path, which runs earlier in
  `server::Server::handle`, did not.

- **Filter lists refreshed on uptime, not staleness.** The maintenance loop
  fired when the minute counter hit a multiple of the interval, so a fresh
  install had no rules for 24 hours, and a server restarted more often than
  the interval never refreshed at all — the counter reset every boot.
  Upstream refreshes a list when *its own* `last_updated` plus the interval
  has passed, which `Manager::stale_ids` now does; `last_updated` comes from
  the file on disk, so it survives a restart.

- **The wizard had no addresses to show.** `/control/install/get_addresses`
  returned `"interfaces": {}`, so the setup wizard listed no address to point
  a router at and both "Listen interface" dropdowns were empty. The interface
  list is real now (`sift-api/src/netiface.rs`); the wizard reads `name`,
  `ip_addresses` and `flags`, and greys out anything whose flags lack `up`.

- **`dhcp_available` was `true`.** Upstream sets it from whether it actually
  built a DHCP server. The interface gates its entire DHCP section on the
  field, so answering `true` sent it to `/control/dhcp/status` and rendered a
  settings page whose every save answers 501 — the exact failure the DHCP
  exclusion exists to avoid.

## Found by swapping a real Go deployment, and fixed

A second pass replaced a *configured* `adguard/adguardhome:v0.107.79`
container with this image on the same volumes, then swapped back, then had the
Go build read everything this one had written. The contract held — the image's
entrypoint, command, working directory, user, volumes, exposed ports,
environment, healthcheck and stop signal are identical, the config file came
through byte for byte, and neither build signs anyone out. Two things did not
hold.

- **The data directory was world-readable.** Upstream creates directories
  `0o700` and files `0o600` (`aghos.DefaultPermDir`, `aghos.DefaultPermFile`);
  this created `work/data`, `work/data/filters` and `querylog.json` at `0o755`
  and `0o644`. The query log records every name every client on the network
  looked up, so on a shared host — or in a volume mounted into a second
  container — that is a disclosure the Go build does not make. The modes now
  come from `sift_core::perms`, which the config writer, the query log, the
  filter cache and `Paths::ensure` all share.

- **The setup wizard suggested the wrong admin port.** `web_port` in
  `/control/install/get_addresses` is a suggestion for the *finished* install,
  not the port the wizard is being served on: upstream answers 80 while
  listening on 3000, and honours `ADGUARD_HOME_DEFAULT_WEB_PORT` when a
  deployment sets it. Echoing the live port instead quietly put every fresh
  install's admin interface on 3000. `dns_port` is likewise upstream's
  constant 53, not the configured port.

`ADGUARD_HOME_TEST_UPDATE_VERSION_URL` is the only other environment variable
upstream reads, and it is disabled for release builds, so it does nothing in
the image a user runs. Nothing to implement.

## Found on a real deployment, and fixed

A 37-list installation on an Orange Pi 5 — 2,272,040 rules — appeared not to
start: the log stopped after `loaded statistics` and nothing followed. It was
not stuck. It was compiling regular expressions.

**Expressions were built at load, not on first use.** Every rule that is not
`||domain^` needs one, and that installation had 156,557 of them. Building all
of those automata up front cost **22 seconds of parsing and most of a
gigabyte**, for expressions that a query only ever reaches once the domain
index or the Aho-Corasick scan has already named that rule a candidate —
a handful per query, and the overwhelming majority never at all.

`Pattern::Rx` now holds a `LazyRegex`: the source, and a `OnceLock` filled the
first time something matches against it. The `/regex/` form is still compiled
at load, because a user writes that one by hand and a typo in it should be
refused there rather than silently never matching.

Measured on that deployment's own filter files, same machine, same data:

| | before | after | Go v0.107.79 |
|---|---:|---:|---:|
| Time to answer DNS | 55 s | **6 s** | 4 s |
| Memory after loading | 4,196 MB | **532 MB** | 363 MB |

Two guards, both confirmed to fail against the eager code:
`an_expression_is_not_built_until_something_needs_it` asserts the automaton is
absent until a match needs it, and
`rules_needing_an_expression_load_as_cheaply_as_plain_ones` loads 60,000
expression rules and fails over three seconds — it took 9.4 eagerly.

**Why no test caught it.** Every fixture is the AdGuard DNS filter, which is
almost entirely `||domain^`; those take the fast path and never compile
anything. The cost only appears with the lists people actually stack up —
HaGeZi, OISD, 1Hosts — which carry wildcards and modifiers. The differential
fixture proves *verdicts*, and said nothing about what loading them costs.

**The README was wrong about memory.** Its "2.2× less than Go" was one list;
at 37 the ratio inverts to 1.5× more. Both figures are now stated with the
list count they were measured at.

`loading filter lists` is also logged before the work starts, not only after:
several seconds of silence between "starting" and "serving" is what made this
look like a hang in the first place.

## The filtering engine's shape, and why

At two million rules the engine's structure is the whole story, so the choices
are recorded here rather than rediscovered. All of it was measured on a real
37-list installation — 2,272,040 rules — with
`cargo run --release -p sift-filter --example loadprofile <dir>`.

**Expressions are built on first use.** Every rule that is not `||domain^`
needs one; 156,557 did. Building them all at load cost 22 seconds and most of
a gigabyte, for expressions a query only reaches once an index has already
named that rule a candidate. The `/regex/` form is still compiled at load,
because a user writes that by hand and a typo should be refused there.

**Rule text lives in the list, not the rule.** Nothing that decides whether a
rule matches reads the text — only a rule that has matched does. So it is off
the struct the hot loop walks, and it is not copied at all: the manager holds
every list to rebuild from, and rules point into those bytes through an
`Arc<str>`. `TextRef` is eight bytes, carrying its own source index, because a
range table plus `partition_point` cost 100 ns on every blocked query.

**The domain index keeps no keys** (`domidx.rs`). As a
`HashMap<Box<str>, Refs>` it was 148 MB for 1,122,077 domains. It is two
parallel arrays now — a 64-bit hash and a 32-bit value, 12 bytes a slot, 31 MB
— and a probe is confirmed by recovering the key from the matched rule's own
text. That verification costs ~85 ns on a blocked query and is not negotiable:
a hash collision would block a domain the user never blocked, and nobody could
diagnose it. Size it from the domains, not the pairs — 1,984,815 pairs name
1,122,077 domains, and sizing for the pairs left the table a third full at
twice the memory.

**The shortcut index is not an Aho-Corasick automaton** (`shortcut.rs`), which
is the textbook answer and was the wrong one. The automaton was 37.6 MB plus
an 11.2 MB map, walked one state transition per byte with each dependent on
the last, so a hostname's length bought a chain of cache misses through a
structure far larger than any cache. What makes it the wrong tool is that this
haystack is tiny and the patterns are long: 156,070 distinct shortcuts of mean
length 19.5, only 375 shorter than eight bytes. Each is filed under whichever
eight-byte window of itself is rarest across the set — a domain-like string's
rare windows are the ones real names rarely contain — and a query hashes its
own windows, which are independent and so overlap in the memory system. 7.4 MB.

**Both shortcut tables are gated by a bitset**, and this is not optional. The
tables are megabytes, so every probe is a miss; the gates are 8 KB and 256 KB
and stay in cache. Without the short gate, 375 patterns cost 437 ns of a 531 ns
clean lookup — the work is per position, not per pattern. Without the long
gate, a long hostname cost 838 ns against 364 with it.

**What did not improve.** A short clean hostname still costs ~530 ns, much as
it did under Aho-Corasick; the shortcut phase dominates it and neither
structure fixed that. It is the obvious place for the next person to look.

## Found signing in from a second hostname, and fixed

An instance reachable both at `http://<ip>:3180` and at an HTTPS hostname
signed in fine on the first and answered the second with the *browser's* own
Basic sign-in dialog, every time. The hostname was not the cause — a different
origin is simply a different cookie jar, so it was the only one ever seen
signed out. Two defects met there.

- **The gate solicited Basic credentials.** `require_auth` answered 401 with
  `WWW-Authenticate: Basic realm="AdGuard Home"`. Upstream's
  `authMiddlewareDefault` writes a bare 401 and no such header, and the reason
  is the browser: presented with it, Chrome answers the interface's own
  background `fetch` with a native dialog of its own, which becomes the only
  prompt the user ever sees. `/login.html` never renders, and cancelling the
  dialog leaves nothing. Basic credentials are still *accepted* — that is what
  the scripted API users send — they are no longer *asked for*.

- **The web interface was not behind the gate at all.** The middleware was
  layered on the `/control` router only, so `GET /` served the dashboard shell
  to anyone. That is survivable in upstream's design and not in this one:
  upstream wraps its whole mux and redirects `/` and `/index.html` to
  `login.html` for a signed-out visitor, which is *the* route to the login
  form. The shipped interface sends itself there only when an API call answers
  **403**, and the gate answers 401 — so a dashboard
  handed to a signed-out browser is a dashboard that can never load. `serve_ui`
  now applies upstream's `handlePublicAccess`: `/assets/*`, `/login.*` and
  `/forgot_password.*` are served, `/` and `/index.html` redirect to the form,
  anything else is 401, and a visitor who *is* signed in is bounced off
  `/login.html` back to `/`.

**Verified** against a running build: signed out, `/` is `302 login.html`,
`/control/status` is a 401 carrying no `www-authenticate`, and the form and the
`login.<hash>.js`, `login.<hash>.css` and `/assets/*` it is built from all
serve; signed in, `/` is 200 and `/login.html` is `302 /`; Basic credentials
still open `/control/status`. A browser pointed at the root renders AdGuard's
login form with no native dialog and no console errors. Three tests in
`sift-api/tests/gate.rs` cover it, including the absence of the header.

## Found reading the code after that, and fixed

Two defects in the sign-in path, neither of which any test covered.

- **The login throttle was dead code.** `LoginLimiter` was written, exported
  and unit-tested, and nothing ever constructed it — so the admin password
  could be guessed at line rate, over the form or over the Basic credentials
  every other endpoint accepts. It lives on `AppState` now and both paths
  consult it, which matters: throttling only `/control/login` would have left
  an attacker free to guess against `GET /control/status` instead, where a 200
  says the same thing a 302 does. The cookie path is deliberately *not*
  throttled, as upstream's is not — a session token is sixteen random bytes,
  so nobody is guessing one, and throttling it would let a stale cookie lock
  an address out.

  The limiter's arithmetic is upstream's `authRateLimiter`, including the part
  that reads like a bug: until the count is spent every failure keeps the
  *first* one's one-minute deadline, so a trickle of guesses lapses instead of
  accumulating, and only the failure that reaches the threshold installs the
  full block. It keys on the connection's own peer address with the port
  dropped — never a forwarded-for header, which anyone could set to spend
  someone else's attempts or dodge their own block
  ([upstream #2799](https://github.com/AdguardTeam/AdGuardHome/issues/2799)) —
  and `auth_attempts: 0` or `block_auth_min: 0` switches it off with a warning
  at startup, as upstream's `emptyRateLimiter` does.

- **A failed login answered 401 where upstream answers 403.** Upstream's
  `handleLogin` hands `newCookie`'s error to `writeErrorWithIP` with
  `StatusForbidden`. Nothing in the interface reads the difference — the login
  page does not redirect itself from either — but it is a status on the
  drop-in surface, and it was wrong.

**Verified** against a running build: five wrong passwords answer 403 and the
sixth answers `429` with `Retry-After: 899` (900 seconds truncated, as Go's
`int(left.Seconds())` truncates); the block then refuses the *correct*
password and correct Basic credentials from that address; five wrong Basic
credentials block the login form for the same address; a request carrying no
credentials is not an attempt, so `/`, `/login.html` and an unauthenticated
`/control/status` behave normally throughout; and `auth_attempts: 0` logs
`login rate limiting is disabled` and never blocks. Four tests in
`sift-api/tests/gate.rs` and five in `sift-api/src/auth.rs` cover it; the two
throttle tests were confirmed to fail against an unlimited build, and the
clearing test against a build that never calls `record_success`.

## Found auditing the DNS settings page, and fixed

A report that **Access settings → Allowed clients** did nothing turned out to
be two defects, and looking for others on the same page turned up a third that
was larger than either.

- **The access lists understood only bare addresses.** `allowed_clients` and
  `disallowed_clients` were parsed with `filter_map(|s| s.parse::<IpAddr>())`,
  so every CIDR and every ClientID was silently dropped — and the reported
  allowlist was `mi12t`, `hoangnc-chrome`, `172.17.0.0/16`, `192.168.99.2/31`,
  which is *entirely* CIDRs and ClientIDs. It parsed to nothing, and an empty
  allowlist admits everybody: the operator had asked for a closed server and
  had an open one. The interface says the field takes "CIDRs, IP addresses, or
  ClientIDs" and upstream's `processAccessClients` accepts all three.

  `Access` now keeps the three apart, as upstream's `accessManager` does,
  because the two modes combine them differently and the asymmetry is
  load-bearing: in **allowlist** mode a client is refused only when *both* the
  address check and the ClientID check refuse it, so a listed ClientID gets in
  from an unlisted address and a listed address gets in over plain UDP with no
  ClientID at all; in **blocklist** mode either one refusing is enough. That is
  `IsBlockedClient`, and the check now reaches `Server::handle_as`, where the
  ClientID a DoH path segment or a DoT server name carries already sat unused.

- **`/control/access/set` stored what it could not parse.** Upstream refuses an
  entry that is not an address, a network or a ClientID, and refuses duplicates
  within a list and any entry appearing in both lists. This accepted anything,
  wrote it to the config file, and dropped it when the lists were built — the
  silent no-op the page above warns about. It also refused a request that set
  *both* lists, which upstream allows (the disallowed list is ignored while the
  allowed one is non-empty, exactly as the interface tells the user), and it
  mutated the in-memory config *before* validating, so a rejected request left
  the running server holding settings that were never saved.

- **Most of the page needed a restart.** `Reloader::reload` covered the
  resolver settings, rewrites, clients, safe search and the certificate, and
  nothing else — so a saved change to the upstream servers, the upstream mode,
  the fallback or bootstrap servers, the upstream timeout, the private reverse
  resolvers, the rate limit, either rate-limiting subnet prefix, the
  rate-limiting allowlist, the cache size or optimistic caching was written to
  the file and ignored until the process restarted. Upstream applies all of it
  live, through `dnsforward.Server.Reconfigure`. Measured before the fix:
  pointing every upstream at `127.0.0.1:1` and clearing the cache still
  resolved through the old resolver, and `ratelimit: 0` still answered only 20
  of a 100-query burst.

  `Limiter` and `Cache` hold their configuration behind a lock now and take a
  `set_config`; the pools are rebuilt through `SharedPool::store`. Rebuilding a
  pool resolves each upstream's host through the bootstrap resolvers, so it
  cannot run inside the synchronous `reload` — it is spawned, and queries keep
  going to the old upstreams until the new ones are ready rather than failing
  in between. Two guards come with that: a generation counter, so two saves in
  quick succession cannot leave the slower rebuild's pool installed, and a
  fingerprint of everything the pools are built from, so toggling protection
  does not reconnect every upstream. `upstream_dns_file` is fingerprinted by
  its *contents*, because it exists for a script to change the upstreams
  without touching `AdGuardHome.yaml`.

**Verified** against a running build, for each: an allowlist of the reported
shape drops a query from an unlisted address on UDP and answers `REFUSED` on
TCP, while an address inside a listed CIDR resolves; with the allowlist holding
one ClientID and no address at all, `/dns-query/mi12t` answers and both
`/dns-query` and `/dns-query/someone-else` are refused; a bad entry, a
duplicate and an intersecting entry each answer 400 with upstream's message,
and both lists together answer 200. Live, with no restart: the upstreams swap
to a dead address (SERVFAIL) and back (NOERROR); the rate limit answers 20, 100
and 5 of a 100-query burst at limits of 20, off and 5; switching the cache off
stops a repeated name being served from cache, and switching it back on
resumes; and a protection toggle plus a filter-rule save log no upstream
reload at all, where an upstream change logs one.

**"Disallowed domains" was a list of rules pretending to be a list of names.**
The same card's other field matched an entry against the host and its
subdomains, and ignored the wildcard (`*.example.org`) and rule
(`||example.org^`) forms the interface documents. Upstream's `newAccessCtx`
lowercases every entry, hands the whole list to `urlfilter.NewDNSEngine`, and
asks it whether anything matched — so all three forms are just rule syntaxes,
and the query *type* takes part in the match.

The fix is to do the same: `sift_dns::blocked::BlockedHosts` compiles the list
with `sift_filter`'s engine, the one the filter lists already use, so
`$dnstype`, hosts-file syntax and the rest come along rather than being
special-cased. One conversion is needed first, and it is the whole reason the
old behaviour looked defensible: upstream's parser tries `rules.NewHostRule`
before anything else, so a line holding a bare host name becomes a *host* rule
and is matched by **equality**. Entries that are bare names are emitted as
`0.0.0.0 <name>` for that reason; everything else is passed through as written.

What a Go build actually does, measured rather than inferred — and the old
matcher was wrong in both directions:

| entry | matches | does **not** match |
|---|---|---|
| `exact.example.org` | `exact.example.org`, any query type | `sub.exact.example.org`, `notexact.example.org`, `exact.example.org.evil.net` |
| `*.wild.example.org` | `a.wild.example.org`, `b.a.wild.example.org`, `a.wild.example.org.evil.net` | `wild.example.org`, `notwild.example.org` |
| `||rule.example.org^` | `rule.example.org`, `x.sub.rule.example.org` | `arule.example.org`, `rule.example.org.evil.net` |

Three findings there are worth keeping, because none is guessable:

- **A plain entry does not cover subdomains.** The old comment said it did,
  "as upstream's rule engine does for bare domain rules". It does not, and the
  shipped defaults are plain names, so `sub.version.bind` was being refused
  where the Go build answers it.
- **A wildcard is an unanchored pattern, not a suffix.** `*.wild.example.org`
  is the substring `.wild.example.org` appearing anywhere, which is why it
  covers `a.wild.example.org.evil.net` and does *not* cover
  `wild.example.org` itself.
- **An `@@` exception in this field blocks rather than permits.**
  `isBlockedHost` throws the match away and keeps only the "something matched"
  flag (`_, ok = ...MatchRequest(...)`), so `@@||allow.example.org^` listed
  here refuses `allow.example.org`. Confirmed on the Go build.

Plus two smaller ones: an underscore makes an entry a *pattern* rather than a
name, because upstream's host parser rejects it — so `_test.example.org`
listed plainly also refuses `sub._test.example.org` — and
`||typed.example.org^$dnstype=AAAA` refuses AAAA while answering A and TXT,
which is why the matcher takes a query type at all.

**Verified** by building `upstream/` v0.107.79 with Go 1.27 and running it
beside this one on high ports with an identical config, then comparing the
verdict for **70 cases** — every row of the table above plus the underscore,
hosts-file, exception and `$dnstype` forms, each over A and AAAA, plus TXT,
HTTPS and NS for a plain entry, and uppercase questions throughout. A blocked
host answers REFUSED on a connected transport, so every query went over TCP
where the verdict is visible. **0 mismatches.** Re-running the same comparison
before the fix showed 12 on the first sixteen cases alone. The list also
applies without a restart: a `||live.example.org^` added through
`/control/access/set` refuses the name and its subdomains on the next query,
and a name dropped from the list is answered again. Twelve tests in
`sift-dns/src/blocked.rs` carry the measured cases, each noted with what the Go
build did.

## Found optimising the upstream query path, and fixed

`cache_optimistic` was carried from the config file into the cache and then
ignored. That is the failure mode CLAUDE.md warns about: a setting the
interface offers, the config file records, and nothing acts on.

- **An expired entry was recognised and then thrown away.** `Cache::get`
  returned `Freshness::Stale` for an entry inside `cache_optimistic_max_age`,
  and the resolver acted only on `Freshness::Fresh` — so the stale answer was
  cloned, had its TTLs decremented, and was dropped on the floor on the way
  upstream. `Freshness::Stale` was constructed in one place and read in none.
  Switching optimistic caching on bought nothing but the memory to hold expired
  entries for twelve hours, and a wasted clone per lookup.

  The entry is served immediately now, and fetched again behind the client.
  Measured against a running AdGuard Home v0.107.79 whose upstream answered a
  different address every time, so each answer says which exchange produced it,
  with a record TTL of 2s and `cache_optimistic_answer_ttl: 7s`:

  | | Go v0.107.79 | this build |
  |---|---|---|
  | t=0.0 first, a miss | `10.0.0.2` ttl 2 | `10.0.0.2` ttl 2 |
  | t=1.0 inside the TTL | `10.0.0.2` ttl 1 | `10.0.0.2` ttl 1 |
  | t=4.0 expired | `10.0.0.2` **ttl 7** | `10.0.0.2` **ttl 7** |
  | t=5.0 just after | `10.0.0.3` ttl 1 | `10.0.0.3` ttl 1 |
  | t=6.0 | `10.0.0.3` ttl 7 | `10.0.0.3` ttl 7 |
  | t=12.0 | `10.0.0.4` ttl 7 | `10.0.0.4` ttl 7 |
  | upstream exchanges for the name | 4 | 4 |
  | query log lines | 6 | 6 |

- **`cache_optimistic_answer_ttl` had no readers at all.** It defaulted to 30s
  in `sift-config` and nothing outside that crate ever looked at it. The run
  above is what settled its meaning: the configured TTL is *stamped* on an
  optimistically served answer rather than counted down from what the entry had
  left — which would hand the client a number that had already run out. The
  value used was a deliberately non-default 7s, so a build that hardcoded the
  30s default would have shown it. It now reaches `CacheConfig`, and applies on
  reload with the rest of the cache settings.

  `tests/compat/dns_diff.py` could not have caught this: it unpacks a record
  with `">HHIH"` and binds the TTL field to `_`.

- **The shard's eviction order leaked, without bound.** `Shard::order` was
  drained only by `evict_to_fit`, which runs only while a shard is over its
  budget. The expiry path in `get` removed the entry from `map` and decremented
  `bytes` without touching `order` — so on a cache comfortably inside its
  budget, which is the normal case, `order` grew by a slot for every
  expired-then-looked-up key and nothing ever collected them. Serving stale
  entries makes it far worse, because an expired entry now survives to be
  looked up again and again.

  Worse, a key stored again after expiring was pushed a second time, and the
  dead slot sorted ahead of the live one: the next eviction threw away the
  entry that had just been stored and kept an older one, which is exactly
  backwards. Slots carry the sequence number of the entry they were pushed for
  now, so a dead one is recognised and skipped, and a shard compacts its order
  once the dead slots outnumber the live entries — one pass, and it cannot run
  again until the shard has grown again.

---

## Found watching a container's memory, and fixed

A deployment reported 269 MB at start and 371 MB eighteen hours later, dropping
back to 269 MB on restart. All of it was statistics, and the restart is the
clue: what a restart loads is the *capped* form of each hour, and that is all
upstream ever holds.

- **Every hour in the window kept every name it had seen.** `Stats::units` was
  a `BTreeMap<u32, Unit>`, and a `Unit` holds `AHashMap<String, u64>` for
  queried domains, blocked domains, clients and the two upstream counters, with
  no cap. Only the way to `stats.db` capped anything: `to_db` takes the top 100
  of each. So the process grew with the number of distinct names asked for
  across the whole retention window — a day by default — while `stats.db` and
  everything a restart read back held 100 per hour.

  `internal/stats` keeps **one** live unit and reads the rest back from the
  database; `loadUnits` serialises the current one for every request, so even
  the live hour is reported capped. Finished hours are now compacted to the
  form they are stored in, which is both what upstream reports and what a
  restart here already produced.

- **Every save and every `/control/stats` call copied the lot.** `data()`
  cloned every unit — maps and all — before merging, and `snapshot()`, which
  the maintenance tick calls every 60 seconds, ran `to_pairs` over every
  unit, and `to_pairs` cloned every key in the map to sort them and then threw
  all but 100 away. Both costs grew with uptime, and neither is memory the
  process gets back: the allocator holds the high-water mark.

  `data()` now merges the stored form, taking the finished hours by `Arc`
  without copying them at all, and `to_pairs` copies only the names that
  survive the cut, selecting them with `select_nth_unstable_by` rather than
  sorting the hour.

Measured on one machine, same binary either side, against the same load: 100k
distinct names per round through a stub upstream, one list of 180,049 rules,
`statistics.interval: 1d`.

| | before | after |
|---|---:|---:|
| RSS, idle with the list loaded | 43 MB | 43 MB |
| RSS after 500k distinct names in one hour | 170 MB | 127 MB |
| RSS after three `/control/stats` calls on that | **266 MB** | **127 MB** |
| One `/control/stats` call | 0.31 s | **0.04 s** |
| RSS with statistics switched off, 500k names | 59 MB | 59 MB |

That last row is the attribution: with `statistics.enabled: false` the same
half-million distinct names leave RSS flat, so the cache, the query log, the
client registry and the connection pools were not what grew.

The hour boundary is what a short run cannot show, so the restart stands in for
it: 600k distinct names live is 130 MB, and the same statistics after a restart
— the same counts, the same top lists, read back from `stats.db` — is 45 MB.
That compaction now happens every hour rather than only when the process dies.
`a_finished_hour_holds_only_what_is_stored` guards it, and
`an_hour_that_goes_quiet_is_compacted_by_the_sweep` covers the resolver that
stops being asked before the hour turns.

**What this changes in the response.** The top lists for a multi-hour window
are now merged from each hour's top 100 rather than from complete maps, so a
name that is 101st in every hour no longer sums its way into the list. That is
what upstream reports, and what this build already reported for any hour it had
restarted through; it is now the same before and after a restart.

**Left alone.** The live hour still holds every name, because upstream's does
and it is bounded by an hour of traffic — around 6 MB at the rate the reporting
deployment grew. `store::save` still rewrites the whole database every 60
seconds where upstream writes a unit when it rotates; that is I/O, not memory,
and it is a durability choice worth keeping.

---

## Found counting writes against the Go build, and fixed

A deployment on flash storage asked what this writes and why. The way to
answer it was to run `adguard/adguardhome:v0.107.79` and this build under the
same load — 20 queries a second for six minutes through a stub upstream, the
same config either side — and record every time a file in `data/` changed.

| in six minutes, 7,200 queries | Go v0.107.79 | this build, before | after |
|---|---:|---:|---:|
| `stats.db` writes | **0** | 6 | **0** |
| `querylog.json` writes | 7 | 13 | **7** |
| bytes per query-log write | 268 KB | 268 KB and 50 KB alternating | 263 KB |

The Go build wrote `stats.db` exactly once in an hour of watching, at
`13:00:00` — `internal/stats` writes a unit when it rotates and when it shuts
down, and at no other time. It never flushed the query log on a timer: the
writes landed 50.2 s apart, which at 20 q/s is the 1,000-entry `size_memory`
buffer filling, and a four-minute run at 2 q/s — not enough to fill it —
produced no write at all.

- **`stats.db` was rewritten every 60 seconds, whole.** The maintenance tick
  called `save` unconditionally, and `sift-bolt` writes a database by writing
  all of it. At the default day-long window that is 1,440 rewrites of a
  311 KB file — **448 MB a day** — and the file grows with the window: 2.1 MB
  at seven days, 8.9 MB at thirty, 26.6 MB at ninety, where the same tick
  comes to **38 GB a day**. `Stats::claim_save` now reports the changes the
  file does not hold — an hour rotating, units falling out of the window, a
  reset — and the tick writes only for those. What it costs is upstream's
  cost: an unclean kill loses the hour in progress. A signal does not, because
  the shutdown path saves; that was checked by stopping the server and reading
  the counts back.

- **The query log was flushed on the same tick.** Its buffer already flushes
  when it fills, which is what upstream does and all upstream does, so the
  tick only added a second, partial write between the full ones — the 50 KB
  entries in the table above. Removed.

- **Every refresh rewrote every list, unchanged or not.** `apply_fetched`
  wrote the file and reported success whatever came back, so the caller
  counted it as an update, wrote the configuration and **rebuilt the whole
  engine**. On the 37-list installation that is a daily rewrite of every list
  and a rebuild of 2,272,040 rules for nothing. Upstream downloads to a
  temporary file, compares a checksum with the one it holds, and on a match
  discards the download and calls `os.Chtimes` on the real file instead
  (`update` in `internal/filtering/filter.go`); `refreshFiltersIntl` returns
  early without `EnableFilters` when no list changed. `apply_fetched` now
  returns `Fetched::Unchanged` and touches the file's timestamps, and both
  callers rebuild and save only when something actually differed.

## Found while counting those writes: the query log never rotated

`QueryLog::rotate` was implemented and tested and **called by nothing**, so
`querylog.interval` — 90 days by default — was carried from the config file,
reported by the API and acted on by no one. `querylog.json` grew for as long
as the server ran.

Upstream's `checkAndRotate` decides from the **first record in the file**: it
reads the first 512 bytes, takes the `T` field out of them, and renames the
file over `querylog.json.1` once that moment plus the interval has passed. It
checks when it starts and then hourly, whatever the interval is. That detail
is the whole of it — a file being appended to was modified moments ago, so a
build that rotated on the modification time would never rotate at all, which
is what the first attempt to observe this did.

`rotate_if_due` reads the first record the same way, and `maintenance` calls it
at startup and every hour after. Verified end to end: an interval of a minute
and a first entry three hours old rotated on startup, the API kept reading the
entries out of `querylog.json.1`, and a recent first entry left it alone.

**Left alone, deliberately.** `sift-bolt` writes a whole database where bbolt
writes the pages that changed, so an hour's rotation costs 311 KB against
upstream's ~13 KB. At 24 writes a day that is 7.5 MB against 312 KB, and an
incremental bbolt writer is a great deal of machinery for the difference.
Sessions are already written only when one is created, removed or swept, and
the configuration only when something changes it.

---

## Found watching the same container again, and fixed

Holding one hour of statistics instead of the whole window was a real leak and
not that deployment's. It kept growing: 380 MB eighteen hours after the fixed
image started, against a 269 MB baseline, and `memory.stat` said `anon`, so
none of it was page cache. The box turned out to answer **950 queries an hour**
across **147 distinct names** and **19 client addresses all told** — far too
little traffic for statistics, clients, connections or descriptors to be it.
Twenty-two open descriptors, nine threads, no filter refresh in eighteen hours.

**The expression cache had no ceiling.** `Pattern::Rx` holds a `LazyRegex`
whose `OnceLock` is filled the first time something matches against it, and
never emptied again. That solved what building 156,557 automata at load cost —
22 seconds and most of a gigabyte — by arriving at the same place slowly
instead: every name the network asks for that reaches a new candidate rule adds
an expression that is then held for the life of the process.

Reproduced with that installation's own 36 lists, 2,285,525 rules, in the
published image, asking for real names in batches of twenty thousand:

| distinct names asked for | unbounded | bounded |
|---|---:|---:|
| none (lists loaded) | 269.7 MB | 272.8 MB |
| 20,000 | 347.4 MB | 347.9 MB |
| 40,000 | 410.7 MB | 353.7 MB |
| 60,000 | 475.2 MB | 357.1 MB |
| 80,000 | 537.7 MB | 358.1 MB |
| 120,000 | — | 363.2 MB |

The same load with `filtering_enabled: false` moved it 20 MB and then stopped,
which is what said it was the engine and not the response cache, the query log
or the statistics.

An expression costs about 25 KB. It is the compiled program, not the lazy
DFA's cache — `dfa_size_limit` at 4 KB moved 24.4 KB to 21.7 KB and nothing
else did anything — so the only thing that bounds it is holding fewer of them.
`MAX_COMPILED` is 2,000, the oldest is dropped to make room, and an expression
that has matched since it was last considered gets a second chance first:
building one costs 105 microseconds, and the point is not to pay that again for
the one name the network asks for constantly. Dropping one costs nothing but
building it again, which `only_so_many_expressions_are_kept_built` checks along
with the verdict being the same either way.

## Watching the third climb: the snapshot, rather than the guess

Both leaks above were found the same way: watch a container, form a hypothesis
about which structure the climb belonged to, and add a print statement to test
it. That worked twice and cost a day each time, and the second one was only
narrowed down by switching features off one at a time on a live resolver.

`GET /control/debug/memory` reports the evidence directly. Ours, gated with
the rest of `/control`, and nothing in the web interface asks for it.

- **What the kernel says**: resident size, `VmHWM`, resident anonymous and
  file-backed memory, threads, descriptors and the number of mapped regions.
  The high-water mark is the one worth having beside the resident size: the two
  rising together is something still being held, and a gap between them is the
  allocator keeping a peak it has not given back.
- **What the container says**: the cgroup's `memory.current`, its peak and its
  limit, and `anon`, `file`, `slab` and `sock` out of `memory.stat`. That first
  number is what `docker stats` shows, which is what an operator is looking at
  when they ask the question. `anon` against `file` is the answer to "is it
  page cache" without shelling into the container, which the second
  investigation above had to do by hand.
- **What each structure holds**: a count per subsystem, listed below.

**Counts, not estimated bytes.** Only the response cache knows its own size.
Everything else reports how many of something it is holding, which is honest
and enough: a count that climbs with the resident size is where the memory
went, and a count that stands still while the resident size climbs says just
as much — that was the shape of the expression-cache leak, where the
statistics and the cache were flat the whole way up.

**No allocation-site profiler, deliberately.** That would mean a custom global
allocator or a call to `mallinfo2`, and the tree carries no unsafe code and no
`libc`; `unsafe_code = "deny"` is a workspace lint, and everything the kernel
exposes is a file read. If an allocation-site breakdown is ever genuinely
needed, the honest way is a `jemalloc` feature that is off in the shipping
build, not unsafe in the tree — and the numbers here should be exhausted
first, because both leaks so far were a structure anybody could count.

**If the counters are flat and the resident size still climbs, it is the
allocator, and the allocator here is musl's.** Every Linux build is statically
linked against musl — `rust:1.98-alpine` in `docker/Dockerfile`, and
`*-unknown-linux-musl` in the release workflow — so `mallocng` is what is
holding the memory, not glibc. `MALLOC_ARENA_MAX` is a glibc knob and does
nothing here; there is no equivalent to tune. What the snapshot says in that
case is `process.rss` climbing while `process.peak_rss` tracks it and every
count stands still, and the experiment that follows is a different allocator
behind a feature flag, measured against the same load. Nothing has been
measured on that yet — it is written down so the next session does not reach
for the glibc answer to a musl question.

### What the fields say, and what is already bounded

Every structure in the process that has grown without bound here is now
bounded, and the snapshot reports each one against its bound:

| Field | Bound | What an unbounded climb would mean |
|---|---|---|
| `filters.compiled_expressions` | `MAX_COMPILED`, 2,000 | the ceiling is not holding |
| `filters.list_bytes` | the lists themselves | a refresh that keeps the old text |
| `cache.bytes` | `dns.cache_size` | the size accounting is wrong |
| `cache.eviction_slots` | compaction at twice the entries | the slot leak is back |
| `stats.live_domains` | an hour of traffic | the hour is not rolling |
| `stats.past_hours` | `statistics.interval` | pruning has stopped |
| `querylog.recent` | `RECENT_CAP`, 5,000 | the ring is not dropping |
| `server.ratelimit_buckets` | swept at 16,384, dropping five-minute-idle | sources active in one window, not a leak |
| `server.probe_marks` | swept at 16,384, keeping the live ones | the same |
| `clients.runtime` | **nothing** | see below |

`clients.runtime` is the one with no bound: an address is recorded the first
time it asks something and kept for the life of the process, with a reverse
name and, where WHOIS is on, an organisation, a city and a country. That is
upstream's behaviour and it is bounded by the network on a home installation —
19 addresses on the deployment above — but on a resolver reachable from the
internet it counts every distinct source that has ever reached it. The
snapshot reports it and how many of those carry a WHOIS record, which is the
expensive half. Nothing has been changed about it: a bound would be a
behaviour change, and the number should be looked at before it is chosen.

### What the high-water mark turned out to say

The first deployment to be asked for these numbers reported `VmHWM` 660.7 MB
against `VmRSS` 386.9 MB, with `memory.stat` saying `anon` 378.8 MB and `file`
48.7 MB. Two things follow from that pair before anything is instrumented: it
is the heap and not page cache, and **274 MB had already been given back** —
a process that never returns memory sits at its own high-water mark.

What took it there was measured rather than guessed, in the published image on
the same architecture and the same libc (`linux/arm64`, static musl), with
514,587 rules across three lists:

| | RSS | `VmHWM` |
|---|---:|---:|
| one 181k-rule list loaded | 31.3 MB | 41.8 MB |
| three lists, 514,587 rules | 89.6 MB | 146.2 MB |
| after one forced rebuild | 88.7 MB | 171.8 MB |
| after a second rebuild | 89.0 MB | 171.8 MB |

- **Loading lists costs about 1.63× the steady size**, transiently, and musl
  gives it back. The reporting deployment's own ratio is 1.71×.
- **A rebuild costs one more engine.** The first one raised the high-water
  mark by 28.3 MB where the rules alone are 514,587 × 56 bytes = 28.8 MB:
  `reload_filters` calls `build_engine` and only then `set_engine`, so both
  engines are live for the length of the build. At 2.29M rules that is 128 MB
  of rules for the second copy.
- **The second rebuild raised it by nothing**, and the steady size did not
  move across either: the space the first one took is reused, so the peak is
  reached once rather than climbing with every refresh. Nothing leaks across a
  rebuild.

Two things worth keeping in mind because of it. A memory limit has to leave
room for the transient, not the steady size — roughly 1.7× — or the daily
refresh is what kills the container, at the one moment the operator is not
watching. And on macOS the same rebuild shows *no* RSS bump at all, because
the allocator satisfies the second engine out of space it already holds; the
high-water mark is the only honest way to see it, which is why `peak_rss` is
in the snapshot.

### The step a refresh leaves, and why it stays

The deployment above was watched for fifteen hours with a sample every five
minutes. The resident size went 281.5 MB to 363.4 MB, and **81% of that
arrived in one hour** — the one holding `filter lists refreshed updated=13`
and `updated=5`, 47 seconds apart. Thirteen hours of serving either side of it
came to 14 MB, at a load of 3,539 distinct names in the whole query log. The
queries were never it.

Reproduced with that installation's own 37 lists — 2,220,598 rules, 50.3 MB of
list text — in the published image, `linux/arm64`, static musl:

| | resident | peak |
|---|---:|---:|
| loaded, settled | 280.6 MB | 413.9 MB |
| after a refresh that changed 18 lists | 341.2 MB | 667.5 MB |
| a minute later | 338.6 MB | 667.5 MB |
| after a second such refresh | 337.9 MB | 667.5 MB |
| after a third | 337.7 MB | 667.5 MB |

**It does not accumulate.** The first refresh costs about 56 MB of resident
size and every later one reuses that space rather than adding to it — which is
what says the memory is free and musl is holding it, not that something here
is still pointing at it. The peak settles at the first refresh too and does not
move again. The reporting deployment's own numbers are the same shape: +66 MB
on the step, a peak of 662.5 MB against this reproduction's 667.5 MB.

Why the transient is that large is arithmetic: for the length of the rebuild
both engines are live — 2.2M rules at 56 bytes is 124 MB of rules each — and
so are both copies of the list text, because the live engine's rules point
into the old bytes until it is replaced. Building the new engine after
dropping the old would halve it and leave the resolver unfiltered for the ten
seconds in between, which is not a trade worth making.

**mimalloc was tried, and is worse.** The obvious answer to "musl does not
give it back" is an allocator that does. Same lists, same image, same
protocol, one build apart:

| | musl | mimalloc |
|---|---:|---:|
| loaded, settled | 280.6 MB | 320.7 MB |
| peak during a refresh | 667.5 MB | 808.1 MB |
| settled after that refresh | 335.7 MB | 445.1 MB |
| time to settle after loading | immediate | ~3 minutes |

Worse on the baseline by 40 MB, on the peak by 140 MB and after a refresh by
110 MB, and it holds the load transient at its peak for minutes before purging
any of it. The change was reverted. musl's `mallocng` is doing the right thing
here; the step is the cost of the rebuild, paid once.

What that leaves: a refresh of a large list set costs a permanent-looking step
in the resident size, and it is free space that the next refresh spends. An
operator watching a container sees it and cannot tell it from a leak, which is
what `peak_rss` and the counters in the snapshot are for — and, for anyone
measuring the same thing again, so is the table above.

### The peak, and what came off it

The peak is dominated by two live engines and cannot go below that without a
gap in filtering. What sat above that floor was avoidable, and three rounds of
it have been measured in the image — arm64, musl, two containers from the same
work directory doing the same refresh, `VmHWM` and nothing else.

- **The domain index was handed 1.9M owned strings to produce 1.9M `u64`s.**
  `DomainIndex` stores no keys — a lookup is decided by `hashes[i] == h` and
  the caller's verification — so every domain the builder boxed was hashed
  once and dropped. It takes `(u64, u32)` pairs now, hashed where the rule is
  parsed.
- **The shortcut index sized a map from a guess.**
  `AHashMap::with_capacity(long_offs.len() * 12)` asked hashbrown for 1.87M
  entries for 155,609 patterns, which it rounds to 4,194,304 buckets: **71 MB
  allocated inside every build**, every page touched, whatever the real number
  of distinct windows turns out to be. The windows are collected and sorted
  instead — one `u64` each, ~15 MB, freed before the selection pass — which
  gives the exact count *and* the frequencies without a hash lookup per
  window.
- **Compiled expressions were held through the rebuild.** They belong to the
  rules being replaced and are discarded at the swap in any case, so
  `rule::drop_compiled()` lets them go before the new engine is built rather
  than after. Worth 25 KB per expression against a ceiling of 2,000.

- **The domain index was built by growing into a table.** It grew from 1,024
  slots by doubling, reinserting while the old tables were live, and gave
  every repeated domain a `Vec` of its own — about 500,000 of them. It sorts
  the pairs and fills a table sized once instead. The sort has to be stable,
  which costs a scratch buffer of half the input and is why this one is worth
  3 MB rather than the 40 it looked like.
- **`NetworkRule` went from 40 bytes to 24.** The pattern was an enum whose
  `Arc` niche was spent by two payloadless variants, so it cost 16 bytes where
  a pointer and three bits do; and every rule carried an `i64` list identifier
  to say one of 37 things, which belongs to the source it was parsed from.
  2.07M rules make that 33 MB of engine, and a rebuild holds two.

- **A hosts entry kept its names twice.** 147,175 of them carried a
  `Vec<String>` of the very words their text already held — a `Vec` and a
  `String` allocation each, about 12 MB of duplicate. `HostRule::hostnames`
  reads them back out of the line, which only the build and the tests ask
  for: a lookup goes through the host index, whose keys are those names
  already. 80 bytes down to 48, and the heap beside them from 30.3 MB to
  8.7 MB.
- **The domain index stores half a hash.** A probe starts at the hash's low
  bits, so storing them again in the slot says nothing a hit has not proved;
  the top 32 are kept and the table is 8.4 MB lighter. A stray match still
  has to pass the caller's verification, which is there because no keys are
  stored at all.

- **An expression kept its source, which is a copy of the rule's own text.**
  `LazyRegex` held what `to_regex` made of the pattern -- 156,000 of them,
  about 18 MB, to say what the rule text next to it already said. The matcher
  regenerates it from the text if and when it has to build, which is the
  first match against that rule and the first after an eviction. The parser
  stops generating it at all for the wildcard forms, which is 156,000
  `to_regex` calls off the load.

- **A rebuild parsed every list again, including the ones that had not
  changed.** The rules of one list are now a *segment* held by `Arc`, and the
  engine being built shares the segments of the one still serving wherever
  the list's text is the same `Arc` — which is exactly what `apply_fetched`
  leaves alone when a download matches what is on disk. A refresh that
  changes ten of 37 lists parses ten.

  Rules are referred to by a packed `(segment, position)` number, 8 bits and
  23. The segment is the high part deliberately: a priority tie is settled by
  the earlier rule, which upstream defines as the order the lists were read
  and then the order within the list, so comparing packed references
  numerically is comparing exactly that and `higher_priority` did not change.
  The `$badfilter` set stays one set over all segments, because such a rule
  cancels a rule in another list as readily as one in its own.

| | v0.9.0 | now |
|---|---:|---:|
| loaded, settled | 284.2 MB | **193.5 MB** |
| peak loading | 413.9 MB | **257.0 MB** |
| peak during a refresh of 10 of 37 lists | 662.4 MB | **324.9 MB** |

38% off the load peak and **51% off the refresh peak**, 91 MB off the steady size,
and the verdicts unchanged — the differential test against Go's answers for
4,190 domains covers that, and `sizes.rs` now fails if a rule grows past 24
bytes. Each step was measured in the image against the commit before it, not
against v0.9.0, so the numbers add up rather than overlapping:

| change | load peak | refresh peak |
|---|---:|---:|
| shortcut map sized from the windows there are | −58 MB | −71 MB |
| compiled expressions released before the rebuild | — | −11 MB (at 349 held) |
| domain index built by sorting | −2 MB | −3 MB |
| `NetworkRule` 40 bytes to 24 | −33 MB | −66 MB |
| host rules without their duplicate names, half-width index hashes | −35 MB | −70 MB |
| expressions without their stored source | −9 MB | −18 MB |
| segments carried over from the engine being replaced | — | −79 MB |

The engine's own estimate of itself falls from 192.0 MB to 123.0 MB over
those, which is the number the peak is twice.

### A claim in the last round was wrong: musl does not copy a growing vector

The round before this one also made `shrink_to_fit` conditional, on the theory
that shrinking an 83 MB vector cost an 83 MB copy inside the peak. **It does
not, on the target this ships to**, and the −54 MB measured then was the
domain-hash change alone.

Rust's `System` allocator reallocates through libc, and musl's `mallocng`
serves anything past its 128 KB mmap threshold from `mmap` and resizes it with
`mremap(MREMAP_MAYMOVE)`: growing moves page tables rather than copying, and
shrinking truncates in place and returns the pages at once. Measured in the
image, a 160 MB vector:

```
80 MB allocated+touched      rss  80 MB   hwm  80 MB
grown to 160 MB, untouched   rss  80 MB   hwm  80 MB     <- no copy
160 MB touched               rss 160 MB   hwm 160 MB
truncated+shrunk to 80 MB    rss  80 MB   hwm 160 MB     <- no spike
```

So the conditional shrink was reverted: it saved nothing and kept an overshoot
musl hands back for free. Two rules follow for anyone tuning this further.
Exact capacity planning for a large `Vec` is worth **nothing** here — what
costs is a *hashbrown resize* (allocate-new-and-reinsert, both live) and the
sheer number of small long-lived allocations, which is what the step after a
refresh is made of. And macOS is not a measuring instrument for any of it:
`loadprofile` there varied by 80 MB between runs of the same binary.

### Where the rest of it is, if this is taken further

Three expert reviews of the build path agree on the shape, and on rejecting
the obvious idea. **Per-list indexes combined at query time is the wrong
tool**: 37 segments means ~148 domain probes and ~590 shortcut-gate tests per
query instead of 16, which is 0.5–0.9 µs becoming 3–6 µs on a desktop core and
worse on a small ARM board, and the 256 KB gate staying in L2 is the thing
this design was measured into. A front filter fixes the clean path but not the
blocked one; a global router that fixes both is itself a full-size table
rebuilt every refresh.

What they agree *does* work, in order of value against risk:

1. **`NetworkRule` from 40 bytes to 16** — `pattern` tag, `list_id` and
   `allowlist` become flags plus a side table; `list_id` is already derivable
   from `net_text[idx].src`. Peak −100 MB, steady −50 MB, latency neutral,
   and `crates/sift-filter/tests/sizes.rs` already guards the layout.
2. **Segment the storage, keep one global index.** One parsed segment per
   list version, reused across rebuilds when `Arc::ptr_eq` says the text did
   not change; rebuild only the global tables over the segments in order, with
   rule references packed as `(ordinal, local)` so the existing `ai < bi`
   tie-break is unchanged. Removes the unchanged lists' rules from the second
   copy — ~124 MB of the transient — and stops re-parsing them, which is most
   of the rebuild's seconds. It also keeps unchanged lists' compiled
   expressions warm across a refresh.
3. **Host rules as text references with a hash-only index** — 147,175 host
   rules are 7% of the rules and 20% of the engine, at ~280 bytes each against
   ~60 for a network rule. Peak −64 MB, steady −32 MB.
4. **Builder scratch**: `DomainIndex::build` sorting its pairs instead of
   growing a table from 1,024 slots and keeping ~500,000 per-domain `Vec`s;
   the shortcut map keyed by hash rather than `String`. Peak −40 MB.
5. **Regenerate the regex source instead of storing it** — it is a pure
   function of the rule text, which is one `text_of` away. Peak −30 MB.

If all of that landed, the arithmetic is a refresh peaking near 300–350 MB
against a settled 175 MB — a refresh below today's *load* peak.

**The compatibility conditions, if segmentation is ever built.** A review
against the Go semantics found the merge is exact only when: the `$badfilter`
set is the **union** across segments and is passed *into* each segment's
candidate loop, because a `$badfilter` rule in the user's own list cancels a
rule in a subscribed one; host rules are concatenated across segments
**before** the address-family narrowing, not after; `0` and `-1` keep their
positions, since `reason_for_list` reads the first cited rule's list id to
tell `RewrittenAutoHosts` from a block; and the allow side's emptiness test
becomes "every allow segment is empty". The same review turned up three
pre-existing divergences from Go that are nothing to do with memory and are
recorded under *Deliberate deviations* to be checked against a running build:
the system hosts file is a list inside the block set here where Go consults it
first, `canonical_text` compares `$badfilter` by text where Go compares
parsed structure, and `@@||host^$dnsrewrite=` is applied as a rewrite here
where urlfilter treats it as an exception.

### Using it

```bash
scripts/memwatch.py -u http://host:3000 -p <password> -i 5m
```

Python 3 and nothing else. Each line is a sample; Ctrl-C prints the first
sample against the last, sorted by how much each number moved, with what did
not move on one line at the end. `--once` prints a single snapshot whole.

Verified against a running server: five queries moved the cache, the live
hour's names and both query-log buffers by exactly the four new names between
two samples, and the resident size by 64 KB. The three tests in
`crates/sift-api/tests/memory.rs` seed a different amount into every subsystem,
so a field wired to the wrong source reads another subsystem's number.

**Not yet used to find anything.** It exists because the next climb should
cost an hour rather than a day.

---

## The response cache, packed

Prompted by Cloudflare's write-up of the cache behind 1.1.1.1 ("How we saved
100 terabytes of memory by optimizing 1.1.1.1's DNS cache", 2026), which took
a typical entry from 953 bytes to 420 with five changes to a Rust cache. All
five apply here, and measuring before changing anything turned up a bug the
article does not have: **the cache's size accounting was wrong**.

Measured with a counting global allocator over 50,000 entries in a release
build. The harness was a scratch file and was not committed, because the tree
carries no unsafe code:

| Answer | Before: real | Before: charged | After: real | After: charged |
|---|---|---|---|---|
| one `A` record, with OPT | 833 B | 384 B | 259 B | 257 B |
| `CNAME` then two `A`, with OPT | 1,377 B | 576 B | 318 B | 316 B |

An entry held a hickory `Message`, and `estimate_weight` charged a guess of 64
bytes a record. A `Record` is 272 bytes whatever it holds, because `RData` is
as large as its largest variant and `Name` carries a 32-byte inline buffer. So
the default 4 MiB `cache_size` really held about 9 MB: 10,900 one-address
answers at 833 bytes each. Packed, the same budget holds about 16,300 of them
in 4.2 MB. That is half again as many answers in less than half the memory,
and `cache.bytes` in `/control/debug/memory` now means what it says.

What changed, in `crates/sift-dns/src/packed.rs` and `cache.rs`:

- **Fixed-size buffers.** A response is one `Box<[u8]>` rather than four
  `Vec`s, because nothing is appended to an entry once it is stored.
- **One list for all three sections.** Three `u16` counts say where each
  section ends.
- **Record data in wire form**, so an `A` record costs its 4 bytes rather than
  the 184 of `RData`. Names inside the data are compressed against earlier
  names in the buffer, the way a DNS message does it.
- **Owner names elided.** One byte says which name the owner repeats: the
  question's name, the previous record's owner, or the previous `CNAME`'s
  target. A chain is therefore stored as its targets alone. The article
  elides only the question's name. The other two cases are ours, because
  parsing names is most of what unpacking costs.
- **Narrow fields.** `Instant` + `Duration` became milliseconds since the
  cache's epoch (`u64`) and seconds (`u32`). `hits` is a `u8` capped at the
  only threshold anything reads, and `weight` is a `u32`. `Entry` went from
  208 bytes to 72, and `an_entry_stays_small` guards it.
- **The key's name is shared, and in wire form.** Every entry holds its key
  twice, once in the map and once in the eviction order, so the name is an
  `Arc<[u8]>` rather than two separate strings. It is the lowercased wire
  form rather than text, because rendering a name as text escapes it, and
  that was a quarter of a hit. Wire form is just as unambiguous:
  `www.victim\.com.` and `www.victim.com.` are different bytes, which is what
  stops a crafted name from filling another name's entry with its NXDOMAIN.
  `a_dot_inside_a_label_is_a_different_name` guards that.

**The answer is kept losslessly; the exchange is not.** Every record comes
back byte for byte, including the case of each owner name: elision compares
with `eq_case`, because `Name`'s `==` ignores case. The tests in `packed.rs`
compare encoded bytes, since `Name` equality cannot catch a case change. The
question and the OPT record are deliberately not kept, for the reason in the
next section. A response without exactly one question, a signed one, or one
whose response code needs an OPT record to carry it is refused. None of those
is cached anyway: only `NOERROR` and `NXDOMAIN` are.

**Times kept exact, deliberately.** Whole seconds would have been four bytes
smaller, but an entry stored at 0.99 s would then expire at 1.0 s. An
`optimistic.rs` test that stores a one-second TTL could flake on that.

**What a hit costs.** Counted in instructions with callgrind, because wall
time on the build machine swung by ±100 ns between runs. Each count covers
building the key and the lookup, over 2,000 entries:

| Hit | Holding `Message`s | First packed version | Now |
|---|---|---|---|
| one `A` record | 4,248 | 6,831 | **3,473** |
| `CNAME` then two `A` | 4,832 | 9,539 | 5,324 |

The first packed version was slower than what it replaced, because every hit
re-parsed the stored question's name. Three changes brought it back:

- **The request's name is reused.** When the request spells the name the
  way the stored one is spelled, which is almost always, that name is
  cloned rather than parsed.
- **The key is built from the labels**, not from `Name::to_ascii`.
- **Keyed `ahash` for both the shard and the map.** The map used to hash
  with std's SipHash. The shard is picked by a separately keyed hasher,
  because keys that shared their low hash bits would crowd one corner of
  their shard's table.

Sections are also sized exactly now. Collecting through an `Option` iterator
lost the count, so a one-record answer allocated room for four.

A chain still costs more than it did, because its `CNAME` targets are parsed
from the buffer. A whole DNS message as the stored form was measured and
rejected: it decodes in 400 ns. The end-to-end cost against a UDP exchange was
not measured.

### Found while packing: a hit was addressed to whoever filled the entry

A cache hit returned the stored message with only its ID changed, and so did a
query that waited on an identical one in flight (`pending_requests`). Two
things in that message belonged to the first asker rather than the answer:

- **The question, spelled the first asker's way.** The cache key is
  lowercased, so `WWW.example.com` could be answered with a question reading
  `www.example.com`. A client that randomises the case of its names (DNS 0x20)
  checks that the question comes back as it sent it, and rejects the answer
  otherwise. The `RD` and `CD` bits were also the first asker's.
- **The upstream's OPT options.** A client's EDNS cookie is forwarded
  upstream, and the upstream echoes it, so the first asker's client cookie
  was stored and then handed to everyone. RFC 7873 5.3 has any other client
  discard an answer whose client cookie is not its own. `dig`, which sends a
  cookie by default, prints `Client COOKIE mismatch`.

`msg::readdress` now makes a shared answer the asker's own: its ID, its
question as spelled, its `RD` and `CD`, and no OPT record. `shape_to_request`
then builds the asker's own OPT from its request, as it already did for
locally built answers. A waiter is also given its TTLs clamped to
`cache_ttl_min` and `cache_ttl_max`. The leader clamps its own copy after
publishing it, so waiters had been getting the unclamped TTLs.
`a_coalesced_answer_is_addressed_to_each_asker` fails without the fix, and
`a_hit_is_addressed_to_the_request_not_the_one_that_filled_it` covers the
cache.

**Not yet compared against a running build.** This follows the RFCs, and
dnsproxy's cache as its source reads: `unpackItem` builds the reply with
`SetRcode(req, …)`, which takes the ID, question, `RD` and `CD` from the
request, and a comment there says OPT records are not returned from cache.
That is inferred from source, which this project does not treat as enough.
Before this is called matched, `verify.sh` should ask both servers the same
name twice, in two spellings and with a cookie, and compare the second
answers.

## Found comparing `$dnsrewrite` against a running build, and fixed

A reading of the code suggested `@@||host^$dnsrewrite=1.2.3.4` was being
*applied* here rather than treated as an exception. It was, and comparing 24
cases against a running v0.107.79 — the published image, user rules set
through the API, then `check_host` and a real query for each — found **twelve**
of them answered differently. Two mistakes, both of which a reading of
urlfilter's source would have got half right:

- **An `@@…$dnsrewrite` rule is an exception, and this build applied it.**
  `consider` routed every rule carrying a rewrite into the rewrite list
  whatever its `allowlist` flag, so `@@||a.example^$dnsrewrite=1.2.3.4` sent
  the client to 1.2.3.4 — the exact opposite of what someone writes that rule
  for. It now removes matching rewrites and is never applied itself.

  Which rewrites it removes was captured rather than inferred, and two details
  are not what the source reads like. An exception with **no value** removes
  rewrites of *any* value, and `=NOERROR` parses to the same thing, so
  `@@||a.example^$dnsrewrite=NOERROR` removes `$dnsrewrite=1.2.3.4` rather
  than only the rewrites that answer NOERROR. And the comparison is by the
  **parsed value**, so `@@…$dnsrewrite=1.2.3.4` removes
  `…$dnsrewrite=NOERROR;A;1.2.3.4`. `$important` decides the rest: an ordinary
  exception leaves an `$important` rewrite alone, and an `$important`
  exception takes it.

- **`$dnsrewrite` with no value is a rewrite, not a cancellation.**
  `$dnsrewrite`, `$dnsrewrite=` and `$dnsrewrite=NOERROR` each report
  `RewriteRule` and answer NOERROR with an empty answer section. This build
  parsed them to a `DnsRewrite::Exclude` of its own invention that cancelled
  every rewrite for the host — so a rule meant to answer "nothing here"
  silently disabled the rules beside it, and `||a.example^$dnsrewrite=1.2.3.4`
  next to `||a.example^$dnsrewrite=NOERROR` resolved upstream where Go answers
  1.2.3.4 citing both rules. The variant is gone; they parse to `RCode(0)`,
  and in the resolver only a **non-zero** response code outranks the records
  beside it.

- **A rewrite of a host to itself is dropped**, as upstream's
  `processDNSResultRewrites` drops `res.CanonName == host`:
  `||a.example^$dnsrewrite=a.example` reports `NotFilteredNotFound` and
  resolves normally.

23 of the 24 cases now agree. `tests/compat/dnsrewrite_diff.py` is the
comparison, wired into `scripts/verify.sh` beside `ratelimit_diff.py` because
it too changes a setting — it replaces the user rules and puts the originals
back. The captured answers are pinned in-repo by
`crates/sift-filter/tests/dnsrewrite.rs` (14 cases, verdict and cited rules)
and three resolver tests in `crates/sift-dns/src/resolver.rs` (the answer
shape), so the suite covers them without a Go build.

**The twenty-fourth is left, and recorded.** `||a.example^$dnsrewrite=b.example`
gets `CNAME b.example` from both, but Go then resolves `b.example` and answers
with *its* status — NXDOMAIN for a name that does not exist — where this build
answers NOERROR and stops at the CNAME. Following a rewritten CNAME is a
resolver change with a loop guard, a cache interaction and a query-log entry
to decide, not a filtering one, so it is a task of its own rather than
something to bundle into this. `dnsrewrite_diff.py` reports it as a known
divergence and fails on anything else.

---

## Found reading the Go search code beside ours, and fixed

Searching the query log for a client — `"192.168.99.1"`, `"hoangnc-chrome"` —
answered "Nothing found" for both. Two reasons, both in the same function.

- **A quoted term was matched with its quotes.** Upstream's
  `getDoubleQuotesEnclosedValue` strips a surrounding pair and turns the search
  from a substring into an exact match; `ctDomainOrClientCaseStrict` then
  compares the whole of the queried name, the client's address, its name and
  its ClientID. This build took the parameter as written and looked for
  `"192.168.99.1"`, quotes included, inside each field — which nothing ever
  contains. The interface quotes the term whenever the user picks a client out
  of the log, so the one search a user is most likely to run was the one that
  could never match.

- **Only discovered names were searched.** The name came from the runtime
  store alone, so a client the user had named in the interface was neither
  findable by that name nor shown beside its queries. Upstream's
  `clientOrArtificial` asks the persistent store first and the runtime one
  after, which is what `name_of` does now — and `client_info.name` carries the
  configured name with it.

Checked against a running server, five queries from a client named
`hoangnc-chrome`:

| search | before | after |
|---|---:|---:|
| `"127.0.0.1"` | 0 | 10 |
| `"hoangnc-chrome"` | 0 | 10 |
| `127.0.0` | 10 | 10 |
| `"127.0.0"` | 0 | 0 |
| `"hoangnc"` | 0 | 0 |

The last two are the point of the quotes: an exact match on a whole field, so a
part of one does not match.

**And the term's ASCII form.** Upstream converts the lowercased term with
`idna.ToASCII` and tries that against the queried name as well, because the log
stores a question as the wire carried it — punycode — while the user types
their own script. That is the third difference the comparison turned up, and it
is closed with the same `idna` the tree already carries.

---

## Found reading the dashboard's Top clients, and fixed

**The statistics counted every ClientID under the address it came from.** Top
clients reported 11,538 queries from `192.168.99.1` — the router every DoH and
DoT client on the network arrives through — while the query log beside it named
`hoangnc-chrome` and `mi12t` on rows sharing that address. The two views
disagreed because only the query log carried the ClientID: `Recorder::observe`
built the statistics entry from the client address alone.

Upstream's `updateStats` takes the ClientID when the query carried one and the
address only when it did not, the same priority `processQueryLogsAndStats`
gives the two identifiers everywhere else. This build does that now, and
nothing downstream needed changing: `/control/clients/find` already resolves a
ClientID to its persistent client, so the interface turns the new key into the
client's name rather than showing a bare identifier, and the query log keeps
recording the address with the ClientID in `CID` as before.

The effect is visible only where it should be — a network whose clients use
ClientIDs. Anything arriving by plain UDP or TCP has no ClientID and is counted
by address exactly as it was, and the units already on disk are untouched:
older hours keep the keys they were written with.
`statistics_count_a_client_id_apart_from_the_address_it_shares` in
`crates/sift/src/wiring.rs` pins both halves.

---

## The web interface, rewritten

The interface was AdGuard's compiled output, then a fork of their sources, and
is now **this project's own**, at `web/client`, built by
`scripts/build-frontend.sh` into `web/build`.

Why not stay a fork: it carried a decade of accumulated shape — Redux with
thunks and `redux-actions`, `react-table` 6, `react-select`, two className
libraries, `date-fns` 1, a vendored Bootstrap 4 — about forty runtime
dependencies to render a dozen pages, none of which the exclusions made
smaller. Rewriting against the same API is a smaller surface to keep true than
a fork is to keep merged.

### What it is now

React 19, TypeScript 5.9, react-router 7 and ECharts 6, built by Vite 7. Those
four are the whole runtime dependency list: no store, no component library, no
CSS framework, no test runner. 1.0 MB embedded, against the fork's 1.7 MB.

| | Before | After |
|---|---|---|
| Runtime dependencies | 33 | 4 |
| `web/build`, brotli | 1.7 MB | 0.4 MB |
| Files embedded | 46 | 11 |
| Dashboard's own bundle | 721 KB js + 43 KB css | 234 KB + 3 KB |
| Login page's bundle | 439 KB | 59 KB |
| Languages | 36 | 1 |
| Charts | Recharts | ECharts |
| State | Redux, thunks, `redux-actions` | `useAsync`, one context |
| Build | webpack | Vite |

The state question is the one worth stating plainly. Every page here loads what
it needs, edits a local draft and saves it; nothing is cached across a route
change and nothing is synchronised. That is right for this application because
every page reads a different endpoint and none of them shares state with
another — the three things that *are* shared (server status, profile,
protection) live in `src/app/context.tsx`, and they are three.

### What carried over

- **The routes**, so a bookmark still lands on the same page — `/logs`,
  `/settings`, `/dns`, `/filters`, `/blocked_services` and the rest. React
  Router 7 writes `#/logs` where the old interface wrote `#logs`, so
  `main.tsx` rewrites the bare form once at boot.
- **Hash routing itself**, which is not cosmetic: signed out, the server
  redirects `/` to the login form and answers every other path 401, so a
  bookmarked `/settings` under a browser router would be a blank 401 rather
  than a sign-in prompt.
- **The three documents** — `index.html`, `login.html`, `install.html` — and
  the asset names the server's gate matches on.

### Three builds, not one

`build.mjs` runs Vite once per document. A single multi-entry build would hoist
React into a shared chunk under a third name, and `is_public_page` serves an
asset without a session only when its basename starts with `login.` — so the
login form would ask for a script that answers 401 to exactly the visitor who
needs it. The cost is React twice more on disk, ~75 KB brotli per page, which
is a fair price for a gate that cannot be got wrong by a bundler setting.

### Kept honest

`.github/workflows/ci.yml` grew a **Web interface** job: `npm ci`,
`npm run typecheck`, then `scripts/build-frontend.sh` and a check that the
rebuild produced no file name the repository does not already have. Names,
not bytes — each is a hash of the chunk's own contents, so a source change
nobody built shows up as a name that was never committed, while brotli output
that differs by a byte between zlib versions does not fail the build.

### Found building it

- **The profile's theme never applied on a fresh browser.** The theme was
  restored from `localStorage` at boot and written back when changed, but
  nothing applied the theme the *profile* reported — so a browser that had
  never been to that origin ignored the account's choice. Caught by loading the
  production build on `:3000` after setting light mode on `:5173`: different
  origin, empty storage, dark page.
- **`grid.containLabel` is deprecated in ECharts 6** and logs on every chart;
  `outerBoundsMode: 'same'` with `outerBoundsContain: 'axisLabel'` is the
  replacement.
- **A `.field > label` rule silently beat `.check`.** Higher specificity, so a
  radio row inside a field turned back into a block and the control sat flush
  against its text. `:not(.check)` on the rule, and a comment saying why.
- **The service icons are `fill="currentColor"`.** Inside an `<img>` that
  resolves against the image's own root and comes out black — invisible on the
  dark theme. Drawn as a CSS mask instead, which paints the shape in the text
  colour and runs nothing from the file.
- **`upstream_mode` is `""`, not `"load_balance"`.** That is what the config
  has always written and what the API echoes; `POST /control/dns_config` takes
  either. A radio group matching on the name alone shows nothing selected.
- **`input[type='text']` does not match `<input>`.** An input with no `type`
  attribute *is* a text input, and the attribute selector does not match it —
  so the server name, the blocking addresses, the filter URL and half a dozen
  other fields rendered a third of the width of the ports below them. The
  stylesheet now selects by what a control is not.
- **A five-column table is unreadable on a phone**, and scrolling one sideways
  to read a log is worse. `table.stack` lays each query log row out as a card:
  name and action first, verdict under it, client and time along the bottom.
  `table.rows` does the general case for the other tables, each cell naming
  itself from its `data-label`.
- **The breakpoint for that is 1000px, not a phone width.** The constraint is
  the content column, and the sidebar takes 232px out of it whenever it is not
  a drawer — so a table needing 620px was already scrolling sideways in a
  900px window. Measured rather than guessed: `scrollWidth` against
  `clientWidth` on every `.table-wrap`, at 375, 406, 458, 914 and 1051px.
- **A stacked table has to stop being a table.** With `display: block` only on
  the rows, the `<table>` box still sized itself from the widest cell and the
  row scrolled sideways anyway; the element and its `tbody` both need it.
- **The blocked-services page groups by the catalogue's own `group_id`**, with
  a Block all and an Unblock all per group and a switch per service, rather
  than one flat grid of 139 checkboxes. The catalogue names its twelve groups
  only by identifier — upstream keeps the names in its translation files — so
  the headings were written here.
- **A card reading zero and a line flat along the axis were taking the room the
  numbers that moved needed.** The dashboard now draws a tile and a series only
  for a category that has counted something; Queries always stays, so the page
  is never empty, and a period with no queries at all says so instead of
  drawing a flat chart.
- **A dialog has to fit the window.** The catalogue picker is 4,300px of
  content; with the backdrop scrolling rather than the body, its buttons were
  off the bottom of the screen. The modal is now capped at 90vh with the head
  and foot pinned and the body scrolling.
- **The upstream bar chart was the wrong shape** for a half-width card — its
  axis labels collided, and each bar needed its value spelled out beside it
  anyway. It is a table now, which also let the bar and pie modules go: the
  dashboard draws one line chart and nothing else.

### Assets: brotli, and cached properly

`sift-api/src/ui.rs` used to store gzip and serve it to whoever accepted gzip.
It now stores **brotli** — 1.3 MB of assets to 0.4 MB — compressed by
`scripts/brotli.mjs` at quality 11, run from the build script.

The catch is that browsers advertise `br` only over a secure origin. Over plain
HTTP on a LAN address, a browser sends `gzip, deflate` and is served the
**decompressed** bytes: bigger on the wire than gzip was, and a decompression
per request. Two things make that affordable, and they are the rest of the
change:

- a name carrying a content hash — anything the build wrote under `static/` —
  is served `Cache-Control: public, max-age=31536000, immutable`, so it is
  fetched once per build and never asked about again;
- everything else is `no-cache` with an `ETag`, and `If-None-Match` is answered
  **304** without touching the body.

The `ETag` is the stored file's SHA-256, which rust-embed computes at build
time, suffixed with the encoding: `"<hash>-br"` and `"<hash>-identity"`. They
must differ — a shared validator lets a cache hand compressed bytes to a client
that asked for plain ones. `Vary: Accept-Encoding` is on every response.

`flate2`, `tower-http` and `mime_guess` left `sift-api`'s manifest with this:
the first because nothing decodes gzip there any more, the other two because
nothing had referenced them in the first place. `brotli-decompressor` replaced
them — the decoder only, since the encoding happens in Node at build time.

**Watch out for:** `content-length: 0` on a 304. hyper writes it and removing
it in the handler does not survive serialisation. RFC 9110 makes the header
optional there and a truthful value would mean decompressing the very body the
304 exists to avoid, so it stays.

## Found improving the protection control, and fixed

### A timed pause never ended

The interface offered "disable for 30 seconds" and four more like it, and
`POST /control/protection` **read the duration and threw it away**:

```rust
s.config.write().filtering.protection_enabled = req.enabled;
```

`GET /control/status` then reported `protection_disabled_duration: 0`
unconditionally. So every timed option turned protection off *permanently*,
and the interface had no way to know: it drew no countdown because the server
always said there was none. `filtering.protection_disabled_until` existed in
the config model, was written by the schema-34 migration, and nothing ever set
or read it.

This is the shape this tree warns about everywhere else — a setting the
interface accepts and the server discards — and it is worse than most, because
the thing silently left off is the filtering.

What it took:

- **A deadline, not a countdown.** `protection_disabled_until` holds the
  moment protection comes back, so a pause means the same thing across a
  restart. Checked: a 20-second pause restarted at 2 seconds resumed with 17.7
  left, rather than starting over.
- **`AppState::expire_protection_pause`**, which re-enables and saves — and
  saving already pushes settings to the resolver, so nothing else was needed
  to make it take effect.
- **Its own one-second task**, not a line in `maintenance`. That ticks once a
  minute, and the shortest pause offered is thirty seconds: a pause that ends
  up to a minute late is a pause that lied. Its first tick fires immediately,
  which is also what catches a pause that elapsed while the process was down.
- **`pause_left` and `pause_deadline` are pure**, and tested: that a pause
  counts down from its deadline, that an elapsed or unparseable one reads as
  zero rather than negative, that turning protection *on* clears the deadline
  — a leftover one would later turn protection on by itself — and that a
  deadline read back later resumes instead of restarting.

### The menu did not say what it did

The durations sat under a bare chevron: "For an hour" of what? The menu now
carries a heading, `Turn protection off`, and ends with `Until I turn it back
on` for the indefinite case, which the switch does but nothing named. Added
`Until tomorrow` — the length of which is computed at the moment it is
clicked, since it depends on when that is — and the badge now reads
`off for 0:59` rather than a bare countdown.

## Found while first forking the interface, and fixed

Three things the first pass left behind, and one it introduced.

### Per-client upstreams were stored and ignored

`clients.rs` carried `Persistent::upstreams`, `app.rs` copied it into the
registry and the client form offered the field — and nothing read it. Every
client resolved through the global pool. The exact shape this tree warns
against everywhere else: a setting the interface accepts and the resolver
throws away.

Wired through, and the interesting part is what had to come with it:

- **`Resolver::client_pools`**, a map from an upstream set to its pool, built
  by `app::build_client_pools` and installed by `reload_upstreams` beside the
  global one. Keyed by `clients::upstream_key` — the normalised upstream lines,
  not the client's name — so two clients configured with the same servers share
  one pool, and renaming a client reconnects nothing.
- **`cache::Key::upstreams`.** Without this the fix would have been worse than
  the bug: client A resolves an intranet name through its company's
  split-horizon resolver, client B asks the same question, and B gets A's
  answer out of the shared cache. The key now carries the same identity the
  pool does, and `PendingKey` embeds `Key`, so request coalescing is namespaced
  for free. `None` is the global pool, so the common case costs one word.
- **Refreshes keep the entry's own upstreams.** `refresh::Job` already carried
  the `Key`; the worker reads the pool identity from it rather than from the
  settings, or a background refresh would overwrite a client's entry with an
  answer its resolvers never gave.
- **The reload window does not poison the cache.** Connecting takes seconds, so
  a client added by a settings save briefly has a key and no pool. It is
  answered from the global upstreams rather than failing — but `pool_for`
  reports that it did, and `forward` drops the cache key, so nothing from that
  window is stored as the client's own.
- `upstream_fingerprint` now includes every client's upstream list, or editing
  one would never trigger a rebuild.

Verified live: the same question from the same address, once plain and once
with a ClientID, went to `1.1.1.1` and `9.9.9.9` and took a cache entry each.

### The caching rule was a guess

`is_content_addressed` called any dotted segment of 16-plus hex characters a
content hash. Right for the bundler's hash of the day, and quietly wrong — for
a year, per client — the first time someone shortened the hash or added an
asset whose name read like a digest. (Vite's is base64url, and would never have
matched at all.)

The build writes its hashed output under `static/` and nothing else there, so
the predicate is `starts_with("static/")`: a fact about the build rather than a
guess about the name. `everything_the_build_emitted_is_classified_the_way_it_was_built`
walks the real embedded assets and fails if that stops being true.

**That move broke the login page**, which is worth recording because nothing in
the suite noticed. `is_public_page` matched `/login.`, and the login bundle had
become `/static/login.<hash>.js`; a signed-out browser got a blank page and two
401s. Same for the setup wizard. Both gates now strip the directory before
matching the name, and two tests check them against the assets the build
actually emitted rather than against names typed into a test.

### The translations named the wrong product

*Kept for the record: the catalogues this describes were removed when the
interface went English only. See **The interface is English only** under
Deliberate deviations.*

All 35 non-English locales said "AdGuard Home" under a LITE logo. The reason to
hesitate was that a machine substitution can break languages that inflect a
name — so that was checked rather than assumed. Every locale uses the literal
ASCII string, and only two needed more than a replace:

- **Korean** particles have two forms, chosen by whether the preceding syllable
  ends in a consonant. "Home" is read 홈 and takes 은/이/을; "Lite" is 라이트 and
  takes 는/가/를. Twenty-two of them moved.
- **Finnish** vowel harmony: "Home" carries a back vowel and "Lite" does not, so
  one partitive went from `-a` to `-ä`. The genitive `-n` and the illative
  `-en` do not harmonise.

Danish and Swedish genitive `-s`, and the Japanese and Chinese particles, are
unaffected by what precedes them.

## Naming

The project was called **AdGuard Lite** and used a recoloured AdGuard shield.
Both are gone. The reason is not the licence — the GPL-3.0 covers all of the
code and is complied with — but trademark, which the GPL does not grant and
explicitly lets an upstream withhold (§7(e)):

- "AdGuard Lite" was built like a tier in their own product line — AdGuard
  Home, AdGuard DNS, AdGuard VPN — which is the worst case for likelihood of
  confusion as to source, the test that actually decides infringement.
- The gold shield was a recolour of their figurative mark. Colour is not what
  is protected; the shape is.
- Every substantial fork of a trademarked project renames: Firefox→Iceweasel,
  MySQL→MariaDB, Redis→Valkey, Terraform→OpenTofu.

**Sift** is its own name and its own mark: a funnel, drawn in
`ui/svg/logo.tsx`, and the word set in the system UI font. No AdGuard mark
appears anywhere in the interface, the icons, the repository or the image.

What the rename touched:

| | |
|---|---|
| Crates | `agl-*` → `sift-*`, and the binary crate `adguardlite` → `sift` |
| Binary | **unchanged**: `AdGuardHome` at `/opt/adguardhome/AdGuardHome` |
| Config | **unchanged**: `AdGuardHome.yaml` |
| Repository | `openhoangnc/adguardlite` → `openhoangnc/sift` |
| Image | `ghcr.io/openhoangnc/adguardlite` → `ghcr.io/openhoangnc/sift` |
| User-Agent | `AdGuardLite/<version>` → `Sift/<version>` |
| Locales | all 36, 1,682 strings |

The binary and config names stay because they are the drop-in contract, not
branding — an existing installation already has them at those paths. `NOTICE.md`
records that distinction so nobody "finishes the rename" and breaks every
deployment.

### What the translations needed beyond a replace

The same class of problem as the previous rename, in different languages,
because "Sift" ends in a consonant where "Lite" ended in a vowel:

- **Finnish** inserts a linking `i` before a case ending on a consonant-final
  foreign name: `Siftin`, `Siftiä`, `Siftiin`.
- **Hungarian** picks both the article and the suffix by sound. "AdGuard"
  opens with a vowel and carries a back one, so it took *az* and `-ot`/`-ban`;
  "Sift" opens with a consonant and carries a front vowel, so it takes *a* and
  `-et`/`-ben`.
- **Korean** needed nothing this time: 시프트 ends without a final consonant
  just as 라이트 did, so the particles fixed in the previous rename still hold.
- Danish and Swedish genitive `-s`, the German, Dutch and Norwegian compound
  hyphens, and the Japanese and Chinese particles are all unaffected by what
  precedes them.

One upstream typo surfaced while checking: the Dutch `update_announcement` had
no space before `{{version}}`, which rendered as "Sift0.2.0 is nu
beschikbaar". Fixed, since the file is ours now.

## Version numbering

The binary reports **its own** version, `sift_core::VERSION`, built from the
workspace version in the root `Cargo.toml`, starting at **v0.2.0**. It used to
report `v0.107.79`.

- `sift_core::AGH_COMPAT_VERSION` keeps `v0.107.79` as what the formats are
  matched against. Nothing reads it; it is there so the number has one home.
- Nothing on disk carried the version, so this changed no file format. The
  config's compatibility is `SCHEMA_VERSION`, which is untouched at 34.
- The inter-crate `version = "0.107.79"` pins in every `crates/*/Cargo.toml`
  were dropped in favour of bare `path` dependencies, so a version bump is one
  line in the root manifest rather than twenty-three.
- The outbound `User-Agent` is `Sift/<version>` (via `AdGuardLite/` before the
  rename). It was `AdGuardHome/<version>`, which after the bump would have
  claimed to be an AdGuard Home 0.2.0.

---

## Deliberate deviations


- **The interface is this project's own, not upstream's.** It reads the same
  API and keeps the same routes, so a bookmark and a habit both survive; it
  does not reproduce upstream's layout, and it does not carry their code. See
  *The web interface, rewritten*.
- **The blocklist picker says what each list is for, in our words.** Upstream
  offers 64 names and a URL each. This build adds a tag set and a sentence or
  two per list — what it blocks, who it suits, what it will break — written
  here, plus a rule count measured by downloading every list. That last part
  doubles as validation: `--measure` refuses to publish a catalogue in which
  anything 404s or comes back empty, so a dead list is caught at import rather
  than by the user who picked it.

  The tags are a closed vocabulary of 23, and the importer rejects
  anything outside it: a typo would otherwise become a filter chip that
  matches nothing. Measured at the time of writing, `starter` selects exactly
  five lists, which is the question most people arrive with.
- **A client that sends no OPT record is held to 512 bytes over UDP, not
  2,048.** RFC 1035 gives such a client 512 and RFC 6891 gives it no way to ask
  for more, so that is what it is sent, with the truncation bit set and the
  full answer a TCP retry away. The Go build sends it up to 2,048 — but only
  with `enable_dnssec` and the cache both on, because the number is an artifact
  of dnsproxy reading the client's limit out of a request it had itself edited
  to carry `OPT(2048, DO)` for the upstream. Matching it would mean
  fragmenting a 2 KB datagram towards a client that never said it could take
  one. Measured four ways and written up under *Found comparing answer shapes*.
- **One API path is added, none changed.** `GET /control/filtering/catalogue`
  serves the vetted-blocklist catalogue that AdGuard Home bundles in its own
  client, so the "Choose blocklists" picker can offer 66 known lists — their
  64 and two added here — without `web/client` carrying anything of theirs.
  Nothing upstream answers is altered, and the picker degrades to the
  custom-address form if the path is ever missing.
  `scripts/import-blocklists.py` regenerates the bundled blob from
  upstream's generated `filters.ts`, byte for byte.
- **The interface is English only.** Upstream ships 36 translations and the
  first version of this rewrite kept their catalogues. They are gone, with
  them: a translation is someone else's writing, and this interface's wording
  is now its own — the catalogues could not be kept without keeping AdGuard's
  sentences. Nothing else changed: `dns.language` in the config still
  round-trips for a user who switches back to the Go build, and the API's
  `/control/i18n/*` endpoints still answer. The interface simply no longer
  offers a language menu, rather than offering one that does nothing.
- **Upstream connections outlive the query.** dnsproxy pools DoT
  (`upstream/dot.go`), caches one `http.Client` for DoH and keeps a single
  QUIC connection for DoQ, so keeping connections is parity, not invention.
  Where this build goes further: **plain TCP is pooled too**, which dnsproxy
  dials per query, and the HTTP/2-versus-HTTP/3 choice is **remembered per
  upstream** with a timed retry rather than re-raced on every query. An
  operator watching outbound sockets will see a few long-lived connections
  per upstream where there were many short ones.
- **Every reply is checked against the question asked**, on every transport.
  This is dnsproxy's `validateResponse`, which this build did not have: an
  upstream answering a question nobody asked had its answer returned and
  cached under the name that *was* asked. A tolerant, misbehaving upstream
  that appeared to work will now fail over. Names compare by their labels,
  case-insensitively — not with `Name`'s own equality, which also compares
  whether a name is fully qualified and so rejects every bootstrap reply.
- **Each upstream address gets a bounded share of the timeout.**
  `upstream_timeout` defaults to ten seconds and addresses were tried in
  order, each with the whole budget, so one unroutable address cost the full
  ten seconds on every query and the remaining addresses were never reached
  before the client below had given up. Attempts are now capped at two
  seconds with the remainder carried to the last, and the address that
  answered is preferred next time. The upstream gets the same total budget;
  only its division changed.


**A first launch as a non-root user is allowed.** The Go build refuses one —
*"this is the first launch of adguard home; you must run it as
administrator"* — and exits. This build starts and serves the wizard. The
difference is confined to the first launch: an already-configured
installation runs as `--user 65534:65534` under both, logs in under both, and
behaves identically. Refusing to start would be the worse failure, so the
extra permissiveness stands.

Not bugs; recorded so nobody "fixes" them.

- **Cited rule on ties.** When several rules of equal priority match, upstream's
  choice falls out of its shortcut index's bucket balancing and the order it
  walks the URL. This engine uses a suffix-walk index and resolves ties by load
  order, so it may cite a different — equally valid — rule for about 0.8% of
  matches. The verdict is always identical.
- **`gob` byte-equality.** Not attempted: Go's own encoder does not reproduce
  its own bytes for the same value. The bar is mutual decodability, which is
  tested directly.
- **`stats.db` page size.** Written at a fixed 4 KiB rather than the OS page
  size, so output is reproducible across machines. bbolt reads any size.
- **Filter list identifiers.** Assigned sequentially rather than from a
  timestamp. Any unused identifier is valid.
- **ipset through the command, not netlink.** Upstream talks to the kernel
  directly. This runs `ipset add … -exist`, which needs no netlink
  implementation, and remembers what it has already added so the cost is one
  process per new address rather than one per query.
- **Privilege dropping is Linux-only.** `os.user` and `os.group` use the
  thread-scoped `setuid`/`setgid` the safe wrapper exposes, applied before the
  runtime spawns a second thread. On other Unixes the setting is reported as
  unsupported rather than silently ignored. `os.rlimit_nofile` works
  everywhere.
- **User and group lookups read `/etc/passwd` and `/etc/group`.** A numeric id
  is used directly. Names defined only through NSS — LDAP, for instance — are
  not resolved; the container this ships in has a plain passwd file.
- **Refresh-ahead on a popular name.** Not an AdGuard Home feature, and given
  no config key of its own on purpose: adding one would change the file
  `reproduces_the_reference_config_byte_for_byte` guards. An entry in the last
  tenth of its TTL that has been served more than once is fetched again before
  it expires, so a name under constant query is never served stale at all. It
  is gated on `cache_optimistic` — the setting that says a stale answer is
  acceptable in the first place — so with optimistic caching off the cache
  behaves exactly as the Go build's does. A refresh calls `Resolver::forward`
  directly and never `Server::handle`, so it is not rate limited, not counted
  in `/control/stats` and not written to `querylog.json`: the Go build logs six
  lines for six client queries over a name it refreshed four times, and so does
  this one. The queue holds 1024 jobs with 32 running at once, and a job is
  dropped rather than queued when it is full — no client ever waits on somebody
  else's refresh.
- **A changed listener *port* still needs a restart.** The certificate is
  live-reloadable; which ports are bound is decided when the listeners start.
  Everything else on the DNS settings page now applies without one.
- **A certificate renewed on disk is picked up without being told.** The Go
  build reads `certificate_path` and `private_key_path` once, at startup and
  whenever the config is saved, so a certbot renewal is served only after the
  next restart — a deployment that never restarts serves an expired
  certificate. `docs/encryption.md` had already promised otherwise, which is
  what turned this up. When either path is set, the maintenance tick digests
  what the files hold and installs a pair that differs from the one being
  served; inline PEM is left alone, because it can only change through
  `/control/tls/configure`, which installs it itself. No config key: the file
  `reproduces_the_reference_config_byte_for_byte` guards must not grow one.
  Three things make it safe to run on a timer rather than on a signal. The new
  pair has to parse and prove itself against rustls before anything is
  installed, so a renewal caught between its two files replaces nothing and is
  retried a minute later. The comparison is of contents, not mtime, so a
  renewal script that rewrites both files nightly costs one digest rather than
  a rebuilt signing key. And the same failure is logged once rather than every
  minute, so a genuinely broken pair does not bury the log. The watch runs only
  when encrypted listeners actually started: installing into a slot nothing
  serves would log a reload that reached nobody.

---

## Not implemented

Nothing outstanding. The features listed under **Deliberate exclusions** above
are decisions rather than gaps, and each refuses clearly at the point a user
would notice.

### Weighed while keeping connections, and left alone

Designed, costed, and not built, because each buys less than it risks once the
handshakes are gone. Recorded so the next person does not re-derive them.

- **A circuit breaker on `pool::Member`.** A dead upstream still costs the full
  `upstream_timeout` on the query that discovers it, every time, because
  `failures` decays only on success and a member demoted by `score()` is never
  chosen again to earn one. Time-decayed failures plus an open/half-open state
  would turn that into one slow query per backoff window. The reason to wait is
  that it has to fail *open* when every member is broken, or a transient blip
  becomes a total outage, and that is worth measuring rather than reasoning
  about. Note `record_success` is a load-then-store, not a CAS, so concurrent
  successes lose updates; fix that with it.
- **Hedging the second-best upstream** once the chosen one passes its own p90.
  Worth roughly 6× on the upstream p99 for ~10% more upstream queries, which
  is a real trade to make deliberately and not a free win.
- **A pool of UDP source sockets.** `udp_exchange` binds and closes a socket
  per query: ~8-10 µs of syscalls on a path that then waits 50 ms for the
  network, so it is a throughput item and not a latency one. It also trades
  away source-port entropy, which is a defence against off-path spoofing.
  Not worth paying that for a win that does not show up in p50, p90 or p99.
- **`loadgen` is closed-loop**, so its tail figures understate stalls: when the
  server stops answering the generator stops offering load. Anything measured
  with it should be read as a floor, the numbers above included.
- **The HTTP/1.1 DoH fallback has no test.** It is reviewed by reading only;
  every reachable DoH server negotiates h2, so exercising it needs an h1-only
  local server that nothing else in the tree wants.

## Found debugging a Mac that could not resolve Cloudflare, and fixed

`curl https://api.cloudflare.com` on macOS failed with `connect=0.000000s` —
never a TCP connection, so `getaddrinfo` had failed before it. `github.com`
worked. Chrome worked for both, and so did `dig`. The pattern was the tell:
**every failing name was DNSSEC-signed** (Cloudflare signs by default, and
`github.com` does not), Chrome speaks DoH to this server directly and never
asks macOS, and `dig` prints whatever arrives rather than judging its shape.

**Every answer carried whatever the upstream said, not an answer to the
client's question.** `forward` sets the `DO` bit on every upstream query while
`enable_dnssec` is on — which is the point of the setting — and the response
went back to the client unchanged. So a plain `A` query, `DO` never set, was
answered with an `RRSIG` in the answer section. RFC 4035 3.2.1 forbids that,
and macOS's `mDNSResponder` enforces it: a response carrying records it did not
ask for is discarded, question and all.

Measured against a real `adguard/adguardhome:v0.107.79` on the same upstream,
one query shape per row. Four divergences, all of them in the same family:

| a plain `A` query for a signed name | Go v0.107.79 | before | after |
|---|---|---|---|
| answer section | `A A` | `A A RRSIG` | `A A` |
| authority section of a negative answer | `SOA` | `SOA RRSIG NSEC RRSIG` | `SOA` |
| `AD` bit, client asked for neither `DO` nor `AD` | clear | set | clear |
| OPT record, request carried none | absent | `udp=512 do=1` | absent |
| OPT record, request advertised 1400 | `udp=1400 do=0` | `udp=512 do=1` | `udp=1400 do=0` |

`msg::shape_to_request` is the fix, called from the one `finish` closure every
path out of `Resolver::resolve` returns through — so a path added later cannot
forget it, and the query log and statistics, which observe the outcome
afterwards, record what the client was actually sent. A running Go build stores
the same: its `querylog.json` holds `A A` for a plain query and keeps the
`RRSIG` only for the entries whose client set `DO`.

Four rules, each measured rather than inferred:

- **Signatures go only to a client that set `DO`.** `RRSIG`, `DNSKEY`, `DS`,
  `NSEC` and `NSEC3` are dropped from all three sections — the RFC 4035 and RFC
  5155 set, deliberately not hickory's `RecordType::is_dnssec`, which also
  counts `TSIG` and `SIG`.
- **Except the question's own type.** A `DNSKEY` question is answered with its
  keys whatever `DO` says — they are the answer — while the `RRSIG` over them is
  not. Confirmed against the Go build for `DNSKEY`, `DS` and `NSEC` questions.
- **`AD` is cleared unless the client set `DO` or `AD`** (RFC 6840 5.7). The Go
  build answers a signed name `ad=0` when neither is set, `ad=1` when `AD`
  alone is — and `ad=0` for an unsigned name either way, so it is passing the
  upstream's verdict through rather than echoing the request.
- **The OPT record is the client's, not the upstream's.** No OPT in, no OPT out;
  one in, and the answer carries the request's own `DO` bit and advertised
  size. The Go build echoes 512, 1400 and 4096 back unchanged, and adds an OPT
  to answers it built itself — a `NOTIMP` from `refuse_any` included, which
  this now does too.

`tests/compat/dnssec_diff.py` is the guard, run by `scripts/verify.sh`: seven
names by five request forms, comparing the shape of both servers' answers
rather than their contents, since a CDN may hand the two different addresses
but cannot make one of them volunteer an `RRSIG`. All 35 agree. Fourteen tests in
the tree cover it without the oracle — five in `msg.rs`, five in `edns.rs`, and
four in `tests/forward.rs` driving a fake upstream that answers the way a
signed name is answered, including that the cache keeps the whole answer while
each client is handed its own shape of it.

**Two divergences this turned up**, both found while comparing shapes and both
fixed in their own pass afterwards: UDP truncation, below, and
`_dns.resolver.arpa` being forwarded when there is nothing to answer with —
see *Found comparing answer shapes, and fixed* below.

## Found comparing answer shapes, and fixed

### A UDP answer was not cut to what the client could receive

`server::truncate_if_needed` compared the encoded answer against a fixed 4 KB
and, if it was over, **threw away every record** and returned a header with the
truncation bit set. So a client that advertised 512 bytes was sent a 2,539-byte
`cloudflare.com TXT` answer with `TC` clear — a datagram the network may drop
whole, and one that is fragmented above the path MTU, which firewalls do drop —
while `adobe.com TXT`, whose full answer is 6 KB, came back as 27 bytes holding
nothing at all.

Both halves are now right: the limit comes from the request, and what fits is
kept rather than discarded. `msg::truncate` finds the longest prefix of the
answer, authority and additional sections that encodes inside the limit, by
halving rather than by adding up record lengths — names are compressed as they
are written, so what a record costs depends on what is already in the message,
and the only honest measure is to encode it. The prefix, and emptying the
sections behind a half-full one, is what `miekg/dns`'s `Msg.Truncate` leaves.
The OPT record is never dropped: it is not an answer.

It runs in the same `finish` closure as `shape_to_request`, not at the listener,
because a running Go build **logs the truncated answer** — its `querylog.json`
held 2,039 bytes and 26 records for the query it answered with 2,039 bytes and
26 records, and 488 bytes and 6 for the same question from a client advertising
512. The query log shows what the client got.

| `adobe.com TXT`, 74 records, 6,022 bytes whole | Go v0.107.79 | before | after |
|---|---|---|---|
| client advertised 512 | 469B `TC` | 2,539B, no `TC` | 487B `TC` |
| client advertised 1400 | 1,354B `TC` | 2,539B, no `TC` | 1,319B `TC` |
| client advertised 4096 | 4,019B `TC` | **27B**, nothing kept | 4,046B `TC` |
| client advertised 8192 | 6,022B | 6,022B | 6,022B |
| over TCP | 6,011B | 6,011B | 6,011B |

Record counts differ from the Go build's by one or two at the same limit, and
that is not a difference in behaviour: each server holds its own cached copy of
the upstream's answer and a TXT set comes back in a different order each time,
so how many fit is a fact about the records rather than about the server. Both
answers are the most that fits.

**The limit for a client that sent no OPT record is 512 here, and 2,048 in the
Go build.** That is a deliberate deviation, recorded under *Deliberate
deviations*. The 2,048 was measured before it was explained: sweeping advertised
sizes put it inside `[2046, 2061)` across seven names, and `dropbox.com`'s
2,046-byte answer ruled out 2,000. The cause is in dnsproxy — `addDO` gives a
request with no OPT record one of `OPT(2048, DO)` on its way upstream, and
`scrub` then reads the client's limit back out of the request it just edited
with `dnsSize(isUDP, dctx.Req)`. It is an artifact, and a conditional one:
turning `enable_dnssec` off, or the cache off, and the Go build cuts the same
answer to 512 like everything else. Measured:

| Go v0.107.79, `adobe.com TXT`, client sent no OPT | no-EDNS limit |
|---|---|
| `enable_dnssec: true`, `cache_enabled: true` | 2,048 (2,018B, 25 records) |
| `enable_dnssec: false`, `cache_enabled: true` | 512 (466B, 6 records) |
| `enable_dnssec: false`, `cache_enabled: false` | 512 (479B, 5 records) |
| `enable_dnssec: true`, `cache_enabled: false` | 512 (503B, 5 records) |

Reproducing it would mean deliberately sending a 2 KB datagram to a client that
never said it could take one, in exactly one of four configurations, and
fragmenting it on the way. `dnsSize` — `max(512, advertised)` — is what the Go
code means, and it is what this build does.

`tests/compat/truncate_diff.py` is the guard, run by `scripts/verify.sh`. It
compares a property rather than bytes, for the ordering reason above: that the
answer fits, that `TC` is set when and only when something was left out, and
that a stream transport is not cut. Run against **v0.7.2** it reports 35
problems, the bug itself among them — `2539 bytes for a client that asked for
512`. Nine tests cover it without the oracle: six in `msg.rs`, including that
one more record would not have fitted, and three in `tests/forward.rs` for the
transports.

One thing hickory will not reproduce: `Edns::set_max_payload` floors what it
stores at 512, so a request advertising 128 is answered with an OPT record
saying 512 where the Go build echoes 128. RFC 6891 6.2.3 makes the two mean the
same thing, and the floor is the reason the limit is right.

### A discovery query was answered by the upstream

`_dns.resolver.arpa` is how a client asks which encrypted transports *this*
resolver offers. `app::ddr_endpoints` returned `None` when there was no
certificate or no encrypted listener, `Settings::ddr` was that `Option`, and the
resolver's step 4 read it as "is DDR handled" — so a server with nothing to
advertise forwarded the query. Quad9 answered it, with **its own** three `SVCB`
records and their address glue, and a client acting on that discovery stops
talking to this server at all. The answer a plain `A` for the same name got was
the upstream's negative one.

The two questions are now separate, which is the whole fix: `Settings::handle_ddr`
decides whether the name is answered here, and `Settings::ddr` decides whether
the answer carries anything. `ddr::respond` already returned an empty `NOERROR`
for a question it had nothing for — it was never reached.

Measured against the Go build, `handle_ddr: true` and no TLS configured:

| `_dns.resolver.arpa` | Go v0.107.79 | before | after |
|---|---|---|---|
| `SVCB` | empty `NOERROR`, 47B | `SVCB`×3 + glue, **from Quad9** | empty `NOERROR` |
| `A`, `AAAA`, `HTTPS` | empty `NOERROR` | the upstream's `SOA` | empty `NOERROR` |
| `resolver.arpa`, `foo.resolver.arpa` | forwarded | forwarded | forwarded |

The control that settles it: with `handle_ddr: false` the Go build forwards the
name, and its answers are then byte-for-byte what this build used to give — 418
bytes for the `SVCB` and 88 for the `A`. So the old behaviour was not a
different reading of DDR, it was DDR switched off by accident whenever there was
nothing to advertise.

`tests/compat/ddr_diff.py` is the guard, run by `scripts/verify.sh` with
`handle_ddr: true` written into the seeded config so it cannot pass vacuously.
Against **v0.7.2** it reports the forwarded `SVCB` records and all three other
types. Two tests cover it in the tree, one for the name being answered whatever
the type and one for the rest of `resolver.arpa` still being forwarded, so an
over-eager fix fails as loudly as the missing one did.

### Rate limiting applied to every transport, and upstream limits UDP alone

Found while writing those harnesses: one firing a few hundred queries at the
fixture's `ratelimit: 20` lost TCP answers at random, which is exactly what a
real busy NAT looks like. `Server::handle_as` checked the limiter before it
parsed anything, whatever the protocol. dnsproxy gates it on the transport:

```go
// ratelimit based on IP only, protects CPU cycles and outbound connections
if d.Proto == ProtoUDP && p.isRatelimited(ip) {
	// Don't reply to ratelimited clients.
	return nil
}
```

Which is the right shape, and the reason is the same one `Proto::is_datagram`
already carries for access control: the limit exists so a spoofed datagram
cannot be turned into amplification — the attacker puts a victim's address in
the source field and the answer goes there — and a client that completed a
handshake cannot do that, because the address it claims is the one the packets
came back to. So `handle_as` now reads
`proto.is_datagram() && !self.limiter.allow(client.ip())`.

The cost of getting it wrong was not a slower client, it was a silent one.
Measured against the Go build, both at `ratelimit: 20`, 60 queries from one
address:

| 60 queries from one address | Go v0.107.79 | before | after |
|---|---|---|---|
| UDP | 58 answered, 2 dropped | 58 answered, 2 dropped | 58 answered, 2 dropped |
| TCP, a connection each | **60 answered** | 20 answered, **40 closed with no answer** | 60 answered |
| TCP, one kept-alive connection | **60 answered** | 20 answered, then 34 writes failed outright | 60 answered |

The last row is the one that would have been reported as a broken server: the
connection is torn down mid-conversation, so the client's next question cannot
even be written, let alone refused.

`tests/compat/ratelimit_diff.py` is the guard. It is the only harness that
*changes* a setting — the limit has to be on to be visible, and `verify.sh`
seeds it off so nothing else is throttled — so it sets `ratelimit` through
`/control/dns_config`, measures, and puts the old value back, which is also why
`verify.sh` runs it last among the DNS comparisons. Putting it back walks
`ratelimit` through the config round-trip the step after it checks, so that came
free. Against **v0.7.2** it reports both stream rows. Two tests cover it in the
tree, beside the datagram one that was already there: one asserting eight
queries in a row are answered over each of TCP, DoT, DoH and DoQ, and one that
floods the limiter over UDP and then asks over TCP, so a shared limiter that
spends a connection's allowance on datagrams fails.

## Found in a running server's log, and fixed

A running server's log filled with one line, twice a second:

```
WARN Illegal SNI extension: ignoring IP address presented as hostname (3131382e37312e3133342e313436)
```

The hex decodes to `118.71.134.146`: a client had put an IP address where a
hostname belongs, in the SNI extension of its ClientHello, and rustls writes
that warning once per handshake. Something was reconnecting twice a second, and
nothing else in the log survived it.

The message is about the **peer's** message rather than this server's
configuration, and nothing an operator can do changes it: rustls decides on its
own terms whether to carry on. It is not even a lead. SNI names the *server*, so
the address in it is this server's own as the client reached it — the warning
never said who was connecting. A DoT client that goes on to ask something is in
the query log with its address and `dot`; one that only handshakes is recorded
nowhere. Either way the log line is the same.

So the default filter now carries `rustls::msgs=error` alongside `rustls=warn`,
which is the whole of rustls' message *parsing*: every warning in that module
reports a malformed handshake received from somewhere else. Warnings from the
rest of rustls — the ones about this server's own certificates and keys — still
come through.

`DEP_FILTER` in `crates/sift/src/main.rs` is now one constant that
`init_logging` and the filter tests share, so the two cannot drift.
`a_peers_malformed_handshake_does_not_flood_the_log` asserts both halves, under
`--verbose` as well as without it: a WARN from `rustls::msgs::handshake` is
dropped, and a WARN from `rustls` is not. `RUST_LOG` still overrides all of it
for anyone debugging a handshake.

### Quieting the log was not the mitigation

The log was the symptom. What the source was actually costing was **a TLS
handshake per connection** — the most expensive thing an unauthenticated
stranger can make this process do — as fast as it cared to reconnect.

The rate limiter could not be pointed at it, and must not be: it is a defence
against *datagram* amplification and deliberately leaves a connection alone,
because limiting streams by rate is exactly the bug the commit before this one
fixed — every client behind one busy address cut off, silently.

What separates a scanner from a busy client is not the rate. **It is that a
real client asks something.** A DoT client opens a connection in order to send
a query; a scanner handshakes, learns what it came for, and leaves. So
`sift-dns/src/probe.rs` counts only the connections that were answered
*nothing at all*: six within a minute and the source is refused for ten
minutes, before the handshake rather than after it, and a single answered query
clears its record. A NAT is answering queries by definition, so it cannot be
shut out — which is the property the rate-limit version of this got wrong.

Four decisions in it, each because the obvious version is worse:

- **The strikes decay.** A liveness monitor that connects once a minute to see
  whether the port is up looks exactly like a scanner to a cumulative counter.
  `connections_spread_out_do_not_accumulate` runs fifty such connections and
  fails if any of them is refused.
- **A local address is never counted.** The threat is the internet, and the
  LAN is where an operator's own probes come from. Only the tests turn this
  off, through `exempt_local`, so the refusal can be driven over loopback.
- **An unvalidated QUIC address is never counted.** A QUIC initial packet can
  carry a forged source, so a spoofer could otherwise lock a victim out of DoQ.
  The strike is recorded only once the handshake has proved the address; over
  TCP the accept has already done that, so a handshake that never completes
  counts there and not here.
- **Bytes that do not parse as a query buy no exemption.** `serve_stream`
  counts a query only when an answer was written, so junk on the wire is
  silence. A client refused by the access list *does* count — it is answered
  REFUSED, which makes it a client this server knows about.

Wired into all four stream listeners, so the mitigation is not one transport's:
`serve_tcp` and `serve_dot` in `sift-dns/src/server.rs`, `doq::serve`, and
`https::serve` with `http3::serve` in `sift-api`, where any single request —
a DoH query, a page, an asset — counts as asking something. The plain-HTTP web
listener is left alone.

The operator's escape hatch is `ratelimit_whitelist`, reused rather than a
setting of our own: adding a field to `AdGuardHome.yaml` that the Go build does
not write would break the file's round trip for the sake of a defence that
needs no tuning. `strikes: 0` switches the guard off for anyone who wants that
in a fork.

Eleven tests, eight over the guard's own decisions and three over the
listeners: `a_connection_that_asks_nothing_costs_a_strike_and_a_query_clears_it`
drives a real TCP listener and asserts both directions, and
`a_refused_source_is_closed_before_the_handshake` asserts the client sees
end-of-file rather than a certificate — the handshake is the cost, so a
mitigation that refused *after* it would have saved nothing.

It is documented for operators under *Scanners* in `docs/encryption.md`,
because a source being refused for ten minutes is behaviour someone has to be
able to find an explanation for. **It is not a substitute for a firewall**: it
caps what a scanner costs, and says nothing about who should be able to reach
the port at all.
