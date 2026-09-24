# Encryption

**Settings → Encryption settings** turns on TLS. One certificate and one key
serve four listeners:

| Protocol | Port | Transport |
|---|---|---|
| Web interface over HTTPS | `tls.port_https` (443) | TCP |
| DNS-over-HTTPS | `tls.port_https` (443) | TCP, and UDP for HTTP/3 |
| DNS-over-TLS | `tls.port_dns_over_tls` (853) | TCP |
| DNS-over-QUIC | `tls.port_dns_over_quic` (853) | UDP |

DNSCrypt is not implemented and `tls.port_dnscrypt` is ignored.

## What you need

- **A certificate chain**, PEM, leaf first, then any intermediates. Pasted into
  the form or read from `tls.certificate_path`.
- **A private key**, PEM. RSA, ECDSA and Ed25519 are all accepted, in PKCS#1,
  SEC1 or PKCS#8 encoding. Pasted into the form or read from
  `tls.private_key_path`.
- **A server name** in `tls.server_name`, matching the certificate. Clients
  verify it, and it is also what makes [ClientIDs over DoT and
  DoQ](clients.md#clientid) work.

The form reports what it parsed — subject, validity window, whether the chain
and the key belong together — before you save, so a mismatch is caught without
restarting anything.

## Reloading

The listeners hold the certificate behind a shared slot, so replacing one takes
effect on the **next handshake**. No restart, and connections already open are
not disturbed.

Two things replace it:

- **Saving one** through Settings → Encryption settings, which installs it at
  once.
- **Rewriting the files.** When `tls.certificate_path` or
  `tls.private_key_path` is set, the files are compared with what is being
  served once a minute, and a changed pair is installed. This is what makes an
  ACME client's renewal reach the listeners: it rewrites the files on its own
  schedule and has no way to tell the server, and nothing in the configuration
  moves when it does.

A renewal that is caught halfway through — the new certificate beside the old
key — does not replace anything: the pair has to parse and belong together
first, and the check a minute later finds it whole. The same goes for a file
that is briefly missing. In both cases the certificate in use keeps being
served, and the log says what it saw.

A certificate with less than a week to run and nothing renewing it is reported
hourly, and an expired one as an error. Neither can be fixed from here — by
that point whatever was meant to renew it has stopped — but it is the last
chance to act before clients start refusing to connect.

Listener **ports** are read at startup. Changing one needs a restart.

## Getting a certificate

Any certificate works; nothing here talks to a CA. The two usual routes:

**Let's Encrypt, for a name that resolves publicly.** Use your preferred ACME
client and point `tls.certificate_path` and `tls.private_key_path` at what it
writes. A renewal is then picked up within a minute and served on the next
handshake, without touching the configuration and without a restart.

```yaml
tls:
  enabled: true
  server_name: dns.example.org
  certificate_path: /etc/letsencrypt/live/dns.example.org/fullchain.pem
  private_key_path: /etc/letsencrypt/live/dns.example.org/privkey.pem
```

For ClientIDs over DoT or DoQ the certificate also needs `*.dns.example.org`,
which means a DNS-01 challenge.

**Your own CA, for a name that does not.** Issue a certificate for the server
name, and install the CA certificate on every client that will use it.
Self-signed certificates that no client trusts will fail to connect rather than
warn, because DNS clients have nowhere to show a warning.

## Serving DoH without TLS

`http.doh.insecure_enabled` serves DNS-over-HTTPS over **plain HTTP**. It
exists for one case: a reverse proxy in front that terminates TLS itself. With
it off — the default — the DoH route answers only on the encrypted listener, so
an operator cannot expose queries in the clear by accident.

## Reachable from the internet

An encrypted listener that the internet can reach gets scanned, probed for
exploits, and occasionally used by strangers as a free resolver. The server
defends every port it listens on with TCP or QUIC — 443, 853 and 53/tcp —
without any setting to turn on.

Nothing here applies to **addresses on your own network**, which are never
counted, capped or refused. That means:

- loopback, link-local and unique-local addresses;
- the networks in `dns.private_networks` or, when that is empty, the usual
  private ranges (including `100.64.0.0/10`, which is Tailscale's);
- anything in `ratelimit_whitelist`.

Devices that reach the server at its own global IPv6 address are in the same
/64 as the server. They are not exempt, because on many hosting providers that
/64 is shared with other customers. Each of them is judged as its own address,
though, not as the /64 an internet source would be.

### Scanners

What tells a scanner from a client is that a client connects *in order to ask
something*. So the server counts only connections that asked nothing, and a
single answered question clears a source's record, unless it is already being
refused. A busy client, or a NAT with a hundred of them behind it, can
therefore never be shut out by connecting often.

A connection that closes within a second without sending a byte costs
nothing: that is what a port monitor does, whether it is Uptime Kuma's TCP
check or `nc -z`. Nor does an answer the server was too busy to give: a
`SERVFAIL` because a limit below was reached counts neither way.

A source that makes **six connections in a minute without asking anything** is
refused for **ten minutes**. Refused means its next connection is closed before
the TLS handshake, which is the expensive part. A source that comes back and
does it again within a day is refused for twice as long each time, up to a day.
One that stays away for a day is forgotten.

What counts as asking something:

- **DNS, on any transport:** a question that was answered. These do *not*
  count:
  - a question refused because `allowed_clients` or `disallowed_clients`
    turned the client away;
  - a question refused by `blocked_hosts` (`version.bind`, `id.server`,
    `hostname.bind` by default — exactly what scanners ask);
  - a malformed or unsupported question.
- **HTTPS:** a request answered with a status below 400. A path scanner that
  collects 401s and 404s asked nothing. A connection that gets 32 such answers
  in a row is closed.

An IPv6 source is judged as its **/64**. Every address in a /64 is free to
whoever holds it, so a scanner changing address inside it stays the same
source.

### Exploit probes

Some requests are only ever made by something looking for a way in:

- `/.env`, `/.git/…`
- `/wp-login.php`, `/phpmyadmin`, anything ending in `.php` (or `.phtml`,
  `.phar` and the numbered variants), `.asp`, `.jsp` or `.cgi`
- path traversal, a NUL byte, overlong UTF-8, and IIS's `%u` escapes, in any
  encoding
- a `CONNECT` request

On the HTTPS port, and over HTTP/3, such a request gets a plain 404, its
connection is closed, and the source is refused immediately, escalating the
same way. Nothing the web interface, the API or a DNS-over-HTTPS client asks
for can match.

### Limits

These bound what the internet may *hold* at once, never how fast it asks:

| What | Limit |
|---|---|
| Connections from one source (an IPv4 address, or an IPv6 /64) | 64 |
| Connections from the internet, all sources together | 4096, or half the file-descriptor limit if that is lower |
| TLS and QUIC handshakes in progress | 256 |
| DNS questions being answered for one source on TCP, DoT, DoH or DoQ | 32; more wait up to a second, then get `SERVFAIL` |

Reaching a limit is being busy, not being hostile. The connection is turned
away and nothing is held against the source. Under load, a new QUIC client is
first asked to prove its address with a Retry, which costs it one round trip.

The descriptor limit itself is raised at start-up to the hard limit, as the Go
build's runtime does. Under a systemd unit that means roughly half a million
rather than 1,024.

### Deadlines

| Where | Deadline |
|---|---|
| TLS handshake | 10 s |
| HTTPS: first request after the handshake | 10 s |
| HTTPS: request headers | 10 s |
| HTTPS: request body | 60 s |
| HTTPS: idle connection | 60 s |
| HTTPS: answer to a request | 5 min |
| DoT and TCP: rest of a message once it starts | 5 s |
| DoT and TCP: client reading its answer | 10 s |
| DoQ: query on a stream | 5 s |
| DoQ: client reading its answer | 10 s |

A connection that misses one is closed. If it had asked nothing, it counts
towards the six.

### Signing in

`auth_attempts` wrong passwords within a minute (5 by default) block a source
for `block_auth_min` minutes (15 by default), as with the Go build. The
differences:

- **An IPv6 source is its /64** here too.
- **Passwords from the internet are checked two at a time.** A sign-in that
  cannot be checked within 5 seconds is answered 429, and the sign-in page says
  to try again in a moment.
- **An attempt is counted before its password is checked,** so guesses sent all
  at once cannot slip past the limit together.

Sign-ins from your own network are checked at once and counted afterwards,
exactly as the Go build does it. A script there sending several at once, such
as Home Assistant's integration, is never turned away. That includes anything
arriving through a reverse proxy on the same machine, which the server sees as
local.

### What the log says

A refusal is logged once, with the client's address, which is what the rustls
handshake warnings never give you:

```text
INFO refusing a source that keeps connecting without asking anything client=198.51.100.7 connections=6 offence=1 seconds=600
INFO refusing a source for a request only an attacker makes client=203.0.113.9 reason="WordPress" offence=1 seconds=600
```

Reaching a limit is logged at most once a minute, with a count.
`GET /control/debug/memory` reports the running totals under `server.probes`:

- sources tracked and currently refused;
- connections and handshakes open;
- refusals and penalties since start.

If something legitimate connects without ever asking anything, such as an
unusual health check or a probe of your own, add its address to
`ratelimit_whitelist`. That exempts it from all of the above and from the rate
limiter, and takes effect as soon as the DNS settings are saved.

This is not a substitute for a firewall. It caps what a stranger can cost you;
it does not decide who should be able to reach the port in the first place.
For a resolver only you use, `allowed_clients` with
[ClientIDs](clients.md#clientid) is what does that.

## Strict SNI

`tls.strict_sni_check: true` refuses a DNS-over-TLS or DNS-over-QUIC client
whose server name the certificate does not cover. The names are the
certificate's DNS names, or its common name if it has none, and `*.example.org`
covers every name below `example.org`. A client that sends no name, or an IP
address, is refused as well. The refusal happens during the handshake, before
anything is signed, so a scanner dialling the port by address costs almost
nothing.

With `tls.server_name` set, every question over DoT, DoQ and DoH (when its
path carries no ClientID) is also checked against the name the client
connected with, as upstream checks it:

- one label below the server name is the [ClientID](clients.md#clientid);
- a label that is not a valid ClientID is answered `SERVFAIL`, strict or not;
- with strict on, any other name is answered `SERVFAIL` too.

The web interface and DNS-over-HTTPS are served whatever name the browser
used, as upstream serves them. The setting has no form in the interface; set
it in `AdGuardHome.yaml`. A saved change applies to the next handshake.

## Checking it works

```bash
# DNS-over-TLS
kdig -d @dns.example.org +tls-ca +tls-host=dns.example.org example.org

# DNS-over-HTTPS
curl -sS -H 'accept: application/dns-message' \
  'https://dns.example.org/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDb3JnAAABAAE'
```

A failure to verify is a certificate problem, not a DNS one: check that the
chain is complete and that the name you connected to is in it.
