# Clients

**Settings → Client settings** is where a device gets a name, its own filtering
rules, or its own upstreams. A client is either *persistent* — one you created,
identified by something stable — or *runtime*, which is just an address the
server has seen.

## How a client is identified

A persistent client carries a list of identifiers. Any one of them matching
makes the query that client's. Four forms are accepted:

| Identifier | Example | Matched against |
|---|---|---|
| Address | `192.168.1.42` | the query's source address |
| Subnet | `192.168.1.0/24` | the query's source address |
| MAC | `ac:de:48:00:11:22` | the ARP entry for the source address, if any |
| ClientID | `laptop` | the identifier the client sent (see below) |

When several persistent clients match one query, the **most specific**
identifier wins: a ClientID beats a MAC, which beats an exact address, which
beats a subnet — and among subnets, the longest prefix.

A MAC only matches when the operating system's ARP table already ties one to
the source address: a DNS query itself carries no hardware address. On anything
but the same link, it will not match.

## ClientID

An address is a poor identifier for a device that roams, and useless for one
behind NAT. A **ClientID** is a name the client sends with the query itself, so
the same device is recognised from anywhere.

It is a single DNS label: 1–63 characters, ASCII letters, digits and hyphens,
not starting or ending with a hyphen. Matching ignores case.

It can only be sent over an encrypted transport, because plain DNS has nowhere
to put it.

### DNS-over-HTTPS

Append it to the query path:

```
https://dns.example.org/dns-query/laptop
```

Or put it in the server name, as below. The path wins when both are given.

### DNS-over-TLS and DNS-over-QUIC

Put it in front of the server's own name in the TLS server name (SNI):

```
laptop.dns.example.org
```

This needs `tls.server_name` to be set, and a certificate that covers the
wildcard — `*.dns.example.org` alongside `dns.example.org`. Only the single
label directly below the server's own name is read: a name with more labels
under it, or an unrelated name, yields no identifier rather than having part of
it taken as one.

A label there that is not a valid ClientID — one with an underscore, say — is
answered `SERVFAIL` rather than ignored, as upstream answers it. With
`tls.strict_sni_check` on, so is every name other than the server's own and
one label below it; see [Strict SNI](encryption.md#strict-sni).

### Apple devices

**Setup guide → Encrypted DNS** takes a ClientID beside the host name and
writes it into the configuration profiles it offers, so an iPhone or a Mac that
installs one arrives already identified — over DNS-over-HTTPS in the query
path, and over DNS-over-TLS in the name it asks for.

### Access control

ClientIDs work in **Settings → DNS settings → Access settings** as well as
addresses: putting one in the allowed list admits that client from any address,
and putting one in the disallowed list refuses it from everywhere.

## Tags

A persistent client can carry tags, which `$ctag` filtering rules match
against — a rule can then apply to every device tagged `device_phone` without
naming each one. The available tags come from `/control/clients` and are shown
in the client form's tag selector.

See AdGuard's [filtering syntax reference][ctag] for the `$ctag` modifier
itself.

[ctag]: https://adguard-dns.io/kb/general/dns-filtering-syntax/#ctag-modifier

## Per-client settings

A persistent client with **Use global settings** cleared overrides, for its own
queries only:

- the filtering and safe search toggles.

Independently of that switch, clearing **Use global blocked services** gives the
client its own blocked-services list and its own schedule.

Two more per-client switches always apply: **Ignore query log** and **Ignore
statistics** keep the client's queries out of those records.

Which settings apply is worked out **before** the query is filtered, so an
override changes every later step, not just the verdict.

## Per-client upstreams

A persistent client given its own **Upstreams** resolves through those servers
instead of the global ones. The syntax is the same as
[the global field](configuration.md#upstreams), including the bracketed
`[/domain/]` groups, and `sdns://` is no more supported here than it is there.

Everything *around* the servers stays global: the bootstrap resolvers, the
upstream mode, the timeouts and the fallback servers. Only which servers are
asked changes, which is what AdGuard Home does too.

Two consequences worth knowing:

- **Cached answers do not cross over.** A name resolved through one client's
  own servers is stored against those servers, so a different client never
  receives it. That matters for split-horizon names, where the global
  resolvers and a company's internal ones answer the same question
  differently.
- **Clients sharing an upstream list share a pool.** Configure two devices with
  the same servers and they use one set of connections and one set of cache
  entries, because they are the same resolvers. Reordering the list makes it a
  different one.

Saving a change here reconnects those upstreams in the background. For the few
seconds that takes, the client's queries are answered from the global servers
rather than failing — and those answers are deliberately not cached, so nothing
from that window outlives it.
