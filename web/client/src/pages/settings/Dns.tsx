import { useState } from 'react';

import * as api from '../../api';
import type { AccessList, BlockingMode, DnsConfig, UpstreamMode } from '../../api';
import { Card, Check, Field, Loading, Notice, SaveButton, useToast } from '../../components/ui';
import { lines, unlines } from '../../lib/format';
import { message, useAsync } from '../../lib/hooks';

const UPSTREAM_MODES: { value: UpstreamMode; label: string; hint: string }[] = [
    {
        value: 'load_balance',
        label: 'Load balance',
        hint: 'Send each query to one server, preferring the ones that have been answering fastest.',
    },
    {
        value: 'parallel',
        label: 'Query all at once',
        hint: 'Ask every server together and take the first answer. Fastest, and the most traffic.',
    },
    {
        value: 'fastest_addr',
        label: 'Fastest address',
        hint: 'Ask every server and return the address that responds quickest, not the first answer back.',
    },
];

/** How an encrypted upstream is reached, in the scheme its address carries. */
type Transport = 'https' | 'tls' | 'quic';

const TRANSPORTS: { value: Transport; label: string }[] = [
    { value: 'https', label: 'DNS-over-HTTPS' },
    { value: 'tls', label: 'DNS-over-TLS' },
    { value: 'quic', label: 'DNS-over-QUIC' },
];

/**
 * A handful of public resolvers that answer over an encrypted transport, for
 * adding one without looking its address up.  Deliberately short: the ones
 * people ask for, each in the variants its operator publishes.  Every one
 * speaks DNS-over-HTTPS; the other transports only where the operator runs
 * them.  An unfiltered variant comes first, since filtering is this server's
 * job and a filtering upstream answers for names it never shows in the log.
 */
const KNOWN_UPSTREAMS: { provider: string; variants: { name: string; addr: Partial<Record<Transport, string>> }[] }[] = [
    {
        provider: 'Cloudflare',
        variants: [
            {
                name: 'Unfiltered',
                addr: { https: 'https://cloudflare-dns.com/dns-query', tls: 'tls://one.one.one.one' },
            },
            {
                name: 'Blocks malware',
                addr: {
                    https: 'https://security.cloudflare-dns.com/dns-query',
                    tls: 'tls://security.cloudflare-dns.com',
                },
            },
            {
                name: 'Blocks malware and adult sites',
                addr: { https: 'https://family.cloudflare-dns.com/dns-query', tls: 'tls://family.cloudflare-dns.com' },
            },
        ],
    },
    {
        provider: 'Google',
        variants: [{ name: 'Unfiltered', addr: { https: 'https://dns.google/dns-query', tls: 'tls://dns.google' } }],
    },
    {
        provider: 'Quad9',
        variants: [
            {
                name: 'Unfiltered',
                addr: { https: 'https://dns10.quad9.net/dns-query', tls: 'tls://dns10.quad9.net' },
            },
            { name: 'Blocks malware', addr: { https: 'https://dns.quad9.net/dns-query', tls: 'tls://dns.quad9.net' } },
        ],
    },
    {
        provider: 'AdGuard DNS',
        variants: [
            {
                name: 'Unfiltered',
                addr: {
                    https: 'https://unfiltered.adguard-dns.com/dns-query',
                    tls: 'tls://unfiltered.adguard-dns.com',
                    quic: 'quic://unfiltered.adguard-dns.com',
                },
            },
            {
                name: 'Blocks ads and trackers',
                addr: {
                    https: 'https://dns.adguard-dns.com/dns-query',
                    tls: 'tls://dns.adguard-dns.com',
                    quic: 'quic://dns.adguard-dns.com',
                },
            },
            {
                name: 'Blocks ads, trackers and adult sites',
                addr: {
                    https: 'https://family.adguard-dns.com/dns-query',
                    tls: 'tls://family.adguard-dns.com',
                    quic: 'quic://family.adguard-dns.com',
                },
            },
        ],
    },
    {
        provider: 'Mullvad',
        variants: [
            { name: 'Unfiltered', addr: { https: 'https://dns.mullvad.net/dns-query', tls: 'tls://dns.mullvad.net' } },
            {
                name: 'Blocks ads and trackers',
                addr: { https: 'https://adblock.dns.mullvad.net/dns-query', tls: 'tls://adblock.dns.mullvad.net' },
            },
        ],
    },
    {
        provider: 'OpenDNS',
        variants: [
            { name: 'Unfiltered', addr: { https: 'https://doh.opendns.com/dns-query' } },
            { name: 'Blocks adult sites', addr: { https: 'https://doh.familyshield.opendns.com/dns-query' } },
        ],
    },
];

const BLOCKING_MODES: { value: BlockingMode; label: string; hint: string }[] = [
    { value: 'default', label: 'Default', hint: 'Answer with the null address, or with whatever the matching rule says.' },
    { value: 'refused', label: 'REFUSED', hint: 'Refuse the query outright.' },
    { value: 'nxdomain', label: 'NXDOMAIN', hint: 'Answer that the name does not exist.' },
    { value: 'null_ip', label: 'Null address', hint: 'Always answer 0.0.0.0 and ::, whatever the rule says.' },
    { value: 'custom_ip', label: 'A chosen address', hint: 'Answer every blocked name with the addresses below.' },
];

export default function Dns() {
    const toast = useToast();
    const dns = useAsync(() => api.getDnsConfig());
    const access = useAsync(() => api.getAccessList());

    if (!dns.data || !access.data) {
        return dns.error ? <Notice kind="error">{dns.error}</Notice> : <Loading />;
    }

    const save = async (patch: Partial<DnsConfig>, ok = 'Saved') => {
        try {
            await api.setDnsConfig(patch);
            await dns.reload();
            toast.ok(ok);
        } catch (e) {
            toast.fail(message(e));
        }
    };

    return (
        <>
            <div className="page-head">
                <h1>DNS settings</h1>
            </div>

            <Upstreams config={dns.data} save={save} />
            <Cache config={dns.data} save={save} />
            <Server config={dns.data} save={save} />
            <Access list={access.data} reload={access.reload} />
        </>
    );
}

type Save = (patch: Partial<DnsConfig>, ok?: string) => Promise<void>;

function Upstreams({ config, save }: { config: DnsConfig; save: Save }) {
    const toast = useToast();
    const [upstream, setUpstream] = useState(unlines(config.upstream_dns));
    const [bootstrap, setBootstrap] = useState(unlines(config.bootstrap_dns));
    const [fallback, setFallback] = useState(unlines(config.fallback_dns));
    const [privatePtr, setPrivatePtr] = useState(unlines(config.local_ptr_upstreams));
    const [mode, setMode] = useState<UpstreamMode>(config.upstream_mode || 'load_balance');
    const [results, setResults] = useState<Record<string, string>>();
    const [testing, setTesting] = useState(false);

    const test = async () => {
        setTesting(true);
        setResults(undefined);
        try {
            setResults(
                await api.testUpstream({
                    upstream_dns: lines(upstream),
                    bootstrap_dns: lines(bootstrap),
                    fallback_dns: lines(fallback),
                    private_upstream: lines(privatePtr),
                }),
            );
        } catch (e) {
            toast.fail(message(e));
        } finally {
            setTesting(false);
        }
    };

    return (
        <Card title="Upstream servers">
            <Field hint="One address per line. Plain UDP or TCP, tls://, https:// and quic:// are all understood, and a line may be scoped to a domain with [/example.org/]server.">
                <textarea
                    value={upstream}
                    spellCheck={false}
                    placeholder="https://dns.quad9.net/dns-query"
                    onChange={(e) => setUpstream(e.target.value)}
                />
            </Field>

            <KnownUpstream
                onAdd={(addr) => {
                    const current = lines(upstream);
                    if (current.includes(addr)) {
                        toast.ok(`${addr} is already in the list`);
                    } else {
                        setUpstream(unlines([...current, addr]));
                    }
                }}
            />

            {config.upstream_dns_file && (
                <Notice kind="info">
                    More servers are read from <span className="mono">{config.upstream_dns_file}</span> and are not
                    editable here.
                </Notice>
            )}

            <div className="field">
                <span className="field-label">How they are used</span>
                {UPSTREAM_MODES.map((m) => (
                    <label className="check" key={m.value}>
                        <input
                            type="radio"
                            name="upstream_mode"
                            checked={mode === m.value}
                            onChange={() => setMode(m.value)}
                        />
                        <span className="text">
                            <b>{m.label}</b>
                            <div className="hint">{m.hint}</div>
                        </span>
                    </label>
                ))}
            </div>

            <Field
                label="Bootstrap servers"
                hint="Plain addresses used to resolve the hostnames of the encrypted upstreams above. One per line.">
                <textarea value={bootstrap} spellCheck={false} onChange={(e) => setBootstrap(e.target.value)} />
            </Field>

            <Field label="Fallback servers" hint="Tried only when every upstream above fails to answer.">
                <textarea value={fallback} spellCheck={false} onChange={(e) => setFallback(e.target.value)} />
            </Field>

            <Field
                label="Private reverse DNS servers"
                hint="Where to send reverse lookups for addresses on your own network. Left empty, Sift uses whatever the system resolver is configured with.">
                <textarea value={privatePtr} spellCheck={false} onChange={(e) => setPrivatePtr(e.target.value)} />
            </Field>

            <Check
                checked={config.use_private_ptr_resolvers}
                label="Resolve private addresses with those servers"
                hint="With this off, a reverse lookup for a private address is answered NXDOMAIN instead of being forwarded."
                onChange={(v) => void save({ use_private_ptr_resolvers: v })}
            />
            <Check
                checked={config.resolve_clients}
                label="Look up client names"
                hint="Sends a reverse lookup for each client so the log and the dashboard can show a name rather than an address."
                onChange={(v) => void save({ resolve_clients: v })}
            />

            {results && (
                <div className="stack" style={{ margin: '14px 0' }}>
                    {Object.entries(results).map(([server, status]) => (
                        <div key={server} className={`notice ${status === 'OK' ? 'ok' : 'error'}`}>
                            <div>
                                <span className="mono">{server}</span> — {status === 'OK' ? 'answered' : status}
                            </div>
                        </div>
                    ))}
                </div>
            )}

            <div className="btn-row">
                <SaveButton
                    onClick={() =>
                        save(
                            {
                                upstream_dns: lines(upstream),
                                bootstrap_dns: lines(bootstrap),
                                fallback_dns: lines(fallback),
                                local_ptr_upstreams: lines(privatePtr),
                                upstream_mode: mode,
                            },
                            'Upstream servers saved',
                        )
                    }>
                    Apply
                </SaveButton>
                <button type="button" className="btn" disabled={testing} onClick={() => void test()}>
                    {testing && <span className="spinner" style={{ width: 13, height: 13, borderWidth: 2 }} />}
                    Test these servers
                </button>
            </div>
        </Card>
    );
}

/** Picks one of `KNOWN_UPSTREAMS` and hands its address over; nothing is saved until Apply. */
function KnownUpstream({ onAdd }: { onAdd: (addr: string) => void }) {
    const [pick, setPick] = useState('0:0');
    const [transport, setTransport] = useState<Transport>('https');

    const [p, v] = pick.split(':').map(Number);
    const variant = KNOWN_UPSTREAMS[p!]!.variants[v!]!;
    // Every variant speaks HTTPS, so a transport it lacks falls back to that.
    const addr = variant.addr[transport] ?? variant.addr.https!;

    return (
        <div className="field">
            <span className="field-label">Add a public server</span>
            <div className="row">
                <select
                    value={pick}
                    aria-label="Public server"
                    style={{ width: 'auto', flex: '1 1 220px' }}
                    onChange={(e) => setPick(e.target.value)}>
                    {KNOWN_UPSTREAMS.map((k, pi) => (
                        <optgroup key={k.provider} label={k.provider}>
                            {k.variants.map((x, vi) => (
                                <option key={x.name} value={`${pi}:${vi}`}>
                                    {k.provider} · {x.name}
                                </option>
                            ))}
                        </optgroup>
                    ))}
                </select>
                <select
                    value={variant.addr[transport] ? transport : 'https'}
                    aria-label="Transport"
                    style={{ width: 'auto', flex: '0 1 auto' }}
                    onChange={(e) => setTransport(e.target.value as Transport)}>
                    {TRANSPORTS.map((t) => (
                        <option key={t.value} value={t.value} disabled={!variant.addr[t.value]}>
                            {t.label}
                        </option>
                    ))}
                </select>
                <button type="button" className="btn" onClick={() => onAdd(addr)}>
                    Add
                </button>
            </div>
            <div className="hint mono">{addr}</div>
        </div>
    );
}

function Cache({ config, save }: { config: DnsConfig; save: Save }) {
    const [size, setSize] = useState(config.cache_size);
    const [min, setMin] = useState(config.cache_ttl_min);
    const [max, setMax] = useState(config.cache_ttl_max);

    return (
        <Card title="Cache">
            <Field label="Size in bytes" hint="Zero turns the cache off entirely.">
                <input type="number" min={0} value={size} onChange={(e) => setSize(Number(e.target.value))} />
            </Field>
            <div className="grid grid-2">
                <Field label="Shortest lifetime, in seconds" hint="Holds an answer at least this long, whatever its own TTL says.">
                    <input type="number" min={0} value={min} onChange={(e) => setMin(Number(e.target.value))} />
                </Field>
                <Field label="Longest lifetime, in seconds" hint="Discards an answer after this long even if its TTL is longer. Zero means no limit.">
                    <input type="number" min={0} value={max} onChange={(e) => setMax(Number(e.target.value))} />
                </Field>
            </div>
            <Check
                checked={config.cache_optimistic}
                label="Serve expired answers while refreshing them"
                hint="A stale answer goes out immediately and the real one is fetched in the background, so a slow upstream never blocks a page load."
                onChange={(v) => void save({ cache_optimistic: v })}
            />

            <div style={{ marginTop: 10 }}>
                <SaveButton onClick={() => save({ cache_size: size, cache_ttl_min: min, cache_ttl_max: max })}>
                    Save
                </SaveButton>
            </div>
        </Card>
    );
}

function Server({ config, save }: { config: DnsConfig; save: Save }) {
    const [d, setD] = useState(config);
    const set = <K extends keyof DnsConfig>(k: K, v: DnsConfig[K]) => setD({ ...d, [k]: v });

    return (
        <Card title="Server">
            <div className="grid grid-2">
                <Field
                    label="Queries per second, per client"
                    hint="Plain UDP only, where a source address can be forged. Zero removes the limit."
                >
                    <input
                        type="number"
                        min={0}
                        value={d.ratelimit}
                        onChange={(e) => set('ratelimit', Number(e.target.value))}
                    />
                </Field>
                <Field label="Upstream timeout, in seconds">
                    <input
                        type="number"
                        min={1}
                        value={d.upstream_timeout}
                        onChange={(e) => set('upstream_timeout', Number(e.target.value))}
                    />
                </Field>
                <Field label="IPv4 prefix the limit counts by" hint="Clients inside one prefix share an allowance.">
                    <input
                        type="number"
                        min={0}
                        max={32}
                        value={d.ratelimit_subnet_len_ipv4}
                        onChange={(e) => set('ratelimit_subnet_len_ipv4', Number(e.target.value))}
                    />
                </Field>
                <Field label="IPv6 prefix the limit counts by">
                    <input
                        type="number"
                        min={0}
                        max={128}
                        value={d.ratelimit_subnet_len_ipv6}
                        onChange={(e) => set('ratelimit_subnet_len_ipv6', Number(e.target.value))}
                    />
                </Field>
            </div>

            <Field label="Clients exempt from the limit" hint="One address per line.">
                <textarea
                    value={unlines(d.ratelimit_whitelist)}
                    spellCheck={false}
                    onChange={(e) => set('ratelimit_whitelist', lines(e.target.value))}
                />
            </Field>

            <div className="field">
                <span className="field-label">How a blocked query is answered</span>
                {BLOCKING_MODES.map((m) => (
                    <label className="check" key={m.value}>
                        <input
                            type="radio"
                            name="blocking_mode"
                            checked={d.blocking_mode === m.value}
                            onChange={() => set('blocking_mode', m.value)}
                        />
                        <span className="text">
                            <b>{m.label}</b>
                            <div className="hint">{m.hint}</div>
                        </span>
                    </label>
                ))}
            </div>

            {d.blocking_mode === 'custom_ip' && (
                <div className="grid grid-2">
                    <Field label="IPv4 to answer with">
                        <input value={d.blocking_ipv4} onChange={(e) => set('blocking_ipv4', e.target.value)} />
                    </Field>
                    <Field label="IPv6 to answer with">
                        <input value={d.blocking_ipv6} onChange={(e) => set('blocking_ipv6', e.target.value)} />
                    </Field>
                </div>
            )}

            <Field label="How long a client may cache a blocked answer, in seconds">
                <input
                    type="number"
                    min={0}
                    value={d.blocked_response_ttl}
                    onChange={(e) => set('blocked_response_ttl', Number(e.target.value))}
                />
            </Field>

            <Check
                checked={d.dnssec_enabled}
                label="Ask upstreams to validate DNSSEC"
                hint="Sets the DO bit on every outgoing query, so a device that asks for signatures is given them. The upstream has to support it."
                onChange={(v) => set('dnssec_enabled', v)}
            />
            <Check
                checked={d.disable_ipv6}
                label="Drop IPv6 lookups"
                hint="Answers every AAAA question with an empty response, which forces clients onto IPv4."
                onChange={(v) => set('disable_ipv6', v)}
            />
            <Check
                checked={d.edns_cs_enabled}
                label="Send the client's subnet upstream"
                hint="Passes a masked form of the client's address to the upstream so it can answer with a nearby server. Private and loopback addresses are never sent."
                onChange={(v) => set('edns_cs_enabled', v)}
            />
            {d.edns_cs_enabled && (
                <>
                    <Check
                        checked={d.edns_cs_use_custom}
                        label="Send a fixed subnet instead"
                        onChange={(v) => set('edns_cs_use_custom', v)}
                    />
                    {d.edns_cs_use_custom && (
                        <Field label="The subnet to send">
                            <input
                                value={d.edns_cs_custom_ip}
                                onChange={(e) => set('edns_cs_custom_ip', e.target.value)}
                            />
                        </Field>
                    )}
                </>
            )}

            <div style={{ marginTop: 12 }}>
                <SaveButton
                    onClick={() =>
                        save({
                            ratelimit: d.ratelimit,
                            ratelimit_subnet_len_ipv4: d.ratelimit_subnet_len_ipv4,
                            ratelimit_subnet_len_ipv6: d.ratelimit_subnet_len_ipv6,
                            ratelimit_whitelist: d.ratelimit_whitelist,
                            upstream_timeout: d.upstream_timeout,
                            blocking_mode: d.blocking_mode,
                            blocking_ipv4: d.blocking_ipv4,
                            blocking_ipv6: d.blocking_ipv6,
                            blocked_response_ttl: d.blocked_response_ttl,
                            dnssec_enabled: d.dnssec_enabled,
                            disable_ipv6: d.disable_ipv6,
                            edns_cs_enabled: d.edns_cs_enabled,
                            edns_cs_use_custom: d.edns_cs_use_custom,
                            edns_cs_custom_ip: d.edns_cs_custom_ip,
                        })
                    }>
                    Save
                </SaveButton>
            </div>
        </Card>
    );
}

/**
 * Access control, which is its own endpoint rather than part of `dns_config`.
 *
 * The three lists are sent together: `/control/access/set` replaces what it is
 * given, so leaving one out would clear it.
 */
function Access({ list, reload }: { list: AccessList; reload: () => Promise<void> }) {
    const toast = useToast();
    const [allowed, setAllowed] = useState(unlines(list.allowed_clients));
    const [disallowed, setDisallowed] = useState(unlines(list.disallowed_clients));
    const [hosts, setHosts] = useState(unlines(list.blocked_hosts));

    const save = async () => {
        try {
            await api.setAccessList({
                allowed_clients: lines(allowed),
                disallowed_clients: lines(disallowed),
                blocked_hosts: lines(hosts),
            });
            await reload();
            toast.ok('Access settings saved');
        } catch (e) {
            toast.fail(message(e));
        }
    };

    return (
        <Card title="Who may query" desc="Addresses, CIDR ranges and ClientIDs, one per line.">
            <Field
                label="Allowed clients"
                hint="With anything listed here, only these clients are served and everyone else is refused.">
                <textarea value={allowed} spellCheck={false} onChange={(e) => setAllowed(e.target.value)} />
            </Field>
            <Field label="Blocked clients" hint="Ignored entirely when the list above has entries.">
                <textarea value={disallowed} spellCheck={false} onChange={(e) => setDisallowed(e.target.value)} />
            </Field>
            <Field
                label="Refused names"
                hint="Not a filter list: a query for one of these is dropped before anything else happens and never reaches the query log. A bare name matches only itself; write ||name^ to catch its subdomains too."
            >
                <textarea value={hosts} spellCheck={false} onChange={(e) => setHosts(e.target.value)} />
            </Field>
            <SaveButton onClick={save}>Save</SaveButton>
        </Card>
    );
}
