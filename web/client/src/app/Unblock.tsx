import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import * as api from '../api';
import type { Filter, FilteringStatus, LogEntry } from '../api';
import { IconAllow, IconRefresh } from '../components/icons';
import { Loading, Modal, Notice, useToast } from '../components/ui';
import { message } from '../lib/hooks';

/**
 * The lists that have no entry under Filters, by the identifier the resolver
 * records against a rule.  These are upstream's `rulelist.APIID` values.
 */
export const RESERVED: Record<number, string> = {
    0: 'Custom rules',
    [-1]: 'System hosts file',
    [-2]: 'Blocked services',
    // Neither is produced any more; a log written by AdGuard Home has them.
    [-3]: 'Parental control',
    [-4]: 'Safe browsing',
};

/** Names the list a rule came from, falling back to its identifier. */
export function listNamer(status: FilteringStatus | undefined): (id: number) => string {
    const all = [...(status?.filters ?? []), ...(status?.whitelist_filters ?? [])];

    return (id) => RESERVED[id] ?? all.find((f) => f.id === id)?.name ?? `List ${id}`;
}

/**
 * Second-level labels a country-code TLD sells names under, as in
 * `example.co.uk`.  A heuristic in place of the public suffix list, which is
 * a quarter of a megabyte; the button names the domain it will allow, so a
 * wrong guess is visible before it is acted on.
 */
const SECOND_LEVEL = new Set([
    'ac', 'co', 'com', 'edu', 'go', 'gob', 'gov', 'ltd', 'mil', 'ne', 'net', 'or', 'org', 'plc', 'sch',
]);

/** The registrable domain a name belongs to: `hubspotlinks.com` for `a.b.hubspotlinks.com`. */
function rootDomain(host: string): string {
    const labels = host.split('.');
    const n = labels.length;
    const cc = n > 2 && labels[n - 1]!.length === 2 && SECOND_LEVEL.has(labels[n - 2]!);

    return labels.slice(-(cc ? 3 : 2)).join('.');
}

/** The name a log entry asked for, as a rule spells it. */
const hostOf = (entry: LogEntry) => entry.question.name.replace(/\.$/, '').toLowerCase();

/**
 * Whether an entry was blocked by something a rule can let through.  Safe
 * search answers rather than blocks, and `FilteredInvalid` is an access-list
 * or `blocked_hosts` refusal, which no filtering exception reaches.
 */
export function isBlocked(entry: LogEntry): boolean {
    return entry.reason.startsWith('Filtered') && entry.reason !== 'FilteredSafeSearch' && entry.reason !== 'FilteredInvalid';
}

/**
 * The ways out of a block, narrowest first: an exception for this name alone,
 * one for the whole domain it belongs to, and then the source of the block
 * itself — the custom rule that matched, or the list it came from.
 *
 * `onDone` runs after a change was made, with what was made.
 */
export function UnblockActions({
    entry,
    blocklists,
    onDone,
}: {
    entry: LogEntry;
    blocklists: Filter[];
    onDone: (what: string) => void;
}) {
    const toast = useToast();
    const [busy, setBusy] = useState(false);

    const host = hostOf(entry);
    const root = rootDomain(host);
    // An exception loses to an `$important` block unless it is one too.
    const suffix = entry.rules.some((r) => /[$,]important\b/.test(r.text)) ? '$important' : '';
    // `|name^` pins the exception to the name itself; `||name^` takes in
    // everything under it as well.
    const exact = `@@|${host}^${suffix}`;
    const wide = `@@||${root}^${suffix}`;

    const custom = entry.rules.filter((r) => r.filter_list_id === 0).map((r) => r.text);
    const ids = new Set(entry.rules.map((r) => r.filter_list_id));
    const lists = blocklists.filter((f) => f.enabled && ids.has(f.id));

    const run = async (act: () => Promise<string | undefined>) => {
        setBusy(true);
        try {
            const done = await act();
            if (done) {
                toast.ok(done);
                onDone(done);
            }
        } catch (e) {
            toast.fail(message(e));
        } finally {
            setBusy(false);
        }
    };

    /** Adds one rule to the custom list, or removes one. */
    const editRule = (rule: string, remove: boolean) =>
        run(async () => {
            const rules = (await api.getFilteringStatus()).user_rules ?? [];
            const present = rules.some((r) => r.trim() === rule);
            if (present !== remove) {
                return remove ? `${rule} is no longer a custom rule` : `${rule} is already a custom rule`;
            }

            await api.setUserRules(remove ? rules.filter((r) => r.trim() !== rule) : [...rules, rule]);

            return `${remove ? 'Removed' : 'Added'} custom rule ${rule}`;
        });

    const disableList = (f: Filter) =>
        run(async () => {
            if (!window.confirm(`Turn off ${f.name}? Nothing it blocks will be blocked until it is turned back on.`)) {
                return undefined;
            }

            await api.setFilter(f.url, false, { name: f.name, url: f.url, enabled: false });

            return `Turned off ${f.name}`;
        });

    return (
        <>
            <button type="button" className="btn" disabled={busy} title={`Adds ${exact}`} onClick={() => void editRule(exact, false)}>
                Only {host}
            </button>
            {root !== host && (
                <button type="button" className="btn" disabled={busy} title={`Adds ${wide}`} onClick={() => void editRule(wide, false)}>
                    All of {root}
                </button>
            )}
            {custom.map((r) => (
                <button
                    key={r}
                    type="button"
                    className="btn danger"
                    disabled={busy}
                    title={`Removes ${r}`}
                    onClick={() => void editRule(r, true)}>
                    Remove custom rule
                </button>
            ))}
            {lists.map((f) => (
                <button key={f.id} type="button" className="btn danger" disabled={busy} onClick={() => void disableList(f)}>
                    Turn off {f.name}
                </button>
            ))}
        </>
    );
}

/**
 * The custom exception, of the forms `UnblockActions` writes, that already
 * lets `host` through: the log is history, and a name allowed since it was
 * blocked should say so rather than offer the same rule again.
 */
function allowedBy(host: string, rules: string[]): string | undefined {
    return rules.find((raw) => {
        const m = /^@@(\|\|?)([^\^$|]+)\^(\$important)?$/.exec(raw.trim());
        if (!m) {
            return false;
        }

        const name = m[2]!.toLowerCase();

        return m[1] === '|' ? name === host : name === host || host.endsWith(`.${name}`);
    });
}

/** How many blocked entries the panel reads; the server allows up to 5,000. */
const SCAN = 2_000;

/** The device filter, kept per browser: whoever opens this is usually on the same one. */
const CLIENT_KEY = 'sift.unblock.client';

/** Who asked, as one key: the client ID when there is one, else the address. */
const clientKey = (e: LogEntry) => e.client_id || e.client;
const clientLabel = (e: LogEntry) => {
    const name = e.client_info?.name || e.client_id;

    return name ? `${name} (${e.client})` : e.client;
};

/** "3 min ago", for how recent a block is; the exact time is in the title. */
function ago(iso: string): string {
    const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
    if (s < 60) {
        return `${s}s ago`;
    }
    if (s < 3600) {
        return `${Math.floor(s / 60)} min ago`;
    }
    if (s < 86_400) {
        return `${Math.floor(s / 3600)} h ago`;
    }

    return `${Math.floor(s / 86_400)} d ago`;
}

interface Group {
    host: string;
    latest: LogEntry;
    count: number;
}

/**
 * The top bar's way from "something just broke" to letting it through: the
 * names blocked most recently, one line per name, narrowed to one device if
 * asked, each opening the same actions as the query log's details.
 */
export function QuickUnblock() {
    const [open, setOpen] = useState(false);

    return (
        <>
            <button
                type="button"
                className="btn sm"
                onClick={() => setOpen(true)}
                title="See what was blocked just now and let it through">
                <IconAllow size={15} />
                <span className="wide-only">Unblock</span>
            </button>
            {open && <RecentlyBlocked onClose={() => setOpen(false)} />}
        </>
    );
}

function RecentlyBlocked({ onClose }: { onClose: () => void }) {
    const [entries, setEntries] = useState<LogEntry[]>();
    const [status, setStatus] = useState<FilteringStatus>();
    const [error, setError] = useState<string>();
    const [loading, setLoading] = useState(true);
    const [client, setClient] = useState(() => {
        try {
            return localStorage.getItem(CLIENT_KEY) ?? '';
        } catch {
            return '';
        }
    });
    const [term, setTerm] = useState('');
    const [expanded, setExpanded] = useState<string>();
    const [done, setDone] = useState<Record<string, string>>({});

    const load = useCallback(async () => {
        setLoading(true);
        setError(undefined);
        try {
            const [log, st] = await Promise.all([
                api.getQueryLog({ limit: SCAN, response_status: 'blocked' }),
                api.getFilteringStatus(),
            ]);
            setEntries((log.data ?? []).filter(isBlocked));
            setStatus(st);
        } catch (e) {
            setError(message(e));
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => void load(), [load]);

    const pickClient = (v: string) => {
        setClient(v);
        try {
            if (v) {
                localStorage.setItem(CLIENT_KEY, v);
            } else {
                localStorage.removeItem(CLIENT_KEY);
            }
        } catch {
            // Remembering the choice is a convenience; the filter still works.
        }
    };

    // Every device seen, labelled by its most recent entry.
    const clients = useMemo(() => {
        const seen = new Map<string, string>();
        for (const e of entries ?? []) {
            if (!seen.has(clientKey(e))) {
                seen.set(clientKey(e), clientLabel(e));
            }
        }

        return [...seen].sort((a, b) => a[1].localeCompare(b[1]));
    }, [entries]);

    // The log is newest first, so the first entry for a name is its latest.
    const groups = useMemo(() => {
        const byHost = new Map<string, Group>();
        const needle = term.trim().toLowerCase();
        for (const e of entries ?? []) {
            if (client && clientKey(e) !== client) {
                continue;
            }

            const host = hostOf(e);
            if (needle && !host.includes(needle)) {
                continue;
            }

            const g = byHost.get(host);
            if (g) {
                g.count += 1;
            } else {
                byHost.set(host, { host, latest: e, count: 1 });
            }
        }

        return [...byHost.values()].slice(0, 100);
    }, [entries, client, term]);

    const listName = listNamer(status);
    // A device remembered from another day may have nothing blocked in reach.
    const known = !client || clients.some(([k]) => k === client);

    return (
        <Modal title="Recently blocked" onClose={onClose} wide>
            <div className="row" style={{ marginBottom: 12 }}>
                <input
                    type="search"
                    value={term}
                    placeholder="Part of a domain"
                    aria-label="Domain"
                    style={{ flex: '1 1 180px', width: 'auto' }}
                    onChange={(e) => setTerm(e.target.value)}
                />
                <select
                    value={client}
                    aria-label="Device"
                    style={{ flex: '1 1 180px', width: 'auto' }}
                    onChange={(e) => pickClient(e.target.value)}>
                    <option value="">Every device</option>
                    {!known && <option value={client}>{client}</option>}
                    {clients.map(([k, label]) => (
                        <option key={k} value={k}>
                            {label}
                        </option>
                    ))}
                </select>
                <button type="button" className="btn" onClick={() => void load()} disabled={loading} title="Read the log again">
                    <IconRefresh size={15} />
                </button>
            </div>

            {error && <Notice kind="error">{error}</Notice>}
            {loading && !entries && <Loading />}
            {entries && groups.length === 0 && (
                <div className="empty">
                    {entries.length === 0 ? 'Nothing has been blocked recently.' : 'Nothing blocked matches.'}
                </div>
            )}

            <div className="blocked-list">
                {groups.map((g) => {
                    const allowed = done[g.host] ?? allowedBy(g.host, status?.user_rules ?? []);
                    const isOpen = expanded === g.host && !allowed;

                    return (
                        <div key={g.host} className={`blocked-item ${isOpen ? 'open' : ''}`}>
                            <button
                                type="button"
                                className="blocked-head"
                                aria-expanded={isOpen}
                                disabled={!!allowed}
                                onClick={() => setExpanded(isOpen ? undefined : g.host)}>
                                <span className="mono truncate">{g.host}</span>
                                {allowed ? (
                                    <span className="badge green" title={allowed}>
                                        Allowed
                                    </span>
                                ) : (
                                    <span className="muted" title={new Date(g.latest.time).toLocaleString()}>
                                        {g.count > 1 ? `${g.count}× · ` : ''}
                                        {ago(g.latest.time)}
                                    </span>
                                )}
                            </button>
                            <div className="muted truncate" style={{ fontSize: 12 }}>
                                {g.latest.rules[0] ? listName(g.latest.rules[0].filter_list_id) : g.latest.reason}
                                {!client && ` · ${clientLabel(g.latest)}`}
                            </div>
                            {isOpen && (
                                <div className="row" style={{ marginTop: 8 }}>
                                    <UnblockActions
                                        entry={g.latest}
                                        blocklists={status?.filters ?? []}
                                        onDone={(what) => {
                                            setDone((d) => ({ ...d, [g.host]: what }));
                                            setExpanded(undefined);
                                            // A list turned off changes which
                                            // actions the other rows offer.
                                            void api.getFilteringStatus().then(setStatus, () => undefined);
                                        }}
                                    />
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>

            <BrowserCache />

            <p className="muted" style={{ fontSize: 12, marginTop: 12 }}>
                The whole history is in the{' '}
                <Link to="/logs" onClick={onClose}>
                    query log
                </Link>
                .
            </p>
        </Modal>
    );
}

/**
 * Where this browser keeps its own DNS cache, and what to press there.
 *
 * A change here applies to the next lookup, but a browser holds a blocked
 * answer for a minute or so on its own account.  Its internal pages cannot be
 * linked to — a browser refuses to navigate to them from a web page — so the
 * address is offered to copy instead.
 */
function cachePage(): { url: string; press: string } | undefined {
    const ua = navigator.userAgent;
    if (/Edg\//.test(ua)) {
        return { url: 'edge://net-internals/#dns', press: 'Clear host cache' };
    }
    if (/Firefox\//.test(ua)) {
        return { url: 'about:networking#dns', press: 'Clear DNS Cache' };
    }
    if (/Chrome\//.test(ua)) {
        return { url: 'chrome://net-internals/#dns', press: 'Clear host cache' };
    }

    return undefined;
}

function BrowserCache() {
    const toast = useToast();
    const page = cachePage();

    const copy = async (url: string) => {
        try {
            await navigator.clipboard.writeText(url);
            toast.ok('Copied — paste it into the address bar');
        } catch {
            toast.fail('Could not copy; select the address and copy it by hand');
        }
    };

    return (
        <div className="muted" style={{ fontSize: 12, marginTop: 12 }}>
            Still blocked? The browser may have kept the old answer.{' '}
            {page ? (
                <>
                    Open <code className="mono">{page.url}</code>{' '}
                    <button type="button" className="btn sm" onClick={() => void copy(page.url)}>
                        Copy
                    </button>{' '}
                    and press <b>{page.press}</b>, then reload the page.
                </>
            ) : (
                'Reload the page, or restart the browser if that is not enough.'
            )}
        </div>
    );
}
