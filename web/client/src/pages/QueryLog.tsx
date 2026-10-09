import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

import * as api from '../api';
import type { Filter, FilterReason, LogEntry } from '../api';
import { RESERVED, UnblockActions, isBlocked, listNamer } from '../app/Unblock';
import { Loading, Modal, Notice, useToast } from '../components/ui';
import { IconRefresh, IconSearch } from '../components/icons';
import { formatTime } from '../lib/format';
import { message, useAsync } from '../lib/hooks';

/** One page of entries; the server caps what it will return anyway. */
const PAGE = 100;

/** The filters the status dropdown offers, as the API spells them. */
const STATUSES = [
    { value: 'all', label: 'Everything' },
    { value: 'processed', label: 'Answered' },
    { value: 'blocked', label: 'Blocked' },
    { value: 'whitelisted', label: 'Allowed by a rule' },
    { value: 'rewritten', label: 'Rewritten' },
    { value: 'safe_search', label: 'Safe search' },
];

/** How a verdict reads, and the colour it is shown in. */
function verdict(reason: FilterReason): { text: string; tone: string } {
    switch (reason) {
        case 'FilteredBlackList':
            return { text: 'Blocked by a filter', tone: 'red' };
        // Neither is produced any more, but a log written by AdGuard Home
        // still carries them.
        case 'FilteredSafeBrowsing':
            return { text: 'Malware or phishing', tone: 'red' };
        case 'FilteredParental':
            return { text: 'Adult site', tone: 'red' };
        case 'FilteredBlockedService':
            return { text: 'Blocked service', tone: 'red' };
        case 'FilteredInvalid':
            return { text: 'Refused', tone: 'red' };
        case 'FilteredSafeSearch':
            return { text: 'Safe search', tone: 'amber' };
        case 'NotFilteredWhiteList':
            return { text: 'Allowed by a rule', tone: 'green' };
        case 'Rewrite':
        case 'RewriteEtcHosts':
        case 'RewriteRule':
            return { text: 'Rewritten', tone: 'blue' };
        default:
            return { text: 'Answered', tone: 'grey' };
    }
}

export default function QueryLog() {
    const toast = useToast();
    const [params, setParams] = useSearchParams();

    const search = params.get('search') ?? '';
    const status = params.get('response_status') ?? 'all';
    const list = params.get('filter_id') ?? '';

    // The lists, for the filter below and for naming the rule that matched.
    // A failure here leaves both falling back to the identifier, which is
    // worse than a name but better than an empty log page.
    const lists = useAsync(() => api.getFilteringStatus());
    const listName = useMemo(() => listNamer(lists.data), [lists.data]);

    const [term, setTerm] = useState(search);
    const [rows, setRows] = useState<LogEntry[]>([]);
    const [cursor, setCursor] = useState<string>();
    const [done, setDone] = useState(false);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string>();
    const [detail, setDetail] = useState<LogEntry>();
    const [disabled, setDisabled] = useState(false);

    useEffect(() => setTerm(search), [search]);

    useEffect(() => {
        void api
            .getQueryLogConfig()
            .then((c) => setDisabled(!c.enabled))
            .catch(() => undefined);
    }, []);

    /** Fetches a page; `older_than` empty starts over from the newest entry. */
    const fetchPage = useCallback(
        async (olderThan?: string, replace = false) => {
            setLoading(true);
            setError(undefined);
            try {
                const r = await api.getQueryLog({
                    limit: PAGE,
                    older_than: olderThan,
                    search: search || undefined,
                    response_status: status === 'all' ? undefined : status,
                    filter_id: list || undefined,
                });
                const data = r.data ?? [];
                setRows((prev) => (replace ? data : [...prev, ...data]));
                // The cursor is the oldest entry's own timestamp, which is
                // what the server takes to page backwards.
                setCursor(data.length ? data[data.length - 1]?.time : undefined);
                setDone(data.length < PAGE);
            } catch (e) {
                setError(message(e));
                setDone(true);
            } finally {
                setLoading(false);
            }
        },
        [search, status, list],
    );

    useEffect(() => {
        setRows([]);
        setCursor(undefined);
        setDone(false);
        void fetchPage(undefined, true);
    }, [fetchPage]);

    // The sentinel below the table pulls the next page in as it comes into
    // view, which is cheaper than a scroll listener and does not fight the
    // browser over momentum.
    const sentinel = useRef<HTMLDivElement>(null);
    useEffect(() => {
        const el = sentinel.current;
        if (!el || done || loading) {
            return;
        }

        const io = new IntersectionObserver((entries) => {
            if (entries.some((e) => e.isIntersecting) && cursor) {
                void fetchPage(cursor);
            }
        });
        io.observe(el);

        return () => io.disconnect();
    }, [cursor, done, loading, fetchPage]);

    const apply = (next: { search?: string; response_status?: string; filter_id?: string }) => {
        const p = new URLSearchParams(params);
        for (const [k, v] of Object.entries(next)) {
            if (v) {
                p.set(k, v);
            } else {
                p.delete(k);
            }
        }
        setParams(p, { replace: true });
    };

    const clear = async () => {
        if (!window.confirm('Discard every entry in the query log?')) {
            return;
        }

        try {
            await api.clearQueryLog();
            toast.ok('Query log cleared');
            void fetchPage(undefined, true);
        } catch (e) {
            toast.fail(message(e));
        }
    };

    /**
     * Blocks or unblocks a domain through the custom rule list.
     *
     * The two forms are opposites, so asking for one **withdraws** the other
     * rather than stacking on it: the block rule carries `$important` and
     * would beat an `@@` exception added beside it, leaving a domain the
     * interface calls unblocked and the resolver still refuses.
     */
    const setRule = async (entry: LogEntry, allow: boolean) => {
        const host = entry.question.name.replace(/\.$/, '');
        const block = `||${host}^$important`;
        const unblock = `@@||${host}^`;
        const wanted = allow ? unblock : block;
        const opposite = allow ? block : unblock;

        try {
            const st = await api.getFilteringStatus();
            const rules = st.user_rules ?? [];

            // Withdrawing our own rule is enough when it is the only reason.
            const withoutOpposite = rules.filter((r) => r.trim() !== opposite);
            const next = withoutOpposite.length < rules.length ? withoutOpposite : [...rules, wanted];

            await api.setUserRules(next);
            const withdrew = next.length < rules.length;
            toast.ok(`${withdrew ? 'Removed' : 'Added'} custom rule ${withdrew ? opposite : wanted}`);
            void fetchPage(undefined, true);
        } catch (e) {
            toast.fail(message(e));
        }
    };

    return (
        <>
            <div className="page-head">
                <h1>Query log</h1>
                <div className="spacer" />
                <button type="button" className="btn" onClick={() => void fetchPage(undefined, true)}>
                    <IconRefresh size={15} /> Refresh
                </button>
                <button type="button" className="btn danger" onClick={() => void clear()}>
                    Clear log
                </button>
            </div>

            {disabled && (
                <Notice kind="warn">
                    The query log is switched off, so nothing new is being recorded. Turn it back on in{' '}
                    <Link to="/settings">General settings</Link>.
                </Notice>
            )}
            {error && <Notice kind="error">{error}</Notice>}

            <div className="card">
                <form
                    className="row"
                    onSubmit={(e) => {
                        e.preventDefault();
                        apply({ search: term });
                    }}>
                    <div style={{ position: 'relative', flex: 1, minWidth: 220 }}>
                        <IconSearch
                            size={15}
                            style={{ position: 'absolute', left: 9, top: 9, color: 'var(--text-faint)' }}
                        />
                        <input
                            type="search"
                            value={term}
                            placeholder="A domain or a client"
                            style={{ paddingLeft: 30 }}
                            onChange={(e) => setTerm(e.target.value)}
                        />
                    </div>
                    <select
                        value={status}
                        aria-label="Verdict"
                        style={{ width: 'auto' }}
                        onChange={(e) => apply({ response_status: e.target.value })}>
                        {STATUSES.map((s) => (
                            <option key={s.value} value={s.value}>
                                {s.label}
                            </option>
                        ))}
                    </select>
                    <select
                        value={list}
                        aria-label="Filter list"
                        style={{ width: 'auto' }}
                        onChange={(e) => apply({ filter_id: e.target.value })}>
                        <option value="">Any list</option>
                        <option value="0">{RESERVED[0]}</option>
                        {(lists.data?.filters ?? []).length > 0 && (
                            <optgroup label="Blocklists">
                                {(lists.data?.filters ?? []).map((f) => (
                                    <option key={f.id} value={f.id}>
                                        {f.name}
                                    </option>
                                ))}
                            </optgroup>
                        )}
                        {(lists.data?.whitelist_filters ?? []).length > 0 && (
                            <optgroup label="Allowlists">
                                {(lists.data?.whitelist_filters ?? []).map((f) => (
                                    <option key={f.id} value={f.id}>
                                        {f.name}
                                    </option>
                                ))}
                            </optgroup>
                        )}
                        <optgroup label="Built in">
                            <option value="-2">{RESERVED[-2]}</option>
                            <option value="-1">{RESERVED[-1]}</option>
                        </optgroup>
                    </select>
                    <button type="submit" className="btn primary">
                        Search
                    </button>
                    {(search || status !== 'all' || list) && (
                        <button
                            type="button"
                            className="btn ghost"
                            onClick={() => {
                                setTerm('');
                                setParams(new URLSearchParams(), { replace: true });
                            }}>
                            Reset
                        </button>
                    )}
                </form>
            </div>

            <div className="table-wrap">
                {/* Fixed layout: the columns below are sized on purpose, and
                    without it one long rule pushes the table past the card and
                    the whole page grows a horizontal scrollbar. */}
                <table className="fixed stack">
                    <thead>
                        <tr>
                            <th style={{ width: 112 }}>Time</th>
                            <th>Request</th>
                            <th style={{ width: '22%' }}>Verdict</th>
                            <th style={{ width: '20%' }}>Client</th>
                            <th className="actions" />
                        </tr>
                    </thead>
                    <tbody>
                        {rows.map((e, i) => (
                            <Row
                                key={`${e.time}-${i}`}
                                entry={e}
                                onOpen={() => setDetail(e)}
                                onRule={(allow) => void setRule(e, allow)}
                            />
                        ))}
                    </tbody>
                </table>
                {rows.length === 0 && !loading && <div className="empty">No queries match.</div>}
                {loading && <Loading />}
                <div ref={sentinel} style={{ height: 1 }} />
            </div>

            {detail && (
                <Details
                    entry={detail}
                    listName={listName}
                    blocklists={lists.data?.filters ?? []}
                    onDone={() => {
                        setDetail(undefined);
                        void lists.reload();
                    }}
                    onClose={() => setDetail(undefined)}
                />
            )}
        </>
    );
}

function Row({ entry, onOpen, onRule }: { entry: LogEntry; onOpen: () => void; onRule: (allow: boolean) => void }) {
    const { text, tone } = verdict(entry.reason);
    const blocked = tone === 'red';
    const name = entry.client_info?.name;

    return (
        <tr>
            <td className="mono" title={formatTime(entry.time, true)}>
                {formatTime(entry.time)}
            </td>
            <td>
                <button type="button" className="linklike truncate" onClick={onOpen} title="Show the details">
                    {entry.question.name}
                </button>
                <div className="muted" style={{ fontSize: 12 }}>
                    {entry.question.type} · {entry.elapsedMs} ms{entry.cached ? ' · from cache' : ''}
                </div>
            </td>
            <td>
                <span className={`badge ${tone}`}>{text}</span>
                {entry.rule && (
                    <div className="mono muted truncate" title={entry.rule}>
                        {entry.rule}
                    </div>
                )}
            </td>
            <td>
                <div className="mono truncate">{entry.client}</div>
                {(name || entry.client_id) && (
                    <div className="muted truncate" style={{ fontSize: 12 }}>
                        {name || entry.client_id}
                    </div>
                )}
            </td>
            <td className="actions">
                <button type="button" className="btn sm" onClick={() => onRule(blocked)}>
                    {blocked ? 'Unblock' : 'Block'}
                </button>
            </td>
        </tr>
    );
}

function Details({
    entry,
    listName,
    blocklists,
    onDone,
    onClose,
}: {
    entry: LogEntry;
    listName: (id: number) => string;
    blocklists: Filter[];
    onDone: () => void;
    onClose: () => void;
}) {
    const { text } = verdict(entry.reason);
    const rows: [string, React.ReactNode][] = [
        ['Time', formatTime(entry.time, true)],
        ['Domain', entry.question.name],
        ['Question', `${entry.question.type} ${entry.question.class}`],
        ['Answer', `${entry.status} — ${text}`],
        ['Took', `${entry.elapsedMs} ms`],
        ['Client', entry.client + (entry.client_id ? ` (${entry.client_id})` : '')],
        ['Transport', entry.client_proto || 'plain DNS'],
        ['Upstream', entry.upstream ?? '—'],
        ['DNSSEC', entry.answer_dnssec ? 'validated' : 'not validated'],
        ['Cache', entry.cached ? 'served from cache' : 'fetched upstream'],
    ];

    return (
        <Modal
            title="Query details"
            onClose={onClose}
            wide
            footer={
                isBlocked(entry) ? (
                    <>
                        <span className="muted" style={{ marginRight: 'auto' }}>
                            Unblock
                        </span>
                        <UnblockActions entry={entry} blocklists={blocklists} onDone={onDone} />
                    </>
                ) : undefined
            }>
            <table>
                <tbody>
                    {rows.map(([k, v]) => (
                        <tr key={k}>
                            <td style={{ width: 200, color: 'var(--text-muted)' }}>{k}</td>
                            <td className="mono">{v}</td>
                        </tr>
                    ))}
                    {entry.rules.length > 0 && (
                        <tr>
                            <td style={{ color: 'var(--text-muted)' }}>Matched</td>
                            <td className="mono">
                                {entry.rules.map((r, i) => (
                                    <div key={i}>
                                        {r.text}
                                        <div className="muted" style={{ fontSize: 12 }}>
                                            {listName(r.filter_list_id)}
                                        </div>
                                    </div>
                                ))}
                            </td>
                        </tr>
                    )}
                    {entry.answer && entry.answer.length > 0 && (
                        <tr>
                            <td style={{ color: 'var(--text-muted)' }}>Records</td>
                            <td className="mono">
                                {entry.answer.map((a, i) => (
                                    <div key={i}>
                                        {a.type} {a.value} <span className="muted">({a.ttl}s)</span>
                                    </div>
                                ))}
                            </td>
                        </tr>
                    )}
                </tbody>
            </table>
        </Modal>
    );
}

