/** The handful of primitives every page is built from. */
import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useId,
    useMemo,
    useRef,
    useState,
} from 'react';
import type { ReactNode } from 'react';
import { createPortal } from 'react-dom';

import { IconClose } from './icons';

/* ---------- Card ---------- */

export function Card({
    title,
    desc,
    actions,
    children,
    className = '',
}: {
    title?: ReactNode;
    desc?: ReactNode;
    actions?: ReactNode;
    children?: ReactNode;
    className?: string;
}) {
    return (
        <section className={`card ${className}`}>
            {(title || actions) && (
                <div className="card-head">
                    {title && <h2>{title}</h2>}
                    <div className="spacer" />
                    {actions}
                </div>
            )}
            {desc && <p className="card-desc">{desc}</p>}
            {children}
        </section>
    );
}

/* ---------- Notices ---------- */

export function Notice({ kind = 'info', children }: { kind?: 'info' | 'error' | 'warn' | 'ok'; children: ReactNode }) {
    if (children === undefined || children === null || children === false || children === '') {
        return null;
    }

    return (
        <div className={`notice ${kind}`} role={kind === 'error' ? 'alert' : undefined}>
            <div>{children}</div>
        </div>
    );
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
    return (
        <div className="loading-page">
            <span className="spinner" /> {label}
        </div>
    );
}

/* ---------- Form fields ---------- */

export function Field({
    label,
    hint,
    children,
    error,
}: {
    label?: ReactNode;
    hint?: ReactNode;
    children: ReactNode;
    error?: ReactNode;
}) {
    const id = useId();

    return (
        <div className="field">
            {label && <label htmlFor={id}>{label}</label>}
            <Labelled id={id}>{children}</Labelled>
            {error ? <div className="hint" style={{ color: 'var(--danger)' }}>{error}</div> : hint ? <div className="hint">{hint}</div> : null}
        </div>
    );
}

/** Gives the single child the label's `id`, so clicking the label focuses it. */
function Labelled({ id, children }: { id: string; children: ReactNode }) {
    if (children && typeof children === 'object' && 'type' in children) {
        const el = children as React.ReactElement<{ id?: string }>;
        if (!el.props.id) {
            return <el.type {...el.props} id={id} />;
        }
    }

    return <>{children}</>;
}

export function Check({
    checked,
    onChange,
    label,
    hint,
    disabled,
}: {
    checked: boolean;
    onChange: (v: boolean) => void;
    label: ReactNode;
    hint?: ReactNode;
    disabled?: boolean;
}) {
    return (
        <label className="check">
            <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
            <span className="text">
                <b>{label}</b>
                {hint && <div className="hint">{hint}</div>}
            </span>
        </label>
    );
}

export function Switch({
    checked,
    onChange,
    label,
    disabled,
}: {
    checked: boolean;
    onChange: (v: boolean) => void;
    label: string;
    disabled?: boolean;
}) {
    return (
        <label className="switch" title={label}>
            <input
                type="checkbox"
                role="switch"
                aria-label={label}
                checked={checked}
                disabled={disabled}
                onChange={(e) => onChange(e.target.checked)}
            />
            <span />
        </label>
    );
}

/* ---------- Modal ---------- */

/**
 * A dialog over the whole page.  It is rendered into `body` rather than where
 * it is used: the top bar's `backdrop-filter` makes it the containing block
 * for anything fixed inside it, and a modal opened from there was confined to
 * the bar's 80 pixels.
 */
export function Modal({
    title,
    onClose,
    children,
    footer,
    wide,
}: {
    title: ReactNode;
    onClose: () => void;
    children: ReactNode;
    footer?: ReactNode;
    wide?: boolean;
}) {
    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            if (e.key === 'Escape') {
                onClose();
            }
        };

        document.addEventListener('keydown', onKey);
        const { overflow } = document.body.style;
        document.body.style.overflow = 'hidden';

        return () => {
            document.removeEventListener('keydown', onKey);
            document.body.style.overflow = overflow;
        };
    }, [onClose]);

    return createPortal(
        <div
            className="modal-backdrop"
            onMouseDown={(e) => {
                if (e.target === e.currentTarget) {
                    onClose();
                }
            }}>
            <div className={`modal ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true">
                <div className="modal-head">
                    <h2>{title}</h2>
                    <button type="button" className="btn ghost icon" onClick={onClose} aria-label="Close">
                        <IconClose />
                    </button>
                </div>
                <div className="modal-body">{children}</div>
                {footer && <div className="modal-foot">{footer}</div>}
            </div>
        </div>,
        document.body,
    );
}

/* ---------- Dropdown menu ---------- */

export function Menu({ button, children, label }: { button: ReactNode; children: ReactNode; label: string }) {
    const [open, setOpen] = useState(false);
    const box = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (!open) {
            return;
        }

        const away = (e: MouseEvent) => {
            if (box.current && !box.current.contains(e.target as Node)) {
                setOpen(false);
            }
        };
        const esc = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);

        document.addEventListener('mousedown', away);
        document.addEventListener('keydown', esc);

        return () => {
            document.removeEventListener('mousedown', away);
            document.removeEventListener('keydown', esc);
        };
    }, [open]);

    return (
        <div className="menu" ref={box}>
            <button
                type="button"
                className="btn ghost"
                aria-label={label}
                aria-expanded={open}
                onClick={() => setOpen((v) => !v)}>
                {button}
            </button>
            {open && (
                <div className="menu-panel" onClick={() => setOpen(false)}>
                    {children}
                </div>
            )}
        </div>
    );
}

/* ---------- Toasts ---------- */

interface Toast {
    id: number;
    text: string;
    kind: 'ok' | 'error';
}

interface ToastCtx {
    ok: (text: string) => void;
    fail: (text: string) => void;
}

const Toasts = createContext<ToastCtx>({ ok: () => {}, fail: () => {} });

export function ToastProvider({ children }: { children: ReactNode }) {
    const [items, setItems] = useState<Toast[]>([]);
    const next = useRef(1);

    const push = useCallback((text: string, kind: Toast['kind']) => {
        const id = next.current++;
        setItems((v) => [...v, { id, text, kind }]);
        // Failures stay longer: they are usually a sentence worth reading.
        window.setTimeout(() => setItems((v) => v.filter((t) => t.id !== id)), kind === 'error' ? 9000 : 4000);
    }, []);

    const value = useMemo<ToastCtx>(
        () => ({ ok: (t) => push(t, 'ok'), fail: (t) => push(t, 'error') }),
        [push],
    );

    return (
        <Toasts.Provider value={value}>
            {children}
            <div className="toasts" aria-live="polite">
                {items.map((t) => (
                    <div key={t.id} className={`toast ${t.kind}`}>
                        <div>{t.text}</div>
                        <button type="button" onClick={() => setItems((v) => v.filter((x) => x.id !== t.id))}>
                            <IconClose size={14} />
                        </button>
                    </div>
                ))}
            </div>
        </Toasts.Provider>
    );
}

export function useToast(): ToastCtx {
    return useContext(Toasts);
}

/* ---------- Tables ---------- */

export function Table({
    head,
    children,
    empty,
    className = '',
}: {
    head: ReactNode;
    children: ReactNode;
    empty?: ReactNode;
    className?: string;
}) {
    const rows = Array.isArray(children) ? children.flat() : children;
    const isEmpty = Array.isArray(rows) ? rows.filter(Boolean).length === 0 : !rows;

    return (
        <div className="table-wrap">
            <table className={className}>
                <thead>
                    <tr>{head}</tr>
                </thead>
                {!isEmpty && <tbody>{rows}</tbody>}
            </table>
            {isEmpty && <div className="empty">{empty ?? 'Nothing here yet.'}</div>}
        </div>
    );
}

/* ---------- A save button that reports what it is doing ---------- */

export function SaveButton({
    onClick,
    disabled,
    children,
}: {
    onClick: () => void | Promise<void>;
    disabled?: boolean;
    children: ReactNode;
}) {
    const [busy, setBusy] = useState(false);

    return (
        <button
            type="button"
            className="btn primary"
            disabled={busy || disabled}
            onClick={async () => {
                setBusy(true);
                try {
                    await onClick();
                } finally {
                    setBusy(false);
                }
            }}>
            {busy && <span className="spinner" style={{ width: 13, height: 13, borderWidth: 2 }} />}
            {children}
        </button>
    );
}
