import { useEffect, useState } from 'react';

import * as api from '../api';
import type { Theme } from '../api';
import { Menu, Switch, useToast } from '../components/ui';
import { IconChevron, IconMenu, IconMoon, IconRefresh, IconSun, IconUser } from '../components/icons';
import { countdown } from '../lib/format';
import { message } from '../lib/hooks';
import { useServer } from './context';
import { QuickUnblock } from './Unblock';

/**
 * How long protection may be turned off for.
 *
 * `ms` is a function rather than a number because one of these is not a fixed
 * length: "until tomorrow" is however long it is until local midnight, which
 * depends on when it is asked.
 */
const DURATIONS: { label: string; ms: () => number }[] = [
    { label: 'For 30 seconds', ms: () => 30_000 },
    { label: 'For 1 minute', ms: () => 60_000 },
    { label: 'For 10 minutes', ms: () => 10 * 60_000 },
    { label: 'For 1 hour', ms: () => 60 * 60_000 },
    { label: 'Until tomorrow', ms: untilTomorrow },
];

/** Milliseconds from now until the next local midnight. */
function untilTomorrow(): number {
    const midnight = new Date();
    midnight.setHours(24, 0, 0, 0);

    return midnight.getTime() - Date.now();
}

/**
 * Whether one release is later than another.
 *
 * The announcement is the newest *published* release, which a build from
 * `main` is ahead of, so comparing for inequality announces a downgrade as if
 * it were an update. The server applies the same rule to `can_autoupdate`,
 * and anything unreadable is not newer.
 */
function isNewer(candidate: string, running: string): boolean {
    const parts = (v: string) => /^v?(\d+)\.(\d+)\.(\d+)/.exec(v.trim())?.slice(1, 4).map(Number);
    const c = parts(candidate);
    const r = parts(running);
    if (!c || !r) {
        return false;
    }

    for (const [i, n] of c.entries()) {
        const other = r[i] ?? 0;
        if (n !== other) {
            return n > other;
        }
    }

    return false;
}

const THEMES: { value: Theme; label: string }[] = [
    { value: 'auto', label: 'Match the system' },
    { value: 'light', label: 'Light' },
    { value: 'dark', label: 'Dark' },
];

export default function Topbar({ onBurger }: { onBurger: () => void }) {
    const { status, profile, version, checkVersion, setProtection, setTheme } = useServer();
    const toast = useToast();
    const [left, setLeft] = useState(status.protection_disabled_duration);
    const [installing, setInstalling] = useState(false);
    const [checking, setChecking] = useState(false);

    // The server reports how long protection stays off; the countdown here is
    // only the display of it, and is re-seeded every time the status reloads.
    useEffect(() => {
        setLeft(status.protection_disabled_duration);
        if (status.protection_enabled || status.protection_disabled_duration <= 0) {
            return;
        }

        const id = window.setInterval(() => setLeft((v) => Math.max(0, v - 1000)), 1000);

        return () => window.clearInterval(id);
    }, [status.protection_disabled_duration, status.protection_enabled]);

    const change = async (enabled: boolean, ms?: number) => {
        try {
            await setProtection(enabled, ms);
            toast.ok(enabled ? 'Protection is on' : 'Protection is off');
        } catch (e) {
            toast.fail(message(e));
        }
    };

    const clearCache = async () => {
        if (!window.confirm('Empty the DNS cache? Every name will be looked up again.')) {
            return;
        }

        try {
            await api.clearCache();
            toast.ok('DNS cache cleared');
        } catch (e) {
            toast.fail(message(e));
        }
    };

    const newVersion =
        version && !version.disabled && version.new_version && isNewer(version.new_version, status.version)
            ? version.new_version
            : undefined;

    /**
     * What the profile menu says about updates.
     *
     * Every branch says something. A server that is current, one whose check
     * never reached GitHub, and one that found a release it cannot install
     * all showed nothing at all before, which reads from the operator's seat
     * as a build that cannot update itself.
     */
    const updateState = (): string => {
        if (!version) {
            return 'Checking for updates…';
        }
        if (version.disabled) {
            return 'Update checks are off (--no-check-update)';
        }
        if (version.check_failed) {
            return 'Could not reach the release server';
        }
        if (!newVersion) {
            return 'Up to date';
        }

        return version.can_autoupdate
            ? `${newVersion} is ready to install`
            : `${newVersion} is available — ${version.autoupdate_blocked_by ?? 'install it yourself'}`;
    };

    const check = async () => {
        setChecking(true);
        try {
            const info = await checkVersion(true);
            if (info.check_failed) {
                toast.fail('Could not reach the release server');
            } else if (info.new_version && isNewer(info.new_version, status.version)) {
                toast.ok(`${info.new_version} is available`);
            } else {
                toast.ok(`Up to date — ${status.version} is the newest release`);
            }
        } finally {
            setChecking(false);
        }
    };

    const install = async () => {
        if (
            !window.confirm(
                `Install ${newVersion}? The server replaces its own binary and restarts. ` +
                    'Your settings and data are untouched, and the version you are running now is kept.',
            )
        ) {
            return;
        }

        setInstalling(true);
        try {
            await api.installUpdate();
        } catch (e) {
            setInstalling(false);
            toast.fail(message(e));

            return;
        }

        toast.ok(`Installing ${newVersion}; the server is restarting`);

        // The server answers this request and then hands its process over to
        // the new binary, so the page has to wait for a server that is not
        // there yet rather than reload into a connection error.
        const until = Date.now() + 120_000;
        const wait = async (): Promise<void> => {
            if (Date.now() > until) {
                setInstalling(false);
                toast.fail('The server has not come back; check its logs');

                return;
            }

            await new Promise((r) => setTimeout(r, 2000));
            try {
                await api.getStatus();
                window.location.reload();
            } catch {
                await wait();
            }
        };

        void wait();
    };

    return (
        <header className="topbar">
            <button type="button" className="btn ghost icon burger" onClick={onBurger} aria-label="Menu">
                <IconMenu />
            </button>

            <Switch
                checked={status.protection_enabled}
                onChange={(v) => void change(v)}
                label={status.protection_enabled ? 'Turn protection off' : 'Turn protection on'}
            />
            <span className="wide-only" style={{ fontWeight: 550 }}>
                Protection
            </span>
            {!status.protection_enabled && (
                <span
                    className="badge amber"
                    title={left > 0 ? `Protection comes back on in ${countdown(left)}` : 'Protection is off until you turn it back on'}>
                    {left > 0 ? `off for ${countdown(left)}` : 'off'}
                </span>
            )}
            {status.protection_enabled && (
                <Menu label="Turn protection off for a while" button={<IconChevron size={14} />}>
                    {/* The durations alone read as "for an hour" of nothing in
                        particular, so the menu says what it is an hour of. */}
                    <div className="menu-title">Turn protection off</div>
                    {DURATIONS.map((d) => (
                        <button
                            key={d.label}
                            type="button"
                            className="menu-item"
                            onClick={() => void change(false, d.ms())}>
                            {d.label}
                        </button>
                    ))}
                    <div className="menu-sep" />
                    <button type="button" className="menu-item" onClick={() => void change(false)}>
                        Until I turn it back on
                    </button>
                </Menu>
            )}

            <div className="spacer" />

            <QuickUnblock />

            <button type="button" className="btn sm" onClick={() => void clearCache()} title="Empty the DNS cache">
                <IconRefresh size={15} />
                <span className="wide-only">Clear cache</span>
            </button>

            {newVersion && (
                <a
                    className="badge green"
                    href={version?.announcement_url ?? 'https://github.com/openhoangnc/sift/releases'}
                    target="_blank"
                    rel="noreferrer">
                    {newVersion} is available
                </a>
            )}

            {/* Offered only where the server says it could actually do it: not
                in a container, where the image is what gets updated, and not
                where a restart could not bind the ports it has now. */}
            {newVersion && version?.can_autoupdate && (
                <button type="button" className="btn sm" onClick={() => void install()} disabled={installing}>
                    {installing ? 'Installing…' : 'Install'}
                </button>
            )}

            <Menu label="Theme" button={profile.theme === 'dark' ? <IconMoon /> : <IconSun />}>
                {THEMES.map((th) => (
                    <button
                        key={th.value}
                        type="button"
                        className={`menu-item ${profile.theme === th.value ? 'active' : ''}`}
                        onClick={() => void setTheme(th.value).catch((e) => toast.fail(message(e)))}>
                        {th.label}
                    </button>
                ))}
            </Menu>

            <Menu label={profile.name} button={<IconUser />}>
                <div className="menu-item" style={{ color: 'var(--text-muted)' }}>
                    {profile.name}
                </div>
                <div className="menu-item" style={{ color: 'var(--text-faint)', fontSize: 12 }}>
                    Sift {status.version}
                </div>
                <div className="menu-item" style={{ color: 'var(--text-faint)', fontSize: 12 }}>
                    {updateState()}
                </div>
                {!version?.disabled && (
                    <button type="button" className="menu-item" disabled={checking} onClick={() => void check()}>
                        {checking ? 'Checking…' : 'Check for updates'}
                    </button>
                )}
                <div className="menu-sep" />
                <button
                    type="button"
                    className="menu-item"
                    onClick={() => {
                        void api.logout().finally(() => window.location.replace('login.html'));
                    }}>
                    Sign out
                </button>
            </Menu>
        </header>
    );
}
