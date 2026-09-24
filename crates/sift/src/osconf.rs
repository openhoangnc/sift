//! Operating-system settings: the user to run as, the descriptor limit and
//! the PID file.
//!
//! These are applied before the async runtime starts, while the process is
//! still single-threaded.  On Linux the `setuid` and `setgid` syscalls act on
//! the calling thread, so dropping privileges after the runtime has spawned
//! its worker threads would leave most of them privileged.

use std::io;
use std::path::Path;

/// A failure applying an operating-system setting.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The named user or group does not exist.
    #[error("no such {kind} {name:?}")]
    NotFound {
        /// Either `user` or `group`.
        kind: &'static str,
        /// The name that was looked up.
        name: String,
    },

    /// The system call failed, usually for want of privilege.
    #[error("{what}: {source}")]
    Syscall {
        /// What was being attempted.
        what: &'static str,
        /// The underlying error.
        #[source]
        source: io::Error,
    },

    /// The platform does not support the setting.
    ///
    /// Carried only where it can happen.  Every setting in the `os` block is
    /// honoured on Linux, so nothing there constructs this, and a variant
    /// that cannot occur is one a reader has to rule out.
    #[cfg(not(target_os = "linux"))]
    #[error("{0} is not supported on this platform")]
    Unsupported(&'static str),
}

/// Looks a user name up, accepting a numeric id directly.
///
/// `/etc/passwd` is read rather than the name service: in the container this
/// ships in, that file is the whole directory, and a numeric id — which is
/// what a container image normally uses — needs no lookup at all.
pub fn lookup_uid(name: &str) -> Option<u32> {
    if let Ok(n) = name.parse::<u32>() {
        return Some(n);
    }

    let text = std::fs::read_to_string("/etc/passwd").ok()?;

    field_of(&text, name, 2)
}

/// Looks a group name up, accepting a numeric id directly.
pub fn lookup_gid(name: &str) -> Option<u32> {
    if let Ok(n) = name.parse::<u32>() {
        return Some(n);
    }

    let text = std::fs::read_to_string("/etc/group").ok()?;

    field_of(&text, name, 2)
}

/// Reads the numeric field at `index` from the line naming `name`.
///
/// Both `/etc/passwd` and `/etc/group` are colon-separated with the name
/// first and the numeric id third.
fn field_of(text: &str, name: &str, index: usize) -> Option<u32> {
    text.lines().find_map(|line| {
        let mut f = line.split(':');
        if f.next()? != name {
            return None;
        }

        f.nth(index - 1)?.parse().ok()
    })
}

/// Switches the process to a group.
#[cfg(unix)]
pub fn set_group(name: &str) -> Result<u32, Error> {
    let gid = lookup_gid(name).ok_or_else(|| Error::NotFound {
        kind: "group",
        name: name.to_string(),
    })?;

    set_gid(gid)?;

    Ok(gid)
}

/// Switches the process to a user.
#[cfg(unix)]
pub fn set_user(name: &str) -> Result<u32, Error> {
    let uid = lookup_uid(name).ok_or_else(|| Error::NotFound {
        kind: "user",
        name: name.to_string(),
    })?;

    set_uid(uid)?;

    Ok(uid)
}

/// Applies the group id.
#[cfg(all(unix, target_os = "linux"))]
fn set_gid(gid: u32) -> Result<(), Error> {
    // Safe wrappers; on Linux these act on the calling thread, which is why
    // this runs before the runtime spawns any others.
    rustix::thread::set_thread_gid(rustix::thread::Gid::from_raw(gid)).map_err(|e| Error::Syscall {
        what: "setting the group id",
        source: e.into(),
    })
}

/// Applies the user id.
#[cfg(all(unix, target_os = "linux"))]
fn set_uid(uid: u32) -> Result<(), Error> {
    rustix::thread::set_thread_uid(rustix::thread::Uid::from_raw(uid)).map_err(|e| Error::Syscall {
        what: "setting the user id",
        source: e.into(),
    })
}

/// Applies the group id.
///
/// rustix only exposes the thread-scoped form on Linux, so elsewhere the
/// setting is reported as unsupported rather than silently ignored.
#[cfg(all(unix, not(target_os = "linux")))]
fn set_gid(_gid: u32) -> Result<(), Error> {
    Err(Error::Unsupported("os.group"))
}

/// Applies the user id.
#[cfg(all(unix, not(target_os = "linux")))]
fn set_uid(_uid: u32) -> Result<(), Error> {
    Err(Error::Unsupported("os.user"))
}

/// Switches the process to a group.
#[cfg(not(unix))]
pub fn set_group(_name: &str) -> Result<u32, Error> {
    Err(Error::Unsupported("os.group"))
}

/// Switches the process to a user.
#[cfg(not(unix))]
pub fn set_user(_name: &str) -> Result<u32, Error> {
    Err(Error::Unsupported("os.user"))
}

/// Raises the limit on open file descriptors.
#[cfg(unix)]
pub fn set_rlimit_nofile(limit: u64) -> Result<(), Error> {
    use rustix::process::{Resource, Rlimit, setrlimit};

    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(limit),
            maximum: Some(limit),
        },
    )
    .map_err(|e| Error::Syscall {
        what: "setting the descriptor limit",
        source: e.into(),
    })
}

/// Raises the limit on open file descriptors.
#[cfg(not(unix))]
pub fn set_rlimit_nofile(_limit: u64) -> Result<(), Error> {
    Err(Error::Unsupported("os.rlimit_nofile"))
}

/// The descriptor limit the process runs under now -- the soft one -- or
/// `None` when it is unlimited or cannot be known.
#[cfg(unix)]
pub fn nofile_limit() -> Option<u64> {
    rustix::process::getrlimit(rustix::process::Resource::Nofile).current
}

/// The descriptor limit the process runs under now.
#[cfg(not(unix))]
pub fn nofile_limit() -> Option<u64> {
    None
}

/// What Go's runtime raises the soft descriptor limit to when it starts, or
/// `None` when it leaves it alone.
///
/// Go has done this since 1.19, in `syscall`'s `init`, before `main`, on
/// every Unix.  In 1.26, which AdGuard Home v0.107.79 is built with:
///
/// ```go
/// if err := Getrlimit(RLIMIT_NOFILE, &lim); err == nil && lim.Max > 0 && lim.Cur < lim.Max-1 {
///     nlim := lim
///     nlim.Cur = nlim.Max - 1
///     adjustFileLimit(&nlim)          // darwin: at most kern.maxfilesperproc
///     setrlimit(RLIMIT_NOFILE, &nlim)
/// }
/// ```
///
/// so the same unit file that leaves a process 1,024 descriptors gives the Go
/// build the hard limit, half a million under systemd's defaults.  `max` is
/// the hard limit with infinity as `u64::MAX`, which is Linux's
/// `RLIM_INFINITY`: there Go asks for one less and the kernel refuses, so
/// Go's limit stays where it was, and so does this one.  `cap` is darwin's
/// per-process ceiling.
///
/// One deliberate difference: Go *lowers* a soft limit that is already above
/// darwin's ceiling, and this never lowers anything.
pub fn go_raised_nofile(current: u64, max: u64, cap: Option<u64>) -> Option<u64> {
    if max == 0 || current >= max - 1 {
        return None;
    }

    let target = cap.map_or(max - 1, |c| c.min(max - 1));

    (target > current).then_some(target)
}

/// darwin's per-process descriptor ceiling, `kern.maxfilesperproc`.
///
/// Read with `sysctl(8)`: the system call itself is out of reach without
/// `unsafe`, and this runs once, before anything else has started.
#[cfg(target_os = "macos")]
fn per_process_cap() -> Option<u64> {
    let out = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.maxfilesperproc"])
        .output()
        .ok()?;

    String::from_utf8(out.stdout).ok()?.trim().parse().ok()
}

/// Every other Unix leaves the limit to the kernel.
#[cfg(not(target_os = "macos"))]
fn per_process_cap() -> Option<u64> {
    None
}

/// Raises the soft descriptor limit the way Go's runtime does at start.
///
/// The Go build gets this whether or not `os.rlimit_nofile` is set, before
/// anything reads its configuration; without it, a unit file or a container
/// that worked for the Go build left this one with a thousand descriptors,
/// which a scan of the DNS-over-TLS port uses up in seconds.
#[cfg(unix)]
fn raise_nofile_like_go() {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    let lim = getrlimit(Resource::Nofile);
    // An unlimited soft limit has nowhere to go.
    let Some(current) = lim.current else {
        return;
    };
    let Some(target) =
        go_raised_nofile(current, lim.maximum.unwrap_or(u64::MAX), per_process_cap())
    else {
        return;
    };

    let raised = setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(target),
            maximum: lim.maximum,
        },
    );
    match raised {
        Ok(()) => tracing::info!(from = current, to = target, "descriptor limit raised"),
        // Go says nothing; the limit it was left with is worth a line, since
        // the connection limits are sized from it.
        Err(e) => tracing::warn!(limit = current, error = %e, "raising the descriptor limit"),
    }
}

/// Nothing to raise off Unix.
#[cfg(not(unix))]
fn raise_nofile_like_go() {}

/// Applies the `os` block of the configuration.
///
/// A setting the platform cannot honour is a warning rather than a failure, as
/// upstream treats it: the server is still usable, just not confined.
pub fn apply(os: &sift_config::model::OsConfig) {
    // First, as Go's runtime does it before AdGuard Home reads anything; an
    // explicit `rlimit_nofile` then replaces it, as it does there.
    raise_nofile_like_go();

    if os.rlimit_nofile != 0 {
        match set_rlimit_nofile(os.rlimit_nofile) {
            Ok(()) => tracing::info!(limit = os.rlimit_nofile, "descriptor limit set"),
            Err(e) => tracing::warn!(error = %e, "setting the descriptor limit"),
        }
    }

    // The group must be dropped first: once the user is no longer root, the
    // group can no longer be changed.
    if !os.group.is_empty() {
        match set_group(&os.group) {
            Ok(gid) => tracing::info!(group = %os.group, gid, "group set"),
            Err(e) => tracing::warn!(error = %e, "setting the group"),
        }
    }

    if !os.user.is_empty() {
        match set_user(&os.user) {
            Ok(uid) => tracing::info!(user = %os.user, uid, "user set"),
            Err(e) => tracing::warn!(error = %e, "setting the user"),
        }
    }
}

/// Writes the process identifier to a file.
pub fn write_pidfile(path: &Path) -> io::Result<()> {
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir)?;
    }

    std::fs::write(path, format!("{}\n", std::process::id()))
}

/// Removes the PID file, ignoring a missing one.
pub fn remove_pidfile(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "\
root:x:0:0:root:/root:/bin/sh
adguardhome:x:1001:1001::/opt/adguardhome:/sbin/nologin
";

    const GROUP: &str = "\
root:x:0:
adguardhome:x:1001:
";

    #[test]
    fn names_resolve_to_ids() {
        assert_eq!(field_of(PASSWD, "adguardhome", 2), Some(1001));
        assert_eq!(field_of(PASSWD, "root", 2), Some(0));
        assert_eq!(field_of(PASSWD, "nobody", 2), None);
        assert_eq!(field_of(GROUP, "adguardhome", 2), Some(1001));
    }

    #[test]
    fn a_numeric_id_needs_no_lookup() {
        // A container image usually has no passwd entry for the id it runs as.
        assert_eq!(lookup_uid("65534"), Some(65534));
        assert_eq!(lookup_gid("0"), Some(0));
    }

    #[test]
    fn the_descriptor_limit_is_raised_as_gos_runtime_raises_it() {
        // A systemd unit's defaults: Go runs with one short of the hard limit.
        assert_eq!(go_raised_nofile(1024, 524_288, None), Some(524_287));
        // Docker's.
        assert_eq!(go_raised_nofile(1024, 1_048_576, None), Some(1_048_575));
        // darwin, whose hard limit is unlimited, stops at its ceiling.
        assert_eq!(go_raised_nofile(256, u64::MAX, Some(61_440)), Some(61_440));
        // Linux with an unlimited hard limit: Go asks for one less than
        // infinity, and the kernel refuses it there as it will here.
        assert_eq!(go_raised_nofile(1024, u64::MAX, None), Some(u64::MAX - 1));
    }

    #[test]
    fn a_limit_already_where_go_would_put_it_is_left_alone() {
        assert_eq!(go_raised_nofile(524_287, 524_288, None), None);
        assert_eq!(go_raised_nofile(524_288, 524_288, None), None);
        assert_eq!(go_raised_nofile(0, 0, None), None, "a hard limit of zero");
        // Go would lower this to darwin's ceiling; nothing here lowers a limit.
        assert_eq!(go_raised_nofile(1_048_576, u64::MAX, Some(61_440)), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_descriptor_limit_can_be_read() {
        // Whatever the test runner was given, it is something.
        assert!(nofile_limit().is_none_or(|n| n > 0));
    }

    #[test]
    fn a_pidfile_is_written_and_removed() {
        let dir = std::env::temp_dir().join(format!("sift-pid-{}", std::process::id()));
        let path = dir.join("agh.pid");

        write_pidfile(&path).expect("the pid file should be writable");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.trim(), std::process::id().to_string());

        remove_pidfile(&path);
        assert!(!path.exists());
        // Removing a missing file is not an error.
        remove_pidfile(&path);

        std::fs::remove_dir_all(&dir).ok();
    }
}
