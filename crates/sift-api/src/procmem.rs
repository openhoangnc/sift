//! What the kernel says this process is holding.
//!
//! The allocator's own accounting is not reachable without a C call, and the
//! tree carries no unsafe code; but everything a container's memory question
//! actually turns on is a file read.  `/proc/self/status` gives the resident
//! size and, in `VmHWM`, the high-water mark -- the difference between the two
//! is the memory the allocator is holding rather than using, which is what
//! separates a leak from a peak nothing gave back.  The cgroup files give the
//! number the container runtime reports, which is the one an operator is
//! looking at when they ask why it climbs.
//!
//! Everything here is optional: on a system without these files each field is
//! simply absent, and the snapshot is still worth reading for the counters
//! that come from inside the process.

use serde::Serialize;

/// The process, as `/proc/self` describes it.
#[derive(Debug, Default, Serialize)]
pub struct Process {
    /// Resident set size, in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss: Option<u64>,
    /// The largest resident set size this process has ever had, in bytes.
    ///
    /// Read beside `rss`: a gap between them is the allocator keeping a peak
    /// it has not returned, and a climb where the two rise together is
    /// something still being held.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_rss: Option<u64>,
    /// Resident anonymous memory, in bytes: the heap and the stacks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anon: Option<u64>,
    /// Resident file-backed memory, in bytes: the binary and anything mapped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<u64>,
    /// Threads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threads: Option<u64>,
    /// Open file descriptors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptors: Option<u64>,
    /// Mapped regions.
    ///
    /// glibc gives a thread its own arena rather than contending for one, and
    /// an arena is a mapping that is never unmapped, so a mapping count that
    /// climbs with nothing else is fragmentation rather than a leak.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mappings: Option<u64>,
}

/// The cgroup, as the container runtime accounts for it.
#[derive(Debug, Default, Serialize)]
pub struct Cgroup {
    /// The cgroup version the numbers came from, 1 or 2.
    pub version: u8,
    /// Current usage in bytes -- what `docker stats` reports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<u64>,
    /// The highest usage recorded, in bytes, where the kernel offers it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak: Option<u64>,
    /// The limit in bytes, absent when the group is unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<u64>,
    /// Anonymous memory in bytes: the part a leak lives in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anon: Option<u64>,
    /// Page cache in bytes: charged to the group, but reclaimable, so a rise
    /// here is not the process growing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<u64>,
    /// Kernel slab in bytes, where the kernel reports it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slab: Option<u64>,
    /// Socket buffers in bytes, where the kernel reports it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sock: Option<u64>,
}

/// Reads what `/proc/self` says, leaving every field absent where it does not.
///
/// Off Linux only the resident size is reachable, and only by asking `ps` --
/// which is what `sift-filter`'s load profile does for the same reason.  The
/// deployments this is for are containers, but a snapshot that reported
/// nothing at all on the machine the code is written on would never be tried
/// before it was needed.
pub fn process() -> Process {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    if status.is_empty() {
        return Process {
            rss: ps_rss(),
            ..Default::default()
        };
    }

    Process {
        rss: kb_field(&status, "VmRSS:"),
        peak_rss: kb_field(&status, "VmHWM:"),
        anon: kb_field(&status, "RssAnon:"),
        file: kb_field(&status, "RssFile:"),
        threads: count_field(&status, "Threads:"),
        descriptors: std::fs::read_dir("/proc/self/fd")
            .ok()
            .map(|d| d.count() as u64),
        mappings: std::fs::read_to_string("/proc/self/maps")
            .ok()
            .map(|m| m.lines().count() as u64),
    }
}

/// Reads the cgroup's memory accounting, or `None` outside one.
///
/// A container gets its own cgroup namespace, so the group's files are at the
/// mount point itself; a process in a named group on the host is not what this
/// is for and reports nothing rather than the root group's numbers, which
/// would be the whole machine.
pub fn cgroup() -> Option<Cgroup> {
    const V2: &str = "/sys/fs/cgroup";
    const V1: &str = "/sys/fs/cgroup/memory";

    if let Some(current) = read_u64(&format!("{V2}/memory.current")) {
        let stat = std::fs::read_to_string(format!("{V2}/memory.stat")).unwrap_or_default();

        return Some(Cgroup {
            version: 2,
            current: Some(current),
            peak: read_u64(&format!("{V2}/memory.peak")),
            max: read_u64(&format!("{V2}/memory.max")),
            anon: stat_field(&stat, "anon"),
            file: stat_field(&stat, "file"),
            slab: stat_field(&stat, "slab"),
            sock: stat_field(&stat, "sock"),
        });
    }

    let current = read_u64(&format!("{V1}/memory.usage_in_bytes"))?;
    let stat = std::fs::read_to_string(format!("{V1}/memory.stat")).unwrap_or_default();

    Some(Cgroup {
        version: 1,
        current: Some(current),
        peak: read_u64(&format!("{V1}/memory.max_usage_in_bytes")),
        // A group with no limit reports a number close to `u64::MAX`, which is
        // noise rather than a limit.
        max: read_u64(&format!("{V1}/memory.limit_in_bytes")).filter(|&m| m < u64::MAX / 2),
        anon: stat_field(&stat, "rss"),
        file: stat_field(&stat, "cache"),
        slab: None,
        sock: None,
    })
}

/// One `/proc/self/status` field that is spelled in kilobytes, as bytes.
fn kb_field(text: &str, name: &str) -> Option<u64> {
    count_field(text, name).map(|kb| kb * 1024)
}

/// One `/proc/self/status` field that is spelled as a bare number.
fn count_field(text: &str, name: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix(name))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// One `memory.stat` field: a name, a space and a number.
fn stat_field(text: &str, name: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| {
            let rest = l.strip_prefix(name)?;

            rest.strip_prefix(' ')
        })?
        .trim()
        .parse()
        .ok()
}

/// The resident size in bytes, from `ps`, for a system without `/proc`.
fn ps_rss() -> Option<u64> {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p"])
        .arg(std::process::id().to_string())
        .output()
        .ok()?;

    let kb: u64 = String::from_utf8(out.stdout).ok()?.trim().parse().ok()?;

    Some(kb * 1024)
}

/// A file holding one number, where `max` is not one.
fn read_u64(path: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "Name:\tAdGuardHome\nThreads:\t9\nVmSize:\t 1234567 kB\nVmHWM:\t  391168 kB\nVmRSS:\t  381952 kB\nRssAnon:\t  360448 kB\nRssFile:\t   21504 kB\n";

    #[test]
    fn the_status_file_reports_in_kilobytes() {
        assert_eq!(kb_field(STATUS, "VmRSS:"), Some(381_952 * 1024));
        assert_eq!(kb_field(STATUS, "VmHWM:"), Some(391_168 * 1024));
        assert_eq!(count_field(STATUS, "Threads:"), Some(9));
        assert_eq!(kb_field(STATUS, "Nothing:"), None);
    }

    #[test]
    fn a_stat_field_is_not_matched_by_its_prefix() {
        // `anon` and `anon_thp` differ by what follows the name, and taking
        // the first line that starts with one of them reports the wrong
        // number for a group whose file happens to order them the other way.
        let stat = "anon_thp 0\nfile 12288\nanon 402653184\nslab 1048576\n";

        assert_eq!(stat_field(stat, "anon"), Some(402_653_184));
        assert_eq!(stat_field(stat, "file"), Some(12288));
        assert_eq!(stat_field(stat, "sock"), None);
    }

    #[test]
    fn reading_what_is_not_there_is_not_an_error() {
        // Every field is optional, so a system without these files reports a
        // snapshot with the counters and nothing else.
        assert_eq!(read_u64("/sys/fs/cgroup/nothing-here"), None);

        let p = process();
        if let Some(rss) = p.rss {
            assert!(rss > 0, "a resident size that is reported is not zero");
        }
    }
}
