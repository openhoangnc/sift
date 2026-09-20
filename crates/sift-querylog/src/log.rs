//! The query log itself: an in-memory buffer backed by `querylog.json`.
//!
//! Layout matches the Go implementation, because an existing installation's
//! log must stay usable:
//!
//! ```text
//! <data>/querylog.json      the current file, one JSON object per line
//! <data>/querylog.json.1    the previous file, after a rotation
//! ```
//!
//! Entries are buffered in memory up to `size_memory` and appended in one
//! write, which is what keeps the log cheap on the query path.

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;

use crate::entry::Entry;

/// Query log settings.
#[derive(Clone, Debug)]
pub struct Config {
    /// Whether the log is collected at all.
    pub enabled: bool,
    /// Whether entries are written to disk.
    pub file_enabled: bool,
    /// How many entries are held in memory before a flush.
    pub size_memory: usize,
    /// Hosts excluded from the log.
    pub ignored: Vec<String>,
    /// Whether `ignored` is honoured.
    pub ignored_enabled: bool,
    /// Whether client addresses are anonymised.
    pub anonymize_client_ip: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: true,
            file_enabled: true,
            size_memory: 1000,
            ignored: Vec::new(),
            ignored_enabled: false,
            anonymize_client_ip: false,
        }
    }
}

/// The query log.
pub struct QueryLog {
    /// Where the current file lives.
    path: PathBuf,
    /// Where the rotated file lives.
    rotated: PathBuf,
    /// Settings, replaceable while running.
    cfg: Mutex<Config>,
    /// Entries not yet written to disk, oldest first.
    pending: Mutex<Vec<Entry>>,
    /// Recent entries kept for the API, newest first.
    recent: Mutex<VecDeque<Entry>>,
}

/// How many entries the API-facing ring keeps, independent of `size_memory`.
const RECENT_CAP: usize = 5_000;

impl QueryLog {
    /// Opens the log at the given paths.
    pub fn new(path: PathBuf, rotated: PathBuf, cfg: Config) -> Self {
        Self {
            path,
            rotated,
            cfg: Mutex::new(cfg),
            pending: Mutex::new(Vec::new()),
            recent: Mutex::new(VecDeque::with_capacity(256)),
        }
    }

    /// Replaces the settings.
    pub fn set_config(&self, cfg: Config) {
        *self.cfg.lock() = cfg;
    }

    /// A snapshot of the settings.
    pub fn config(&self) -> Config {
        self.cfg.lock().clone()
    }

    /// The path of the current file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Records one entry.
    ///
    /// Returns whether it was accepted; an ignored host or a disabled log
    /// drops it.
    pub fn push(&self, e: Entry) -> bool {
        let cfg = self.cfg.lock().clone();
        if !cfg.enabled || self.is_ignored(&cfg, &e.question_host) {
            return false;
        }

        {
            let mut recent = self.recent.lock();
            recent.push_front(e.clone());
            if recent.len() > RECENT_CAP {
                recent.pop_back();
            }
        }

        if !cfg.file_enabled {
            return true;
        }

        let should_flush = {
            let mut pending = self.pending.lock();
            pending.push(e);

            pending.len() >= cfg.size_memory.max(1)
        };

        if should_flush {
            let _ = self.flush();
        }

        true
    }

    /// Reports whether a host is excluded from the log.
    fn is_ignored(&self, cfg: &Config, host: &str) -> bool {
        if !cfg.ignored_enabled {
            return false;
        }

        cfg.ignored.iter().any(|i| {
            // "." is the root domain, which upstream treats as "everything".
            i == "." || sift_core::name::is_subdomain_of(host, &i.to_ascii_lowercase())
        })
    }

    /// Writes buffered entries to disk.
    pub fn flush(&self) -> std::io::Result<usize> {
        let batch: Vec<Entry> = {
            let mut pending = self.pending.lock();
            if pending.is_empty() {
                return Ok(0);
            }

            std::mem::take(&mut *pending)
        };

        if let Some(dir) = self.path.parent() {
            sift_core::perms::create_dir_all(dir)?;
        }

        // 0o600 at creation, as upstream's `aghos.DefaultPermFile` is: this
        // file records every name every client on the network looked up.
        let file = open_restricted(&self.path)?;
        let mut w = BufWriter::new(file);
        let mut written = 0;
        for e in &batch {
            if let Ok(line) = e.to_line() {
                w.write_all(line.as_bytes())?;
                written += 1;
            }
        }
        w.flush()?;

        Ok(written)
    }

    /// Rotates the log when its oldest entry is older than `interval`.
    ///
    /// The decision comes from the **first record in the file**, not from the
    /// file's own timestamps: upstream's `checkAndRotate` reads the first 512
    /// bytes, takes the `T` field out of them, and rotates once that moment
    /// plus the interval has passed.  A file that is being appended to was
    /// modified moments ago, so a modification time would never fire.
    ///
    /// Returns whether it rotated.
    pub fn rotate_if_due(&self, interval: std::time::Duration) -> std::io::Result<bool> {
        let Some(oldest) = first_entry_secs(&self.path) else {
            return Ok(false);
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        if oldest.saturating_add(interval.as_secs() as i64) > now {
            return Ok(false);
        }

        self.rotate()?;

        Ok(true)
    }

    /// Rotates the current file over the previous one.
    pub fn rotate(&self) -> std::io::Result<()> {
        self.flush()?;
        if !self.path.exists() {
            return Ok(());
        }

        std::fs::rename(&self.path, &self.rotated)
    }

    /// Removes every entry, in memory and on disk.
    pub fn clear(&self) -> std::io::Result<()> {
        self.pending.lock().clear();
        self.recent.lock().clear();

        for p in [&self.path, &self.rotated] {
            match std::fs::remove_file(p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Returns entries newest first, reading memory before disk.
    ///
    /// `limit` caps how many are returned; `offset` skips that many first.
    pub fn read(&self, offset: usize, limit: usize) -> Vec<Entry> {
        let mut out: Vec<Entry> = Vec::with_capacity(limit.min(1024));

        {
            let recent = self.recent.lock();
            out.extend(recent.iter().skip(offset).take(limit).cloned());
        }

        if out.len() >= limit {
            return out;
        }

        // Fall back to the files, newest first.  The in-memory ring already
        // covered the newest entries, so skip past what it supplied.
        let already = self.recent.lock().len();
        let file_offset = offset.saturating_sub(already);
        let want = limit - out.len();

        for p in [&self.path, &self.rotated] {
            if out.len() >= limit {
                break;
            }
            out.extend(read_tail(p, file_offset, want.saturating_sub(out.len())));
        }

        out
    }

    /// The number of entries the recent-entry ring holds.
    ///
    /// Capped at [`RECENT_CAP`], so this stands still once the server has
    /// been asked that many things; a snapshot reports it to say so.
    pub fn recent(&self) -> usize {
        self.recent.lock().len()
    }

    /// The number of entries held in memory.
    pub fn buffered(&self) -> usize {
        self.pending.lock().len()
    }
}

/// The `T` field of a log's first record, as a Unix second.
///
/// Scans the first 512 bytes for it, as upstream's `readJSONValue` does,
/// rather than parsing the line: the field is the first one every record
/// carries, and a record can be much longer than the answer is worth.
fn first_entry_secs(path: &Path) -> Option<i64> {
    use std::io::Read;

    const KEY: &str = "\"T\":\"";

    let mut buf = [0u8; 512];
    let n = std::fs::File::open(path).ok()?.read(&mut buf).ok()?;
    let head = String::from_utf8_lossy(&buf[..n]);

    let rest = &head[head.find(KEY)? + KEY.len()..];

    sift_core::gotime::parse_rfc3339_secs(&rest[..rest.find('"')?])
}

/// Reads up to `limit` entries from the end of a file, newest first.
///
/// Reads backwards in chunks so a multi-gigabyte log does not have to be
/// loaded to answer a request for the most recent hundred entries.
pub fn read_tail(path: &Path, offset: usize, limit: usize) -> Vec<Entry> {
    use std::io::{Read, Seek, SeekFrom};

    if limit == 0 {
        return Vec::new();
    }

    let Ok(mut f) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let Ok(meta) = f.metadata() else {
        return Vec::new();
    };

    let mut pos = meta.len();
    let mut carry: Vec<u8> = Vec::new();
    let mut out = Vec::with_capacity(limit.min(1024));
    let mut skipped = 0usize;

    const CHUNK: u64 = 64 * 1024;

    while pos > 0 && out.len() < limit {
        let take = CHUNK.min(pos);
        pos -= take;
        if f.seek(SeekFrom::Start(pos)).is_err() {
            break;
        }

        let mut buf = vec![0u8; take as usize];
        if f.read_exact(&mut buf).is_err() {
            break;
        }
        buf.extend_from_slice(&carry);

        // Everything before the first newline belongs to the previous chunk.
        let first_nl = buf.iter().position(|&b| b == b'\n');
        let (head, body) = match first_nl {
            Some(i) if pos > 0 => buf.split_at(i + 1),
            _ => (&[][..], &buf[..]),
        };
        carry = head.to_vec();

        for line in body.split(|&b| b == b'\n').rev() {
            if line.is_empty() {
                continue;
            }
            let Ok(text) = std::str::from_utf8(line) else {
                continue;
            };
            let Ok(e) = Entry::from_line(text.trim()) else {
                continue;
            };

            if skipped < offset {
                skipped += 1;

                continue;
            }

            out.push(e);
            if out.len() >= limit {
                break;
            }
        }
    }

    out
}

/// Opens the log for appending, creating it with upstream's file mode.
#[cfg(unix)]
fn open_restricted(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(sift_core::perms::FILE)
        .open(path)
}

/// Opens the log for appending.
#[cfg(not(unix))]
fn open_restricted(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Result as EntryResult;
    use std::time::Duration;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sift-qlog-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();

        d
    }

    fn log(dir: &Path, cfg: Config) -> QueryLog {
        QueryLog::new(dir.join("querylog.json"), dir.join("querylog.json.1"), cfg)
    }

    fn entry(host: &str) -> Entry {
        Entry {
            time: "2026-09-14T17:41:53.85+07:00".into(),
            question_host: host.into(),
            question_type: "A".into(),
            question_class: "IN".into(),
            ip: "127.0.0.1".into(),
            elapsed: 1234,
            result: EntryResult::default(),
            ..Default::default()
        }
    }

    #[test]
    fn buffers_then_flushes_to_disk() {
        let d = tmpdir("flush");
        let l = log(
            &d,
            Config {
                size_memory: 3,
                ..Default::default()
            },
        );

        l.push(entry("a.com"));
        l.push(entry("b.com"));
        assert_eq!(l.buffered(), 2);
        assert!(
            !d.join("querylog.json").exists(),
            "should not write before the buffer fills"
        );

        l.push(entry("c.com"));
        assert_eq!(l.buffered(), 0, "the buffer should have flushed");

        let written = std::fs::read_to_string(d.join("querylog.json")).unwrap();
        assert_eq!(written.lines().count(), 3);

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_disabled_log_records_nothing() {
        let d = tmpdir("disabled");
        let l = log(
            &d,
            Config {
                enabled: false,
                ..Default::default()
            },
        );
        assert!(!l.push(entry("a.com")));
        assert!(l.read(0, 10).is_empty());

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn memory_only_mode_keeps_entries_off_disk() {
        let d = tmpdir("memonly");
        let l = log(
            &d,
            Config {
                file_enabled: false,
                size_memory: 1,
                ..Default::default()
            },
        );
        assert!(l.push(entry("a.com")));
        l.flush().unwrap();

        assert!(!d.join("querylog.json").exists());
        assert_eq!(
            l.read(0, 10).len(),
            1,
            "but it is still readable by the API"
        );

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn ignored_hosts_are_dropped() {
        let d = tmpdir("ignored");
        let l = log(
            &d,
            Config {
                ignored: vec!["ads.example.com".into()],
                ignored_enabled: true,
                ..Default::default()
            },
        );

        assert!(!l.push(entry("ads.example.com")));
        assert!(
            !l.push(entry("sub.ads.example.com")),
            "subdomains are covered too"
        );
        assert!(l.push(entry("other.com")));

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn the_root_domain_ignores_everything() {
        let d = tmpdir("root");
        let l = log(
            &d,
            Config {
                ignored: vec![".".into()],
                ignored_enabled: true,
                ..Default::default()
            },
        );
        assert!(!l.push(entry("anything.com")));

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn ignoring_is_off_unless_enabled() {
        let d = tmpdir("ignoff");
        let l = log(
            &d,
            Config {
                ignored: vec!["ads.example.com".into()],
                ignored_enabled: false,
                ..Default::default()
            },
        );
        assert!(l.push(entry("ads.example.com")));

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn reads_newest_first() {
        let d = tmpdir("order");
        let l = log(
            &d,
            Config {
                size_memory: 1000,
                ..Default::default()
            },
        );
        for h in ["first.com", "second.com", "third.com"] {
            l.push(entry(h));
        }

        let got = l.read(0, 10);
        assert_eq!(got[0].question_host, "third.com");
        assert_eq!(got[2].question_host, "first.com");

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn paging_skips_with_the_offset() {
        let d = tmpdir("paging");
        let l = log(
            &d,
            Config {
                size_memory: 1000,
                ..Default::default()
            },
        );
        for i in 0..10 {
            l.push(entry(&format!("h{i}.com")));
        }

        let page = l.read(2, 3);
        assert_eq!(page.len(), 3);
        assert_eq!(page[0].question_host, "h7.com");

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn rotation_moves_the_current_file_aside() {
        let d = tmpdir("rotate");
        let l = log(
            &d,
            Config {
                size_memory: 1,
                ..Default::default()
            },
        );
        l.push(entry("a.com"));
        l.rotate().unwrap();

        assert!(!d.join("querylog.json").exists());
        assert!(d.join("querylog.json.1").exists());

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn rotation_is_due_once_the_oldest_entry_is_older_than_the_interval() {
        // Nothing rotated the query log at all until this was wired up:
        // `querylog.interval` was carried through the config and read by
        // nobody, so the file grew for as long as the server ran.
        let d = tmpdir("rotate-due");
        let l = log(
            &d,
            Config {
                size_memory: 1,
                ..Default::default()
            },
        );

        let mut old = entry("old.com");
        old.time = "2020-01-01T00:00:00Z".into();
        l.push(old);
        assert!(d.join("querylog.json").exists());

        assert!(l.rotate_if_due(Duration::from_secs(86_400)).unwrap());
        assert!(!d.join("querylog.json").exists());
        assert!(d.join("querylog.json.1").exists());

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_log_inside_its_interval_is_left_alone() {
        // The decision is the first record's own timestamp, not the file's:
        // a log being appended to was modified moments ago, so a modification
        // time would never come due.
        let d = tmpdir("rotate-early");
        let l = log(
            &d,
            Config {
                size_memory: 1,
                ..Default::default()
            },
        );

        let mut old = entry("old.com");
        old.time = "2020-01-01T00:00:00Z".into();
        l.push(old);

        let century = Duration::from_secs(100 * 365 * 86_400);
        assert!(!l.rotate_if_due(century).unwrap());
        assert!(d.join("querylog.json").exists());
        assert!(!d.join("querylog.json.1").exists());

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_log_that_does_not_exist_is_not_due() {
        let d = tmpdir("rotate-missing");
        let l = log(&d, Config::default());

        assert!(!l.rotate_if_due(Duration::from_secs(1)).unwrap());

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn clearing_removes_both_files_and_the_buffer() {
        let d = tmpdir("clear");
        let l = log(
            &d,
            Config {
                size_memory: 1,
                ..Default::default()
            },
        );
        l.push(entry("a.com"));
        l.rotate().unwrap();
        l.push(entry("b.com"));

        l.clear().unwrap();
        assert!(!d.join("querylog.json").exists());
        assert!(!d.join("querylog.json.1").exists());
        assert!(l.read(0, 10).is_empty());

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn reads_from_disk_when_memory_is_cold() {
        let d = tmpdir("cold");
        // Write a file directly, as a previous run would have left it.
        let mut text = String::new();
        for i in 0..2500 {
            text.push_str(&entry(&format!("h{i}.com")).to_line().unwrap());
        }
        std::fs::write(d.join("querylog.json"), text).unwrap();

        let got = read_tail(&d.join("querylog.json"), 0, 5);
        assert_eq!(got.len(), 5);
        assert_eq!(got[0].question_host, "h2499.com", "newest first");
        assert_eq!(got[4].question_host, "h2495.com");

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn reading_a_missing_file_is_not_an_error() {
        let d = tmpdir("missing");
        assert!(read_tail(&d.join("nothing.json"), 0, 10).is_empty());

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn entries_written_are_readable_by_the_parser() {
        let d = tmpdir("roundtrip");
        let l = log(
            &d,
            Config {
                size_memory: 1,
                ..Default::default()
            },
        );
        let mut e = entry("example.com");
        e.upstream = "https://dns10.quad9.net:443/dns-query".into();
        e.cached = true;
        l.push(e.clone());

        let back = read_tail(&d.join("querylog.json"), 0, 1);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0], e);

        std::fs::remove_dir_all(&d).ok();
    }
}
