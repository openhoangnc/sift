//! Filter list storage, refresh and engine construction.
//!
//! Lists live in `<work>/data/filters/<id>.txt` exactly as the Go
//! implementation writes them — raw rule text, no header — so an existing
//! installation's downloaded lists are picked up without a re-download.

use std::path::PathBuf;
use std::sync::Arc;

use crate::engine::Engine;
use sift_config::model::FilterYaml;

use jiff::Timestamp;

use sift_config::Paths;

/// The list identifier used for the user's own rules.
///
/// These match upstream's `rulelist.APIID` constants, which the web UI knows
/// by number when it labels where a block came from.
pub const CUSTOM_LIST_ID: i64 = 0;

/// The list identifier for rules derived from the system hosts file.
pub const ETC_HOSTS_LIST_ID: i64 = -1;

/// The list identifier for the blocked-services rules.
pub const BLOCKED_SERVICE_LIST_ID: i64 = -2;

/// One filter list and its loaded contents.
#[derive(Clone, Debug)]
pub struct List {
    /// The list identifier.
    pub id: i64,
    /// Where the list is fetched from.
    pub url: String,
    /// The display name.
    pub name: String,
    /// Whether the list is applied.
    pub enabled: bool,
    /// Whether this is an allowlist.
    pub allowlist: bool,
    /// The rule text, as loaded from disk.
    ///
    /// Shared rather than owned outright: the engine's rules point into these
    /// bytes instead of keeping a second copy of them.
    pub text: Arc<str>,
    /// The number of rules the text holds.
    pub rules_count: usize,
    /// When the list was last written.
    pub last_updated: Option<Timestamp>,
}

impl List {
    /// Builds a list from its configuration entry, with no contents yet.
    pub fn from_config(f: &FilterYaml, allowlist: bool) -> Self {
        Self {
            id: f.id,
            url: f.url.clone(),
            name: f.name.clone(),
            enabled: f.enabled,
            allowlist,
            text: Arc::from(""),
            rules_count: 0,
            last_updated: None,
        }
    }

    /// Converts back to a configuration entry.
    pub fn to_config(&self) -> FilterYaml {
        FilterYaml {
            enabled: self.enabled,
            url: self.url.clone(),
            name: self.name.clone(),
            id: self.id,
        }
    }

    /// Loads the list's contents from disk, if the file exists.
    pub fn load(&mut self, paths: &Paths) {
        let p = paths.filter_file(self.id);
        let Ok(text) = std::fs::read_to_string(&p) else {
            return;
        };

        self.last_updated = std::fs::metadata(&p)
            .and_then(|m| m.modified())
            .ok()
            .map(|t| Timestamp::try_from(t).unwrap_or(Timestamp::UNIX_EPOCH));
        self.rules_count = count_rules(&text);
        self.text = Arc::from(text);
    }

    /// Moves the file's timestamps on without rewriting it.
    ///
    /// What upstream does when a download matches what it already had: its
    /// `update` calls `os.Chtimes` rather than replacing the file, so a list
    /// that has not changed is not written again and is still not due until
    /// the next interval.  On a stack of large lists that is the difference
    /// between a few kilobytes of metadata and rewriting every one of them.
    pub fn touch(&self, paths: &Paths) -> std::io::Result<()> {
        let now = std::time::SystemTime::now();
        let times = std::fs::FileTimes::new()
            .set_accessed(now)
            .set_modified(now);

        std::fs::File::options()
            .write(true)
            .open(paths.filter_file(self.id))?
            .set_times(times)
    }

    /// Writes the list's contents to disk, with upstream's modes.
    pub fn save(&self, paths: &Paths) -> std::io::Result<()> {
        let p = paths.filter_file(self.id);
        if let Some(dir) = p.parent() {
            sift_core::perms::create_dir_all(dir)?;
        }

        std::fs::write(&p, self.text.as_bytes())?;

        sift_core::perms::restrict_file(&p)
    }
}

/// Counts the rules in a list, skipping blanks and comments the way upstream
/// does when reporting `rules_count`.
pub fn count_rules(text: &str) -> usize {
    text.lines()
        .filter(|l| {
            let t = l.trim();

            !t.is_empty() && !t.starts_with('!') && !t.starts_with('#')
        })
        .count()
}

/// What storing a freshly fetched list did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fetched {
    /// The contents differed from what was stored, and were written.
    Written {
        /// How many rules the new contents hold.
        rules: usize,
    },
    /// The contents matched what was already there, so nothing was rewritten.
    Unchanged,
}

impl Fetched {
    /// Whether anything changed, which is what decides if the engine has to
    /// be rebuilt and the configuration written.
    pub fn changed(self) -> bool {
        matches!(self, Fetched::Written { .. })
    }
}

/// Holds every list and builds the filtering engine from them.
#[derive(Clone, Debug, Default)]
pub struct Manager {
    /// Blocklists.
    pub blocklists: Vec<List>,
    /// Allowlists.
    pub allowlists: Vec<List>,
    /// The user's own rules.
    pub user_rules: Vec<String>,
    /// The rules blocking the services the user selected.
    pub service_rules: String,
    /// Host rules taken from the system hosts file.
    pub hosts_rules: String,
}

impl Manager {
    /// Builds a manager from the configured lists, loading contents from disk.
    pub fn load(
        paths: &Paths,
        block: &[FilterYaml],
        allow: &[FilterYaml],
        user: &[String],
    ) -> Self {
        let mut m = Manager {
            blocklists: block.iter().map(|f| List::from_config(f, false)).collect(),
            allowlists: allow.iter().map(|f| List::from_config(f, true)).collect(),
            user_rules: user.to_vec(),
            service_rules: String::new(),
            hosts_rules: String::new(),
        };

        for l in m.blocklists.iter_mut().chain(m.allowlists.iter_mut()) {
            l.load(paths);
        }

        m
    }

    /// Replaces the blocked-services rules from a list of service identifiers.
    pub fn set_blocked_services(&mut self, ids: &[String]) {
        self.service_rules = crate::services::rules_for(ids);
    }

    /// Replaces the rules taken from the system hosts file.
    pub fn set_hosts(&mut self, contents: String) {
        self.hosts_rules = contents;
    }

    /// Builds the engine for the global blocked services, if any are set.
    ///
    /// These are kept out of the main engine so the weekly schedule can pause
    /// them for a request without rebuilding anything.
    pub fn build_services_engine(&self) -> Option<Engine> {
        if self.service_rules.trim().is_empty() {
            return None;
        }

        Some(Engine::build(
            [(BLOCKED_SERVICE_LIST_ID, self.service_rules.as_str())],
            crate::engine::NO_LISTS,
        ))
    }

    /// Builds a filtering engine from the enabled lists and the user's rules.
    ///
    /// The blocked services are **not** included; they get their own engine,
    /// because the schedule decides per request whether they apply.
    pub fn build_engine(&self) -> Engine {
        self.build_engine_from(None)
    }

    /// Builds the engine, carrying over the lists `previous` already parsed.
    ///
    /// What a refresh is for: it replaces a list's text only when the bytes
    /// differ, so the lists it left alone are the same `Arc` and their rules
    /// are shared with the engine still serving rather than parsed and
    /// allocated a second time.
    pub fn build_engine_with(&self, previous: &Engine) -> Engine {
        self.build_engine_from(Some(previous))
    }

    fn build_engine_from(&self, previous: Option<&Engine>) -> Engine {
        let user_text = self.user_rules.join("\n");

        // The lists are handed over by `Arc`, so the engine's rules point at
        // the bytes already loaded here rather than at a second copy. The two
        // synthesised sources are small and are copied once.
        let block: Vec<(i64, Arc<str>)> = [
            (CUSTOM_LIST_ID, Arc::from(user_text)),
            (ETC_HOSTS_LIST_ID, Arc::from(self.hosts_rules.as_str())),
        ]
        .into_iter()
        .chain(
            self.blocklists
                .iter()
                .filter(|l| l.enabled)
                .map(|l| (l.id, Arc::clone(&l.text))),
        )
        .collect();

        let allow: Vec<(i64, Arc<str>)> = self
            .allowlists
            .iter()
            .filter(|l| l.enabled)
            .map(|l| (l.id, Arc::clone(&l.text)))
            .collect();

        match previous {
            Some(p) => p.rebuild(block, allow),
            None => Engine::build(block, allow),
        }
    }

    /// The total number of rules across enabled lists.
    pub fn rules_count(&self) -> usize {
        self.blocklists
            .iter()
            .chain(&self.allowlists)
            .filter(|l| l.enabled)
            .map(|l| l.rules_count)
            .sum::<usize>()
            + self.user_rules.len()
    }

    /// Finds a list by identifier.
    pub fn find_mut(&mut self, id: i64) -> Option<&mut List> {
        self.blocklists
            .iter_mut()
            .chain(self.allowlists.iter_mut())
            .find(|l| l.id == id)
    }

    /// Allocates an identifier not already in use.
    pub fn next_id(&self) -> i64 {
        let max = self
            .blocklists
            .iter()
            .chain(&self.allowlists)
            .map(|l| l.id)
            .max()
            .unwrap_or(0);

        // Upstream assigns identifiers from the current time, but any unused
        // one works; keep them small and stable instead.
        (max + 1).max(1)
    }

    /// Stores freshly fetched contents for a list.
    ///
    /// Downloading lives in the caller: this crate stays free of an HTTP
    /// client so it can be used from tests and tools without one.
    pub fn apply_fetched(
        &mut self,
        paths: &Paths,
        id: i64,
        text: String,
    ) -> Result<Fetched, RefreshError> {
        let count = count_rules(&text);

        let list = self.find_mut(id).ok_or(RefreshError::NotFound(id))?;
        list.last_updated = Some(Timestamp::now());

        // A list that came back the same is not written again.  Upstream
        // compares a checksum of the download with the one it holds and
        // discards the temporary file when they match; the bytes are already
        // here, so compare those.
        if *list.text == *text {
            match list.touch(paths) {
                Ok(()) => return Ok(Fetched::Unchanged),
                // Nothing on disk to touch yet: write it after all.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(RefreshError::Io(e.to_string())),
            }
        }

        list.text = Arc::from(text);
        list.rules_count = count;
        list.save(paths)
            .map_err(|e| RefreshError::Io(e.to_string()))?;

        Ok(Fetched::Written { rules: count })
    }

    /// The URL a list is fetched from.
    pub fn url_of(&self, id: i64) -> Option<String> {
        self.blocklists
            .iter()
            .chain(&self.allowlists)
            .find(|l| l.id == id)
            .map(|l| l.url.clone())
    }

    /// The identifiers of every enabled list.
    /// The enabled lists whose own refresh interval has elapsed.
    ///
    /// Upstream refreshes a list when *its* `last_updated` plus the interval
    /// has passed, never on a multiple of the server's uptime.  That matters
    /// twice: a list that has never been fetched is due immediately, so a
    /// fresh install filters within moments rather than after the interval;
    /// and because `last_updated` comes from the file on disk, a server
    /// restarted more often than the interval still updates, where an uptime
    /// counter would reset and never fire.
    pub fn stale_ids(&self, interval: jiff::SignedDuration) -> Vec<i64> {
        let now = Timestamp::now();

        self.blocklists
            .iter()
            .chain(&self.allowlists)
            .filter(|l| l.enabled)
            .filter(|l| match l.last_updated {
                None => true,
                Some(t) => match t.checked_add(interval) {
                    Ok(due) => due <= now,
                    // Only an out-of-range interval gets here; treat the list
                    // as due rather than never refreshing it again.
                    Err(_) => true,
                },
            })
            .map(|l| l.id)
            .collect()
    }

    /// Every enabled list's identifier.
    pub fn enabled_ids(&self) -> Vec<i64> {
        self.blocklists
            .iter()
            .chain(&self.allowlists)
            .filter(|l| l.enabled)
            .map(|l| l.id)
            .collect()
    }
}

/// Resolves a filesystem list path, rejecting traversal outside the data
/// directory.
///
/// A list `url` that is not an HTTP(S) URL names a file; anything relative is
/// resolved under the user-filters directory so a configuration cannot point
/// the loader at arbitrary files.
pub fn local_list_path(paths: &Paths, url: &str) -> Result<PathBuf, RefreshError> {
    let raw = url.strip_prefix("file://").unwrap_or(url);
    let candidate = PathBuf::from(raw);
    let joined = if candidate.is_absolute() {
        candidate
    } else {
        paths.user_filters().join(candidate)
    };

    if joined
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(RefreshError::Io(format!(
            "path {url:?} escapes the data directory"
        )));
    }

    Ok(joined)
}

/// Reports whether a list `url` names a remote list.
pub fn is_remote(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

/// Why a list could not be refreshed.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    /// No list has that identifier.
    #[error("no filter list with id {0}")]
    NotFound(i64),

    /// The download failed.
    #[error("downloading: {0}")]
    Download(String),

    /// The list could not be read or written.
    #[error("filter list i/o: {0}")]
    Io(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> Paths {
        let base = std::env::temp_dir().join(format!("sift-filters-{tag}-{}", std::process::id()));
        let p = Paths::new(base.join("work"), base.join("conf/AdGuardHome.yaml"));
        p.ensure().unwrap();

        p
    }

    fn cfg(id: i64, enabled: bool) -> FilterYaml {
        FilterYaml {
            enabled,
            url: format!("https://example.invalid/{id}.txt"),
            name: format!("list {id}"),
            id,
        }
    }

    #[test]
    fn counts_rules_ignoring_comments_and_blanks() {
        let text = "! a comment\n\n||a.com^\n# another\n||b.com^\n";
        assert_eq!(count_rules(text), 2);
    }

    #[test]
    fn loads_list_contents_from_disk() {
        let p = tmpdir("load");
        std::fs::write(p.filter_file(1), "||ads.example.com^\n! note\n").unwrap();

        let m = Manager::load(&p, &[cfg(1, true)], &[], &[]);
        assert_eq!(m.blocklists[0].rules_count, 1);
        assert!(m.blocklists[0].last_updated.is_some());

        std::fs::remove_dir_all(p.work.parent().unwrap()).ok();
    }

    #[test]
    fn a_list_that_came_back_the_same_is_not_written_again() {
        // Rewriting every list on every refresh cycle is megabytes of writes
        // for nothing, and it made the caller rebuild the whole engine.
        let p = tmpdir("unchanged");
        let text = "||ads.example.com^\n";
        std::fs::write(p.filter_file(1), text).unwrap();
        let mut m = Manager::load(&p, &[cfg(1, true)], &[], &[]);

        // A sentinel in the file that only a rewrite would remove.
        std::fs::write(p.filter_file(1), "! sentinel\n").unwrap();
        let before = m.blocklists[0].last_updated;

        let got = m.apply_fetched(&p, 1, text.to_string()).unwrap();

        assert_eq!(got, Fetched::Unchanged);
        assert!(!got.changed());
        assert_eq!(
            std::fs::read_to_string(p.filter_file(1)).unwrap(),
            "! sentinel\n",
            "the file must not have been written"
        );
        assert!(
            m.blocklists[0].last_updated > before,
            "but it is no longer due"
        );

        std::fs::remove_dir_all(p.work.parent().unwrap()).ok();
    }

    #[test]
    fn a_list_whose_contents_differ_is_written() {
        let p = tmpdir("changed");
        std::fs::write(p.filter_file(1), "||old.example.com^\n").unwrap();
        let mut m = Manager::load(&p, &[cfg(1, true)], &[], &[]);

        let got = m
            .apply_fetched(&p, 1, "||new.example.com^\n! note\n".to_string())
            .unwrap();

        assert_eq!(got, Fetched::Written { rules: 1 });
        assert!(got.changed());
        assert_eq!(
            std::fs::read_to_string(p.filter_file(1)).unwrap(),
            "||new.example.com^\n! note\n"
        );

        std::fs::remove_dir_all(p.work.parent().unwrap()).ok();
    }

    #[test]
    fn a_list_with_no_file_yet_is_written_even_if_it_matches() {
        // The in-memory text of a list that has never been fetched is empty,
        // and so is a download that failed to produce anything; there is
        // nothing on disk to touch, so it has to be written.
        let p = tmpdir("first-fetch");
        let mut m = Manager::load(&p, &[cfg(1, true)], &[], &[]);
        assert!(!p.filter_file(1).exists());

        let got = m.apply_fetched(&p, 1, String::new()).unwrap();

        assert_eq!(got, Fetched::Written { rules: 0 });
        assert!(p.filter_file(1).exists());

        std::fs::remove_dir_all(p.work.parent().unwrap()).ok();
    }

    #[test]
    fn builds_an_engine_from_enabled_lists_only() {
        let p = tmpdir("engine");
        std::fs::write(p.filter_file(1), "||on.example.com^\n").unwrap();
        std::fs::write(p.filter_file(2), "||off.example.com^\n").unwrap();

        let m = Manager::load(&p, &[cfg(1, true), cfg(2, false)], &[], &[]);
        let e = m.build_engine();

        let matched = |h: &str| {
            e.match_request(&crate::engine::Request {
                hostname: h,
                qtype: 1,
                ..Default::default()
            })
            .reason
        };

        assert_eq!(
            matched("on.example.com"),
            sift_core::Reason::FilteredBlockList
        );
        assert_eq!(
            matched("off.example.com"),
            sift_core::Reason::NotFilteredNotFound
        );

        std::fs::remove_dir_all(p.work.parent().unwrap()).ok();
    }

    #[test]
    fn user_rules_are_applied_under_the_custom_list_id() {
        let p = tmpdir("user");
        let m = Manager::load(&p, &[], &[], &["||custom.example.com^".to_string()]);
        let e = m.build_engine();

        let r = e.match_request(&crate::engine::Request {
            hostname: "custom.example.com",
            qtype: 1,
            ..Default::default()
        });
        assert_eq!(r.reason, sift_core::Reason::FilteredBlockList);
        assert_eq!(r.rules[0].list_id, CUSTOM_LIST_ID);

        std::fs::remove_dir_all(p.work.parent().unwrap()).ok();
    }

    #[test]
    fn allowlists_short_circuit_blocklists() {
        let p = tmpdir("allow");
        std::fs::write(p.filter_file(1), "||example.com^\n").unwrap();
        std::fs::write(p.filter_file(10), "||example.com^\n").unwrap();

        let m = Manager::load(&p, &[cfg(1, true)], &[cfg(10, true)], &[]);
        let e = m.build_engine();

        let r = e.match_request(&crate::engine::Request {
            hostname: "example.com",
            qtype: 1,
            ..Default::default()
        });
        assert_eq!(r.reason, sift_core::Reason::NotFilteredAllowList);

        std::fs::remove_dir_all(p.work.parent().unwrap()).ok();
    }

    #[test]
    fn identifiers_do_not_collide() {
        let p = tmpdir("ids");
        let m = Manager::load(&p, &[cfg(1, true), cfg(7, true)], &[cfg(9, true)], &[]);
        assert_eq!(m.next_id(), 10);

        std::fs::remove_dir_all(p.work.parent().unwrap()).ok();
    }

    #[test]
    fn local_list_paths_cannot_escape_the_data_directory() {
        let p = tmpdir("escape");
        assert!(local_list_path(&p, "../../etc/passwd").is_err());
        assert!(local_list_path(&p, "mylist.txt").is_ok());

        std::fs::remove_dir_all(p.work.parent().unwrap()).ok();
    }

    #[test]
    fn blocked_services_get_their_own_engine() {
        // They are kept out of the main engine so the weekly schedule can
        // pause them per request without rebuilding anything.
        let p = tmpdir("services");
        let mut m = Manager::load(&p, &[], &[], &[]);
        m.set_blocked_services(&["youtube".into()]);

        let main = m.build_engine();
        assert_eq!(
            main.match_request(&crate::engine::Request {
                hostname: "www.youtube.com",
                qtype: 1,
                ..Default::default()
            })
            .reason,
            sift_core::Reason::NotFilteredNotFound,
            "the main engine must not carry the service rules"
        );

        let e = m
            .build_services_engine()
            .expect("a selected service must compile");
        let r = e.match_request(&crate::engine::Request {
            hostname: "www.youtube.com",
            qtype: 1,
            ..Default::default()
        });

        assert_eq!(r.reason, sift_core::Reason::FilteredBlockList);
        assert_eq!(
            r.rules[0].list_id, BLOCKED_SERVICE_LIST_ID,
            "the match must be attributed to the blocked-services list"
        );

        // And nothing is built once the service is deselected.
        m.set_blocked_services(&[]);
        assert!(m.build_services_engine().is_none());
        let e = m.build_engine();
        assert_eq!(
            e.match_request(&crate::engine::Request {
                hostname: "www.youtube.com",
                qtype: 1,
                ..Default::default()
            })
            .reason,
            sift_core::Reason::NotFilteredNotFound
        );

        std::fs::remove_dir_all(p.work.parent().unwrap()).ok();
    }

    #[test]
    fn hosts_file_entries_are_applied() {
        let p = tmpdir("hosts");
        let mut m = Manager::load(&p, &[], &[], &[]);
        m.set_hosts("192.168.1.5 nas.lan\n# a comment\n".into());

        let e = m.build_engine();
        let r = e.match_request(&crate::engine::Request {
            hostname: "nas.lan",
            qtype: 1,
            ..Default::default()
        });

        assert_eq!(r.rules[0].list_id, ETC_HOSTS_LIST_ID);
        assert_eq!(r.rules[0].ip, Some("192.168.1.5".parse().unwrap()));

        std::fs::remove_dir_all(p.work.parent().unwrap()).ok();
    }

    #[test]
    fn round_trips_through_the_config_representation() {
        let f = cfg(3, true);
        let l = List::from_config(&f, false);
        let back = l.to_config();
        assert_eq!(back.id, f.id);
        assert_eq!(back.url, f.url);
        assert_eq!(back.name, f.name);
        assert_eq!(back.enabled, f.enabled);
    }

    #[test]
    fn staleness_is_per_list_and_survives_a_restart() {
        // The bug this guards: refreshing on a multiple of the server's
        // uptime left a fresh install unfiltered for the whole interval, and
        // a server restarted more often than the interval never refreshed at
        // all, because the counter reset every boot.
        let day = jiff::SignedDuration::from_hours(24);
        let mut m = Manager::default();

        let mut never = List::from_config(
            &FilterYaml {
                enabled: true,
                url: "https://example.com/a.txt".into(),
                name: "never fetched".into(),
                id: 1,
            },
            false,
        );
        never.last_updated = None;

        let mut fresh = List::from_config(
            &FilterYaml {
                enabled: true,
                url: "https://example.com/b.txt".into(),
                name: "fetched an hour ago".into(),
                id: 2,
            },
            false,
        );
        fresh.last_updated = Some(Timestamp::now() - jiff::SignedDuration::from_hours(1));

        let mut old = List::from_config(
            &FilterYaml {
                enabled: true,
                url: "https://example.com/c.txt".into(),
                name: "fetched two days ago".into(),
                id: 3,
            },
            false,
        );
        old.last_updated = Some(Timestamp::now() - jiff::SignedDuration::from_hours(48));

        let mut disabled = List::from_config(
            &FilterYaml {
                enabled: false,
                url: "https://example.com/d.txt".into(),
                name: "disabled".into(),
                id: 4,
            },
            false,
        );
        disabled.last_updated = None;

        m.blocklists = vec![never, fresh, old, disabled];

        // Never-fetched and long-stale are due; the recent one is not, and a
        // disabled list is never downloaded.
        assert_eq!(m.stale_ids(day), vec![1, 3]);
    }
}
