//! Statistics collection and the `/control/stats` response.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ahash::{AHashMap, AHashSet};
use parking_lot::Mutex;
use serde::Serialize;

use crate::unit::{
    CountPair, Entry, MAX_CLIENTS, MAX_DOMAINS, RESULT_COUNT, Result, Unit, UnitDb, current_hour,
    to_pairs,
};

/// Statistics settings.
#[derive(Clone, Debug)]
pub struct Config {
    /// Whether statistics are collected.
    pub enabled: bool,
    /// How many hours of history to keep and report.
    pub limit_hours: u32,
    /// Hosts excluded from the top-domain lists.
    pub ignored: Vec<String>,
    /// Whether `ignored` is honoured.
    pub ignored_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: true,
            limit_hours: 24,
            ignored: Vec::new(),
            ignored_enabled: false,
        }
    }
}

/// A top-N entry: one name mapped to its count.
///
/// The API renders these as single-key objects, e.g. `{"example.com": 12}`.
pub type TopAddrs = BTreeMap<String, u64>;

/// A top-N entry with a floating-point value.
pub type TopAddrsFloat = BTreeMap<String, f64>;

/// The `/control/stats` response.
#[derive(Clone, Debug, Serialize)]
pub struct StatsResp {
    /// Whether the per-unit arrays are hours or days.
    pub time_units: &'static str,

    /// The most queried domains.
    pub top_queried_domains: Vec<TopAddrs>,
    /// The busiest clients.
    pub top_clients: Vec<TopAddrs>,
    /// The most blocked domains.
    pub top_blocked_domains: Vec<TopAddrs>,
    /// Responses per upstream.
    pub top_upstreams_responses: Vec<TopAddrs>,
    /// Mean response time per upstream, in seconds.
    pub top_upstreams_avg_time: Vec<TopAddrsFloat>,

    /// Queries per time unit.
    pub dns_queries: Vec<u64>,
    /// Queries blocked by filtering, per time unit.
    pub blocked_filtering: Vec<u64>,
    /// Queries blocked by safe browsing, per time unit.
    pub replaced_safebrowsing: Vec<u64>,
    /// Queries blocked by parental control, per time unit.
    pub replaced_parental: Vec<u64>,

    /// Total queries.
    pub num_dns_queries: u64,
    /// Total blocked by filtering.
    pub num_blocked_filtering: u64,
    /// Total blocked by safe browsing.
    pub num_replaced_safebrowsing: u64,
    /// Total rewritten by safe search.
    pub num_replaced_safesearch: u64,
    /// Total blocked by parental control.
    pub num_replaced_parental: u64,
    /// Mean processing time, in seconds.
    pub avg_processing_time: f64,
}

impl StatsResp {
    /// The response returned when statistics are switched off.
    pub fn empty() -> Self {
        Self {
            time_units: "days",
            top_queried_domains: Vec::new(),
            top_clients: Vec::new(),
            top_blocked_domains: Vec::new(),
            top_upstreams_responses: Vec::new(),
            top_upstreams_avg_time: Vec::new(),
            dns_queries: Vec::new(),
            blocked_filtering: Vec::new(),
            replaced_safebrowsing: Vec::new(),
            replaced_parental: Vec::new(),
            num_dns_queries: 0,
            num_blocked_filtering: 0,
            num_replaced_safebrowsing: 0,
            num_replaced_safesearch: 0,
            num_replaced_parental: 0,
            avg_processing_time: 0.0,
        }
    }
}

/// What the collector is holding, reported by a memory snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sizes {
    /// Finished hours held, each capped to the form `stats.db` stores.
    pub past_hours: usize,
    /// Distinct names counted in the hour in progress.
    pub live_domains: usize,
    /// Distinct blocked names counted in the hour in progress.
    pub live_blocked_domains: usize,
    /// Distinct clients counted in the hour in progress.
    pub live_clients: usize,
    /// Distinct upstreams counted in the hour in progress.
    pub live_upstreams: usize,
}

/// The statistics collector.
pub struct Stats {
    cfg: Mutex<Config>,
    /// What is held in memory, live hour and history alike.
    inner: Mutex<Inner>,
    /// Whether something has happened that `stats.db` does not hold.
    unsaved: AtomicBool,
}

/// The units, split by whether they are still being counted.
///
/// Only the hour in progress keeps every name it has seen.  A finished hour is
/// compacted to the same top-N form that `stats.db` holds, which is what a
/// restart would load and what upstream reports for it: `internal/stats` keeps
/// one live unit and reads the rest back from the database.  Keeping every
/// hour's full map instead grew the process by roughly 180 bytes for every
/// distinct name asked for in the window -- a hundred megabytes over a day on
/// a busy resolver -- and had every save and every `/control/stats` call copy
/// the lot.
#[derive(Default)]
struct Inner {
    /// The hour being counted now, with every name it has seen.
    current: Option<Unit>,
    /// Finished hours, in the form they are stored in.
    past: BTreeMap<u32, Arc<UnitDb>>,
}

impl Inner {
    /// Compacts the live unit once it is no longer the hour given.
    ///
    /// Reports whether it did, which is the moment `stats.db` falls behind
    /// what is held: it is the only one that changes a finished hour.
    fn roll(&mut self, hour: u32) -> bool {
        let Some(done) = self.current.take_if(|u| u.id != hour) else {
            return false;
        };

        self.past.insert(done.id, Arc::new(done.to_db()));

        true
    }

    /// The stored form of one hour, or `None` when nothing was counted in it.
    ///
    /// The live hour is compacted on the way out, as upstream's `loadUnits`
    /// serialises its current unit for every request.
    fn unit(&self, id: u32) -> Option<Arc<UnitDb>> {
        match &self.current {
            Some(u) if u.id == id => Some(Arc::new(u.to_db())),
            _ => self.past.get(&id).cloned(),
        }
    }
}

impl Stats {
    /// Creates an empty collector.
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg: Mutex::new(cfg),
            inner: Mutex::new(Inner::default()),
            unsaved: AtomicBool::new(false),
        }
    }

    /// Replaces the settings.
    pub fn set_config(&self, cfg: Config) {
        *self.cfg.lock() = cfg;
        self.prune();
    }

    /// A snapshot of the settings.
    pub fn config(&self) -> Config {
        self.cfg.lock().clone()
    }

    /// Records one query.
    ///
    /// Returns whether it was counted.
    pub fn add(&self, e: &Entry) -> bool {
        self.add_at(e, current_hour())
    }

    /// Records one query into the given hour.
    ///
    /// Split out so the rollover can be tested without waiting for one.
    fn add_at(&self, e: &Entry, hour: u32) -> bool {
        if !self.cfg.lock().enabled || !e.is_valid() {
            return false;
        }

        let mut inner = self.inner.lock();
        if inner.roll(hour) {
            self.unsaved.store(true, Ordering::Relaxed);
        }
        inner.current.get_or_insert_with(|| Unit::new(hour)).add(e);

        true
    }

    /// Loads previously stored units.
    ///
    /// A unit for the hour in progress becomes the live one, so a restart
    /// carries on counting the hour it died in rather than starting it again.
    pub fn load<U: Into<Arc<UnitDb>>>(&self, stored: impl IntoIterator<Item = (u32, U)>) {
        let hour = current_hour();

        {
            let mut inner = self.inner.lock();
            for (id, db) in stored {
                let db = db.into();
                if id == hour {
                    inner.current = Some(Unit::from_db(id, &db));
                } else {
                    inner.past.insert(id, db);
                }
            }
        }

        self.prune();
    }

    /// Returns every unit in serialisable form, for persistence.
    ///
    /// The finished hours are handed over by `Arc`: they are already in the
    /// stored form and never change again, so saving does not copy them.
    pub fn snapshot(&self) -> Vec<(u32, Arc<UnitDb>)> {
        let hour = current_hour();
        let mut inner = self.inner.lock();
        if inner.roll(hour) {
            self.unsaved.store(true, Ordering::Relaxed);
        }

        let mut out: Vec<(u32, Arc<UnitDb>)> = inner
            .past
            .iter()
            .map(|(id, u)| (*id, Arc::clone(u)))
            .collect();

        if let Some(u) = &inner.current {
            out.push((u.id, Arc::new(u.to_db())));
        }

        out
    }

    /// What is held in memory, for a memory snapshot.
    ///
    /// A finished hour is capped at a hundred names of each kind, so only the
    /// live hour grows with the traffic, and only until the hour turns.  The
    /// whole window used to keep every name it had seen -- what the first
    /// container-memory investigation found -- so these are the numbers that
    /// say whether that has come back.
    pub fn sizes(&self) -> Sizes {
        let inner = self.inner.lock();
        let live = inner.current.as_ref();

        Sizes {
            past_hours: inner.past.len(),
            live_domains: live.map_or(0, |u| u.domains.len()),
            live_blocked_domains: live.map_or(0, |u| u.blocked_domains.len()),
            live_clients: live.map_or(0, |u| u.clients.len()),
            live_upstreams: live.map_or(0, |u| u.upstreams_responses.len()),
        }
    }

    /// Discards units older than the configured window.
    pub fn prune(&self) {
        let limit = self.cfg.lock().limit_hours;
        let cur = current_hour();
        let oldest = cur.saturating_sub(limit.saturating_sub(1));

        let mut inner = self.inner.lock();
        // Compacting here as well as in `add` is what bounds the live unit on
        // a resolver that goes quiet: an hour nothing was asked in would
        // otherwise keep its full map until the next query arrived.
        let rolled = inner.roll(cur);
        let before = inner.past.len();
        inner.past.retain(|id, _| *id >= oldest);

        if rolled || inner.past.len() != before {
            self.unsaved.store(true, Ordering::Relaxed);
        }
    }

    /// Removes every unit.
    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.current = None;
        inner.past.clear();
        drop(inner);

        // `/control/stats_reset` has to reach the file, or a restart brings
        // back everything it just cleared.
        self.unsaved.store(true, Ordering::Relaxed);
    }

    /// Claims the pending write to `stats.db`, if there is one.
    ///
    /// True once for each change the file does not already hold: an hour
    /// rotating, units falling out of the window, or a reset.  Queries
    /// counted into the live hour are deliberately not one of them.
    ///
    /// A running AdGuard Home writes `stats.db` when a unit rotates and when
    /// it shuts down, and at no other time: watched under 20 queries a second
    /// it wrote the file once, at the top of the hour.  Writing it every 60
    /// seconds instead -- the whole file, since that is how bbolt is written
    /// here -- was 1,440 rewrites a day, 448 MB of them at the default
    /// day-long window and 38 GB at a 90-day one, for a file that is the same
    /// bytes as an hour ago except for one unit.
    ///
    /// What it costs is upstream's cost: an unclean kill loses the hour in
    /// progress.  A signal does not, because the shutdown path saves.
    pub fn claim_save(&self) -> bool {
        self.unsaved.swap(false, Ordering::Relaxed)
    }

    /// The number of stored units.
    pub fn len(&self) -> usize {
        let inner = self.inner.lock();

        inner.past.len() + usize::from(inner.current.is_some())
    }

    /// Reports whether nothing has been recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Builds the `/control/stats` response.
    pub fn data(&self) -> StatsResp {
        let cfg = self.cfg.lock().clone();
        if cfg.limit_hours == 0 {
            return StatsResp::empty();
        }

        let cur = current_hour();
        let limit = cfg.limit_hours as usize;

        // A dense, oldest-first window of exactly `limit` units, filling gaps
        // with empty ones so the per-unit arrays line up with wall-clock time.
        let units: Vec<Arc<UnitDb>> = {
            let empty = Arc::new(UnitDb::default());
            let inner = self.inner.lock();

            (0..limit)
                .map(|i| {
                    let id = cur.saturating_sub((limit - 1 - i) as u32);

                    inner.unit(id).unwrap_or_else(|| Arc::clone(&empty))
                })
                .collect()
        };

        let ignored: AHashSet<String> = if cfg.ignored_enabled {
            cfg.ignored.iter().map(|s| s.to_ascii_lowercase()).collect()
        } else {
            AHashSet::new()
        };

        let mut resp = StatsResp::empty();

        resp.top_queried_domains = merge_top(&units, MAX_DOMAINS, &ignored, |u| &u.domains);
        resp.top_blocked_domains = merge_top(&units, MAX_DOMAINS, &ignored, |u| &u.blocked_domains);
        resp.top_clients = merge_top(&units, MAX_CLIENTS, &AHashSet::new(), |u| &u.clients);

        let (responses, avg_time) = merge_upstreams(&units);
        resp.top_upstreams_responses = responses;
        resp.top_upstreams_avg_time = avg_time;

        fill_per_unit(&mut resp, &units);

        // Totals.
        let mut n_result = [0u64; RESULT_COUNT];
        let mut n_total = 0u64;
        let mut time_avg_sum = 0u64;
        let mut time_units_counted = 0u64;

        for u in &units {
            n_total += u.n_total;
            for (i, slot) in n_result.iter_mut().enumerate() {
                *slot += u.n_result.get(i).copied().unwrap_or(0);
            }
            // The stored form already holds the hour's mean, which is what
            // `time_sum / n_total` recovered before.
            if u.time_avg != 0 {
                time_avg_sum += u64::from(u.time_avg);
                time_units_counted += 1;
            }
        }

        resp.num_dns_queries = n_total;
        resp.num_blocked_filtering = n_result[Result::Filtered as usize];
        resp.num_replaced_safebrowsing = n_result[Result::SafeBrowsing as usize];
        resp.num_replaced_safesearch = n_result[Result::SafeSearch as usize];
        resp.num_replaced_parental = n_result[Result::Parental as usize];

        if time_units_counted != 0 {
            // Upstream averages the per-hour means, then converts to seconds.
            resp.avg_processing_time =
                time_avg_sum.checked_div(time_units_counted).unwrap_or(0) as f64 / 1_000_000.0;
        }

        resp
    }
}

/// One unit's count for a result category.
fn n_result_of(u: &UnitDb, r: Result) -> u64 {
    u.n_result.get(r as usize).copied().unwrap_or(0)
}

/// Fills the per-time-unit arrays, collapsing to days past a week.
fn fill_per_unit(resp: &mut StatsResp, units: &[Arc<UnitDb>]) {
    let days = units.len() / 24;

    if days > 7 {
        resp.time_units = "days";
        let size = days;
        resp.dns_queries = vec![0; size];
        resp.blocked_filtering = vec![0; size];
        resp.replaced_safebrowsing = vec![0; size];
        resp.replaced_parental = vec![0; size];

        // Drop the leading partial day so each bucket holds a full 24 hours.
        let hours = size * 24;
        let tail = &units[units.len() - hours..];
        for (i, u) in tail.iter().enumerate() {
            let d = i / 24;
            resp.dns_queries[d] += u.n_total;
            resp.blocked_filtering[d] += n_result_of(u, Result::Filtered);
            resp.replaced_safebrowsing[d] += n_result_of(u, Result::SafeBrowsing);
            resp.replaced_parental[d] += n_result_of(u, Result::Parental);
        }

        return;
    }

    resp.time_units = "hours";
    resp.dns_queries = units.iter().map(|u| u.n_total).collect();
    resp.blocked_filtering = units
        .iter()
        .map(|u| n_result_of(u, Result::Filtered))
        .collect();
    resp.replaced_safebrowsing = units
        .iter()
        .map(|u| n_result_of(u, Result::SafeBrowsing))
        .collect();
    resp.replaced_parental = units
        .iter()
        .map(|u| n_result_of(u, Result::Parental))
        .collect();
}

/// Merges one counter across units and returns the top `max` entries.
fn merge_top(
    units: &[Arc<UnitDb>],
    max: usize,
    ignored: &AHashSet<String>,
    pick: impl Fn(&UnitDb) -> &[CountPair],
) -> Vec<TopAddrs> {
    let mut merged: AHashMap<String, u64> = AHashMap::new();
    for u in units {
        for p in pick(u) {
            if !ignored.is_empty() && ignored.contains(&p.name.to_ascii_lowercase()) {
                continue;
            }
            *merged.entry(p.name.clone()).or_insert(0) += p.count;
        }
    }

    to_top(&to_pairs(&merged, max))
}

/// Merges upstream counters and derives the mean response time per upstream.
fn merge_upstreams(units: &[Arc<UnitDb>]) -> (Vec<TopAddrs>, Vec<TopAddrsFloat>) {
    let mut responses: AHashMap<String, u64> = AHashMap::new();
    let mut time_sum: AHashMap<String, u64> = AHashMap::new();

    for u in units {
        for p in &u.upstreams_responses {
            *responses.entry(p.name.clone()).or_insert(0) += p.count;
        }
        for p in &u.upstreams_time_sum {
            *time_sum.entry(p.name.clone()).or_insert(0) += p.count;
        }
    }

    let pairs = to_pairs(&responses, MAX_CLIENTS);
    let avg: Vec<TopAddrsFloat> = pairs
        .iter()
        .map(|p| {
            let total = time_sum.get(&p.name).copied().unwrap_or(0);
            let mean = total
                .checked_div(p.count)
                .map_or(0.0, |micros| micros as f64 / 1_000_000.0);

            TopAddrsFloat::from([(p.name.clone(), mean)])
        })
        .collect();

    (to_top(&pairs), avg)
}

/// Converts pairs into the API's list-of-single-key-objects shape.
fn to_top(pairs: &[CountPair]) -> Vec<TopAddrs> {
    pairs
        .iter()
        .map(|p| TopAddrs::from([(p.name.clone(), p.count)]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::UpstreamStat;
    use std::time::Duration;

    fn entry(domain: &str, client: &str, result: Result, micros: u64) -> Entry {
        Entry {
            client: client.into(),
            domain: domain.into(),
            result,
            processing_time: Duration::from_micros(micros),
            upstreams: Vec::new(),
        }
    }

    #[test]
    fn counts_totals_and_categories() {
        let s = Stats::new(Config::default());
        s.add(&entry("good.com", "1.1.1.1", Result::NotFiltered, 100));
        s.add(&entry("ads.com", "1.1.1.1", Result::Filtered, 200));
        s.add(&entry("bad.com", "2.2.2.2", Result::SafeBrowsing, 300));
        s.add(&entry("kid.com", "2.2.2.2", Result::Parental, 400));

        let d = s.data();
        assert_eq!(d.num_dns_queries, 4);
        assert_eq!(d.num_blocked_filtering, 1);
        assert_eq!(d.num_replaced_safebrowsing, 1);
        assert_eq!(d.num_replaced_parental, 1);
        assert!(d.avg_processing_time > 0.0);
    }

    #[test]
    fn reports_hours_for_a_day_long_window() {
        let s = Stats::new(Config {
            limit_hours: 24,
            ..Default::default()
        });
        s.add(&entry("a.com", "c", Result::NotFiltered, 10));

        let d = s.data();
        assert_eq!(d.time_units, "hours");
        assert_eq!(d.dns_queries.len(), 24);
        // The current hour is the last bucket.
        assert_eq!(*d.dns_queries.last().unwrap(), 1);
        assert_eq!(d.dns_queries[..23].iter().sum::<u64>(), 0);
    }

    #[test]
    fn collapses_to_days_past_a_week() {
        // 30 days of hours.
        let s = Stats::new(Config {
            limit_hours: 24 * 30,
            ..Default::default()
        });
        s.add(&entry("a.com", "c", Result::NotFiltered, 10));

        let d = s.data();
        assert_eq!(d.time_units, "days");
        assert_eq!(d.dns_queries.len(), 30);
        assert_eq!(d.dns_queries.iter().sum::<u64>(), 1);
    }

    #[test]
    fn a_week_still_reports_hours() {
        let s = Stats::new(Config {
            limit_hours: 24 * 7,
            ..Default::default()
        });
        let d = s.data();
        assert_eq!(d.time_units, "hours", "7 days is not more than 7, so hours");
        assert_eq!(d.dns_queries.len(), 24 * 7);
    }

    #[test]
    fn top_lists_are_shaped_as_single_key_objects() {
        let s = Stats::new(Config::default());
        for _ in 0..3 {
            s.add(&entry("popular.com", "1.1.1.1", Result::NotFiltered, 10));
        }
        s.add(&entry("rare.com", "1.1.1.1", Result::NotFiltered, 10));
        s.add(&entry("ads.com", "1.1.1.1", Result::Filtered, 10));

        let d = s.data();
        assert_eq!(d.top_queried_domains[0].get("popular.com"), Some(&3));
        assert_eq!(d.top_queried_domains[1].get("rare.com"), Some(&1));
        assert_eq!(d.top_blocked_domains[0].get("ads.com"), Some(&1));
        assert_eq!(d.top_clients[0].get("1.1.1.1"), Some(&5));
    }

    #[test]
    fn upstream_means_are_reported_in_seconds() {
        let s = Stats::new(Config::default());
        let mut e = entry("a.com", "c", Result::NotFiltered, 10);
        e.upstreams = vec![UpstreamStat {
            address: "9.9.9.10:53".into(),
            duration: Duration::from_micros(250_000),
            cached: false,
            failed: false,
        }];
        s.add(&e);
        s.add(&e);

        let d = s.data();
        assert_eq!(d.top_upstreams_responses[0].get("9.9.9.10:53"), Some(&2));
        let mean = d.top_upstreams_avg_time[0]
            .get("9.9.9.10:53")
            .copied()
            .unwrap();
        assert!((mean - 0.25).abs() < 1e-9, "expected 0.25 s, got {mean}");
    }

    #[test]
    fn ignored_domains_are_excluded_from_the_top_lists() {
        let s = Stats::new(Config {
            ignored: vec!["secret.com".into()],
            ignored_enabled: true,
            ..Default::default()
        });
        s.add(&entry("secret.com", "c", Result::NotFiltered, 10));
        s.add(&entry("public.com", "c", Result::NotFiltered, 10));

        let d = s.data();
        let names: Vec<&String> = d
            .top_queried_domains
            .iter()
            .flat_map(|m| m.keys())
            .collect();
        assert!(!names.iter().any(|n| n.as_str() == "secret.com"));
        assert!(names.iter().any(|n| n.as_str() == "public.com"));
        // The query still counts towards the totals.
        assert_eq!(d.num_dns_queries, 2);
    }

    #[test]
    fn disabled_statistics_record_nothing() {
        let s = Stats::new(Config {
            enabled: false,
            ..Default::default()
        });
        assert!(!s.add(&entry("a.com", "c", Result::NotFiltered, 10)));
        assert_eq!(s.data().num_dns_queries, 0);
    }

    #[test]
    fn a_zero_window_returns_the_empty_response() {
        let s = Stats::new(Config {
            limit_hours: 0,
            ..Default::default()
        });
        s.add(&entry("a.com", "c", Result::NotFiltered, 10));

        let d = s.data();
        assert_eq!(d.time_units, "days");
        assert!(d.dns_queries.is_empty());
        assert!(d.top_queried_domains.is_empty());
    }

    #[test]
    fn snapshots_round_trip_through_load() {
        let s = Stats::new(Config::default());
        s.add(&entry("a.com", "c", Result::NotFiltered, 1000));
        s.add(&entry("b.com", "c", Result::Filtered, 2000));

        let snap = s.snapshot();
        assert_eq!(snap.len(), 1);

        let s2 = Stats::new(Config::default());
        s2.load(snap);
        let d = s2.data();
        assert_eq!(d.num_dns_queries, 2);
        assert_eq!(d.num_blocked_filtering, 1);
    }

    #[test]
    fn a_finished_hour_holds_only_what_is_stored() {
        // The hour being counted keeps every name it has seen; an hour that
        // has rolled over keeps the top-N that `stats.db` holds and upstream
        // reports.  Keeping the full map for every hour in the window grew the
        // process by every distinct name the network asked for, all day.
        let s = Stats::new(Config::default());
        let hour = current_hour();
        for i in 0..5_000 {
            let e = entry(&format!("h{i}.example.net"), "c", Result::NotFiltered, 10);
            s.add_at(&e, hour);
        }
        assert_eq!(
            s.inner.lock().current.as_ref().unwrap().domains.len(),
            5_000,
            "the live hour keeps every name"
        );

        s.add_at(
            &entry("next.example.net", "c", Result::NotFiltered, 10),
            hour + 1,
        );

        let inner = s.inner.lock();
        let done = inner.past.get(&hour).expect("the finished hour is kept");
        assert_eq!(
            done.domains.len(),
            MAX_DOMAINS,
            "compacted to what is stored"
        );
        assert_eq!(done.n_total, 5_000, "the totals are not capped");
    }

    #[test]
    fn a_rolled_hour_still_counts_towards_the_window() {
        let s = Stats::new(Config::default());
        let hour = current_hour();
        s.add_at(&entry("a.com", "c", Result::NotFiltered, 10), hour - 1);
        s.add_at(&entry("b.com", "c", Result::Filtered, 20), hour);

        let d = s.data();
        assert_eq!(d.num_dns_queries, 2);
        assert_eq!(d.num_blocked_filtering, 1);
        assert_eq!(d.top_queried_domains[0].get("a.com"), Some(&1));
        assert_eq!(d.top_blocked_domains[0].get("b.com"), Some(&1));
        assert!(
            d.avg_processing_time > 0.0,
            "the hourly means still average"
        );
    }

    #[test]
    fn an_hour_that_goes_quiet_is_compacted_by_the_sweep() {
        // Rolling only on the next query would leave the last busy hour's
        // full map resident on a resolver that has gone idle.
        let s = Stats::new(Config::default());
        s.add_at(
            &entry("a.com", "c", Result::NotFiltered, 10),
            current_hour() - 1,
        );
        assert!(s.inner.lock().current.is_some());

        s.prune();
        assert!(
            s.inner.lock().current.is_none(),
            "a unit for a past hour must not stay live"
        );
        assert_eq!(s.data().num_dns_queries, 1, "and it is still counted");
    }

    #[test]
    fn clearing_drops_everything() {
        let s = Stats::new(Config::default());
        s.add(&entry("a.com", "c", Result::NotFiltered, 10));
        assert!(!s.is_empty());
        s.clear();
        assert!(s.is_empty());
        assert_eq!(s.data().num_dns_queries, 0);
    }

    #[test]
    fn pruning_drops_units_outside_the_window() {
        let s = Stats::new(Config {
            limit_hours: 2,
            ..Default::default()
        });
        let cur = current_hour();
        s.load([
            (cur - 10, Unit::new(cur - 10).to_db()),
            (cur, Unit::new(cur).to_db()),
        ]);

        assert_eq!(s.len(), 1, "the old unit should have been pruned");
    }

    #[test]
    fn the_response_serialises_with_the_api_field_names() {
        let s = Stats::new(Config::default());
        s.add(&entry("a.com", "c", Result::NotFiltered, 10));
        let json = serde_json::to_string(&s.data()).unwrap();

        for key in [
            "time_units",
            "top_queried_domains",
            "top_clients",
            "top_blocked_domains",
            "top_upstreams_responses",
            "top_upstreams_avg_time",
            "dns_queries",
            "blocked_filtering",
            "replaced_safebrowsing",
            "replaced_parental",
            "num_dns_queries",
            "num_blocked_filtering",
            "num_replaced_safebrowsing",
            "num_replaced_safesearch",
            "num_replaced_parental",
            "avg_processing_time",
        ] {
            assert!(
                json.contains(&format!("\"{key}\"")),
                "missing {key} in {json}"
            );
        }
    }
}
