//! A TTL-aware DNS response cache.
//!
//! Sized in bytes to match `cache_size` in the config, and sharded so that
//! concurrent queries rarely contend on the same lock.
//!
//! Responses are held packed ([`crate::packed`]) rather than as hickory
//! `Message`s, and each entry is charged what it actually occupies.  Holding
//! the message cost 833 bytes of heap for a one-address answer while the
//! budget was charged 384 for it, so `cache_size` was exceeded by more than
//! twice over before a single entry was evicted.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use parking_lot::Mutex;

use crate::packed::Packed;

/// How a cached entry stands against its TTL.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Freshness {
    /// The entry is within its TTL.
    Fresh,
    /// The entry has expired but is being served optimistically.
    Stale,
}

/// What a lookup found.
pub struct Hit {
    /// The stored response, readdressed to the request and with its TTLs
    /// adjusted for this caller.
    pub msg: Message,
    /// Whether the entry is still inside its TTL.
    pub freshness: Freshness,
    /// Whether this caller should start a background refresh of the entry.
    ///
    /// The claim is made under the shard lock, so a burst of lookups produces
    /// one refresh rather than one each.  Whoever is told to refresh must
    /// release the claim with [`Cache::end_refresh`] once it is done, or the
    /// entry is never refreshed again.
    pub refresh: bool,
}

/// The key identifying a cached response.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Key {
    /// The question name, lowercased, in wire form: each label behind its
    /// length, without the root's terminating zero.
    ///
    /// Not text, because rendering a name as text escapes it, and that was a
    /// quarter of a cache hit.  The wire form is just as unambiguous, which
    /// is the property that matters: `www.victim\.com.` and `www.victim.com.`
    /// are different bytes, so a name crafted with a dot inside a label can
    /// never be answered from, or fill, another name's entry.
    ///
    /// Shared rather than owned, because every entry holds its key twice --
    /// once in the map and once in the eviction order -- and the name is the
    /// only part of it on the heap.
    pub name: Arc<[u8]>,
    /// The question type.
    pub qtype: u16,
    /// The question class.
    pub qclass: u16,
    /// Whether the query asked for DNSSEC records.
    ///
    /// An answer to a query carrying the EDNS `DO` bit holds signatures that
    /// an answer without it does not, so the two cannot share an entry: a
    /// validating client served the stripped form would fail to validate.
    pub dnssec_ok: bool,
    /// Which upstreams answered, when they were not the global ones.
    ///
    /// A persistent client may resolve through its own servers, and those can
    /// answer differently — a split-horizon name, a different CDN edge, a
    /// filtered feed.  Without this in the key, whichever client asked first
    /// would decide what every other client is told.  `None` is the global
    /// pool, so the common case costs one word and no allocation.
    pub upstreams: Option<Arc<str>>,
}

impl Key {
    /// Derives a cache key from a request, or `None` when it has no question.
    pub fn from_request(req: &Message) -> Option<Self> {
        let q = req.queries.first()?;

        let mut name = Vec::with_capacity(q.name().len() + 1);
        for label in q.name().iter() {
            // A label is at most 63 bytes, which `Name` enforces.
            name.push(u8::try_from(label.len()).ok()?);
            name.extend(label.iter().map(u8::to_ascii_lowercase));
        }

        Some(Key {
            name: name.into(),
            qtype: q.query_type().into(),
            qclass: q.query_class().into(),
            dnssec_ok: crate::edns::wants_dnssec(req),
            upstreams: None,
        })
    }

    /// Scopes the key to a client's own upstreams.
    #[must_use]
    pub fn for_upstreams(mut self, upstreams: Option<Arc<str>>) -> Self {
        self.upstreams = upstreams;

        self
    }

    /// What the key's name occupies on the heap: its bytes and the two
    /// reference counts in front of them.
    ///
    /// The upstreams are not charged: one string is shared by every entry
    /// of every client configured with it.
    fn heap_len(&self) -> usize {
        self.name.len() + 2 * size_of::<usize>()
    }
}

/// A cached response.
///
/// Every field is as narrow as what it holds allows, because the cache holds
/// as many of these as `cache_size` fits: `an_entry_stays_small` pins the size.
#[derive(Clone, Debug)]
struct Entry {
    /// The stored response, with TTLs as received.
    msg: Packed,
    /// When the entry was stored, in milliseconds since the cache's epoch.
    ///
    /// Half an `Instant`, and still exact enough that nothing expires a
    /// moment early.  Ages are taken with wrapping arithmetic, so a test can
    /// move this back past the epoch.
    stored: u64,
    /// The TTL the entry was stored with, in seconds.
    ttl: u32,
    /// What the entry occupies, in bytes.  See [`charge`].
    weight: u32,
    /// How many times the entry has been served, up to [`REFRESH_MIN_HITS`]
    /// -- nothing asks for more than whether it got that far.
    hits: u8,
    /// Whether a background refresh of this entry is already running.
    refreshing: bool,
    /// The eviction slot this entry owns.
    ///
    /// A key stored again -- after expiry, or by a refresh -- is pushed onto
    /// `order` a second time, so the slot left behind names an entry that no
    /// longer exists.  Matching the sequence number is what stops it from
    /// evicting the live entry under the same key.
    seq: u64,
}

impl Entry {
    /// Reports how much time has passed since the entry was stored, given
    /// the time now in milliseconds since the cache's epoch.
    fn age(&self, now: u64) -> Duration {
        Duration::from_millis(now.wrapping_sub(self.stored))
    }

    /// The TTL the entry was stored with.
    fn ttl(&self) -> Duration {
        Duration::from_secs(u64::from(self.ttl))
    }
}

/// Cache tuning, mirroring the `cache_*` config keys.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// The total budget in bytes.  Zero disables the cache.
    pub size_bytes: usize,
    /// Lower bound applied to a response's TTL, or zero for none.
    pub ttl_min: u32,
    /// Upper bound applied to a response's TTL, or zero for none.
    pub ttl_max: u32,
    /// Whether expired entries may still be served while a refresh runs.
    pub optimistic: bool,
    /// The TTL put on an optimistically served answer.
    ///
    /// Not what is left of the entry's own TTL, which has already run out: a
    /// fixed, short number telling the client to come back once the refresh
    /// behind it has landed.  This is `cache_optimistic_answer_ttl`.
    pub optimistic_answer_ttl: Duration,
    /// How long an expired entry may still be served.
    pub optimistic_max_age: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            size_bytes: 4 * 1024 * 1024,
            ttl_min: 0,
            ttl_max: 0,
            optimistic: false,
            optimistic_answer_ttl: Duration::from_secs(30),
            optimistic_max_age: Duration::from_secs(12 * 3600),
        }
    }
}

/// The number of shards.  A power of two so the index is a mask.
const SHARDS: usize = 16;

/// How many times an entry must be served before it is refreshed ahead of its
/// expiry.
///
/// A refresh costs an upstream exchange, so a name asked for exactly once --
/// most of them -- is left to expire quietly.
const REFRESH_MIN_HITS: u8 = 2;

/// How many dead eviction slots a shard tolerates before compacting.
///
/// Compaction is one pass over `order`, and can only run again once the shard
/// has grown again, which is what makes it amortised.
const COMPACT_SLACK: usize = 64;

/// A sharded, size-bounded DNS cache.
pub struct Cache {
    shards: Vec<Mutex<Shard>>,
    /// What picks a key's shard.
    ///
    /// Randomly keyed, like each shard's map, because the names are chosen
    /// by whoever is asking; and a different key from the maps', because a
    /// shard whose keys all shared their low hash bits would crowd them into
    /// a corner of its own table.
    shard_hasher: ahash::RandomState,
    cfg: parking_lot::RwLock<Config>,
    /// What [`Entry::stored`] counts from.
    epoch: Instant,
}

/// One shard's state.
struct Shard {
    map: HashMap<Key, Entry, ahash::RandomState>,
    /// Keys in rough insertion order, used for eviction.
    ///
    /// Each slot carries the sequence number of the entry it was pushed for.
    /// Entries leave `map` without their slot being found and removed -- that
    /// would be a linear scan on a hot path -- so a slot may name an entry
    /// that is gone, or an older incarnation of one that is still there.
    order: std::collections::VecDeque<(u64, Key)>,
    bytes: usize,
    budget: usize,
    /// The next sequence number to hand out.
    next_seq: u64,
}

impl Shard {
    /// Evicts oldest entries until the shard fits its budget.
    fn evict_to_fit(&mut self) {
        while self.bytes > self.budget {
            let Some((seq, k)) = self.order.pop_front() else {
                break;
            };

            // A slot naming an entry that is gone, or one stored again since,
            // is simply dropped: evicting on it would throw away a live entry
            // that has its own slot further along.
            let live = self.map.get(&k).is_some_and(|e| e.seq == seq);
            if live && let Some(e) = self.map.remove(&k) {
                self.bytes = self.bytes.saturating_sub(e.weight as usize);
            }
        }
    }

    /// Drops one entry outside of eviction.
    fn remove(&mut self, k: &Key) {
        if let Some(e) = self.map.remove(k) {
            self.bytes = self.bytes.saturating_sub(e.weight as usize);
        }
        // The entry's slot in `order` outlives it, and nothing else would
        // ever collect it on a shard that stays under its budget.
        self.compact_order();
    }

    /// Drops eviction slots that no longer name a live entry.
    ///
    /// Without this `order` grows with every expiry and every re-store, on a
    /// shard whose `bytes` never reach its budget and so never evict -- which
    /// is the common case, and was an unbounded leak.
    fn compact_order(&mut self) {
        if self.order.len() <= self.map.len() * 2 + COMPACT_SLACK {
            return;
        }

        let map = &self.map;
        self.order
            .retain(|(seq, k)| map.get(k).is_some_and(|e| e.seq == *seq));
    }
}

impl Cache {
    /// Builds a cache with the given configuration.
    pub fn new(cfg: Config) -> Self {
        let per_shard = (cfg.size_bytes / SHARDS).max(1);
        let shards = (0..SHARDS)
            .map(|_| {
                Mutex::new(Shard {
                    map: HashMap::default(),
                    order: std::collections::VecDeque::new(),
                    bytes: 0,
                    budget: per_shard,
                    next_seq: 0,
                })
            })
            .collect();

        Self {
            shards,
            shard_hasher: ahash::RandomState::new(),
            cfg: parking_lot::RwLock::new(cfg),
            epoch: Instant::now(),
        }
    }

    /// The time now, in milliseconds since the cache's epoch.
    fn now(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Replaces the configuration on a running cache.
    ///
    /// Each shard's budget is resized and trimmed to fit, so shrinking the
    /// cache -- or switching it off, which is a size of zero -- takes effect
    /// at once rather than at the next restart.  Upstream's `Reconfigure`
    /// rebuilds the cache outright; keeping the entries that still fit is the
    /// kinder version of the same thing.
    pub fn set_config(&self, cfg: Config) {
        let per_shard = (cfg.size_bytes / SHARDS).max(1);
        *self.cfg.write() = cfg;

        for shard in &self.shards {
            let mut s = shard.lock();
            s.budget = per_shard;
            s.evict_to_fit();
        }

        if self.is_disabled() {
            self.clear();
        }
    }

    /// Reports whether caching is switched off.
    pub fn is_disabled(&self) -> bool {
        self.cfg.read().size_bytes == 0
    }

    /// Picks the shard for a key.
    fn shard_of(&self, k: &Key) -> &Mutex<Shard> {
        &self.shards[(self.shard_hasher.hash_one(k) as usize) % SHARDS]
    }

    /// Looks up the answer to `req`, stored under `k`, adjusting its TTLs to
    /// the time already elapsed and readdressing it to `req` as
    /// [`crate::msg::readdress`] does.
    ///
    /// Returns `None` on a miss, or when the entry has expired and optimistic
    /// serving is off.
    pub fn get(&self, k: &Key, req: &Message) -> Option<Hit> {
        let asked = req.queries.first()?;
        // `Config` is `Copy`, so one acquisition covers every field the
        // lookup needs.
        let cfg = *self.cfg.read();
        if cfg.size_bytes == 0 {
            return None;
        }

        let now = self.now();
        let mut sh = self.shard_of(k).lock();
        let e = sh.map.get_mut(k)?;

        let age = e.age(now);
        let ttl = e.ttl();
        let expired = age >= ttl;

        // An expired entry is dropped unless optimistic serving is on and it
        // is still inside the stale window.
        if expired && (!cfg.optimistic || age > cfg.optimistic_max_age) {
            sh.remove(k);

            return None;
        }

        // Unpacked under the lock, because the entry is only borrowed from
        // it; a failure is a bug in the packing, and the entry goes rather
        // than failing the same way on every lookup.
        let Some(mut msg) = e.msg.unpack(asked) else {
            tracing::warn!(
                "a cached answer for {} did not unpack; dropping it",
                asked.name
            );
            sh.remove(k);

            return None;
        };

        e.hits = e.hits.saturating_add(1).min(REFRESH_MIN_HITS);

        // Refreshing shortly before the TTL runs out keeps a popular name
        // from being served stale at all.  It is worth an upstream exchange
        // only for a name that has been asked for more than once.
        let remaining = ttl.saturating_sub(age);
        let expiring = cfg.optimistic
            && e.hits >= REFRESH_MIN_HITS
            && remaining <= (ttl / 10).max(Duration::from_secs(1));

        let refresh = (expired || expiring) && !e.refreshing;
        if refresh {
            e.refreshing = true;
        }
        drop(sh);
        crate::msg::readdress(req, &mut msg);

        if expired {
            // A running AdGuard Home stamps `cache_optimistic_answer_ttl` on
            // an optimistically served answer rather than counting down from
            // what it stored; counting down would hand the client a TTL that
            // had already run out.
            set_ttls(&mut msg, secs_u32(cfg.optimistic_answer_ttl));
        } else {
            decrement_ttls(&mut msg, age.as_secs() as u32);
        }

        Some(Hit {
            msg,
            freshness: if expired {
                Freshness::Stale
            } else {
                Freshness::Fresh
            },
            refresh,
        })
    }

    /// Releases the refresh claim on an entry.
    ///
    /// A refresh that produced an answer has already replaced the entry
    /// through [`Cache::put`], which clears the claim with it.  This is what
    /// keeps a refresh that *failed* from leaving the key marked forever, and
    /// so never refreshed again.
    pub fn end_refresh(&self, k: &Key) {
        if let Some(e) = self.shard_of(k).lock().map.get_mut(k) {
            e.refreshing = false;
        }
    }

    /// Stores a response, if it is cacheable.
    ///
    /// Returns whether the response was stored.
    pub fn put(&self, k: Key, msg: &Message) -> bool {
        if self.is_disabled() {
            return false;
        }

        let Some(ttl) = self.cache_ttl_for(msg) else {
            return false;
        };

        let Some(packed) = Packed::pack(msg) else {
            return false;
        };

        let weight = charge(&k, &packed);
        let mut sh = self.shard_of(&k).lock();

        // Oversized single entries are simply not cached.
        if weight > sh.budget {
            return false;
        }

        let seq = sh.next_seq;
        sh.next_seq += 1;

        if let Some(old) = sh.map.insert(
            k.clone(),
            Entry {
                msg: packed,
                stored: self.now(),
                ttl,
                // A message is at most 64 KiB, so its charge always fits.
                weight: u32::try_from(weight).unwrap_or(u32::MAX),
                hits: 0,
                refreshing: false,
                seq,
            },
        ) {
            sh.bytes = sh.bytes.saturating_sub(old.weight as usize);
        }
        // Always a new slot, even when replacing: finding the old one would
        // be a linear scan, and the sequence number makes it harmless to
        // leave behind.  A re-stored entry moving to the back of the eviction
        // order is what you want anyway.
        sh.order.push_back((seq, k));
        sh.bytes += weight;
        sh.compact_order();
        sh.evict_to_fit();

        true
    }

    /// Decides the TTL to cache a response for, in seconds, or `None` if it
    /// must not be cached.
    fn cache_ttl_for(&self, msg: &Message) -> Option<u32> {
        // Only successful and negative answers are worth caching.
        match msg.metadata.response_code {
            ResponseCode::NoError | ResponseCode::NXDomain => {}
            _ => return None,
        }

        // A response with no records at all carries no TTL to honour.
        let base = crate::msg::min_ttl(msg)?;

        let mut ttl = base;
        let (ttl_min, ttl_max) = {
            let cfg = self.cfg.read();

            (cfg.ttl_min, cfg.ttl_max)
        };
        if ttl_min > 0 {
            ttl = ttl.max(ttl_min);
        }
        if ttl_max > 0 {
            ttl = ttl.min(ttl_max);
        }

        if ttl == 0 {
            return None;
        }

        Some(ttl)
    }

    /// Removes every entry.
    pub fn clear(&self) {
        for s in &self.shards {
            let mut sh = s.lock();
            sh.map.clear();
            sh.order.clear();
            sh.bytes = 0;
        }
    }

    /// The number of cached entries.
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().map.len()).sum()
    }

    /// Reports whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The approximate number of bytes held.
    pub fn bytes(&self) -> usize {
        self.shards.iter().map(|s| s.lock().bytes).sum()
    }

    /// Moves an entry's clock back, so a test can reach expiry without
    /// sleeping through it.
    #[cfg(test)]
    fn backdate(&self, k: &Key, by: Duration) {
        if let Some(e) = self.shard_of(k).lock().map.get_mut(k) {
            let by = u64::try_from(by.as_millis()).expect("a test's duration");
            e.stored = e.stored.wrapping_sub(by);
        }
    }

    /// The number of eviction slots held across every shard.
    ///
    /// This is the number that used to grow without bound, so it is the one
    /// worth asserting on -- and the one a memory snapshot reports beside the
    /// entry count, since a shard comfortably inside its budget is exactly
    /// where the two used to drift apart.
    pub fn order_len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().order.len()).sum()
    }
}

/// Reduces every record's TTL by `secs`, flooring at one second so a cached
/// answer never claims to be already expired.
fn decrement_ttls(msg: &mut Message, secs: u32) {
    for r in msg
        .answers
        .iter_mut()
        .chain(&mut msg.authorities)
        .chain(&mut msg.additionals)
    {
        r.ttl = r.ttl.saturating_sub(secs).max(1);
    }
}

/// Replaces every record's TTL with `secs`.
///
/// The same sections as [`decrement_ttls`]: the OPT pseudo-record lives in
/// `Message::edns`, not in `additionals`, so none of this touches it.
fn set_ttls(msg: &mut Message, secs: u32) {
    for r in msg
        .answers
        .iter_mut()
        .chain(&mut msg.authorities)
        .chain(&mut msg.additionals)
    {
        r.ttl = secs;
    }
}

/// A duration in whole seconds, saturating rather than wrapping.
fn secs_u32(d: Duration) -> u32 {
    u32::try_from(d.as_secs()).unwrap_or(u32::MAX)
}

/// What an entry occupies: its slot in the map, its slot in the eviction
/// order, the packed response, and the key's name.
///
/// What the allocator rounds up to, and the empty buckets a hash table keeps,
/// are not charged; they are the only part of the cache's footprint that this
/// leaves out.
fn charge(k: &Key, msg: &Packed) -> usize {
    size_of::<(Key, Entry)>() + size_of::<(u64, Key)>() + msg.heap_len() + k.heap_len()
}

/// Reports whether a query type may be cached at all.
pub fn is_cacheable_type(qt: RecordType) -> bool {
    !matches!(qt, RecordType::AXFR | RecordType::IXFR | RecordType::ANY)
}

/// Convenience for building a cache with a non-zero size.
pub fn with_size(bytes: NonZeroUsize) -> Cache {
    Cache::new(Config {
        size_bytes: bytes.get(),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RData, Record, rdata::A};

    fn req(name: &str) -> Message {
        let mut m = Message::query();
        m.add_query(Query::query(Name::from_utf8(name).unwrap(), RecordType::A));

        m
    }

    /// A request for the name `k` is keyed on.
    fn ask(k: &Key) -> Message {
        let mut labels = Vec::new();
        let mut wire = &k.name[..];
        while let [len, rest @ ..] = wire {
            let (label, rest) = rest.split_at(usize::from(*len));
            labels.push(label);
            wire = rest;
        }

        let mut m = Message::query();
        m.add_query(Query::query(
            Name::from_labels(labels).unwrap(),
            RecordType::from(k.qtype),
        ));

        m
    }

    fn resp(name: &str, ttl: u32) -> Message {
        let mut m = crate::msg::reply(&req(name), ResponseCode::NoError);
        m.answers = vec![Record::from_rdata(
            Name::from_utf8(name).unwrap(),
            ttl,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        )];

        m
    }

    #[test]
    fn a_clients_own_upstreams_get_their_own_entries() {
        // The bug this prevents: client A resolves through its company's
        // split-horizon resolver, client B through the global ones, and
        // whichever asks first decides what the other is told.
        let c = Cache::new(Config::default());
        let global = Key::from_request(&req("intranet.example.com.")).unwrap();
        let theirs = global.clone().for_upstreams(Some(Arc::from("10.0.0.1")));

        assert_ne!(global, theirs);
        assert!(c.put(global.clone(), &resp("intranet.example.com.", 300)));

        assert!(
            c.get(&global, &ask(&global)).is_some(),
            "the global entry is there"
        );
        assert!(
            c.get(&theirs, &ask(&theirs)).is_none(),
            "a client with its own upstreams must not be served it"
        );

        // And the two coexist rather than evicting each other.
        assert!(c.put(theirs.clone(), &resp("intranet.example.com.", 300)));
        assert_eq!(c.len(), 2);
        assert!(c.get(&global, &ask(&global)).is_some());
        assert!(c.get(&theirs, &ask(&theirs)).is_some());
    }

    #[test]
    fn clients_configured_with_the_same_upstreams_share_entries() {
        let c = Cache::new(Config::default());
        let one = Key::from_request(&req("example.com."))
            .unwrap()
            .for_upstreams(Some(Arc::from("10.0.0.1")));
        let two = Key::from_request(&req("example.com."))
            .unwrap()
            .for_upstreams(Some(Arc::from("10.0.0.1")));

        assert_eq!(one, two);
        assert!(c.put(one, &resp("example.com.", 300)));
        assert!(c.get(&two, &ask(&two)).is_some());
    }

    #[test]
    fn the_cache_can_be_reconfigured_while_running() {
        // Saving a new cache size used to change nothing until a restart.
        let c = Cache::new(Config::default());
        let k = Key::from_request(&req("example.com.")).unwrap();
        assert!(c.put(k.clone(), &resp("example.com.", 300)));
        assert_eq!(c.len(), 1);

        // Switching caching off empties it and stops it storing anything.
        c.set_config(Config {
            size_bytes: 0,
            ..Default::default()
        });
        assert!(c.is_disabled());
        assert_eq!(c.len(), 0, "entries must not survive the cache being off");
        assert!(!c.put(k.clone(), &resp("example.com.", 300)));
        assert!(c.get(&k, &ask(&k)).is_none());

        // And switching it back on works without a restart.
        c.set_config(Config::default());
        assert!(!c.is_disabled());
        assert!(c.put(k.clone(), &resp("example.com.", 300)));
        assert!(c.get(&k, &ask(&k)).is_some());
    }

    #[test]
    fn new_ttl_bounds_apply_without_a_restart() {
        // The bounds decide how long an entry is held, not what TTL the
        // answer carries, so check the lifetime the cache would choose.
        let c = Cache::new(Config::default());
        let r = resp("example.com.", 300);
        assert_eq!(c.cache_ttl_for(&r), Some(300));

        c.set_config(Config {
            ttl_max: 5,
            ..Default::default()
        });
        assert_eq!(c.cache_ttl_for(&r), Some(5));

        c.set_config(Config {
            ttl_min: 600,
            ..Default::default()
        });
        assert_eq!(c.cache_ttl_for(&r), Some(600));
    }

    #[test]
    fn stores_and_retrieves() {
        let c = Cache::new(Config::default());
        let k = Key::from_request(&req("example.com.")).unwrap();
        assert!(c.put(k.clone(), &resp("example.com.", 300)));

        let hit = c.get(&k, &ask(&k)).expect("should hit");
        assert_eq!(hit.freshness, Freshness::Fresh);
        assert_eq!(hit.msg.answers.len(), 1);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn keys_distinguish_name_type_and_dnssec() {
        let a = Key::from_request(&req("example.com.")).unwrap();
        let b = Key::from_request(&req("other.com.")).unwrap();
        assert_ne!(a, b);

        let mut r = req("example.com.");
        r.metadata.authentic_data = true;
        assert_ne!(a, Key::from_request(&r).unwrap());
    }

    #[test]
    fn the_dnssec_ok_bit_separates_entries() {
        // Serving a signed answer's cache entry to a client that did not ask
        // for signatures is harmless; the reverse is not, because a
        // validating client cannot validate what it was not sent.
        let plain = Key::from_request(&req("example.com.")).unwrap();

        let mut signed = req("example.com.");
        crate::edns::set_dnssec_ok(&mut signed, true);

        assert_ne!(plain, Key::from_request(&signed).unwrap());
    }

    #[test]
    fn keys_are_case_insensitive_and_ignore_the_trailing_dot() {
        let a = Key::from_request(&req("Example.COM.")).unwrap();
        let b = Key::from_request(&req("example.com.")).unwrap();
        assert_eq!(a, b);
        assert_eq!(&*a.name, b"\x07example\x03com");
    }

    #[test]
    fn a_dot_inside_a_label_is_a_different_name() {
        // `www.victim\.com.` is two labels under a top-level domain that does
        // not exist, and its NXDOMAIN must never be what `www.victim.com.`
        // is told.  Keys rendered as text told the two apart only because
        // the text was escaped.
        let crafted = Name::from_labels(vec![&b"www"[..], b"victim.com"]).unwrap();
        let mut r = Message::query();
        r.add_query(Query::query(crafted, RecordType::A));

        assert_ne!(
            Key::from_request(&r).unwrap(),
            Key::from_request(&req("www.victim.com.")).unwrap()
        );
    }

    #[test]
    fn a_miss_returns_nothing() {
        let c = Cache::new(Config::default());
        let r = req("absent.com.");
        assert!(c.get(&Key::from_request(&r).unwrap(), &r).is_none());
    }

    #[test]
    fn refuses_to_cache_failures() {
        let c = Cache::new(Config::default());
        let k = Key::from_request(&req("example.com.")).unwrap();
        let mut m = resp("example.com.", 300);
        m.metadata.response_code = ResponseCode::ServFail;
        assert!(!c.put(k.clone(), &m));
        assert!(c.get(&k, &ask(&k)).is_none());
    }

    #[test]
    fn refuses_to_cache_a_zero_ttl() {
        let c = Cache::new(Config::default());
        let k = Key::from_request(&req("example.com.")).unwrap();
        assert!(!c.put(k.clone(), &resp("example.com.", 0)));
    }

    #[test]
    fn applies_the_configured_ttl_bounds() {
        let c = Cache::new(Config {
            ttl_min: 60,
            ..Default::default()
        });
        assert_eq!(c.cache_ttl_for(&resp("a.com.", 5)), Some(60));

        let c = Cache::new(Config {
            ttl_max: 30,
            ..Default::default()
        });
        assert_eq!(c.cache_ttl_for(&resp("a.com.", 300)), Some(30));
    }

    #[test]
    fn a_disabled_cache_stores_nothing() {
        let c = Cache::new(Config {
            size_bytes: 0,
            ..Default::default()
        });
        assert!(c.is_disabled());
        let k = Key::from_request(&req("example.com.")).unwrap();
        assert!(!c.put(k.clone(), &resp("example.com.", 300)));
        assert!(c.get(&k, &ask(&k)).is_none());
    }

    #[test]
    fn evicts_when_over_budget() {
        // A tiny budget so a handful of entries forces eviction.
        let c = Cache::new(Config {
            size_bytes: SHARDS * 400,
            ..Default::default()
        });
        for i in 0..500 {
            let name = format!("host{i}.example.com.");
            let k = Key::from_request(&req(&name)).unwrap();
            c.put(k, &resp(&name, 300));
        }

        assert!(
            c.len() < 500,
            "eviction should have dropped entries, got {}",
            c.len()
        );
        assert!(
            c.bytes() <= SHARDS * 400 + 4096,
            "bytes should stay near budget"
        );
    }

    #[test]
    fn clearing_empties_the_cache() {
        let c = Cache::new(Config::default());
        let k = Key::from_request(&req("example.com.")).unwrap();
        c.put(k, &resp("example.com.", 300));
        assert!(!c.is_empty());
        c.clear();
        assert!(c.is_empty());
        assert_eq!(c.bytes(), 0);
    }

    #[test]
    fn an_expired_entry_is_served_with_the_configured_optimistic_ttl() {
        // Captured from AdGuard Home v0.107.79 with `cache_optimistic` on and
        // `cache_optimistic_answer_ttl: 7s`: a stale answer came back with a
        // TTL of 7, not with what was left of the two seconds it was stored
        // for.  The value is non-default on purpose -- an implementation that
        // hardcoded the 30s default would pass a test written against it.
        let c = Cache::new(Config {
            optimistic: true,
            optimistic_answer_ttl: Duration::from_secs(7),
            ..Default::default()
        });
        let k = Key::from_request(&req("example.com.")).unwrap();
        c.put(k.clone(), &resp("example.com.", 300));
        c.backdate(&k, Duration::from_secs(400));

        let hit = c.get(&k, &ask(&k)).expect("optimistic serving keeps it");
        assert_eq!(hit.freshness, Freshness::Stale);
        assert_eq!(hit.msg.answers[0].ttl, 7);
        assert!(hit.refresh, "and its caller is told to refresh it");
    }

    #[test]
    fn an_expired_entry_is_still_dropped_when_optimistic_serving_is_off() {
        let c = Cache::new(Config::default());
        let k = Key::from_request(&req("example.com.")).unwrap();
        c.put(k.clone(), &resp("example.com.", 300));
        c.backdate(&k, Duration::from_secs(400));

        assert!(c.get(&k, &ask(&k)).is_none());
        assert_eq!(c.len(), 0, "and it is gone rather than kept");
    }

    #[test]
    fn an_entry_past_the_stale_window_is_dropped_rather_than_served() {
        let c = Cache::new(Config {
            optimistic: true,
            optimistic_max_age: Duration::from_secs(60),
            ..Default::default()
        });
        let k = Key::from_request(&req("example.com.")).unwrap();
        c.put(k.clone(), &resp("example.com.", 300));
        c.backdate(&k, Duration::from_secs(3600));

        assert!(c.get(&k, &ask(&k)).is_none());
    }

    #[test]
    fn only_one_caller_at_a_time_is_told_to_refresh() {
        // Otherwise a burst on one expired name queues a job per client.
        let c = Cache::new(Config {
            optimistic: true,
            ..Default::default()
        });
        let k = Key::from_request(&req("example.com.")).unwrap();
        c.put(k.clone(), &resp("example.com.", 300));
        c.backdate(&k, Duration::from_secs(400));

        assert!(
            c.get(&k, &ask(&k)).expect("a hit").refresh,
            "the first claims it"
        );
        assert!(
            !c.get(&k, &ask(&k)).expect("a hit").refresh,
            "the rest are served the same stale answer and refresh nothing"
        );

        c.end_refresh(&k);
        assert!(
            c.get(&k, &ask(&k)).expect("a hit").refresh,
            "and the claim can be taken again once it is released"
        );
    }

    #[test]
    fn a_popular_entry_is_refreshed_before_it_expires() {
        // The last tenth of the TTL is the window.  Refreshing there is what
        // keeps a name that is asked for constantly from ever going stale.
        let c = Cache::new(Config {
            optimistic: true,
            ..Default::default()
        });
        let k = Key::from_request(&req("example.com.")).unwrap();
        c.put(k.clone(), &resp("example.com.", 100));
        c.backdate(&k, Duration::from_secs(95));

        let first = c.get(&k, &ask(&k)).expect("a hit");
        assert_eq!(first.freshness, Freshness::Fresh);
        assert!(
            !first.refresh,
            "a name asked for once is left to expire quietly"
        );
        assert!(
            c.get(&k, &ask(&k)).expect("a hit").refresh,
            "a second ask pays for the exchange"
        );
    }

    #[test]
    fn an_entry_well_inside_its_ttl_is_left_alone() {
        let c = Cache::new(Config {
            optimistic: true,
            ..Default::default()
        });
        let k = Key::from_request(&req("example.com.")).unwrap();
        c.put(k.clone(), &resp("example.com.", 100));
        c.backdate(&k, Duration::from_secs(10));

        for _ in 0..5 {
            assert!(!c.get(&k, &ask(&k)).expect("a hit").refresh);
        }
    }

    #[test]
    fn refreshing_ahead_is_gated_on_optimistic_serving() {
        // It is not an AdGuard Home feature and has no config key of its own,
        // so `cache_optimistic` is what turns it on.
        let c = Cache::new(Config::default());
        let k = Key::from_request(&req("example.com.")).unwrap();
        c.put(k.clone(), &resp("example.com.", 100));
        c.backdate(&k, Duration::from_secs(95));

        assert!(!c.get(&k, &ask(&k)).expect("a hit").refresh);
        assert!(!c.get(&k, &ask(&k)).expect("a hit").refresh);
    }

    #[test]
    fn the_eviction_order_does_not_grow_without_bound() {
        // An expiring lookup takes the entry out of `map` without finding its
        // slot in `order`, and storing the key again adds a second slot.
        // Only eviction drained `order`, and eviction only runs when the
        // shard is over budget -- so on a cache holding almost nothing,
        // `order` grew forever.
        let c = Cache::new(Config::default());
        let k = Key::from_request(&req("example.com.")).unwrap();

        for _ in 0..10_000 {
            c.put(k.clone(), &resp("example.com.", 300));
            c.backdate(&k, Duration::from_secs(400));
            assert!(
                c.get(&k, &ask(&k)).is_none(),
                "expired, and dropped by the lookup"
            );
        }

        assert_eq!(c.len(), 0, "the cache is empty");
        assert!(
            c.order_len() <= COMPACT_SLACK * 2,
            "{} eviction slots for an empty cache",
            c.order_len()
        );
    }

    #[test]
    fn a_dead_eviction_slot_does_not_take_the_live_entry_with_it() {
        // A key stored again after expiring leaves its first slot behind.
        // That slot sorts ahead of everything stored since, so an eviction
        // that acted on it threw away the newest entry and kept the oldest --
        // exactly backwards.
        let c = Cache::new(Config::default());
        let k = Key::from_request(&req("example.com.")).unwrap();

        c.put(k.clone(), &resp("example.com.", 300));
        c.backdate(&k, Duration::from_secs(400));
        assert!(
            c.get(&k, &ask(&k)).is_none(),
            "the lookup drops it, leaving its slot"
        );

        // Something else in the same shard, stored between the dead slot and
        // the live one, is what eviction should actually take.
        let other = name_in_shard_of(&c, &k);
        let ok = Key::from_request(&req(&other)).unwrap();
        c.put(ok.clone(), &resp(&other, 300));
        c.put(k.clone(), &resp("example.com.", 300));

        // Just enough pressure to need one entry's worth freed.
        {
            let mut sh = c.shard_of(&k).lock();
            assert_eq!(sh.order.len(), 3, "the dead slot is still in the order");
            sh.budget = sh.bytes - 1;
            sh.evict_to_fit();
        }

        assert!(
            c.get(&k, &ask(&k)).is_some(),
            "the entry stored last must survive its own dead slot"
        );
        assert!(
            c.get(&ok, &ask(&ok)).is_none(),
            "the genuinely older entry is what goes instead"
        );
    }

    /// A name landing in the same shard as `k`, so one shard's eviction order
    /// can be driven without the other fifteen muddying it.
    fn name_in_shard_of(c: &Cache, k: &Key) -> String {
        let target = c.shard_of(k);

        (0..10_000)
            .map(|i| format!("filler{i}.example.com."))
            .find(|n| {
                let other = Key::from_request(&req(n)).expect("a key");

                std::ptr::eq(c.shard_of(&other), target)
            })
            .expect("some name shares the shard")
    }

    #[test]
    fn an_entry_stays_small() {
        // The cache holds as many of these as `cache_size` fits.  Holding a
        // hickory `Message` made an entry 208 bytes before its heap, which
        // was another 360 for one address.
        assert!(
            size_of::<Entry>() <= 72,
            "Entry grew to {} bytes",
            size_of::<Entry>()
        );
        assert!(
            size_of::<Key>() <= 40,
            "Key grew to {} bytes, and every entry holds two",
            size_of::<Key>()
        );
    }

    #[test]
    fn an_entry_is_charged_for_what_it_holds() {
        // A one-address answer used to be charged 384 bytes while occupying
        // 833, so the budget was overrun twice over before anything was
        // evicted.  Measured with a counting allocator, the packed form
        // occupies within a few bytes of its charge.
        let c = Cache::new(Config::default());
        let k = Key::from_request(&req("example.com.")).unwrap();
        assert!(c.put(k.clone(), &resp("example.com.", 300)));

        let slots = size_of::<(Key, Entry)>() + size_of::<(u64, Key)>();
        assert!(c.bytes() > slots, "both slots and the heap are charged");
        assert!(c.bytes() < 300, "charged {} bytes", c.bytes());
    }

    #[test]
    fn a_hit_is_the_answer_that_was_stored() {
        // Byte for byte, and so case for case: packing is lossless.
        let c = Cache::new(Config::default());
        let q = "www.example.com.";
        let mut m = resp(q, 300);
        m.answers = vec![
            Record::from_rdata(
                Name::from_utf8(q).unwrap(),
                300,
                RData::CNAME(hickory_proto::rr::rdata::CNAME(
                    Name::from_ascii("Edge.CDN.example.net.").unwrap(),
                )),
            ),
            Record::from_rdata(
                Name::from_ascii("Edge.CDN.example.net.").unwrap(),
                300,
                RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
            ),
        ];
        let k = Key::from_request(&req(q)).unwrap();
        assert!(c.put(k.clone(), &m));

        // Readdressed to whoever asked, and otherwise the same.
        let asking = ask(&k);
        let hit = c.get(&k, &asking).expect("a hit");
        m.metadata.id = asking.metadata.id;
        assert_eq!(hit.msg.to_vec().unwrap(), m.to_vec().unwrap());
        assert_eq!(hit.msg.answers[1].name.to_ascii(), "Edge.CDN.example.net.");
    }

    #[test]
    fn a_hit_is_addressed_to_the_request_not_the_one_that_filled_it() {
        let c = Cache::new(Config::default());
        let mut first = req("www.example.com.");
        first.metadata.recursion_desired = true;
        let mut stored = resp("www.example.com.", 300);
        stored.metadata.recursion_desired = true;
        let mut edns = hickory_proto::op::Edns::new();
        edns.options_mut()
            .insert(hickory_proto::rr::rdata::opt::EdnsOption::Unknown(
                10,
                vec![0xAA; 8],
            ));
        stored.edns = Some(edns);
        let k = Key::from_request(&first).unwrap();
        assert!(c.put(k.clone(), &stored));

        let mut second = Message::query();
        second.add_query(Query::query(
            Name::from_ascii("WwW.eXaMpLe.CoM.").unwrap(),
            RecordType::A,
        ));
        second.metadata.recursion_desired = false;
        second.metadata.checking_disabled = true;
        assert_eq!(Key::from_request(&second).unwrap(), k, "the same entry");

        let hit = c.get(&k, &second).expect("a hit").msg;
        assert_eq!(hit.metadata.id, second.metadata.id);
        assert_eq!(hit.queries[0].name.to_ascii(), "WwW.eXaMpLe.CoM.");
        assert!(!hit.metadata.recursion_desired);
        assert!(hit.metadata.checking_disabled);
        assert!(hit.edns.is_none(), "not the first asker's cookie");
    }

    #[test]
    fn zone_transfer_and_any_are_not_cacheable() {
        assert!(!is_cacheable_type(RecordType::AXFR));
        assert!(!is_cacheable_type(RecordType::ANY));
        assert!(is_cacheable_type(RecordType::A));
    }
}
