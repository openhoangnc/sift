//! An index from literal shortcuts to the rules that carry them.
//!
//! A rule that is not `||domain^` is prefiltered by its shortcut, the longest
//! literal run in its pattern: the rule is only a candidate when the shortcut
//! occurs in the query. This answers "which shortcuts occur in this hostname".
//!
//! It replaced an Aho-Corasick automaton, the textbook answer. On a real
//! 37-list installation the automaton cost 37.6 MB plus an 11.2 MB map from
//! pattern to rules, and about 440 ns of every query — most of what a clean
//! hostname took to filter. Each byte of the haystack is one state transition
//! that depends on the previous one, into a structure far larger than any
//! cache, so the walk is a chain of misses and the hostname's length sets the
//! price.
//!
//! What made the automaton the wrong tool is that this haystack is tiny and
//! the patterns are long: that installation had 156,070 distinct shortcuts of
//! mean length 19.5, and only 375 shorter than eight bytes. So each shortcut
//! is filed under one eight-byte window of itself, and a query hashes each of
//! its own eight-byte windows — about 16 for a typical hostname — into an
//! open-addressing table. The probes are independent of each other, so they
//! overlap in the memory system instead of chaining, and the table is small
//! enough to stay in L2. A key hit is confirmed by comparing the whole
//! shortcut with the hostname, so a collision cannot produce a candidate.
//!
//! Which window is chosen matters. Filing each shortcut under whichever of
//! its windows is rarest across the whole shortcut set — a domain-like
//! string's rare windows are also the ones real names rarely contain — cut
//! key hits that failed verification from 0.49 to 0.10 per host over the
//! differential test's 4,190-host corpus, against 0.80 real matches. Three
//! and four-byte windows were ruled out first: with three, 36,000 of the
//! 64,000 possible windows would be keys and every position of every
//! hostname hit one.
//!
//! The few shortcuts shorter than a window are keyed by their whole text in
//! a second, tiny table, behind an 8 KB bitset over their leading three bytes
//! so that a query touches that table only at a position that can hold one.

use std::mem::size_of;

use ahash::AHashMap;

use crate::rule::MIN_SHORTCUT_LEN;

/// The window a shortcut is filed under.
const WINDOW: usize = 8;

/// Bits in the gate over the long patterns' windows.
///
/// The table holds 156,070 patterns in cache-line buckets, about 3 MB, so
/// every probe is a miss or two. A typical hostname offers three windows,
/// which measured as 512 ns of a 574 ns clean lookup — the same order the
/// Aho-Corasick automaton this replaced was costing. 2 Mbit is 256 KB, stays
/// in L2, and at a 7% fill rejects nearly every window that no pattern uses.
const LONG_GATE_BITS: usize = 1 << 21;

/// Words in the long gate.
const LONG_GATE_WORDS: usize = LONG_GATE_BITS / 64;

/// Bits in the gate over the short patterns' leading bytes.
///
/// 64 Kbit is 8 KB, which stays in L1, so a position that cannot begin a
/// short pattern costs one test instead of a hash probe. Without this the
/// short table was probed at every position of every query: with only 375
/// short patterns in a real 37-list installation that was still 437 ns of a
/// 531 ns clean lookup, because the work is per position, not per pattern.
const GATE_BITS: usize = 1 << 16;

/// Words in the gate.
const GATE_WORDS: usize = GATE_BITS / 64;

/// The gate bitset covers the leading `MIN_SHORTCUT_LEN` bytes of every short
/// pattern, so a window must be longer than that for "short" to mean
/// anything.
const _: () = assert!(MIN_SHORTCUT_LEN < WINDOW && MIN_SHORTCUT_LEN > 0);

/// Marks an arena rule reference as an offset into `spill`.
const SPILL: u32 = 1 << 31;

/// A pattern's header in the arena: the rule reference, its length, and
/// where its window sits.
const HEADER: usize = 6;

/// The longest text kept for a pattern. A longer shortcut is filed by its
/// first 255 bytes, which still have to occur for the rule to match: this
/// only widens the candidate set, never narrows it, and nobody writes a
/// 255-byte literal.
const MAX_TEXT: usize = u8::MAX as usize;

/// Keys per line: a cache line of them.
const LINE: usize = 8;

/// One cache line of keys, aligned so a probe never straddles two.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, align(64))]
struct Line([u64; LINE]);

/// An open-addressing table from a 64-bit key to an arena offset.
///
/// A key hashes to a line, and a probe compares all eight keys of that line
/// at once: the first version walked slot by slot until it found an empty
/// one, and the exit branch of that loop, whose trip count varied from one
/// to ten, mispredicted on nearly every probe. Reading a whole line is the
/// same memory traffic with one predictable branch.
///
/// A key may be present several times: an insert takes the first empty slot
/// from its line onwards, so equal keys stack up and a probe collects them
/// all before it reaches a line with an empty slot.
#[derive(Debug, Default)]
struct Table {
    /// Every slot's key, by line. Zero is an empty slot; a key of zero
    /// would only cost a verification, never a wrong answer.
    lines: Box<[Line]>,
    /// Every slot's pattern, as an arena offset, in the same layout.
    vals: Box<[[u32; LINE]]>,
    /// `64 - log2(lines.len())`: the shift that leaves a line number.
    shift: u32,
}

impl Table {
    /// A table for `n` entries: a power of two of lines holding them at
    /// most two-thirds full, so a line with no empty slot is rare and a
    /// probe almost always reads exactly one.
    fn with_capacity(n: usize) -> Self {
        let lines = ((n + n / 2) / LINE).next_power_of_two().max(2);

        Self {
            lines: vec![Line::default(); lines].into_boxed_slice(),
            vals: vec![[0; LINE]; lines].into_boxed_slice(),
            shift: 64 - lines.trailing_zeros(),
        }
    }

    /// The line a key hashes to.
    ///
    /// Multiply-shift, keeping the *top* bits of the product: an input bit
    /// only reaches product bits at or above its own position, so a line
    /// taken from the middle ignored differences in a key's last byte, and
    /// 60,000 patterns of the form `ads<n>.example.com` chained into one
    /// cluster that took seconds to build.
    fn line(&self, key: u64) -> usize {
        (key.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> self.shift) as usize
    }

    /// Reports whether the table has no slots at all.
    fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// The bytes the table occupies.
    fn footprint(&self) -> usize {
        self.lines.len() * size_of::<Line>() + self.vals.len() * size_of::<[u32; LINE]>()
    }

    fn insert(&mut self, key: u64, val: u32) {
        let mask = self.lines.len() - 1;
        let mut l = self.line(key);
        loop {
            if let Some(i) = self.lines[l].0.iter().position(|&k| k == 0) {
                self.lines[l].0[i] = key;
                self.vals[l][i] = val;
                return;
            }
            l = (l + 1) & mask;
        }
    }
}

/// Every window of `text`, as a key.
fn windows(text: &[u8]) -> impl Iterator<Item = u64> + '_ {
    text.windows(WINDOW)
        .map(|w| u64::from_le_bytes(w.try_into().unwrap_or([0; WINDOW])))
}

/// Where a window sits in the long gate.
fn long_gate_bit(key: u64) -> usize {
    (key.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 40) as usize & (LONG_GATE_BITS - 1)
}

/// Where a position's leading bytes sit in the gate.
fn gate_bit(text: &[u8]) -> usize {
    let mut k = 0u32;
    for &b in &text[..MIN_SHORTCUT_LEN] {
        k = k.wrapping_mul(31).wrapping_add(u32::from(b));
    }

    (k.wrapping_mul(0x9E37_79B1) >> 13) as usize & (GATE_BITS - 1)
}

/// The key of a pattern shorter than a window: its first
/// `MIN_SHORTCUT_LEN` bytes. Verification checks the rest, so patterns that
/// share a prefix simply share a key.
fn short_key(text: &[u8]) -> u64 {
    let mut b = [0u8; WINDOW];
    b[..MIN_SHORTCUT_LEN].copy_from_slice(&text[..MIN_SHORTCUT_LEN]);

    u64::from_le_bytes(b)
}

/// One query in progress: the hostname, which patterns have been reported,
/// and where the rules go.
struct Scan<'a, F> {
    host: &'a [u8],
    /// Patterns already reported, by arena offset. Empty, and so never
    /// allocated, for the common query that matches nothing.
    seen: Vec<u32>,
    found: F,
}

/// Shortcut to rule indices.
#[derive(Debug, Default)]
pub struct ShortcutIndex {
    /// Patterns at least a window long, keyed by their chosen window.
    long: Table,
    /// Which windows any long pattern is filed under, so a query touches
    /// `long` only where one could match. See [`LONG_GATE_BITS`].
    long_gate: Box<[u64]>,
    /// Patterns shorter than a window, keyed by their first three bytes.
    short: Table,
    /// Which leading-byte triples any short pattern begins with, so a query
    /// touches `short` only where one could start. See [`GATE_BITS`].
    short_gate: Box<[u64]>,
    /// Every pattern's header and text, back to back.
    arena: Box<[u8]>,
    /// Runs of rule indices for patterns carried by more than one rule, each
    /// a length followed by that many indices.
    spill: Box<[u32]>,
    /// Rules whose shortcut occurs in `http`, and therefore in every query's
    /// `http://<host>` form: reported unconditionally and indexed nowhere.
    always: Box<[u32]>,
    /// How many patterns are indexed.
    len: usize,
}

impl ShortcutIndex {
    /// Builds the index from `(shortcut, rule indices)` pairs.
    ///
    /// A shortcut's rules keep the order they arrive in, which is load order.
    pub fn build(mut patterns: Vec<(String, Vec<u32>)>) -> Self {
        patterns.retain(|(text, rules)| text.len() >= MIN_SHORTCUT_LEN && !rules.is_empty());
        if patterns.is_empty() {
            return Self::default();
        }

        // The pairs come out of a hash map, so sort them: the layout, and
        // with it every measurement, is then the same from one load to the
        // next.
        patterns.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        let mut always = Vec::new();
        let mut arena: Vec<u8> =
            Vec::with_capacity(patterns.iter().map(|(t, _)| HEADER + t.len()).sum());
        let mut spill: Vec<u32> = Vec::new();
        let mut long_offs: Vec<u32> = Vec::new();
        let mut short_offs: Vec<u32> = Vec::new();

        for (text, rules) in &patterns {
            if "http".contains(text.as_str()) {
                always.extend_from_slice(rules);
                continue;
            }

            let text = &text.as_bytes()[..text.len().min(MAX_TEXT)];
            let rref = match rules.as_slice() {
                [one] => *one,
                many => {
                    let at = spill.len() as u32;
                    spill.push(many.len() as u32);
                    spill.extend_from_slice(many);
                    SPILL | at
                }
            };

            let off = arena.len() as u32;
            arena.extend_from_slice(&rref.to_le_bytes());
            arena.push(text.len() as u8);
            // The window offset, decided below once every window is counted.
            arena.push(0);
            arena.extend_from_slice(text);

            if text.len() >= WINDOW {
                long_offs.push(off);
            } else {
                short_offs.push(off);
            }
        }

        let text_range = |arena: &[u8], off: u32| -> std::ops::Range<usize> {
            let off = off as usize;
            let len = arena[off + 4] as usize;

            off + HEADER..off + HEADER + len
        };

        // Every window's frequency across the pattern set, then its load —
        // how many patterns have been filed under it — so that each pattern
        // takes its rarest window, and among equally rare ones the emptiest.
        //
        // Sized from the number of *distinct* windows rather than from a
        // guess at how many each pattern has. `with_capacity(patterns * 12)`
        // asked hashbrown for 1.87M entries on a real list set, which it
        // rounds up to 4,194,304 buckets -- 71 MB allocated inside every
        // build, every page of it touched, whatever the real number turns out
        // to be. Collecting the windows and sorting them costs one `u64` each
        // -- 15 MB, freed before the selection pass -- and gives both the
        // exact count and the frequencies without a hash lookup per window.
        let mut all: Vec<u64> = Vec::new();
        for &off in &long_offs {
            all.extend(windows(&arena[text_range(&arena, off)]));
        }
        all.sort_unstable();

        let distinct =
            all.windows(2).filter(|w| w[0] != w[1]).count() + usize::from(!all.is_empty());
        let mut grams: AHashMap<u64, (u32, u32)> = AHashMap::with_capacity(distinct);

        let mut i = 0;
        while i < all.len() {
            let w = all[i];
            let mut j = i + 1;
            while j < all.len() && all[j] == w {
                j += 1;
            }
            grams.insert(w, ((j - i) as u32, 0));
            i = j;
        }

        drop(all);

        let mut long = Table::default();
        let mut long_gate: Vec<u64> = Vec::new();
        if !long_offs.is_empty() {
            long = Table::with_capacity(long_offs.len());
            long_gate = vec![0u64; LONG_GATE_WORDS];
            for &off in &long_offs {
                let mut best: Option<(u64, usize, (u32, u32))> = None;
                for (i, w) in windows(&arena[text_range(&arena, off)]).enumerate() {
                    let stat = grams.get(&w).copied().unwrap_or_default();
                    if best.is_none_or(|(_, _, b)| stat < b) {
                        best = Some((w, i, stat));
                    }
                }
                let Some((w, i, _)) = best else {
                    continue;
                };
                if let Some(g) = grams.get_mut(&w) {
                    g.1 += 1;
                }
                arena[off as usize + 5] = i as u8;
                long.insert(w, off);

                let bit = long_gate_bit(w);
                long_gate[bit / 64] |= 1 << (bit % 64);
            }
        }

        let mut short = Table::default();
        let mut short_gate: Vec<u64> = Vec::new();
        if !short_offs.is_empty() {
            short = Table::with_capacity(short_offs.len());
            short_gate = vec![0u64; GATE_WORDS];
            for &off in &short_offs {
                let text = &arena[text_range(&arena, off)];
                short.insert(short_key(text), off);

                let bit = gate_bit(text);
                short_gate[bit / 64] |= 1 << (bit % 64);
            }
        }

        Self {
            long,
            long_gate: long_gate.into_boxed_slice(),
            short,
            short_gate: short_gate.into_boxed_slice(),
            arena: arena.into_boxed_slice(),
            spill: spill.into_boxed_slice(),
            always: always.into_boxed_slice(),
            len: long_offs.len() + short_offs.len(),
        }
    }

    /// How many patterns are indexed, the unconditional ones aside.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Reports whether nothing is indexed.
    pub fn is_empty(&self) -> bool {
        self.len == 0 && self.always.is_empty()
    }

    /// TEMPORARY: (long lines, short lines, long lines read for `host`,
    /// short lines read, short key hits).
    #[doc(hidden)]
    pub fn debug_stats(&self, host: &[u8]) -> (usize, usize, usize, usize, usize) {
        let (mut long_lines, mut short_lines, mut short_hits) = (0, 0, 0);
        let n = host.len();
        let count = |t: &Table, key: u64| -> (usize, bool) {
            let mask = t.lines.len() - 1;
            let mut l = t.line(key);
            let mut reads = 0;
            let mut hit = false;
            loop {
                reads += 1;
                let line = &t.lines[l].0;
                hit |= line.contains(&key);
                if line.contains(&0) {
                    return (reads, hit);
                }
                l = (l + 1) & mask;
            }
        };
        if n >= MIN_SHORTCUT_LEN {
            for at in 0..=n - MIN_SHORTCUT_LEN {
                if !self.short.is_empty() {
                    let (r, h) = count(&self.short, short_key(&host[at..]));
                    short_lines += r;
                    short_hits += usize::from(h);
                }
                if !self.long.is_empty() && at + WINDOW <= n {
                    let key = host[at..at + WINDOW]
                        .try_into()
                        .map_or(0, u64::from_le_bytes);
                    long_lines += count(&self.long, key).0;
                }
            }
        }

        (
            self.long.lines.len(),
            self.short.lines.len(),
            long_lines,
            short_lines,
            short_hits,
        )
    }

    /// The bytes the index occupies, for reporting.
    pub fn footprint(&self) -> usize {
        let gate = (self.short_gate.len() + self.long_gate.len()) * 8;
        gate + self.long.footprint()
            + self.short.footprint()
            + self.arena.len()
            + (self.spill.len() + self.always.len()) * 4
    }

    /// Calls `found` with the index of every rule whose shortcut occurs in
    /// `host`, which must already be lowercase, or in the `http://` before it.
    ///
    /// A rule is reported once, however many times its shortcut occurs.
    pub fn find(&self, host: &[u8], mut found: impl FnMut(u32)) {
        for &r in &self.always {
            found(r);
        }

        if host.len() < MIN_SHORTCUT_LEN {
            return;
        }

        let mut scan = Scan {
            host,
            seen: Vec::new(),
            found,
        };
        let long = !self.long.is_empty();
        let short = !self.short.is_empty();
        let n = host.len();

        for at in 0..=n - MIN_SHORTCUT_LEN {
            if long && at + WINDOW <= n {
                let key = host[at..at + WINDOW]
                    .try_into()
                    .map_or(0, u64::from_le_bytes);
                let bit = long_gate_bit(key);
                if self.long_gate[bit / 64] & (1 << (bit % 64)) != 0 {
                    self.probe(&self.long, key, at, &mut scan);
                }
            }

            if short {
                let bit = gate_bit(&host[at..]);
                if self.short_gate[bit / 64] & (1 << (bit % 64)) != 0 {
                    self.probe(&self.short, short_key(&host[at..]), at, &mut scan);
                }
            }
        }
    }

    /// Looks `key` up in `table` and reports every pattern filed under it
    /// that really occurs in the host with its window at `at`.
    fn probe(&self, table: &Table, key: u64, at: usize, scan: &mut Scan<'_, impl FnMut(u32)>) {
        let mask = table.lines.len() - 1;
        let mut l = table.line(key);
        loop {
            let line = &table.lines[l].0;
            // Both folds over the whole line, so that this compiles to
            // straight-line compares rather than an early-exit loop.
            let hit = line.iter().fold(false, |h, &k| h | (k == key));
            let empty = line.iter().fold(false, |e, &k| e | (k == 0));
            if hit {
                for (i, &k) in line.iter().enumerate() {
                    if k != key {
                        continue;
                    }
                    let off = table.vals[l][i];
                    if self.occurs(off, scan.host, at) && !scan.seen.contains(&off) {
                        scan.seen.push(off);
                        self.report(off, &mut scan.found);
                    }
                }
            }
            if empty {
                return;
            }
            l = (l + 1) & mask;
        }
    }

    /// Reports whether the pattern at `off` occurs in `host` with its window
    /// starting at `at`.
    fn occurs(&self, off: u32, host: &[u8], at: usize) -> bool {
        let off = off as usize;
        let len = self.arena[off + 4] as usize;
        let woff = self.arena[off + 5] as usize;
        let Some(start) = at.checked_sub(woff) else {
            return false;
        };

        host.get(start..start + len) == self.arena.get(off + HEADER..off + HEADER + len)
    }

    /// Hands the rules of the pattern at `off` to `found`.
    fn report(&self, off: u32, found: &mut impl FnMut(u32)) {
        let off = off as usize;
        let r = u32::from_le_bytes(self.arena[off..off + 4].try_into().unwrap_or([0; 4]));
        if r & SPILL == 0 {
            found(r);
            return;
        }

        let at = (r & !SPILL) as usize;
        let n = self.spill[at] as usize;
        for &i in &self.spill[at + 1..at + 1 + n] {
            found(i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(patterns: &[(&str, &[u32])]) -> ShortcutIndex {
        ShortcutIndex::build(
            patterns
                .iter()
                .map(|(p, r)| ((*p).to_string(), r.to_vec()))
                .collect(),
        )
    }

    fn found(i: &ShortcutIndex, host: &str) -> Vec<u32> {
        let mut out = Vec::new();
        i.find(host.as_bytes(), |r| out.push(r));
        out
    }

    #[test]
    fn finds_a_pattern_wherever_it_sits() {
        let i = index(&[("tracker.example", &[7])]);
        for host in [
            "tracker.example",
            "tracker.example.com",
            "www.tracker.example",
            "a.tracker.example.b",
        ] {
            assert_eq!(found(&i, host), [7], "{host}");
        }
        assert!(found(&i, "tracker.examplf").is_empty());
        assert!(found(&i, "example").is_empty());
    }

    #[test]
    fn finds_patterns_shorter_than_a_window() {
        let i = index(&[("ads", &[1]), ("ww4.", &[2]), ("cdn-a", &[3])]);
        assert_eq!(found(&i, "ads.example"), [1]);
        assert_eq!(found(&i, "ww4.example"), [2]);
        assert_eq!(found(&i, "xcdn-ab"), [3]);
        assert_eq!(found(&i, "ad.example"), &[] as &[u32]);
        // The gate is keyed by the first three bytes, so a host that shares
        // them without the rest must not be reported.
        assert_eq!(found(&i, "ww5.example"), &[] as &[u32]);
    }

    #[test]
    fn a_pattern_inside_http_is_reported_for_every_host_exactly_once() {
        // `|http://ads.` has the shortcut `http`, which every `http://<host>`
        // contains; a host that also contains it must not double up.
        let i = index(&[("http", &[4]), ("ttp", &[5])]);
        assert_eq!(found(&i, "example.com"), [4, 5]);
        assert_eq!(found(&i, "httpbin.org"), [4, 5]);
        assert_eq!(found(&i, "a"), [4, 5]);
    }

    #[test]
    fn a_pattern_occurring_twice_is_reported_once() {
        let i = index(&[("ads.ads.", &[1]), ("ads", &[2])]);
        assert_eq!(found(&i, "ads.ads.ads.ads.com"), [1, 2]);
    }

    #[test]
    fn several_rules_under_one_pattern_keep_load_order() {
        let i = index(&[("tracker.example", &[9, 3, 5])]);
        assert_eq!(found(&i, "x.tracker.example"), [9, 3, 5]);
    }

    #[test]
    fn an_empty_index_answers_nothing_for_any_host() {
        let i = ShortcutIndex::build(Vec::new());
        assert!(i.is_empty());
        for host in ["", "a", "ab", "abc", "example.com"] {
            assert!(found(&i, host).is_empty(), "{host:?}");
        }
        // Only long patterns, then only short ones: the other table is empty.
        let i = index(&[("tracker.example", &[1])]);
        assert!(found(&i, "ads.com").is_empty());
        assert!(found(&i, "ab").is_empty());
        let i = index(&[("ads", &[1])]);
        assert!(found(&i, "tracker.example").is_empty());
    }

    #[test]
    fn a_pattern_longer_than_the_text_limit_is_still_found() {
        let long = "a".repeat(300) + ".example";
        let i = index(&[(long.as_str(), &[1])]);
        assert_eq!(found(&i, &long), [1]);
        // Its first 255 bytes are what is kept, so a host with only those is
        // a candidate too — a superset, which the rule's own pattern settles.
        assert_eq!(found(&i, &"a".repeat(255)), [1]);
        assert!(found(&i, &"a".repeat(254)).is_empty());
    }

    #[test]
    fn agrees_with_brute_force_on_a_dense_alphabet() {
        // A tiny alphabet makes windows collide and patterns overlap, which
        // is where a hash index goes wrong if it is going to.
        struct Gen(u64);
        impl Gen {
            fn next(&mut self, n: usize) -> usize {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                (self.0 % n as u64) as usize
            }

            fn word(&mut self, len: usize) -> String {
                const ALPHABET: &[u8] = b"ab.-";
                (0..len)
                    .map(|_| char::from(ALPHABET[self.next(ALPHABET.len())]))
                    .collect()
            }
        }
        let mut g = Gen(0x2545_F491_4F6C_DD1D);

        let mut patterns: Vec<(String, Vec<u32>)> = Vec::new();
        for r in 0..400u32 {
            let len = MIN_SHORTCUT_LEN + g.next(12);
            let text = g.word(len);
            match patterns.iter_mut().find(|(t, _)| *t == text) {
                Some((_, rules)) => rules.push(r),
                None => patterns.push((text, vec![r])),
            }
        }
        let i = ShortcutIndex::build(patterns.clone());

        for _ in 0..2_000 {
            let len = 1 + g.next(30);
            let host = g.word(len);
            let mut want: Vec<u32> = patterns
                .iter()
                .filter(|(t, _)| host.contains(t.as_str()) || "http".contains(t.as_str()))
                .flat_map(|(_, r)| r.iter().copied())
                .collect();
            want.sort_unstable();
            let mut got = found(&i, &host);
            got.sort_unstable();
            assert_eq!(got, want, "for host {host:?}");
        }
    }

    #[test]
    fn reports_its_size() {
        let i = index(&[("tracker.example", &[1]), ("ads", &[2, 3])]);
        assert_eq!(i.len(), 2);
        assert!(!i.is_empty());
        assert!(i.footprint() > 0);
    }
}
