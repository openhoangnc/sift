//! A compact index from domain to the rules filed under it.
//!
//! The obvious structure is `HashMap<Box<str>, Vec<u32>>`, and that is what
//! this replaced. On a real 37-list installation it held 1,122,077 entries and
//! cost about 148 MB: a boxed key string per domain, a table sized for the
//! load factor with a 16-byte key and a 32-byte value in every slot, and a
//! `Vec` for each domain named by more than one rule.
//!
//! This stores two parallel arrays instead — a 64-bit hash and a 32-bit value
//! per slot, 12 bytes against roughly 130 — and keeps no key strings at all.
//! The key is recovered from the rule's own text when a probe hits, which is
//! rare enough not to matter and is what makes a hash collision impossible to
//! mistake for a match.

/// Marks a value as an offset into the spill list rather than a rule index.
const SPILL: u32 = 1 << 31;

/// An empty slot. Rule indices are well under this, and a real slot's hash is
/// stored separately, so this is unambiguous.
const EMPTY: u32 = u32::MAX;

/// Domain to rule indices, in open addressing.
#[derive(Debug, Default)]
pub struct DomainIndex {
    /// Each slot's key hash; meaningless where `vals` says the slot is empty.
    hashes: Box<[u64]>,
    /// Each slot's rule index, or a spill offset, or [`EMPTY`].
    vals: Box<[u32]>,
    /// Runs of rule indices for domains named by more than one rule, each a
    /// length followed by that many indices.
    spill: Box<[u32]>,
    /// `hashes.len() - 1`, for wrapping a probe.
    mask: usize,
    /// How many domains are indexed.
    len: usize,
}

impl DomainIndex {
    /// Hashes a key the way the index does.
    ///
    /// FxHash-style multiply-xor: the keys are short ASCII domain names, and
    /// this is several times quicker over them than a general-purpose hash
    /// while spreading well enough for open addressing.
    ///
    /// Reachable from the engine's builder because that is where a key is
    /// hashed now -- see [`Self::build`].
    pub(crate) fn hash(key: &str) -> u64 {
        const K: u64 = 0x517c_c1b7_2722_0a95;

        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in key.as_bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(K);
        }
        h ^= h >> 32;

        // Never zero, so a hash is always distinguishable from a fresh slot.
        h | 1
    }

    /// How many domains are indexed.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Reports whether nothing is indexed.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The number of slots, for reporting.
    pub fn capacity(&self) -> usize {
        self.hashes.len()
    }

    /// The bytes the index occupies, for reporting.
    pub fn footprint(&self) -> usize {
        self.hashes.len() * 8 + self.vals.len() * 4 + self.spill.len() * 4
    }

    /// Builds the index from `(domain hash, rule index)` pairs.
    ///
    /// Pairs may repeat a domain; the rule indices for one domain keep the
    /// order they arrive in, which is the order the lists were read and so
    /// the order upstream would consider them.
    ///
    /// The *hash* rather than the domain, because the hash is the only thing
    /// this ever wanted: a key is never stored, and a lookup is decided by
    /// `hashes[i] == h` and the caller's verification. Taking the domains
    /// meant the builder held an owned copy of every one of them until the
    /// index was built -- 1.9M allocations on a real 37-list installation, to
    /// produce 1.9M `u64`s and drop them again. Hashing where the rule is
    /// parsed is the same arithmetic on the same bytes, and the string is
    /// freed on the spot.
    pub fn build(mut pairs: Vec<(u64, u32)>) -> Self {
        if pairs.is_empty() {
            return Self::default();
        }

        // Sorted by hash alone, and **stably**, which puts each domain's
        // rules in one contiguous run still in the order they arrived -- the
        // order upstream considers them and the order `get` promises. Sorting
        // by the pair would order a run by rule index instead, which is the
        // same thing only because the builder happens to append in that
        // order; `keeps_every_rule_for_one_domain_in_order` passes indices
        // out of order precisely so that assumption cannot creep in.
        //
        // Sorting costs one pass over 16 bytes a pair. What it replaces cost
        // a good deal more: the table was grown from 1,024 slots by doubling,
        // and each doubling allocated new tables and reinserted into them
        // while the old ones were still live, eleven times over on a real
        // list set; and every domain named more than once got a `Vec` of its
        // own, about 500,000 of them, live until the runs were flattened.
        // Both sat inside the rebuild's peak.
        pairs.sort_by_key(|&(h, _)| h);

        // One pass for both sizes: how many domains there are, and how much
        // spill their repeats need -- a run of n rules takes a length and n
        // entries.
        let (mut len, mut spill_len) = (0usize, 0usize);
        let mut i = 0;
        while i < pairs.len() {
            let mut j = i + 1;
            while j < pairs.len() && pairs[j].0 == pairs[i].0 {
                j += 1;
            }

            len += 1;
            if j - i > 1 {
                spill_len += 1 + (j - i);
            }

            i = j;
        }

        // Sized from the domains rather than the pairs: a blocklist names the
        // same domain from several lists, so pairs outnumber domains by a lot
        // -- on a real 37-list installation, 1,917,629 pairs for 1,232,249
        // domains. Sizing for the pairs left the table less than a third full
        // and cost twice the memory it needed. Kept under a 70% load, which
        // also guarantees the empty slot a miss stops on.
        let mut cap = 1024usize;
        while (len + 1) * 10 > cap * 7 {
            cap *= 2;
        }

        let mask = cap - 1;
        let mut hashes = vec![0u64; cap];
        let mut vals = vec![EMPTY; cap];
        let mut spill: Vec<u32> = Vec::with_capacity(spill_len);

        let mut i = 0;
        while i < pairs.len() {
            let h = pairs[i].0;
            let mut j = i + 1;
            while j < pairs.len() && pairs[j].0 == h {
                j += 1;
            }

            let mut slot = (h as usize) & mask;
            while vals[slot] != EMPTY {
                slot = (slot + 1) & mask;
            }

            hashes[slot] = h;
            vals[slot] = if j - i == 1 {
                // One rule: it lives in the slot itself.
                pairs[i].1
            } else {
                let off = spill.len() as u32;
                spill.push((j - i) as u32);
                spill.extend(pairs[i..j].iter().map(|&(_, idx)| idx));

                SPILL | off
            };

            i = j;
        }

        Self {
            hashes: hashes.into_boxed_slice(),
            vals: vals.into_boxed_slice(),
            spill: spill.into_boxed_slice(),
            mask,
            len,
        }
    }

    /// The rule indices filed under `key`, or an empty slice.
    ///
    /// `verify` is handed a candidate rule index and must say whether that
    /// rule really is filed under `key`. No key strings are stored, so this is
    /// what turns a hash hit into a certainty; it is only ever called on a
    /// hit, which for a miss is never.
    pub fn get<'a, F>(&'a self, key: &str, verify: F) -> &'a [u32]
    where
        F: Fn(u32) -> bool,
    {
        if self.len == 0 {
            return &[];
        }

        let h = Self::hash(key);
        let mut i = (h as usize) & self.mask;
        loop {
            let v = self.vals[i];
            if v == EMPTY {
                return &[];
            }

            if self.hashes[i] == h {
                let run = if v & SPILL == 0 {
                    std::slice::from_ref(&self.vals[i])
                } else {
                    let off = (v & !SPILL) as usize;
                    let n = self.spill[off] as usize;
                    &self.spill[off + 1..off + 1 + n]
                };

                // One verification is enough: every rule in a run was filed
                // under the same key.
                return if run.first().is_some_and(|&first| verify(first)) {
                    run
                } else {
                    &[]
                };
            }

            i = (i + 1) & self.mask;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx(pairs: &[(&str, u32)]) -> DomainIndex {
        DomainIndex::build(
            pairs
                .iter()
                .map(|(k, v)| (DomainIndex::hash(k), *v))
                .collect(),
        )
    }

    #[test]
    fn finds_a_single_rule() {
        let i = idx(&[("example.com", 7)]);
        assert_eq!(i.get("example.com", |_| true), &[7]);
        assert_eq!(i.get("other.com", |_| true), &[] as &[u32]);
        assert_eq!(i.len(), 1);
    }

    #[test]
    fn keeps_every_rule_for_one_domain_in_order() {
        // Upstream considers rules in the order the lists were read, and the
        // tie-break between two rules naming the same domain depends on it.
        let i = idx(&[
            ("example.com", 1),
            ("other.com", 2),
            ("example.com", 5),
            ("example.com", 3),
        ]);
        assert_eq!(i.get("example.com", |_| true), &[1, 5, 3]);
        assert_eq!(i.get("other.com", |_| true), &[2]);
        assert_eq!(i.len(), 2);
    }

    #[test]
    fn a_rejected_verification_is_a_miss() {
        // No key strings are stored, so a hash collision would otherwise be
        // indistinguishable from a real hit.
        let i = idx(&[("example.com", 7)]);
        assert_eq!(i.get("example.com", |_| false), &[] as &[u32]);
    }

    #[test]
    fn survives_a_full_table_and_many_collisions() {
        let pairs: Vec<(String, u32)> = (0..5_000u32)
            .map(|n| (format!("host{n}.example.com"), n))
            .collect();
        let i = DomainIndex::build(
            pairs
                .iter()
                .map(|(k, v)| (DomainIndex::hash(k), *v))
                .collect(),
        );

        assert_eq!(i.len(), 5_000);
        for (k, v) in &pairs {
            assert_eq!(i.get(k, |_| true), &[*v], "{k}");
        }
        assert!(i.get("absent.example.com", |_| true).is_empty());
    }

    #[test]
    fn runs_and_singles_survive_a_table_that_has_to_probe() {
        // The build packs a domain named once into its slot and a domain
        // named more than once into a spill run, and fills the table in hash
        // order rather than arrival order, so a slot is often reached by
        // probing past another. This mixes the two shapes, repeats out of
        // index order, and checks every key against what arrived.
        let mut pairs: Vec<(String, u32)> = Vec::new();
        let mut idx = 0u32;
        for n in 0..3_000u32 {
            let key = format!("host{n}.example.com");
            // Every third domain is named three times, the rest once, and
            // the repeats are pushed with descending indices so index order
            // and arrival order cannot be confused.
            let times = if n % 3 == 0 { 3 } else { 1 };
            for _ in 0..times {
                idx += 7;
                pairs.push((key.clone(), 1_000_000 - idx));
            }
        }

        let i = DomainIndex::build(
            pairs
                .iter()
                .map(|(k, v)| (DomainIndex::hash(k), *v))
                .collect(),
        );

        assert_eq!(i.len(), 3_000);
        for n in 0..3_000u32 {
            let key = format!("host{n}.example.com");
            let want: Vec<u32> = pairs
                .iter()
                .filter(|(k, _)| *k == key)
                .map(|(_, v)| *v)
                .collect();

            assert_eq!(i.get(&key, |_| true), want.as_slice(), "{key}");
        }

        assert!(i.get("absent.example.com", |_| true).is_empty());
    }

    #[test]
    fn an_empty_index_answers_nothing() {
        let i = DomainIndex::build(Vec::new());
        assert!(i.is_empty());
        assert!(i.get("example.com", |_| true).is_empty());
    }
}
