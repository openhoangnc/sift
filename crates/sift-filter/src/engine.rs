//! The indexed rule store and the matching engine.
//!
//! Lookup strategy, in the order candidates are gathered:
//!
//!   1. **Domain index** — `||domain^` rules, by far the bulk of DNS
//!      blocklists, live in a hash map keyed by domain.  A query walks its own
//!      parent domains, so matching costs one hash lookup per label.
//!   2. **Shortcut index** — other literal patterns are prefiltered by their
//!      longest literal substring, looked up by hashed windows of the
//!      hostname.
//!   3. **Scan list** — regexes and patterns too short to index are checked
//!      one by one.  This list is kept small.

use std::net::IpAddr;

use sift_core::Reason;
use std::borrow::Cow;
use std::sync::Arc;

use ahash::{AHashMap, AHashSet};

use crate::domidx::DomainIndex;
use crate::pattern::Target;
use crate::rule::{
    DnsRewrite, HostRule, MIN_SHORTCUT_LEN, NetworkRule, Options, PatternRef, Rule, parse,
};
use crate::shortcut::ShortcutIndex;

/// An empty set of lists, for a build with no allowlist.
///
/// `Engine::build` is generic over the text type now, and a bare `[]` gives
/// the compiler nothing to infer it from.
pub const NO_LISTS: [(i64, &str); 0] = [];

/// A candidate rule and its index, which the caller needs to recover the
/// rule's text from the arena.
type Candidate<'a> = (u32, &'a NetworkRule);

/// A rule's text, as a slice of the list it was read from.
///
/// No bytes of its own: the text is the line still sitting in the segment's
/// source. Which source is not stored, because a segment has exactly one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TextRef {
    /// Byte offset into the segment's source.
    off: u32,
    /// Length in bytes. A line longer than this can hold is not a rule
    /// anyone wrote; such a rule still matches, it just reports no text.
    len: u16,
}

/// How many bits of a rule reference name the rule within its segment.
const LOCAL_BITS: u32 = 23;

/// The part of a rule reference that names the rule within its segment.
const LOCAL_MASK: u32 = (1 << LOCAL_BITS) - 1;

/// The most rules one list may contribute.
const MAX_LOCAL: usize = LOCAL_MASK as usize;

/// The most lists one set may hold.
///
/// A reference has 31 bits, because both indexes reserve bit 31 to mark a
/// spill offset. The largest subscribed list anyone publishes is around two
/// million rules, so the split gives the per-list half the headroom.
const MAX_SEGMENTS: usize = 1 << (31 - LOCAL_BITS);

/// A reference to a rule: which segment it is in, and where.
///
/// The segment is the high part deliberately. Priority ties are settled by
/// the *earlier* rule, which upstream defines as the order the lists were
/// read and then the order within the list -- so comparing packed references
/// numerically is comparing exactly that, and `higher_priority` needs to know
/// nothing about segments.
const fn pack(seg: usize, local: usize) -> u32 {
    ((seg as u32) << LOCAL_BITS) | (local as u32)
}

/// Which segment a reference names.
const fn seg_of(idx: u32) -> usize {
    (idx >> LOCAL_BITS) as usize
}

/// Where in its segment a reference names.
const fn local_of(idx: u32) -> usize {
    (idx & LOCAL_MASK) as usize
}

/// One list's rules, as parsed.
///
/// Held by `Arc` so the engine being built can share the segments of the one
/// still serving: a refresh changes a handful of lists and leaves the rest
/// byte for byte the same, and parsing those again produced a second copy of
/// rules identical to the ones already in memory. Carried over instead, they
/// cost a pointer -- and keep the expressions they have already compiled.
#[derive(Default)]
struct Segment {
    /// The list this came from.
    list_id: i64,
    /// The text the rules point into.
    source: Arc<str>,
    /// The rules, in file order.
    net: Vec<NetworkRule>,
    /// Where each rule's text sits in `source`.
    net_text: Vec<TextRef>,
    /// Hosts-file entries, in file order.
    hosts: Vec<HostRule>,
    /// The canonical text of this list's `$badfilter` rules.
    badfilter: Vec<Box<str>>,
    /// Rules of both kinds, as `len` counts them.
    rules_count: usize,
}

impl Segment {
    /// The text of one of this segment's rules.
    fn text(&self, local: usize) -> &str {
        let Some(r) = self.net_text.get(local) else {
            return "";
        };

        self.source
            .get(r.off as usize..r.off as usize + r.len as usize)
            .unwrap_or("")
    }
}

/// Where a rule is filed in the global indexes.
enum Key {
    /// Under a domain, by hash.
    Domain(u64),
    /// Under a substring of its pattern.
    Shortcut(String),
    /// Nowhere: it is consulted on every query.
    Scan,
}

/// Where a rule belongs in the indexes, from the rule and its text.
///
/// Derived here rather than kept on the rule: the parser worked this out
/// once, and storing it was 12 bytes a rule for something a string scan
/// recovers. It is the same decision `parse_pattern` made, from the same
/// text.
fn index_key(r: &NetworkRule, text: &str) -> Key {
    let body = text.strip_prefix("@@").unwrap_or(text);
    let pattern = crate::rule::pattern_part(body);

    match r.pattern() {
        PatternRef::DomainAnchor => crate::rule::domain_anchor_of(pattern)
            .map_or(Key::Scan, |d| Key::Domain(DomainIndex::hash(&d))),
        PatternRef::Rx { .. } => match crate::pattern::shortcut(pattern, MIN_SHORTCUT_LEN) {
            Some(sc) if sc.len() >= MIN_SHORTCUT_LEN => Key::Shortcut(sc),
            _ => Key::Scan,
        },
        PatternRef::Any => Key::Scan,
    }
}

/// The rule indices stored under one index key.
///
/// Almost every domain is named by exactly one rule, so the common case is
/// kept inline: a `Vec` here would cost a 24-byte header plus a heap
/// allocation apiece, tens of megabytes across a real blocklist.
#[derive(Clone, Debug)]
enum Refs {
    /// A single rule.
    One(u32),
    /// Several rules, in load order.
    Many(Vec<u32>),
}

impl Refs {
    /// Adds an index, promoting to the heap only when a second one arrives.
    fn push(&mut self, idx: u32) {
        match self {
            Refs::One(first) => *self = Refs::Many(vec![*first, idx]),
            Refs::Many(v) => v.push(idx),
        }
    }

    /// Iterates the stored indices.
    fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        match self {
            Refs::One(i) => std::slice::from_ref(i).iter().copied(),
            Refs::Many(v) => v.iter().copied(),
        }
    }
}

/// A DNS filtering request.
#[derive(Clone, Debug, Default)]
pub struct Request<'a> {
    /// The queried hostname, already lowercased and without a trailing dot.
    pub hostname: &'a str,
    /// The query type, e.g. 1 for `A`.
    pub qtype: u16,
    /// The client's address, if known.
    pub client_ip: Option<IpAddr>,
    /// The client's name or ClientID, if known.
    pub client_name: Option<&'a str>,
    /// The client's tags.
    pub client_tags: &'a [String],
}

/// A rule that contributed to a match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchedRule {
    /// The rule's original text.
    pub text: String,
    /// The list the rule came from.
    pub list_id: i64,
    /// The address a host rule resolves to, if this was a host rule.
    pub ip: Option<IpAddr>,
}

/// The outcome of matching a request.
#[derive(Clone, Debug, Default)]
pub struct MatchResult {
    /// Why the request was filtered, allowed or rewritten.
    pub reason: Reason,
    /// The rules that matched.
    pub rules: Vec<MatchedRule>,
    /// The response to synthesise, for `$dnsrewrite` matches.
    pub rewrites: Vec<DnsRewrite>,
}

impl MatchResult {
    /// Reports whether anything matched.
    pub fn matched(&self) -> bool {
        self.reason.matched()
    }
}

/// An indexed set of rules from one group of lists.
#[derive(Default)]
pub struct RuleSet {
    /// One per list, in the order the lists were given, shared with whatever
    /// engine was built before this one where the list did not change.
    segments: Vec<Arc<Segment>>,
    domain_index: DomainIndex,
    host_index: AHashMap<Box<str>, Refs>,
    shortcuts: ShortcutIndex,
    scan: Vec<u32>,
    badfilter: AHashSet<Box<str>>,
    rules_count: usize,
}

impl RuleSet {
    /// Builds a rule set from the lines of one or more lists.
    ///
    /// `lists` pairs a list identifier with its text.  Unparseable lines are
    /// skipped, as upstream does, rather than failing the whole list.
    ///
    /// The text is kept, not copied: rules point into it for the life of the
    /// set.  Hand it an `Arc<str>` that something else already holds and it
    /// costs nothing; a `&str` is copied once, which is what tests want.
    pub fn build<T: Into<Arc<str>>>(lists: impl IntoIterator<Item = (i64, T)>) -> Self {
        Self::assemble(lists, None)
    }

    /// Builds a rule set, carrying over the segments of `self` whose list is
    /// unchanged.
    ///
    /// "Unchanged" is `Arc::ptr_eq` on the text: the manager replaces a
    /// list's `Arc<str>` only when the bytes it downloaded differ, so sharing
    /// the pointer *is* the test, and it costs nothing. A daily refresh of a
    /// real installation leaves most lists alone, and those are not parsed
    /// again, not allocated again, and keep the expressions they have already
    /// compiled.
    pub fn rebuild<T: Into<Arc<str>>>(&self, lists: impl IntoIterator<Item = (i64, T)>) -> Self {
        Self::assemble(lists, Some(self))
    }

    /// Parses what it must, carries over what it can, and indexes the lot.
    fn assemble<T: Into<Arc<str>>>(
        lists: impl IntoIterator<Item = (i64, T)>,
        previous: Option<&Self>,
    ) -> Self {
        let mut segments: Vec<Arc<Segment>> = Vec::new();

        for (id, text) in lists {
            // Past this a reference would not fit in the 31 bits the indexes
            // leave, so the lists beyond it are not loaded rather than
            // silently folded into another list's rules.
            if segments.len() >= MAX_SEGMENTS {
                break;
            }

            let text: Arc<str> = text.into();
            let carried = previous.and_then(|p| {
                p.segments
                    .iter()
                    .find(|s| s.list_id == id && Arc::ptr_eq(&s.source, &text))
            });

            segments.push(match carried {
                Some(s) => Arc::clone(s),
                None => Arc::new(parse_segment(id, text)),
            });
        }

        merge(segments)
    }

    /// One of the set's rules.
    fn rule(&self, idx: u32) -> Option<&NetworkRule> {
        self.segments.get(seg_of(idx))?.net.get(local_of(idx))
    }

    /// One of the set's host rules.
    fn host(&self, idx: u32) -> Option<&HostRule> {
        self.segments.get(seg_of(idx))?.hosts.get(local_of(idx))
    }

    /// A rough breakdown of where the set's memory goes.
    ///
    /// Heap estimates rather than an allocator reading: enough to tell which
    /// structure to attack, which is all it is for.
    pub fn footprint(&self) -> String {
        use std::mem::size_of;

        let net_count: usize = self.segments.iter().map(|s| s.net.len()).sum();
        let host_count: usize = self.segments.iter().map(|s| s.hosts.len()).sum();

        let net_structs: usize = self
            .segments
            .iter()
            .map(|s| s.net.capacity() * size_of::<NetworkRule>())
            .sum();
        let net_text: usize = self
            .segments
            .iter()
            .map(|s| s.net_text.capacity() * size_of::<TextRef>())
            .sum::<usize>()
            + self.segments.capacity() * size_of::<Arc<Segment>>();
        let net_opts: usize = self
            .segments
            .iter()
            .flat_map(|s| s.net.iter())
            .filter(|r| r.opts.is_some())
            .count()
            * (size_of::<Options>() + 32);

        let host_structs: usize = self
            .segments
            .iter()
            .map(|s| s.hosts.capacity() * size_of::<HostRule>())
            .sum();
        let host_text: usize = self
            .segments
            .iter()
            .flat_map(|s| s.hosts.iter())
            .map(|h| h.text.len() + 32)
            .sum();

        let idx = |m: &AHashMap<Box<str>, Refs>| -> (usize, usize, usize) {
            let keys: usize = m.keys().map(|k| k.len() + 32).sum();
            let spill: usize = m
                .values()
                .map(|r| match r {
                    Refs::One(_) => 0,
                    Refs::Many(v) => v.capacity() * 4 + 32,
                })
                .sum();
            let table = m.capacity() * (size_of::<Box<str>>() + size_of::<Refs>() + 1);

            (keys, spill, table)
        };

        let (dk, ds, dt) = (0usize, 0usize, self.domain_index.footprint());
        let (hk, hs, ht) = idx(&self.host_index);

        let shortcuts = self.shortcuts.footprint();
        let scan = self.scan.capacity() * 4;
        let badfilter: usize = self.badfilter.iter().map(|k| k.len() + 32).sum();

        let total = net_structs
            + net_text
            + net_opts
            + host_structs
            + host_text
            + dk
            + ds
            + dt
            + hk
            + hs
            + ht
            + shortcuts
            + scan
            + badfilter;
        let mb = |b: usize| b as f64 / 1e6;

        let mut out = String::from("footprint (estimated heap)\n");
        for (label, bytes, note) in [
            (
                "network rule structs",
                net_structs,
                format!("{net_count} rules"),
            ),
            ("network rule text", net_text, String::new()),
            ("network rule options", net_opts, String::new()),
            (
                "host rule structs",
                host_structs,
                format!("{host_count} rules"),
            ),
            ("host rule text+names", host_text, String::new()),
            (
                "domain index keys",
                dk,
                format!("{} entries", self.domain_index.len()),
            ),
            ("domain index spill", ds, String::new()),
            (
                "domain index table",
                dt,
                format!("cap {}", self.domain_index.capacity()),
            ),
            (
                "host index keys",
                hk,
                format!("{} entries", self.host_index.len()),
            ),
            ("host index spill", hs, String::new()),
            ("host index table", ht, String::new()),
            (
                "shortcut index",
                shortcuts,
                format!("{} patterns", self.shortcuts.len()),
            ),
            ("full-scan list", scan, String::new()),
            ("badfilter set", badfilter, String::new()),
            ("TOTAL", total, String::new()),
        ] {
            out.push_str(&format!("  {label:<22} {:>8.1} MB  {note}\n", mb(bytes)));
        }

        out
    }

    /// One network rule's original text, from the list it was read from.
    /// The list a rule came from, which is the segment it is in.
    fn list_of(&self, idx: u32) -> i64 {
        self.segments.get(seg_of(idx)).map_or(0, |s| s.list_id)
    }

    fn text_of(&self, idx: u32) -> &str {
        self.segments
            .get(seg_of(idx))
            .map_or("", |s| s.text(local_of(idx)))
    }

    /// The number of rules that were loaded.
    pub fn len(&self) -> usize {
        self.rules_count
    }

    /// Reports whether the set holds no rules.
    pub fn is_empty(&self) -> bool {
        self.rules_count == 0
    }

    /// Finds the applicable network rules for `req` and returns the winner,
    /// plus every `$dnsrewrite` rule that applies.
    fn match_network(&self, req: &Request<'_>) -> (Option<Candidate<'_>>, Vec<Candidate<'_>>) {
        // Built on the stack: a hostname is at most 253 bytes, and this ran
        // once per query.
        let mut buf = [0u8; URL_BUF];
        let url = url_for(&mut buf, req.hostname);
        let url = url.as_ref();

        let mut best: Option<(u32, &NetworkRule)> = None;
        let mut rewrites: Vec<(u32, &NetworkRule)> = Vec::new();

        // 1. Domain index: walk the query's parent domains.  A rule is filed
        //    under exactly one key, so this phase cannot repeat one.
        for suffix in sift_core::name::suffixes(req.hostname) {
            // No key strings are stored, so the rule's own text is what
            // confirms a probe: a 64-bit collision cannot be mistaken for a
            // match. Only ever called on a hit.
            for &i in self.domain_index.get(suffix, |first| {
                anchored_domain_is(self.text_of(first), suffix)
            }) {
                self.consider(i, req, url, &mut best, &mut rewrites);
            }
        }

        // 2. Shortcut index, over the hostname alone: a shortcut has no `:`
        //    or `/`, so one that occurs in `http://<host>` occurs in the
        //    host or in `http`, and the index answers for `http` by itself.
        //    The index reports each rule once however many times its
        //    shortcut occurs, so this phase cannot repeat one either.
        if !self.shortcuts.is_empty() {
            let host = &url.as_bytes()[SCHEME.len()..];
            self.shortcuts.find(host, |i| {
                self.consider(i, req, url, &mut best, &mut rewrites);
            });
        }

        // 3. Everything that could not be indexed.
        for &i in &self.scan {
            self.consider(i, req, url, &mut best, &mut rewrites);
        }

        (best, rewrites)
    }

    /// Folds candidate rule `idx` into the running best rule and rewrite list.
    fn consider<'r>(
        &'r self,
        idx: u32,
        req: &Request<'_>,
        url: &str,
        best: &mut Option<(u32, &'r NetworkRule)>,
        rewrites: &mut Vec<(u32, &'r NetworkRule)>,
    ) {
        let Some(r) = self.rule(idx) else {
            return;
        };

        // `$badfilter` is rare — a real 37-list installation has none at all —
        // and answering it needs the rule's text, which nothing else on this
        // path touches. Ask the cheap question first, so the common case
        // never reaches the arena.
        if !self.badfilter.is_empty()
            && self
                .badfilter
                .contains(canonical_text(self.text_of(idx)).as_ref())
        {
            return;
        }

        if !self.applies(idx, r, req, url) {
            return;
        }

        if r.dnsrewrite().is_some() {
            rewrites.push((idx, r));

            return;
        }

        if best.is_none_or(|(bi, b)| higher_priority((idx, r), (bi, b))) {
            *best = Some((idx, r));
        }
    }

    /// Reports whether `r` applies to `req`, checking both the pattern and the
    /// modifiers.
    fn applies(&self, idx: u32, r: &NetworkRule, req: &Request<'_>, url: &str) -> bool {
        if r.badfilter() {
            return false;
        }

        let Some(opts) = r.opts() else {
            // No modifiers: only the pattern decides.
            return self.pattern_matches(idx, r, req, url);
        };

        if let Some(t) = &opts.dnstype
            && !t.matches(req.qtype)
        {
            return false;
        }

        if let Some(c) = &opts.client {
            let ip = req.client_ip.map(|i| i.to_string());
            let name_ok = req.client_name.is_some_and(|n| c.matches(n));
            let ip_ok = ip.as_deref().is_some_and(|i| c.matches(i));
            // An all-negative list applies unless the client is excluded.
            let neg_only = c.included.is_empty();
            if !(name_ok || ip_ok || (neg_only && !excluded(c, req))) {
                return false;
            }
        }

        if let Some(t) = &opts.ctag
            && !t.matches_any(req.client_tags)
        {
            return false;
        }

        if !opts.denyallow.is_empty()
            && opts
                .denyallow
                .iter()
                .any(|d| sift_core::name::is_subdomain_of(req.hostname, d))
        {
            return false;
        }

        self.pattern_matches(idx, r, req, url)
    }

    /// Reports whether the rule's pattern matches the request.
    fn pattern_matches(&self, idx: u32, r: &NetworkRule, req: &Request<'_>, url: &str) -> bool {
        match r.pattern() {
            PatternRef::Any => true,
            // Reaching a domain-anchored rule means the domain index already
            // matched one of the hostname's suffixes.
            PatternRef::DomainAnchor => true,
            PatternRef::Rx { re, target } => {
                let hay = match target {
                    Target::Url => url,
                    Target::Hostname => req.hostname,
                };

                re.is_match(hay, || self.regex_source_of(idx))
            }
        }
    }

    /// The expression source for a rule, made from the rule's own text.
    ///
    /// Only reached when an expression has to be built -- the first match
    /// against the rule, or the first since the ceiling evicted it. The rule
    /// keeps no copy of this: it is `to_regex` of the pattern, and the
    /// pattern is a slice of the text the set already holds.
    fn regex_source_of(&self, idx: u32) -> String {
        let text = self.text_of(idx);
        let body = text.strip_prefix("@@").unwrap_or(text);

        crate::pattern::to_regex(crate::rule::pattern_part(body))
    }

    /// Finds host rules for the request's hostname.
    fn match_hosts(&self, req: &Request<'_>) -> Vec<&HostRule> {
        self.host_index
            .get(req.hostname)
            .map(|ids| ids.iter().filter_map(|i| self.host(i)).collect())
            .unwrap_or_default()
    }
}

/// Reports whether the client is explicitly excluded by the rule's list.
fn excluded(c: &crate::rule::StrList, req: &Request<'_>) -> bool {
    let ip = req.client_ip.map(|i| i.to_string());

    c.excluded.iter().any(|e| {
        req.client_name.is_some_and(|n| n.eq_ignore_ascii_case(e))
            || ip.as_deref().is_some_and(|i| i.eq_ignore_ascii_case(e))
    })
}

/// The priority class of a rule.  Upstream's ordering is:
/// whitelist+important, important, whitelist, then basic rules.
fn rank(r: &NetworkRule) -> u8 {
    match (r.allowlist(), r.important()) {
        (true, true) => 3,
        (false, true) => 2,
        (true, false) => 1,
        (false, false) => 0,
    }
}

/// Reports whether `a` outranks `b`.
///
/// Upstream compares by priority class, then by the *number of specifiers* a
/// rule carries — not by pattern length — and leaves equal rules in the order
/// the engine happened to visit them.  Here the final tie-break is the rule's
/// load order, which reproduces upstream's observed choice while staying
/// independent of index-traversal order.
fn higher_priority(a: (u32, &NetworkRule), b: (u32, &NetworkRule)) -> bool {
    let (ai, ar) = a;
    let (bi, br) = b;

    let (ra, rb) = (rank(ar), rank(br));
    if ra != rb {
        return ra > rb;
    }

    let (sa, sb) = (ar.specificity(), br.specificity());
    if sa != sb {
        return sa > sb;
    }

    ai < bi
}

/// Strips the `$badfilter` modifier so a badfilter rule can be compared with
/// the rule it cancels.
fn canonical_text(text: &str) -> Cow<'_, str> {
    let Some(dollar) = text.rfind('$') else {
        // No modifiers at all, which is nearly every rule: the text is
        // already canonical, so hand it back rather than copying it.
        return Cow::Borrowed(text);
    };

    let (head, mods) = text.split_at(dollar);
    let kept: Vec<&str> = mods[1..]
        .split(',')
        .filter(|m| m.trim() != "badfilter")
        .collect();

    if kept.is_empty() {
        Cow::Borrowed(head)
    } else {
        Cow::Owned(format!("{head}${}", kept.join(",")))
    }
}

/// Reports whether `text` is a `||domain^` rule naming exactly `domain`.
///
/// The domain index keeps no keys, so this recovers one from the rule's own
/// text. `text` is the line as written: an optional `@@`, then `||`, then the
/// domain, then `^`, then any modifiers.
fn anchored_domain_is(text: &str, domain: &str) -> bool {
    let t = text.strip_prefix("@@").unwrap_or(text);
    let Some(t) = t.strip_prefix("||") else {
        return false;
    };
    let Some(end) = t.find('^') else {
        return false;
    };

    t[..end].eq_ignore_ascii_case(domain)
}

/// The scheme the patterns are written against.
const SCHEME: &str = "http://";

/// Room for the scheme plus the longest legal hostname.
const URL_BUF: usize = SCHEME.len() + 253;

/// Renders the `http://<host>` form the patterns are written against.
///
/// Upstream matches rules against a URL, so a hostname query is given one.
/// Borrowing a stack buffer keeps it off the heap; a hostname longer than DNS
/// permits falls back to allocating rather than being truncated.
///
/// The copy is lowercased on the way. Every caller already lowercases, but
/// the shortcut index compares bytes exactly where the automaton it replaced
/// folded case, and doing it here costs nothing in a loop that copies anyway.
fn url_for<'a>(buf: &'a mut [u8; URL_BUF], hostname: &str) -> Cow<'a, str> {
    if hostname.len() > URL_BUF - SCHEME.len() {
        return Cow::Owned(format!("{SCHEME}{}", hostname.to_ascii_lowercase()));
    }

    buf[..SCHEME.len()].copy_from_slice(SCHEME.as_bytes());
    for (dst, src) in buf[SCHEME.len()..].iter_mut().zip(hostname.bytes()) {
        *dst = src.to_ascii_lowercase();
    }

    let n = SCHEME.len() + hostname.len();
    // Valid UTF-8: an ASCII scheme followed by the caller's `&str`, whose
    // non-ASCII bytes lowercasing left alone.
    Cow::Borrowed(std::str::from_utf8(&buf[..n]).unwrap_or(""))
}

/// Inserts a rule index into a `Refs`-valued map.
fn push_ref(map: &mut AHashMap<Box<str>, Refs>, key: Box<str>, idx: u32) {
    match map.entry(key) {
        std::collections::hash_map::Entry::Occupied(mut e) => e.get_mut().push(idx),
        std::collections::hash_map::Entry::Vacant(e) => {
            e.insert(Refs::One(idx));
        }
    }
}

/// Accumulates rules and builds the lookup indexes.
/// Parses one list into a segment.
fn parse_segment(list_id: i64, source: Arc<str>) -> Segment {
    let mut seg = Segment {
        list_id,
        source,
        ..Default::default()
    };

    let base = seg.source.as_ptr() as usize;
    // Cloned so the loop can borrow the source while the segment is written.
    let source = Arc::clone(&seg.source);

    for line in source.lines() {
        match parse(line, list_id) {
            Ok(Rule::Network(n)) => {
                if seg.net.len() >= MAX_LOCAL {
                    break;
                }

                // `parse` trims, so this is exactly the text it used, and it
                // is a slice of the source — hence the offset arithmetic.
                let t = line.trim();
                if n.rule.badfilter() {
                    seg.badfilter
                        .push(canonical_text(t).into_owned().into_boxed_str());
                }

                seg.net_text.push(TextRef {
                    off: (t.as_ptr() as usize - base) as u32,
                    len: u16::try_from(t.len()).unwrap_or(0),
                });
                seg.net.push(n.rule);
                seg.rules_count += 1;
            }
            Ok(Rule::Host(h)) => {
                if seg.hosts.len() >= MAX_LOCAL {
                    break;
                }

                seg.hosts.push(h);
                seg.rules_count += 1;
            }
            Err(_) => {}
        }
    }

    seg.net.shrink_to_fit();
    seg.net_text.shrink_to_fit();
    seg.hosts.shrink_to_fit();

    seg
}

/// Indexes a set of segments into a queryable rule set.
///
/// The segments are walked in order and each segment's rules in file order,
/// so every index is filled in exactly the order a single pass over the
/// concatenated lists would have filled it — which is the order upstream
/// considers rules, and the order a tie is settled by.
fn merge(segments: Vec<Arc<Segment>>) -> RuleSet {
    let mut domain_pairs: Vec<(u64, u32)> = Vec::new();
    let mut shortcuts: AHashMap<String, Vec<u32>> = AHashMap::new();
    let mut scan: Vec<u32> = Vec::new();
    let mut host_index: AHashMap<Box<str>, Refs> = AHashMap::new();
    let mut badfilter: AHashSet<Box<str>> = AHashSet::new();
    let mut rules_count = 0usize;

    for (s, seg) in segments.iter().enumerate() {
        rules_count += seg.rules_count;

        // One set over every segment, because a `$badfilter` rule cancels a
        // rule in another list as readily as one in its own.
        badfilter.extend(seg.badfilter.iter().cloned());

        for (local, r) in seg.net.iter().enumerate() {
            let idx = pack(s, local);
            match index_key(r, seg.text(local)) {
                Key::Domain(h) => domain_pairs.push((h, idx)),
                Key::Shortcut(sc) => shortcuts.entry(sc).or_default().push(idx),
                Key::Scan => scan.push(idx),
            }
        }

        for (local, h) in seg.hosts.iter().enumerate() {
            let idx = pack(s, local);
            for name in h.hostnames() {
                push_ref(&mut host_index, name.into_boxed_str(), idx);
            }
        }
    }

    scan.shrink_to_fit();

    RuleSet {
        segments,
        domain_index: DomainIndex::build(domain_pairs),
        host_index,
        shortcuts: ShortcutIndex::build(shortcuts.into_iter().collect()),
        scan,
        badfilter,
        rules_count,
    }
}

/// Reports whether an `@@…$dnsrewrite` rule removes `rule` from the rewrites.
///
/// Upstream's `removeMatchingException`, captured from a running v0.107.79
/// rather than read off it:
///
/// | exception | rewrite | outcome |
/// |---|---|---|
/// | `@@…$dnsrewrite` | `…$dnsrewrite=1.2.3.4` | removed |
/// | `@@…$dnsrewrite=1.2.3.4` | `…$dnsrewrite=1.2.3.4` | removed |
/// | `@@…$dnsrewrite=1.2.3.4` | `…$dnsrewrite=5.6.7.8` | kept |
/// | `@@…$dnsrewrite` | `…$dnsrewrite=1.2.3.4,important` | kept |
/// | `@@…$dnsrewrite,important` | `…$dnsrewrite=1.2.3.4,important` | removed |
///
/// Two details are the ones a reading of the source would get wrong. An
/// exception carrying no value -- and `=NOERROR`, which parses to the same
/// thing -- removes *every* rewrite rather than the ones that answer NOERROR:
/// `@@||a.example^$dnsrewrite=NOERROR` removes `$dnsrewrite=1.2.3.4`. And the
/// comparison is by the **parsed** value, not the text, so
/// `@@…$dnsrewrite=1.2.3.4` removes `…$dnsrewrite=NOERROR;A;1.2.3.4`.
fn excepts(exception: &NetworkRule, rule: &NetworkRule) -> bool {
    // An ordinary exception leaves an `$important` rewrite alone; an
    // `$important` one takes it too.
    if rule.important() && !exception.important() {
        return false;
    }

    match exception.dnsrewrite() {
        // No value: every rewrite this rule matched.
        Some(DnsRewrite::RCode(0)) => true,
        Some(v) => rule.dnsrewrite() == Some(v),
        None => false,
    }
}

/// Reports whether a rule rewrites the host to itself, which is no rewrite.
///
/// Upstream drops it in `processDNSResultRewrites` (`res.CanonName == host`),
/// and a running v0.107.79 answers `NotFilteredNotFound` for
/// `||a.example^$dnsrewrite=a.example`, resolving the name normally.
fn rewrites_to_itself(rule: &NetworkRule, hostname: &str) -> bool {
    match rule.dnsrewrite() {
        Some(DnsRewrite::CName(c)) => c
            .trim_matches('.')
            .eq_ignore_ascii_case(hostname.trim_matches('.')),
        _ => false,
    }
}

/// The filtering engine: an allowlist set that short-circuits, and a blocklist
/// set consulted when nothing allowed the request.
#[derive(Default)]
pub struct Engine {
    /// Rules from allowlists.  Any match here allows the request outright.
    pub allow: RuleSet,
    /// Rules from blocklists and the user's custom rules.
    pub block: RuleSet,
}

impl Engine {
    /// Builds an engine from blocklist and allowlist sources.
    pub fn build<T: Into<Arc<str>>, U: Into<Arc<str>>>(
        block: impl IntoIterator<Item = (i64, T)>,
        allow: impl IntoIterator<Item = (i64, U)>,
    ) -> Self {
        Self {
            allow: RuleSet::build(allow),
            block: RuleSet::build(block),
        }
    }

    /// Builds an engine, carrying over what `self` already parsed.
    ///
    /// A list whose text is the same `Arc` is not parsed or allocated again;
    /// see [`RuleSet::rebuild`]. The result is the engine [`Self::build`]
    /// would have produced from the same lists --
    /// `a_rebuilt_engine_answers_exactly_as_a_fresh_one` holds it to that.
    pub fn rebuild<T: Into<Arc<str>>, U: Into<Arc<str>>>(
        &self,
        block: impl IntoIterator<Item = (i64, T)>,
        allow: impl IntoIterator<Item = (i64, U)>,
    ) -> Self {
        Self {
            allow: self.allow.rebuild(allow),
            block: self.block.rebuild(block),
        }
    }

    /// The total number of loaded rules.
    pub fn len(&self) -> usize {
        self.allow.len() + self.block.len()
    }

    /// Reports whether the engine holds no rules.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Matches a request.
    ///
    /// The order mirrors upstream: allowlists win outright, then
    /// `$dnsrewrite` rules, then ordinary blocking and host rules.
    pub fn match_request(&self, req: &Request<'_>) -> MatchResult {
        if req.hostname.is_empty() {
            return MatchResult::default();
        }

        // 1. Allowlists short-circuit.
        if !self.allow.is_empty() {
            let (net, _) = self.allow.match_network(req);
            if let Some((idx, r)) = net {
                return MatchResult {
                    reason: Reason::NotFilteredAllowList,
                    rules: vec![to_matched(&self.allow, r, idx)],
                    rewrites: Vec::new(),
                };
            }
            let hosts = self.allow.match_hosts(req);
            if !hosts.is_empty() {
                return MatchResult {
                    reason: Reason::NotFilteredAllowList,
                    rules: hosts.iter().map(|h| host_matched(h)).collect(),
                    rewrites: Vec::new(),
                };
            }
        }

        let (net, rewrites) = self.block.match_network(req);

        // 2. `$dnsrewrite` rules, less the ones an `@@` rule excepts and the
        //    ones that rewrite the host to itself.
        if !rewrites.is_empty() {
            let kept: Vec<(u32, &NetworkRule)> = rewrites
                .iter()
                .copied()
                .filter(|(_, r)| !r.allowlist())
                .filter(|&(_, r)| {
                    !rewrites
                        .iter()
                        .any(|&(_, e)| e.allowlist() && excepts(e, r))
                })
                .filter(|&(_, r)| !rewrites_to_itself(r, req.hostname))
                .collect();

            if !kept.is_empty() {
                return MatchResult {
                    reason: Reason::RewrittenRule,
                    rules: kept
                        .iter()
                        .map(|&(i, r)| to_matched(&self.block, r, i))
                        .collect(),
                    rewrites: kept
                        .iter()
                        .filter_map(|(_, r)| r.dnsrewrite().cloned())
                        .collect(),
                };
            }
        }

        // 3. The winning basic rule.
        if let Some((idx, r)) = net {
            let reason = if r.allowlist() {
                Reason::NotFilteredAllowList
            } else {
                Reason::FilteredBlockList
            };

            return MatchResult {
                reason,
                rules: vec![to_matched(&self.block, r, idx)],
                rewrites: Vec::new(),
            };
        }

        // 4. Host rules.
        let hosts = self.block.match_hosts(req);
        if !hosts.is_empty() {
            // Upstream narrows to the matching address family for A and AAAA
            // queries, and falls back to any rule for other types.
            let want_v4 = req.qtype == 1;
            let want_v6 = req.qtype == 28;
            let selected: Vec<&HostRule> = if want_v4 || want_v6 {
                let f: Vec<&HostRule> = hosts
                    .iter()
                    .copied()
                    .filter(|h| h.ip.is_ipv4() == want_v4)
                    .collect();
                if f.is_empty() { hosts.clone() } else { f }
            } else {
                hosts.clone()
            };

            return MatchResult {
                reason: Reason::FilteredBlockList,
                rules: selected.iter().map(|h| host_matched(h)).collect(),
                rewrites: Vec::new(),
            };
        }

        MatchResult::default()
    }
}

/// Converts a network rule into its reportable form.
fn to_matched(set: &RuleSet, _r: &NetworkRule, idx: u32) -> MatchedRule {
    MatchedRule {
        text: set.text_of(idx).to_string(),
        list_id: set.list_of(idx),
        ip: None,
    }
}

/// Converts a host rule into its reportable form.
fn host_matched(h: &HostRule) -> MatchedRule {
    MatchedRule {
        text: h.text.to_string(),
        list_id: h.list_id,
        ip: Some(h.ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: u16 = 1;
    const AAAA: u16 = 28;
    const TXT: u16 = 16;

    fn engine(block: &str) -> Engine {
        Engine::build([(1i64, block)], NO_LISTS)
    }

    fn req<'a>(host: &'a str, qtype: u16) -> Request<'a> {
        Request {
            hostname: host,
            qtype,
            ..Default::default()
        }
    }

    fn matches(e: &Engine, host: &str) -> MatchResult {
        e.match_request(&req(host, A))
    }

    #[test]
    fn a_rebuilt_engine_answers_exactly_as_a_fresh_one() {
        // The whole point of carrying segments over is that the result is
        // indistinguishable from parsing everything again. This changes some
        // lists and not others, across the shapes where a carried-over
        // segment could go wrong: a tie settled by list order, an exception
        // in one list against a block in another, `$important` across lists,
        // a `$badfilter` in one list cancelling a rule in another, host
        // rules for one name in two lists, and a rewrite.
        let v1: Vec<(i64, Arc<str>)> = vec![
            (
                1,
                Arc::from("||tie.example^\n||only-a.example^\n0.0.0.0 host.example\n"),
            ),
            (
                2,
                Arc::from("||tie.example^\n@@||allowed.example^\n||allowed.example^\n"),
            ),
            (
                3,
                Arc::from("||imp.example^$important\n@@||imp.example^\n::1 host.example\n"),
            ),
            (
                4,
                Arc::from("||bad.example^\n||rw.example^$dnsrewrite=1.2.3.4\n"),
            ),
            (5, Arc::from("||bad.example^$badfilter\n")),
        ];

        // A second version of lists 2 and 4; 1, 3 and 5 keep their `Arc` and
        // so are the ones carried over.
        let mut v2 = v1.clone();
        v2[1].1 = Arc::from("||tie.example^\n@@||allowed.example^\n||added.example^\n");
        v2[3].1 = Arc::from("||bad.example^\n||rw.example^$dnsrewrite=5.6.7.8\n");

        let first = Engine::build(v1, NO_LISTS);
        let rebuilt = first.rebuild(v2.clone(), NO_LISTS);
        let fresh = Engine::build(v2, NO_LISTS);

        // The carried-over segments really were carried over, or this test
        // proves nothing about reuse.
        assert!(
            Arc::ptr_eq(&first.block.segments[0], &rebuilt.block.segments[0]),
            "an unchanged list should be the same segment"
        );
        assert!(
            !Arc::ptr_eq(&first.block.segments[1], &rebuilt.block.segments[1]),
            "a changed list should be parsed again"
        );

        assert_eq!(rebuilt.len(), fresh.len());
        for host in [
            "tie.example",
            "only-a.example",
            "allowed.example",
            "added.example",
            "imp.example",
            "bad.example",
            "rw.example",
            "host.example",
            "nothing.example",
        ] {
            for qtype in [A, AAAA] {
                let a = rebuilt.match_request(&req(host, qtype));
                let b = fresh.match_request(&req(host, qtype));

                assert_eq!(a.reason, b.reason, "{host} {qtype}");
                assert_eq!(
                    a.rules.iter().map(|r| &r.text).collect::<Vec<_>>(),
                    b.rules.iter().map(|r| &r.text).collect::<Vec<_>>(),
                    "{host} {qtype}: cited rules differ"
                );
                assert_eq!(
                    a.rules.iter().map(|r| r.list_id).collect::<Vec<_>>(),
                    b.rules.iter().map(|r| r.list_id).collect::<Vec<_>>(),
                    "{host} {qtype}: cited lists differ"
                );
                assert_eq!(a.rewrites, b.rewrites, "{host} {qtype}");
            }
        }
    }

    #[test]
    fn a_rule_reference_carries_its_segment_and_stays_under_the_spill_bit() {
        // Both indexes reserve bit 31 of a value, so a reference has 31 to
        // work with. The split has to leave the high part above the low one,
        // because comparing packed references numerically is how a priority
        // tie is settled by the earlier list.
        assert_eq!(pack(0, 0), 0);
        assert_eq!(seg_of(pack(37, 12_345)), 37);
        assert_eq!(local_of(pack(37, 12_345)), 12_345);
        assert!(pack(MAX_SEGMENTS - 1, MAX_LOCAL) < 1 << 31);
        assert!(
            pack(1, 0) > pack(0, MAX_LOCAL),
            "an earlier list sorts first"
        );
    }

    #[test]
    fn an_expression_is_rebuilt_from_the_rule_text() {
        // The source is not stored on the rule, so the set makes it from the
        // text when it has to build: strip `@@`, drop the modifiers, and
        // `to_regex` what is left. If that disagrees with what the parser
        // matched on, a rule quietly matches something else. Checked against
        // `to_regex` of the pattern for the awkward shapes -- an exception,
        // modifiers, a `/regex/` form, and a `$` inside the pattern itself.
        for (line, pattern) in [
            ("ads*banner", "ads*banner"),
            ("@@ads*banner", "ads*banner"),
            ("ads*banner$important", "ads*banner"),
            ("@@ads*banner$important,badfilter", "ads*banner"),
            ("/^ads?\\./", "/^ads?\\./"),
            ("/a\\$b/$important", "/a\\$b/"),
        ] {
            let set = RuleSet::build([(1i64, line)]);

            assert_eq!(
                set.regex_source_of(0),
                crate::pattern::to_regex(pattern),
                "{line}"
            );
        }
    }

    #[test]
    fn an_expression_rule_still_matches_without_a_stored_source() {
        // End to end: the rule carries no source, so this only answers if the
        // regenerated one compiles to the same expression.
        let e = engine("@@ads*banner.example^$important\n");

        assert_eq!(
            matches(&e, "ads-x-banner.example").reason,
            Reason::NotFilteredAllowList
        );
        assert_eq!(
            matches(&e, "nothing.example").reason,
            Reason::NotFilteredNotFound
        );
    }

    #[test]
    fn a_list_beginning_with_a_byte_order_mark_still_builds() {
        // Two of one server's twenty-nine subscribed lists start with a UTF-8
        // byte-order mark before their `[Adblock Plus 3.13]` header, and
        // building the engine used to abort the process on the first of them.
        let e = engine("\u{feff}[Adblock Plus 3.13]\n||ads.example.com^\n");

        assert_eq!(
            matches(&e, "ads.example.com").reason,
            Reason::FilteredBlockList
        );
        assert_eq!(
            matches(&e, "example.org").reason,
            Reason::NotFilteredNotFound
        );
    }

    #[test]
    fn blocks_via_the_domain_anchor_fast_path() {
        let e = engine("||ads.example.com^\n");
        assert_eq!(
            matches(&e, "ads.example.com").reason,
            Reason::FilteredBlockList
        );
        assert_eq!(
            matches(&e, "x.ads.example.com").reason,
            Reason::FilteredBlockList
        );
        assert_eq!(
            matches(&e, "example.com").reason,
            Reason::NotFilteredNotFound
        );
        assert_eq!(
            matches(&e, "notads.example.com").reason,
            Reason::NotFilteredNotFound
        );
    }

    #[test]
    fn hosts_rules_block_and_carry_their_address() {
        let e = engine("0.0.0.0 ads.example.com\n");
        let r = matches(&e, "ads.example.com");
        assert_eq!(r.reason, Reason::FilteredBlockList);
        assert_eq!(r.rules[0].ip, Some("0.0.0.0".parse().unwrap()));

        // Hosts rules are exact: subdomains are not covered.
        assert_eq!(
            matches(&e, "x.ads.example.com").reason,
            Reason::NotFilteredNotFound
        );
    }

    #[test]
    fn hosts_rules_select_by_address_family() {
        let e = engine("0.0.0.0 a.example.com\n:: a.example.com\n");
        let v4 = e.match_request(&req("a.example.com", A));
        assert_eq!(v4.rules.len(), 1);
        assert!(v4.rules[0].ip.unwrap().is_ipv4());

        let v6 = e.match_request(&req("a.example.com", AAAA));
        assert_eq!(v6.rules.len(), 1);
        assert!(v6.rules[0].ip.unwrap().is_ipv6());
    }

    #[test]
    fn exception_rules_beat_blocking_rules() {
        let e = engine("||example.com^\n@@||good.example.com^\n");
        assert_eq!(
            matches(&e, "bad.example.com").reason,
            Reason::FilteredBlockList
        );
        assert_eq!(
            matches(&e, "good.example.com").reason,
            Reason::NotFilteredAllowList
        );
    }

    #[test]
    fn important_beats_an_exception() {
        let e = engine("||example.com^$important\n@@||example.com^\n");
        assert_eq!(matches(&e, "example.com").reason, Reason::FilteredBlockList);
    }

    #[test]
    fn important_exception_beats_important_block() {
        let e = engine("||example.com^$important\n@@||example.com^$important\n");
        assert_eq!(
            matches(&e, "example.com").reason,
            Reason::NotFilteredAllowList
        );
    }

    #[test]
    fn a_separate_allowlist_short_circuits() {
        let e = Engine::build([(1i64, "||example.com^")], [(2i64, "||example.com^")]);
        let r = matches(&e, "example.com");
        assert_eq!(r.reason, Reason::NotFilteredAllowList);
        assert_eq!(r.rules[0].list_id, 2);
    }

    #[test]
    fn badfilter_cancels_the_matching_rule() {
        let e = engine("||example.com^\n||example.com^$badfilter\n");
        assert_eq!(
            matches(&e, "example.com").reason,
            Reason::NotFilteredNotFound
        );
    }

    #[test]
    fn dnstype_restricts_the_rule() {
        let e = engine("||example.com^$dnstype=AAAA\n");
        assert_eq!(
            e.match_request(&req("example.com", AAAA)).reason,
            Reason::FilteredBlockList
        );
        assert_eq!(
            e.match_request(&req("example.com", A)).reason,
            Reason::NotFilteredNotFound
        );
        assert_eq!(
            e.match_request(&req("example.com", TXT)).reason,
            Reason::NotFilteredNotFound
        );
    }

    #[test]
    fn denyallow_exempts_listed_domains() {
        let e = engine("||example.com^$denyallow=good.example.com\n");
        assert_eq!(
            matches(&e, "bad.example.com").reason,
            Reason::FilteredBlockList
        );
        assert_eq!(
            matches(&e, "good.example.com").reason,
            Reason::NotFilteredNotFound
        );
    }

    #[test]
    fn client_modifier_restricts_by_name_and_address() {
        let e = engine("||example.com^$client=192.168.1.5\n");

        let mut r = req("example.com", A);
        r.client_ip = Some("192.168.1.5".parse().unwrap());
        assert_eq!(e.match_request(&r).reason, Reason::FilteredBlockList);

        let mut r = req("example.com", A);
        r.client_ip = Some("192.168.1.6".parse().unwrap());
        assert_eq!(e.match_request(&r).reason, Reason::NotFilteredNotFound);
    }

    #[test]
    fn ctag_modifier_restricts_by_tag() {
        let e = engine("||example.com^$ctag=device_phone\n");
        let tags = vec!["device_phone".to_string()];
        let r = Request {
            hostname: "example.com",
            qtype: A,
            client_tags: &tags,
            ..Default::default()
        };
        assert_eq!(e.match_request(&r).reason, Reason::FilteredBlockList);

        let other = vec!["device_pc".to_string()];
        let r = Request {
            hostname: "example.com",
            qtype: A,
            client_tags: &other,
            ..Default::default()
        };
        assert_eq!(e.match_request(&r).reason, Reason::NotFilteredNotFound);
    }

    #[test]
    fn dnsrewrite_reports_a_rewrite() {
        let e = engine("||example.com^$dnsrewrite=1.2.3.4\n");
        let r = matches(&e, "example.com");
        assert_eq!(r.reason, Reason::RewrittenRule);
        assert_eq!(
            r.rewrites,
            vec![DnsRewrite::Addr("1.2.3.4".parse().unwrap())]
        );
    }

    #[test]
    fn regex_rules_match_against_the_hostname() {
        // For DNS, a `/regex/` pattern is applied to the bare hostname.
        let e = engine("/^ads[0-9]+\\./\n");
        assert_eq!(
            matches(&e, "ads123.example.com").reason,
            Reason::FilteredBlockList
        );
        assert_eq!(
            matches(&e, "example.com").reason,
            Reason::NotFilteredNotFound
        );
        assert_eq!(
            matches(&e, "x.ads123.example.com").reason,
            Reason::NotFilteredNotFound
        );
    }

    #[test]
    fn a_left_anchored_bare_pattern_pins_to_the_hostname() {
        // The case the Go differential test caught: `|foo.` anchors to the
        // hostname start, not to `http://`.
        let e = engine("|load.gtm.\n");
        assert_eq!(
            matches(&e, "load.gtm.example.co.uk").reason,
            Reason::FilteredBlockList
        );
        assert_eq!(
            matches(&e, "x.load.gtm.example.co.uk").reason,
            Reason::NotFilteredNotFound
        );
    }

    #[test]
    fn wildcard_text_rules_match() {
        let e = engine("||ad*.example.com^\n");
        assert_eq!(
            matches(&e, "ads.example.com").reason,
            Reason::FilteredBlockList
        );
        assert_eq!(
            matches(&e, "news.example.com").reason,
            Reason::NotFilteredNotFound
        );
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let e = engine("! a comment\n\n||example.com^\n# another\n");
        assert_eq!(e.block.len(), 1);
    }

    #[test]
    fn empty_engine_matches_nothing() {
        let e = Engine::default();
        assert!(e.is_empty());
        assert_eq!(
            matches(&e, "example.com").reason,
            Reason::NotFilteredNotFound
        );
    }
}
