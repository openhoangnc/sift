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
/// Eight bytes, and no bytes of its own: the text is the line still sitting in
/// the source the rule was parsed from. Which source is not stored per rule —
/// rules are added list by list, so `src_starts` recovers it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TextRef {
    /// Byte offset into the source.
    off: u32,
    /// Length in bytes. A line longer than this can hold is not a rule
    /// anyone wrote; such a rule still matches, it just reports no text.
    len: u16,
    /// Which source, indexing `RuleSet::sources`.
    src: u16,
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
    net: Vec<NetworkRule>,
    /// The list texts the rules were parsed from, shared with whatever owns
    /// them rather than copied: the manager keeps every list in memory to
    /// rebuild from, so an arena here held a second copy of the same bytes.
    sources: Vec<Arc<str>>,
    /// The list identifier each source came from, parallel to `sources`.
    ///
    /// Here rather than on the rule: there are 37 of these on a real
    /// installation and 2.2M rules, and an `i64` on every rule was 17 MB to
    /// say one of 37 things.
    list_ids: Vec<i64>,
    /// Where each network rule's text sits within its source.
    net_text: Vec<TextRef>,
    hosts: Vec<HostRule>,
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
        let mut b = Builder::default();
        for (id, text) in lists {
            b.add_list(id, text.into());
        }

        b.finish()
    }

    /// A rough breakdown of where the set's memory goes.
    ///
    /// Heap estimates rather than an allocator reading: enough to tell which
    /// structure to attack, which is all it is for.
    pub fn footprint(&self) -> String {
        use std::mem::size_of;

        let net_structs = self.net.capacity() * size_of::<NetworkRule>();
        let net_text = self.net_text.capacity() * size_of::<TextRef>()
            + self.sources.capacity() * size_of::<Arc<str>>();
        let net_opts =
            self.net.iter().filter(|r| r.opts.is_some()).count() * (size_of::<Options>() + 32);

        let host_structs = self.hosts.capacity() * size_of::<HostRule>();
        let host_text: usize = self
            .hosts
            .iter()
            .map(|h| {
                h.text.len()
                    + 32
                    + h.hostnames.iter().map(|n| n.len() + 32).sum::<usize>()
                    + h.hostnames.capacity() * size_of::<String>()
            })
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
                format!("{} rules", self.net.len()),
            ),
            ("network rule text", net_text, String::new()),
            ("network rule options", net_opts, String::new()),
            (
                "host rule structs",
                host_structs,
                format!("{} rules", self.hosts.len()),
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
    /// The list a rule came from, by the source its text sits in.
    fn list_of(&self, idx: u32) -> i64 {
        self.net_text
            .get(idx as usize)
            .and_then(|r| self.list_ids.get(r.src as usize))
            .copied()
            .unwrap_or_default()
    }

    fn text_of(&self, idx: u32) -> &str {
        let Some(r) = self.net_text.get(idx as usize) else {
            return "";
        };

        let Some(text) = self.sources.get(r.src as usize) else {
            return "";
        };

        text.get(r.off as usize..r.off as usize + r.len as usize)
            .unwrap_or("")
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
        let r = &self.net[idx as usize];

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

        if !self.applies(r, req, url) {
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
    fn applies(&self, r: &NetworkRule, req: &Request<'_>, url: &str) -> bool {
        if r.badfilter() {
            return false;
        }

        let Some(opts) = r.opts() else {
            // No modifiers: only the pattern decides.
            return self.pattern_matches(r, req, url);
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

        self.pattern_matches(r, req, url)
    }

    /// Reports whether the rule's pattern matches the request.
    fn pattern_matches(&self, r: &NetworkRule, req: &Request<'_>, url: &str) -> bool {
        match r.pattern() {
            PatternRef::Any => true,
            // Reaching a domain-anchored rule means the domain index already
            // matched one of the hostname's suffixes.
            PatternRef::DomainAnchor => true,
            PatternRef::Rx { re, target } => match target {
                Target::Url => re.is_match(url),
                Target::Hostname => re.is_match(req.hostname),
            },
        }
    }

    /// Finds host rules for the request's hostname.
    fn match_hosts(&self, req: &Request<'_>) -> Vec<&HostRule> {
        self.host_index
            .get(req.hostname)
            .map(|ids| ids.iter().map(|i| &self.hosts[i as usize]).collect())
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
#[derive(Default)]
struct Builder {
    net: Vec<NetworkRule>,
    sources: Vec<Arc<str>>,
    list_ids: Vec<i64>,
    net_text: Vec<TextRef>,
    hosts: Vec<HostRule>,
    domain_pairs: Vec<(u64, u32)>,
    host_index: AHashMap<Box<str>, Refs>,
    shortcuts: AHashMap<String, Vec<u32>>,
    scan: Vec<u32>,
    badfilter: AHashSet<Box<str>>,
    rules_count: usize,
}

impl Builder {
    /// Parses and indexes every line of one list.
    fn add_list(&mut self, id: i64, text: Arc<str>) {
        let src = self.sources.len() as u16;
        self.sources.push(Arc::clone(&text));
        self.list_ids.push(id);

        let base = text.as_ptr() as usize;
        for line in text.lines() {
            match parse(line, id) {
                Ok(Rule::Network(n)) => {
                    // `parse` trims, so this is exactly the text it used, and
                    // it is a slice of `text` — hence the offset arithmetic.
                    let t = line.trim();
                    let off = (t.as_ptr() as usize - base) as u32;
                    self.add_network(n.rule, t, src, off, n.shortcut);
                }
                Ok(Rule::Host(h)) => self.add_host(h),
                Err(_) => {}
            }
        }
    }

    /// Indexes one network rule.
    fn add_network(
        &mut self,
        r: NetworkRule,
        text: &str,
        src: u16,
        off: u32,
        shortcut: Option<String>,
    ) {
        self.rules_count += 1;

        if r.badfilter() {
            self.badfilter
                .insert(canonical_text(text).into_owned().into_boxed_str());
        }

        let idx = self.net.len() as u32;
        self.net_text.push(TextRef {
            off,
            len: u16::try_from(text.len()).unwrap_or(0),
            src,
        });

        match (r.pattern(), shortcut) {
            (PatternRef::DomainAnchor, Some(d)) => {
                // Hashed here and the string dropped: the index keeps no
                // keys, so holding one per rule until it was built was 1.9M
                // live allocations for nothing.
                self.domain_pairs.push((DomainIndex::hash(&d), idx));
            }
            (PatternRef::Rx { .. }, Some(sc)) if sc.len() >= MIN_SHORTCUT_LEN => {
                self.shortcuts.entry(sc).or_default().push(idx);
            }
            _ => self.scan.push(idx),
        }

        self.net.push(r);
    }

    /// Indexes one hosts-file rule.
    fn add_host(&mut self, h: HostRule) {
        self.rules_count += 1;
        let idx = self.hosts.len() as u32;
        for name in &h.hostnames {
            push_ref(&mut self.host_index, name.clone().into_boxed_str(), idx);
        }
        self.hosts.push(h);
    }

    /// Finalises the indexes into a queryable rule set.
    fn finish(mut self) -> RuleSet {
        // A `Vec` grows by doubling, so each of these can be holding up to
        // twice what it needs. They are written once and read for the life of
        // the process, so hand the overshoot back.
        //
        // This is free on the shipping target and worth having elsewhere.
        // Rust's `System` allocator reallocates through libc, and musl's
        // `mallocng` serves anything past 128 KB from `mmap` and resizes it
        // with `mremap`: growing moves page tables rather than copying, and
        // shrinking truncates in place and returns the pages at once. A
        // conditional version of this was tried on the theory that shrinking
        // an 83 MB vector cost an 83 MB copy inside the rebuild's peak. It
        // does not, on musl -- measured with a 160 MB vector in the image:
        // growing it left `VmHWM` where it was, and shrinking it did too.
        self.net.shrink_to_fit();
        self.net_text.shrink_to_fit();
        self.hosts.shrink_to_fit();
        self.scan.shrink_to_fit();
        self.domain_pairs.shrink_to_fit();

        let Builder {
            net,
            sources,
            list_ids,
            net_text,
            hosts,
            domain_pairs,
            host_index,
            shortcuts,
            scan,
            badfilter,
            rules_count,
        } = self;

        RuleSet {
            net,
            sources,
            list_ids,
            net_text,
            hosts,
            domain_index: DomainIndex::build(domain_pairs),
            host_index,
            shortcuts: ShortcutIndex::build(shortcuts.into_iter().collect()),
            scan,
            badfilter,
            rules_count,
        }
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
        text: h.text.clone(),
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
