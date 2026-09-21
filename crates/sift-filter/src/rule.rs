//! Parsing of AdGuard filtering rules.
//!
//! Two rule families matter for DNS filtering:
//!
//!   * *host rules*, the hosts-file form — `0.0.0.0 ads.example.com`;
//!   * *network rules*, the adblock form — `||ads.example.com^$important`.
//!
//! Network rules are matched against the pseudo-URL `http://<hostname>`, the
//! same string upstream's `FillRequestForHostname` builds, so patterns behave
//! identically to the Go engine.

use std::net::IpAddr;
use std::sync::Arc;

use std::collections::VecDeque;
use std::sync::Weak;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::{Mutex, RwLock};

use regex::Regex;

use crate::pattern::{self, Target};

/// A parsed rule.
#[derive(Clone, Debug)]
pub enum Rule {
    /// A hosts-file entry.
    Host(HostRule),
    /// An adblock-style rule, with the shortcut the index will consume.
    Network(Box<ParsedNetwork>),
}

/// A network rule together with the prefilter shortcut derived from its
/// pattern.
///
/// The shortcut is a product of parsing that only the index needs, so it is
/// kept beside the rule rather than inside it: at list scale, a field that is
/// dead after construction costs tens of megabytes.
#[derive(Clone, Debug)]
pub struct ParsedNetwork {
    /// The rule itself.
    pub rule: NetworkRule,
    /// The longest literal run in the pattern, if it is long enough to index.
    pub shortcut: Option<String>,
}

/// A hosts-file entry: an address and the names it resolves.
///
/// The names are **not** stored. They are the line's own words, and keeping
/// them cost a `Vec` and a `String` each on top of the text they were copied
/// from -- on a real installation 147,175 of these carry about 12 MB of
/// duplicate, and a rebuild holds two sets. [`Self::hostnames`] reads them
/// back out of the text, which only the build and the tests ask for: a lookup
/// goes through the host index, whose keys are those names already.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRule {
    /// The original rule text.
    pub text: Box<str>,
    /// The address the names resolve to.
    pub ip: IpAddr,
    /// The list this rule came from.
    pub list_id: i64,
}

impl HostRule {
    /// The names this entry covers, in the form the index files them under.
    pub fn hostnames(&self) -> impl Iterator<Item = String> + '_ {
        hostnames_of(&self.text)
    }
}

/// The valid names on a hosts line, lowercased and without a trailing dot.
///
/// One definition, used to parse the line and to read it back, so the two
/// cannot drift.
fn hostnames_of(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split_once(|c: char| c.is_ascii_whitespace())
        .map(|(_, rest)| rest)
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("")
        .split_ascii_whitespace()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.is_empty() && sift_core::name::is_valid(h))
}

impl HostRule {
    /// Reports whether this entry blocks rather than rewrites, i.e. whether the
    /// address is unspecified.
    pub fn is_blocking(&self) -> bool {
        self.ip.is_unspecified()
    }
}

/// What a rule matches against, borrowed from the rule.
///
/// The stored form is a pointer and a byte of flags; this is that unpacked
/// into the shape the matcher wants. See [`NetworkRule`].
#[derive(Clone, Copy, Debug)]
pub enum PatternRef<'a> {
    /// `||domain^`, which reaching through the domain index already proves.
    DomainAnchor,
    /// Any other pattern, as an expression built on first use.
    Rx {
        /// The expression.
        re: &'a Arc<LazyRegex>,
        /// What the expression is matched against.
        target: Target,
    },
    /// Matches every hostname.
    Any,
}

/// The pattern is a domain anchor.
const KIND_ANCHOR: u8 = 0;
/// The pattern matches everything.
const KIND_ANY: u8 = 1;
/// The pattern is an expression.
const KIND_RX: u8 = 2;
/// The bits [`KIND_ANCHOR`] and its siblings occupy.
const KIND_MASK: u8 = 0b11;
/// The expression matches the pseudo-URL rather than the bare hostname.
const TARGET_URL: u8 = 1 << 2;
/// The rule is an exception (`@@`).
const ALLOWLIST: u8 = 1 << 3;

/// An adblock-style rule.
///
/// The layout is deliberately tight.  A real installation holds a couple of
/// million of these, so every byte here is multiplied by that, and the
/// rebuild holds two sets of them at once.  Three things follow from that and
/// look odd until it is said:
///
/// * the modifiers live behind a `Box`, because almost no rule has any;
/// * the pattern is a pointer and three bits rather than an enum. As an enum
///   it cost 16 bytes: the `Arc` is 8, its niche is spent by the two payloadless
///   variants, and the target and tag then round the whole thing up. Unpacked
///   through [`Self::pattern`] it costs a byte;
/// * the list a rule came from is **not** here. It is a property of the
///   source the rule was parsed from, one per list, and the rule set holds it
///   there -- 8 bytes a rule for something with 37 distinct values.
///
/// Together those are 40 bytes down to 24, which is 33 MB of a 2.2M-rule
/// engine and twice that off the rebuild's peak.
#[derive(Clone, Debug)]
pub struct NetworkRule {
    /// The expression, for a pattern that needs one.
    re: Option<Arc<LazyRegex>>,
    /// The modifiers attached to the rule, if it has any.
    pub opts: Option<Box<Options>>,
    /// The pattern's kind and target, and whether the rule is an exception.
    flags: u8,
}

impl NetworkRule {
    /// Builds a rule from the parts the parser produces.
    pub fn new(pattern: Pattern, opts: Option<Box<Options>>, allowlist: bool) -> Self {
        let (re, mut flags) = match pattern {
            Pattern::DomainAnchor => (None, KIND_ANCHOR),
            Pattern::Any => (None, KIND_ANY),
            Pattern::Rx { re, target } => (
                Some(re),
                KIND_RX
                    | match target {
                        Target::Url => TARGET_URL,
                        Target::Hostname => 0,
                    },
            ),
        };

        if allowlist {
            flags |= ALLOWLIST;
        }

        Self { re, opts, flags }
    }

    /// What the rule matches against.
    pub fn pattern(&self) -> PatternRef<'_> {
        match self.flags & KIND_MASK {
            KIND_ANCHOR => PatternRef::DomainAnchor,
            KIND_ANY => PatternRef::Any,
            _ => PatternRef::Rx {
                // `KIND_RX` is only ever set beside an expression.
                re: self.re.as_ref().expect("an expression rule carries one"),
                target: if self.flags & TARGET_URL == 0 {
                    Target::Hostname
                } else {
                    Target::Url
                },
            },
        }
    }

    /// Whether this is an exception (`@@`) rule.
    pub fn allowlist(&self) -> bool {
        self.flags & ALLOWLIST != 0
    }

    /// The rule's modifiers, if it carries any.
    pub fn opts(&self) -> Option<&Options> {
        self.opts.as_deref()
    }

    /// Whether the rule has the `$important` modifier.
    pub fn important(&self) -> bool {
        self.opts().is_some_and(|o| o.important)
    }

    /// Whether the rule has the `$badfilter` modifier.
    pub fn badfilter(&self) -> bool {
        self.opts().is_some_and(|o| o.badfilter)
    }

    /// The rule's `$dnsrewrite` value, if it has one.
    pub fn dnsrewrite(&self) -> Option<&DnsRewrite> {
        self.opts().and_then(|o| o.dnsrewrite.as_ref())
    }

    /// Counts the rule's dedicated specifiers, mirroring upstream's
    /// `calcRuleSpecs`.
    pub fn specificity(&self) -> usize {
        let Some(o) = self.opts() else {
            return 0;
        };

        usize::from(o.important)
            + usize::from(o.badfilter)
            + usize::from(o.dnstype.is_some())
            + usize::from(o.client.is_some())
            + usize::from(o.ctag.is_some())
            + usize::from(!o.denyallow.is_empty())
            + usize::from(o.dnsrewrite.is_some())
    }
}

/// A rule's expression, compiled the first time it is needed.
///
/// A real deployment loads a couple of million rules, of which a few hundred
/// thousand are not `||domain^` and so need an expression. Building every
/// automaton at load cost about twenty seconds and most of a gigabyte on one
/// such installation — for expressions that are only ever consulted once the
/// domain index or the Aho-Corasick scan has already picked that rule as a
/// candidate, which is a handful per query. Nearly all of them are never
/// consulted at all.
///
/// So the source is kept and the automaton is built on first use. The result
/// is cached, including a failure: a source that will not compile can never
/// match, which is what dropping the rule at load achieved.
pub struct LazyRegex {
    /// The expression source, as [`crate::pattern::to_regex`] produced it.
    src: Box<str>,
    /// The compiled form, while it is being kept.
    re: RwLock<Slot>,
    /// Whether anything has matched against it since it was last considered
    /// for eviction.  Building one costs 105 microseconds, so an expression
    /// the network keeps reaching should not be thrown away just for being
    /// the oldest.
    used: AtomicBool,
}

/// What a [`LazyRegex`] is holding.
enum Slot {
    /// Never built, or built and since dropped to stay under the ceiling.
    Empty,
    /// Built once and refused by the regex crate; it can never match, and
    /// remembering that costs nothing, so it is never dropped.
    Failed,
    /// Built and being kept.
    ///
    /// Behind an `Arc` so a match can take a reference and let go of the lock
    /// before running: a match must never be what an eviction waits on.
    Built(Arc<Regex>),
}

/// How many compiled expressions are kept at once.
///
/// One costs about 25 KB, measured over the expression rules of real lists,
/// and it is the compiled program rather than the lazy DFA's cache — so
/// `dfa_size_limit` does not touch it, which was the first thing tried.
/// Two thousand of them is therefore a ceiling of roughly 50 MB, and the
/// whole process measured about 90 MB above its idle size at the ceiling,
/// the rest being the response cache and the hour of statistics.
///
/// There has to be a ceiling. Building every expression at load cost 22
/// seconds and most of a gigabyte on a 37-list installation, which is why
/// they are built on first use; but a cache nothing bounds only arrives at
/// the same place more slowly. That installation holds 2,277,924 rules, of
/// which 156,557 need an expression — 3.8 GB, if the network eventually asks
/// for a name that reaches each one. It was doing so at 6 MB an hour.
pub const MAX_COMPILED: usize = 2_000;

/// The point past which a second chance is no longer offered.
const HARD_CEILING: usize = MAX_COMPILED + MAX_COMPILED / 8;

/// The expressions currently built, oldest first.
///
/// Weak, so an engine that has been rebuilt does not keep its old rules alive
/// through this, and entries that no longer upgrade are simply skipped.
static COMPILED: Mutex<VecDeque<Weak<LazyRegex>>> = Mutex::new(VecDeque::new());

/// How many expressions are built right now.
///
/// Slots whose rule is gone -- the engine was rebuilt under them -- are not
/// counted: they leave the next time the ceiling is reached rather than when
/// the rule drops, so counting them would report a number nothing is holding.
///
/// This is the one that used to grow without bound, so it is the one a
/// memory snapshot is really asking about: against [`MAX_COMPILED`] it says
/// whether the ceiling is being reached at all.
pub fn compiled_count() -> usize {
    COMPILED
        .lock()
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|lr| matches!(&*lr.re.read(), Slot::Built(_)))
        .count()
}

/// Drops every expression built so far.
///
/// Called before the engine is rebuilt. The expressions belong to rules the
/// rebuild is about to replace, so they are discarded at the swap in any
/// case; letting them go first means they are not held through the moment
/// both engines are live, which is the peak the whole rebuild is measured by.
/// At the ceiling that is 2,000 of them, about 25 KB each.
///
/// What it costs is the expressions the network asks for again being built
/// again, at 105 microseconds each -- the same cost the swap imposes anyway,
/// since the new engine's are empty.
pub fn drop_compiled() {
    let mut compiled = COMPILED.lock();

    for weak in compiled.drain(..) {
        let Some(lr) = weak.upgrade() else {
            continue;
        };

        let mut slot = lr.re.write();
        if matches!(&*slot, Slot::Built(_)) {
            *slot = Slot::Empty;
        }
    }
}

impl LazyRegex {
    /// Holds an expression without compiling it.
    pub fn new(src: String) -> Self {
        Self {
            src: src.into_boxed_str(),
            re: RwLock::new(Slot::Empty),
            used: AtomicBool::new(false),
        }
    }

    /// Holds an already-compiled expression.
    ///
    /// Used for the `/regex/` form, which a user writes by hand and which is
    /// therefore compiled at load so a malformed one is still rejected there.
    ///
    /// It is not registered for eviction: a user writes few of these by hand,
    /// and dropping one would lose the validation that compiling it proved.
    pub fn compiled(src: String, re: Regex) -> Self {
        Self {
            src: src.into_boxed_str(),
            re: RwLock::new(Slot::Built(Arc::new(re))),
            used: AtomicBool::new(false),
        }
    }

    /// Reports whether the expression matches, building it if needed.
    pub fn is_match(self: &Arc<Self>, haystack: &str) -> bool {
        // Take a reference to the expression and let the lock go before
        // matching against it.
        let held = match &*self.re.read() {
            Slot::Built(re) => Some(Arc::clone(re)),
            Slot::Failed => return false,
            Slot::Empty => None,
        };

        if let Some(re) = held {
            self.used.store(true, Ordering::Relaxed);

            return re.is_match(haystack);
        }

        self.build().is_some_and(|re| re.is_match(haystack))
    }

    /// Builds the expression and keeps it, evicting the oldest if need be.
    fn build(self: &Arc<Self>) -> Option<Arc<Regex>> {
        let Some(re) = Regex::new(&self.src).ok().map(Arc::new) else {
            *self.re.write() = Slot::Failed;

            return None;
        };

        *self.re.write() = Slot::Built(Arc::clone(&re));

        let mut compiled = COMPILED.lock();
        compiled.push_back(Arc::downgrade(self));

        // At most one pass, so an expression given a second chance cannot be
        // reconsidered in the same one.  When every expression held has been
        // used the pass clears their marks and stops, leaving the ceiling
        // exceeded by a little until the next build; that is the cost of not
        // discarding something the network is still asking for.
        let mut passes = compiled.len();
        while compiled.len() > MAX_COMPILED && passes > 0 {
            passes -= 1;

            let Some(old) = compiled.pop_front() else {
                break;
            };
            // An expression whose rule is gone -- the engine was rebuilt --
            // simply leaves.
            let Some(lr) = old.upgrade() else {
                continue;
            };

            // Past the hard ceiling the second chance is not offered: a
            // resolver busy enough to reach every expression between two
            // builds must not be able to grow this without end.
            if compiled.len() <= HARD_CEILING && lr.used.swap(false, Ordering::Relaxed) {
                compiled.push_back(old);

                continue;
            }

            // The caller keeps its own reference, so dropping the rule's is
            // safe even when the expression evicted is this one.
            let mut slot = lr.re.write();
            if matches!(&*slot, Slot::Built(_)) {
                *slot = Slot::Empty;
            }
        }

        Some(re)
    }

    /// The expression source.
    pub fn source(&self) -> &str {
        &self.src
    }

    /// Whether the expression is built and being kept, for tests.
    #[cfg(test)]
    fn is_built(&self) -> bool {
        matches!(&*self.re.read(), Slot::Built(_))
    }
}

impl std::fmt::Debug for LazyRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyRegex")
            .field("src", &self.src)
            .field("compiled", &matches!(&*self.re.read(), Slot::Built(_)))
            .finish()
    }
}

/// The matchable part of a network rule.
#[derive(Clone, Debug)]
pub enum Pattern {
    /// `||domain^` — the domain itself and any subdomain.  The common case in
    /// DNS blocklists, and the one with the fastest lookup path: a suffix walk
    /// is exactly equivalent to the regex this would otherwise compile to.
    ///
    /// No payload: such a rule is only ever reachable through the domain
    /// index, whose key *is* the domain, so arriving here already proves the
    /// hostname matched.
    DomainAnchor,
    /// Any other pattern, expressed as the regex
    /// [`crate::pattern::to_regex`] produces, built on first use.
    Rx {
        /// The expression.
        re: Arc<LazyRegex>,
        /// What the expression is matched against.
        target: Target,
    },
    /// Matches every hostname.
    Any,
}

/// The modifiers a network rule may carry.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// `$important` — outranks exception rules.
    pub important: bool,
    /// `$badfilter` — disables the otherwise-identical rule.
    pub badfilter: bool,
    /// `$dnstype=A|AAAA` — the query types this rule applies to.
    pub dnstype: Option<TypeList>,
    /// `$client=...` — the clients this rule applies to.
    pub client: Option<StrList>,
    /// `$ctag=...` — the client tags this rule applies to.
    pub ctag: Option<StrList>,
    /// `$denyallow=...` — domains this rule must *not* block.
    pub denyallow: Vec<String>,
    /// `$dnsrewrite=...` — the response to synthesise.
    pub dnsrewrite: Option<DnsRewrite>,
}

impl Options {
    /// Reports whether any modifier restricts which requests the rule applies
    /// to.  Unrestricted rules can use the fast lookup paths.
    pub fn is_plain(&self) -> bool {
        self.dnstype.is_none()
            && self.client.is_none()
            && self.ctag.is_none()
            && self.denyallow.is_empty()
            && self.dnsrewrite.is_none()
    }
}

/// A list of values that may be negated individually.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StrList {
    /// Values that must match.
    pub included: Vec<String>,
    /// Values that must not match.
    pub excluded: Vec<String>,
}

impl StrList {
    /// Reports whether `v` satisfies the list.
    pub fn matches(&self, v: &str) -> bool {
        if self.excluded.iter().any(|e| e.eq_ignore_ascii_case(v)) {
            return false;
        }
        if self.included.is_empty() {
            return true;
        }

        self.included.iter().any(|i| i.eq_ignore_ascii_case(v))
    }

    /// Reports whether any of `vs` satisfies the list.
    pub fn matches_any(&self, vs: &[String]) -> bool {
        if vs
            .iter()
            .any(|v| self.excluded.iter().any(|e| e.eq_ignore_ascii_case(v)))
        {
            return false;
        }
        if self.included.is_empty() {
            return true;
        }

        vs.iter()
            .any(|v| self.included.iter().any(|i| i.eq_ignore_ascii_case(v)))
    }
}

/// A list of DNS record types that may be negated.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TypeList {
    /// Types that must match.
    pub included: Vec<u16>,
    /// Types that must not match.
    pub excluded: Vec<u16>,
}

impl TypeList {
    /// Reports whether query type `t` satisfies the list.
    pub fn matches(&self, t: u16) -> bool {
        if self.excluded.contains(&t) {
            return false;
        }
        if self.included.is_empty() {
            return true;
        }

        self.included.contains(&t)
    }
}

/// The response a `$dnsrewrite` rule synthesises.
#[derive(Clone, Debug, PartialEq)]
pub enum DnsRewrite {
    /// Answer with this response code and no records.
    RCode(u16),
    /// Answer with this address.
    Addr(IpAddr),
    /// Answer with this canonical name, then resolve it.
    CName(String),
    /// Answer with an arbitrary record of the given type.
    Record {
        /// The record type.
        rtype: u16,
        /// The record's textual value.
        value: String,
    },
}

/// Why a rule could not be parsed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    /// The line is blank or a comment and carries no rule.
    #[error("not a rule")]
    NotARule,
    /// The line is a cosmetic rule, which DNS filtering ignores.
    #[error("cosmetic rules are not applicable to DNS")]
    Cosmetic,
    /// The rule's syntax is invalid.
    #[error("invalid rule: {0}")]
    Invalid(String),
    /// The rule uses a modifier this engine does not implement.
    #[error("unsupported modifier: {0}")]
    UnsupportedModifier(String),
}

/// Maps a record type name to its numeric code.
pub fn rr_type_from_str(s: &str) -> Option<u16> {
    Some(match s.to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "HINFO" => 13,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "NAPTR" => 35,
        "DS" => 43,
        "SSHFP" => 44,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "TLSA" => 52,
        "SVCB" => 64,
        "HTTPS" => 65,
        "CAA" => 257,
        "ANY" => 255,
        _ => return None,
    })
}

/// Maps a response code name to its numeric value.
fn rcode_from_str(s: &str) -> Option<u16> {
    Some(match s.to_ascii_uppercase().as_str() {
        "NOERROR" => 0,
        "FORMERR" => 1,
        "SERVFAIL" => 2,
        "NXDOMAIN" => 3,
        "NOTIMP" => 4,
        "REFUSED" => 5,
        _ => return None,
    })
}

/// Parses one line of a filter list.
pub fn parse(line: &str, list_id: i64) -> Result<Rule, ParseError> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('!') || t.starts_with("# ") || t == "#" {
        return Err(ParseError::NotARule);
    }

    // Cosmetic rules carry a `##`-family separator; DNS filtering skips them.
    if t.contains("##") || t.contains("#@#") || t.contains("#%#") || t.contains("#$#") {
        return Err(ParseError::Cosmetic);
    }

    if let Some(h) = parse_host_rule(t, list_id) {
        return Ok(Rule::Host(h));
    }

    parse_network_rule(t).map(|r| Rule::Network(Box::new(r)))
}

/// Parses a hosts-file line, returning `None` if it is not one.
fn parse_host_rule(t: &str, list_id: i64) -> Option<HostRule> {
    // A hosts line starts with an address followed by whitespace.
    let (first, _) = t.split_once(|c: char| c.is_ascii_whitespace())?;
    let ip: IpAddr = first.parse().ok()?;

    // Parsed to be sure the line names something valid, then dropped: the
    // text is kept and `hostnames` reads them back from it.
    hostnames_of(t).next()?;

    Some(HostRule {
        text: t.into(),
        ip,
        list_id,
    })
}

/// Parses an adblock-style rule.
fn parse_network_rule(t: &str) -> Result<ParsedNetwork, ParseError> {
    let mut s = t;
    let mut allowlist = false;
    if let Some(rest) = s.strip_prefix("@@") {
        allowlist = true;
        s = rest;
    }

    let (pattern_str, opts) = split_options(s)?;
    let (pattern, domain) = parse_pattern(pattern_str)?;
    let shortcut = match &pattern {
        // A domain-anchored rule is indexed by its domain, not a shortcut.
        Pattern::DomainAnchor => domain,
        _ => pattern::shortcut(pattern_str, MIN_SHORTCUT_LEN),
    };

    let opts = if opts.is_plain() && !opts.important && !opts.badfilter {
        None
    } else {
        Some(Box::new(opts))
    };

    Ok(ParsedNetwork {
        rule: NetworkRule::new(pattern, opts, allowlist),
        shortcut,
    })
}

/// Splits a rule body into its pattern and its parsed modifiers.
///
/// The `$` that introduces modifiers is the last unescaped one that is not
/// inside a `/regex/` pattern.
fn split_options(s: &str) -> Result<(&str, Options), ParseError> {
    let b = s.as_bytes();
    let in_regex = b.first() == Some(&b'/') && s.len() > 1;

    // Find the `$` that starts the modifier list.
    let mut idx = None;
    let mut i = 0usize;
    let mut regex_closed = !in_regex;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b'/' if in_regex && i > 0 => regex_closed = true,
            b'$' if regex_closed => {
                idx = Some(i);
            }
            _ => {}
        }
        i += 1;
    }

    // Only the *last* `$` at the top level starts modifiers, and only if the
    // text after it parses as a modifier list.
    let Some(i) = idx else {
        return Ok((s, Options::default()));
    };

    let opts = parse_options(&s[i + 1..])?;

    Ok((&s[..i], opts))
}

/// Parses a comma-separated modifier list.
fn parse_options(s: &str) -> Result<Options, ParseError> {
    let mut o = Options::default();
    for part in split_unescaped(s, ',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let (name, value) = match part.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (part, None),
        };

        match name {
            "important" => o.important = true,
            "badfilter" => o.badfilter = true,
            "dnstype" => {
                o.dnstype = Some(parse_type_list(value.unwrap_or_default())?);
            }
            "client" => o.client = Some(parse_str_list(value.unwrap_or_default())),
            "ctag" => o.ctag = Some(parse_str_list(value.unwrap_or_default())),
            "denyallow" => {
                o.denyallow = value
                    .unwrap_or_default()
                    .split('|')
                    .filter(|v| !v.is_empty())
                    .map(|v| v.to_ascii_lowercase())
                    .collect();
            }
            "dnsrewrite" => {
                o.dnsrewrite = Some(parse_dnsrewrite(value.unwrap_or_default())?);
            }
            // Modifiers that are meaningful for HTTP filtering but inert for
            // DNS.  Accept and ignore them rather than dropping the rule.
            "domain" | "third-party" | "~third-party" | "3p" | "~3p" | "first-party"
            | "~first-party" | "app" | "network" | "popup" | "document" | "doc" | "all"
            | "method" | "to" | "extension" | "~extension" => {}
            other => return Err(ParseError::UnsupportedModifier(other.to_string())),
        }
    }

    Ok(o)
}

/// Splits on `sep`, honouring backslash escapes.
fn split_unescaped(s: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'\\' {
            i += 2;
            continue;
        }
        if b[i] == sep as u8 {
            out.push(&s[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    out.push(&s[start..]);

    out
}

/// Parses a `|`-separated list of possibly negated values.
fn parse_str_list(s: &str) -> StrList {
    let mut l = StrList::default();
    for v in s.split('|') {
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        match v.strip_prefix('~') {
            Some(neg) => l.excluded.push(neg.to_string()),
            None => l.included.push(v.to_string()),
        }
    }

    l
}

/// Parses a `|`-separated list of possibly negated record types.
fn parse_type_list(s: &str) -> Result<TypeList, ParseError> {
    let mut l = TypeList::default();
    for v in s.split('|') {
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        let (neg, name) = match v.strip_prefix('~') {
            Some(n) => (true, n),
            None => (false, v),
        };
        let t = rr_type_from_str(name)
            .ok_or_else(|| ParseError::Invalid(format!("unknown dns type {name:?}")))?;
        if neg {
            l.excluded.push(t);
        } else {
            l.included.push(t);
        }
    }

    Ok(l)
}

/// Parses a `$dnsrewrite` value.
///
/// Accepts the shorthand forms (`1.2.3.4`, `example.net`, `NXDOMAIN`) and the
/// full `RCODE;TYPE;VALUE` form.
fn parse_dnsrewrite(s: &str) -> Result<DnsRewrite, ParseError> {
    // No value at all is `NOERROR` and no records -- an answer, not a
    // cancellation. Captured from a running v0.107.79: `||a.example^$dnsrewrite`
    // and `||a.example^$dnsrewrite=` both answer NOERROR with an empty answer
    // section and report `RewriteRule`.
    if s.is_empty() {
        return Ok(DnsRewrite::RCode(0));
    }

    let parts: Vec<&str> = s.split(';').collect();
    match parts.as_slice() {
        [one] => {
            if let Some(rc) = rcode_from_str(one) {
                return Ok(DnsRewrite::RCode(rc));
            }
            if let Ok(ip) = one.parse::<IpAddr>() {
                return Ok(DnsRewrite::Addr(ip));
            }
            if sift_core::name::is_valid(one) {
                return Ok(DnsRewrite::CName(one.to_ascii_lowercase()));
            }

            Err(ParseError::Invalid(format!("bad dnsrewrite value {one:?}")))
        }
        [rcode, rtype, value] => {
            let rc = rcode_from_str(rcode)
                .ok_or_else(|| ParseError::Invalid(format!("bad rcode {rcode:?}")))?;
            if rc != 0 {
                return Ok(DnsRewrite::RCode(rc));
            }
            let t = rr_type_from_str(rtype)
                .ok_or_else(|| ParseError::Invalid(format!("bad type {rtype:?}")))?;
            match t {
                1 | 28 => value
                    .parse::<IpAddr>()
                    .map(DnsRewrite::Addr)
                    .map_err(|_| ParseError::Invalid(format!("bad address {value:?}"))),
                5 => Ok(DnsRewrite::CName(value.to_ascii_lowercase())),
                _ => Ok(DnsRewrite::Record {
                    rtype: t,
                    value: value.to_string(),
                }),
            }
        }
        [rcode, ..] if parts.len() == 2 => {
            let rc = rcode_from_str(rcode)
                .ok_or_else(|| ParseError::Invalid(format!("bad rcode {rcode:?}")))?;

            Ok(DnsRewrite::RCode(rc))
        }
        _ => Err(ParseError::Invalid(format!("bad dnsrewrite {s:?}"))),
    }
}

/// The shortest literal run worth indexing as a prefilter shortcut.
pub const MIN_SHORTCUT_LEN: usize = 3;

/// Parses a rule's pattern, returning it and the domain to index it under.
///
/// `||domain^` takes a dedicated fast path; everything else compiles to the
/// regex upstream would have compiled, so the semantics match exactly.
fn parse_pattern(s: &str) -> Result<(Pattern, Option<String>), ParseError> {
    if pattern::matches_all(s) {
        return Ok((Pattern::Any, None));
    }

    if let Some(dom) = domain_anchor_of(s) {
        return Ok((Pattern::DomainAnchor, Some(dom)));
    }

    let src = pattern::to_regex(s);

    // A `/regex/` pattern is written by hand, so it is compiled here and a
    // malformed one is still rejected at load. Everything else is generated
    // by `to_regex` from a wildcard pattern -- `generated_patterns_compile`
    // covers that -- and compiling a few hundred thousand of those up front
    // is the single most expensive thing a large installation does at start.
    let lazy = if pattern::is_regex_pattern(s) {
        let re = Regex::new(&src)
            .map_err(|e| ParseError::Invalid(format!("pattern {s:?} -> {src:?}: {e}")))?;

        LazyRegex::compiled(src, re)
    } else {
        LazyRegex::new(src)
    };

    Ok((
        Pattern::Rx {
            re: Arc::new(lazy),
            target: pattern::target_for(s),
        },
        None,
    ))
}

/// Returns the domain of a `||domain^` pattern, if `s` is exactly that shape.
///
/// The trailing `^` is required: without it the pattern is a prefix match
/// (`||example.org` also matches `example.org.evil.com`), which a suffix walk
/// would get wrong.
fn domain_anchor_of(s: &str) -> Option<String> {
    let body = s.strip_prefix("||")?;
    let dom = body.strip_suffix('^')?;

    let ok = !dom.is_empty()
        && sift_core::name::is_valid(dom)
        && dom
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));

    ok.then(|| dom.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> NetworkRule {
        match parse(s, 1).unwrap() {
            Rule::Network(n) => n.rule,
            other => panic!("expected a network rule, got {other:?}"),
        }
    }

    /// The modifiers of a rule that is expected to carry some.
    fn opts(s: &str) -> Options {
        *net(s).opts.expect("rule should carry modifiers")
    }

    fn host(s: &str) -> HostRule {
        match parse(s, 1).unwrap() {
            Rule::Host(h) => h,
            other => panic!("expected a host rule, got {other:?}"),
        }
    }

    #[test]
    fn an_expression_is_not_built_until_something_needs_it() {
        // The regression this guards: every rule that is not `||domain^`
        // compiled its own automaton at load. On a real installation with
        // 2.27 million rules across 37 lists that was ~22s of the ~55s
        // startup and most of a gigabyte, for expressions that a query only
        // reaches once the index has already named the rule a candidate.
        let Ok(Rule::Network(n)) = parse("/ads/banner", 1) else {
            panic!("expected a network rule");
        };
        let PatternRef::Rx { re, .. } = n.rule.pattern() else {
            panic!("expected an expression pattern");
        };

        assert!(!re.is_built(), "the automaton was built at parse time");
        assert!(re.is_match("http://example.com/ads/banner.png"));
        assert!(re.is_built(), "the automaton should now be cached");
    }

    #[test]
    fn only_so_many_expressions_are_kept_built() {
        // Building every expression at load cost 22 seconds and most of a
        // gigabyte, which is why they are built on first use.  Keeping every
        // one that is built arrives at the same ceiling more slowly: on the
        // installation this came from, 156,557 rules need an expression and
        // one costs about 25 KB.
        let held: Vec<Arc<LazyRegex>> = (0..MAX_COMPILED + 64)
            .map(|i| Arc::new(LazyRegex::new(format!("(?i)ads{i}\\.example\\.com"))))
            .collect();

        for (i, re) in held.iter().enumerate() {
            assert!(re.is_match(&format!("ads{i}.example.com")), "rule {i}");
        }

        assert!(
            held.iter().filter(|r| r.is_built()).count() <= MAX_COMPILED,
            "more expressions are being held than the ceiling allows"
        );
        // The number a memory snapshot reports is the same one, counted from
        // the other side: what the process is holding rather than what this
        // test happens to be holding.  It is a global, so other tests
        // building expressions can only add to it -- the ceiling is what it
        // must respect either way.
        assert!(
            compiled_count() <= HARD_CEILING,
            "the reported count is past even the hard ceiling: {}",
            compiled_count()
        );
        assert!(
            compiled_count() >= held.iter().filter(|r| r.is_built()).count(),
            "the reported count misses expressions that are built"
        );
        assert!(
            !held[0].is_built(),
            "the oldest expression should have been dropped"
        );

        // Dropping one costs nothing but building it again when it is next
        // needed, and the verdict is the same either way.
        assert!(held[0].is_match("ads0.example.com"));
        assert!(!held[0].is_match("ads1.example.com"));
        assert!(held[0].is_built());
    }

    #[test]
    fn an_expression_still_being_used_is_not_the_one_dropped() {
        // Oldest-first alone would throw away an expression the network keeps
        // reaching, and pay 105 microseconds to build it again on the next
        // query that reaches it.
        let hot = Arc::new(LazyRegex::new(r"(?i)hot\.example\.com".to_string()));
        assert!(hot.is_match("hot.example.com"));

        for i in 0..MAX_COMPILED + 64 {
            let cold = Arc::new(LazyRegex::new(format!(r"(?i)cold{i}\.example\.com")));
            assert!(cold.is_match(&format!("cold{i}.example.com")));
            // Reaching it again is what earns it the second chance.
            assert!(hot.is_match("hot.example.com"));
        }

        assert!(
            hot.is_built(),
            "an expression in constant use should not have been dropped"
        );
    }

    #[test]
    fn a_handwritten_regex_is_still_rejected_at_load() {
        // Deferring compilation must not defer *validation* of the one form a
        // user writes by hand, or a typo in a custom rule would be accepted
        // and then silently never match.
        assert!(parse("/[unclosed/", 1).is_err());

        // A valid one is compiled there and then.
        let Ok(Rule::Network(n)) = parse("/^ads?\\./", 1) else {
            panic!("expected a network rule");
        };
        let PatternRef::Rx { re, .. } = n.rule.pattern() else {
            panic!("expected an expression pattern");
        };
        assert!(re.is_built(), "a handwritten regex compiles at load");
    }

    #[test]
    fn skips_comments_and_blanks() {
        for s in ["", "   ", "! comment", "# comment", "#"] {
            assert_eq!(parse(s, 1).unwrap_err(), ParseError::NotARule, "for {s:?}");
        }
    }

    #[test]
    fn skips_cosmetic_rules() {
        for s in [
            "example.org##.ad",
            "example.org#@#.ad",
            "example.org#%#//scriptlet()",
        ] {
            assert_eq!(parse(s, 1).unwrap_err(), ParseError::Cosmetic, "for {s:?}");
        }
    }

    #[test]
    fn parses_hosts_lines() {
        let h = host("0.0.0.0 ads.example.com");
        assert_eq!(h.ip, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(h.hostnames().collect::<Vec<_>>(), ["ads.example.com"]);
        assert!(h.is_blocking());

        // Multiple names and a trailing comment.
        let h = host("127.0.0.1 a.example.com b.example.com # local");
        assert_eq!(
            h.hostnames().collect::<Vec<_>>(),
            ["a.example.com", "b.example.com"]
        );

        // A non-unspecified address rewrites rather than blocks.
        let h = host("192.168.1.5 nas.lan");
        assert!(!h.is_blocking());

        // IPv6 hosts entries.  `::` is a null answer; `::1` is a rewrite to
        // loopback, so only the former counts as blocking.
        assert!(host(":: ads.example.com").is_blocking());
        assert!(!host("::1 localhost").is_blocking());
    }

    #[test]
    fn recognises_the_domain_anchor_fast_path() {
        for (rule, want) in [
            ("||example.org^", "example.org"),
            ("||sub.example.org^", "sub.example.org"),
            ("||a-b_c.example.org^", "a-b_c.example.org"),
        ] {
            let Rule::Network(n) = parse(rule, 1).unwrap() else {
                panic!("{rule} should be a network rule");
            };
            assert!(
                matches!(n.rule.pattern(), PatternRef::DomainAnchor),
                "{rule} should use the fast path"
            );
            // The domain becomes the index key.
            assert_eq!(n.shortcut.as_deref(), Some(want), "for {rule}");
        }
    }

    #[test]
    fn patterns_that_are_not_plain_domains_compile_to_a_regex() {
        for rule in [
            "||example.org/path",
            "||exa*ple.org^",
            "|http://example.org",
        ] {
            assert!(
                matches!(net(rule).pattern(), PatternRef::Rx { .. }),
                "{rule} should compile to a regex"
            );
        }
    }

    #[test]
    fn a_domain_anchor_without_a_separator_is_not_the_fast_path() {
        // `||example.org` is a prefix match, so it must not use the suffix walk.
        assert!(matches!(
            net("||example.org").pattern(),
            PatternRef::Rx { .. }
        ));
        assert!(matches!(
            net("||example.org^").pattern(),
            PatternRef::DomainAnchor
        ));
    }

    #[test]
    fn parses_allowlist_marker() {
        assert!(net("@@||example.org^").allowlist());
        assert!(!net("||example.org^").allowlist());
    }

    #[test]
    fn parses_modifiers() {
        assert!(net("||example.org^$important").important());
        assert!(net("||example.org^$badfilter").badfilter());

        let t = opts("||example.org^$dnstype=A|AAAA").dnstype.unwrap();
        assert_eq!(t.included, [1, 28]);

        assert_eq!(
            opts("||example.org^$dnstype=~TXT")
                .dnstype
                .unwrap()
                .excluded,
            [16]
        );

        let c = opts("||example.org^$client=192.168.1.1|~Laptop")
            .client
            .unwrap();
        assert_eq!(c.included, ["192.168.1.1"]);
        assert_eq!(c.excluded, ["Laptop"]);

        assert_eq!(
            opts("||example.org^$denyallow=good.example.org").denyallow,
            ["good.example.org"]
        );
        assert_eq!(
            opts("||example.org^$ctag=device_phone")
                .ctag
                .unwrap()
                .included,
            ["device_phone"]
        );

        // A rule with no modifiers must not allocate an options block at all.
        assert!(net("||example.org^").opts.is_none());
    }

    #[test]
    fn parses_dnsrewrite_forms() {
        let cases: [(&str, DnsRewrite); 5] = [
            (
                "||a^$dnsrewrite=1.2.3.4",
                DnsRewrite::Addr("1.2.3.4".parse().unwrap()),
            ),
            (
                "||a^$dnsrewrite=example.net",
                DnsRewrite::CName("example.net".into()),
            ),
            ("||a^$dnsrewrite=REFUSED", DnsRewrite::RCode(5)),
            ("||a^$dnsrewrite=NXDOMAIN", DnsRewrite::RCode(3)),
            (
                "||a^$dnsrewrite=NOERROR;A;5.6.7.8",
                DnsRewrite::Addr("5.6.7.8".parse().unwrap()),
            ),
        ];
        for (rule, want) in cases {
            assert_eq!(net(rule).dnsrewrite().cloned(), Some(want), "for {rule}");
        }
    }

    #[test]
    fn parses_regex_rules() {
        assert!(matches!(net("/^ads?\\./").pattern(), PatternRef::Rx { .. }));
        assert!(parse("/[unclosed/", 1).is_err());
    }

    #[test]
    fn rejects_unknown_modifiers() {
        assert!(matches!(
            parse("||example.org^$nosuchmodifier", 1),
            Err(ParseError::UnsupportedModifier(_))
        ));
    }

    #[test]
    fn ignores_http_only_modifiers() {
        // These are meaningless for DNS but must not invalidate the rule.
        for r in ["||example.org^$third-party", "||example.org^$document"] {
            assert!(parse(r, 1).is_ok(), "{r} should parse");
        }
    }

    #[test]
    fn str_list_matching() {
        let l = parse_str_list("a|b|~c");
        assert!(l.matches("a"));
        assert!(l.matches("B"));
        assert!(!l.matches("c"));
        assert!(!l.matches("d"));

        let only_neg = parse_str_list("~c");
        assert!(only_neg.matches("a"));
        assert!(!only_neg.matches("c"));
    }
}
