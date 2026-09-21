//! What `$dnsrewrite` exceptions do, captured from a running AdGuard Home.
//!
//! Every expectation here was taken from **v0.107.79 itself** — the published
//! image, user rules set through `/control/filtering/set_rules`, then
//! `/control/filtering/check_host?name=a.example` and a real query — and not
//! read off its source. The engine had it wrong in two ways that reading the
//! source would not obviously have caught, so the captured answers are the
//! test:
//!
//!   * an `@@…$dnsrewrite` rule is an **exception** that removes matching
//!     rewrites. This build applied it as a rewrite of its own, so
//!     `@@||a.example^$dnsrewrite=1.2.3.4` *sent* the client to 1.2.3.4 —
//!     the opposite of what the user wrote it for;
//!   * `$dnsrewrite` with no value, and `$dnsrewrite=NOERROR`, are rewrites
//!     that answer NOERROR with no records. This build treated them as
//!     cancelling every other rewrite, which no upstream rule does.
//!
//! The DNS answers these produce are pinned in `sift-dns`'s resolver tests;
//! what is pinned here is the verdict and which rules survive to make it.

use sift_core::Reason;
use sift_filter::engine::{Engine, MatchResult, Request};
use sift_filter::rule::DnsRewrite;

/// The engine one list of user rules builds.
fn engine(rules: &[&str]) -> Engine {
    Engine::build([(1i64, rules.join("\n"))], sift_filter::engine::NO_LISTS)
}

/// What `a.example` matches, as `check_host` would ask it.
fn check(rules: &[&str]) -> MatchResult {
    engine(rules).match_request(&Request {
        hostname: "a.example",
        qtype: 1,
        ..Default::default()
    })
}

/// The texts of the rules the match reports, in order.
fn cited(m: &MatchResult) -> Vec<&str> {
    m.rules.iter().map(|r| r.text.as_str()).collect()
}

#[test]
fn an_exception_with_no_value_removes_every_rewrite() {
    // go: reason=NotFilteredNotFound rules=[]  dns=NXDOMAIN
    let m = check(&[
        "||a.example^$dnsrewrite=1.2.3.4",
        "@@||a.example^$dnsrewrite",
    ]);

    assert_eq!(m.reason, Reason::NotFilteredNotFound);
    assert!(m.rules.is_empty(), "{:?}", cited(&m));
    assert!(m.rewrites.is_empty());
}

#[test]
fn an_exception_naming_the_same_value_removes_it() {
    // go: reason=NotFilteredNotFound rules=[]  dns=NXDOMAIN
    let m = check(&[
        "||a.example^$dnsrewrite=1.2.3.4",
        "@@||a.example^$dnsrewrite=1.2.3.4",
    ]);

    assert_eq!(m.reason, Reason::NotFilteredNotFound);
    assert!(m.rules.is_empty(), "{:?}", cited(&m));
}

#[test]
fn an_exception_naming_a_value_leaves_the_others() {
    // go: reason=RewriteRule rules=['||a.example^$dnsrewrite=5.6.7.8']
    //     dns=NOERROR A 5.6.7.8
    let m = check(&[
        "||a.example^$dnsrewrite=1.2.3.4",
        "||a.example^$dnsrewrite=5.6.7.8",
        "@@||a.example^$dnsrewrite=1.2.3.4",
    ]);

    assert_eq!(m.reason, Reason::RewrittenRule);
    assert_eq!(cited(&m), ["||a.example^$dnsrewrite=5.6.7.8"]);
    assert_eq!(
        m.rewrites,
        vec![DnsRewrite::Addr("5.6.7.8".parse().unwrap())]
    );
}

#[test]
fn an_ordinary_exception_leaves_an_important_rewrite() {
    // go: reason=RewriteRule rules=['||a.example^$dnsrewrite=1.2.3.4,important']
    //     dns=NOERROR A 1.2.3.4 -- for the empty-value exception and for one
    //     naming the same value.
    for exception in [
        "@@||a.example^$dnsrewrite",
        "@@||a.example^$dnsrewrite=1.2.3.4",
    ] {
        let m = check(&["||a.example^$dnsrewrite=1.2.3.4,important", exception]);

        assert_eq!(m.reason, Reason::RewrittenRule, "{exception}");
        assert_eq!(
            cited(&m),
            ["||a.example^$dnsrewrite=1.2.3.4,important"],
            "{exception}"
        );
    }
}

#[test]
fn an_important_exception_takes_an_important_rewrite_too() {
    // go: reason=NotFilteredNotFound rules=[]  dns=NXDOMAIN -- with no value
    //     and with the value named.
    for exception in [
        "@@||a.example^$dnsrewrite,important",
        "@@||a.example^$dnsrewrite=1.2.3.4,important",
    ] {
        let m = check(&["||a.example^$dnsrewrite=1.2.3.4,important", exception]);

        assert_eq!(m.reason, Reason::NotFilteredNotFound, "{exception}");
        assert!(m.rules.is_empty(), "{exception}: {:?}", cited(&m));
    }
}

#[test]
fn an_exception_is_never_a_rewrite_of_its_own() {
    // go: reason=NotFilteredNotFound rules=[]  dns=NXDOMAIN. This build used
    // to answer 1.2.3.4 here, sending the client exactly where the rule said
    // not to.
    let m = check(&["@@||a.example^$dnsrewrite=1.2.3.4"]);

    assert_eq!(m.reason, Reason::NotFilteredNotFound);
    assert!(m.rules.is_empty(), "{:?}", cited(&m));
}

#[test]
fn an_exception_with_no_value_matches_a_rewrite_of_any_value() {
    // `=NOERROR` parses to the same thing as no value at all, so it removes
    // an address rewrite rather than only the rewrites that answer NOERROR.
    // go: reason=NotFilteredNotFound rules=[]  dns=NXDOMAIN
    let m = check(&[
        "||a.example^$dnsrewrite=1.2.3.4",
        "@@||a.example^$dnsrewrite=NOERROR",
    ]);

    assert_eq!(m.reason, Reason::NotFilteredNotFound);
    assert!(m.rules.is_empty(), "{:?}", cited(&m));
}

#[test]
fn an_exception_matches_the_parsed_value_not_the_text() {
    // `=1.2.3.4` and `=NOERROR;A;1.2.3.4` are the same rewrite written two
    // ways, and the exception removes it.
    // go: reason=NotFilteredNotFound rules=[]  dns=NXDOMAIN
    let m = check(&[
        "||a.example^$dnsrewrite=NOERROR;A;1.2.3.4",
        "@@||a.example^$dnsrewrite=1.2.3.4",
    ]);

    assert_eq!(m.reason, Reason::NotFilteredNotFound);
    assert!(m.rules.is_empty(), "{:?}", cited(&m));
}

#[test]
fn an_exception_removes_a_cname_rewrite_by_value() {
    // go: reason=NotFilteredNotFound rules=[]  dns=NXDOMAIN
    let m = check(&[
        "||a.example^$dnsrewrite=b.example",
        "@@||a.example^$dnsrewrite=b.example",
    ]);

    assert_eq!(m.reason, Reason::NotFilteredNotFound);
    assert!(m.rules.is_empty(), "{:?}", cited(&m));
}

#[test]
fn an_exception_only_has_to_match_the_host() {
    // A broader pattern excepts a narrower rewrite; a different host does
    // not. go: NotFilteredNotFound for `@@||example^`, RewriteRule for
    // `@@||other.example^`.
    let broader = check(&["||a.example^$dnsrewrite=1.2.3.4", "@@||example^$dnsrewrite"]);
    assert_eq!(broader.reason, Reason::NotFilteredNotFound);

    let elsewhere = check(&[
        "||a.example^$dnsrewrite=1.2.3.4",
        "@@||other.example^$dnsrewrite",
    ]);
    assert_eq!(elsewhere.reason, Reason::RewrittenRule);
    assert_eq!(cited(&elsewhere), ["||a.example^$dnsrewrite=1.2.3.4"]);
}

#[test]
fn a_plain_allowlist_rule_does_not_stop_a_rewrite() {
    // Only a `$dnsrewrite` exception excepts a rewrite: a bare `@@||a.example^`
    // leaves it alone, because the rewrite is applied before the winning
    // basic rule is even considered.
    // go: reason=RewriteRule rules=['||a.example^$dnsrewrite=1.2.3.4']
    //     dns=NOERROR A 1.2.3.4
    let m = check(&["||a.example^$dnsrewrite=1.2.3.4", "@@||a.example^"]);

    assert_eq!(m.reason, Reason::RewrittenRule);
    assert_eq!(cited(&m), ["||a.example^$dnsrewrite=1.2.3.4"]);
}

#[test]
fn a_rewrite_of_the_host_to_itself_is_dropped() {
    // Upstream's `processDNSResultRewrites` drops `res.CanonName == host`, so
    // the name resolves normally instead.
    // go: reason=NotFilteredNotFound rules=[]  dns=NXDOMAIN
    let m = check(&["||a.example^$dnsrewrite=a.example"]);

    assert_eq!(m.reason, Reason::NotFilteredNotFound);
    assert!(m.rules.is_empty(), "{:?}", cited(&m));

    // A CNAME to anywhere else is still a rewrite.
    // go: reason=RewriteRule rules=['||a.example^$dnsrewrite=b.example']
    let other = check(&["||a.example^$dnsrewrite=b.example"]);
    assert_eq!(other.reason, Reason::RewrittenRule);
    assert_eq!(
        other.rewrites,
        vec![DnsRewrite::CName("b.example".to_string())]
    );
}

#[test]
fn a_rewrite_with_no_value_is_a_rewrite() {
    // `$dnsrewrite`, `$dnsrewrite=` and `$dnsrewrite=NOERROR` all report a
    // rewrite and answer NOERROR with nothing in it. This build used to treat
    // them as cancelling every rewrite for the host.
    // go: reason=RewriteRule, dns=NOERROR with an empty answer section.
    for rule in [
        "||a.example^$dnsrewrite",
        "||a.example^$dnsrewrite=",
        "||a.example^$dnsrewrite=NOERROR",
    ] {
        let m = check(&[rule]);

        assert_eq!(m.reason, Reason::RewrittenRule, "{rule}");
        assert_eq!(cited(&m), [rule], "{rule}");
        assert_eq!(m.rewrites, vec![DnsRewrite::RCode(0)], "{rule}");
    }
}

#[test]
fn a_noerror_rewrite_does_not_cancel_an_address_beside_it() {
    // go: reason=RewriteRule, both rules cited, dns=NOERROR A 1.2.3.4.
    let m = check(&[
        "||a.example^$dnsrewrite=1.2.3.4",
        "||a.example^$dnsrewrite=NOERROR",
    ]);

    assert_eq!(m.reason, Reason::RewrittenRule);
    assert_eq!(
        cited(&m),
        [
            "||a.example^$dnsrewrite=1.2.3.4",
            "||a.example^$dnsrewrite=NOERROR"
        ]
    );
}
