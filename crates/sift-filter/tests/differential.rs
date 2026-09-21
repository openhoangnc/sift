//! Differential test against the Go implementation.
//!
//! The fixtures are captured from a real AdGuard Home v0.107.79:
//!
//!   * `adguard-dns-filter.txt.gz` — the AdGuard DNS filter list it downloaded
//!     (179,334 rules);
//!   * `go-check-host.tsv` — what its `/control/filtering/check_host` endpoint
//!     answered for a 300-domain corpus.
//!
//! This engine must reach the same verdict, with the same winning rule, for
//! every domain in that corpus.

use std::io::Read;

use sift_filter::engine::{Engine, Request};

/// Decompresses the captured filter list.
fn filter_list() -> String {
    let gz = include_bytes!("../../../tests/fixtures/filters/adguard-dns-filter.txt.gz");
    let mut s = String::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_string(&mut s)
        .expect("fixture must decompress");

    s
}

/// The expectations captured from the Go implementation.
fn go_truth() -> Vec<(String, String, String)> {
    include_str!("../../../tests/fixtures/filters/go-check-host.tsv")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut it = l.split('\t');
            let dom = it.next().unwrap_or("").to_string();
            let reason = it.next().unwrap_or("").to_string();
            let rule = it.next().unwrap_or("").to_string();

            (dom, reason, rule)
        })
        .collect()
}

#[test]
fn the_same_rules_split_across_lists_answer_the_same_way() {
    // Rules are stored per list and referred to by a packed (list, position)
    // number, so the split is observable in the arithmetic that settles a
    // priority tie: the earlier list must win, exactly as the earlier line
    // does within one list. Splitting the real 179,334-rule filter into 64
    // lists and asking the same 4,190 domains is the test of that -- the
    // verdicts and the cited rules must not move.
    let list = filter_list();
    let one = Engine::build([(1i64, list.as_str())], sift_filter::engine::NO_LISTS);

    let lines: Vec<&str> = list.lines().collect();
    let per = lines.len().div_ceil(64);
    let chunks: Vec<(i64, String)> = lines
        .chunks(per)
        .enumerate()
        .map(|(i, c)| (i as i64 + 1, c.join("\n")))
        .collect();
    let many = Engine::build(chunks, sift_filter::engine::NO_LISTS);

    assert_eq!(one.len(), many.len(), "the same rules, differently grouped");

    for (dom, _, _) in go_truth() {
        let a = one.match_request(&Request {
            hostname: &dom,
            qtype: 1,
            ..Default::default()
        });
        let b = many.match_request(&Request {
            hostname: &dom,
            qtype: 1,
            ..Default::default()
        });

        assert_eq!(a.reason, b.reason, "{dom}");
        assert_eq!(
            a.rules.iter().map(|r| &r.text).collect::<Vec<_>>(),
            b.rules.iter().map(|r| &r.text).collect::<Vec<_>>(),
            "{dom}: cited rules differ"
        );
    }
}

#[test]
fn matches_the_go_engine_on_the_real_adguard_dns_filter() {
    let list = filter_list();
    let engine = Engine::build([(1i64, list.as_str())], sift_filter::engine::NO_LISTS);

    assert!(
        engine.block.len() > 150_000,
        "expected the full list to load, got {} rules",
        engine.block.len()
    );

    let truth = go_truth();
    assert!(
        truth.len() > 4_000,
        "the corpus should hold thousands of domains, got {}",
        truth.len()
    );

    // Two different things are worth measuring separately.
    //
    //   * The *verdict* — blocked, allowed or not filtered.  This is what the
    //     client actually observes, and it must match exactly.
    //   * The *cited rule* — which of the matching rules gets reported.  When
    //     several rules of equal priority match, upstream's choice falls out
    //     of its shortcut index's bucket-balancing and the order it happens to
    //     walk the URL; it is arbitrary, not semantic.  This engine uses the
    //     fast suffix-walk index instead and resolves such ties by load order,
    //     so it may legitimately cite a different, equally valid rule.
    let mut verdict_mismatches: Vec<String> = Vec::new();
    let mut rule_mismatches: Vec<String> = Vec::new();
    let mut compared = 0usize;

    for (dom, want_reason, want_rule) in &truth {
        // `RewriteEtcHosts` comes from the OS hosts file, which this engine is
        // not given here.
        if want_reason == "RewriteEtcHosts" {
            continue;
        }
        compared += 1;

        let res = engine.match_request(&Request {
            hostname: dom,
            qtype: 1,
            ..Default::default()
        });

        let got_reason = res.reason.as_str();
        let got_rule = res.rules.first().map(|r| r.text.as_str()).unwrap_or("");

        if got_reason != want_reason {
            verdict_mismatches.push(format!("{dom}: go={want_reason:?} rust={got_reason:?}"));
        } else if got_rule != want_rule {
            rule_mismatches.push(format!("{dom}: go={want_rule:?} rust={got_rule:?}"));
        }
    }

    assert!(
        verdict_mismatches.is_empty(),
        "{} of {compared} verdicts disagree with the Go engine:\n{}",
        verdict_mismatches.len(),
        verdict_mismatches.join("\n")
    );

    // Ties are permitted, but a regression that scrambles rule selection
    // wholesale should still fail the build.
    let agreement = (compared - rule_mismatches.len()) as f64 / compared as f64;
    assert!(
        agreement >= 0.99,
        "only {:.2}% of cited rules match ({} ties out of {compared}):\n{}",
        agreement * 100.0,
        rule_mismatches.len(),
        rule_mismatches
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );

    eprintln!(
        "verdicts: {compared}/{compared} exact; cited rules: {:.2}% exact ({} arbitrary ties)",
        agreement * 100.0,
        rule_mismatches.len()
    );
}

#[test]
fn loads_the_real_list_quickly_enough_to_be_practical() {
    let list = filter_list();
    let start = std::time::Instant::now();
    let engine = Engine::build([(1i64, list.as_str())], sift_filter::engine::NO_LISTS);
    let elapsed = start.elapsed();

    // Generous bound: this is a correctness guard against an accidental
    // quadratic index build, not a benchmark.
    assert!(
        elapsed.as_secs() < 30,
        "building the index took {elapsed:?} for {} rules",
        engine.block.len()
    );
}

#[test]
fn rules_needing_an_expression_load_as_cheaply_as_plain_ones() {
    // The real list is almost entirely `||domain^`, which never needed an
    // expression, so it never showed what those cost. A deployment with 37
    // lists had 156,557 rules that did, and compiling them at load was
    // ~22 seconds of a ~55 second startup.
    //
    // Wildcards force the expression path.  Measured as a ratio against the
    // same number of plain rules rather than against a wall clock: both halves
    // run on whatever machine this is, at whatever load it is under, so the
    // ratio holds where an absolute budget does not.  A three-second bound
    // used to live here and failed spuriously when the suite ran beside a
    // release build.
    const N: usize = 60_000;

    let plain: String = (0..N).map(|i| format!("||ads{i}.example.com^\n")).collect();
    let with_expressions: String = (0..N)
        .map(|i| format!("||ads{i}.example.com^*track\n"))
        .collect();

    let build = |list: &str| {
        let start = std::time::Instant::now();
        let engine = Engine::build([(1i64, list)], sift_filter::engine::NO_LISTS);

        (engine, start.elapsed())
    };

    let (plain_engine, plain_time) = build(&plain);
    let (engine, elapsed) = build(&with_expressions);

    assert_eq!(
        plain_engine.block.len(),
        N,
        "the baseline should have loaded"
    );
    assert_eq!(engine.block.len(), N, "every rule should have loaded");

    // Eagerly compiling this many cost about seven seconds against
    // hundredths for the plain ones -- two orders of magnitude.  Lazily it is
    // within a small factor, so ten separates them without being delicate.
    let ratio = elapsed.as_secs_f64() / plain_time.as_secs_f64().max(1e-6);
    assert!(
        ratio < 10.0,
        "{N} expression rules took {elapsed:?} against {plain_time:?} for the \
         same number of plain ones ({ratio:.1}x); they are being compiled at \
         load rather than on first use"
    );
}
