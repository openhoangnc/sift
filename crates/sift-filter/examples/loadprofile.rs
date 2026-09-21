//! Profiles an engine build over real lists: where the time and the memory go.
//!
//! Usage: cargo run --release -p sift-filter --example loadprofile -- <dir of .txt>

use std::time::Instant;

use sift_filter::engine::Engine;
use sift_filter::rule::{MIN_SHORTCUT_LEN, PatternRef, Rule, parse};

/// Resident set size in MB.
fn rss_mb() -> f64 {
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for l in s.lines() {
            if let Some(v) = l.strip_prefix("VmRSS:")
                && let Some(kb) = v
                    .split_whitespace()
                    .next()
                    .and_then(|k| k.parse::<f64>().ok())
            {
                return kb / 1024.0;
            }
        }
    }

    std::process::Command::new("ps")
        .args(["-o", "rss=", "-p"])
        .arg(std::process::id().to_string())
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<f64>().ok())
        .map(|kb| kb / 1024.0)
        .unwrap_or(0.0)
}

fn main() {
    let dir = std::env::args().nth(1).expect("a directory of .txt lists");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("reading the directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "txt"))
        .collect();
    files.sort();

    println!("baseline rss {:.0} MB", rss_mb());

    let t = Instant::now();
    let mut texts = Vec::new();
    let mut bytes = 0usize;
    for (i, p) in files.iter().enumerate() {
        let s = std::fs::read_to_string(p).unwrap_or_default();
        bytes += s.len();
        texts.push((i as i64 + 1, s));
    }
    println!(
        "read   {:>7.2}s  {} files, {:.1} MB, rss {:.0} MB",
        t.elapsed().as_secs_f64(),
        texts.len(),
        bytes as f64 / 1e6,
        rss_mb()
    );

    // Parsing on its own, so indexing can be told apart from it.
    let t = Instant::now();
    let (mut net, mut hosts) = (0usize, 0usize);
    let (mut anchors, mut shortcuts, mut scans) = (0usize, 0usize, 0usize);
    for (id, text) in &texts {
        for line in text.lines() {
            match parse(line, *id) {
                Ok(Rule::Network(n)) => {
                    net += 1;
                    match (n.rule.pattern(), &n.shortcut) {
                        (PatternRef::DomainAnchor, Some(_)) => anchors += 1,
                        (PatternRef::Rx { .. }, Some(sc)) if sc.len() >= MIN_SHORTCUT_LEN => {
                            shortcuts += 1;
                        }
                        _ => scans += 1,
                    }
                }
                Ok(Rule::Host(_)) => hosts += 1,
                Err(_) => {}
            }
        }
    }
    println!(
        "parse  {:>7.2}s  {net} network + {hosts} hosts, rss {:.0} MB",
        t.elapsed().as_secs_f64(),
        rss_mb()
    );
    println!("         {anchors} domain-anchored, {shortcuts} shortcut/AC, {scans} full-scan");

    let t = Instant::now();
    let engine = Engine::build(
        texts
            .iter()
            .map(|(id, s)| (*id, std::sync::Arc::<str>::from(s.as_str()))),
        sift_filter::engine::NO_LISTS,
    );
    println!(
        "build  {:>7.2}s  {} rules, rss {:.0} MB",
        t.elapsed().as_secs_f64(),
        engine.len(),
        rss_mb()
    );

    println!();
    print!("{}", engine.block.footprint());

    // Per query shape, because they take different paths: a blocked name
    // stops at the domain index, a clean one pays for the full Aho-Corasick
    // scan and the whole suffix walk before concluding nothing matched.
    let reps: usize = std::env::var("REPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000);

    println!("\nmatch, {reps} iterations each");
    for (label, name) in [
        ("blocked (index hit)", "doubleclick.net"),
        ("blocked (deep sub)", "ads.serving.doubleclick.net"),
        ("clean, short", "github.com"),
        (
            "clean, long",
            "some-very-long-name-that-matches-nothing.example.org",
        ),
    ] {
        let req = sift_filter::engine::Request {
            hostname: name,
            qtype: 1,
            client_ip: None,
            client_name: None,
            client_tags: &[],
        };
        // Warm the lazily-built automata first, so this times matching.
        let warm = engine.match_request(&req);
        let t = Instant::now();
        let mut n = 0usize;
        for _ in 0..reps {
            if engine.match_request(&req).matched() {
                n += 1;
            }
        }
        let el = t.elapsed();
        println!(
            "  {label:<22} {:>7.0} ns   {}",
            el.as_nanos() as f64 / reps as f64,
            if warm.matched() {
                "matched"
            } else {
                "no match"
            }
        );
        std::hint::black_box(n);
    }
    println!("rss after matching {:.0} MB", rss_mb());

    std::hint::black_box(&engine);
}
