//! TEMPORARY: times the shortcut index alone on the real lists.

use std::collections::HashMap;
use std::time::Instant;

use sift_filter::rule::{MIN_SHORTCUT_LEN, PatternRef, Rule, parse};
use sift_filter::shortcut::ShortcutIndex;

fn main() {
    let dir = std::env::args().nth(1).expect("dir");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "txt"))
        .collect();
    files.sort();

    let mut shortcuts: HashMap<String, Vec<u32>> = HashMap::new();
    let mut idx = 0u32;
    for (i, p) in files.iter().enumerate() {
        let s = std::fs::read_to_string(p).unwrap_or_default();
        for line in s.lines() {
            if let Ok(Rule::Network(n)) = parse(line, i as i64 + 1) {
                if let (PatternRef::Rx { .. }, Some(sc)) = (n.rule.pattern(), &n.shortcut)
                    && sc.len() >= MIN_SHORTCUT_LEN
                {
                    shortcuts.entry(sc.clone()).or_default().push(idx);
                }
                idx += 1;
            }
        }
    }
    let pats: Vec<(String, Vec<u32>)> = shortcuts.into_iter().collect();

    let long_only: Vec<(String, Vec<u32>)> =
        pats.iter().filter(|(t, _)| t.len() >= 8).cloned().collect();
    let short_only: Vec<(String, Vec<u32>)> =
        pats.iter().filter(|(t, _)| t.len() < 8).cloned().collect();
    for (label, set) in [
        ("all", pats),
        ("long only", long_only),
        ("short only", short_only),
    ] {
        println!("== {label}");
        bench(set);
    }
}

fn bench(pats: Vec<(String, Vec<u32>)>) {
    let brute: Vec<(String, Vec<u32>)> = pats.clone();

    let t = Instant::now();
    let index = ShortcutIndex::build(pats);
    println!(
        "build {:.3}s, {} patterns, {:.1} MB",
        t.elapsed().as_secs_f64(),
        index.len(),
        index.footprint() as f64 / 1e6
    );

    let reps = 200_000u32;
    for host in [
        "doubleclick.net",
        "ads.serving.doubleclick.net",
        "github.com",
        "some-very-long-name-that-matches-nothing.example.org",
        "www.google.com",
        "static.cloudflareinsights.com",
    ] {
        let mut got = Vec::new();
        index.find(host.as_bytes(), |r| got.push(r));
        let mut want: Vec<u32> = brute
            .iter()
            .filter(|(t, _)| host.contains(t.as_str()) || "http".contains(t.as_str()))
            .flat_map(|(_, r)| r.iter().copied())
            .collect();
        want.sort_unstable();
        let mut g = got.clone();
        g.sort_unstable();

        let t = Instant::now();
        let mut n = 0usize;
        for _ in 0..reps {
            index.find(host.as_bytes(), |r| n += r as usize);
        }
        let el = t.elapsed();
        std::hint::black_box(n);
        let (llines, slines, lreads, sreads, shits) = index.debug_stats(host.as_bytes());
        println!(
            "  {host:<55} {:>6.0} ns  reports {:?}  {}  [long {llines} lines, short {slines} lines; long lines read {lreads}, short lines read {sreads}, short key hits {shits}]",
            el.as_nanos() as f64 / f64::from(reps),
            got,
            if g == want {
                "== brute force"
            } else {
                "MISMATCH vs brute force"
            }
        );
    }
}
