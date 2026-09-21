//! Guards on the in-memory footprint of the rule types.
//!
//! A real installation holds a couple of million network rules, so these
//! structs are multiplied by that -- and a rebuild holds two sets of them at
//! once, which is what makes the refresh peak what it is. When `NetworkRule`
//! carried its `Options` inline it was 296 bytes and the engine used more
//! memory than the Go implementation it replaces; boxing the modifiers and
//! dropping the build-only fields brought it to 56, then to 40, and packing
//! the pattern behind one byte of flags and moving the list identifier to the
//! source it belongs to brought it to 24.  These assertions exist so that
//! regresses loudly rather than quietly.

use std::mem::size_of;

use sift_filter::rule::{HostRule, NetworkRule, Options};

#[test]
fn a_network_rule_stays_small() {
    assert!(
        size_of::<NetworkRule>() <= 24,
        "NetworkRule grew to {} bytes; at 2.2M rules that is ~{} MB, twice \
         that while a rebuild holds two engines",
        size_of::<NetworkRule>(),
        size_of::<NetworkRule>() * 2_200_000 / 1_048_576
    );
}

#[test]
fn the_pattern_costs_the_rule_one_byte() {
    // `Pattern` is the shape the parser hands over; the rule stores it as a
    // pointer that is `None` for the two payloadless kinds plus three bits of
    // flags, so a rule is the pointer, the modifiers and that byte.
    assert!(
        size_of::<NetworkRule>()
            <= size_of::<Option<std::sync::Arc<()>>>() + size_of::<Option<Box<Options>>>() + 8,
        "the rule grew past a pointer, a pointer and a byte: {} bytes",
        size_of::<NetworkRule>()
    );
}

#[test]
fn modifiers_are_not_stored_inline() {
    // Options is large, which is exactly why it must live behind a pointer.
    assert!(
        size_of::<Options>() > size_of::<NetworkRule>(),
        "this test is only meaningful while Options is the larger type"
    );
    assert!(
        size_of::<Option<Box<Options>>>() == 8,
        "the modifiers must cost one pointer when absent"
    );
}

#[test]
fn a_rule_without_modifiers_allocates_no_options() {
    let Ok(sift_filter::rule::Rule::Network(n)) = sift_filter::rule::parse("||ads.example.com^", 1)
    else {
        panic!("expected a network rule");
    };

    assert!(
        n.rule.opts.is_none(),
        "a plain rule must carry no options block"
    );
}

#[test]
fn a_host_rule_stays_small() {
    // A hosts-format list is 147,175 rules on a real installation, and each
    // one used to carry its names twice: once in the text and once in a
    // `Vec<String>` beside it. They are read back out of the text now, so
    // what is left is a boxed line, an address and a list identifier.
    assert!(
        size_of::<HostRule>() <= 48,
        "HostRule grew to {} bytes; at 147,175 rules that is ~{} MB",
        size_of::<HostRule>(),
        size_of::<HostRule>() * 147_175 / 1_048_576
    );
}
