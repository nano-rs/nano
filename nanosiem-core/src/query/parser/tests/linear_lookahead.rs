// SPDX-License-Identifier: AGPL-3.0-or-later

//! Security review 2026-11-08 (NAN-5024): keyword lookaheads used to case-fold
//! the WHOLE remaining query once per term (implicit-AND separator, the
//! `prevalence` condition loop, the `sort` field loop), making parse time
//! quadratic in query length. Each shape below is ~256 KiB (the `/api/search`
//! body cap); before the fix each took tens of seconds to minutes, now each is
//! a linear scan. The bound is deliberately loose (debug build, shared CI host);
//! the old cost was orders of magnitude above it.

use crate::query::parse_query;
use std::time::{Duration, Instant};

const SIZE: usize = 256 * 1024;
const BOUND: Duration = Duration::from_secs(10);

fn assert_fast(name: &str, query: &str) {
    let started = Instant::now();
    let _ = parse_query(query); // accepted or rejected; only the cost matters
    let took = started.elapsed();
    assert!(took < BOUND, "{name}: parsing {} bytes took {took:?}", query.len());
}

#[test]
fn implicit_and_chain_parses_in_linear_time() {
    assert_fast("implicit AND", &"a ".repeat(SIZE / 2));
}

#[test]
fn sort_field_list_parses_in_linear_time() {
    let fields = "f ".repeat(SIZE / 2);
    assert_fast("sort fields", &format!("* | sort {fields}"));
}

#[test]
fn prevalence_condition_list_parses_in_linear_time() {
    let conds = "hash_prevalence <= 5 ".repeat(SIZE / 21);
    assert_fast("prevalence conditions", &format!("* | prevalence {conds}"));
}

/// Legitimate path: the case-insensitive keywords still behave exactly as
/// before at every position the lookahead guards.
#[test]
fn keyword_lookaheads_are_unchanged() {
    // `OR` after whitespace still ends the implicit-AND chain (any case).
    for q in ["a b OR c", "a b or c", "a b Or c"] {
        let parsed = format!("{:?}", parse_query(q).unwrap());
        assert!(parsed.contains("Or("), "{q}: {parsed}");
    }
    // A word merely starting with "or" is still an implicit-AND term.
    let parsed = format!("{:?}", parse_query("a orange").unwrap());
    assert!(!parsed.contains("Or("), "{parsed}");
    // `limit=` still ends a sort field list, any case.
    assert_eq!(
        format!("{:?}", parse_query("* | sort a LIMIT=5").unwrap()),
        format!("{:?}", parse_query("* | sort a limit=5").unwrap()),
    );
    // `window=` still ends a prevalence condition list, any case.
    assert_eq!(
        format!("{:?}", parse_query("* | prevalence hash_prevalence <= 5 WINDOW=7d").unwrap()),
        format!("{:?}", parse_query("* | prevalence hash_prevalence <= 5 window=7d").unwrap()),
    );
}
