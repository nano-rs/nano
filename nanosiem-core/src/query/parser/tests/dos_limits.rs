// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2010: malformed-input DoS hardening for the nPL parser / codegen.
//!
//! Cluster D — deep left-nested ASTs (long boolean/eval chains, deeply nested
//! `IN [...]` subsearches) must be REJECTED at parse time rather than building a
//! structure that a later recursive walk (eval/where evaluation, `PrettyPrint`,
//! the audit source-scope gate, command extraction) stack-overflows on. A Rust
//! stack overflow aborts the whole process (uncatchable), so each test simply
//! running to completion (returning `Err`, not aborting) is the proof.
//!
//! Cluster F — a zero `hop`/`span` must return a clean error, not divide-by-zero.

use crate::query::parse_query;

#[test]
fn deep_implicit_and_chain_is_rejected_not_overflowed() {
    // `a a a … a` — thousands of implicit-AND terms (well over MAX_CHAIN_LEN).
    let q = "a ".repeat(5000);
    assert!(
        parse_query(&q).is_err(),
        "an over-long implicit-AND chain must be rejected"
    );
}

#[test]
fn deep_or_chain_is_rejected_not_overflowed() {
    let q = vec!["a"; 5000].join(" OR ");
    assert!(parse_query(&q).is_err(), "an over-long OR chain must be rejected");
}

#[test]
fn deep_eval_arithmetic_chain_is_rejected_not_overflowed() {
    let chain = vec!["1"; 5000].join("+");
    let q = format!("* | eval x = {chain}");
    assert!(
        parse_query(&q).is_err(),
        "an over-long eval operator chain must be rejected"
    );
}

#[test]
fn deeply_nested_in_subsearch_is_rejected_not_overflowed() {
    // `a IN [ a IN [ … x … ] ]` — nesting far past MAX_NESTING_DEPTH. Before the
    // fix, `in_subsearch_filter` recursed without incrementing the nesting guard.
    let depth = 500;
    let mut q = String::new();
    for _ in 0..depth {
        q.push_str("a IN [ ");
    }
    q.push('x');
    for _ in 0..depth {
        q.push_str(" ]");
    }
    assert!(
        parse_query(&q).is_err(),
        "deeply nested IN[] subsearches must be rejected"
    );
}

#[test]
fn moderate_chains_and_nesting_still_parse() {
    // Comfortably under the bounds — must NOT be false-rejected.
    assert!(parse_query(&vec!["a"; 200].join(" OR ")).is_ok());
    assert!(parse_query(&vec!["a"; 200].join(" ")).is_ok());
    assert!(parse_query("* | eval x = 1+2+3+4+5+6+7+8+9+10").is_ok());
    assert!(parse_query("a IN [ b IN [ c ] ]").is_ok());
}

#[test]
fn bin_hop_zero_is_rejected_not_panicked() {
    use crate::query::clickhouse_sql_gen::ClickHouseSqlGenerator;
    use crate::query::sql_gen::TimeRange;
    use chrono::{TimeZone, Utc};

    let q = parse_query("error | bin span=1h hop=0s").expect("bin hop=0s parses");
    let tr = TimeRange {
        start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
    };
    assert!(
        ClickHouseSqlGenerator::new().generate(&q, &tr).is_err(),
        "bin hop=0 must return a clean error, not a divide-by-zero panic"
    );
}
