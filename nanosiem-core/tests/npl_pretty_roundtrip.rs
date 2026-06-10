// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-1342: nPL pretty-print → re-parse round-trip.
//!
//! `enforce_non_audit_query` parses every search, injects the `source_type != "audit"`
//! filter into the AST, then `pretty_print()`s it back to a string that is re-parsed
//! downstream. Several command formatters emitted nPL their own parser rejected
//! (`transaction startswith=…`, bracket `funnel`, `anomaly count()`, positional `tree`),
//! 400-ing the whole query for every user. Each case below asserts that
//! parse → pretty_print → parse yields an identical AST.

use nanosiem_core::query::{parse_query, PrettyPrint};

fn assert_roundtrips(npl: &str) {
    let ast1 = parse_query(npl).unwrap_or_else(|e| panic!("initial parse failed for `{npl}`: {e}"));
    let printed = ast1.pretty_print();
    let ast2 = parse_query(&printed)
        .unwrap_or_else(|e| panic!("re-parse of pretty_print `{printed}` failed (NAN-1342): {e}"));
    assert_eq!(
        ast1, ast2,
        "round-trip changed the AST:\n  in:  {npl}\n  out: {printed}"
    );
}

#[test]
fn transaction_startswith_endswith_roundtrips() {
    assert_roundtrips(
        r#"* | transaction session_id startswith="login" endswith="logout" maxspan=8h"#,
    );
}

#[test]
fn funnel_bracket_steps_roundtrips() {
    assert_roundtrips(r#"* | funnel by user maxspan=1h [action="login"] [action="search"]"#);
}

#[test]
fn anomaly_aggregation_field_roundtrips() {
    assert_roundtrips("* | anomaly count() by src_ip span=1h");
    assert_roundtrips("* | anomaly threat_score by src_ip");
}

#[test]
fn tree_positional_roundtrips() {
    assert_roundtrips("* | tree process_name by src_host");
    assert_roundtrips("* | tree process_name");
}
