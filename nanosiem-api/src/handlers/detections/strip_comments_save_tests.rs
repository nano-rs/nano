// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4902 lane I (codex P2): detection create/update, test/validate and
//! tuning proposals all clean the query through `detections::strip_comments`,
//! which now applies the parser's boundary rule — so a query that runs in
//! Search is saved unchanged.
use super::strip_comments;

#[test]
fn bare_url_rule_survives_save() {
    let q = "url=http://evil.example/payload | stats count";
    assert_eq!(strip_comments(q), q);
    // The saved text parses to the same query as the original.
    assert_eq!(
        nanosiem_core::query::parse_query(&strip_comments(q)).unwrap(),
        nanosiem_core::query::parse_query(q).unwrap()
    );
}

#[test]
fn regex_and_single_quoted_values_survive_save() {
    let q = "path=/a\\// url='http://x // y' | head 1";
    assert_eq!(strip_comments(q), q);
    assert_eq!(strip_comments("error // why\n| head 1"), "error\n| head 1");
}
