// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5021: command values the pretty-printer used to wrap in raw `"…"`
//! round-trip faithfully. A value carrying `"` used to re-serialize as a
//! broken literal, the source-scope gate's re-parse failed, and the cloud
//! endpoints ran the client's text unscoped.

use crate::query::{parse_query, PrettyPrint};

fn assert_round_trips(q: &str) {
    let parsed = parse_query(q).unwrap_or_else(|e| panic!("{q} must parse: {e:?}"));
    let printed = parsed.pretty_print();
    let reparsed = parse_query(&printed)
        .unwrap_or_else(|e| panic!("{q} printed as {printed} which no longer parses: {e:?}"));
    assert_eq!(parsed, reparsed, "{q} changed meaning when printed as {printed}");
}

#[test]
fn values_with_double_quotes_round_trip() {
    for q in [
        r#"error | fillnull value='a"b'"#,
        r#"* | cloud principal='arn:"x"'"#,
        r#"* | cloud account='a"b'"#,
        r#"* | baseline host='h"1'"#,
        r#"* | inputlookup url='https://x.example/"q"'"#,
    ] {
        assert_round_trips(q);
    }
}

#[test]
fn ordinary_values_are_printed_as_before() {
    let parsed = parse_query(r#"error | fillnull value="N/A""#).unwrap();
    assert_eq!(parsed.pretty_print(), r#"error | fillnull value="N/A""#);
    for q in [
        r#"error | fillnull value="N/A" bytes_in, bytes_out"#,
        r#"* | cloud principal="alice""#,
        r#"* | baseline host="ws-1""#,
        r#"* | fillnull value='C:\Windows\'"#,
    ] {
        assert_round_trips(q);
    }
}

/// Found by the scoped golden pass: names with spaces and regexes with an
/// escaped slash did not survive the gate's round trip.
#[test]
fn quoted_names_and_escaped_regex_slashes_round_trip() {
    for q in [
        r#"* | eval "p95 latency"=1 | where "p95 latency" > 1"#,
        r#"* | eval "a b"=1 | table "a b""#,
        r#"* | rename src_ip as "source address""#,
        r#"* | table src_ip as "Source IP""#,
        r#"user=/a\// | head 1"#,
        r#"process=/\$HOME\/\.[a-z-]+/ | head 1"#,
    ] {
        assert_round_trips(q);
    }
    // Bare names are printed bare, as before.
    let parsed = parse_query("* | eval total=a | rename src_ip as source | table total, source").unwrap();
    assert_eq!(
        parsed.pretty_print(),
        "* | eval total = a | rename src_ip as source | table total, source"
    );
}
