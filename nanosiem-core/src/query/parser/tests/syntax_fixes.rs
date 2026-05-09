// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for NAN-254 parser syntax fixes.
//! Validates that previously-failing nPL syntax now parses correctly.

use crate::query::parse_query;

/// Helper: assert that the given nPL query parses without error.
fn assert_parses(input: &str) {
    if let Err(e) = parse_query(input) {
        panic!("Failed to parse: {input}\n  Error: {e}");
    }
}

#[test]
fn head_no_arg() {
    assert_parses("error | head");
}

#[test]
fn head_with_arg() {
    // Backward compat: head N still works
    assert_parses("error | head 50");
}

#[test]
fn tail_no_arg() {
    assert_parses("error | tail");
}

#[test]
fn tail_with_arg() {
    assert_parses("error | tail 50");
}

#[test]
fn chart_over() {
    assert_parses("error | chart count() over src_ip");
}

#[test]
fn chart_over_by_split() {
    assert_parses("error | chart count() over status by source_type");
}

#[test]
fn chart_by_still_works() {
    // Backward compat
    assert_parses("error | chart count() by src_ip");
}

#[test]
fn stats_p95() {
    assert_parses("error | stats p95(response_time)");
}

#[test]
fn stats_p99_alias() {
    assert_parses("error | stats p99(response_time) as tail_latency");
}

#[test]
fn stats_perc95_still_works() {
    // Backward compat
    assert_parses("error | stats perc95(response_time)");
}

#[test]
fn dedup_count_prefix() {
    assert_parses("error | dedup 3 src_ip");
}

#[test]
fn dedup_sortby() {
    assert_parses("error | dedup src_ip sortby -timestamp");
}

#[test]
fn dedup_plain_still_works() {
    assert_parses("error | dedup src_ip");
}

#[test]
fn top_multi_field() {
    assert_parses("error | top 10 src_ip, dest_port");
}

#[test]
fn rare_multi_field() {
    assert_parses("error | rare 10 src_ip, dest_port");
}

#[test]
fn return_no_fields() {
    assert_parses("error | return 10");
}

#[test]
fn return_dollar_field() {
    assert_parses("error | return 10 $src_ip");
}

#[test]
fn return_dollar_user() {
    assert_parses("error | return 5 $user");
}

#[test]
fn return_plain_still_works() {
    assert_parses("error | return 10 src_ip, user");
}

#[test]
fn spath_any_order() {
    assert_parses("error | spath input=ext path=\"user.name\" output=username");
}

#[test]
fn spath_original_order() {
    // Backward compat: input, output, path
    assert_parses("error | spath input=ext output=username path=\"user.name\"");
}

#[test]
fn bin_bins() {
    assert_parses("error | bin bytes bins=10");
}

#[test]
fn bin_span_still_works() {
    assert_parses("error | bin _time span=5m");
}

#[test]
fn rex_max_match() {
    assert_parses("error | rex field=url \"/pattern\" max_match=0");
}

#[test]
fn rex_without_max_match() {
    // Backward compat
    assert_parses("error | rex field=url \"/pattern\"");
}

#[test]
fn format_sep_alias() {
    assert_parses("error | format sep=\" AND \"");
}

#[test]
fn format_row_sep_still_works() {
    assert_parses("error | format row_sep=\" AND \"");
}

#[test]
fn sequence_maxgap() {
    assert_parses("error | sequence by user maxspan=15m maxgap=5m [status=200] [status=500]");
}

#[test]
fn sequence_without_maxgap() {
    // Backward compat
    assert_parses("error | sequence by user maxspan=15m [status=200] [status=500]");
}
