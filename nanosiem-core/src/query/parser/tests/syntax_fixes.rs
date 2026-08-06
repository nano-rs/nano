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

// ---------------------------------------------------------------------------
// NAN-1157: backslash is literal inside strings; the matching quote always
// closes. Windows paths with a trailing backslash previously failed to parse
// ("Unexpected token") because the trailing `\"` was read as an escaped quote
// that left the string unterminated. A whole class of persistence/defense-
// evasion rules (startup folder, NETLOGON, \Windows\System32\, \pipe\, ...)
// hit this.
// ---------------------------------------------------------------------------

#[test]
fn windows_path_trailing_backslash_parses() {
    assert_parses(r#"process_path CONTAINS "C:\Windows\System32\""#);
}

#[test]
fn startup_folder_rule_path_parses() {
    assert_parses(
        r#"source_type=windows_sysmon | where file_path CONTAINS "\Start Menu\Programs\Startup\""#,
    );
}

#[test]
fn netlogon_trailing_backslash_parses() {
    assert_parses(r#"source_type=windows_security | where file_path CONTAINS "\NETLOGON\""#);
}

#[test]
fn regex_escapes_in_string_still_pass_through() {
    // `\.` `\d` etc. must survive (backslash literal, not consumed as escape).
    assert_parses(r#"message="a\.b\d\w""#);
}

#[test]
fn trailing_backslash_value_is_literal() {
    use crate::query::{Query, SearchExpr, Value};
    fn first_str(q: &Query) -> Option<String> {
        fn walk(e: &SearchExpr) -> Option<String> {
            match e {
                SearchExpr::FieldFilter { value: Value::String(s), .. } => Some(s.clone()),
                SearchExpr::And(a, b) | SearchExpr::Or(a, b) => walk(a).or_else(|| walk(b)),
                SearchExpr::Not(x) | SearchExpr::Group(x) => walk(x),
                _ => None,
            }
        }
        match q {
            Query::Search(s) => walk(s),
            Query::Piped { source, .. } => first_str(source),
        }
    }
    // Trailing single backslash is preserved literally.
    let q = parse_query(r#"file_path="C:\tmp\""#).expect("trailing-backslash path parses");
    assert_eq!(first_str(&q).as_deref(), Some(r"C:\tmp\"));
    // `\\` still collapses to a single backslash (back-compat).
    let q2 = parse_query(r#"file_path="a\\b""#).expect("escaped-backslash parses");
    assert_eq!(first_str(&q2).as_deref(), Some(r"a\b"));
}

// ---------------------------------------------------------------------------
// NAN-2331: SPL permits arithmetic/computed predicates in `where`. Keep the
// existing SearchExpr representation for ordinary filters and bridge only the
// arithmetic leaf to EvalExpression.
// ---------------------------------------------------------------------------

#[test]
fn arithmetic_where_after_stats_parses() {
    assert_parses(
        "* | stats min(timestamp) as first_seen, max(timestamp) as last_seen, \
         count() as event_count, dc(src_ip) as unique_ips by user | \
         where event_count > 5 AND unique_ips >= 2 AND \
         (last_seen - first_seen) >= 300",
    );
}

#[test]
fn scalar_min_max_arithmetic_where_parses() {
    assert_parses(
        "* | stats min(timestamp) as first_seen, max(timestamp) as last_seen by user | \
         where (max(last_seen) - min(first_seen)) < 900",
    );
}

#[test]
fn arithmetic_comparison_variants_and_split_where_stages_parse() {
    for comparator in [">", "<", ">=", "<=", "=", "!="] {
        assert_parses(&format!(
            "* | stats min(timestamp) as first_seen, max(timestamp) as last_seen by user \
             | where (last_seen - first_seen) {comparator} 300"
        ));
    }

    assert_parses(
        "* | stats min(timestamp) as first_seen, max(timestamp) as last_seen, \
         count() as event_count by user | where event_count > 5 \
         | where (last_seen - first_seen) >= 300",
    );
}

#[test]
fn arithmetic_on_the_right_side_parses() {
    use crate::query::{Command, Query, SearchExpr};

    let parsed = parse_query("* | where last_seen < now() - INTERVAL 15 MINUTE").unwrap();
    match parsed {
        Query::Piped {
            command: Command::Where { condition },
            ..
        } => assert!(
            matches!(condition, SearchExpr::FieldFunctionFilter { .. }),
            "existing field/function comparisons must keep their AST path: {condition:?}"
        ),
        other => panic!("expected piped where query, got {other:?}"),
    }
}

#[test]
fn simple_where_keeps_the_index_aware_ast_variant() {
    use crate::query::{Command, Query, SearchExpr};

    let parsed = parse_query("* | where source_type=windows_sysmon").unwrap();
    match parsed {
        Query::Piped {
            command: Command::Where { condition },
            ..
        } => assert!(
            matches!(condition, SearchExpr::FieldFilter { .. }),
            "ordinary filters must not route through EvalPredicate: {condition:?}"
        ),
        other => panic!("expected piped where query, got {other:?}"),
    }
}

#[test]
fn arithmetic_where_uses_eval_predicate_only_for_the_computed_leaf() {
    use crate::query::{Command, PrettyPrint, Query, SearchExpr};

    fn variant_counts(expr: &SearchExpr) -> (usize, usize) {
        match expr {
            SearchExpr::EvalPredicate(_) => (1, 0),
            SearchExpr::FieldFilter { .. } => (0, 1),
            SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
                let left = variant_counts(left);
                let right = variant_counts(right);
                (left.0 + right.0, left.1 + right.1)
            }
            SearchExpr::Not(inner) | SearchExpr::Group(inner) => variant_counts(inner),
            _ => (0, 0),
        }
    }

    let parsed = parse_query(
        "* | where event_count > 5 AND (last_seen - first_seen) >= 300 AND \
         unique_ips >= 2",
    )
    .unwrap();
    match &parsed {
        Query::Piped {
            command: Command::Where { condition },
            ..
        } => {
            assert!(matches!(condition, SearchExpr::And(_, _)));
            assert_eq!(variant_counts(condition), (1, 2));
        }
        other => panic!("expected piped where query, got {other:?}"),
    }

    let printed = parsed.pretty_print();
    let reparsed = parse_query(&printed).unwrap_or_else(|error| {
        panic!("pretty-printed query did not reparse: {printed}: {error:?}")
    });
    assert_eq!(reparsed, parsed, "pretty-print round trip changed the AST");
}
