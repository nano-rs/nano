// SPDX-License-Identifier: AGPL-3.0-or-later

//! nPL parser / eval batch B (NAN-3312, 3313, 3315, 3318, 3319, 3324, 3326).
//!
//! Each test pins the lean lake compile (`lake_query_compile`'s OCSF 1.9
//! profile) for a query that used to compile into the wrong SQL or fail.

use std::sync::Arc;

use crate::query::clickhouse_sql_gen::ClickHouseSqlGenerator;
use crate::query::PrettyPrint;
use crate::query::{
    parse_query, validate_query_fields_with_profile, Command, Comparator, Query, SearchExpr,
    TimeRange,
};
use crate::schema::OcsfProfile;

/// One hour, as the issue repros used.
fn time_range() -> TimeRange {
    TimeRange {
        start: "2026-10-08T00:00:00Z".parse().unwrap(),
        end: "2026-10-08T01:00:00Z".parse().unwrap(),
    }
}

fn lake_profile() -> OcsfProfile {
    OcsfProfile::try_lake_1_9_with_snapshot_field_types(Default::default()).expect("lake profile")
}

fn lean() -> ClickHouseSqlGenerator {
    ClickHouseSqlGenerator::with_table("__nano_lake_source__")
        .with_profile(Arc::new(lake_profile()))
}

fn lean_sql(npl: &str) -> Result<String, String> {
    let query = parse_query(npl).map_err(|e| format!("parse: {e}"))?;
    lean()
        .generate(&query, &time_range())
        .map_err(|e| format!("generate: {e}"))
}

fn ok(npl: &str) -> String {
    lean_sql(npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"))
}

fn last_command(npl: &str) -> Command {
    match parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: {e}")) {
        Query::Piped { command, .. } => command,
        Query::Search(_) => panic!("{npl:?}: expected a piped query"),
    }
}

// --- NAN-3312: bin bins=N ---------------------------------------------------

#[test]
fn nan3312_bins_on_time_derives_a_round_span_from_the_window() {
    // 1h / 10 = 6m minimum -> 10m is the smallest round span with <= 10 buckets.
    let bins = ok("* | bin time bins=10 | stats count by time");
    let span = ok("* | bin time span=10m | stats count by time");
    assert_eq!(bins, span);
    assert!(!bins.contains("/ 1) * 1"), "{bins}");
}

#[test]
fn nan3312_bins_default_field_buckets_time() {
    assert_eq!(
        ok("* | bin bins=4 | stats count by time_bucket"),
        ok("* | bin span=15m | stats count by time_bucket"),
    );
}

#[test]
fn nan3312_bins_on_a_numeric_field_is_rejected_not_unit_bucketed() {
    let err = lean_sql("* | bin traffic.bytes_out bins=10 | stats count by traffic.bytes_out")
        .expect_err("numeric bins= has no compile-time extent");
    assert!(err.contains("span="), "{err}");
}

#[test]
fn nan3312_bins_zero_is_a_parse_error() {
    assert!(parse_query("* | bin bins=0").is_err());
}

#[test]
fn nan3312_bins_round_trips_through_pretty_print() {
    let query = parse_query("* | bin time bins=10").unwrap();
    let printed = query.pretty_print();
    assert!(printed.contains("bins=10"), "{printed}");
    assert_eq!(parse_query(&printed).unwrap(), query);
}

// --- NAN-3313: isnum / isint / isstr / isbool / searchmatch -----------------

#[test]
fn nan3313_type_test_functions_compile_in_where_and_eval() {
    for (npl, needle) in [
        ("* | where isnum(src_endpoint.port)", "toFloat64OrNull"),
        ("* | where isint(src_endpoint.port)", "toInt64OrNull"),
        ("* | where isstr(user.name)", "toTypeName"),
        ("* | where isbool(user.name)", "Bool"),
        ("* | eval x=isstr(user.name) | table x", "toTypeName"),
        (
            "* | eval x=if(isnum(src_endpoint.port), 1, 0) | table x",
            "toFloat64OrNull",
        ),
    ] {
        let sql = ok(npl);
        assert!(sql.contains(needle), "{npl}: {sql}");
    }
}

#[test]
fn nan3313_searchmatch_uses_base_search_semantics() {
    let sql = ok(r#"* | where searchmatch("user.name=adm*")"#);
    assert!(sql.contains("iLike 'adm%'"), "{sql}");
    let sql = ok(r#"* | eval hit=if(searchmatch("user.name=adm*"), 1, 0) | table hit"#);
    assert!(sql.contains("iLike 'adm%'"), "{sql}");
}

#[test]
fn nan3313_searchmatch_rejects_pipes() {
    let err = lean_sql(r#"* | where searchmatch("x | stats count")"#).unwrap_err();
    assert!(err.contains("searchmatch"), "{err}");
    // Hidden inside a string, a subsearch would bypass every AST gate.
    let err = lean_sql(
        r#"* | where searchmatch("user.name IN [search class_uid=3002 | fields user.name]")"#,
    )
    .unwrap_err();
    assert!(err.contains("searchmatch"), "{err}");
}

// --- NAN-3315: piped search wildcard values ---------------------------------

#[test]
fn nan3315_piped_search_wildcard_matches_like_base_search() {
    let sql = ok("* | search user.name=adm*");
    assert!(sql.contains("iLike 'adm%'"), "{sql}");
    assert!(!sql.contains("'adm*'"), "{sql}");

    let sql = ok("* | search user.name!=adm*");
    assert!(sql.contains("NOT iLike 'adm%'"), "{sql}");

    let sql = ok("* | search user.name=a?min");
    assert!(sql.contains("iLike 'a_min'"), "{sql}");
}

#[test]
fn nan3315_piped_search_escapes_like_metacharacters() {
    let sql = ok("* | search user.name=svc_*");
    assert!(sql.contains(r"iLike 'svc\\_%'"), "{sql}");
}

#[test]
fn nan3315_piped_search_rewrites_nested_terms() {
    let sql = ok("* | search (user.name=adm* OR user.name=root) NOT process.name=*.tmp");
    assert!(sql.contains("iLike 'adm%'"), "{sql}");
    assert!(
        sql.contains("NOT ifNull((toString(\"process.name\") iLike '%.tmp')"),
        "{sql}"
    );
}

#[test]
fn nan3315_where_keeps_literal_equality_and_existence_unchanged() {
    // `where` is a literal comparison; only piped `search` has glob semantics.
    let Command::Where { condition } = last_command(r#"* | where user.name="adm*""#) else {
        panic!("where");
    };
    assert!(
        matches!(
            condition,
            SearchExpr::FieldFilter {
                op: Comparator::Eq,
                ..
            }
        ),
        "{condition:?}"
    );
    // `field=*` is still an existence test in piped search.
    let Command::Where { condition } = last_command("* | search user.name=*") else {
        panic!("search");
    };
    assert!(
        matches!(
            condition,
            SearchExpr::FieldFilter {
                op: Comparator::Eq,
                ..
            }
        ),
        "{condition:?}"
    );
}

#[test]
fn nan3315_piped_search_round_trips_through_pretty_print() {
    let query = parse_query("* | search user.name=adm*").unwrap();
    let printed = query.pretty_print();
    assert_eq!(parse_query(&printed).unwrap(), query, "{printed}");
}

// --- NAN-3318: bare fillnull ------------------------------------------------

#[test]
fn nan3318_bare_fillnull_on_the_lake_is_an_error_not_a_no_op() {
    let err = lean_sql("* | fillnull").expect_err("bare fillnull cannot be compiled");
    assert!(err.contains("fillnull needs a field list"), "{err}");
    // The field-list form keeps working.
    let sql = ok(r#"* | fillnull value="-" user.name"#);
    assert!(sql.contains("ifNull(toString("), "{sql}");
}

#[test]
fn nan3318_bare_fillnull_on_gen1_is_unchanged() {
    let query = parse_query("* | fillnull").unwrap();
    ClickHouseSqlGenerator::new()
        .generate(&query, &time_range())
        .expect("gen1 post-processes bare fillnull");
}

// --- NAN-3319: sort by an un-aliased aggregate ------------------------------

#[test]
fn nan3319_sort_by_unaliased_aggregate_passes_lake_field_validation() {
    let npl = "* | stats sum(traffic.bytes_out) by src_endpoint.ip | sort -sum(traffic.bytes_out)";
    let query = parse_query(npl).unwrap();
    let profile = lake_profile();
    let errors = validate_query_fields_with_profile(&query, Some(&profile));
    assert!(errors.is_empty(), "{errors:?}");
    let sql = ok(npl);
    assert!(sql.contains("ORDER BY sum DESC"), "{sql}");

    let npl = "* | stats dc(user.name) by src_endpoint.ip | sort -dc(user.name)";
    let query = parse_query(npl).unwrap();
    assert!(validate_query_fields_with_profile(&query, Some(&profile)).is_empty());
}

#[test]
fn nan3319_sort_still_rejects_illegal_field_names() {
    let query = parse_query(r#"* | stats count by user.name | sort "a;b""#).unwrap();
    let profile = lake_profile();
    assert!(!validate_query_fields_with_profile(&query, Some(&profile)).is_empty());
}

// --- NAN-3324: unparenthesized arithmetic in where --------------------------

#[test]
fn nan3324_where_arithmetic_rhs_without_parens() {
    let sql = ok("* | where traffic.bytes_out > 10 * traffic.bytes_in");
    assert!(!sql.contains("hasAllTokens"), "{sql}");
    assert!(sql.contains("traffic.bytes_in"), "{sql}");
    assert_eq!(
        parse_query("* | where traffic.bytes_out > 10 * traffic.bytes_in").unwrap(),
        parse_query("* | where (traffic.bytes_out > 10 * traffic.bytes_in)").unwrap(),
    );
}

#[test]
fn nan3324_where_arithmetic_lhs_without_parens() {
    let npl = "* | stats min(time) as first_seen, max(time) as last_seen by src_endpoint.ip \
               | where last_seen - first_seen >= 300";
    let sql = ok(npl);
    assert!(!sql.contains("hasAllTokens"), "{sql}");
    assert!(!sql.contains("'%-%'"), "{sql}");
    let Command::Where { condition } = last_command(npl) else {
        panic!("where");
    };
    assert!(
        matches!(condition, SearchExpr::EvalPredicate(_)),
        "{condition:?}"
    );
}

#[test]
fn nan3324_arithmetic_combines_with_other_filters() {
    let Command::Where { condition } = last_command("* | where a - b >= 300 AND user.name=root")
    else {
        panic!("where");
    };
    let SearchExpr::And(left, right) = condition else {
        panic!("{condition:?}");
    };
    assert!(matches!(*left, SearchExpr::EvalPredicate(_)), "{left:?}");
    assert!(
        matches!(*right, SearchExpr::FieldFilter { .. }),
        "{right:?}"
    );
}

#[test]
fn nan3324_plain_filters_keep_their_index_aware_variants() {
    for npl in [
        "* | where host=web-01",
        "* | where day=2024-01-01",
        "* | where count > 5",
        "* | where user.name=root -x",
    ] {
        let Command::Where { condition } = last_command(npl) else {
            panic!("{npl}");
        };
        let first = match condition {
            SearchExpr::And(left, _) => *left,
            other => other,
        };
        assert!(
            matches!(first, SearchExpr::FieldFilter { .. }),
            "{npl}: {first:?}"
        );
    }
}

// --- NAN-3326: base64_decode never fails the search -------------------------

#[test]
fn nan3326_base64_decode_is_non_throwing() {
    let sql = ok(r#"* | eval d=base64_decode("@@@notb64") | table d"#);
    assert!(sql.contains("tryBase64Decode("), "{sql}");
    assert!(!sql.contains(" base64Decode("), "{sql}");
}

// --- NAN-3313 follow-up: fields named inside searchmatch("...") -------------

#[test]
fn nan3313_searchmatch_fields_are_referenced_for_projection() {
    let profile = lake_profile();
    let query = parse_query(r#"* | where searchmatch("process.cmd_line=*enc*")"#).unwrap();
    let referenced = super::field_analysis::collect_referenced_fields(&query, &profile);
    assert!(referenced.contains("process.cmd_line"), "{referenced:?}");
    let required = super::field_analysis::analyze_required_fields(&query, true, &profile)
        .expect("table view prunes");
    assert!(required.contains("process.cmd_line"), "{required:?}");
}

#[test]
fn nan3313_searchmatch_lake_compile_projects_and_validates_inner_fields() {
    let npl = r#"* | where searchmatch("user.name=j*")"#;
    let query = parse_query(npl).unwrap();
    let profile = lake_profile();
    assert!(validate_query_fields_with_profile(&query, Some(&profile)).is_empty());
    let options = crate::query::QueryOptions {
        table_view: true,
        ..Default::default()
    };
    let sql = lean()
        .generate_with_options(&query, &time_range(), &options)
        .unwrap();
    let stage_0 = sql.split("stage_1").next().unwrap();
    assert!(stage_0.contains("\"user.name\""), "{sql}");
    assert!(sql.contains("iLike 'j%'"), "{sql}");

    // A field only named inside the string is still validated.
    let query = parse_query(r#"* | where searchmatch("user.nmae=j*")"#).unwrap();
    let errors = validate_query_fields_with_profile(&query, Some(&profile));
    assert!(
        errors.iter().any(|e| e.field_name == "user.nmae"),
        "{errors:?}"
    );

    // A field only inside searchmatch must survive pruning even when it is
    // not one of the default table-view columns.
    let query = parse_query(r#"* | where searchmatch("process.cmd_line=*enc*")"#).unwrap();
    let sql = lean()
        .generate_with_options(&query, &time_range(), &options)
        .unwrap();
    let stage_0 = sql.split("stage_1").next().unwrap();
    assert!(stage_0.contains("\"process.cmd_line\""), "{sql}");
}
