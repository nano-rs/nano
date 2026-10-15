//! `field=*` must mean "this field exists", not "match every row".
//!
//! NAN-2361: the pure-wildcard comparison short-circuited to the literal SQL
//! `1` (and `0` for `!=`), so the field name was discarded entirely and the
//! predicate degenerated to `WHERE 1`. Measured on the live lake before the
//! fix: `file.hashes.value=*` matched 85,992 rows, of which 395 of 400 sampled
//! carried no hash under ANY path, and `file.hashes.value=*` and
//! `process.file.hashes.value=*` returned the byte-identical row set — the
//! tell that neither field was being consulted.
//!
//! That shape is wrong in both directions for anyone using it as an existence
//! filter: it admits rows where the field is absent, and (because the row set
//! is then dominated by irrelevant rows) it distorts any aggregate built on
//! top of it. Every SIEM query language in this family reads `field=*` as
//! "field is present".
//!
//! Run with: cargo test -p nanosiem-core --test npl_field_existence_tests

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};

fn test_time_range() -> TimeRange {
    TimeRange {
        start: "2024-01-01T00:00:00Z".parse().unwrap(),
        end: "2024-01-02T00:00:00Z".parse().unwrap(),
    }
}

fn npl(query_str: &str) -> String {
    let query = parse_query(query_str)
        .unwrap_or_else(|e| panic!("Parse failed for: {}\nError: {}", query_str, e));
    ClickHouseSqlGenerator::new()
        .generate(&query, &test_time_range())
        .unwrap_or_else(|e| panic!("SQL gen failed for: {}\nError: {}", query_str, e))
}

/// The regression itself: the generated predicate must reference the column.
/// A bare `1` means the field was dropped and every row matches.
#[test]
fn scalar_field_wildcard_is_an_existence_test_not_match_all() {
    let sql = npl("user=*");
    assert!(
        sql.contains("IS NOT NULL"),
        "expected a presence predicate, got:\n{sql}"
    );
    assert!(
        sql.contains("!= ''"),
        "an empty string is not a present value, got:\n{sql}"
    );
}

#[test]
fn negated_scalar_field_wildcard_is_absence() {
    let sql = npl("user!=*");
    assert!(
        sql.contains("NOT (") || sql.contains("NOT("),
        "expected the negation of the presence predicate, got:\n{sql}"
    );
    assert!(sql.contains("IS NOT NULL"), "got:\n{sql}");
}

/// Two different fields must not produce the same predicate. Before the fix
/// both collapsed to `1`, which is exactly why two different `=*` queries
/// returned identical row sets on the live lake.
#[test]
fn distinct_fields_produce_distinct_existence_predicates() {
    let a = npl("user=*");
    let b = npl("src_ip=*");
    assert_ne!(
        a, b,
        "different fields collapsed to the same SQL — the field name is being discarded"
    );
}

/// A wildcard that is not the bare `*` keeps its LIKE behaviour; this pins that
/// the fix did not over-reach into prefix/suffix matching.
#[test]
fn partial_wildcards_still_compile_to_like() {
    let sql = npl("user=admin*");
    assert!(
        sql.to_lowercase().contains("like"),
        "prefix wildcard must still lower to a LIKE, got:\n{sql}"
    );
    assert!(
        !sql.contains("IS NOT NULL AND"),
        "a partial wildcard is a pattern match, not an existence test, got:\n{sql}"
    );
}

/// The same rule inside a pipeline `| where`, which compiles through a separate
/// code path that had the identical bug.
#[test]
fn pipeline_where_field_wildcard_is_an_existence_test() {
    let sql = npl("* | where user=*");
    assert!(
        sql.contains("IS NOT NULL"),
        "the pipeline path must also treat `=*` as existence, got:\n{sql}"
    );
}

/// `*` alone is still "match everything" — it is a bare keyword, not a field
/// comparison, and must not be turned into a presence test on some column.
#[test]
fn bare_star_still_matches_all_rows() {
    let sql = npl("*");
    assert!(
        !sql.contains("IS NOT NULL AND"),
        "bare `*` is match-all, not an existence test, got:\n{sql}"
    );
}
