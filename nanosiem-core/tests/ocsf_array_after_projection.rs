// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5350 regression: an OCSF array field that `| table`, `| rename`,
//! `table f AS g` or `eval g = f` put into a stage column keeps its
//! membership semantics in every later stage.
//!
//! NAN-5306 (v2.0.18) made `table` keep every requested column name and
//! registered names that resolve to an expression or another column
//! (`module.file.signatures.state` → `arrayMap(…) AS "…"`, `category` →
//! `"http_request.url.categories"`) as upstream-computed. That hid their array
//! type: `| where f="v"` compiled `lower(toString(f)) = 'v'`, which compares
//! the text `['v']` and silently returned no rows; `IN` failed with Code 43;
//! `stats … by category` grouped whole arrays instead of elements. Renamed and
//! copied arrays had the same problem before NAN-5306.
//!
//! One test per stage that can follow such a projection. Every predicate form
//! asserted here was executed against ClickHouse 26.10 with array rows when
//! the fix was written (see the PR).

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use nanosiem_core::schema::OcsfProfile;
use std::sync::Arc;

const SIG: &str = r#""module.file.signatures.state""#;
const SIG_MEMBER: &str = r#"has(arrayMap(x -> lower(x), "module.file.signatures.state"), 'valid')"#;

fn tr() -> TimeRange {
    TimeRange {
        start: "2025-06-01T00:00:00Z".parse().unwrap(),
        end: "2025-06-10T00:00:00Z".parse().unwrap(),
    }
}

fn ocsf(q: &str) -> String {
    let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
    ClickHouseSqlGenerator::with_table("nanosiem.ocsf_logs")
        .with_profile(Arc::new(OcsfProfile::new()))
        .generate(&query, &tr())
        .unwrap_or_else(|e| panic!("SQL gen {q}: {e}"))
}

/// The text of `stage_<n>` (up to the next stage or the final SELECT).
fn stage(sql: &str, n: usize) -> &str {
    let start = sql
        .find(&format!("stage_{n} AS ("))
        .unwrap_or_else(|| panic!("no stage_{n} in:\n{sql}"));
    let rest = &sql[start..];
    let end = rest[1..]
        .find("\nstage_")
        .or_else(|| rest.find("\nSELECT * FROM stage_"))
        .map_or(rest.len(), |i| i + 1);
    &rest[..end]
}

/// No stage after the projection compares an array as text.
fn assert_no_text_compare(sql: &str, col: &str) {
    assert!(
        !sql.contains(&format!("lower(toString({col}))")),
        "array compared as text:\n{sql}"
    );
}

#[test]
fn table_keeps_the_requested_column_name() {
    // NAN-5306 is unchanged: the projected array comes back under the name asked for.
    let sql = ocsf(r#"class_uid=1005 | table timestamp, module.file.signatures.state | where module.file.signatures.state="valid""#);
    assert!(stage(&sql, 1).contains(&format!(r#"[]."state") AS {SIG}"#)), "{sql}");
    let sql = ocsf("class_uid=1007 | table time, src_ip | stats count by src_ip");
    assert!(stage(&sql, 1).contains(r#"timestamp AS time, "src_endpoint.ip" AS src_ip"#), "{sql}");
    assert!(stage(&sql, 2).contains("GROUP BY src_ip"), "{sql}");
}

#[test]
fn where_after_table_tests_membership() {
    let base = "class_uid=1005 | table timestamp, module.file.signatures.state | where";
    for (pred, expected) in [
        (r#"module.file.signatures.state="valid""#, SIG_MEMBER.to_string()),
        (r#"module.file.signatures.state!="valid""#, format!("NOT {SIG_MEMBER}")),
        (
            "module.file.signatures.state=*",
            format!("notEmpty(arrayMap(x -> lower(x), {SIG}))"),
        ),
        (
            r#"module.file.signatures.state="val*""#,
            format!("arrayExists(x -> lower(x) LIKE 'val%', arrayMap(x -> lower(x), {SIG}))"),
        ),
        (
            r#"module.file.signatures.state IN ("Valid", "x")"#,
            format!("arrayExists(x -> x IN ('valid', 'x'), arrayMap(x -> lower(x), {SIG}))"),
        ),
        (
            r#"module.file.signatures.state NOT IN ("valid")"#,
            format!("NOT arrayExists(x -> x IN ('valid'), arrayMap(x -> lower(x), {SIG}))"),
        ),
    ] {
        let sql = ocsf(&format!("{base} {pred}"));
        let s2 = stage(&sql, 2);
        assert!(s2.contains(&expected), "`{pred}`: expected `{expected}` in:\n{sql}");
        assert!(!s2.contains("event."), "`{pred}` must read the projected column:\n{sql}");
        assert_no_text_compare(&sql, SIG);
    }
}

#[test]
fn where_after_table_on_alias_and_numeric_arrays() {
    // A UDM alias of a promoted Array column (`category`).
    let sql = ocsf(r#"class_uid=4002 | table timestamp, category | where category="Malware""#);
    assert!(stage(&sql, 2).contains("has(arrayMap(x -> lower(x), category), 'malware')"), "{sql}");
    // A numeric promoted array compares numbers.
    let sql = ocsf("class_uid=1007 | table timestamp, observables.type_id | where observables.type_id IN (1, 2)");
    assert!(stage(&sql, 2).contains(r#"arrayExists(x -> x IN (1, 2), "observables.type_id")"#), "{sql}");
}

#[test]
fn search_after_table_tests_membership() {
    let sql = ocsf(r#"class_uid=1005 | table timestamp, module.file.signatures.state | search module.file.signatures.state="valid""#);
    assert!(stage(&sql, 2).contains(SIG_MEMBER), "{sql}");
    assert_no_text_compare(&sql, SIG);
}

#[test]
fn stats_by_after_table_groups_like_the_source_field() {
    // A promoted Array column splits per element, as `stats by category` does unprojected.
    let sql = ocsf("class_uid=4002 | table timestamp, category | stats count by category");
    assert!(
        stage(&sql, 2).contains("arrayJoin(arrayFilter(x -> x IS NOT NULL, category)) AS _mv_category"),
        "{sql}"
    );
    // A JSON array path groups by the projected value, never re-read from `event`.
    let sql = ocsf("class_uid=1005 | table timestamp, module.file.signatures.state | stats count by module.file.signatures.state");
    let s2 = stage(&sql, 2);
    assert!(s2.contains(&format!("GROUP BY {SIG}")) && !s2.contains("event."), "{sql}");
    // A `where` ahead of the stats keeps membership although the whole-query
    // computed set holds the stats by-field.
    let sql = ocsf(r#"class_uid=1005 | table timestamp, module.file.signatures.state | where module.file.signatures.state="valid" | stats count by module.file.signatures.state"#);
    assert!(stage(&sql, 2).contains(SIG_MEMBER), "{sql}");
}

#[test]
fn eval_after_table_compares_elements() {
    let sql = ocsf(r#"class_uid=1005 | table timestamp, module.file.signatures.state | eval v=if(module.file.signatures.state="valid", 1, 0)"#);
    assert!(
        stage(&sql, 2).contains(&format!("arrayExists(x -> lower(toString(x)) = 'valid', {SIG})")),
        "{sql}"
    );
    assert_no_text_compare(&sql, SIG);
    // `eval g = f` copies the array; a later predicate on `g` is membership.
    let sql = ocsf(r#"class_uid=1005 | table timestamp, module.file.signatures.state | eval s=module.file.signatures.state | where s="valid""#);
    assert!(stage(&sql, 3).contains("has(arrayMap(x -> lower(x), s), 'valid')"), "{sql}");
    let sql = ocsf(r#"class_uid=4002 | eval c=category | where c="malware""#);
    assert!(stage(&sql, 2).contains("has(arrayMap(x -> lower(x), c), 'malware')"), "{sql}");
}

#[test]
fn eval_reassigning_the_name_drops_array_semantics() {
    // The eval replaces the array with a scalar; the predicate is scalar again.
    let sql = ocsf(r#"class_uid=4002 | table timestamp, category | eval category=lower("X") | where category="x""#);
    assert!(stage(&sql, 3).contains("lower(toString(category)) = 'x'"), "{sql}");
    assert!(!stage(&sql, 3).contains("arrayMap"), "{sql}");
}

#[test]
fn dedup_and_sort_after_table_use_the_projected_column() {
    let sql = ocsf("class_uid=1005 | table timestamp, module.file.signatures.state | dedup module.file.signatures.state");
    let s2 = stage(&sql, 2);
    assert!(s2.contains(&format!("LIMIT 1 BY {SIG}")) && !s2.contains("event."), "{sql}");
    let sql = ocsf("class_uid=1005 | table timestamp, module.file.signatures.state | sort module.file.signatures.state");
    let s2 = stage(&sql, 2);
    assert!(s2.contains(&format!("ORDER BY {SIG} ASC")) && !s2.contains("event."), "{sql}");
}

#[test]
fn fields_minus_after_table_keeps_membership() {
    let sql = ocsf(r#"class_uid=1005 | table timestamp, module.file.signatures.state, message | fields - message | where module.file.signatures.state="valid""#);
    assert!(stage(&sql, 3).contains(SIG_MEMBER), "{sql}");
    // Excluding the array itself forgets it.
    let sql = ocsf(r#"class_uid=1005 | table timestamp, module.file.signatures.state as sig, message | fields - sig | eval sig="valid" | where sig="valid""#);
    assert!(stage(&sql, 4).contains("lower(toString(sig)) = 'valid'"), "{sql}");
}

#[test]
fn rename_and_table_alias_carry_the_array() {
    for q in [
        r#"class_uid=1005 | table timestamp, module.file.signatures.state | rename module.file.signatures.state as sig | where sig="valid""#,
        r#"class_uid=1005 | rename module.file.signatures.state as sig | where sig="valid""#,
    ] {
        let sql = ocsf(q);
        assert!(sql.contains("has(arrayMap(x -> lower(x), sig), 'valid')"), "`{q}`:\n{sql}");
        assert_no_text_compare(&sql, "sig");
    }
    let sql = ocsf(r#"class_uid=1005 | table timestamp, module.file.signatures.state as sig | where sig="valid""#);
    assert!(stage(&sql, 2).contains("has(arrayMap(x -> lower(x), sig), 'valid')"), "{sql}");
    let sql = ocsf(r#"class_uid=4002 | table timestamp, category as cat | where cat IN ("Phishing")"#);
    assert!(stage(&sql, 2).contains("arrayExists(x -> x IN ('phishing'), arrayMap(x -> lower(x), cat))"), "{sql}");
    let sql = ocsf(r#"class_uid=4002 | rename category as cat | where cat="phishing""#);
    assert!(stage(&sql, 2).contains("has(arrayMap(x -> lower(x), cat), 'phishing')"), "{sql}");
    // A second `table` of the alias keeps it.
    let sql = ocsf(r#"class_uid=1005 | table timestamp, module.file.signatures.state as sig | table sig | where sig="valid""#);
    assert!(stage(&sql, 3).contains("has(arrayMap(x -> lower(x), sig), 'valid')"), "{sql}");
}

#[test]
fn join_after_table_keeps_membership() {
    let sql = ocsf(r#"class_uid=1005 | table timestamp, device.hostname, module.file.signatures.state | join type=left device.hostname [search class_uid=3002 | fields device.hostname, src_endpoint.ip] | where module.file.signatures.state="valid""#);
    assert!(stage(&sql, 3).contains(SIG_MEMBER), "{sql}");
    assert_no_text_compare(&sql, SIG);
}

#[test]
fn aggregation_ends_the_array_scope() {
    // After `stats … by` splits a promoted array, the column holds elements.
    let sql = ocsf(r#"class_uid=1007 | stats count by observables.value | table observables.value | where observables.value="x""#);
    assert!(!stage(&sql, 3).contains("arrayMap"), "{sql}");
    // After a by-less aggregation the name is gone; nothing reads it as an array.
    let sql = ocsf(r#"class_uid=4002 | table timestamp, category | stats count | eval category="x" | where category="x""#);
    assert!(!sql.contains("has(arrayMap(x -> lower(x), category)"), "{sql}");
}

// ---- Review round (codex P1s): sequential lineage, subsearch arrays, in-place scalarizers.

#[test]
fn chained_rename_follows_each_mapping_in_order() {
    let sql = ocsf(r#"class_uid=1005 | table timestamp, module.file.signatures.state AS sig | rename sig AS a, a AS b | where b="x""#);
    assert!(stage(&sql, 3).contains("has(arrayMap(x -> lower(x), b), 'x')"), "{sql}");
    // A scalar renamed onto the array's name replaces it.
    let sql = ocsf(r#"class_uid=1005 | table timestamp, message, module.file.signatures.state AS sig | rename message AS sig | where sig="x""#);
    assert!(stage(&sql, 3).contains("lower(toString(sig)) = 'x'"), "{sql}");
}

#[test]
fn eval_copies_follow_each_assignment_in_order() {
    // Chained copies keep the array.
    let sql = ocsf(r#"class_uid=1005 | table timestamp, module.file.signatures.state AS sig | eval a=sig, b=a | where b="x""#);
    assert!(stage(&sql, 3).contains("has(arrayMap(x -> lower(x), b), 'x')"), "{sql}");
    // Overwrite, then copy: the copy is the scalar.
    let sql = ocsf(r#"class_uid=1005 | table timestamp, module.file.signatures.state AS sig | eval sig="scalar", copy=sig | where copy="scalar""#);
    let s3 = stage(&sql, 3);
    assert!(s3.contains("lower(toString(copy)) = 'scalar'") && !s3.contains("arrayMap"), "{sql}");
    // Overwriting a schema array name, then copying it.
    let sql = ocsf(r#"class_uid=4002 | eval category="x", c=category | where c="x""#);
    assert!(!stage(&sql, 2).contains("arrayMap"), "{sql}");
}

#[test]
fn join_carries_arrays_projected_in_the_subsearch() {
    let sql = ocsf(r#"class_uid=1005 | table timestamp, device.hostname | join device.hostname [search class_uid=4002 | table device.hostname, category AS cats] | where cats="malware""#);
    assert!(stage(&sql, 3).contains("has(arrayMap(x -> lower(x), cats), 'malware')"), "{sql}");
    // The main side's arrays survive a join that does not replace them.
    let sql = ocsf(r#"class_uid=1005 | table timestamp, device.hostname, module.file.signatures.state AS sig | join device.hostname [search class_uid=4002 | table device.hostname, category AS cats] | where sig="valid""#);
    assert!(stage(&sql, 3).contains("has(arrayMap(x -> lower(x), sig), 'valid')"), "{sql}");
}

#[test]
fn append_keeps_arrays_both_arms_agree_on() {
    let both = r#"class_uid=4002 | table timestamp, category AS cats | append [search class_uid=4002 | table timestamp, category AS cats] | where cats="malware""#;
    let sql = ocsf(both);
    assert!(stage(&sql, 3).contains("has(arrayMap(x -> lower(x), cats), 'malware')"), "{sql}");
    // An arm holding a scalar under the name makes it a scalar column.
    let mixed = r#"class_uid=4002 | table timestamp, category AS cats | append [search class_uid=4002 | table timestamp, message AS cats] | where cats="malware""#;
    let sql = ocsf(mixed);
    assert!(!stage(&sql, 3).contains("arrayMap"), "{sql}");
}

#[test]
fn in_place_scalar_rewrites_end_array_typing() {
    for (q, n) in [
        (r#"class_uid=1005 | table timestamp, module.file.signatures.state AS sig | rex mode=sed field=sig "s/a/b/g" | where sig="x""#, 3),
        (r#"class_uid=1005 | table timestamp, module.file.signatures.state AS sig | fillnull value="none" sig | where sig="x""#, 3),
        (r#"class_uid=1005 | table timestamp, message, module.file.signatures.state AS sig | spath input=message path=a output=sig | where sig="x""#, 3),
    ] {
        let sql = ocsf(q);
        let s = stage(&sql, n);
        assert!(s.contains("lower(toString(sig)) = 'x'") && !s.contains("arrayMap"), "`{q}`:\n{sql}");
    }
}
