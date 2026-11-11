// SPDX-License-Identifier: AGPL-3.0-or-later

//! nPL concept translation under OCSF (NAN-5271 E).

use std::sync::Arc;

use crate::query::clickhouse_sql_gen::ClickHouseSqlGenerator;
use crate::query::{parse_query, TimeRange};
use crate::schema::{OcsfProfile, UdmProfile};

fn time_range() -> TimeRange {
    TimeRange {
        start: "2026-10-08T00:00:00Z".parse().unwrap(),
        end: "2026-10-08T01:00:00Z".parse().unwrap(),
    }
}

fn ocsf_sql(npl: &str) -> String {
    let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"));
    ClickHouseSqlGenerator::new()
        .with_profile(Arc::new(OcsfProfile::new()))
        .generate(&q, &time_range())
        .unwrap_or_else(|e| panic!("{npl:?}: {e}"))
}

fn udm_sql(npl: &str) -> String {
    let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: {e}"));
    ClickHouseSqlGenerator::new()
        .with_profile(Arc::new(UdmProfile::new()))
        .generate(&q, &time_range())
        .unwrap_or_else(|e| panic!("{npl:?}: {e}"))
}

/// The WHERE body after the time bounds (both profiles emit
/// `timestamp >= … AND timestamp < … AND (<filter>)`).
fn where_tail(sql: &str) -> &str {
    let i = sql.find("timestamp < ").expect("time bound");
    &sql[i..]
}

const BLOCKED: &str = crate::schema::ocsf_predicates::BLOCKED;
const ALLOWED: &str = crate::schema::ocsf_predicates::ALLOWED;

#[test]
fn action_blocked_translates_to_disposition_under_ocsf() {
    for q in ["action=blocked", "action=\"Blocked\"", "action=denied", "action=dropped"] {
        let sql = ocsf_sql(q);
        assert!(where_tail(&sql).contains(BLOCKED), "{q}: {sql}");
        assert!(!sql.contains("lower(activity)"), "{q}: {sql}");
    }
    let sql = ocsf_sql("action=allowed");
    assert!(where_tail(&sql).contains(ALLOWED), "{sql}");
}

#[test]
fn action_blocked_negation_and_in_list() {
    let sql = ocsf_sql("action!=blocked");
    assert!(sql.contains(&format!("NOT {BLOCKED}")), "{sql}");

    let sql = ocsf_sql("action IN (blocked, allowed)");
    assert!(sql.contains(&format!("({BLOCKED} OR {ALLOWED})")), "{sql}");

    // Mixed list: the concept ORs with plain membership of the rest.
    let sql = ocsf_sql("action IN (blocked, \"Get\")");
    assert!(sql.contains(BLOCKED) && sql.contains("'get'"), "{sql}");
}

#[test]
fn action_blocked_translates_in_a_where_stage() {
    let sql = ocsf_sql("* | where action=\"blocked\"");
    assert!(sql.contains(BLOCKED), "{sql}");
    let sql = ocsf_sql("* | where action!=\"blocked\"");
    assert!(sql.contains(&format!("NOT {BLOCKED}")), "{sql}");
}

/// HTTP users' OCSF-native meaning of `action` (the activity caption) is kept.
#[test]
fn action_http_method_keeps_activity_meaning() {
    let sql = ocsf_sql("action=\"Get\"");
    assert!(sql.contains("lower(activity) = 'get'"), "{sql}");
    assert!(!sql.contains("disposition_id"), "{sql}");
    let sql = ocsf_sql("action=logon");
    assert!(sql.contains("lower(activity) = 'logon'"), "{sql}");
}

/// UDM `action` is a real String column — no translation, byte-identical.
#[test]
fn udm_action_blocked_is_untouched() {
    let sql = udm_sql("action=blocked");
    assert!(!sql.contains("disposition_id"), "{sql}");
    assert!(sql.contains("'blocked'"), "{sql}");
}

/// Native enum spellings now translate through the manifest labels.
#[test]
fn native_disposition_action_logon_type_labels() {
    assert!(ocsf_sql("disposition_id=blocked").contains("disposition_id = 2"));
    assert!(ocsf_sql("action_id=denied").contains("action_id = 2"));
    assert!(ocsf_sql("logon_type_id=\"remote interactive\"").contains("logon_type_id = 10"));
}

/// NAN-5271 E: `category` (CIM content category → `http_request.url.categories`)
/// is an Array column; the alias used to compile `lower(<Array>) = 'x'`, a CH
/// Code 43 that failed the whole search.
#[test]
fn category_alias_uses_array_membership() {
    let sql = ocsf_sql("category=\"technology\"");
    assert!(!sql.contains("lower(\"http_request.url.categories\")"), "{sql}");
    assert!(sql.contains("has("), "{sql}");
    assert!(sql.contains("http_request.url.categories"), "{sql}");
}

/// The asset view's OCSF event-kind drilldowns (`OCSF_ASSET_CONCEPT_WHERE` in
/// `nanosiem-web/src/lib/schema-fields.ts`, copied verbatim — not
/// `include_str!`'d, which would break the open-core mirror) must compile and
/// select the same rows as the `ocsf_predicates` concept the dossier counted.
#[test]
fn asset_concept_drilldowns_compile_to_the_concept_predicates() {
    use crate::schema::ocsf_predicates as p;
    let cases: &[(&str, &[&str])] = &[
        ("category_uid=3", &["category_uid = 3"]),
        ("class_uid=3002", &["class_uid = 3002"]),
        ("class_uid=3002 AND activity_id!=2 AND status_id=1", &["class_uid = 3002", "activity_id != 2", "status_id = 1"]),
        ("class_uid=3002 AND activity_id!=2 AND status_id=2", &["class_uid = 3002", "activity_id != 2", "status_id = 2"]),
        (
            "class_uid=3002 AND activity_id=1 AND logon_type_id IN (2, 10, 11, 12)",
            &["class_uid = 3002", "activity_id = 1", "logon_type_id IN (2, 10, 11, 12)"],
        ),
        ("class_uid=3002 AND activity_id=1 AND logon_type_id IN (3, 8)", &["class_uid = 3002", "activity_id = 1", "logon_type_id IN (3, 8)"]),
        ("class_uid=1001", &["class_uid = 1001"]),
        ("class_uid IN (1001, 201001, 201002)", &["class_uid IN (1001, 201001, 201002)"]),
    ];
    for (where_body, terms) in cases {
        let sql = ocsf_sql(&format!("* | where {where_body}"));
        for t in *terms {
            assert!(sql.contains(t), "`{where_body}` → {sql}");
        }
    }
    // The copied strings stay in lockstep with the Rust concepts.
    for (concept, terms) in [
        (p::AUTH_SUCCESS, cases[2].1),
        (p::AUTH_FAILURE, cases[3].1),
        (p::INTERACTIVE_LOGON, cases[4].1),
        (p::NETWORK_LOGON, cases[5].1),
        (p::FILE_EVENT, cases[6].1),
        (p::IAM_EVENT, cases[0].1),
    ] {
        for t in terms {
            assert!(concept.contains(t), "{concept} lacks {t}");
        }
    }
}

/// A field-pruned stage must project the concept's columns, or the later
/// `| where` fails with CH Code 47 (validated on local CH: 49,432 rows).
#[test]
fn pruned_stage_projects_concept_columns_for_a_where() {
    for q in [
        "source_type=conduit_proxy | where action=\"blocked\" | stats count by src_ip",
        "source_type=conduit_proxy | where action IN (\"blocked\") | stats count by src_ip",
    ] {
        let sql = ocsf_sql(q);
        let stage0 = &sql[..sql.find("stage_1").expect("staged")];
        assert!(stage0.contains("disposition_id") && stage0.contains("action_id"), "{q}: {sql}");
        assert!(sql.contains(BLOCKED), "{q}: {sql}");
    }
}

/// Every negation spelling selects the complement of the concept (the
/// concept columns are non-Nullable Int32, so `NOT (...)` never drops a row
/// to NULL): `!=`, `NOT field=`, `NOT IN` (search term and `| where`).
#[test]
fn action_blocked_negation_spellings() {
    // `NOT <BLOCKED>` possibly with an extra wrapping paren (`NOT (<BLOCKED>)`).
    let negated = |sql: &str| {
        sql.find(BLOCKED)
            .map(|i| sql[..i].trim_end_matches('(').trim_end().ends_with("NOT"))
            .unwrap_or(false)
    };
    for q in [
        "action!=blocked",
        "NOT action=blocked",
        "action NOT IN (blocked)",
        "* | where action!=\"blocked\"",
        "* | where NOT action=\"blocked\"",
        "* | where action NOT IN (\"blocked\")",
    ] {
        let sql = ocsf_sql(q);
        assert!(negated(&sql), "{q}: {sql}");
        assert!(!sql.contains("lower(activity)"), "{q}: {sql}");
    }
    // Mixed NOT IN negates the whole union, not just the concept leg.
    let sql = ocsf_sql("action NOT IN (blocked, \"Get\")");
    assert!(sql.contains(&format!("NOT ({BLOCKED} OR lower(activity) IN ('get'))")), "{sql}");
    // Wildcards / regex are string matches on `activity`, never the concept.
    let sql = ocsf_sql("action=blocked*");
    assert!(!sql.contains("disposition_id"), "{sql}");
}
