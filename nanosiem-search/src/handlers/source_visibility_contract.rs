// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2361 wave 8: the tenant search view's source-visibility contract on
//! the shared lake.
//!
//! On the lake the ONE row filter is on `metadata.log_source` (the ingest
//! route slug every event carries); the OTLP datasets are gated by their
//! route slug. These tests prove, without a database, that:
//!
//! 1. a restricted member's query — however it is written (OR arms, NOT,
//!    subsearch-free tricks, a direct positive filter on the denied source) —
//!    can never return a row whose `metadata.log_source` is a denied slug:
//!    the enforced query is evaluated row by row against synthetic lake rows
//!    with the same evaluator the Nano-side stages use, and the generated
//!    OCSF lake SQL carries the `NOT IN` on `metadata.log_source` at the top
//!    level of the scan;
//! 2. the detection runtime's explicit `SourceVisibility::Unrestricted`
//!    leaves the query byte-identical (full lake) while a member-initiated
//!    rule test under the same rule text sees nothing from the denied source;
//! 3. a case participant's `SourceVisibility::CaseScoped` re-admits exactly
//!    the attached evidence rows of a denied source and nothing else from it;
//! 4. the OTLP datasets are hidden iff their route slug is denied.

use std::collections::BTreeSet;

use nanosiem_core::{
    auth::source_visibility::SourceVisibility,
    query::{parse_query, ClickHouseSqlGenerator, Query, QueryOptions, SearchExpr, TimeRange},
    schema::{OcsfProfile, SchemaProfile},
    search::{
        evaluate_condition_on_json,
        query_processing::{enforce_source_scope_with_field, otlp_dataset_denied},
    },
};

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// Synthetic lake rows: `(metadata.uid, metadata.log_source, user.name)`.
fn lake_rows() -> Vec<serde_json::Value> {
    [
        ("evt-w1", "hec_windows", "bob"),
        ("evt-w2", "hec_windows", "alice"),
        ("evt-w3", "hec_windows", "bob"),
        ("evt-a1", "apache", "bob"),
        ("evt-d1", "default", "bob"),
        ("evt-o1", "otlp_log", "carol"),
    ]
    .iter()
    .map(|(uid, source, user)| {
        serde_json::json!({
            "metadata": {"uid": uid, "log_source": source},
            "user": {"name": user},
            "message": format!("{source} event for {user}"),
        })
    })
    .collect()
}

/// The base scan expression of a (possibly piped) query.
fn base_expr(query: &Query) -> &SearchExpr {
    match query {
        Query::Search(expr) => expr,
        Query::Piped { source, .. } => base_expr(source),
    }
}

fn rows_returned(enforced: &str) -> Vec<String> {
    let parsed = parse_query(enforced).expect("enforced query parses");
    let expr = base_expr(&parsed);
    lake_rows()
        .iter()
        .filter(|row| evaluate_condition_on_json(expr, row))
        .map(|row| row["metadata"]["uid"].as_str().unwrap().to_string())
        .collect()
}

fn source_of(uid: &str) -> String {
    lake_rows()
        .iter()
        .find(|r| r["metadata"]["uid"] == uid)
        .map(|r| r["metadata"]["log_source"].as_str().unwrap().to_string())
        .unwrap()
}

/// Every way a member might try to reach a denied source's rows.
const ADVERSARIAL_QUERIES: &[&str] = &[
    r#"metadata.log_source="hec_windows""#,
    r#"metadata.log_source="hec_windows" OR user.name="bob""#,
    r#"user.name="bob" OR metadata.log_source="hec_windows""#,
    r#"NOT metadata.log_source="apache""#,
    r#"NOT (metadata.log_source="apache" OR metadata.log_source="default")"#,
    r#"metadata.log_source!="apache""#,
    r#"metadata.log_source IN ("hec_windows", "apache")"#,
    r#"metadata.log_source NOT IN ("apache")"#,
    "*",
    "bob",
    r#"user.name="bob" | stats count by metadata.log_source"#,
    r#"metadata.uid="evt-w1""#,
];

#[test]
fn restricted_member_never_receives_rows_from_a_denied_source() {
    let member = SourceVisibility::member(set(&["hec_windows"]));
    for query in ADVERSARIAL_QUERIES {
        let enforced = member.enforce_lake_query(query).unwrap_or_else(|e| panic!("{query}: {e}"));
        let returned = rows_returned(&enforced);
        for uid in &returned {
            assert_ne!(source_of(uid), "hec_windows", "{query} → {enforced} leaked {uid}");
        }
        assert!(
            enforced.contains(r#"metadata.log_source NOT IN ("hec_windows")"#),
            "{query} → {enforced}: missing the one row filter"
        );
        assert!(!enforced.contains("source_type"), "{enforced}");
    }
    // The gate does not hide what the member may see.
    let enforced = member.enforce_lake_query("bob").unwrap();
    assert_eq!(rows_returned(&enforced), vec!["evt-a1", "evt-d1"]);
    // Two denied sources, nothing but the third comes back.
    let two = SourceVisibility::member(set(&["hec_windows", "default"]));
    assert_eq!(rows_returned(&two.enforce_lake_query("bob OR carol").unwrap()), vec!["evt-a1", "evt-o1"]);
}

/// The generated OCSF lake SQL carries the filter on the `metadata.log_source`
/// column at the top level of the scan's WHERE — the shape the lake worker
/// executes for every logs query of a restricted member.
#[test]
fn lake_sql_for_a_restricted_member_filters_on_metadata_log_source() {
    let deny = set(&["hec_windows"]);
    let enforced = enforce_source_scope_with_field(
        r#"metadata.log_source="hec_windows" OR user.name="bob" | stats count by user.name"#,
        &deny,
        "metadata.log_source",
    )
    .unwrap();
    let parsed = parse_query(&enforced).unwrap();
    let profile: std::sync::Arc<dyn SchemaProfile> =
        std::sync::Arc::new(OcsfProfile::try_lake_1_9_with_snapshot_field_types(Default::default()).unwrap());
    let sql = ClickHouseSqlGenerator::with_table("__nano_lake_source__")
        .with_profile(profile)
        .generate_with_options(
            &parsed,
            &TimeRange::new(
                chrono::DateTime::parse_from_rfc3339("2026-09-01T00:00:00Z").unwrap().with_timezone(&chrono::Utc),
                chrono::DateTime::parse_from_rfc3339("2026-09-02T00:00:00Z").unwrap().with_timezone(&chrono::Utc),
            ),
            &QueryOptions { use_cache: false, table_view: false, limit: Some(100), unordered: false },
        )
        .unwrap();
    let where_clause = sql.split("WHERE").nth(1).expect("a WHERE clause");
    assert!(where_clause.contains("metadata.log_source"), "{sql}");
    assert!(where_clause.contains("NOT IN ('hec_windows')") || where_clause.contains("NOT IN ( 'hec_windows' )"), "{sql}");
    // The user's OR is parenthesized as one operand of the AND: the NOT IN
    // is a conjunct of the whole scan, never an OR arm.
    let not_in = where_clause.find("NOT IN").unwrap();
    let before = &where_clause[..not_in];
    assert!(before.trim_end().ends_with("AND") || before.contains(") AND"), "{sql}");
    assert!(!sql.contains("source_type"), "{sql}");
}

/// Member-initiated rule testing runs under the member's own set (no
/// peephole); the detection runtime reads the full lake, explicitly.
#[test]
fn rule_test_sees_nothing_from_a_denied_source_but_the_detection_runtime_sees_everything() {
    let rule = r#"metadata.log_source="hec_windows" user.name="bob" | stats count"#;
    let member = SourceVisibility::member(set(&["hec_windows"]));
    let tested = member.enforce_lake_query(rule).unwrap();
    assert!(rows_returned(&tested).is_empty(), "{tested}");

    let runtime = SourceVisibility::detection_runtime();
    let run = runtime.enforce_lake_query(rule).unwrap();
    assert_eq!(run, rule, "the runtime's query is byte-identical");
    assert_eq!(rows_returned(&run), vec!["evt-w1", "evt-w3"]);
    assert_eq!(runtime.bypass_label().as_deref(), Some("detection_runtime"));
    assert!(member.bypass_label().is_none());
}

/// A case participant sees exactly the attached evidence rows of a denied
/// source (`evt-w1`), and nothing else from it — including under adversarial
/// query shapes — while the rest of the lake stays under the member set.
#[test]
fn case_participant_sees_exactly_the_attached_evidence_from_a_denied_source() {
    let case_id = uuid::Uuid::from_u128(0xca5e);
    let scoped = SourceVisibility::CaseScoped {
        case_id,
        member_denied: set(&["hec_windows"]),
        evidence_uids: set(&["evt-w1", "evt-a1"]),
    };
    for query in ADVERSARIAL_QUERIES {
        let enforced = scoped.enforce_lake_query(query).unwrap_or_else(|e| panic!("{query}: {e}"));
        for uid in rows_returned(&enforced) {
            if source_of(&uid) == "hec_windows" {
                assert_eq!(uid, "evt-w1", "{query} → {enforced} leaked {uid}");
            }
        }
    }
    assert_eq!(rows_returned(&scoped.enforce_lake_query("bob").unwrap()), vec!["evt-w1", "evt-a1", "evt-d1"]);
    assert_eq!(rows_returned(&scoped.enforce_lake_query(r#"metadata.log_source="hec_windows""#).unwrap()), vec!["evt-w1"]);
    assert_eq!(scoped.bypass_label().as_deref(), Some(format!("case:{case_id}").as_str()));
    // A non-evidence uid guessed by the member is still hidden.
    assert!(rows_returned(&scoped.enforce_lake_query(r#"metadata.uid="evt-w2""#).unwrap()).is_empty());
}

#[test]
fn otlp_datasets_are_hidden_iff_their_route_slug_is_denied() {
    assert!(otlp_dataset_denied("spans", &set(&["otlp_trace"])));
    assert!(otlp_dataset_denied("metrics", &set(&["otlp_metric"])));
    assert!(!otlp_dataset_denied("spans", &set(&["otlp_metric"])));
    assert!(!otlp_dataset_denied("metrics", &set(&["otlp_trace", "hec_windows"])));
    assert!(!otlp_dataset_denied("logs", &set(&["otlp_trace", "otlp_metric"])));
    assert!(!otlp_dataset_denied("spans", &BTreeSet::new()));
    // The gate is the dataset branch of `SearchService::search` on the primary
    // lake; pin the call so the branch cannot be dropped silently.
    let core_search = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../nanosiem-core/src/search/service/core_search.rs"
    ))
    .expect("read core_search.rs");
    let branch = core_search.find("if is_primary_otel_request {").expect("native OTLP branch");
    let gate = core_search.find("otlp_dataset_denied(dataset, scope.deny_set())").expect("OTLP dataset gate");
    assert!(gate > branch, "the OTLP gate must sit inside the primary-lake OTLP branch");
}

/// NAN-2602: lake rows with no declared source are stored as `unknown`,
/// while the model / UI restrict the same bucket as `default`. The two are
/// ONE label ("Unattributed"): a member restricted from either spelling sees
/// neither, whatever the query; an unrestricted member sees both.
fn unattributed_rows() -> Vec<serde_json::Value> {
    [
        ("evt-u1", "unknown", "bob"),
        ("evt-u2", "unknown", "alice"),
        ("evt-d1", "default", "bob"),
        ("evt-w1", "hec_windows", "bob"),
    ]
    .iter()
    .map(|(uid, source, user)| {
        serde_json::json!({
            "metadata": {"uid": uid, "log_source": source},
            "user": {"name": user},
            "message": format!("{source} event for {user}"),
        })
    })
    .collect()
}

fn unattributed_rows_returned(enforced: &str) -> Vec<String> {
    let parsed = parse_query(enforced).expect("enforced query parses");
    let expr = base_expr(&parsed);
    unattributed_rows()
        .iter()
        .filter(|row| evaluate_condition_on_json(expr, row))
        .map(|row| row["metadata"]["uid"].as_str().unwrap().to_string())
        .collect()
}

/// Matches every synthetic row under the local evaluator (which, unlike the
/// lake, does not treat a bare `*` as match-all).
const ALL_ROWS: &str = r#"user.name="bob" OR user.name="alice""#;

const UNATTRIBUTED_PROBES: &[&str] = &[
    "*",
    ALL_ROWS,
    "bob",
    r#"metadata.log_source="unknown""#,
    r#"metadata.log_source="UNKNOWN""#,
    r#"metadata.log_source="default""#,
    r#"metadata.log_source IN ("unknown", "default")"#,
    r#"NOT metadata.log_source="hec_windows""#,
    r#"metadata.log_source!="hec_windows""#,
    r#"user.name="alice" OR metadata.log_source="unknown""#,
    r#"metadata.uid="evt-u1""#,
    r#"* | stats count by metadata.log_source"#,
];

#[test]
fn member_restricted_from_unattributed_sees_neither_unknown_nor_default_rows() {
    // The UI's one "Unattributed" option stores `default`; a stale API write
    // might have stored `unknown`. Either spelling denies both.
    for denied in [&["default"][..], &["unknown"][..], &["Default "][..]] {
        let member = SourceVisibility::member(set(denied));
        assert_eq!(member.deny_set(), &set(&["default", "unknown"]), "{denied:?}");
        for query in UNATTRIBUTED_PROBES {
            let enforced = member.enforce_lake_query(query).unwrap_or_else(|e| panic!("{query}: {e}"));
            assert!(
                enforced.contains(r#"metadata.log_source NOT IN ("default", "unknown")"#),
                "{denied:?} {query} → {enforced}"
            );
            for uid in unattributed_rows_returned(&enforced) {
                assert!(uid == "evt-w1", "{denied:?} {query} → {enforced} leaked {uid}");
            }
        }
        // Still sees the sources it is not denied.
        assert_eq!(unattributed_rows_returned(&member.enforce_lake_query("bob").unwrap()), vec!["evt-w1"]);
    }
    // Even a deny set that reached the lake gate WITHOUT going through the
    // member constructor (a raw wire / job set naming only `default`) fails
    // closed at the enforcement boundary.
    let raw = enforce_source_scope_with_field(ALL_ROWS, &set(&["default"]), "metadata.log_source").unwrap();
    assert!(unattributed_rows_returned(&raw) == vec!["evt-w1"], "{raw}");
    // A case participant restricted from Unattributed gets back exactly the
    // attached unattributed evidence and nothing else of that label.
    let scoped = SourceVisibility::CaseScoped {
        case_id: uuid::Uuid::from_u128(0x2602),
        member_denied: set(&["default"]),
        evidence_uids: set(&["evt-u2"]),
    };
    assert_eq!(unattributed_rows_returned(&scoped.enforce_lake_query(ALL_ROWS).unwrap()), vec!["evt-u2", "evt-w1"]);
}

#[test]
fn unrestricted_member_still_sees_unknown_and_default_rows() {
    let open = SourceVisibility::member(BTreeSet::new());
    assert_eq!(open.enforce_lake_query("*").unwrap(), "*");
    assert_eq!(unattributed_rows_returned(ALL_ROWS), vec!["evt-u1", "evt-u2", "evt-d1", "evt-w1"]);
    // Restricting another source leaves both unattributed spellings visible.
    let other = SourceVisibility::member(set(&["hec_windows"]));
    assert_eq!(other.deny_set(), &set(&["hec_windows"]));
    assert_eq!(unattributed_rows_returned(&other.enforce_lake_query(ALL_ROWS).unwrap()), vec!["evt-u1", "evt-u2", "evt-d1"]);
    // The detection runtime reads the full lake.
    assert_eq!(SourceVisibility::detection_runtime().enforce_lake_query("*").unwrap(), "*");
}

/// The generated lake SQL denies BOTH spellings on `metadata.log_source`.
#[test]
fn lake_sql_for_an_unattributed_restriction_denies_both_spellings() {
    let enforced = SourceVisibility::member(set(&["default"])).enforce_lake_query("user.name=\"bob\"").unwrap();
    let parsed = parse_query(&enforced).unwrap();
    let profile: std::sync::Arc<dyn SchemaProfile> =
        std::sync::Arc::new(OcsfProfile::try_lake_1_9_with_snapshot_field_types(Default::default()).unwrap());
    let sql = ClickHouseSqlGenerator::with_table("__nano_lake_source__")
        .with_profile(profile)
        .generate_with_options(
            &parsed,
            &TimeRange::new(
                chrono::DateTime::parse_from_rfc3339("2026-09-01T00:00:00Z").unwrap().with_timezone(&chrono::Utc),
                chrono::DateTime::parse_from_rfc3339("2026-09-02T00:00:00Z").unwrap().with_timezone(&chrono::Utc),
            ),
            &QueryOptions { use_cache: false, table_view: false, limit: Some(100), unordered: false },
        )
        .unwrap();
    let where_clause = sql.split("WHERE").nth(1).expect("a WHERE clause");
    assert!(where_clause.contains("NOT IN ('default', 'unknown')"), "{sql}");
}

/// The legacy ClickHouse `source_type` gate is not touched by the lake
/// label: dedicated deployments keep their exact deny set.
#[test]
fn clickhouse_source_type_gate_is_unchanged_by_the_lake_label() {
    let enforced = enforce_source_scope_with_field("*", &set(&["default"]), "source_type").unwrap();
    assert!(enforced.contains(r#"source_type NOT IN ("default")"#) || enforced.contains(r#"source_type!="default""#), "{enforced}");
    assert!(!enforced.contains("unknown"), "{enforced}");
}

/// NAN-3224: `metadata.log_source=risk` is a query-time alias of the findings
/// that added risk. A member denied `findings` gets nothing through the
/// alias, however it is spelled; a member who may see findings gets exactly
/// the scored ones; and nothing named `risk` exists to be denied separately.
#[test]
fn risk_alias_is_gated_exactly_like_findings() {
    let rows = [
        ("fnd-1", "findings", 40),
        ("fnd-0", "findings", 0),
        ("evt-a1", "apache", 90),
    ]
    .iter()
    .map(|(uid, source, score)| {
        // The JSON evaluator resolves each source spelling literally, so the
        // rows carry every spelling the aliases use.
        serde_json::json!({
            "metadata": {"uid": uid, "log_source": source},
            "source_type": source,
            "sourcetype": source,
            "risk_score": score,
        })
    })
    .collect::<Vec<_>>();
    let returned = |enforced: &str| {
        let parsed = parse_query(enforced).expect("enforced query parses");
        rows.iter()
            .filter(|row| evaluate_condition_on_json(base_expr(&parsed), row))
            .map(|row| row["metadata"]["uid"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    let aliases = [
        "metadata.log_source=risk",
        "source_type=risk",
        "sourcetype=risk",
        r#"metadata.log_source="RISK" OR metadata.log_source="apache""#,
        "metadata.log_source IN (risk, apache)",
        "metadata.log_source=risk | stats sum(risk_score) by resources.name",
    ];

    let denied = SourceVisibility::member(set(&["findings"]));
    for query in aliases {
        let enforced = denied.enforce_lake_query(query).unwrap_or_else(|e| panic!("{query}: {e}"));
        let leaked = returned(&enforced);
        assert!(
            !leaked.iter().any(|uid| uid.starts_with("fnd-")),
            "{query} → {enforced} leaked {leaked:?}"
        );
        assert!(enforced.contains(r#"NOT IN ("findings")"#), "{query} → {enforced}");
    }

    let allowed = SourceVisibility::member(set(&["apache"]));
    assert_eq!(returned(&allowed.enforce_lake_query("metadata.log_source=risk").unwrap()), vec!["fnd-1"]);
    let runtime = SourceVisibility::detection_runtime();
    assert_eq!(returned(&runtime.enforce_lake_query("source_type=risk").unwrap()), vec!["fnd-1"]);
}
