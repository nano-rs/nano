// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5697: a `dataset=risk` notable is attributed to the persisted origins
//! of the findings that built its entity's score, not to the fail-closed
//! stamp. Before the fix every risk notable carried
//! `['__nano:unresolved_source__', 'audit']`, so every non-admin analyst got
//! 404 on it.
//!
//! As in `source_stamp_tests`, the Postgres `source_types && $deny` overlap is
//! modelled by hand; the SQL predicate itself is pinned by the
//! `AlertRepository::scope_clause` tests.

use std::collections::BTreeSet;

use serde_json::json;

use super::alerts::fold_overflow_provenance;
use super::execution::{fail_closed_stamp, risk_origin_stamp, risk_row_entities};
use super::provenance::RowProvenance;
use crate::auth::{deny_bind_values, UNRESOLVED_SOURCE_SENTINEL};
use crate::db::repository::alerts::distinct_source_types;
use crate::risk::clickhouse_sql::RiskOriginRow;

fn deny(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|s| s.to_string()).collect()
}

/// `true` = the row is HIDDEN from a principal with this deny set.
fn hidden(stamped: &[String], denied: &BTreeSet<String>) -> bool {
    let bind = deny_bind_values(denied);
    stamped.iter().any(|s| bind.contains(s))
}

fn origin(entity: &str, origins: &[&str], unresolved: u64) -> RiskOriginRow {
    RiskOriginRow {
        entity: entity.to_string(),
        origin_source_types: origins.iter().map(|s| s.to_string()).collect(),
        unresolved,
    }
}

/// The notable's stored `alerts.source_types`, built exactly as
/// `create_alert` builds it from the stamped row.
fn notable_source_types(stamp: serde_json::Value) -> Vec<String> {
    distinct_source_types(&json!([{
        "entity": "rba-user", "entity_type": "user", "score_24h": 60,
        "_nano_source_types": stamp,
    }]))
}

/// An analyst with `alerts:view` + `risk:view` and no per-source restriction
/// (deny set = the implicit `audit` only) can open the notable; one denied a
/// contributing source cannot.
#[test]
fn allowed_analyst_sees_the_notable_and_a_source_restricted_one_does_not() {
    let manifest = [origin("rba-user", &["Windows_Event", " okta "], 0)];
    let stamp = risk_origin_stamp(&manifest, Some("rba-user")).expect("attributed");
    let stored = notable_source_types(stamp);
    assert_eq!(stored, vec!["okta".to_string(), "windows_event".to_string()]);

    let analyst = deny(&["audit"]);
    assert!(!hidden(&stored, &analyst), "allowed analyst must see the notable: {stored:?}");
    assert!(!hidden(&stored, &deny(&["audit", "insider_threat"])), "an unrelated restriction does not hide it");
    assert!(!hidden(&stored, &BTreeSet::new()), "unrestricted admin sees it");

    for restricted in [deny(&["audit", "windows_event"]), deny(&["okta"])] {
        assert!(
            hidden(&stored, &restricted),
            "a viewer denied a contributing source must not see the notable ({restricted:?})"
        );
    }
}

/// Risk from an audit-origin rule keeps the audit gate.
#[test]
fn an_audit_contribution_keeps_the_notable_from_non_audit_viewers() {
    let stamp = risk_origin_stamp(&[origin("rba-user", &["audit", "okta"], 0)], Some("rba-user")).unwrap();
    let stored = notable_source_types(stamp);
    assert!(hidden(&stored, &deny(&["audit"])));
    assert!(!hidden(&stored, &BTreeSet::new()));
}

/// Legacy findings without persisted origins: the read path hides them from
/// restricted viewers (`notEmpty(origin_source_types)`), so the notable does
/// too, even when its other contributors are allowed.
#[test]
fn a_contributor_without_origin_fails_closed_for_restricted_viewers() {
    let stamp = risk_origin_stamp(&[origin("rba-user", &["okta"], 2)], Some("rba-user")).unwrap();
    let stored = notable_source_types(stamp);
    assert!(stored.contains(&UNRESOLVED_SOURCE_SENTINEL.to_string()));
    assert!(hidden(&stored, &deny(&["audit"])));
    assert!(!hidden(&stored, &BTreeSet::new()));
}

/// Another entity's findings never attribute this row; a row with no
/// manifest at all is not attributable (the caller fails closed).
#[test]
fn rows_are_attributed_per_entity_and_missing_manifests_are_not_attributed() {
    let manifest = [origin("alice", &["okta"], 0), origin("bob", &["insider_threat"], 0)];
    let alice = risk_origin_stamp(&manifest, Some("alice")).unwrap();
    assert_eq!(alice, json!(["okta"]));
    assert_eq!(risk_origin_stamp(&manifest, Some("carol")), None);
    assert_eq!(risk_origin_stamp(&[origin("alice", &[], 0)], Some("alice")), None, "no origins at all");
    assert_eq!(risk_origin_stamp(&[], None), None);
    // Whole-window form: the union of every manifest row.
    assert_eq!(risk_origin_stamp(&manifest, None).unwrap(), json!(["insider_threat", "okta"]));
}

/// The fail-closed fallback is unchanged and still hides the row from every
/// non-admin, which is why the producer must not reach it in the normal case.
#[test]
fn the_fail_closed_fallback_is_what_produced_the_404() {
    let stored = notable_source_types(fail_closed_stamp(&BTreeSet::new()));
    assert!(hidden(&stored, &deny(&["audit"])));
}

#[test]
fn rows_key_by_entity_only_when_the_rule_cannot_rewrite_it() {
    let rows = vec![
        json!({"entity": "bob", "score_24h": 5}),
        json!({"entity": "alice", "score_24h": 9}),
        json!({"entity": "alice", "score_24h": 9}),
    ];
    assert_eq!(risk_row_entities(&rows, true), Some(vec!["alice".to_string(), "bob".to_string()]));
    assert_eq!(risk_row_entities(&rows, false), None, "rule-written entity: whole window");
    // An aggregate row with no entity: whole window for every row.
    let agg = vec![json!({"entity": "alice"}), json!({"count": 3})];
    assert_eq!(risk_row_entities(&agg, true), None);
    assert_eq!(risk_row_entities(&[json!({"entity": ""})], true), None);
    // Rows that carry their own source_type take no stamp and need no key.
    let mixed = vec![json!({"entity": "alice"}), json!({"source_type": "okta", "count": 1})];
    assert_eq!(risk_row_entities(&mixed, true), Some(vec!["alice".to_string()]));
}

#[test]
fn only_entity_local_pipelines_key_rows_by_entity() {
    for q in [
        "entity=\"rba-user\" | where score_24h > 0",
        "* | where score_24h > 50 OR score_7d > 100",
        "* | sort -score_24h | table entity, score_24h",
        "* | eval band=if(score_24h > 100, \"high\", \"low\") | fields entity, band",
        "* | rename last_rule_name AS rule | reverse",
        "* | stats max(score_24h) as peak by entity",
    ] {
        assert!(crate::query::parse_query(q).is_ok(), "fixture must parse: {q}");
        assert!(RowProvenance::for_rule_query(q).risk_rows_entity_local, "{q}");
    }
    for q in [
        // Rewrites `entity`.
        "* | eval entity=\"alice\"",
        "* | rename last_rule_name AS entity",
        "* | table last_rule_name AS entity, score_24h",
        "* | stats max(score_24h) as entity by entity_type",
        // Review P1: cross-row stages keep `entity` but copy other rows' data.
        "score_24h > 0 | eventstats max(score_24h) as max_score, values(entity) as all_entities | where entity=\"alice\"",
        "score_24h > 0 | eventstats avg(score_24h) as peer_avg, count() as peer_count by entity_type | where score_24h > peer_avg",
        "score_24h > 0 | eventstats max(score_24h) as m by entity",
        "score_24h > 0 | streamstats current=false last(entity) as prev_entity, last(score_24h) as prev_score",
        "score_24h > 0 | top entity",
        "score_24h > 0 | rare entity",
        "score_24h > 0 | chart count by entity",
        "score_24h > 0 | stats count by entity, entity_type",
        "score_24h > 0 | stats values(entity) as e by entity_type",
        "score_24h > 0 | lookup entity_tags entity",
        // Rank-dependent selection (explicit sort or the grain's default order).
        "* | sort -score_24h | head 10 | table entity, score_24h",
        "* | sort -score_24h | head 2 | tail 1",
        "* | sort score_24h | dedup entity_type",
        "* | head 5",
        "* | tail 5",
        "* | dedup entity",
    ] {
        // Each case must PARSE, or the assertion would pass vacuously on the
        // unparseable-fails-closed branch below.
        assert!(crate::query::parse_query(q).is_ok(), "fixture must parse: {q}");
        assert!(!RowProvenance::for_rule_query(q).risk_rows_entity_local, "{q}");
    }
    assert!(!RowProvenance::for_rule_query("score_24h > | | (").risk_rows_entity_local);
}

/// Review P1 leak scenario: `alice` (okta) and `bob` (restricted
/// `insider_threat`); a cross-row stage copies bob's data onto alice's row.
/// The rule is not entity-local, so every row is attributed to the whole
/// window, and an analyst denied `insider_threat` must NOT see the notable.
#[test]
fn a_cross_row_stage_hides_the_notable_from_a_viewer_denied_any_entity_in_the_window() {
    let rows = vec![json!({
        "entity": "alice", "score_24h": 60, "max_score": 200, "all_entities": ["alice", "bob"],
    })];
    let q = "score_24h > 0 | eventstats max(score_24h) as max_score, values(entity) as all_entities | where entity=\"alice\"";
    let keys = risk_row_entities(&rows, RowProvenance::for_rule_query(q).risk_rows_entity_local);
    assert_eq!(keys, None, "cross-row rule must use the whole-window manifest");
    // The whole-window manifest is a single row covering every entity.
    let manifest = [origin("", &["okta", "insider_threat"], 0)];
    let stored = notable_source_types(risk_origin_stamp(&manifest, None).unwrap());
    assert!(hidden(&stored, &deny(&["audit", "insider_threat"])), "{stored:?}");
    assert!(!hidden(&stored, &BTreeSet::new()));
}

/// Rank leak: `bob` (restricted `insider_threat`, score 200) outranks `alice`
/// (okta, 60) and is cut by the selection; alice's surviving row reveals that
/// a higher-scoring entity exists. The rule is not entity-local, so the row
/// takes the whole-window union and an analyst denied `insider_threat` must
/// NOT see the notable.
#[test]
fn a_rank_selection_that_cuts_a_denied_entity_hides_the_notable() {
    let q = "* | sort -score_24h | head 2 | tail 1";
    assert!(crate::query::parse_query(q).is_ok());
    let surviving = vec![json!({"entity": "alice", "score_24h": 60})];
    assert_eq!(
        risk_row_entities(&surviving, RowProvenance::for_rule_query(q).risk_rows_entity_local),
        None,
        "a rank selection must use the whole-window manifest"
    );
    let manifest = [origin("", &["okta", "insider_threat"], 0)];
    let stored = notable_source_types(risk_origin_stamp(&manifest, None).unwrap());
    assert!(hidden(&stored, &deny(&["audit", "insider_threat"])), "{stored:?}");
    assert!(!hidden(&stored, &deny(&["audit"])), "an analyst denied nothing in the window still sees it");

    // The same rule without the selection keeps the precise per-entity stamp.
    let q = "* | sort -score_24h";
    let keys = risk_row_entities(&surviving, RowProvenance::for_rule_query(q).risk_rows_entity_local);
    assert_eq!(keys, Some(vec!["alice".to_string()]));
    let own = [origin("alice", &["okta"], 0), origin("bob", &["insider_threat"], 0)];
    let stored = notable_source_types(risk_origin_stamp(&own, Some("alice")).unwrap());
    assert!(!hidden(&stored, &deny(&["audit", "insider_threat"])));
}

// ---------------------------------------------------------------------------
// Review P1: grouped alerts store a capped sample of their rows
// ---------------------------------------------------------------------------

fn risk_row(entity: &str, origin: &str) -> serde_json::Value {
    json!({"entity": entity, "score_24h": 60, "_nano_source_types": [origin]})
}

/// 105 entities match, the alert stores the first 100; entity 101 (`bob`)
/// comes only from restricted `insider_threat`. The stored alert and every
/// grouped finding (whose origin `FindingEvent::alert` derives from the stored
/// sample) must still carry `insider_threat`, so an analyst denied it sees
/// neither the alert nor bob's finding.
#[test]
fn rows_past_the_alert_sample_cap_still_stamp_the_alert_and_its_findings() {
    let mut results: Vec<serde_json::Value> = (0..105).map(|i| risk_row(&format!("u{i}"), "okta")).collect();
    results[101] = risk_row("bob", "insider_threat");
    let mut sample: Vec<serde_json::Value> = results[..100].to_vec();
    fold_overflow_provenance(&mut sample, &results[100..]);

    let stored = distinct_source_types(&serde_json::Value::Array(sample.clone()));
    assert_eq!(stored, vec!["insider_threat".to_string(), "okta".to_string()]);
    let restricted = deny(&["audit", "insider_threat"]);
    assert!(hidden(&stored, &restricted), "alert leaked past the sample cap");
    assert!(!hidden(&stored, &deny(&["audit"])), "an allowed analyst still sees it");

    let finding_origin = crate::detection::findings::FindingEvent::origin_source_types_from(&sample);
    assert!(
        finding_origin.contains(&"insider_threat".to_string()),
        "bob's finding would be written with laundered origins: {finding_origin:?}"
    );
    // Only the `_nano_` annotation changed: the row data is the same.
    assert_eq!(sample.len(), 100);
    assert_eq!(sample[0]["entity"], "u0");
}

#[test]
fn no_overflow_leaves_the_sample_untouched() {
    let results = vec![risk_row("alice", "okta")];
    let mut sample = results.clone();
    fold_overflow_provenance(&mut sample, &[]);
    assert_eq!(sample, results);
}

/// A sample with no provenance anywhere must not become "attributed" through
/// the fold (the webhook would stop redacting it): it gains the sentinel too.
#[test]
fn an_unattributed_sample_stays_unresolved_after_the_fold() {
    let mut sample = vec![json!({"message": "x"})];
    fold_overflow_provenance(&mut sample, &[json!({"source_type": "okta"})]);
    let stored = distinct_source_types(&serde_json::Value::Array(sample));
    assert!(stored.contains(&UNRESOLVED_SOURCE_SENTINEL.to_string()), "{stored:?}");
    assert!(stored.contains(&"okta".to_string()));
}

/// A raw row keeps its own `source_type`; the fold adds the overflow's
/// origins beside it.
#[test]
fn the_fold_adds_to_a_raw_row_without_dropping_its_own_origin() {
    let mut sample = vec![json!({"source_type": "okta", "user": "a"})];
    fold_overflow_provenance(&mut sample, &[json!({"source_type": "insider_threat"})]);
    let stored = distinct_source_types(&serde_json::Value::Array(sample));
    assert_eq!(stored, vec!["insider_threat".to_string(), "okta".to_string()]);
}
