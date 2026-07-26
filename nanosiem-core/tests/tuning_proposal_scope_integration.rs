// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2085 / NAN-2088 — DB-backed matrix for AI tuning artifact provenance.
//!
//! Proposals persist exact values lifted out of matched events (NAN-2085) and a
//! restricted source's exact volume / field occupancy / peak counts
//! (NAN-2088), and were served under `detections:view` alone with no record of
//! their origin. These tests run the REAL repository SQL against a migrated
//! Postgres to prove:
//!
//! * a proposal derived only from a denied source is absent from `list` and
//!   `get` (identical to a nonexistent id — no existence oracle);
//! * the tuning LOG that nests the same proposal is filtered identically, which
//!   is the alternate path to the same bytes;
//! * a mixed-source proposal is hidden if ANY contributor is denied;
//! * a legacy proposal with no provenance fails CLOSED for restricted readers
//!   and stays visible to unrestricted ones;
//! * restricting a source AFTER generation revokes access on the next read.
//!
//! `tuning_proposals` is enterprise-stripped from the open fresh-init snapshot,
//! so this suite applies the enterprise overlay (which is also where the
//! `source_types` columns live). `#[ignore]`d like the sibling DB suites.

mod common;

use nanosiem_core::tuning::{
    ProposalType, TuningLogEntry, TuningRepository, TuningScope, TuningStatus,
};
use sqlx::PgPool;
use std::collections::BTreeSet;
use tokio::sync::OnceCell;
use uuid::Uuid;

static ENTERPRISE_MIGRATED: OnceCell<()> = OnceCell::const_new();

async fn enterprise_pool() -> PgPool {
    let pool = common::migrated_pool().await;
    ENTERPRISE_MIGRATED
        .get_or_init(|| async {
            let mut migrator = sqlx::migrate!("../migrations/postgres-enterprise");
            migrator.set_ignore_missing(true);
            migrator
                .run(&pool)
                .await
                .expect("apply enterprise PostgreSQL overlay");
        })
        .await;
    pool
}

fn deny(values: &[&str]) -> TuningScope {
    let set: BTreeSet<String> = values.iter().map(|s| s.to_string()).collect();
    TuningScope::from_denied(&set)
}

async fn insert_rule(pool: &PgPool) -> Uuid {
    let rule_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO detection_rules (id, name, description, query, severity, mode)
        VALUES ($1, $2, 'NAN-2085 scope test', 'source_type=apache', 'medium', 'alerting')
        "#,
    )
    .bind(rule_id)
    .bind(format!("NAN-2085-{rule_id}"))
    .execute(pool)
    .await
    .expect("insert rule");
    rule_id
}

/// Insert a proposal through the REAL repository so the stamping path
/// (normalization + the "empty manifest can never be complete" rule) is under
/// test too, not just the read filter.
///
/// `proposal_type` is a parameter because `uq_tuning_proposals_open_rule_type`
/// allows at most ONE open proposal per (rule, type) — tests that need several
/// proposals on one rule vary the type rather than the rule, so the rule_id
/// filter on `list_proposals` still exercises a multi-row page.
async fn insert_proposal_of_type(
    repo: &TuningRepository,
    rule_id: Uuid,
    proposal_type: ProposalType,
    source_types: &[&str],
    complete: bool,
) -> Uuid {
    let proposal = nanosiem_core::tuning::TuningProposal {
        id: Uuid::now_v7(),
        rule_id,
        rule_name: None,
        created_at: chrono::Utc::now(),
        proposal_type,
        original_query: "source_type=apache".to_string(),
        proposed_query: "source_type=apache AND user!=\"svc-secret\"".to_string(),
        rationale: "restricted-source username appears here".to_string(),
        confidence_score: 0.8,
        changes_summary: vec!["excluded svc-secret".to_string()],
        affected_patterns: Vec::new(),
        source_types: source_types.iter().map(|s| s.to_string()).collect(),
        source_types_complete: complete,
        safety_validation: nanosiem_core::tuning::SafetyValidation {
            is_safe: true,
            critical_indicators_preserved: true,
            validation_checks: Vec::new(),
            warnings: Vec::new(),
        },
        status: TuningStatus::Proposed,
        current_hints: None,
        proposed_hints: None,
        hints_diff: None,
        pr_url: None,
        pr_number: None,
        pr_state: None,
    };
    let id = proposal.id;
    repo.create_proposal(&proposal)
        .await
        .expect("create proposal");
    id
}

async fn insert_proposal(
    repo: &TuningRepository,
    rule_id: Uuid,
    source_types: &[&str],
    complete: bool,
) -> Uuid {
    insert_proposal_of_type(
        repo,
        rule_id,
        ProposalType::QueryTuning,
        source_types,
        complete,
    )
    .await
}

async fn insert_log(repo: &TuningRepository, rule_id: Uuid, proposal_id: Uuid) -> Uuid {
    let proposal = repo
        .get_proposal(proposal_id, &TuningScope::system())
        .await
        .expect("load proposal")
        .expect("proposal exists");
    repo.create_log_entry(TuningLogEntry {
        id: Uuid::now_v7(),
        rule_id,
        rule_name: "nan2085".to_string(),
        triggered_at: chrono::Utc::now(),
        trigger_reason: "test".to_string(),
        proposal,
        test_results: None,
        staging_deployment: None,
        status: TuningStatus::Proposed,
        reverted_at: None,
        reverted_by: None,
        revert_reason: None,
    })
    .await
    .expect("create log entry")
}

async fn listed_ids(repo: &TuningRepository, rule_id: Uuid, scope: &TuningScope) -> Vec<Uuid> {
    repo.list_proposals(Some(rule_id), None, None, 100, 0, scope)
        .await
        .expect("list proposals")
        .into_iter()
        .map(|p| p.id)
        .collect()
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn a_denied_source_proposal_is_absent_from_list_and_get() {
    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;

    let denied = insert_proposal(&repo, rule_id, &["insider_threat"], true).await;
    let granted =
        insert_proposal_of_type(&repo, rule_id, ProposalType::HintUpdate, &["apache"], true).await;

    let scope = deny(&["insider_threat"]);

    let ids = listed_ids(&repo, rule_id, &scope).await;
    assert!(!ids.contains(&denied));
    assert!(ids.contains(&granted));

    assert!(repo
        .get_proposal(denied, &scope)
        .await
        .expect("get")
        .is_none());
    assert!(repo
        .get_proposal(granted, &scope)
        .await
        .expect("get")
        .is_some());

    // An unrestricted reader still sees both.
    let all = listed_ids(&repo, rule_id, &TuningScope::system()).await;
    assert!(all.contains(&denied) && all.contains(&granted));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn every_list_filter_combination_binds_in_the_right_order_with_a_scope() {
    // `list_proposals` builds its SQL by hand and numbers placeholders as it
    // appends. The scope predicate slots in AFTER the filters and BEFORE
    // limit/offset, so a mis-numbered bind would either error or — worse —
    // silently compare the wrong values. Exercise every filter combination.
    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let visible = insert_proposal(&repo, rule_id, &["apache"], true).await;
    let scope = deny(&["insider_threat"]);

    for (rule, status, ptype) in [
        (None, None, None),
        (Some(rule_id), None, None),
        (None, Some(TuningStatus::Proposed), None),
        (None, None, Some(ProposalType::QueryTuning)),
        (Some(rule_id), Some(TuningStatus::Proposed), None),
        (
            Some(rule_id),
            Some(TuningStatus::Proposed),
            Some(ProposalType::QueryTuning),
        ),
    ] {
        let ids: Vec<Uuid> = repo
            .list_proposals(rule, status, ptype, 500, 0, &scope)
            .await
            .expect("list proposals")
            .into_iter()
            .map(|p| p.id)
            .collect();
        assert!(
            ids.contains(&visible),
            "filters rule={rule:?} status={status:?} type={ptype:?} lost a visible proposal"
        );
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn a_denied_proposal_and_a_nonexistent_one_are_indistinguishable() {
    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let denied = insert_proposal(&repo, rule_id, &["insider_threat"], true).await;
    let scope = deny(&["insider_threat"]);

    let denied_result = repo.get_proposal(denied, &scope).await.expect("get");
    let ghost_result = repo
        .get_proposal(Uuid::now_v7(), &scope)
        .await
        .expect("get");
    assert!(denied_result.is_none() && ghost_result.is_none());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn a_mixed_source_proposal_is_hidden_if_any_contributor_is_denied() {
    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let mixed = insert_proposal(&repo, rule_id, &["apache", "insider_threat"], true).await;

    assert!(repo
        .get_proposal(mixed, &deny(&["insider_threat"]))
        .await
        .expect("get")
        .is_none());
    assert!(repo
        .get_proposal(mixed, &deny(&["something_else"]))
        .await
        .expect("get")
        .is_some());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn a_legacy_proposal_without_provenance_fails_closed_for_restricted_readers() {
    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;

    // Exactly what a pre-feature row carries: '{}' + FALSE.
    let legacy = insert_proposal(&repo, rule_id, &[], false).await;
    // A producer that CLAIMS completeness with an empty manifest must not be
    // able to fabricate visibility — create_proposal downgrades it.
    let lying = insert_proposal_of_type(&repo, rule_id, ProposalType::HintUpdate, &[], true).await;

    let scope = deny(&["insider_threat"]);
    assert!(repo
        .get_proposal(legacy, &scope)
        .await
        .expect("get")
        .is_none());
    assert!(
        repo.get_proposal(lying, &scope)
            .await
            .expect("get")
            .is_none(),
        "an empty manifest can never be complete"
    );

    // Unrestricted readers are unaffected — the gate is not a global outage.
    assert!(repo
        .get_proposal(legacy, &TuningScope::system())
        .await
        .expect("get")
        .is_some());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn restricting_a_source_after_generation_revokes_the_proposal() {
    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let proposal = insert_proposal(&repo, rule_id, &["late_restricted"], true).await;

    // Before the restriction the reader can see it…
    assert!(repo
        .get_proposal(proposal, &deny(&["other"]))
        .await
        .expect("get")
        .is_some());
    // …and after, the SAME stored row is gone. Visibility is re-evaluated on
    // every read rather than frozen at generation time.
    assert!(repo
        .get_proposal(proposal, &deny(&["late_restricted"]))
        .await
        .expect("get")
        .is_none());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn manifest_matching_is_case_and_whitespace_insensitive() {
    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    // Stored un-normalized by a careless producer; create_proposal normalizes.
    let proposal = insert_proposal(&repo, rule_id, &["  Insider_Threat "], true).await;

    assert!(repo
        .get_proposal(proposal, &deny(&["insider_threat"]))
        .await
        .expect("get")
        .is_none());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn tuning_logs_inherit_the_nested_proposals_scope() {
    // The log is the alternate path to the same bytes — it INNER JOINs the
    // proposal and returns its full text.
    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;

    let denied_proposal = insert_proposal(&repo, rule_id, &["insider_threat"], true).await;
    let granted_proposal =
        insert_proposal_of_type(&repo, rule_id, ProposalType::HintUpdate, &["apache"], true).await;
    let denied_log = insert_log(&repo, rule_id, denied_proposal).await;
    let granted_log = insert_log(&repo, rule_id, granted_proposal).await;

    let scope = deny(&["insider_threat"]);

    assert!(repo
        .get_log_entry(denied_log, &scope)
        .await
        .expect("get log")
        .is_none());
    assert!(repo
        .get_log_entry(granted_log, &scope)
        .await
        .expect("get log")
        .is_some());

    let for_rule: Vec<Uuid> = repo
        .get_logs_for_rule(rule_id, &scope)
        .await
        .expect("logs for rule")
        .into_iter()
        .map(|l| l.id)
        .collect();
    assert!(!for_rule.contains(&denied_log));
    assert!(for_rule.contains(&granted_log));

    // The cross-rule feed behind `GET /api/tuning/logs` with no rule filter —
    // the widest read in the module.
    let recent: Vec<Uuid> = repo
        .get_recent_logs(500, &scope)
        .await
        .expect("recent logs")
        .into_iter()
        .map(|l| l.id)
        .collect();
    assert!(!recent.contains(&denied_log));

    // System callers still see everything.
    assert!(repo
        .get_log_entry(denied_log, &TuningScope::system())
        .await
        .expect("get log")
        .is_some());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn upgrading_a_silent_proposal_restamps_its_provenance() {
    // NAN-2088: the upgraded rationale is re-derived from fresh signals, so a
    // stale (permissive) manifest must not survive.
    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let proposal = insert_proposal(&repo, rule_id, &["apache"], true).await;

    let upgraded = repo
        .upgrade_silent_proposal(
            proposal,
            "now describes insider_threat volume",
            0.9,
            &["tier upgrade".to_string()],
            &["insider_threat".to_string()],
            true,
        )
        .await
        .expect("upgrade");
    assert!(upgraded);

    assert!(repo
        .get_proposal(proposal, &deny(&["insider_threat"]))
        .await
        .expect("get")
        .is_none());
    assert!(repo
        .get_proposal(proposal, &deny(&["apache"]))
        .await
        .expect("get")
        .is_some());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn an_open_ended_silent_rule_upgrade_fails_closed() {
    // A rule with no source_type filter queries across everything: empty
    // manifest, not complete, denied to every restricted reader.
    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let proposal = insert_proposal(&repo, rule_id, &["apache"], true).await;

    assert!(repo
        .upgrade_silent_proposal(
            proposal,
            "open-ended rule",
            0.9,
            &["tier upgrade".to_string()],
            &[],
            false,
        )
        .await
        .expect("upgrade"));

    assert!(repo
        .get_proposal(proposal, &deny(&["anything"]))
        .await
        .expect("get")
        .is_none());
}

// ---------------------------------------------------------------------------
// codex round 1 — independently-derived and mutation-side gaps.
// ---------------------------------------------------------------------------

/// Attach a validation result to a log. `comparison_metrics.pattern_changes`
/// stores raw matched-field values from an independent replay, and the alert
/// counts span every source the rule touches — none of it provenance-stamped.
async fn attach_test_result(pool: &PgPool, proposal_id: Uuid, log_id: Uuid) {
    let test_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO tuning_test_results (
            id, proposal_id, tested_at, original_alert_count, tuned_alert_count,
            reduction_percentage, true_positives_preserved, validation_passed,
            comparison_metrics
        )
        VALUES ($1, $2, NOW(), 100, 40, 60.0, true, true,
                '{"alerts_removed":60,"alerts_preserved":40,"unique_entities_removed":3,
                  "severity_distribution_change":{},
                  "pattern_changes":[{"field_name":"src_user","field_value":"svc-secret",
                                      "before_count":60,"after_count":0}]}'::jsonb)
        "#,
    )
    .bind(test_id)
    .bind(proposal_id)
    .execute(pool)
    .await
    .expect("insert test result");

    sqlx::query("UPDATE tuning_logs SET test_results_id = $1 WHERE id = $2")
        .bind(test_id)
        .bind(log_id)
        .execute(pool)
        .await
        .expect("attach test result");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn un_provenanced_validation_results_are_withheld_from_restricted_readers() {
    // The proposal's manifest cannot authorize the replay payload: the replay
    // runs over the rule's whole window, so it can surface values from sources
    // that never appeared in the proposal's samples.
    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let proposal = insert_proposal(&repo, rule_id, &["apache"], true).await;
    let log_id = insert_log(&repo, rule_id, proposal).await;
    attach_test_result(&pool, proposal, log_id).await;

    // Unrestricted reader gets the validation payload as before.
    let unrestricted = repo
        .get_log_entry(log_id, &TuningScope::system())
        .await
        .expect("get log")
        .expect("visible");
    assert!(unrestricted.test_results.is_some());

    // A restricted reader still sees the log (its proposal is disjoint) but
    // NOT the un-provenanced replay data.
    let restricted = repo
        .get_log_entry(log_id, &deny(&["insider_threat"]))
        .await
        .expect("get log")
        .expect("proposal is visible to this reader");
    assert!(
        restricted.test_results.is_none(),
        "replay results carry no provenance and must be withheld"
    );

    for entry in repo
        .get_logs_for_rule(rule_id, &deny(&["insider_threat"]))
        .await
        .expect("logs for rule")
    {
        assert!(entry.test_results.is_none());
    }
    for entry in repo
        .get_recent_logs(500, &deny(&["insider_threat"]))
        .await
        .expect("recent logs")
        .into_iter()
        .filter(|l| l.id == log_id)
    {
        assert!(entry.test_results.is_none());
    }
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn a_status_transition_cannot_action_a_proposal_restamped_onto_a_denied_source() {
    // The handler's preflight `get_proposal` is check-then-act: the silent-rule
    // detector can restamp `source_types` on a still-open proposal. The deny
    // scope therefore rides inside the compare-and-set.
    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let proposal = insert_proposal(&repo, rule_id, &["apache"], true).await;

    // Simulate the concurrent restamp.
    assert!(repo
        .upgrade_silent_proposal(
            proposal,
            "restamped",
            0.9,
            &["restamped".to_string()],
            &["insider_threat".to_string()],
            true,
        )
        .await
        .expect("restamp"));

    // The actor that read it while stamped `apache` can no longer transition it.
    assert!(
        !repo
            .transition_proposal_status(
                proposal,
                &[TuningStatus::Proposed],
                TuningStatus::Rejected,
                Some("stale read"),
                &deny(&["insider_threat"]),
            )
            .await
            .expect("transition"),
        "a proposal restamped onto a denied source must not be actionable"
    );

    let status: String = sqlx::query_scalar("SELECT status FROM tuning_proposals WHERE id = $1")
        .bind(proposal)
        .fetch_one(&pool)
        .await
        .expect("read status");
    assert_eq!(status, "proposed", "the write must not have happened");

    // An unrestricted actor still can.
    assert!(repo
        .transition_proposal_status(
            proposal,
            &[TuningStatus::Proposed],
            TuningStatus::Rejected,
            Some("ok"),
            &TuningScope::system(),
        )
        .await
        .expect("transition"));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn the_atomic_apply_rechecks_scope_under_the_row_lock() {
    use nanosiem_core::tuning::{
        AtomicProposalApplyError, AtomicProposalApplyRequest, ProposalRuleMutation,
    };

    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let proposal = insert_proposal(&repo, rule_id, &["insider_threat"], true).await;

    let err = repo
        .apply_proposal_atomic(AtomicProposalApplyRequest {
            proposal_id: proposal,
            target_status: TuningStatus::ManuallyApproved,
            mutation: ProposalRuleMutation::Query {
                query: "source_type=apache AND user!=\"svc-secret\"".to_string(),
                created_by: None,
                change_reason: "scope regression".to_string(),
            },
            reviewer_notes: None,
            log_trigger_reason: "scope regression".to_string(),
            scope: deny(&["insider_threat"]),
        })
        .await
        .expect_err("a denied proposal must not be applicable");

    // Reported exactly like a missing proposal — no existence oracle.
    assert!(
        matches!(err, AtomicProposalApplyError::ProposalNotFound(id) if id == proposal),
        "unexpected error: {err:?}"
    );

    let status: String = sqlx::query_scalar("SELECT status FROM tuning_proposals WHERE id = $1")
        .bind(proposal)
        .fetch_one(&pool)
        .await
        .expect("read status");
    assert_eq!(status, "proposed");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn proposal_history_carries_the_provenance_generation_must_union() {
    // NAN-2085: `get_proposal_history` feeds prior proposals into the tuning
    // prompt, so the agent needs each entry's origin to stamp the next one.
    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let stamped = insert_proposal(&repo, rule_id, &["insider_threat"], true).await;
    let legacy =
        insert_proposal_of_type(&repo, rule_id, ProposalType::HintUpdate, &[], false).await;

    let history = repo
        .get_proposal_history(rule_id, 10)
        .await
        .expect("history");
    assert_eq!(history.len(), 2, "both proposals should be in history");
    assert!(
        history.iter().any(
            |h| h.source_types == vec!["insider_threat".to_string()] && h.source_types_complete
        ),
        "stamped proposal {stamped} must expose its manifest"
    );
    assert!(
        history
            .iter()
            .any(|h| h.source_types.is_empty() && !h.source_types_complete),
        "legacy proposal {legacy} must expose its missing provenance"
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn a_pr_claim_cannot_freeze_a_proposal_restamped_onto_a_denied_source() {
    // The frozen operation carries `rationale`, `changes_summary` and both
    // queries, and ends up in a GitHub PR body — so the claim must re-check
    // provenance under its own row lock, not trust the handler's earlier read.
    use nanosiem_core::tuning::{PrApprovalProvenance, PrOperationError};

    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let proposal = insert_proposal(&repo, rule_id, &["insider_threat"], true).await;

    let target_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO detection_code_targets (
            id, name, repo_url, base_branch, path_template,
            pr_branch_prefix, rule_format, enabled
        )
        VALUES ($1, $2, 'https://github.com/acme/detections', 'main',
                'detections/{rule_name}.yaml', 'nano-tuning/', 'nanosiem', true)
        "#,
    )
    .bind(target_id)
    .bind(format!("NAN-2085-target-{target_id}"))
    .execute(&pool)
    .await
    .expect("insert target");

    let err = repo
        .claim_pr_operation_with_provenance(
            proposal,
            target_id,
            "source_type=apache",
            PrApprovalProvenance {
                actor_user_id: Some(Uuid::now_v7()),
                api_key_id: None,
                api_key_name: None,
                validation_skipped: false,
                reason: None,
            },
            &deny(&["insider_threat"]),
        )
        .await
        .expect_err("a denied proposal must not be claimable");
    assert!(
        matches!(err, PrOperationError::ProposalNotFound(id) if id == proposal),
        "unexpected error: {err:?}"
    );

    let phase: Option<String> =
        sqlx::query_scalar("SELECT pr_operation_phase FROM tuning_proposals WHERE id = $1")
            .bind(proposal)
            .fetch_one(&pool)
            .await
            .expect("read phase");
    assert!(phase.is_none(), "the claim must not have been frozen");
}
