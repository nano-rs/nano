// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL-backed coverage for NAN-1768's tuning state machine.

mod common;

use std::sync::Arc;

use nanosiem_core::detection::MaterializedViewGenerator;
use nanosiem_core::detection_code_target::acquire_autonomous_tuning_dac_lock;
use nanosiem_core::tuning::{
    AtomicProposalApplyError, AtomicProposalApplyRequest, PrApprovalProvenance,
    PrDestinationPayload, PrOperationClaim, PrOperationError, PrOperationPhase,
    ProposalRuleMutation, RuleVersion, RuleVersionManager, TuningLogEntry, TuningRepository,
    TuningStatus, TuningValidationProof, TuningValidationWindow,
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::OnceCell;
use uuid::Uuid;

static ENTERPRISE_MIGRATED: OnceCell<()> = OnceCell::const_new();

#[test]
fn migration_contract_orders_common_version_invariant_before_enterprise_state() {
    let common = include_str!("../../migrations/postgres/225_atomic_rule_version_invariants.sql");
    let enterprise =
        include_str!("../../migrations/postgres-enterprise/9000026_atomic_tuning_state.sql");
    let validation =
        include_str!("../../migrations/postgres-enterprise/9000027_tuning_validation_proof.sql");
    let checkpoints = include_str!(
        "../../migrations/postgres-enterprise/9000028_dac_pr_operation_checkpoints.sql"
    );
    let approval_audit =
        include_str!("../../migrations/postgres-enterprise/9000030_dac_pr_approval_audit.sql");
    assert!(common.contains("uq_detection_rule_versions_active"));
    assert!(common.contains("version.query = rule.query"));
    assert!(common.contains("detection_rule_runtime_sync_jobs"));
    assert_eq!(
        common.matches("LEFT JOIN detection_rule_versions").count(),
        2
    );
    assert!(enterprise.contains("version = 225 AND success = true"));
    assert!(enterprise.contains("pr_operation_snapshot JSONB"));
    assert!(enterprise.contains("pr_destination_payload JSONB"));
    assert!(enterprise.contains("tuning_proposals_pr_target_id_fkey"));
    assert!(validation.contains("version = 9000026 AND success = true"));
    assert!(validation.contains("validation_proof JSONB"));
    assert!(validation.contains("bump_tuning_tp_corpus_revision"));
    assert!(checkpoints.contains("version = 9000026 AND success = true"));
    assert!(checkpoints.contains("pr_operation_phase TEXT"));
    assert!(checkpoints.contains("pr_branch_sha TEXT"));
    assert!(checkpoints.contains("pr_commit_sha TEXT"));
    assert!(checkpoints.contains("pr_operation_started_at ASC NULLS FIRST, id ASC"));
    assert!(approval_audit.contains("version = 9000028 AND success = true"));
    assert!(approval_audit.contains("pr_approval_provenance JSONB"));
    assert!(
        !enterprise.contains("CREATE UNIQUE INDEX IF NOT EXISTS uq_detection_rule_versions_active")
    );
}

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

async fn insert_rule(pool: &PgPool, query: &str) -> Uuid {
    let rule_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO detection_rules (id, name, description, query, severity, mode)
        VALUES ($1, $2, 'NAN-1768 integration test', $3, 'medium', 'alerting')
        "#,
    )
    .bind(rule_id)
    .bind(format!("NAN-1768-{rule_id}"))
    .bind(query)
    .execute(pool)
    .await
    .expect("insert test rule");
    rule_id
}

async fn insert_realtime_rule(pool: &PgPool, query: &str) -> Uuid {
    let rule_id = insert_rule(pool, query).await;
    sqlx::query(
        "UPDATE detection_rules
         SET detection_mode = 'real-time', realtime_enabled = true
         WHERE id = $1",
    )
    .bind(rule_id)
    .execute(pool)
    .await
    .expect("mark integration rule real-time");
    rule_id
}

async fn insert_target(pool: &PgPool) -> Uuid {
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
    .bind(format!("NAN-1768-target-{target_id}"))
    .execute(pool)
    .await
    .expect("insert test target");
    target_id
}

async fn insert_query_proposal(
    pool: &PgPool,
    rule_id: Uuid,
    original_query: &str,
    proposed_query: &str,
) -> Uuid {
    let proposal_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO tuning_proposals (
            id, rule_id, proposal_type, original_query, proposed_query,
            rationale, confidence_score, safety_validation, status
        )
        VALUES (
            $1, $2, 'query_tuning', $3, $4, 'integration test', 0.95,
            '{"is_safe":true}'::jsonb, 'proposed'
        )
        "#,
    )
    .bind(proposal_id)
    .bind(rule_id)
    .bind(original_query)
    .bind(proposed_query)
    .execute(pool)
    .await
    .expect("insert test proposal");
    proposal_id
}

fn validation_proof(
    original_query: &str,
    proposed_query: &str,
    corpus_revision: i64,
) -> TuningValidationProof {
    let evaluation_start = chrono::Utc::now() - chrono::Duration::hours(24);
    let evaluation_end = chrono::Utc::now() - chrono::Duration::minutes(1);
    let windows = vec![TuningValidationWindow {
        start: evaluation_start,
        end: evaluation_start + chrono::Duration::minutes(5),
    }];
    let digest = |value: &[u8]| hex::encode(Sha256::digest(value));
    TuningValidationProof {
        proof_version: 1,
        original_query_sha256: digest(original_query.as_bytes()),
        proposed_query_sha256: digest(proposed_query.as_bytes()),
        dataset: "logs".to_string(),
        schedule_cron: "*/5 * * * *".to_string(),
        lookback_minutes: 5,
        evaluation_start,
        evaluation_end,
        windows_sha256: digest(&serde_json::to_vec(&windows).unwrap()),
        windows,
        corpus_count: 1,
        corpus_sha256: "a".repeat(64),
        corpus_revision,
        corpus_unique_source_count: 1,
        corpus_source_ids_sha256: "b".repeat(64),
        corpus_truncated: false,
        corpus_identity_complete: true,
        original_match_count: 100,
        proposed_match_count: 50,
        original_source_ids_sha256: "c".repeat(64),
        proposed_source_ids_sha256: "d".repeat(64),
        original_failed_windows: 0,
        proposed_failed_windows: 0,
        original_truncated_windows: 0,
        proposed_truncated_windows: 0,
        original_identity_errors: 0,
        proposed_identity_errors: 0,
        original_rows_examined: 100,
        proposed_rows_examined: 50,
        original_bytes_examined: 1_000,
        proposed_bytes_examined: 500,
        original_budget_exceeded: false,
        proposed_budget_exceeded: false,
        counts_exact: true,
        true_positives_preserved: true,
        identity_mode: "physical_id_uuid_v1".to_string(),
    }
}

async fn insert_validation_result(
    pool: &PgPool,
    proposal_id: Uuid,
    proof: &TuningValidationProof,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO tuning_test_results (
            id, proposal_id, original_alert_count, tuned_alert_count,
            reduction_percentage, true_positives_preserved,
            validation_passed, comparison_metrics, validation_proof
        )
        VALUES ($1, $2, 100, 50, 50.0, true, true, '{}', $3)
        "#,
    )
    .bind(id)
    .bind(proposal_id)
    .bind(serde_json::to_value(proof).unwrap())
    .execute(pool)
    .await
    .expect("insert validation result");
    id
}

async fn enable_autonomous_rule(pool: &PgPool, rule_id: Uuid) {
    sqlx::query(
        r#"
        UPDATE detection_rules
        SET auto_tuning_enabled = true,
            auto_apply_enabled = true,
            auto_tuning_min_confidence = 0.8,
            detection_mode = 'scheduled',
            schedule_cron = '*/5 * * * *',
            lookback_minutes = 5,
            archived = false,
            mode = 'alerting'
        WHERE id = $1
        "#,
    )
    .bind(rule_id)
    .execute(pool)
    .await
    .expect("enable autonomous test rule");
}

fn promoted_query_request(proposal_id: Uuid, query: &str) -> AtomicProposalApplyRequest {
    let mut request = apply_request(proposal_id, query, None);
    request.target_status = TuningStatus::Promoted;
    request
}

fn apply_request(
    proposal_id: Uuid,
    query: &str,
    created_by: Option<Uuid>,
) -> AtomicProposalApplyRequest {
    AtomicProposalApplyRequest {
        proposal_id,
        target_status: TuningStatus::ManuallyApproved,
        mutation: ProposalRuleMutation::Query {
            query: query.to_string(),
            created_by,
            change_reason: "NAN-1768 integration test".to_string(),
        },
        reviewer_notes: None,
        log_trigger_reason: "NAN-1768 integration test".to_string(),
    }
}

async fn cleanup_rule(pool: &PgPool, rule_id: Uuid) {
    sqlx::query("DELETE FROM detection_rule_runtime_sync_jobs WHERE rule_id = $1")
        .bind(rule_id)
        .execute(pool)
        .await
        .expect("clean up runtime sync job");
    sqlx::query("DELETE FROM detection_rules WHERE id = $1")
        .bind(rule_id)
        .execute(pool)
        .await
        .expect("clean up test rule");
}

async fn scheduler_log_entry(repository: &TuningRepository, proposal_id: Uuid) -> TuningLogEntry {
    let proposal = repository
        .get_proposal(proposal_id)
        .await
        .unwrap()
        .expect("proposal exists");
    TuningLogEntry {
        id: Uuid::now_v7(),
        rule_id: proposal.rule_id,
        rule_name: proposal
            .rule_name
            .clone()
            .unwrap_or_else(|| "NAN-1768 test".to_string()),
        triggered_at: chrono::Utc::now(),
        trigger_reason: "late scheduler normal-review log".to_string(),
        proposal,
        test_results: None,
        staging_deployment: None,
        status: TuningStatus::Proposed,
        reverted_at: None,
        reverted_by: None,
        revert_reason: None,
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn stale_base_rolls_back_without_rule_version_or_log_changes() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "newer analyst query").await;
    let proposal_id =
        insert_query_proposal(&pool, rule_id, "old proposal base", "tuned query").await;
    let repository = TuningRepository::new(pool.clone());

    let result = repository
        .apply_proposal_atomic(apply_request(proposal_id, "tuned query", None))
        .await;
    assert!(matches!(
        result,
        Err(AtomicProposalApplyError::StaleRuleBase { .. })
    ));

    let query: String = sqlx::query_scalar("SELECT query FROM detection_rules WHERE id = $1")
        .bind(rule_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM tuning_proposals WHERE id = $1")
        .bind(proposal_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let version_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM detection_rule_versions WHERE rule_id = $1")
            .bind(rule_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let log_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM tuning_logs WHERE proposal_id = $1")
            .bind(proposal_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(query, "newer analyst query");
    assert_eq!(status, "proposed");
    assert_eq!(version_count, 0);
    assert_eq!(log_count, 0);
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn realtime_apply_validates_and_commits_a_claimed_runtime_job_atomically() {
    let pool = enterprise_pool().await;
    let original = "src_ip=\"10.0.0.1\"";
    let tuned = "src_ip=\"10.0.0.2\"";
    let rule_id = insert_realtime_rule(&pool, original).await;
    let proposal_id = insert_query_proposal(&pool, rule_id, original, tuned).await;
    let repository = TuningRepository::new(pool.clone());
    let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
    let owner = format!("integration:{}", Uuid::now_v7());

    let result = repository
        .apply_proposal_atomic_with_runtime(
            apply_request(proposal_id, tuned, None),
            &generator,
            Some(&owner),
        )
        .await
        .expect("real-time tuning applies");
    let version_id = result.version_id.expect("query apply creates version");
    assert!(result.runtime_sync_required);
    assert!(result.runtime_sync_claimed);

    let persisted: (String, String, i32, String, Option<String>) = sqlx::query_as(
        r#"
        SELECT dr.query, tp.status, job.desired_version_id, job.status, job.claimed_by
        FROM detection_rules dr
        JOIN tuning_proposals tp ON tp.rule_id = dr.id
        JOIN detection_rule_runtime_sync_jobs job ON job.rule_id = dr.id
        WHERE dr.id = $1 AND tp.id = $2
        "#,
    )
    .bind(rule_id)
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(persisted.0, tuned);
    assert_eq!(persisted.1, "manually_approved");
    assert_eq!(persisted.2, version_id);
    assert_eq!(persisted.3, "pending");
    assert_eq!(persisted.4.as_deref(), Some(owner.as_str()));
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn incompatible_realtime_apply_rolls_back_before_rule_version_or_job_changes() {
    let pool = enterprise_pool().await;
    let original = "src_ip=\"10.0.0.1\"";
    let incompatible = "src_ip=\"10.0.0.2\" | stats count by user";
    let rule_id = insert_realtime_rule(&pool, original).await;
    let proposal_id = insert_query_proposal(&pool, rule_id, original, incompatible).await;
    let repository = TuningRepository::new(pool.clone());
    let generator = MaterializedViewGenerator::new(clickhouse::Client::default());

    let result = repository
        .apply_proposal_atomic_with_runtime(
            apply_request(proposal_id, incompatible, None),
            &generator,
            Some("integration:invalid-realtime"),
        )
        .await;
    assert!(matches!(
        result,
        Err(AtomicProposalApplyError::RealTimeValidation { .. })
    ));

    let persisted: (String, String, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            (SELECT query FROM detection_rules WHERE id = $1),
            (SELECT status FROM tuning_proposals WHERE id = $2),
            (SELECT COUNT(*) FROM detection_rule_versions WHERE rule_id = $1),
            (SELECT COUNT(*) FROM detection_rule_runtime_sync_jobs WHERE rule_id = $1)
        "#,
    )
    .bind(rule_id)
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        persisted,
        (original.to_string(), "proposed".to_string(), 0, 0)
    );
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn concurrent_approvals_have_one_winner_and_one_version() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "base query").await;
    let proposal_id = insert_query_proposal(&pool, rule_id, "base query", "tuned query").await;
    let repository = Arc::new(TuningRepository::new(pool.clone()));

    let first_repo = repository.clone();
    let second_repo = repository.clone();
    let (first, second) = tokio::join!(
        first_repo.apply_proposal_atomic(apply_request(proposal_id, "tuned query", None)),
        second_repo.apply_proposal_atomic(apply_request(proposal_id, "tuned query", None)),
    );

    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let loser = if first.is_err() { first } else { second };
    assert!(matches!(
        loser,
        Err(AtomicProposalApplyError::InvalidProposalState { .. })
    ));

    let counts: (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            (SELECT COUNT(*) FROM detection_rule_versions WHERE rule_id = $1),
            (SELECT COUNT(*) FROM detection_rule_versions WHERE rule_id = $1 AND is_active),
            (SELECT COUNT(*) FROM tuning_logs WHERE proposal_id = $2)
        "#,
    )
    .bind(rule_id)
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(counts, (1, 1, 1));
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn normal_review_log_race_cannot_restore_proposed_state_or_log() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "base query").await;
    let proposal_id = insert_query_proposal(&pool, rule_id, "base query", "tuned query").await;
    let repository = TuningRepository::new(pool.clone());

    let scheduler_log = scheduler_log_entry(&repository, proposal_id).await;
    let (inserted, applied) = tokio::join!(
        repository.create_log_entry_if_proposal_status(scheduler_log, &[TuningStatus::Proposed]),
        repository.apply_proposal_atomic(apply_request(proposal_id, "tuned query", None)),
    );
    inserted.unwrap();
    applied.unwrap();

    let states: (String, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            (SELECT status FROM tuning_proposals WHERE id = $1),
            (SELECT COUNT(*) FROM tuning_logs WHERE proposal_id = $1),
            (SELECT COUNT(*) FROM tuning_logs WHERE proposal_id = $1 AND status = 'proposed')
        "#,
    )
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(states, ("manually_approved".to_string(), 1, 0));
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn pr_claim_and_reject_race_has_one_winner_without_reopen() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "base query").await;
    let proposal_id = insert_query_proposal(&pool, rule_id, "base query", "tuned query").await;
    let repository = Arc::new(TuningRepository::new(pool.clone()));
    let target_id = insert_target(&pool).await;

    let claim_repo = repository.clone();
    let reject_repo = repository.clone();
    let (claim, rejected) = tokio::join!(
        claim_repo.claim_pr_operation(proposal_id, target_id, "tuned query"),
        reject_repo.transition_proposal_status(
            proposal_id,
            &[TuningStatus::Proposed, TuningStatus::TestPassed],
            TuningStatus::Rejected,
            Some("race test"),
        ),
    );

    let status: String = sqlx::query_scalar("SELECT status FROM tuning_proposals WHERE id = $1")
        .bind(proposal_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    match (claim, rejected.unwrap()) {
        (Ok(PrOperationClaim::Claimed { .. }), false) => assert_eq!(status, "pr_pending"),
        (Err(PrOperationError::InvalidState { .. }), true) => assert_eq!(status, "rejected"),
        other => panic!("unexpected race outcome: {other:?}"),
    }
    let mismatched_logs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tuning_logs WHERE proposal_id = $1 AND status <> $2",
    )
    .bind(proposal_id)
    .bind(&status)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(mismatched_logs, 0);
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn expired_pr_lease_reuses_frozen_branch_query_and_completion_is_idempotent() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "base query").await;
    let proposal_id = insert_query_proposal(&pool, rule_id, "base query", "tuned query").await;
    let repository = TuningRepository::new(pool.clone());
    let target_id = insert_target(&pool).await;
    let approval = PrApprovalProvenance {
        actor_user_id: Some(Uuid::now_v7()),
        api_key_id: Some(Uuid::now_v7()),
        api_key_name: Some("tuning-promoter".to_string()),
        validation_skipped: true,
        reason: Some("approved malformed legacy query".to_string()),
    };

    let first = repository
        .claim_pr_operation_with_provenance(
            proposal_id,
            target_id,
            "analyst modified query",
            approval.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        repository
            .get_pr_operation_target_id(proposal_id)
            .await
            .unwrap(),
        Some(target_id)
    );
    let (first_attempt, original_branch) = match first {
        PrOperationClaim::Claimed {
            resumed: false,
            attempt,
            operation,
            destination: None,
            ..
        } => {
            assert_eq!(operation.repo_url, "https://github.com/acme/detections");
            assert_eq!(operation.base_branch, "main");
            assert_eq!(operation.path_template, "detections/{rule_name}.yaml");
            assert_eq!(operation.approval_provenance, Some(approval.clone()));
            (attempt, operation.branch)
        }
        other => panic!("unexpected first claim: {other:?}"),
    };
    assert_eq!(first_attempt, 1);
    assert!(matches!(
        repository
            .claim_pr_operation(proposal_id, target_id, "analyst modified query")
            .await,
        Err(PrOperationError::InProgress(_))
    ));
    sqlx::query(
        "UPDATE tuning_proposals SET pr_operation_started_at = NOW() - INTERVAL '10 minutes' WHERE id = $1",
    )
    .bind(proposal_id)
    .execute(&pool)
    .await
    .unwrap();

    let frozen_destination = PrDestinationPayload {
        file_path: "detections/frozen.yaml".to_string(),
        file_content: "frozen content".to_string(),
        commit_message: "frozen commit".to_string(),
        title: "frozen title".to_string(),
        body: "frozen body".to_string(),
    };
    repository
        .freeze_pr_destination(proposal_id, first_attempt, &frozen_destination)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE detection_code_targets SET repo_url = 'https://github.com/changed/repo', base_branch = 'changed', path_template = 'changed/{rule_name}.yaml' WHERE id = $1",
    )
    .bind(target_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE detection_rules SET name = 'changed name', source_path = 'changed.yaml' WHERE id = $1")
        .bind(rule_id)
        .execute(&pool)
        .await
        .unwrap();

    let resumed = repository
        .claim_pr_operation(proposal_id, target_id, "changed retry query")
        .await
        .unwrap();
    match resumed {
        PrOperationClaim::Claimed {
            resumed: true,
            attempt: 2,
            operation,
            destination: Some(destination),
            checkpoint,
        } => {
            assert_eq!(operation.branch, original_branch);
            assert_eq!(operation.effective_query, "analyst modified query");
            assert_eq!(operation.repo_url, "https://github.com/acme/detections");
            assert_eq!(operation.base_branch, "main");
            assert_eq!(operation.rule.name, format!("NAN-1768-{rule_id}"));
            assert_eq!(operation.approval_provenance, Some(approval.clone()));
            assert_eq!(destination, frozen_destination);
            assert_eq!(checkpoint.phase, PrOperationPhase::DestinationReady);
        }
        other => panic!("unexpected resumed claim: {other:?}"),
    }

    repository
        .checkpoint_pr_branch(proposal_id, &original_branch, 2, "branch-sha")
        .await
        .unwrap();
    repository
        .checkpoint_pr_branch(proposal_id, &original_branch, 2, "branch-sha")
        .await
        .unwrap();
    repository
        .checkpoint_pr_commit(proposal_id, &original_branch, 2, "commit-sha")
        .await
        .unwrap();
    repository
        .checkpoint_reconciled_pull_request(
            proposal_id,
            &original_branch,
            2,
            "commit-sha",
            "https://github.com/acme/detections/pull/42",
            42,
            "open",
        )
        .await
        .unwrap();
    repository
        .complete_pr_operation(
            proposal_id,
            &original_branch,
            2,
            "https://github.com/acme/detections/pull/42",
            42,
            "open",
            None,
            &approval,
        )
        .await
        .unwrap();
    repository
        .complete_pr_operation(
            proposal_id,
            &original_branch,
            2,
            "https://github.com/acme/detections/pull/42",
            42,
            "merged",
            None,
            &approval,
        )
        .await
        .unwrap();

    let state: (
        String,
        i64,
        String,
        String,
        String,
        String,
        String,
        Option<Uuid>,
    ) = sqlx::query_as(
        r#"
        SELECT status, pr_attempt_count, pr_operation_query, pr_state,
               pr_operation_phase, pr_branch_sha, pr_commit_sha, pr_target_id
        FROM tuning_proposals WHERE id = $1
        "#,
    )
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        state,
        (
            "pr_opened".to_string(),
            2,
            "analyst modified query".to_string(),
            "merged".to_string(),
            "completed".to_string(),
            "branch-sha".to_string(),
            "commit-sha".to_string(),
            None
        )
    );
    let log_states: Vec<String> =
        sqlx::query_scalar("SELECT status FROM tuning_logs WHERE proposal_id = $1")
            .bind(proposal_id)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(!log_states.is_empty());
    assert!(log_states.iter().all(|status| status == "pr_opened"));
    let logged_approval: serde_json::Value = sqlx::query_scalar(
        "SELECT pr_approval_provenance FROM tuning_logs WHERE proposal_id = $1 LIMIT 1",
    )
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(logged_approval, serde_json::to_value(&approval).unwrap());
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn delayed_pr_failure_cannot_release_reclaimed_or_completed_operation() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "base query").await;
    let proposal_id = insert_query_proposal(&pool, rule_id, "base query", "tuned query").await;
    let repository = TuningRepository::new(pool.clone());
    let target_id = insert_target(&pool).await;

    let (first_attempt, branch) = match repository
        .claim_pr_operation(proposal_id, target_id, "tuned query")
        .await
        .unwrap()
    {
        PrOperationClaim::Claimed {
            attempt, operation, ..
        } => (attempt, operation.branch),
        other => panic!("unexpected first claim: {other:?}"),
    };
    sqlx::query(
        "UPDATE tuning_proposals SET pr_operation_started_at = NOW() - INTERVAL '10 minutes' WHERE id = $1",
    )
    .bind(proposal_id)
    .execute(&pool)
    .await
    .unwrap();
    let second_attempt = match repository
        .claim_pr_operation(proposal_id, target_id, "changed retry query")
        .await
        .unwrap()
    {
        PrOperationClaim::Claimed {
            resumed: true,
            attempt,
            ..
        } => attempt,
        other => panic!("unexpected reclaimed claim: {other:?}"),
    };
    assert_ne!(first_attempt, second_attempt);
    assert!(!repository
        .fail_pr_operation(proposal_id, &branch, first_attempt, "late timeout")
        .await
        .unwrap());

    let destination = PrDestinationPayload {
        file_path: "detections/recovered.yaml".to_string(),
        file_content: "content".to_string(),
        commit_message: "commit".to_string(),
        title: "title".to_string(),
        body: "body".to_string(),
    };
    repository
        .freeze_pr_destination(proposal_id, second_attempt, &destination)
        .await
        .unwrap();
    repository
        .checkpoint_pr_branch(proposal_id, &branch, second_attempt, "branch-43")
        .await
        .unwrap();
    repository
        .checkpoint_pr_commit(proposal_id, &branch, second_attempt, "commit-43")
        .await
        .unwrap();
    repository
        .checkpoint_pull_request(
            proposal_id,
            &branch,
            second_attempt,
            "https://github.com/acme/detections/pull/43",
            43,
            "merged",
        )
        .await
        .unwrap();
    let automated_approval = PrApprovalProvenance::automated();
    repository
        .complete_pr_operation(
            proposal_id,
            &branch,
            second_attempt,
            "https://github.com/acme/detections/pull/43",
            43,
            "merged",
            None,
            &automated_approval,
        )
        .await
        .unwrap();
    assert!(!repository
        .fail_pr_operation(proposal_id, &branch, first_attempt, "later timeout")
        .await
        .unwrap());

    let state: (String, String) = sqlx::query_as(
        r#"
        SELECT
            status,
            (SELECT status FROM tuning_logs WHERE proposal_id = $1 ORDER BY triggered_at DESC LIMIT 1)
        FROM tuning_proposals WHERE id = $1
        "#,
    )
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state, ("pr_opened".to_string(), "pr_opened".to_string()));
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn failed_pr_retry_reuses_original_target_and_branch() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "base query").await;
    let proposal_id = insert_query_proposal(&pool, rule_id, "base query", "tuned query").await;
    let repository = TuningRepository::new(pool.clone());
    let target_id = insert_target(&pool).await;

    let (attempt, branch) = match repository
        .claim_pr_operation(proposal_id, target_id, "first query")
        .await
        .unwrap()
    {
        PrOperationClaim::Claimed {
            attempt, operation, ..
        } => (attempt, operation.branch),
        other => panic!("unexpected first claim: {other:?}"),
    };
    assert!(repository
        .fail_pr_operation(proposal_id, &branch, attempt, "safe retry")
        .await
        .unwrap());

    assert!(matches!(
        repository
            .claim_pr_operation(proposal_id, Uuid::now_v7(), "second query")
            .await,
        Err(PrOperationError::InvalidMetadata { .. })
    ));
    let retry = repository
        .claim_pr_operation(proposal_id, target_id, "second query")
        .await
        .unwrap();
    match retry {
        PrOperationClaim::Claimed {
            resumed: true,
            attempt: retry_attempt,
            operation,
            ..
        } => {
            assert_eq!(retry_attempt, attempt + 1);
            assert_eq!(operation.branch, branch);
            assert_eq!(operation.effective_query, "first query");
        }
        other => panic!("unexpected retry claim: {other:?}"),
    }
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn autonomous_apply_rechecks_policy_under_the_rule_lock() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "base query").await;
    enable_autonomous_rule(&pool, rule_id).await;
    let proposal_id = insert_query_proposal(&pool, rule_id, "base query", "tuned query").await;
    let proof = validation_proof("base query", "tuned query", 0);
    let test_result_id = insert_validation_result(&pool, proposal_id, &proof).await;
    sqlx::query("UPDATE detection_rules SET auto_apply_enabled = false WHERE id = $1")
        .bind(rule_id)
        .execute(&pool)
        .await
        .unwrap();

    let request = promoted_query_request(proposal_id, "tuned query");
    let validator = MaterializedViewGenerator::new(clickhouse::Client::default());
    let result = TuningRepository::new(pool.clone())
        .apply_validated_query_atomic_with_runtime(
            request,
            &validator,
            None,
            test_result_id,
            &proof,
        )
        .await;
    assert!(matches!(
        result,
        Err(AtomicProposalApplyError::AutonomousPolicyRejected { .. })
    ));
    let state: (String, String, i64) = sqlx::query_as(
        r#"
        SELECT
            (SELECT query FROM detection_rules WHERE id = $1),
            (SELECT status FROM tuning_proposals WHERE id = $2),
            (SELECT COUNT(*) FROM detection_rule_versions WHERE rule_id = $1)
        "#,
    )
    .bind(rule_id)
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state, ("base query".to_string(), "proposed".to_string(), 0));
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn validated_autonomous_apply_commits_rule_version_status_and_bound_log() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "base query").await;
    enable_autonomous_rule(&pool, rule_id).await;
    let proposal_id = insert_query_proposal(&pool, rule_id, "base query", "tuned query").await;
    let proof = validation_proof("base query", "tuned query", 0);
    let test_result_id = insert_validation_result(&pool, proposal_id, &proof).await;
    let validator = MaterializedViewGenerator::new(clickhouse::Client::default());

    let result = TuningRepository::new(pool.clone())
        .apply_validated_query_atomic_with_runtime(
            promoted_query_request(proposal_id, "tuned query"),
            &validator,
            None,
            test_result_id,
            &proof,
        )
        .await
        .expect("validated autonomous apply");
    let version_id = result.version_id.expect("query apply version");

    let state: (String, String, i32, Option<i32>, Option<Uuid>) = sqlx::query_as(
        r#"
        SELECT dr.query, tp.status, drv.id,
               tl.applied_version_id, tl.test_results_id
        FROM detection_rules dr
        JOIN tuning_proposals tp ON tp.rule_id = dr.id
        JOIN detection_rule_versions drv
          ON drv.rule_id = dr.id AND drv.is_active
        JOIN tuning_logs tl ON tl.proposal_id = tp.id
        WHERE dr.id = $1 AND tp.id = $2
        "#,
    )
    .bind(rule_id)
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state.0, "tuned query");
    assert_eq!(state.1, "promoted");
    assert_eq!(state.2, version_id);
    assert_eq!(state.3, Some(version_id));
    assert_eq!(state.4, Some(test_result_id));

    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn manual_query_apply_waits_for_dac_activation_and_refuses_direct_mutation() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "base query").await;
    let proposal_id = insert_query_proposal(&pool, rule_id, "base query", "tuned query").await;
    let target_id = insert_target(&pool).await;

    let mut target_tx = pool.begin().await.unwrap();
    acquire_autonomous_tuning_dac_lock(&mut target_tx)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE detection_code_targets \
         SET token_encrypted = $2, token_nonce = 'test-nonce' \
         WHERE id = $1",
    )
    .bind(target_id)
    .bind(vec![1_u8, 2, 3])
    .execute(&mut *target_tx)
    .await
    .unwrap();

    let apply_pool = pool.clone();
    let mut apply_task = tokio::spawn(async move {
        TuningRepository::new(apply_pool)
            .apply_proposal_atomic(apply_request(proposal_id, "tuned query", None))
            .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), &mut apply_task)
            .await
            .is_err(),
        "direct apply did not wait for the DaC activation lock"
    );

    target_tx.commit().await.unwrap();
    let result = apply_task.await.expect("apply task join");
    assert!(matches!(
        result,
        Err(AtomicProposalApplyError::DetectionAsCodeRequired { .. })
    ));

    let state: (String, String, i64) = sqlx::query_as(
        r#"
        SELECT
            (SELECT query FROM detection_rules WHERE id = $1),
            (SELECT status FROM tuning_proposals WHERE id = $2),
            (SELECT COUNT(*) FROM detection_rule_versions WHERE rule_id = $1)
        "#,
    )
    .bind(rule_id)
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state, ("base query".to_string(), "proposed".to_string(), 0));

    sqlx::query("DELETE FROM detection_code_targets WHERE id = $1")
        .bind(target_id)
        .execute(&pool)
        .await
        .unwrap();
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn expired_silent_pr_is_recoverable_without_a_breach_and_can_be_cancelled() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "base query").await;
    let proposal_id = insert_query_proposal(&pool, rule_id, "base query", "silent rewrite").await;
    sqlx::query("UPDATE tuning_proposals SET proposal_type = 'silent_rule' WHERE id = $1")
        .bind(proposal_id)
        .execute(&pool)
        .await
        .unwrap();
    let target_id = insert_target(&pool).await;
    let repository = TuningRepository::new(pool.clone());
    repository
        .claim_pr_operation(proposal_id, target_id, "silent rewrite")
        .await
        .unwrap();

    assert!(!repository
        .cancel_expired_pr_operation(proposal_id, "too early")
        .await
        .unwrap());
    let delete_error = sqlx::query("DELETE FROM detection_code_targets WHERE id = $1")
        .bind(target_id)
        .execute(&pool)
        .await
        .expect_err("claimed target must be protected");
    assert_eq!(
        delete_error
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("23503")
    );

    sqlx::query(
        "UPDATE tuning_proposals SET pr_operation_started_at = NOW() - INTERVAL '10 minutes' WHERE id = $1",
    )
    .bind(proposal_id)
    .execute(&pool)
    .await
    .unwrap();
    let recoverable = repository
        .list_proposals(None, Some(TuningStatus::PrPending), None, 100, 0)
        .await
        .unwrap();
    assert!(recoverable.iter().any(|proposal| {
        proposal.id == proposal_id
            && proposal.proposal_type == nanosiem_core::tuning::ProposalType::SilentRule
    }));
    assert!(repository
        .list_recoverable_pr_operation_ids(100)
        .await
        .unwrap()
        .contains(&proposal_id));
    assert!(repository
        .cancel_expired_pr_operation(proposal_id, "operator cancelled expired retry")
        .await
        .unwrap());
    sqlx::query("DELETE FROM detection_code_targets WHERE id = $1")
        .bind(target_id)
        .execute(&pool)
        .await
        .expect("cancelled operation releases target deletion");
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn failed_first_recovery_page_rotates_before_the_101st_candidate() {
    let pool = enterprise_pool().await;
    let repository = TuningRepository::new(pool.clone());
    let target_id = insert_target(&pool).await;
    let mut rule_ids = Vec::with_capacity(101);
    let mut proposal_ids = Vec::with_capacity(101);

    for index in 0..101 {
        let rule_id = insert_rule(&pool, &format!("recovery query {index}")).await;
        let proposal_id = insert_query_proposal(
            &pool,
            rule_id,
            &format!("recovery query {index}"),
            &format!("recovered query {index}"),
        )
        .await;
        sqlx::query(
            r#"
            UPDATE tuning_proposals
            SET status = 'pr_pending',
                pr_target_id = $1,
                pr_operation_started_at = TIMESTAMPTZ '2000-01-01 00:00:00+00'
            WHERE id = $2
            "#,
        )
        .bind(target_id)
        .bind(proposal_id)
        .execute(&pool)
        .await
        .unwrap();
        rule_ids.push(rule_id);
        proposal_ids.push(proposal_id);
    }

    let first_page = repository
        .list_recoverable_pr_operation_ids(100)
        .await
        .unwrap();
    assert_eq!(first_page.len(), 100);
    let remaining = *proposal_ids
        .iter()
        .find(|id| !first_page.contains(id))
        .expect("one test candidate must remain beyond the first page");

    for proposal_id in first_page {
        assert!(repository
            .defer_expired_pr_operation_recovery(proposal_id, "injected pre-claim failure")
            .await
            .unwrap());
    }
    assert!(repository
        .list_recoverable_pr_operation_ids(100)
        .await
        .unwrap()
        .contains(&remaining));

    for rule_id in rule_ids {
        cleanup_rule(&pool, rule_id).await;
    }
    sqlx::query("DELETE FROM detection_code_targets WHERE id = $1")
        .bind(target_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn concurrent_version_creation_serializes_max_plus_one_and_activation() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "base query").await;
    let manager = RuleVersionManager::new(pool.clone());
    let version = |query: &str| RuleVersion {
        id: 0,
        rule_id,
        version_number: 0,
        query: query.to_string(),
        name: format!("NAN-1768-{rule_id}"),
        description: None,
        severity: "medium".to_string(),
        enabled: true,
        is_active: true,
        created_at: chrono::Utc::now(),
        created_by: None,
        change_reason: "concurrency test".to_string(),
        tuning_proposal_id: None,
        reverted_from_version: None,
    };

    let (first, second) = tokio::join!(
        manager.create_version(version("version one")),
        manager.create_version(version("version two")),
    );
    first.expect("first version succeeds");
    second.expect("second version succeeds");

    let numbers: Vec<i32> = sqlx::query_scalar(
        "SELECT version_number FROM detection_rule_versions WHERE rule_id = $1 ORDER BY version_number",
    )
    .bind(rule_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM detection_rule_versions WHERE rule_id = $1 AND is_active",
    )
    .bind(rule_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(numbers, vec![1, 2]);
    assert_eq!(active_count, 1);
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn late_version_failure_restores_rule_proposal_and_active_version() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "base query").await;
    let proposal_id = insert_query_proposal(&pool, rule_id, "base query", "tuned query").await;
    let manager = RuleVersionManager::new(pool.clone());
    let original_version = manager
        .create_version(RuleVersion {
            id: 0,
            rule_id,
            version_number: 0,
            query: "base query".to_string(),
            name: format!("NAN-1768-{rule_id}"),
            description: None,
            severity: "medium".to_string(),
            enabled: true,
            is_active: true,
            created_at: chrono::Utc::now(),
            created_by: None,
            change_reason: "initial".to_string(),
            tuning_proposal_id: None,
            reverted_from_version: None,
        })
        .await
        .unwrap();

    // created_by has an FK to users. A random, absent user forces failure at
    // version insertion, after the transaction has updated the rule and
    // deactivated the old version.
    let result = TuningRepository::new(pool.clone())
        .apply_proposal_atomic(apply_request(
            proposal_id,
            "tuned query",
            Some(Uuid::now_v7()),
        ))
        .await;
    assert!(matches!(result, Err(AtomicProposalApplyError::Database(_))));

    let query: String = sqlx::query_scalar("SELECT query FROM detection_rules WHERE id = $1")
        .bind(rule_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM tuning_proposals WHERE id = $1")
        .bind(proposal_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let active_id: i32 = sqlx::query_scalar(
        "SELECT id FROM detection_rule_versions WHERE rule_id = $1 AND is_active",
    )
    .bind(rule_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(query, "base query");
    assert_eq!(status, "proposed");
    assert_eq!(active_id, original_version);
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn database_rejects_a_second_open_proposal_for_the_same_rule_and_type() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "base query").await;
    insert_query_proposal(&pool, rule_id, "base query", "first tuned query").await;

    let duplicate = sqlx::query(
        r#"
        INSERT INTO tuning_proposals (
            id, rule_id, proposal_type, original_query, proposed_query,
            rationale, confidence_score, status
        )
        VALUES ($1, $2, 'query_tuning', 'base query', 'second tuned query',
                'duplicate', 0.9, 'test_passed')
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(rule_id)
    .execute(&pool)
    .await
    .expect_err("partial unique index must reject the second open proposal");
    assert_eq!(
        duplicate
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("23505")
    );
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL)"]
async fn silent_upgrade_cannot_mutate_an_actioned_proposal() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "base query").await;
    let proposal_id = insert_query_proposal(&pool, rule_id, "base query", "base query").await;
    sqlx::query("UPDATE tuning_proposals SET proposal_type = 'silent_rule' WHERE id = $1")
        .bind(proposal_id)
        .execute(&pool)
        .await
        .unwrap();
    let repository = TuningRepository::new(pool.clone());
    assert!(repository
        .transition_proposal_status(
            proposal_id,
            &[TuningStatus::Proposed],
            TuningStatus::Rejected,
            Some("analyst rejected"),
        )
        .await
        .unwrap());

    assert!(!repository
        .upgrade_silent_proposal(
            proposal_id,
            "scheduler overwrite",
            0.99,
            &["late tier upgrade".to_string()],
        )
        .await
        .unwrap());
    let persisted: (String, String, f64) = sqlx::query_as(
        "SELECT status, rationale, confidence_score FROM tuning_proposals WHERE id = $1",
    )
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(persisted.0, "rejected");
    assert_eq!(persisted.1, "integration test");
    assert_eq!(persisted.2, 0.95);
    cleanup_rule(&pool, rule_id).await;
}
