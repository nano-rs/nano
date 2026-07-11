// SPDX-License-Identifier: AGPL-3.0-or-later

mod common;

use chrono::{Duration, Utc};
use nanosiem_core::tuning::versions::{RuleVersionManager, TuningRevertPlan};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires migrated PostgreSQL"]
async fn tuning_revert_is_target_bound_atomic_and_idempotent() {
    let pool = common::migrated_pool().await;
    let rule_id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let proposal_id = Uuid::now_v7();
    let log_id = Uuid::now_v7();
    let auto_proposal_id = Uuid::now_v7();
    let auto_log_id = Uuid::now_v7();

    sqlx::query(
        "INSERT INTO users (id, email, name, password_hash)
         VALUES ($1, $2, 'Rollback Test', 'not-used')",
    )
    .bind(user_id)
    .bind(format!("rollback-{user_id}@example.invalid"))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO detection_rules (
             id, name, description, query, severity, mode, detection_mode,
             auto_tuning_disabled_until
         ) VALUES ($1, 'Tuned rule', 'tuned', $2, 'high', 'live', 'scheduled', $3)",
    )
    .bind(rule_id)
    .bind("source_type=windows AND user=admin")
    .bind(Utc::now() + Duration::days(30))
    .execute(&pool)
    .await
    .unwrap();

    let original_version_id: i32 = sqlx::query_scalar(
        "INSERT INTO detection_rule_versions (
             rule_id, version_number, query, name, description, severity,
             enabled, is_active, change_reason
         ) VALUES ($1, 1, $2, 'Original rule', 'original', 'medium', TRUE, FALSE,
                   'initial_creation')
         RETURNING id",
    )
    .bind(rule_id)
    .bind("source_type=windows")
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO tuning_proposals (
             id, rule_id, original_query, proposed_query, rationale,
             confidence_score, proposal_type, status
         ) VALUES ($1, $2, $3, $4, 'test', 0.99, 'query_tuning', 'manually_approved')",
    )
    .bind(proposal_id)
    .bind(rule_id)
    .bind("source_type=windows")
    .bind("source_type=windows AND user=admin")
    .execute(&pool)
    .await
    .unwrap();
    let applied_version_id: i32 = sqlx::query_scalar(
        "INSERT INTO detection_rule_versions (
             rule_id, version_number, query, name, description, severity,
             enabled, is_active, change_reason, tuning_proposal_id
         ) VALUES ($1, 2, $2, 'Tuned rule', 'tuned', 'high', TRUE, TRUE,
                   'auto_tuning', $3)
         RETURNING id",
    )
    .bind(rule_id)
    .bind("source_type=windows AND user=admin")
    .bind(proposal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO tuning_logs (
             id, rule_id, rule_name, trigger_reason, proposal_id,
             applied_version_id, status
         ) VALUES ($1, $2, 'Tuned rule', 'test', $3, NULL, 'proposed')",
    )
    .bind(log_id)
    .bind(rule_id)
    .bind(proposal_id)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO tuning_proposals (
             id, rule_id, original_query, proposed_query, rationale,
             confidence_score, proposal_type, status
         ) VALUES ($1, $2, $3, $4, 'auto test', 0.99, 'query_tuning', 'promoted')",
    )
    .bind(auto_proposal_id)
    .bind(rule_id)
    .bind("source_type=windows AND user=admin")
    .bind("source_type=windows AND user=admin AND process_name=cmd.exe")
    .execute(&pool)
    .await
    .unwrap();
    let auto_applied_version_id: i32 = sqlx::query_scalar(
        "INSERT INTO detection_rule_versions (
             rule_id, version_number, query, name, description, severity,
             enabled, is_active, change_reason, tuning_proposal_id
         ) VALUES ($1, 3, $2, 'Auto tuned rule', 'auto', 'high', TRUE, FALSE,
                   'auto_tuning', $3)
         RETURNING id",
    )
    .bind(rule_id)
    .bind("source_type=windows AND user=admin AND process_name=cmd.exe")
    .bind(auto_proposal_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO tuning_logs (
             id, rule_id, rule_name, trigger_reason, proposal_id,
             applied_version_id, status
         ) VALUES ($1, $2, 'Auto tuned rule', 'test', $3, NULL, 'proposed')",
    )
    .bind(auto_log_id)
    .bind(rule_id)
    .bind(auto_proposal_id)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::raw_sql(include_str!(
        "../../migrations/postgres-enterprise/9000031_tuning_revert_idempotency.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let legacy_rows: Vec<(Uuid, Option<i32>, String)> = sqlx::query_as(
        "SELECT id, applied_version_id, status
         FROM tuning_logs WHERE id = ANY($1::uuid[]) ORDER BY id",
    )
    .bind(vec![log_id, auto_log_id])
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(legacy_rows.iter().any(|row| {
        row.0 == log_id && row.1 == Some(applied_version_id) && row.2 == "manually_approved"
    }));
    assert!(legacy_rows.iter().any(|row| {
        row.0 == auto_log_id && row.1 == Some(auto_applied_version_id) && row.2 == "promoted"
    }));

    let manager = RuleVersionManager::new(pool.clone());
    assert!(manager
        .plan_tuning_revert(rule_id, applied_version_id, log_id)
        .await
        .is_err());
    assert!(matches!(
        manager
            .plan_tuning_revert(rule_id, original_version_id, log_id)
            .await
            .unwrap(),
        TuningRevertPlan::Ready
    ));

    let first = manager
        .revert_tuning_log_claimed(
            rule_id,
            original_version_id,
            user_id,
            log_id,
            "false positives".to_string(),
            "integration:first",
            "live",
            "scheduled",
        )
        .await
        .unwrap();
    assert!(first.changed);
    assert!(!first.replayed);
    assert!(!first.runtime_sync_required);

    let replay = manager
        .revert_tuning_log_claimed(
            rule_id,
            original_version_id,
            user_id,
            log_id,
            "retry".to_string(),
            "integration:replay",
            "live",
            "scheduled",
        )
        .await
        .unwrap();
    assert_eq!(replay.version_id, first.version_id);
    assert!(!replay.changed);
    assert!(replay.replayed);

    let (rule_query, rule_severity, cooldown): (String, String, chrono::DateTime<Utc>) =
        sqlx::query_as(
            "SELECT query, severity, auto_tuning_disabled_until
             FROM detection_rules WHERE id = $1",
        )
        .bind(rule_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rule_query, "source_type=windows");
    assert_eq!(rule_severity, "medium");
    assert!(cooldown > Utc::now() + Duration::days(29));

    sqlx::query("UPDATE detection_rules SET auto_tuning_disabled_until = NULL WHERE id = $1")
        .bind(rule_id)
        .execute(&pool)
        .await
        .unwrap();
    let direct_route_replay = manager
        .revert_to_version_claimed(
            rule_id,
            original_version_id,
            user_id,
            "integration:direct-route",
            "live",
            "scheduled",
        )
        .await
        .unwrap();
    assert!(!direct_route_replay.changed);
    assert!(!direct_route_replay.replayed);
    let direct_route_cooldown: chrono::DateTime<Utc> = sqlx::query_scalar(
        "SELECT auto_tuning_disabled_until FROM detection_rules WHERE id = $1",
    )
    .bind(rule_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(direct_route_cooldown >= Utc::now() + Duration::days(6));
    assert!(direct_route_cooldown <= Utc::now() + Duration::days(8));

    let (status, target_id, result_id): (String, Option<i32>, Option<i32>) = sqlx::query_as(
        "SELECT status, reverted_to_version_id, reverted_result_version_id
         FROM tuning_logs WHERE id = $1",
    )
    .bind(log_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status, "reverted");
    assert_eq!(target_id, Some(original_version_id));
    assert_eq!(result_id, Some(first.version_id));

    let version_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM detection_rule_versions WHERE rule_id = $1")
            .bind(rule_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(version_count, 4);

    let rendered_revision: chrono::DateTime<Utc> =
        sqlx::query_scalar("SELECT updated_at FROM detection_rules WHERE id = $1")
            .bind(rule_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO detection_rule_runtime_sync_jobs (
             rule_id, desired_version_id, claimed_by, claimed_at
         ) VALUES ($1, $2, 'integration:revision', NOW())",
    )
    .bind(rule_id)
    .bind(first.version_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE detection_rules
         SET updated_at = updated_at + INTERVAL '1 second'
         WHERE id = $1",
    )
    .bind(rule_id)
    .execute(&pool)
    .await
    .unwrap();
    let pending = nanosiem_core::tuning::versions::PendingRuntimeSync {
        rule_id,
        desired_version_id: first.version_id,
    };
    assert!(!manager
        .complete_runtime_sync(&pending, "integration:revision", rendered_revision)
        .await
        .unwrap());
    let latest_revision: chrono::DateTime<Utc> =
        sqlx::query_scalar("SELECT updated_at FROM detection_rules WHERE id = $1")
            .bind(rule_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(manager
        .complete_runtime_sync(&pending, "integration:revision", latest_revision)
        .await
        .unwrap());

    let runtime_lock =
        nanosiem_core::detection::materialized_view::acquire_rule_runtime_lock(&pool, rule_id)
            .await
            .unwrap();
    assert!(tokio::time::timeout(
        std::time::Duration::from_millis(100),
        nanosiem_core::detection::materialized_view::acquire_rule_runtime_lock(&pool, rule_id),
    )
    .await
    .is_err());
    drop(runtime_lock);

    sqlx::query("DELETE FROM tuning_logs WHERE id = ANY($1::uuid[])")
        .bind(vec![log_id, auto_log_id])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM detection_rule_versions WHERE rule_id = $1")
        .bind(rule_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM tuning_proposals WHERE id = ANY($1::uuid[])")
        .bind(vec![proposal_id, auto_proposal_id])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM detection_rules WHERE id = $1")
        .bind(rule_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO detection_rule_runtime_sync_jobs (
             rule_id, desired_version_id, claimed_by, claimed_at
         ) VALUES ($1, 0, 'integration:deleted', NOW())",
    )
    .bind(rule_id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(manager
        .complete_deleted_runtime_sync(
            &nanosiem_core::tuning::versions::PendingRuntimeSync {
                rule_id,
                desired_version_id: 0,
            },
            "integration:deleted",
        )
        .await
        .unwrap());
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
}
