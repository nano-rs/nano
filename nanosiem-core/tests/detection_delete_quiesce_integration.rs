// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4902 review — `quiesce_for_delete` must be side-effect free when the
//! rule is claimed (the caller returns a retryable 409), and must still pause
//! an unclaimed rule so no scheduler can claim it before it is archived.
//!
//! `#[ignore]`d like the sibling DB suites: the `pg-integration-tests` lane runs
//! them with `-- --ignored` (locally `docker compose up -d postgres`).

mod common;

use chrono::{DateTime, Utc};
use nanosiem_core::db::repository::DetectionRuleRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn insert_scheduled_rule(pool: &PgPool) -> Uuid {
    let rule_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO detection_rules
            (id, name, description, query, severity, mode,
             detection_mode, schedule_cron, next_run_at)
        VALUES ($1, $2, 'NAN-4902 quiesce test', 'source_type=apache', 'medium',
                'alerting', 'scheduled', '* * * * *', NOW() - INTERVAL '1 minute')
        "#,
    )
    .bind(rule_id)
    .bind(format!("NAN-4902-quiesce-{rule_id}"))
    .execute(pool)
    .await
    .expect("insert rule");
    rule_id
}

async fn schedule_state(pool: &PgPool, id: Uuid) -> (String, Option<DateTime<Utc>>, bool) {
    sqlx::query_as("SELECT mode, next_run_at, archived FROM detection_rules WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read rule")
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn claimed_rule_conflict_leaves_mode_and_schedule_untouched() {
    let pool = common::migrated_pool().await;
    let repo = DetectionRuleRepository::new(pool.clone());
    let id = insert_scheduled_rule(&pool).await;
    sqlx::query("UPDATE detection_rules SET claimed_by = 'node-a', claimed_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    let before = schedule_state(&pool, id).await;

    assert!(!repo.quiesce_for_delete(id).await.unwrap(), "claimed → not drained");

    let after = schedule_state(&pool, id).await;
    assert_eq!(after, before, "a 409 must not pause or unschedule the rule");
    assert_eq!(after.0, "alerting");
    assert!(after.1.is_some());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn unclaimed_rule_is_paused_and_no_longer_claimable() {
    let pool = common::migrated_pool().await;
    let repo = DetectionRuleRepository::new(pool.clone());
    let id = insert_scheduled_rule(&pool).await;

    assert!(repo.quiesce_for_delete(id).await.unwrap());

    let (mode, next_run_at, archived) = schedule_state(&pool, id).await;
    assert_eq!(mode, "paused");
    assert!(next_run_at.is_none());
    assert!(!archived);
    // `claim_due_rules` excludes `mode = 'paused'` and `next_run_at IS NULL`;
    // probe its predicate for this row only (a real claim would grab other
    // suites' due rules in the shared database).
    let claimable: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM detection_rules WHERE id = $1 AND archived = false \
           AND mode NOT IN ('staging', 'paused') AND next_run_at IS NOT NULL)",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!claimable, "quiesced rule is still claimable");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn archived_or_missing_rule_is_not_found() {
    let pool = common::migrated_pool().await;
    let repo = DetectionRuleRepository::new(pool.clone());
    assert!(repo.quiesce_for_delete(Uuid::now_v7()).await.is_err());
}
