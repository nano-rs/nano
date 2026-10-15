// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL contract for the late-arriving detection repair queue.

use chrono::{DateTime, Duration, SubsecRound, Utc};
use nanosiem_core::db::repository::detection_rules::{
    DetectionRuleRepository, LateReplayReleaseOutcome,
};
use nanosiem_core::db::run_postgres_migrations;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool};
use uuid::Uuid;

const TEST_DB_NAME: &str = "nanosiem_late_replay_test";

fn admin_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nanosiem:nanosiem@localhost:5432/postgres".to_string())
}

fn test_db_url() -> String {
    let admin = admin_url();
    let last_slash = admin.rfind('/').expect("admin url must contain '/'");
    format!("{}/{}", &admin[..last_slash], TEST_DB_NAME)
}

async fn recreate_test_db() -> Result<PgPool, sqlx::Error> {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url())
        .await?;
    let _ = admin
        .execute(
            format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                 WHERE datname = '{TEST_DB_NAME}' AND pid <> pg_backend_pid()"
            )
            .as_str(),
        )
        .await;
    admin
        .execute(format!("DROP DATABASE IF EXISTS {TEST_DB_NAME}").as_str())
        .await?;
    admin
        .execute(format!("CREATE DATABASE {TEST_DB_NAME}").as_str())
        .await?;
    PgPoolOptions::new()
        .max_connections(4)
        .connect(&test_db_url())
        .await
}

#[tokio::test]
async fn publication_plan_claim_retry_and_complete_preserve_normal_watermark() {
    let pool = match recreate_test_db().await {
        Ok(pool) => pool,
        Err(error) => {
            eprintln!("late-arrival integration skipped; PostgreSQL unavailable: {error}");
            return;
        }
    };
    std::env::set_var("NANOSIEM_MIGRATION_MODE", "fresh");
    run_postgres_migrations(&pool)
        .await
        .expect("apply fresh open-core migrations");
    std::env::remove_var("NANOSIEM_MIGRATION_MODE");

    let rule_id = Uuid::now_v7();
    // PostgreSQL timestamptz keeps microseconds; a nanosecond watermark would
    // never compare equal after the round trip.
    let watermark = (Utc::now() - Duration::minutes(30)).trunc_subsecs(6);
    sqlx::query(
        r#"
        INSERT INTO detection_rules (
            id, name, query, severity, schedule_cron, mode,
            detection_mode, last_run_at, next_run_at, lookback_minutes,
            dataset, kind
        )
        VALUES ($1, 'late event contract', 'class_uid=3002', 'medium',
                '* * * * *', 'live', 'scheduled', $2, $3, 15,
                'logs', 'standard')
        "#,
    )
    .bind(rule_id)
    .bind(watermark)
    .bind(watermark + Duration::minutes(1))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO lake_detection_event_publications (
            tenant_id, bronze_store_id, batch_sha256,
            min_event_time, max_event_time, published_at
        )
        VALUES ('tenant-a', 'rustfs:test:bronze', $1, $2, $3, $4)
        "#,
    )
    .bind("a".repeat(64))
    .bind(watermark - Duration::minutes(30))
    .bind(watermark + Duration::minutes(5))
    .bind(Utc::now() - Duration::seconds(31))
    .execute(&pool)
    .await
    .unwrap();

    let repository = DetectionRuleRepository::new(pool.clone());
    let plan = repository
        .plan_late_replays(10, Duration::days(7), Duration::minutes(15))
        .await
        .unwrap();
    assert_eq!(plan.publications, 1);
    assert_eq!(plan.jobs, 1);
    assert_eq!(plan.coalesced, 0);
    assert_eq!(plan.expired, 0);
    let (window_start, window_end): (DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
        "SELECT window_start, window_end FROM detection_late_replay_jobs WHERE rule_id = $1",
    )
    .bind(rule_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(window_start, watermark - Duration::minutes(45));
    assert_eq!(window_end, watermark);
    assert_eq!(
        repository
            .plan_late_replays(10, Duration::days(7), Duration::minutes(15))
            .await
            .unwrap()
            .publications,
        0
    );

    // A due normal cron execution must yield to a due repair for the same
    // rule. Otherwise synchronized five-second/ten-second poll loops can let
    // the normal lane win forever and starve the repair job.
    assert!(repository
        .claim_due_rules(1, "normal-node", 360, true)
        .await
        .unwrap()
        .is_empty());

    let first = repository
        .claim_late_replays(1, "node-a", Duration::minutes(6), Duration::minutes(6))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(first.rule.id, rule_id);
    assert_eq!(first.attempt, 1);
    assert_eq!(
        repository
            .release_late_replay(&first, "node-a", Some("transient"), 3, Duration::days(7),)
            .await
            .unwrap(),
        LateReplayReleaseOutcome::Retry
    );
    sqlx::query("UPDATE detection_late_replay_jobs SET next_attempt_at = NOW() WHERE id = $1")
        .bind(first.job_id)
        .execute(&pool)
        .await
        .unwrap();

    let second = repository
        .claim_late_replays(1, "node-b", Duration::minutes(6), Duration::minutes(6))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(second.attempt, 2);
    assert_eq!(
        repository
            .release_late_replay_progress(&second, "node-b", "committed 100 events; 151 remain",)
            .await
            .unwrap(),
        LateReplayReleaseOutcome::Draining
    );
    sqlx::query("UPDATE detection_late_replay_jobs SET next_attempt_at = NOW() WHERE id = $1")
        .bind(second.job_id)
        .execute(&pool)
        .await
        .unwrap();

    let final_batch = repository
        .claim_late_replays(1, "node-b", Duration::minutes(6), Duration::minutes(6))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        final_batch.attempt, 1,
        "a committed drain batch must reset the failure-attempt budget"
    );
    assert_eq!(
        repository
            .release_late_replay(&final_batch, "node-b", None, 3, Duration::days(7))
            .await
            .unwrap(),
        LateReplayReleaseOutcome::Completed
    );

    let (status, attempts): (String, i32) =
        sqlx::query_as("SELECT status, attempts FROM detection_late_replay_jobs WHERE id = $1")
            .bind(first.job_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "completed");
    assert_eq!(attempts, 1);

    // Completing the repair removes the priority fence and normal scheduling
    // resumes on the next claim cycle.
    let normal = repository
        .claim_due_rules(1, "normal-node", 360, true)
        .await
        .unwrap();
    assert_eq!(normal.len(), 1);
    assert_eq!(normal[0].id, rule_id);
    repository
        .release_claim(
            rule_id,
            "normal-node",
            Utc::now() + Duration::minutes(1),
            None,
        )
        .await
        .unwrap();
    let unchanged: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_run_at FROM detection_rules WHERE id = $1")
            .bind(rule_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(unchanged, Some(watermark));

    // Scheduler overflow uses the same fenced queue with an immutable window,
    // including for non-log datasets. Enqueue is idempotent and a productive
    // drain batch resets the failure budget instead of dead-lettering progress.
    let metric_rule_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO detection_rules (
            id, name, query, severity, schedule_cron, mode,
            detection_mode, last_run_at, next_run_at, lookback_minutes,
            dataset, kind
        )
        VALUES ($1, 'metric drain contract', '*', 'medium',
                '* * * * *', 'live', 'scheduled', $2, $3, 15,
                'metrics', 'standard')
        "#,
    )
    .bind(metric_rule_id)
    .bind(watermark)
    .bind(watermark + Duration::minutes(1))
    .execute(&pool)
    .await
    .unwrap();
    let drain_window =
        nanosiem_core::search::TimeRangeInput::new(watermark - Duration::minutes(5), watermark);
    repository
        .enqueue_window_drain(metric_rule_id, &drain_window)
        .await
        .unwrap();
    repository
        .enqueue_window_drain(metric_rule_id, &drain_window)
        .await
        .unwrap();
    let drain_jobs: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM detection_late_replay_jobs WHERE rule_id = $1")
            .bind(metric_rule_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(drain_jobs, 1);
    let drain = repository
        .claim_late_replays(1, "drain-node", Duration::minutes(6), Duration::minutes(6))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(drain.rule.id, metric_rule_id);
    assert_eq!(drain.time_range.start, drain_window.start);
    assert_eq!(drain.time_range.end, drain_window.end);
    assert_eq!(
        repository
            .release_late_replay(&drain, "drain-node", None, 3, Duration::days(7))
            .await
            .unwrap(),
        LateReplayReleaseOutcome::Completed
    );

    // Multiple unplanned publications for the same rule/store coalesce into
    // one unclaimed successor window instead of scheduling redundant scans.
    for (digest, start_offset, end_offset) in [("b".repeat(64), -10, -9), ("c".repeat(64), -20, -8)]
    {
        sqlx::query(
            r#"
            INSERT INTO lake_detection_event_publications (
                tenant_id, bronze_store_id, batch_sha256,
                min_event_time, max_event_time, published_at
            )
            VALUES ('tenant-a', 'rustfs:test:bronze', $1, $2, $3, $4)
            "#,
        )
        .bind(digest)
        .bind(watermark + Duration::minutes(start_offset))
        .bind(watermark + Duration::minutes(end_offset))
        .bind(Utc::now() - Duration::seconds(31))
        .execute(&pool)
        .await
        .unwrap();
    }
    let coalesced = repository
        .plan_late_replays(10, Duration::days(7), Duration::minutes(15))
        .await
        .unwrap();
    assert_eq!(coalesced.publications, 2);
    assert_eq!(coalesced.jobs, 1);
    assert_eq!(coalesced.coalesced, 1);
    let pending_jobs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM detection_late_replay_jobs WHERE rule_id = $1 AND status = 'pending'",
    )
    .bind(rule_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pending_jobs, 1);

    // Exhausting the count during an ordinary outage keeps the immutable job
    // pending until its repair horizon expires.
    let dead_letter = repository
        .claim_late_replays(1, "node-c", Duration::minutes(6), Duration::minutes(6))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        repository
            .release_late_replay(
                &dead_letter,
                "node-c",
                Some("temporary outage"),
                1,
                Duration::days(7),
            )
            .await
            .unwrap(),
        LateReplayReleaseOutcome::Retry
    );
    let retry_status: String =
        sqlx::query_scalar("SELECT status FROM detection_late_replay_jobs WHERE id = $1")
            .bind(dead_letter.job_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retry_status, "pending");

    // Once the same finite horizon expires, the next exhausted attempt is
    // retained as a visible dead letter instead of retrying forever.
    sqlx::query(
        "UPDATE detection_late_replay_jobs SET created_at = NOW() - INTERVAL '8 days', \
         next_attempt_at = NOW() WHERE id = $1",
    )
    .bind(dead_letter.job_id)
    .execute(&pool)
    .await
    .unwrap();
    let expired = repository
        .claim_late_replays(1, "node-c", Duration::minutes(6), Duration::minutes(6))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        repository
            .release_late_replay(&expired, "node-c", Some("permanent"), 1, Duration::days(7),)
            .await
            .unwrap(),
        LateReplayReleaseOutcome::DeadLetter
    );
    let dead_status: String =
        sqlx::query_scalar("SELECT status FROM detection_late_replay_jobs WHERE id = $1")
            .bind(dead_letter.job_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(dead_status, "dead_letter");
    let unchanged: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_run_at FROM detection_rules WHERE id = $1")
            .bind(rule_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(unchanged, Some(watermark));

    // Close the publication-vs-watermark race. A normal rule may have taken
    // its query snapshot before an event publication committed, then advance
    // its watermark after this planner pass. Publication after claimed_at is
    // therefore replay-worthy even when its event time is newer than the old
    // watermark; execution remains fenced behind the same rule claim.
    sqlx::query("UPDATE detection_rules SET archived = true WHERE id IN ($1, $2)")
        .bind(rule_id)
        .bind(metric_rule_id)
        .execute(&pool)
        .await
        .unwrap();
    let race_rule_id = Uuid::now_v7();
    let claimed_at = Utc::now() - Duration::seconds(40);
    sqlx::query(
        r#"
        INSERT INTO detection_rules (
            id, name, query, severity, schedule_cron, mode,
            detection_mode, last_run_at, next_run_at, lookback_minutes,
            dataset, kind, claimed_by, claimed_at
        )
        VALUES ($1, 'publication snapshot race', 'class_uid=3002', 'medium',
                '* * * * *', 'live', 'scheduled', $2, $3, 15,
                'logs', 'standard', 'normal-node', $4)
        "#,
    )
    .bind(race_rule_id)
    .bind(watermark)
    .bind(watermark + Duration::minutes(1))
    .bind(claimed_at)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO lake_detection_event_publications (
            tenant_id, bronze_store_id, batch_sha256,
            min_event_time, max_event_time, published_at
        ) VALUES ('tenant-a', 'rustfs:test:bronze', $1, $2, $3, $4)
        "#,
    )
    .bind("d".repeat(64))
    .bind(watermark + Duration::seconds(10))
    .bind(watermark + Duration::seconds(11))
    .bind(claimed_at + Duration::seconds(5))
    .execute(&pool)
    .await
    .unwrap();
    let race_plan = repository
        .plan_late_replays(10, Duration::days(7), Duration::minutes(15))
        .await
        .unwrap();
    assert_eq!(race_plan.jobs, 1);
    let race_window_end: DateTime<Utc> =
        sqlx::query_scalar("SELECT window_end FROM detection_late_replay_jobs WHERE rule_id = $1")
            .bind(race_rule_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(race_window_end > watermark);
    assert!(
        repository
            .claim_late_replays(1, "repair-node", Duration::minutes(6), Duration::minutes(6),)
            .await
            .unwrap()
            .is_empty(),
        "repair must yield while the normal rule owns its claim"
    );
    let advanced_watermark = watermark + Duration::minutes(1);
    sqlx::query(
        "UPDATE detection_rules SET last_run_at = $2, claimed_by = NULL, claimed_at = NULL \
         WHERE id = $1",
    )
    .bind(race_rule_id)
    .bind(advanced_watermark)
    .execute(&pool)
    .await
    .unwrap();
    let race_claim = repository
        .claim_late_replays(1, "repair-node", Duration::minutes(6), Duration::minutes(6))
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        repository
            .release_late_replay(&race_claim, "repair-node", None, 3, Duration::days(7))
            .await
            .unwrap(),
        LateReplayReleaseOutcome::Completed
    );
    let watermark_after_repair: DateTime<Utc> =
        sqlx::query_scalar("SELECT last_run_at FROM detection_rules WHERE id = $1")
            .bind(race_rule_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(watermark_after_repair, advanced_watermark);

    // Terminal repair metadata is useful but finite. Pending/running work is
    // never pruned; completed rows live one horizon and dead letters four.
    sqlx::query(
        "UPDATE detection_late_replay_jobs SET completed_at = NOW() - INTERVAL '8 days' \
         WHERE status = 'completed'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE detection_late_replay_jobs SET completed_at = NOW() - INTERVAL '29 days' \
         WHERE status = 'dead_letter'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE lake_detection_event_publications \
         SET planned_at = NOW() - INTERVAL '8 days' \
         WHERE planned_at IS NOT NULL",
    )
    .execute(&pool)
    .await
    .unwrap();
    let pruned = repository
        .plan_late_replays(10, Duration::days(7), Duration::minutes(15))
        .await
        .unwrap();
    assert!(pruned.pruned_jobs >= 2);
    assert!(pruned.pruned_publications >= 1);
}
