// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5772 live PostgreSQL tests: a deleted (archived) rule drops out of every
//! detection-health count and list: SIEM Health `metrics.detection`
//! (`total_enabled_rules`, `rules_by_mode`, `noisy_rules`, `stale_rules`,
//! `coverage_gaps_7d*`), `/health/detailed` (`coverage_gaps_24h`), and the
//! `GET /api/rules/health-summary` noisy count.
//!
//! Each test runs in a transaction that is rolled back. It first parks every
//! pre-existing rule (`mode = 'paused'`) and clears pre-existing coverage
//! gaps, so the counts it asserts are exactly its own rows, on any database.
//!
//! Every archived case appears twice: as the delete path leaves it
//! (`archived = TRUE`, mode reset to `staging`, as `archive_for_delete` does)
//! and as a legacy archived row that kept a running mode. The legacy row is the
//! one that proves each `archived = FALSE` filter on its own, since a mode
//! filter alone already hides a `staging` row.
//!
//! Against a disposable, fully migrated database only:
//!
//! ```text
//! NANOSIEM_TEST_DATABASE_URL=postgres://nanosiem:test@127.0.0.1:38433/nanosiem \
//!   cargo test -p nanosiem-core --lib -- detection_metrics_archived_tests --ignored --test-threads=1
//! ```

use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

use super::collect_detection_metrics_on;
use crate::db::repository::detection_rules::delete_archive_live_tests::pool;
use crate::detection::health::{count_noisy_rules, read_execution_health};
use crate::siem_health::types::DetectionMetrics;

/// Past the SIEM Health noisy bar (1000 today) and the health-summary weekly
/// bar (500 over 7 days).
const NOISY: i64 = 5_000;
const WEEKLY_THRESHOLD: i64 = 500;

/// A transaction that sees only the rules and coverage gaps the test adds.
async fn scoped(pool: &sqlx::PgPool) -> Transaction<'static, Postgres> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("UPDATE detection_rules SET mode = 'paused'")
        .execute(&mut *tx)
        .await
        .expect("park existing rules");
    sqlx::query("DELETE FROM detection_coverage_gaps")
        .execute(&mut *tx)
        .await
        .expect("clear existing gaps");
    tx
}

/// Inserts a rule and returns its id. `tag` names the case in assertions.
async fn insert_rule(conn: &mut PgConnection, tag: &str, mode: &str, archived: bool) -> (Uuid, String) {
    let name = format!("nan_5772_{tag}_{}", Uuid::new_v4().simple());
    let id = sqlx::query_scalar(
        "INSERT INTO detection_rules (name, query, severity, mode, archived) \
         VALUES ($1, 'class_uid=3002', 'medium', $2, $3) RETURNING id",
    )
    .bind(&name)
    .bind(mode)
    .bind(archived)
    .fetch_one(conn)
    .await
    .expect("insert rule");
    (id, name)
}

/// What `DetectionRuleRepository::archive_for_delete` does to the row.
async fn delete_rule(conn: &mut PgConnection, id: Uuid) {
    sqlx::query("UPDATE detection_rules SET archived = TRUE, mode = 'staging' WHERE id = $1")
        .bind(id)
        .execute(conn)
        .await
        .expect("archive");
}

async fn record_matches(conn: &mut PgConnection, id: Uuid, matches: i64) {
    sqlx::query(
        "INSERT INTO detection_daily_stats (rule_id, date, match_count, alert_count) \
         VALUES ($1, CURRENT_DATE, $2, 0)",
    )
    .bind(id)
    .bind(matches)
    .execute(conn)
    .await
    .expect("record matches");
}

async fn record_gap(conn: &mut PgConnection, id: Uuid) {
    sqlx::query(
        "INSERT INTO detection_coverage_gaps (rule_id, window_start, window_end, attempts, error_message) \
         VALUES ($1, NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour', 3, 'nan-5772 test gap')",
    )
    .bind(id)
    .execute(conn)
    .await
    .expect("record gap");
}

fn by_mode(metrics: &DetectionMetrics) -> Vec<(String, i64)> {
    let mut modes: Vec<_> = metrics.rules_by_mode.iter().map(|m| (m.mode.clone(), m.count)).collect();
    modes.sort();
    modes
}

fn noisy(metrics: &DetectionMetrics) -> Vec<String> {
    metrics.noisy_rules.iter().map(|r| r.rule_name.clone()).collect()
}

fn stale(metrics: &DetectionMetrics) -> Vec<String> {
    metrics.stale_rules.iter().map(|r| r.rule_name.clone()).collect()
}

fn gaps(metrics: &DetectionMetrics) -> Vec<String> {
    metrics.coverage_gaps_7d.iter().map(|g| g.rule_name.clone()).collect()
}

#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn siem_health_detection_metrics_count_only_existing_rules() {
    let Some(pool) = pool().await else { return };
    let mut tx = scoped(&pool).await;

    // Kept: a noisy live rule with a gap, a never-matched alerting rule
    // (stale), and a noisy staging draft (enabled, but it does not execute).
    let (live, live_name) = insert_rule(&mut tx, "live", "live", false).await;
    record_matches(&mut tx, live, NOISY).await;
    record_gap(&mut tx, live).await;
    let (_alerting, alerting_name) = insert_rule(&mut tx, "alerting", "alerting", false).await;
    let (draft, _) = insert_rule(&mut tx, "draft", "staging", false).await;
    record_matches(&mut tx, draft, NOISY).await;
    let (paused, _) = insert_rule(&mut tx, "paused", "paused", false).await;
    record_matches(&mut tx, paused, NOISY).await;

    // Gone: a legacy archived alerting rule (never matched, noisy, gap) and a
    // rule deleted through the delete path (noisy, gap).
    let (legacy, _) = insert_rule(&mut tx, "legacy", "alerting", true).await;
    record_matches(&mut tx, legacy, NOISY).await;
    record_gap(&mut tx, legacy).await;
    let (deleted, _) = insert_rule(&mut tx, "deleted", "live", false).await;
    record_matches(&mut tx, deleted, NOISY).await;
    record_gap(&mut tx, deleted).await;
    delete_rule(&mut tx, deleted).await;

    let m = collect_detection_metrics_on(&mut tx).await;
    assert_eq!(m.total_enabled_rules, 3, "total_enabled_rules: live + alerting + staging draft");
    assert_eq!(
        by_mode(&m),
        vec![("alerting".into(), 1), ("live".into(), 1), ("staging".into(), 1)],
        "rules_by_mode"
    );
    assert_eq!(noisy(&m), vec![live_name.clone()], "noisy_rules: running, non-archived rules only");
    assert_eq!(stale(&m), vec![alerting_name.clone()], "stale_rules");
    assert_eq!(m.coverage_gaps_7d_total, 1, "coverage_gaps_7d_total");
    assert_eq!(gaps(&m), vec![live_name.clone()], "coverage_gaps_7d");
    // History stays: every rule's matches still count toward engine activity.
    assert_eq!(m.total_matches_24h, 5 * NOISY, "total_matches_24h keeps match history");

    // Deleting the live rule takes it out of every count and list at once.
    delete_rule(&mut tx, live).await;
    let after = collect_detection_metrics_on(&mut tx).await;
    assert_eq!(after.total_enabled_rules, 2, "total_enabled_rules after delete");
    assert_eq!(
        by_mode(&after),
        vec![("alerting".into(), 1), ("staging".into(), 1)],
        "rules_by_mode after delete: the deleted rule is not a staging rule"
    );
    assert!(noisy(&after).is_empty(), "noisy_rules after delete: {:?}", noisy(&after));
    assert_eq!(after.coverage_gaps_7d_total, 0, "coverage_gaps_7d_total after delete");
    assert!(gaps(&after).is_empty(), "coverage_gaps_7d after delete");
    assert_eq!(after.total_matches_24h, 5 * NOISY, "match history kept after delete");

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn execution_health_ignores_coverage_gaps_of_deleted_rules() {
    let Some(pool) = pool().await else { return };
    let mut tx = scoped(&pool).await;

    let (live, _) = insert_rule(&mut tx, "gap_live", "live", false).await;
    record_gap(&mut tx, live).await;
    let (legacy, _) = insert_rule(&mut tx, "gap_legacy", "alerting", true).await;
    record_gap(&mut tx, legacy).await;

    let health = read_execution_health(&mut *tx).await.expect("health");
    assert_eq!(health.coverage_gaps_24h, 1, "only the existing rule's gap counts");
    assert_eq!(health.status, "degraded");

    delete_rule(&mut tx, live).await;
    let health = read_execution_health(&mut *tx).await.expect("health");
    assert_eq!(health.coverage_gaps_24h, 0, "a deleted rule's gap no longer degrades health");
    assert_eq!(health.status, "ok");

    tx.rollback().await.expect("rollback");
}

#[tokio::test]
#[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
async fn health_summary_noisy_count_counts_only_existing_running_rules() {
    let Some(pool) = pool().await else { return };
    let mut tx = scoped(&pool).await;

    let (live, _) = insert_rule(&mut tx, "sum_live", "live", false).await;
    record_matches(&mut tx, live, NOISY).await;
    let (quiet, _) = insert_rule(&mut tx, "sum_quiet", "alerting", false).await;
    record_matches(&mut tx, quiet, WEEKLY_THRESHOLD).await;
    for (tag, mode, archived) in [
        ("sum_legacy", "live", true),
        ("sum_draft", "staging", false),
        ("sum_paused", "paused", false),
    ] {
        let (id, _) = insert_rule(&mut tx, tag, mode, archived).await;
        record_matches(&mut tx, id, NOISY).await;
    }

    assert_eq!(count_noisy_rules(&mut *tx, WEEKLY_THRESHOLD).await.expect("count"), 1);

    delete_rule(&mut tx, live).await;
    assert_eq!(
        count_noisy_rules(&mut *tx, WEEKLY_THRESHOLD).await.expect("count"),
        0,
        "health-summary noisy_count drops the deleted rule"
    );
    let kept: i64 = sqlx::query_scalar("SELECT SUM(match_count)::bigint FROM detection_daily_stats WHERE rule_id = $1")
        .bind(live)
        .fetch_one(&mut *tx)
        .await
        .expect("history");
    assert_eq!(kept, NOISY, "the deleted rule's match history stays");

    tx.rollback().await.expect("rollback");
}
