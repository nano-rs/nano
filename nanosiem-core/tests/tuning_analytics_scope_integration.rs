// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2086 DB-backed regression coverage for tuning analytics reads.
//!
//! These tests invoke the production [`TuningRepository`] SQL against migrated
//! PostgreSQL. They do not reproduce the visibility predicate in test code.

mod common;

use std::collections::BTreeSet;

use chrono::{Duration, Utc};
use nanosiem_core::tuning::{TuningRepository, TuningScope};
use sqlx::PgPool;
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

fn denied(values: &[&str]) -> TuningScope {
    TuningScope::from_denied(&BTreeSet::from_iter(
        values.iter().map(|value| value.to_string()),
    ))
}

async fn insert_rule(pool: &PgPool, label: &str) -> Uuid {
    let rule_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO detection_rules (id, name, description, query, severity, mode)
        VALUES ($1, $2, 'NAN-2086 tuning analytics scope test', 'source_type=apache', 'medium', 'alerting')
        "#,
    )
    .bind(rule_id)
    .bind(format!("NAN-2086-{label}-{rule_id}"))
    .execute(pool)
    .await
    .expect("insert rule");
    rule_id
}

async fn insert_metric(
    pool: &PgPool,
    rule_id: Uuid,
    age_minutes: i64,
    sentinel: i64,
    source_types: &[&str],
    complete: bool,
) {
    let source_types: Vec<String> = source_types.iter().map(|value| value.to_string()).collect();
    sqlx::query(
        r#"
        INSERT INTO detection_rule_metrics (
            rule_id, timestamp, alert_count_1h, alert_count_24h, alert_count_7d,
            unique_users, unique_hosts, unique_ips, avg_severity,
            source_types, source_types_complete
        ) VALUES ($1, $2, $3, $3, $3, $3, $3, $3, $3::double precision, $4, $5)
        "#,
    )
    .bind(rule_id)
    .bind(Utc::now() - Duration::minutes(age_minutes))
    .bind(sentinel)
    .bind(source_types)
    .bind(complete)
    .execute(pool)
    .await
    .expect("insert metric");
}

async fn insert_baseline(
    pool: &PgPool,
    rule_id: Uuid,
    sentinel: f64,
    source_types: &[&str],
    complete: bool,
) {
    let source_types: Vec<String> = source_types.iter().map(|value| value.to_string()).collect();
    sqlx::query(
        r#"
        INSERT INTO detection_rule_baselines (
            rule_id, established_at, last_updated, mean_alerts_per_hour,
            std_dev_alerts_per_hour, percentile_95, percentile_99,
            threshold_breach_level, data_points, source_types, source_types_complete
        ) VALUES ($1, NOW() - INTERVAL '8 days', NOW(), $2, 1, $2, $2, $2, 168, $3, $4)
        "#,
    )
    .bind(rule_id)
    .bind(sentinel)
    .bind(source_types)
    .bind(complete)
    .execute(pool)
    .await
    .expect("insert baseline");
}

async fn insert_breach(
    pool: &PgPool,
    rule_id: Uuid,
    age_minutes: i64,
    sentinel: f64,
    source_types: &[&str],
    complete: bool,
) {
    let source_types: Vec<String> = source_types.iter().map(|value| value.to_string()).collect();
    sqlx::query(
        r#"
        INSERT INTO detection_threshold_breaches (
            rule_id, detected_at, current_value, baseline_mean,
            baseline_threshold, deviation_magnitude, consecutive_periods,
            source_types, source_types_complete
        ) VALUES ($1, $2, $3, 1, 2, $3, 1, $4, $5)
        "#,
    )
    .bind(rule_id)
    .bind(Utc::now() - Duration::minutes(age_minutes))
    .bind(sentinel)
    .bind(source_types)
    .bind(complete)
    .execute(pool)
    .await
    .expect("insert breach");
}

async fn insert_all_artifacts(
    pool: &PgPool,
    rule_id: Uuid,
    sentinel: i64,
    source_types: &[&str],
    complete: bool,
) {
    insert_metric(pool, rule_id, 0, sentinel, source_types, complete).await;
    insert_baseline(pool, rule_id, sentinel as f64, source_types, complete).await;
    insert_breach(pool, rule_id, 0, sentinel as f64, source_types, complete).await;
}

async fn assert_all_hidden(repo: &TuningRepository, rule_id: Uuid, scope: &TuningScope) {
    assert!(repo
        .get_baseline_for_scope(rule_id, scope)
        .await
        .expect("get baseline")
        .is_none());
    assert!(repo
        .list_metrics_for_scope(rule_id, 100, scope)
        .await
        .expect("list metrics")
        .is_empty());
    assert!(repo
        .list_breaches_for_scope(rule_id, 100, scope)
        .await
        .expect("list breaches")
        .is_empty());
}

async fn assert_all_visible(
    repo: &TuningRepository,
    rule_id: Uuid,
    sentinel: i64,
    scope: &TuningScope,
) {
    let baseline = repo
        .get_baseline_for_scope(rule_id, scope)
        .await
        .expect("get baseline")
        .expect("baseline visible");
    assert_eq!(baseline.mean_alerts_per_hour, sentinel as f64);

    let metrics = repo
        .list_metrics_for_scope(rule_id, 100, scope)
        .await
        .expect("list metrics");
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0].alert_count_1h, sentinel);

    let breaches = repo
        .list_breaches_for_scope(rule_id, 100, scope)
        .await
        .expect("list breaches");
    assert_eq!(breaches.len(), 1);
    assert_eq!(breaches[0].current_value, sentinel as f64);
}

#[tokio::test]
#[ignore = "requires PostgreSQL; runs production tuning repository SQL"]
async fn production_reads_fail_closed_for_denied_mixed_and_legacy_artifacts() {
    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let denied_rule = insert_rule(&pool, "denied").await;
    let mixed_rule = insert_rule(&pool, "mixed").await;
    let legacy_rule = insert_rule(&pool, "legacy").await;
    let allowed_rule = insert_rule(&pool, "allowed").await;

    insert_all_artifacts(&pool, denied_rule, 11, &["insider_threat"], true).await;
    insert_all_artifacts(&pool, mixed_rule, 22, &["apache", "insider_threat"], true).await;
    insert_all_artifacts(&pool, legacy_rule, 33, &[], false).await;
    insert_all_artifacts(&pool, allowed_rule, 44, &["apache"], true).await;

    let scope = denied(&["insider_threat"]);
    assert_all_hidden(&repo, denied_rule, &scope).await;
    assert_all_hidden(&repo, mixed_rule, &scope).await;
    assert_all_hidden(&repo, legacy_rule, &scope).await;
    assert_all_visible(&repo, allowed_rule, 44, &scope).await;

    // Unrestricted system/view-all readers preserve pre-feature behavior,
    // including access to legacy rows whose provenance cannot be reconstructed.
    assert_all_visible(&repo, legacy_rule, 33, &TuningScope::system()).await;

    for rule_id in [denied_rule, mixed_rule, legacy_rule, allowed_rule] {
        sqlx::query("DELETE FROM detection_rules WHERE id = $1")
            .bind(rule_id)
            .execute(&pool)
            .await
            .expect("cleanup rule");
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL; runs production tuning repository SQL"]
async fn current_scope_revokes_old_rows_and_filtering_precedes_limit() {
    let pool = enterprise_pool().await;
    let repo = TuningRepository::new(pool.clone());
    let rule_id = insert_rule(&pool, "revocation").await;

    insert_baseline(&pool, rule_id, 55.0, &["apache"], true).await;
    // Newer denied rows must not consume the single visible page slot.
    insert_metric(&pool, rule_id, 0, 66, &["insider_threat"], true).await;
    insert_metric(&pool, rule_id, 1, 55, &["apache"], true).await;
    insert_breach(&pool, rule_id, 0, 66.0, &["insider_threat"], true).await;
    insert_breach(&pool, rule_id, 1, 55.0, &["apache"], true).await;

    let before_restriction = denied(&["unrelated"]);
    assert!(repo
        .get_baseline_for_scope(rule_id, &before_restriction)
        .await
        .expect("get baseline")
        .is_some());

    let insider_restricted = denied(&["insider_threat"]);
    let metrics = repo
        .list_metrics_for_scope(rule_id, 1, &insider_restricted)
        .await
        .expect("list metrics");
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0].alert_count_1h, 55);
    let breaches = repo
        .list_breaches_for_scope(rule_id, 1, &insider_restricted)
        .await
        .expect("list breaches");
    assert_eq!(breaches.len(), 1);
    assert_eq!(breaches[0].current_value, 55.0);

    // The rows are unchanged; only the current caller scope changes. A source
    // restriction added after collection revokes every affected artifact.
    let apache_restricted = denied(&["apache"]);
    assert!(repo
        .get_baseline_for_scope(rule_id, &apache_restricted)
        .await
        .expect("get baseline")
        .is_none());
    assert_eq!(
        repo.list_metrics_for_scope(rule_id, 100, &apache_restricted)
            .await
            .expect("list metrics")
            .len(),
        1,
        "the unrelated insider_threat metric remains visible"
    );
    assert_eq!(
        repo.list_breaches_for_scope(rule_id, 100, &apache_restricted)
            .await
            .expect("list breaches")
            .len(),
        1,
        "the unrelated insider_threat breach remains visible"
    );

    sqlx::query("DELETE FROM detection_rules WHERE id = $1")
        .bind(rule_id)
        .execute(&pool)
        .await
        .expect("cleanup rule");
}
