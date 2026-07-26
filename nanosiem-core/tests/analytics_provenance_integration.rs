// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2137 live regression coverage for durable analytics provenance.
//!
//! These ignored tests exercise the production migration, classifiers, and
//! writer chain against local PostgreSQL + ClickHouse.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use chrono::{Duration, Utc};
use clickhouse::Client;
use nanosiem_core::auth::{ArtifactScope, SourceProvenance};
use nanosiem_core::db::TableNames;
use nanosiem_core::siem_health::SiemHealthRepository;
use nanosiem_core::tuning::{BaselineMonitor, MetricsCollector, ThresholdDetector};
use serde_json::json;
use sqlx::PgPool;
use tokio::sync::OnceCell;
use uuid::Uuid;

static ENTERPRISE_MIGRATED: OnceCell<()> = OnceCell::const_new();

fn ch_url() -> String {
    std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}

fn ch_client() -> Client {
    Client::default()
        .with_url(ch_url())
        .with_user("nanosiem")
        .with_password("nanosiem")
        .with_database("nanosiem")
}

fn ch_insert_client() -> Client {
    ch_client()
        .with_option("async_insert", "0")
        .with_option("wait_end_of_query", "1")
}

async fn insert_rule(pool: &PgPool, label: &str) -> Uuid {
    let rule_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO detection_rules (id, name, description, query, severity, mode)
        VALUES ($1, $2, 'NAN-2137 provenance test', 'source_type=apache', 'medium', 'alerting')
        "#,
    )
    .bind(rule_id)
    .bind(format!("NAN-2137-{label}-{rule_id}"))
    .execute(pool)
    .await
    .expect("insert rule");
    rule_id
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

async fn cleanup_rule(pool: &PgPool, rule_id: Uuid) {
    let _ = sqlx::query("DELETE FROM detection_rules WHERE id = $1")
        .bind(rule_id)
        .execute(pool)
        .await;
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn migration_defaults_constraints_and_health_repository_fail_closed() {
    let pool = common::migrated_pool().await;
    let rule_id = insert_rule(&pool, "migration").await;

    // Omitting both new columns models a pre-feature analytics row.
    sqlx::query(
        r#"
        INSERT INTO detection_rule_metrics (
            rule_id, timestamp, alert_count_1h, alert_count_24h, alert_count_7d
        ) VALUES ($1, NOW(), 1, 1, 1)
        "#,
    )
    .bind(rule_id)
    .execute(&pool)
    .await
    .expect("insert legacy-shaped metric");
    let legacy: (Vec<String>, bool) = sqlx::query_as(
        r#"
        SELECT source_types, source_types_complete
        FROM detection_rule_metrics
        WHERE rule_id = $1
        "#,
    )
    .bind(rule_id)
    .fetch_one(&pool)
    .await
    .expect("read legacy defaults");
    assert!(legacy.0.is_empty());
    assert!(!legacy.1);

    let invalid = sqlx::query(
        r#"
        INSERT INTO detection_rule_metrics (
            rule_id, timestamp, alert_count_1h, alert_count_24h, alert_count_7d,
            source_types, source_types_complete
        ) VALUES ($1, NOW() - INTERVAL '1 minute', 1, 1, 1, '{}', TRUE)
        "#,
    )
    .bind(rule_id)
    .execute(&pool)
    .await;
    assert!(
        invalid.is_err(),
        "database must reject an empty manifest claiming completeness"
    );

    let provenance = SourceProvenance::incomplete([" Windows_Event ", "apache"]);
    let health_repo = SiemHealthRepository::new(pool.clone());
    let report = health_repo
        .insert(
            80,
            "healthy",
            80,
            80,
            80,
            80,
            80,
            "known-source envelope remains conservative",
            &json!({}),
            &json!([]),
            &json!({}),
            &provenance,
            None,
            Some(1),
        )
        .await
        .expect("store health report through production repository");
    let stored = health_repo
        .get_by_id(report.id)
        .await
        .expect("reload health report");
    assert_eq!(
        stored.source_types,
        vec!["apache".to_string(), "windows_event".to_string()]
    );
    assert!(!stored.source_types_complete);

    let _ = sqlx::query("DELETE FROM siem_health_reports WHERE id = $1")
        .bind(report.id)
        .execute(&pool)
        .await;
    cleanup_rule(&pool, rule_id).await;
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn postgres_metric_baseline_breach_chain_preserves_union_and_direction() {
    let pool = enterprise_pool().await;
    let rule_id = insert_rule(&pool, "lineage").await;
    let now = Utc::now();

    // Twenty-four complete historical snapshots spanning more than one day
    // satisfy the real baseline monitor's provisional-baseline gate.
    for index in 0..24 {
        let source_types = if index % 2 == 0 {
            vec!["apache".to_string()]
        } else {
            vec!["insider_threat".to_string()]
        };
        sqlx::query(
            r#"
            INSERT INTO detection_rule_metrics (
                rule_id, timestamp, alert_count_1h, alert_count_24h, alert_count_7d,
                source_types, source_types_complete
            ) VALUES ($1, $2, $3, $3, $3, $4, TRUE)
            "#,
        )
        .bind(rule_id)
        .bind(now - Duration::hours(48 - index))
        .bind(1_i64 + (index % 2) as i64)
        .bind(source_types)
        .execute(&pool)
        .await
        .expect("insert attributed metric");
    }

    let baseline_monitor = Arc::new(BaselineMonitor::new(pool.clone()));
    baseline_monitor
        .establish_baseline(rule_id)
        .await
        .expect("establish production baseline");
    let baseline_scope: (Vec<String>, bool) = sqlx::query_as(
        r#"
        SELECT source_types, source_types_complete
        FROM detection_rule_baselines
        WHERE rule_id = $1
        "#,
    )
    .bind(rule_id)
    .fetch_one(&pool)
    .await
    .expect("read baseline provenance");
    assert_eq!(
        baseline_scope.0,
        vec!["apache".to_string(), "insider_threat".to_string()]
    );
    assert!(baseline_scope.1);

    // The production threshold reader must union the current metric origin
    // with every baseline input before persisting the breach.
    sqlx::query(
        r#"
        INSERT INTO detection_rule_metrics (
            rule_id, timestamp, alert_count_1h, alert_count_24h, alert_count_7d,
            source_types, source_types_complete
        ) VALUES ($1, $2, 1000, 1000, 1000, ARRAY['windows_event'], TRUE)
        "#,
    )
    .bind(rule_id)
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert current attributed metric");

    let detector = ThresholdDetector::new(pool.clone(), baseline_monitor);
    let breaches = detector
        .check_thresholds()
        .await
        .expect("run production threshold detector");
    assert!(breaches.iter().any(|breach| breach.rule_id == rule_id));

    let breach_scope: (Vec<String>, bool) = sqlx::query_as(
        r#"
        SELECT source_types, source_types_complete
        FROM detection_threshold_breaches
        WHERE rule_id = $1
        ORDER BY detected_at DESC
        LIMIT 1
        "#,
    )
    .bind(rule_id)
    .fetch_one(&pool)
    .await
    .expect("read breach provenance");
    assert_eq!(
        breach_scope.0,
        vec![
            "apache".to_string(),
            "insider_threat".to_string(),
            "windows_event".to_string()
        ]
    );
    assert!(breach_scope.1);

    let denied = BTreeSet::from(["insider_threat".to_string()]);
    let scoped = ArtifactScope::from_denied(&denied);
    assert!(!scoped.allows(&breach_scope.0, breach_scope.1));
    let disjoint = ArtifactScope::from_denied(&BTreeSet::from(["secret_other".to_string()]));
    assert!(disjoint.allows(&breach_scope.0, breach_scope.1));

    cleanup_rule(&pool, rule_id).await;
}

async fn insert_finding(client: &Client, rule_id: Uuid, message: &str, origins: Option<&[&str]>) {
    let metadata = match origins {
        Some(origins) => json!({
            "origin_source_types": origins,
            "matched_events_sample": [{
                "source_type": origins.first().copied().unwrap_or_default(),
                "src_user": format!("user-{message}"),
                "src_host": format!("host-{message}"),
                "src_ip": "192.0.2.10"
            }]
        }),
        None => json!({
            "matched_events_sample": [{
                "source_type": "legacy_unknown",
                "src_user": format!("user-{message}")
            }]
        }),
    };
    let escaped_metadata = metadata.to_string().replace('\'', "''");
    let escaped_message = message.replace('\'', "''");
    let sql = format!(
        "INSERT INTO nanosiem.logs \
         (id, timestamp, source_type, message, rule_id, severity, metadata) \
         VALUES (generateUUIDv4(), now(), 'findings', '{escaped_message}', \
                 '{rule_id}', 'high', '{escaped_metadata}')"
    );
    client
        .query(&sql)
        .execute()
        .await
        .expect("insert finding fixture");
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL + ClickHouse validation"]
async fn clickhouse_collector_stamps_exact_full_window_origins_and_legacy_incomplete() {
    let pool = common::migrated_pool().await;
    let rule_id = insert_rule(&pool, "clickhouse").await;
    let client = ch_insert_client();

    client
        .query("SELECT 1")
        .execute()
        .await
        .expect("local ClickHouse must be reachable");

    insert_finding(&client, rule_id, "allowed", Some(&[" Apache "])).await;
    insert_finding(
        &client,
        rule_id,
        "mixed",
        Some(&["apache", "insider_threat"]),
    )
    .await;

    let collector = MetricsCollector::new(pool.clone(), ch_client(), TableNames::new(false));
    let first = collector
        .collect_and_store_rule_metrics(rule_id)
        .await
        .expect("collect and persist real finding aggregate");
    assert_eq!(first.value.alert_count_7d, 2);
    assert_eq!(
        first.provenance.source_types(),
        &["apache".to_string(), "insider_threat".to_string()]
    );
    assert!(first.provenance.is_complete());

    let persisted: (Vec<String>, bool) = sqlx::query_as(
        r#"
        SELECT source_types, source_types_complete
        FROM detection_rule_metrics
        WHERE rule_id = $1
        ORDER BY timestamp DESC
        LIMIT 1
        "#,
    )
    .bind(rule_id)
    .fetch_one(&pool)
    .await
    .expect("read persisted collector provenance");
    assert_eq!(persisted.0, first.provenance.source_types());
    assert!(persisted.1);
    assert!(
        !ArtifactScope::from_denied(&BTreeSet::from(["insider_threat".to_string()]))
            .allows(&persisted.0, persisted.1)
    );

    // A pre-provenance finding in the same exact aggregate window poisons
    // completeness while retaining every origin the producer did identify.
    insert_finding(&client, rule_id, "legacy", None).await;
    let second = collector
        .collect_rule_metrics_with_provenance(rule_id)
        .await
        .expect("recollect with legacy input");
    assert_eq!(second.value.alert_count_7d, 3);
    assert_eq!(
        second.provenance.source_types(),
        &[
            "apache".to_string(),
            "insider_threat".to_string(),
            "legacy_unknown".to_string()
        ]
    );
    assert!(!second.provenance.is_complete());
    assert!(
        !ArtifactScope::from_denied(&BTreeSet::from(["unrelated".to_string()]))
            .allows_provenance(&second.provenance),
        "every restricted reader must fail closed on unattributed input"
    );

    let _ = client
        .query(&format!(
            "DELETE FROM nanosiem.logs WHERE source_type = 'findings' AND rule_id = '{rule_id}'"
        ))
        .execute()
        .await;
    cleanup_rule(&pool, rule_id).await;
}
