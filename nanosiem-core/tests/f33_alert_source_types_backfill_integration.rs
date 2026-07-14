// SPDX-License-Identifier: AGPL-3.0-or-later

//! F-33 regression test: the migration-250 backfill of `alerts.source_types`.
//!
//! Migration 246 added `alerts.source_types TEXT[] DEFAULT '{}'` with NO
//! backfill, so every pre-feature `kind='detection'` alert carried `'{}'` (=
//! visible-to-all) even when its `matched_events[0].source_type` was a restricted
//! source — leaking that evidence to a source-denied viewer. Migration 250
//! derives the real source types from `matched_events` (fail-closed to the
//! restricted registry when derivation is empty) for DETECTION rows only.
//!
//! The critical guardrail against the NAIVE fix (deny-on-empty, which would hide
//! ALL observability/risk alerts): `metric_monitor` / `risk_notable` empty-stamp
//! rows MUST stay visible.
//!
//! Gated like the sibling DB suites: compiles with every `cargo test` (drift
//! catch) but is `#[ignore]`d — run via `pg-integration-tests` CI, or locally
//! with `docker compose up -d postgres` and `cargo test -- --ignored`.

mod common;

use std::collections::BTreeSet;

use nanosiem_core::db::repository::{AlertRepository, AlertRepositoryError};
use sqlx::PgPool;
use uuid::Uuid;

/// Insert a legacy alert directly (bypassing `create_alert`, which would stamp
/// `source_types` from `matched_events` — we need the pre-feature `'{}'` state).
/// Returns the new alert id.
async fn insert_legacy_alert(
    pool: &PgPool,
    kind: &str,
    matched_events: serde_json::Value,
) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO alerts (rule_id, severity, matched_events, kind, source_types)
        VALUES (NULL, 'high', $1::jsonb, $2, '{}')
        RETURNING id
        "#,
    )
    .bind(matched_events)
    .bind(kind)
    .fetch_one(pool)
    .await
    .expect("insert legacy alert")
}

async fn source_types_of(pool: &PgPool, id: Uuid) -> Vec<String> {
    sqlx::query_scalar::<_, Vec<String>>("SELECT source_types FROM alerts WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read source_types")
}

fn deny(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

/// The backfill stamps a legacy DETECTION alert with the source types derived
/// from its matched events, so a viewer denied that source now gets an
/// indistinguishable 404 — while empty-stamp observability/risk alerts stay
/// visible (the anti-naive-fix guardrail).
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn backfill_stamps_detection_leaves_observability_visible() {
    let pool = common::migrated_pool().await;
    let repo = AlertRepository::new(pool.clone());

    // A legacy DETECTION alert whose only evidence is a windows_sysmon event,
    // stamped '{}' (pre-feature) so today it leaks to a windows_sysmon-denied
    // viewer.
    let detection = insert_legacy_alert(
        &pool,
        "detection",
        serde_json::json!([
            {"source_type": "windows_sysmon", "message": "suspicious powershell"}
        ]),
    )
    .await;

    // Non-source-derived producers: these legitimately carry no source_type and
    // MUST stay visible after the backfill (guardrail against deny-on-empty).
    let metric = insert_legacy_alert(&pool, "metric_monitor", serde_json::json!([])).await;
    let risk = insert_legacy_alert(&pool, "risk_notable", serde_json::json!([])).await;

    // Run the EXACT migration-250 SQL (idempotent; re-running over the already
    // migrated DB only touches our just-inserted '{}' rows). No drift vs prod.
    sqlx::raw_sql(include_str!(
        "../../migrations/postgres/251_alert_source_types_backfill.sql"
    ))
    .execute(&pool)
    .await
    .expect("run migration 250 backfill");

    // Column-level: detection derived its real source, others stayed '{}'.
    assert_eq!(
        source_types_of(&pool, detection).await,
        vec!["windows_sysmon".to_string()],
        "detection alert must be stamped with its derived source_type"
    );
    assert!(
        source_types_of(&pool, metric).await.is_empty(),
        "metric_monitor must stay '{{}}' (non-source-derived)"
    );
    assert!(
        source_types_of(&pool, risk).await.is_empty(),
        "risk_notable must stay '{{}}' (non-source-derived)"
    );

    // Read-path: a windows_sysmon-denied viewer gets NotFound for the detection
    // alert (indistinguishable 404), Ok for the observability/risk alerts.
    let denied = deny(&["windows_sysmon"]);

    assert!(
        matches!(
            repo.find_by_id(detection, &denied).await,
            Err(AlertRepositoryError::NotFound(_))
        ),
        "backfilled detection alert must be 404 for a windows_sysmon-denied viewer"
    );
    // Same alert is still readable with no deny (proves the row exists — the 404
    // above is a redaction, not a missing row).
    assert!(
        repo.find_by_id(detection, &BTreeSet::new()).await.is_ok(),
        "detection alert must still be visible to an unrestricted viewer"
    );
    assert!(
        repo.find_by_id(metric, &denied).await.is_ok(),
        "empty-stamp metric_monitor must stay visible to a restricted viewer"
    );
    assert!(
        repo.find_by_id(risk, &denied).await.is_ok(),
        "empty-stamp risk_notable must stay visible to a restricted viewer"
    );

    // Idempotency: a second backfill run must NOT change the already-stamped rows.
    sqlx::raw_sql(include_str!(
        "../../migrations/postgres/251_alert_source_types_backfill.sql"
    ))
    .execute(&pool)
    .await
    .expect("re-run migration 250 backfill (idempotent)");
    assert_eq!(
        source_types_of(&pool, detection).await,
        vec!["windows_sysmon".to_string()],
        "re-running the backfill must be idempotent"
    );

    // Best-effort cleanup.
    for id in [detection, metric, risk] {
        let _ = sqlx::query("DELETE FROM alerts WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await;
    }
}
