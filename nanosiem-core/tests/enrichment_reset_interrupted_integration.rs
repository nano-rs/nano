// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration test for NAN-1280: startup reconciliation re-queues enrichment
//! syncs orphaned by a restart (stuck `in_progress`) to `pending`, while
//! leaving terminal-status sources untouched and behaving idempotently.

mod common;

use nanosiem_core::enrichment::{EnrichmentRepository, EnrichmentSourceConfig, SyncStatus};

fn cfg(id: &str) -> EnrichmentSourceConfig {
    EnrichmentSourceConfig {
        id: id.to_string(),
        name: format!("Test {id}"),
        source_type: "ipinfo_lite".to_string(),
        description: None,
        download_url: Some("https://example.test/feed.csv.gz".to_string()),
        config: Some(serde_json::json!({})),
        enabled: true,
    }
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn reset_interrupted_syncs_requeues_only_in_progress() {
    let pool = common::migrated_pool().await;
    let repo = EnrichmentRepository::new(pool.clone());

    // Unique ids so parallel suites / reruns don't collide.
    let stuck = format!("nan1280_stuck_{}", uuid::Uuid::now_v7());
    let done = format!("nan1280_done_{}", uuid::Uuid::now_v7());

    repo.upsert_source(&cfg(&stuck)).await.unwrap();
    repo.upsert_source(&cfg(&done)).await.unwrap();

    // One orphaned mid-sync, one cleanly finished.
    repo.update_sync_status(&stuck, SyncStatus::InProgress, None, None, None)
        .await
        .unwrap();
    repo.update_sync_status(&done, SyncStatus::Success, None, Some(42), None)
        .await
        .unwrap();

    // Reconcile: only the orphaned in_progress source is re-queued.
    let reset = repo.reset_interrupted_syncs().await.unwrap();
    assert!(
        reset.contains(&stuck),
        "stuck in_progress source should be reset, got {reset:?}"
    );
    assert!(
        !reset.contains(&done),
        "cleanly-finished source must not be touched"
    );

    let stuck_after = repo.get_source(&stuck).await.unwrap();
    assert_eq!(stuck_after.last_sync_status.as_deref(), Some("pending"));
    assert_eq!(
        stuck_after.last_sync_error.as_deref(),
        Some("Previous sync interrupted by service restart")
    );

    let done_after = repo.get_source(&done).await.unwrap();
    assert_eq!(done_after.last_sync_status.as_deref(), Some("success"));

    // Idempotent: a second pass finds nothing still in_progress to reset.
    let reset2 = repo.reset_interrupted_syncs().await.unwrap();
    assert!(
        !reset2.contains(&stuck),
        "already-pending source must not be reset again"
    );

    // Cleanup (best-effort).
    let _ = sqlx::query("DELETE FROM enrichment_sources WHERE id = ANY($1)")
        .bind(vec![stuck, done])
        .execute(&pool)
        .await;
}
