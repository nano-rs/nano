// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5606 — a source-scoped reader cannot read a `hunt_finding` alert (or its
//! event copies) whose sources it is denied, through any alert read path the
//! alert API uses: get, list, the stream (even with `include_hunt_findings`),
//! and the counts. The alert's `source_types` is the hunt finding's manifest
//! (plus the unresolved sentinel when incomplete), and every one of these
//! reads applies the caller's deny set to it.
//!
//! `NANO_TEST_DATABASE_URL=postgres://… cargo test -p nanosiem-core --lib -- alerts_hunt_finding_scope --ignored`

use std::collections::BTreeSet;

use chrono::{Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use super::*;

async fn pool() -> PgPool {
    let url = nanosiem_test_db::require_pg_url();
    sqlx::postgres::PgPoolOptions::new().max_connections(3).connect(&url).await.unwrap()
}

async fn hunt_alert(repo: &AlertRepository, manifest: &[&str]) -> Uuid {
    let events = json!([{"id": "ev-1", "source_type": "sysmon", "src_host": "WS-1", "command_line": "secret"}]);
    let manifest: Vec<String> = manifest.iter().map(|s| s.to_string()).collect();
    repo.create_alert_with_manifest(
        AlertInsert {
            kind: "hunt_finding",
            rule_id: None,
            source_id: Some(format!("lead_nan5606_{}", Uuid::new_v4().simple())),
            severity: &Severity::High,
            matched_events: &events,
            event_hash: None,
            match_count: Some(1),
        },
        &manifest,
    )
    .await
    .unwrap()
    .id
}

fn deny(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|s| s.to_string()).collect()
}

/// Deletes the test's alerts even when an assertion fails.
struct Cleanup(PgPool, Vec<Uuid>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let (pool, ids) = (self.0.clone(), std::mem::take(&mut self.1));
        let _ = std::thread::spawn(move || {
            tokio::runtime::Runtime::new().unwrap().block_on(async move {
                sqlx::query("DELETE FROM alerts WHERE id = ANY($1)").bind(ids).execute(&pool).await.ok();
            })
        })
        .join();
    }
}

#[tokio::test]
#[ignore = "requires NANO_TEST_DATABASE_URL (a throwaway Postgres with the full schema)"]
async fn a_reader_denied_the_findings_sources_cannot_read_its_alert_anywhere() {
    let pool = pool().await;
    let repo = AlertRepository::new(pool.clone());
    // Source names unique to this run, so the assertions are exact on a shared database.
    let src = format!("nan5606_{}", Uuid::new_v4().simple());
    let other = format!("nan5606_other_{}", Uuid::new_v4().simple());
    let complete = hunt_alert(&repo, &[src.as_str()]).await;
    let incomplete = hunt_alert(&repo, &[src.as_str(), crate::auth::UNRESOLVED_SOURCE_SENTINEL]).await;
    let _cleanup = Cleanup(pool.clone(), vec![complete, incomplete]);
    let kinds = vec!["hunt_finding".to_string()];
    let denied_src = deny(&[src.as_str()]);
    let denied_other = deny(&[other.as_str()]);
    let unrestricted = BTreeSet::new();

    // get
    assert!(matches!(repo.find_by_id(complete, &denied_src).await, Err(AlertRepositoryError::NotFound(_))));
    // A restricted reader's deny carries the unresolved sentinel: an
    // incomplete manifest is hidden even when its known sources are allowed.
    assert!(matches!(repo.find_by_id(incomplete, &denied_other).await, Err(AlertRepositoryError::NotFound(_))));
    assert!(repo.find_by_id(complete, &denied_other).await.is_ok());
    assert!(repo.find_by_id(incomplete, &unrestricted).await.is_ok());

    // list (the kind named explicitly)
    let ids = |v: Vec<Alert>| v.into_iter().map(|a| a.id).collect::<Vec<_>>();
    let listed = ids(repo.list(None, None, Some(kinds.as_slice()), 1000, 0, &denied_src).await.unwrap());
    assert!(!listed.contains(&complete) && !listed.contains(&incomplete));
    let listed = ids(repo.list(None, None, Some(kinds.as_slice()), 1000, 0, &denied_other).await.unwrap());
    assert!(listed.contains(&complete) && !listed.contains(&incomplete));

    // stream, opted in
    let since = Utc::now() - Duration::hours(1);
    let streamed = ids(repo.list_after(since, Uuid::nil(), 1000, &denied_src, true).await.unwrap());
    assert!(!streamed.contains(&complete) && !streamed.contains(&incomplete));

    // counts: the two restricted readers differ by exactly the complete alert
    // (both are denied the sentinel-tagged one).
    let total = |v: Vec<(AlertStatus, i64)>| v.into_iter().map(|(_, n)| n).sum::<i64>();
    let seen_by_other = total(repo.count_by_status(Some(kinds.as_slice()), &denied_other).await.unwrap());
    let seen_by_src = total(repo.count_by_status(Some(kinds.as_slice()), &denied_src).await.unwrap());
    assert_eq!(seen_by_other - seen_by_src, 1);
}
