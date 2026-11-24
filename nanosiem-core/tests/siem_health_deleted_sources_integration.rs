// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5760: SIEM Health stops reporting deleted log sources.
//!
//! Against migrated PostgreSQL: every delete path (single, bulk, the parser
//! repository's) leaves a tombstone through the `log_sources` trigger, the
//! health read sets the deleted source's `source_type` aside from a stored
//! report, a re-created source takes its key back, and stale tombstones are
//! pruned. Ignored in ordinary unit runs; executed by the pg-integration lane.

mod common;

use nanosiem_core::auth::SourceProvenance;
use nanosiem_core::log_sources::LogSourceRepository;
use nanosiem_core::parsers::ParserRepository;
use nanosiem_core::siem_health::removed_sources::{tombstoned_route_keys, KeyEvidence, RemovedSourceKeys};
use nanosiem_core::siem_health::SiemHealthRepository;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn create_draft(pool: &PgPool, name: &str, match_values: Option<&[&str]>) -> Uuid {
    let id = Uuid::now_v7();
    let values: Option<Vec<String>> = match_values.map(|v| v.iter().map(|s| s.to_string()).collect());
    sqlx::query(
        "INSERT INTO log_sources (id, name, source_type, parser_vrl, match_values)
         VALUES ($1, $2, 'routed', '.', $3)",
    )
    .bind(id)
    .bind(name)
    .bind(values)
    .execute(pool)
    .await
    .expect("create log source");
    id
}

/// A source that had a live claim: deployed now.
async fn create_source(pool: &PgPool, name: &str, match_values: Option<&[&str]>) -> Uuid {
    let id = create_draft(pool, name, match_values).await;
    sqlx::query("UPDATE log_sources SET deployed = true, deployed_at = now() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("mark deployed");
    id
}

async fn bind_token(pool: &PgPool, source_id: Uuid) {
    let hex = format!("{}{}", Uuid::now_v7().simple(), Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO ingest_tokens (name, token_prefix, token_sha256, source_id)
         VALUES ($1, 'nit_ABCDEFGH', $2, $3)",
    )
    .bind(format!("nan5760-{}", &hex[..12]))
    .bind(&hex)
    .bind(source_id)
    .execute(pool)
    .await
    .expect("bind token");
}

async fn tombstone_count(pool: &PgPool, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM log_source_tombstones WHERE log_source_id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count tombstones")
}

fn metrics_with(volumes: &[(&str, u64, u64)], silent: &[&str]) -> serde_json::Value {
    let source_volumes: Vec<_> = volumes
        .iter()
        .map(|(source_type, now, prior)| {
            json!({"source_type": source_type, "count_24h": now, "count_prior_24h": prior, "change_pct": 0.0})
        })
        .collect();
    json!({
        "ingestion": {
            "source_volumes": source_volumes,
            "total_events_24h": volumes.iter().map(|v| v.1).sum::<u64>(),
            "total_events_prior_24h": volumes.iter().map(|v| v.2).sum::<u64>(),
            "silent_sources": silent
        },
        "parsing": { "field_coverage": [], "high_ext_sources": [] },
        "enrichment": {
            "total_events_24h": 0, "geoip_fill_pct": 0.0, "asn_fill_pct": 0.0,
            "ioc_hit_pct": 0.0, "identity_fill_pct": 0.0, "per_source_coverage": []
        },
        "detection": {
            "total_enabled_rules": 0, "rules_by_mode": [], "stale_rules": [],
            "noisy_rules": [], "alerts_24h_by_severity": []
        },
        "alerting": {
            "total_alerts_24h": 0, "total_alerts_prior_24h": 0, "by_status": [],
            "mean_mtta_minutes": null, "active_webhooks": 0, "webhook_deliveries_24h": 0,
            "webhook_success_pct": null, "active_routing_rules": 0
        },
        "collected_at": chrono::Utc::now()
    })
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn single_and_bulk_deletes_take_the_source_out_of_the_latest_health_report() {
    let pool = common::migrated_pool().await;
    let suffix = Uuid::now_v7().simple().to_string();
    let kept_key = format!("kept_{suffix}");
    let single_key = format!("single_{suffix}");
    let bulk_a_key = format!("bulk_a_{suffix}");
    let bulk_b_name = format!("Bulk B {suffix}");
    // No match values: its events carry the safe name.
    let bulk_b_key = format!("bulk_b_{suffix}");

    let kept = create_source(&pool, &format!("kept {suffix}"), Some(&[kept_key.as_str()])).await;
    let single = create_source(&pool, &format!("single {suffix}"), Some(&[single_key.as_str()])).await;
    let bulk_a = create_source(&pool, &format!("bulk a {suffix}"), Some(&[bulk_a_key.as_str()])).await;
    let bulk_b = create_source(&pool, &bulk_b_name, None).await;

    // A report generated while every source still existed: two of them silent.
    let repo = SiemHealthRepository::new(pool.clone());
    let report = repo
        .insert(
            40, "warning", 40, 80, 80, 80, 80, "stale",
            &metrics_with(
                &[
                    (kept_key.as_str(), 900, 1000),
                    (single_key.as_str(), 0, 500),
                    (bulk_a_key.as_str(), 0, 300),
                    (bulk_b_key.as_str(), 20, 30),
                ],
                &[single_key.as_str(), bulk_a_key.as_str()],
            ),
            &json!([]),
            &json!({}),
            &SourceProvenance::incomplete([kept_key.as_str()]),
            None,
            Some(1),
        )
        .await
        .expect("insert report");

    let sources = LogSourceRepository::new(pool.clone());
    sources.delete(single).await.expect("single delete");
    let deleted = sources.delete_many(&[bulk_a, bulk_b]).await.expect("bulk delete");
    assert_eq!(deleted.len(), 2);
    for id in [single, bulk_a, bulk_b] {
        assert_eq!(tombstone_count(&pool, id).await, 1, "every delete path leaves a tombstone");
    }
    assert_eq!(tombstone_count(&pool, kept).await, 0);

    let removed = RemovedSourceKeys::load_candidates(&pool).await.expect("load removed keys");
    for key in [&single_key, &bulk_a_key, &bulk_b_key] {
        assert!(removed.contains(key), "{key} is removed");
    }
    assert!(!removed.contains(&kept_key));

    // The read path the latest-report handler runs.
    // ClickHouse evidence is pinned by the unit tests; here every candidate
    // stopped before its delete.
    let mut removed = removed;
    let evidence = removed
        .keys()
        .map(|k| (k.to_string(), KeyEvidence { first_event: 0, last_event: 0 }))
        .collect();
    removed.retain_evidenced(&evidence);
    let mut stored = repo.get_by_id(report.id).await.expect("read report");
    stored.set_aside_removed_sources(&removed);
    let ingestion = &stored.metrics["ingestion"];
    let volumes: Vec<&str> = ingestion["source_volumes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["source_type"].as_str().unwrap())
        .collect();
    assert_eq!(volumes, [kept_key.as_str()]);
    assert_eq!(ingestion["silent_sources"], json!([]), "deleted sources are never silent");
    assert_eq!(ingestion["total_events_24h"], 900);
    let mut set_aside: Vec<&str> = ingestion["removed_sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["source_type"].as_str().unwrap())
        .collect();
    set_aside.sort();
    let mut expected = vec![bulk_a_key.as_str(), bulk_b_key.as_str(), single_key.as_str()];
    expected.sort();
    assert_eq!(set_aside, expected);

    // Re-creating a source that claims a deleted key brings it back.
    let again = create_source(&pool, &format!("single again {suffix}"), Some(&[single_key.as_str()])).await;
    let removed = RemovedSourceKeys::load_candidates(&pool).await.expect("reload removed keys");
    assert!(!removed.contains(&single_key), "a live claim wins over a tombstone");
    assert!(removed.contains(&bulk_a_key));

    let _ = sqlx::query("DELETE FROM siem_health_reports WHERE id = $1").bind(report.id).execute(&pool).await;
    let _ = sqlx::query("DELETE FROM log_sources WHERE id = ANY($1)").bind(vec![kept, again]).execute(&pool).await;
    let _ = sqlx::query("DELETE FROM log_source_tombstones WHERE name LIKE $1")
        .bind(format!("%{suffix}%"))
        .execute(&pool)
        .await;
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn parser_repository_deletes_tombstone_and_old_tombstones_are_pruned() {
    let pool = common::migrated_pool().await;
    let suffix = Uuid::now_v7().simple().to_string();

    // An orphan from long ago: older than any health window.
    let stale_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO log_source_tombstones (log_source_id, name, match_values, deleted_at)
         VALUES ($1, $2, NULL, now() - INTERVAL '8 days')",
    )
    .bind(stale_id)
    .bind(format!("stale {suffix}"))
    .execute(&pool)
    .await
    .expect("seed stale tombstone");

    let key = format!("parser_{suffix}");
    let id = create_source(&pool, &format!("parser {suffix}"), Some(&[key.as_str()])).await;
    ParserRepository::new(pool.clone()).delete(id).await.expect("parser repository delete");

    assert_eq!(tombstone_count(&pool, id).await, 1);
    assert_eq!(tombstone_count(&pool, stale_id).await, 0, "the delete pruned the stale tombstone");
    assert!(RemovedSourceKeys::load_candidates(&pool).await.expect("load").contains(&key));

    let _ = sqlx::query("DELETE FROM log_source_tombstones WHERE log_source_id = $1").bind(id).execute(&pool).await;
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn a_source_without_a_live_claim_leaves_no_tombstone() {
    // NAN-5760 review P1: create-then-delete of a never-deployed draft must not
    // be able to hide a live stream it names.
    let pool = common::migrated_pool().await;
    let suffix = Uuid::now_v7().simple().to_string();
    let live_stream = format!("hec_fw_{suffix}");
    let draft = create_draft(&pool, &format!("draft {suffix}"), Some(&[live_stream.as_str(), "audit"])).await;
    LogSourceRepository::new(pool.clone()).delete(draft).await.expect("delete draft");
    assert_eq!(tombstone_count(&pool, draft).await, 0, "a never-live draft leaves no tombstone");
    assert!(!RemovedSourceKeys::load_candidates(&pool).await.unwrap().contains(&live_stream));
    assert!(tombstoned_route_keys(&pool, &[draft]).await.unwrap().is_empty());

    // Token-bound: its events carried the key, so it is tombstoned. Reserved
    // keys it named are never candidates.
    let token_key = format!("tok_{suffix}");
    let bound = create_draft(&pool, &format!("bound {suffix}"), Some(&[token_key.as_str(), "audit", "nano_x"])).await;
    bind_token(&pool, bound).await;
    // Ever deployed (undeployed since): the success record still counts.
    let ever_key = format!("ever_{suffix}");
    let ever = create_draft(&pool, &format!("ever {suffix}"), Some(&[ever_key.as_str()])).await;
    sqlx::query("INSERT INTO log_source_deployments (log_source_id, action, status) VALUES ($1, 'deploy', 'success')")
        .bind(ever)
        .execute(&pool)
        .await
        .expect("deployment record");
    LogSourceRepository::new(pool.clone()).delete_many(&[bound, ever]).await.expect("bulk delete");
    assert_eq!(tombstone_count(&pool, bound).await, 1);
    assert_eq!(tombstone_count(&pool, ever).await, 1);
    let audited = tombstoned_route_keys(&pool, &[bound, ever]).await.unwrap();
    assert_eq!(audited[&bound], vec![token_key.clone()], "reserved keys are dropped");
    assert_eq!(audited[&ever], vec![ever_key.clone()]);
    let candidates = RemovedSourceKeys::load_candidates(&pool).await.unwrap();
    assert!(candidates.contains(&token_key) && candidates.contains(&ever_key));
    assert!(!candidates.contains("audit"));

    let _ = sqlx::query("DELETE FROM ingest_tokens WHERE token_prefix = 'nit_ABCDEFGH' AND source_id IS NULL")
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM log_source_tombstones WHERE name LIKE $1")
        .bind(format!("%{suffix}%"))
        .execute(&pool)
        .await;
}
