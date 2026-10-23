// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dedicated store on a fresh disposable PostgreSQL database, including negative tenant checks.
use std::collections::HashMap;
use nano_connector::{first_party, service::{admin::{AdminError, NewFeed}, pg::{PgFeedStore, Tenancy}, store::FeedStore, TenantSlot}};
use nanosiem_core::crypto::EncryptionService;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL naming a disposable fresh PostgreSQL database"]
async fn open_feed_cursor_survives_store_restart_and_mutations_are_tenant_scoped() {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL is required");
    let pool = PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
    nanosiem_core::db::migrations::run_postgres_migrations(&pool).await.unwrap();
    let tenant_a = nanosiem_core::reports::COMPATIBILITY_TENANT_ID;
    let tenant_b = Uuid::new_v4();
    sqlx::query("INSERT INTO public.tenants (id, slug, display_name, status) VALUES ($1, 'connector-negative-fixture', 'Fixture', 'active')")
        .bind(tenant_b).execute(&pool).await.unwrap();
    let slot_a = TenantSlot { tenant_id: tenant_a, actor_id: Uuid::nil() };
    let slot_b = TenantSlot { tenant_id: tenant_b, actor_id: Uuid::nil() };
    let cipher = EncryptionService::new(b"test-key-32-bytes-for-aes256!!!!");
    let store = PgFeedStore::new(Tenancy::Dedicated { pool: pool.clone() }, cipher.clone()).probe_schema().await.unwrap();
    let plan = first_party::plan("okta_system_log").unwrap();
    let feed = NewFeed {
        name: "open-fixture".into(), enabled: true,
        config: serde_json::from_value(json!({"OKTA_DOMAIN": "fixture.okta.com"})).unwrap(),
        vendor_credentials: HashMap::from([("API_TOKEN".into(), "fixture-vendor".into())]),
        ..Default::default()
    };
    let id = store.create_feed(&slot_a, &plan, &feed, "http://vector:8088/services/collector/event", Some("fixture-ingest")).await.unwrap();
    assert!(store.list_feeds(&slot_b).await.unwrap().is_empty());
    assert!(matches!(store.set_enabled(&slot_b, id, false).await, Err(AdminError::FeedNotFound(_))));
    assert!(matches!(store.delete_feed(&slot_b, id).await, Err(AdminError::FeedNotFound(_))));
    assert!(store.claim_due(&slot_b, "fixture", 1, &|_| 120).await.unwrap().is_empty());
    let claim = store.claim_due(&slot_a, "fixture", 1, &|_| 120).await.unwrap().remove(0);
    assert!(store.load_checkpoints(&claim).await.unwrap().is_empty(), "new feed must start point-forward");
    let cursor = json!({"since": "2026-10-13T12:00:00Z", "uids": ["fixture-row"]});
    store.save_checkpoint(&claim, "system_log", &cursor).await.unwrap();
    let restarted = PgFeedStore::new(Tenancy::Dedicated { pool: pool.clone() }, cipher);
    assert_eq!(restarted.load_checkpoints(&claim).await.unwrap()["system_log"], cursor);
    restarted.set_enabled(&slot_a, id, false).await.unwrap();
    assert!(restarted.claim_due(&slot_a, "fixture-two", 1, &|_| 120).await.unwrap().is_empty());
    restarted.delete_feed(&slot_a, id).await.unwrap();
    assert!(restarted.list_feeds(&slot_a).await.unwrap().is_empty());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM public.connector_feed_checkpoints WHERE tenant_id = $1 AND feed_id = $2")
        .bind(tenant_a).bind(id).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 0);
    assert!(restarted.save_checkpoint(&claim, "system_log", &cursor).await.is_err(), "deleted lease must be fenced");
    pool.close().await;
}

/// NAN-3767: deleting an open-core identity feed is a pending delete. The row
/// is disabled and marked, listed as `deleting`, cannot be resumed, and is
/// claimed by the runner's delete pass (which removes the feed's directory
/// rows at the coordinator) before it goes; a collector still goes at once.
#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL naming a disposable fresh PostgreSQL database"]
async fn open_identity_feed_delete_waits_for_the_directory_delete() {
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL is required");
    let pool = PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
    nanosiem_core::db::migrations::run_postgres_migrations(&pool).await.unwrap();
    let slot = TenantSlot { tenant_id: nanosiem_core::reports::COMPATIBILITY_TENANT_ID, actor_id: Uuid::nil() };
    let cipher = EncryptionService::new(b"test-key-32-bytes-for-aes256!!!!");
    let store = PgFeedStore::new(Tenancy::Dedicated { pool: pool.clone() }, cipher).probe_schema().await.unwrap();
    let plan = first_party::plan("okta_users").unwrap();
    let feed = NewFeed {
        name: "open-identity-fixture".into(), enabled: true,
        config: serde_json::from_value(json!({"OKTA_DOMAIN": "fixture.okta.com", "PRIVILEGED_GROUPS": "Okta Admins"})).unwrap(),
        vendor_credentials: HashMap::from([("API_TOKEN".into(), "fixture-vendor".into())]),
        ..Default::default()
    };
    let id = store.create_feed(&slot, &plan, &feed, "", None).await.unwrap();
    store.delete_feed(&slot, id).await.unwrap();
    let listed = store.list_feeds(&slot).await.unwrap();
    let row = listed.iter().find(|f| f.id == id).expect("an identity feed stays until its directory delete");
    assert_eq!((row.enabled, row.last_status.as_deref(), row.credential.as_str()), (false, Some("deleting"), "not_required"));
    assert!(matches!(store.set_enabled(&slot, id, true).await, Err(AdminError::FeedNotFound(_))), "a deleting feed cannot resume");
    store.delete_feed(&slot, id).await.unwrap();
    assert!(store.claim_due(&slot, "fixture", 4, &|_| 120).await.unwrap().is_empty(), "a deleting feed never runs");
    assert!(store.tenants().await.unwrap().iter().any(|t| t.tenant_id == slot.tenant_id), "its tenant is still visited");
    let claims = store.claim_deletes(&slot, "fixture", 4, 60).await.unwrap();
    assert_eq!(claims.len(), 1);
    assert!(claims[0].identity && claims[0].feed_id == id);
    store.finish_delete(&claims[0], Ok(())).await.unwrap();
    assert!(store.list_feeds(&slot).await.unwrap().iter().all(|f| f.id != id));

    // A collector still goes at once.
    let plan = first_party::plan("okta_system_log").unwrap();
    let feed = NewFeed {
        name: "open-collector-fixture".into(), enabled: true,
        config: serde_json::from_value(json!({"OKTA_DOMAIN": "fixture.okta.com"})).unwrap(),
        vendor_credentials: HashMap::from([("API_TOKEN".into(), "fixture-vendor".into())]),
        ..Default::default()
    };
    let id = store.create_feed(&slot, &plan, &feed, "http://vector:8088/services/collector/event", Some("fixture-ingest")).await.unwrap();
    store.delete_feed(&slot, id).await.unwrap();
    assert!(store.list_feeds(&slot).await.unwrap().iter().all(|f| f.id != id));
    pool.close().await;
}
