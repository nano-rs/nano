// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4937 (codex P1): a deploy advances the user-visible `deployed_at` (which
//! clears the UI's "Pending" changes) ONLY after Vector activated it, and only
//! when nothing changed after it was rendered.
//!
//! - activated (the per-change marker runs): stamped, nothing pending;
//! - Vector never confirms: not stamped, the change stays pending;
//! - the router rewrite fails: not stamped;
//! - the row, or its rules, changed after the render: not stamped
//!   (compare-and-swap on the rendered `updated_at` and rule `created_at`);
//! - a first deploy sets `deployed = true` (the router reads it) without
//!   stamping `deployed_at`.
//!
//! Run (against a throwaway Postgres, e.g. an e2e stack's):
//! `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 NANOSIEM_ALLOW_DEFAULT_KEYS=true DATABASE_URL=… \
//!   cargo test -p nanosiem-core --test source_config_deploy_stamp_integration -- --ignored --test-threads=1`

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use nanosiem_core::auth::CredentialUseGrant;
use nanosiem_core::source_configs::SourceConfigService;
use nanosiem_core::SourceConfigRepository;
use uuid::Uuid;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// Vector's metrics exporter, faked: with `confirm` set it reports the
/// activation marker on disk as running (as in the NAN-4936 boot test).
struct FakeVectorMetrics {
    marker_file: PathBuf,
    confirm: Arc<AtomicBool>,
}

impl Respond for FakeVectorMetrics {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let mut body = String::from("nanosiem_vector_reloaded_total{host=\"h\"} 1\n");
        if self.confirm.load(Ordering::SeqCst) {
            if let Ok(toml) = std::fs::read_to_string(&self.marker_file) {
                if let Some(id) = toml
                    .lines()
                    .find_map(|l| l.strip_prefix("[sources.").and_then(|r| r.strip_suffix(']')))
                {
                    body.push_str(&format!(
                        "nanosiem_vector_component_sent_events_total{{component_id=\"{id}\",host=\"h\"}} 3\n"
                    ));
                }
            }
        }
        ResponseTemplate::new(200).set_body_string(body)
    }
}

struct Fixture {
    pool: sqlx::PgPool,
    service: SourceConfigService,
    confirm: Arc<AtomicBool>,
    config_dir: tempfile::TempDir,
    _validation: tempfile::TempDir,
    _metrics: MockServer,
}

async fn fixture() -> Fixture {
    let pool = common::migrated_pool().await;
    let config_dir = tempfile::tempdir().unwrap();
    let validation = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(config_dir.path().join("sources/configs")).unwrap();
    std::fs::create_dir_all(config_dir.path().join("sources/parsers")).unwrap();
    std::fs::write(
        config_dir.path().join("sources/parsers/_router.toml"),
        "[transforms.source_router]\ntype = \"route\"\ninputs = []\n",
    )
    .unwrap();
    let confirm = Arc::new(AtomicBool::new(true));
    let metrics = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .respond_with(FakeVectorMetrics {
            marker_file: config_dir.path().join("sources/configs/_nano_activation.toml"),
            confirm: confirm.clone(),
        })
        .mount(&metrics)
        .await;
    // SAFETY: test setup before the service runs; tests run with --test-threads=1.
    unsafe {
        std::env::set_var("VECTOR_VALIDATION_DIR", validation.path());
        std::env::set_var("VECTOR_CONTAINER_NAME", format!("nan4937-absent-{}", Uuid::new_v4().simple()));
        std::env::set_var("VECTOR_METRICS_URL", format!("{}/metrics", metrics.uri()));
        std::env::set_var("VECTOR_RELOAD_ACK_TIMEOUT_SECS", "3");
    }
    let service = SourceConfigService::with_vector_config_dir(pool.clone(), config_dir.path());
    Fixture { pool, service, confirm, config_dir, _validation: validation, _metrics: metrics }
}

/// An `http` (system-listener) source config with one routing rule.
async fn http_config(pool: &sqlx::PgPool, deployed: bool) -> Uuid {
    let id = Uuid::now_v7();
    let name = format!("nan4937-stamp-{}", id.simple());
    sqlx::query(
        "INSERT INTO source_configurations (id, name, config_type, connection_config, enabled, deployed, deployed_at)
         VALUES ($1, $2, 'http', '{}', TRUE, $3, CASE WHEN $3 THEN NOW() - INTERVAL '1 hour' END)",
    )
    .bind(id)
    .bind(&name)
    .bind(deployed)
    .execute(pool)
    .await
    .expect("insert source config");
    add_rule(pool, id, 10, "app_a").await;
    id
}

async fn add_rule(pool: &sqlx::PgPool, id: Uuid, priority: i32, target: &str) {
    sqlx::query(
        "INSERT INTO routing_rules (source_configuration_id, priority, match_field, match_type, match_value, target_source_type)
         VALUES ($1, $2, 'source_type', 'exact', $3, $3)",
    )
    .bind(id)
    .bind(priority)
    .bind(target)
    .execute(pool)
    .await
    .expect("insert routing rule");
}

async fn stamps(pool: &sqlx::PgPool, id: Uuid) -> (bool, Option<DateTime<Utc>>, DateTime<Utc>) {
    sqlx::query_as("SELECT deployed, deployed_at, updated_at FROM source_configurations WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read stamps")
}

/// The web UI's pending check: settings newer than `deployed_at`.
fn pending(deployed_at: Option<DateTime<Utc>>, updated_at: DateTime<Utc>) -> bool {
    deployed_at.is_none_or(|d| updated_at > d)
}

async fn edit(pool: &sqlx::PgPool, id: Uuid) {
    tokio::time::sleep(Duration::from_millis(5)).await;
    sqlx::query("UPDATE source_configurations SET description = 'edited' WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("edit");
}

async fn cleanup(pool: &sqlx::PgPool, id: Uuid) {
    sqlx::query("DELETE FROM source_configurations WHERE id = $1").bind(id).execute(pool).await.ok();
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn activated_redeploy_clears_pending() {
    let f = fixture().await;
    let id = http_config(&f.pool, true).await;
    edit(&f.pool, id).await;
    let (_, before, updated) = stamps(&f.pool, id).await;
    assert!(pending(before, updated), "the edit must show as pending before the deploy");

    let result = f.service.deploy(id, CredentialUseGrant::system()).await.expect("deploy");
    assert!(result.success, "{}", result.message);
    let (deployed, after, updated) = stamps(&f.pool, id).await;
    assert!(deployed && after > before, "activated deploy must advance deployed_at");
    assert!(!pending(after, updated), "activated deploy must clear pending");
    cleanup(&f.pool, id).await;
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn unconfirmed_activation_keeps_pending() {
    let f = fixture().await;
    f.confirm.store(false, Ordering::SeqCst);
    let id = http_config(&f.pool, true).await;
    edit(&f.pool, id).await;
    let (_, before, _) = stamps(&f.pool, id).await;

    let result = f.service.deploy(id, CredentialUseGrant::system()).await.expect("deploy");
    assert!(!result.success, "Vector never confirmed: the deploy must not report success");
    let (_, after, updated) = stamps(&f.pool, id).await;
    assert_eq!(after, before, "deployed_at must not move without activation");
    assert!(pending(after, updated), "the change must stay pending");
    cleanup(&f.pool, id).await;
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn router_rewrite_failure_keeps_pending() {
    let f = fixture().await;
    let router = f.config_dir.path().join("sources/parsers/_router.toml");
    std::fs::remove_file(&router).unwrap();
    std::fs::create_dir(&router).unwrap(); // unreadable as a file: the rewrite fails
    let id = http_config(&f.pool, true).await;
    edit(&f.pool, id).await;
    let (_, before, _) = stamps(&f.pool, id).await;

    assert!(f.service.deploy(id, CredentialUseGrant::system()).await.is_err(), "router failure must fail the deploy");
    let (_, after, updated) = stamps(&f.pool, id).await;
    assert_eq!(after, before, "deployed_at must not move when the router was not rewritten");
    assert!(pending(after, updated));
    cleanup(&f.pool, id).await;
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn first_deploy_flags_deployed_but_stamps_only_on_activation() {
    let f = fixture().await;
    f.confirm.store(false, Ordering::SeqCst);
    let id = http_config(&f.pool, false).await;
    let result = f.service.deploy(id, CredentialUseGrant::system()).await.expect("deploy");
    assert!(!result.success);
    let (deployed, at, _) = stamps(&f.pool, id).await;
    assert!(deployed, "the router needs deployed = true before activation");
    assert!(at.is_none(), "deployed_at must wait for activation");

    f.confirm.store(true, Ordering::SeqCst);
    let result = f.service.deploy(id, CredentialUseGrant::system()).await.expect("deploy");
    assert!(result.success, "{}", result.message);
    let (_, at, updated) = stamps(&f.pool, id).await;
    assert!(at.is_some() && !pending(at, updated));
    cleanup(&f.pool, id).await;
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn stamp_is_a_compare_and_swap_on_the_rendered_snapshot() {
    let f = fixture().await;
    let repo = SourceConfigRepository::new(f.pool.clone());
    let id = http_config(&f.pool, true).await;

    // Rendered, then the row was saved again: no stamp.
    let rendered_at = repo.db_now().await.unwrap();
    let (_, before, rendered_updated) = stamps(&f.pool, id).await;
    edit(&f.pool, id).await;
    assert!(!repo.stamp_deployed(id, rendered_updated, rendered_at).await.unwrap());
    assert_eq!(stamps(&f.pool, id).await.1, before);

    // Rendered, then a routing rule was added: no stamp.
    let rendered_at = repo.db_now().await.unwrap();
    let (_, _, rendered_updated) = stamps(&f.pool, id).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    add_rule(&f.pool, id, 20, "app_b").await;
    assert!(!repo.stamp_deployed(id, rendered_updated, rendered_at).await.unwrap());

    // Nothing changed after the render: stamped, and nothing pending.
    let rendered_at = repo.db_now().await.unwrap();
    let (_, _, rendered_updated) = stamps(&f.pool, id).await;
    assert!(repo.stamp_deployed(id, rendered_updated, rendered_at).await.unwrap());
    let (_, at, updated) = stamps(&f.pool, id).await;
    assert!(!pending(at, updated));

    // The first-deploy flag never stamps, and reports a stale snapshot.
    let fresh = http_config(&f.pool, false).await;
    let (_, _, snap) = stamps(&f.pool, fresh).await;
    edit(&f.pool, fresh).await;
    assert!(repo.set_deployed_flag(fresh, snap).await.unwrap().is_none(), "stale snapshot must be reported");
    let (deployed, at, _) = stamps(&f.pool, fresh).await;
    assert!(deployed && at.is_none());
    cleanup(&f.pool, fresh).await;
    cleanup(&f.pool, id).await;
}
