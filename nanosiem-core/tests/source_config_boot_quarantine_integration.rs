// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4936 (codex re-check P1): API boot reconciliation must not record a
//! quarantine as confirmed without proof that Vector stopped running the source.
//!
//! A deployed source whose credential no longer builds is quarantined at boot.
//! Its removal from the running Vector is only "confirmed" once the per-change
//! activation marker runs; when Vector cannot confirm, the state stays
//! `quarantine_unconfirmed`, and a later reconciliation (when the row is already
//! undeployed and the file already gone) must NOT downgrade it to a plain
//! `quarantined` without that proof.
//!
//! Run (against a throwaway Postgres, e.g. an e2e stack's):
//! `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 NANOSIEM_ALLOW_DEFAULT_KEYS=true DATABASE_URL=… \
//!   cargo test -p nanosiem-core --test source_config_boot_quarantine_integration -- --ignored`

mod common;

use std::path::{Path, PathBuf};

use nanosiem_core::auth::CredentialUseGrant;
use nanosiem_core::source_configs::SourceConfigService;
use nanosiem_core::{CreateCloudCredential, CredentialRepository};
use uuid::Uuid;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// Vector's metrics exporter, faked. With `confirm` set, it reports the
/// activation marker currently on disk as running (Vector loaded the tree
/// without the quarantined source); otherwise nothing changes.
struct FakeVectorMetrics {
    marker_file: PathBuf,
    confirm: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Respond for FakeVectorMetrics {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let mut body = String::from("nanosiem_vector_reloaded_total{host=\"h\"} 1\n");
        if self.confirm.load(std::sync::atomic::Ordering::SeqCst) {
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

async fn latest_status(pool: &sqlx::PgPool, id: Uuid) -> (String, Option<String>) {
    sqlx::query_as(
        "SELECT status, error_message FROM source_configuration_deployments \
         WHERE source_configuration_id = $1 ORDER BY deployed_at DESC LIMIT 1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("latest deployment row")
}

fn live_file(config_dir: &Path, name: &str) -> PathBuf {
    config_dir.join("sources/configs").join(format!("{name}.toml"))
}

#[tokio::test]
#[ignore = "requires live Postgres"]
async fn boot_quarantine_stays_unconfirmed_until_vector_proves_the_removal() {
    let pool = common::migrated_pool().await;
    let config_dir = tempfile::tempdir().unwrap();
    let validation = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(config_dir.path().join("sources/configs")).unwrap();

    let confirm = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let metrics = MockServer::start().await;
    Mock::given(wiremock::matchers::method("GET"))
        .respond_with(FakeVectorMetrics {
            marker_file: config_dir.path().join("sources/configs/_nano_activation.toml"),
            confirm: confirm.clone(),
        })
        .mount(&metrics)
        .await;
    // Marker mode on (shared validation volume), no reachable Vector container,
    // a short acknowledgement window.
    // SAFETY: single-threaded test setup before any service runs.
    unsafe {
        std::env::set_var("VECTOR_VALIDATION_DIR", validation.path());
        std::env::set_var("VECTOR_CONTAINER_NAME", format!("nan4936-absent-{}", Uuid::new_v4().simple()));
        std::env::set_var("VECTOR_METRICS_URL", format!("{}/metrics", metrics.uri()));
        std::env::set_var("VECTOR_RELOAD_ACK_TIMEOUT_SECS", "3");
    }

    // A deployed Kafka source whose CA no longer parses: the preflight refuses
    // it, so boot reconciliation quarantines it.
    let suffix = Uuid::new_v4().simple().to_string();
    let name = format!("nan4936-boot-{suffix}");
    let cred = CredentialRepository::new(pool.clone())
        .create(
            &CreateCloudCredential {
                name: format!("{name}-cred"),
                provider: "kafka".to_string(),
                external_id: None,
                credentials: serde_json::json!({ "tls_enabled": true, "tls_ca_cert": "not-a-pem" }),
                description: None,
                region: None,
                environment: None,
                expires_at: None,
            },
            None,
        )
        .await
        .expect("create kafka credential");
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO source_configurations
            (id, name, config_type, connection_config, credential_id, enabled, deployed)
         VALUES ($1, $2, 'kafka', $3, $4, TRUE, TRUE)",
    )
    .bind(id)
    .bind(&name)
    .bind(serde_json::json!({ "bootstrap_servers": "broker.invalid:9092", "topics": ["t"] }))
    .bind(cred.id)
    .execute(&pool)
    .await
    .expect("insert deployed source");
    let file = live_file(config_dir.path(), &name.replace('-', "_"));
    std::fs::write(&file, "# previously rendered, running in Vector\n").unwrap();

    let service = SourceConfigService::with_vector_config_dir(pool.clone(), config_dir.path());

    // 1. Vector cannot confirm the removal: unconfirmed, never "quarantined".
    service.reconcile_on_boot(CredentialUseGrant::system()).await.unwrap();
    let (status, reason) = latest_status(&pool, id).await;
    assert_eq!(status, "quarantine_unconfirmed", "{reason:?}");
    assert!(reason.unwrap_or_default().contains("not confirmed"));

    // 2. A retry (row now undeployed, file gone) must not downgrade it.
    service.reconcile_on_boot(CredentialUseGrant::system()).await.unwrap();
    let (status, _) = latest_status(&pool, id).await;
    assert_eq!(status, "quarantine_unconfirmed", "a retry without proof must not confirm the quarantine");

    // 3. Only a running marker (Vector loaded a tree without the source) clears it.
    confirm.store(true, std::sync::atomic::Ordering::SeqCst);
    service.reconcile_on_boot(CredentialUseGrant::system()).await.unwrap();
    let (status, _) = latest_status(&pool, id).await;
    assert_eq!(status, "quarantined");

    sqlx::query("DELETE FROM source_configurations WHERE id = $1").bind(id).execute(&pool).await.ok();
    sqlx::query("DELETE FROM cloud_credentials WHERE id = $1").bind(cred.id).execute(&pool).await.ok();
}
