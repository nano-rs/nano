// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5789 against a real, fully migrated PostgreSQL: a fetch log source
//! (kafka here) with no source configuration used to fail EVERY Vector render
//! on the install, and the next unrelated log-source delete answered
//! `500 DATABASE_ERROR`. Pinned here:
//!
//! * create / update / enable / deploy refuse a fetch source without an
//!   existing configuration of its own type (drafts included), and a live one
//!   without a deployed one;
//! * a row that already exists (an install upgraded with one) is left out of
//!   the render with a note on its own row (a real validation error is kept),
//!   every other source still renders;
//! * a LIVE source left out (its configuration deleted or undeployed) raises a
//!   High `system_health_events` condition, resolved once it renders again;
//! * deleting another source works while that row is present.
//!
//! `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 NANOSIEM_ALLOW_DEFAULT_KEYS=true cargo test -p nanosiem-core \
//!     --test fetch_source_without_config_integration -- --ignored --test-threads=1`
//! (the boot batch may decrypt other configurations' credentials).
//!
//! PostgreSQL only: nothing exercised here reaches ClickHouse. Every row the
//! test writes is its own (unique names) and is removed afterwards, pass or
//! fail; no other suite's rows are modified.

mod common;

use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};

use futures::FutureExt;
use nanosiem_core::db::DualPool;
use nanosiem_core::log_sources::{LogSourceService, LogSourceServiceError, NewLogSource, UpdateLogSource};
use nanosiem_core::auth::CredentialUseGrant;
use nanosiem_core::parsers::unrouted::{self, ReportMode};
use nanosiem_core::SourceConfigService;
use nanosiem_core::parsers::{ParserService, VectorConfigManager, SOURCE_CONFIG_NOTE_PREFIX};
use sqlx::PgPool;
use tempfile::TempDir;
use uuid::Uuid;

fn source(name: &str, source_type: &str, binding: Option<Uuid>) -> NewLogSource {
    NewLogSource {
        name: name.into(),
        description: None,
        namespace: "default".into(),
        timezone: "UTC".into(),
        source_type: source_type.into(),
        parser_vrl: ".parsed = true\n".into(),
        output_fields: None,
        dispatch_source_config_id: binding,
        category: None,
        vendor: None,
        product: None,
        icon: None,
        color: None,
        match_field: None,
        match_pattern: None,
        match_values: Some(vec![name.to_lowercase()]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        lifecycle_status: Some("draft".into()),
    }
}

fn unique(prefix: &str) -> String {
    format!("{prefix}_{}", &Uuid::new_v4().simple().to_string()[..8])
}

/// Every row this test created, removed afterwards whatever happened.
#[derive(Default, Clone)]
struct Owned {
    sources: Arc<Mutex<Vec<Uuid>>>,
    configs: Arc<Mutex<Vec<Uuid>>>,
    credentials: Arc<Mutex<Vec<Uuid>>>,
}

impl Owned {
    fn source(&self, id: Uuid) -> Uuid {
        self.sources.lock().unwrap().push(id);
        id
    }
    async fn clean(&self, pool: &PgPool) {
        let sources = self.sources.lock().unwrap().clone();
        let configs = self.configs.lock().unwrap().clone();
        let keys: Vec<String> = sources.iter().map(|id| unrouted::health_dedup_key(*id)).collect();
        let _ = sqlx::query("DELETE FROM system_health_events WHERE dedup_key = ANY($1)").bind(&keys).execute(pool).await;
        let _ = sqlx::query("DELETE FROM log_sources WHERE id = ANY($1)").bind(&sources).execute(pool).await;
        let _ = sqlx::query("DELETE FROM source_configurations WHERE id = ANY($1)").bind(&configs).execute(pool).await;
        let credentials = self.credentials.lock().unwrap().clone();
        let _ = sqlx::query("DELETE FROM cloud_credentials WHERE id = ANY($1)").bind(&credentials).execute(pool).await;
    }
}

async fn config(pool: &PgPool, owned: &Owned, name: &str, config_type: &str, deployed: bool) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO source_configurations (name, config_type, enabled, deployed) VALUES ($1, $2, true, $3) RETURNING id",
    )
    .bind(name)
    .bind(config_type)
    .bind(deployed)
    .fetch_one(pool)
    .await
    .unwrap();
    owned.configs.lock().unwrap().push(id);
    id
}

/// Declare `<name>_route` in the tree, as a deployed configuration's file does.
fn declare_route(dir: &TempDir, config_name: &str) {
    let configs = dir.path().join("sources/configs");
    std::fs::create_dir_all(&configs).unwrap();
    std::fs::write(
        configs.join(format!("{config_name}.toml")),
        format!("[transforms.{config_name}_route]\ntype = \"remap\"\ninputs = [\"x\"]\nsource = \".\"\n"),
    )
    .unwrap();
}

async fn validation_error(pool: &PgPool, id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT validation_error FROM log_sources WHERE id = $1").bind(id).fetch_one(pool).await.unwrap()
}

async fn health_status(pool: &PgPool, id: Uuid) -> Option<(String, String)> {
    sqlx::query_as(
        "SELECT status, severity FROM system_health_events WHERE dedup_key = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(unrouted::health_dedup_key(id))
    .fetch_optional(pool)
    .await
    .unwrap()
}

fn file_for(dir: &TempDir, name: &str) -> bool {
    dir.path().join("sources/parsers").join(format!("{name}.toml")).exists()
}

/// The full-render report (what the source-configuration re-render runs),
/// scoped to this test's rows.
async fn full_report(pool: &PgPool, manager: &VectorConfigManager, owned: &Owned) -> Vec<unrouted::UnroutableParser> {
    let ids = owned.sources.lock().unwrap().clone();
    let mut parsers: Vec<_> = nanosiem_core::parsers::list_effective_deployed_parsers(pool)
        .await
        .unwrap()
        .into_iter()
        .filter(|p| ids.contains(&p.id))
        .collect();
    nanosiem_core::parsers::resolve_parser_dispatch_routes(pool, &mut parsers).await.unwrap();
    unrouted::report(pool, manager, &parsers, ReportMode::FULL).await
}

async fn scenario(pool: PgPool, owned: Owned) {
    let dir = TempDir::new().unwrap();
    let vector = Arc::new(VectorConfigManager::new(dir.path()));
    let dual = DualPool::for_postgres_integration_tests(pool.clone());
    let sources = LogSourceService::with_dual_pool_and_vector_config(&dual, vector.clone());
    let renderer = ParserService::with_vector_config_dir(pool.clone(), dir.path());

    let kafka_cfg_name = unique("kafka_cfg");
    let kafka_cfg = config(&pool, &owned, &kafka_cfg_name, "kafka", true).await;
    let s3_cfg = config(&pool, &owned, &unique("s3_cfg"), "aws_s3", true).await;
    let idle_cfg = config(&pool, &owned, &unique("idle_cfg"), "kafka", false).await;
    declare_route(&dir, &kafka_cfg_name);

    // 1. Validation on create: unbound (drafts included), missing, wrong type.
    for binding in [None, Some(Uuid::new_v4()), Some(s3_cfg)] {
        let err = sources.create(source(&unique("kafka_bad"), "kafka", binding)).await.unwrap_err();
        assert!(
            matches!(&err, LogSourceServiceError::MissingSourceConfiguration { field: "dispatch_source_config_id", .. }),
            "{binding:?}: {err:?}"
        );
    }
    // A matching binding is accepted, and the type is stored canonical.
    let bound = sources.create(source(&unique("kafka_ok"), "KAFKA", Some(kafka_cfg))).await.unwrap();
    owned.source(bound.id);
    assert_eq!(bound.source_type, "kafka");

    let keep_name = unique("keep");
    let doomed_name = unique("doomed");
    let bad_name = unique("legacy_kafka");
    let keep = sources.create(source(&keep_name, "routed", None)).await.unwrap();
    let doomed = sources.create(source(&doomed_name, "routed", None)).await.unwrap();
    let bad = sources.create(source(&bad_name, "routed", None)).await.unwrap();
    for id in [keep.id, doomed.id, bad.id] {
        owned.source(id);
    }

    // 2. Validation on update and enable.
    let to_s3 = UpdateLogSource { source_type: Some("aws_s3".into()), ..Default::default() };
    assert!(matches!(
        sources.update(keep.id, to_s3).await.unwrap_err(),
        LogSourceServiceError::MissingSourceConfiguration { .. }
    ));
    let wrong_type = UpdateLogSource { dispatch_source_config_id: Some(s3_cfg), ..Default::default() };
    assert!(matches!(
        sources.update(bound.id, wrong_type).await.unwrap_err(),
        LogSourceServiceError::MissingSourceConfiguration { .. }
    ));
    // Live + an undeployed configuration: refused (it would ingest nothing).
    sqlx::query("UPDATE log_sources SET enabled = true, validated = true WHERE id = $1").bind(bound.id).execute(&pool).await.unwrap();
    let to_idle = UpdateLogSource { dispatch_source_config_id: Some(idle_cfg), ..Default::default() };
    let err = sources.update(bound.id, to_idle).await.unwrap_err();
    assert!(matches!(&err, LogSourceServiceError::MissingSourceConfiguration { message, .. } if message.contains("not deployed")), "{err:?}");
    // A PUT that touches neither the transport, the binding nor enabled is not checked.
    sources.update(keep.id, UpdateLogSource { description: Some("kept".into()), ..Default::default() }).await.unwrap();

    // 3. An existing install's bad row, written past today's validation, with
    //    healthy neighbours. Enable refuses it; so does a deploy (before
    //    enabling it), and ParserService::deploy_parser.
    sqlx::query("UPDATE log_sources SET source_type = 'kafka', dispatch_source_config_id = NULL, validated = true WHERE id = $1")
        .bind(bad.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(sources.enable(bad.id).await.unwrap_err(), LogSourceServiceError::MissingSourceConfiguration { .. }));
    assert!(matches!(sources.deploy(bad.id).await.unwrap_err(), LogSourceServiceError::MissingSourceConfiguration { .. }));
    let enabled: bool = sqlx::query_scalar("SELECT enabled FROM log_sources WHERE id = $1").bind(bad.id).fetch_one(&pool).await.unwrap();
    assert!(!enabled, "a refused deploy must not leave the source enabled");
    nanosiem_core::parsers::test_sandbox::permit_in_process_for_test_harness();
    // Round 2: deploy_parser runs the same binding check (unbound, missing,
    // wrong type) before anything else.
    let err = renderer.deploy_parser(bad.id).await.unwrap_err();
    assert!(err.to_string().contains("needs a source configuration"), "{err}");
    let mismatched = sources.create(source(&unique("kafka_mismatch"), "routed", None)).await.unwrap();
    owned.source(mismatched.id);
    sqlx::query("UPDATE log_sources SET source_type = 'kafka', dispatch_source_config_id = $2, validated = true WHERE id = $1")
        .bind(mismatched.id)
        .bind(s3_cfg)
        .execute(&pool)
        .await
        .unwrap();
    let err = renderer.deploy_parser(mismatched.id).await.unwrap_err();
    assert!(err.to_string().contains("is a aws_s3 source configuration"), "{err}");
    // ...and ParserService::update cannot enable it either (it used to skip
    // the check when only `enabled` changed).
    let enable = nanosiem_core::parsers::UpdateParser { enabled: Some(true), ..Default::default() };
    assert!(renderer.update(bad.id, enable).await.is_err(), "enabling an unbound fetch source via update must be refused");

    // Now make it live, as an upgraded install may have it.
    sqlx::query("UPDATE log_sources SET enabled = true WHERE id = $1").bind(bad.id).execute(&pool).await.unwrap();
    sqlx::query("UPDATE log_sources SET enabled = true, validated = true WHERE id = ANY($1)")
        .bind(vec![keep.id, doomed.id])
        .execute(&pool)
        .await
        .unwrap();

    // 4. The render succeeds, writes the healthy sources, leaves the bad one
    //    out. The full report notes it and raises a High condition.
    renderer.render_to_vector_config().await.expect("one bad source must not fail the render");
    assert!(file_for(&dir, &keep_name));
    assert!(file_for(&dir, &doomed_name));
    assert!(!file_for(&dir, &bad_name));
    let out = full_report(&pool, &vector, &owned).await;
    let live_out: Vec<Uuid> = out.iter().filter(|u| u.enabled).map(|u| u.id).collect();
    assert_eq!(live_out, vec![bad.id], "only the bad source is left out of the live ones");
    let note = validation_error(&pool, bad.id).await.expect("the bad source carries a note");
    assert!(note.starts_with(SOURCE_CONFIG_NOTE_PREFIX), "{note}");
    assert!(validation_error(&pool, keep.id).await.is_none());
    assert_eq!(health_status(&pool, bad.id).await, Some(("active".into(), "high".into())));
    assert!(health_status(&pool, bound.id).await.is_none(), "a source that renders raises nothing");

    // A real validation error is never overwritten by the note.
    sqlx::query("UPDATE log_sources SET validation_error = 'VRL: boom' WHERE id = $1").bind(bad.id).execute(&pool).await.unwrap();
    full_report(&pool, &vector, &owned).await;
    assert_eq!(validation_error(&pool, bad.id).await.as_deref(), Some("VRL: boom"));
    sqlx::query("UPDATE log_sources SET validation_error = NULL WHERE id = $1").bind(bad.id).execute(&pool).await.unwrap();

    // 5. Deleting another source works while the bad row is present (it
    //    answered 500 DATABASE_ERROR before).
    sources.delete(doomed.id).await.expect("the delete must succeed");
    let gone: bool = sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM log_sources WHERE id = $1)")
        .bind(doomed.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(gone, "the row must be deleted");
    assert!(!file_for(&dir, &doomed_name), "its file must be pruned");
    assert!(file_for(&dir, &keep_name), "the other source must stay rendered");

    // 6. Fixing the bad row (routed needs no configuration) clears the note
    //    and resolves the condition.
    sources.update(bad.id, UpdateLogSource { source_type: Some("routed".into()), ..Default::default() }).await.unwrap();
    full_report(&pool, &vector, &owned).await;
    assert!(validation_error(&pool, bad.id).await.is_none(), "the note must be cleared once routable");
    assert_eq!(health_status(&pool, bad.id).await.map(|s| s.0).as_deref(), Some("resolved"));

    // 7. A LIVE, correctly bound source whose configuration is then deleted
    //    (ON DELETE SET NULL) or undeployed is no longer silent.
    full_report(&pool, &vector, &owned).await;
    assert!(health_status(&pool, bound.id).await.is_none());
    sqlx::query("DELETE FROM source_configurations WHERE id = $1").bind(kafka_cfg).execute(&pool).await.unwrap();
    let out = full_report(&pool, &vector, &owned).await;
    assert!(out.iter().any(|u| u.id == bound.id && u.enabled), "{out:?}");
    assert!(validation_error(&pool, bound.id).await.is_some_and(|n| n.starts_with(SOURCE_CONFIG_NOTE_PREFIX)));
    assert_eq!(health_status(&pool, bound.id).await, Some(("active".into(), "high".into())));

    // Rebound to a configuration whose route is not on disk: still reported
    // (this used to leave validation_error NULL).
    let undeployed_name = unique("kafka_cfg_undeployed");
    let undeployed = config(&pool, &owned, &undeployed_name, "kafka", true).await;
    sqlx::query("UPDATE log_sources SET dispatch_source_config_id = $2 WHERE id = $1").bind(bound.id).bind(undeployed).execute(&pool).await.unwrap();
    let out = full_report(&pool, &vector, &owned).await;
    let u = out.iter().find(|u| u.id == bound.id).expect("a route missing on disk is reported");
    assert!(u.note.contains("is not deployed"), "{}", u.note);
    // Its configuration deploys: the note clears and the condition resolves.
    declare_route(&dir, &undeployed_name);
    assert!(!full_report(&pool, &vector, &owned).await.iter().any(|u| u.id == bound.id));
    assert!(validation_error(&pool, bound.id).await.is_none());
    assert_eq!(health_status(&pool, bound.id).await.map(|s| s.0).as_deref(), Some("resolved"));

    // A disabled bad draft is noted (not alerted) and can itself be deleted.
    sqlx::query("UPDATE log_sources SET source_type = 'gcp_pubsub', enabled = false WHERE id = $1").bind(bad.id).execute(&pool).await.unwrap();
    full_report(&pool, &vector, &owned).await;
    assert!(validation_error(&pool, bad.id).await.is_some_and(|n| n.starts_with(SOURCE_CONFIG_NOTE_PREFIX)));
    assert_eq!(health_status(&pool, bad.id).await.map(|s| s.0).as_deref(), Some("resolved"), "a disabled draft raises nothing new");
    sources.delete(bad.id).await.expect("deleting the bad source itself works");
}

#[tokio::test]
#[ignore = "needs PostgreSQL (DATABASE_URL)"]
async fn an_unbound_fetch_source_never_breaks_the_render_or_a_delete() {
    let pool = common::migrated_pool().await;
    let owned = Owned::default();
    let outcome = AssertUnwindSafe(scenario(pool.clone(), owned.clone())).catch_unwind().await;
    owned.clean(&pool).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

async fn routing_rule(pool: &PgPool, config: Uuid) {
    sqlx::query(
        "INSERT INTO routing_rules (source_configuration_id, priority, match_field, match_type, match_value, target_source_type) \
         VALUES ($1, 10, 'source_type', 'exact', 'x', 'x')",
    )
    .bind(config)
    .execute(pool)
    .await
    .unwrap();
}

/// A live kafka source bound to `config`, as an upgraded install may hold it.
async fn live_bound(pool: &PgPool, sources: &LogSourceService, owned: &Owned, config: Uuid) -> Uuid {
    let id = owned.source(sources.create(source(&unique("live_kafka"), "routed", None)).await.unwrap().id);
    sqlx::query(
        "UPDATE log_sources SET source_type = 'kafka', dispatch_source_config_id = $2, enabled = true, validated = true WHERE id = $1",
    )
    .bind(id)
    .bind(config)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn event_count(pool: &PgPool, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM system_health_events WHERE dedup_key = $1")
        .bind(unrouted::health_dedup_key(id))
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn boot_and_delete_scenario(pool: PgPool, owned: Owned) {
    let dir = TempDir::new().unwrap();
    let vector = Arc::new(VectorConfigManager::new(dir.path()));
    let dual = DualPool::for_postgres_integration_tests(pool.clone());
    let sources = LogSourceService::with_dual_pool_and_vector_config(&dual, vector);
    let configs = SourceConfigService::with_publication_vector_config_dir(pool.clone(), dir.path());

    // Boot on a cold tree. Two enabled configurations deploy in name order;
    // a live source reads from the SECOND. When the first one deploys, the
    // second is not on disk yet: that must not page (it used to raise, then
    // resolve, a High condition on every pod start).
    let stem = &Uuid::new_v4().simple().to_string()[..8];
    let first = config(&pool, &owned, &format!("a0_{stem}"), "http", false).await;
    let second = config(&pool, &owned, &format!("a1_{stem}"), "http", false).await;
    routing_rule(&pool, first).await;
    routing_rule(&pool, second).await;
    let on_second = live_bound(&pool, &sources, &owned, second).await;
    // A live source on a configuration that is neither enabled nor deployed:
    // nothing in the batch deploys it, so only a report after the batch sees
    // it (it used to stay silent until an unrelated write).
    let parked = config(&pool, &owned, &unique("parked_cfg"), "http", false).await;
    sqlx::query("UPDATE source_configurations SET enabled = false WHERE id = $1").bind(parked).execute(&pool).await.unwrap();
    let on_parked = live_bound(&pool, &sources, &owned, parked).await;
    // Round 3: a pull configuration that sorts FIRST and is quarantined (its
    // Kafka CA is not a PEM). Quarantine re-renders the router; inside the
    // batch that must be notes only, or it pages for `on_second` (not on disk
    // yet) and resolves milliseconds later.
    let credential = nanosiem_core::parsers::CredentialRepository::new(pool.clone())
        .create(
            &nanosiem_core::parsers::CreateCloudCredential {
                name: unique("bad_ca"),
                provider: "kafka".into(),
                external_id: None,
                credentials: serde_json::json!({ "tls_ca_cert": "not a certificate" }),
                description: None,
                region: None,
                environment: None,
                expires_at: None,
            },
            None,
        )
        .await
        .unwrap();
    owned.credentials.lock().unwrap().push(credential.id);
    let broken = config(&pool, &owned, &format!("a0a_{stem}"), "kafka", false).await;
    sqlx::query("UPDATE source_configurations SET credential_id = $2 WHERE id = $1")
        .bind(broken)
        .bind(credential.id)
        .execute(&pool)
        .await
        .unwrap();
    // Round 3: a DEPLOYED but disabled configuration. The batch deploys only
    // enabled ones, so a cold tree lacks it until the publication reconciler
    // renders it; that must not page either.
    let disabled_name = format!("a2_{stem}");
    let deployed_disabled = config(&pool, &owned, &disabled_name, "http", true).await;
    routing_rule(&pool, deployed_disabled).await;
    sqlx::query("UPDATE source_configurations SET enabled = false WHERE id = $1").bind(deployed_disabled).execute(&pool).await.unwrap();
    let on_deployed_disabled = live_bound(&pool, &sources, &owned, deployed_disabled).await;

    configs.reconcile_on_boot(CredentialUseGrant::system()).await.unwrap();
    let quarantined: bool = sqlx::query_scalar("SELECT NOT deployed FROM source_configurations WHERE id = $1")
        .bind(broken)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(quarantined, "the broken pull configuration was quarantined in the batch");
    assert!(dir.path().join(format!("sources/configs/a1_{stem}.toml")).exists(), "the second configuration deployed");
    assert_eq!(event_count(&pool, on_second).await, 0, "no transient page while the batch was still deploying");
    assert_eq!(event_count(&pool, on_deployed_disabled).await, 0, "a deployed, disabled configuration is not 'not deployed'");
    assert!(validation_error(&pool, on_deployed_disabled).await.is_none());
    assert!(validation_error(&pool, on_second).await.is_none());
    assert_eq!(health_status(&pool, on_parked).await, Some(("active".into(), "high".into())));
    assert!(validation_error(&pool, on_parked).await.is_some_and(|n| n.contains("is not deployed")));

    // Deleting a configuration a live source reads from (never deployed here)
    // reports at once, with the real reason: it has none now.
    configs.delete(parked).await.unwrap();
    owned.configs.lock().unwrap().retain(|id| *id != parked);
    let (reason, summary): (String, String) = sqlx::query_as(
        "SELECT diagnostic_context->>'reason', summary FROM system_health_events WHERE dedup_key = $1 AND status = 'active'",
    )
    .bind(unrouted::health_dedup_key(on_parked))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(reason, "unbound");
    assert!(!summary.contains("Deploy that source configuration"), "{summary}");

    let deleted_live = live_bound(&pool, &sources, &owned, first).await;
    assert_eq!(event_count(&pool, deleted_live).await, 0);
    configs.delete(first).await.unwrap();
    owned.configs.lock().unwrap().retain(|id| *id != first);
    let reason: String = sqlx::query_scalar(
        "SELECT diagnostic_context->>'reason' FROM system_health_events WHERE dedup_key = $1 AND status = 'active'",
    )
    .bind(unrouted::health_dedup_key(deleted_live))
    .fetch_one(&pool)
    .await
    .expect("deleting a configuration a live source reads from raises the condition at once");
    assert_eq!(reason, "unbound", "never 'not deployed, deploy that source configuration' for a deleted one");
}

#[tokio::test]
#[ignore = "needs PostgreSQL (DATABASE_URL)"]
async fn a_boot_batch_and_a_config_delete_report_once_with_the_real_reason() {
    let pool = common::migrated_pool().await;
    let owned = Owned::default();
    let outcome = AssertUnwindSafe(boot_and_delete_scenario(pool.clone(), owned.clone())).catch_unwind().await;
    owned.clean(&pool).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
