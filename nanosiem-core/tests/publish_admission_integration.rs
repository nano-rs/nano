// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5889 (review): the checks publish and deploy run BEFORE their job are
//! database reads only, against a real, fully migrated PostgreSQL (and the
//! ClickHouse `DualPool` requires), on the default OCSF profile.
//!
//! Needs a THROWAWAY database: `NANOSIEM_TEST_DATABASE_URL`,
//! `NANOSIEM_TEST_CLICKHOUSE_URL` and `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1`.
//! `#[ignore]`d like every DB-backed suite; run with `-- --ignored`.

use std::sync::Arc;

use nanosiem_core::db::{DualPool, DualPoolConfig};
use nanosiem_core::log_sources::{LogSourceService, LogSourceServiceError, NewLogSource, OcsfGateInput};
use nanosiem_core::parsers::VectorConfigManager;
use sqlx::PgPool;
use tempfile::TempDir;
use uuid::Uuid;

async fn ctx() -> (PgPool, LogSourceService, TempDir) {
    let url = std::env::var("NANOSIEM_TEST_DATABASE_URL").expect("NANOSIEM_TEST_DATABASE_URL");
    let ch = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL").expect("NANOSIEM_TEST_CLICKHOUSE_URL");
    assert_eq!(std::env::var("NANOSIEM_ALLOW_DESTRUCTIVE_TESTS").as_deref(), Ok("1"));
    let mut config = DualPoolConfig::with_auth(url, ch, "nanosiem", "default", "");
    config.clickhouse_rawsql_password = Some("unused".into());
    config.clickhouse_rawsql_noaudit_password = Some("unused".into());
    let dual = DualPool::new(&config).await.expect("dual pool");
    let pg = dual.postgres().clone();
    nanosiem_core::db::run_postgres_migrations(&pg).await.expect("migrations");
    let dir = TempDir::new().unwrap();
    let vector = Arc::new(VectorConfigManager::new(dir.path()));
    (pg, LogSourceService::with_dual_pool_and_vector_config(&dual, vector), dir)
}

fn source(name: &str) -> NewLogSource {
    let key = format!("adm_{}", &Uuid::new_v4().simple().to_string()[..8]);
    NewLogSource {
        name: format!("{name} {key}"),
        description: None,
        namespace: "default".into(),
        timezone: "UTC".into(),
        source_type: "routed".into(),
        parser_vrl: ".parsed = true".into(),
        output_fields: None,
        dispatch_source_config_id: None,
        category: None,
        vendor: None,
        product: None,
        icon: None,
        color: None,
        match_field: None,
        match_pattern: None,
        match_values: Some(vec![key]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        lifecycle_status: None,
    }
}

fn no_sample() -> OcsfGateInput {
    OcsfGateInput { samples: Vec::new(), acknowledge_unattested: false }
}

/// A stored plan that no longer parses (written straight to the row, as an
/// old or hand-edited install could have it) is still a plan: publish's
/// pre-job check lets the job report what is wrong with it, instead of the
/// misleading "no OCSF receipt" 422.
#[tokio::test]
#[ignore = "needs a throwaway PostgreSQL + ClickHouse"]
async fn a_broken_pipe_plan_is_not_mistaken_for_a_parser_without_a_receipt() {
    let (pg, sources, _dir) = ctx().await;
    let created = sources.create(source("Broken plan")).await.unwrap();
    let broken = format!("{}not json\nnot the plan body", nanosiem_core::parsers::pipe::HEADER);
    sqlx::query("UPDATE log_sources SET parser_vrl = $2 WHERE id = $1")
        .bind(created.id)
        .bind(&broken)
        .execute(&pg)
        .await
        .unwrap();
    sources
        .ocsf_publish_admission(created.id, None, &no_sample())
        .await
        .expect("a plan is exempt from the parser gate; the job reports the broken plan");
    let result = sources.publish(created.id, None, None).await.unwrap();
    assert!(!result.success);
    assert!(result.message.starts_with("The processing plan is not valid"), "{}", result.message);
}

/// The plain-parser refusal still answers before any job, for publish and
/// for a first-go-live deploy; an acknowledgement lets both through.
#[tokio::test]
#[ignore = "needs a throwaway PostgreSQL + ClickHouse"]
async fn a_parser_without_a_receipt_is_refused_before_the_job() {
    let (_pg, sources, _dir) = ctx().await;
    let created = sources.create(source("No receipt")).await.unwrap();
    for refused in [
        sources.ocsf_publish_admission(created.id, None, &no_sample()).await.map(|_| ()),
        sources.ocsf_deploy_admission(created.id, &no_sample()).await,
    ] {
        assert!(matches!(refused, Err(LogSourceServiceError::OcsfValidationFailed(_))), "{refused:?}");
    }
    let ack = OcsfGateInput { samples: Vec::new(), acknowledge_unattested: true };
    sources.ocsf_publish_admission(created.id, None, &ack).await.unwrap();
    sources.ocsf_deploy_admission(created.id, &ack).await.unwrap();
    // Oversized samples are refused before the job too.
    let huge = OcsfGateInput { samples: vec!["x".repeat(300 * 1024)], acknowledge_unattested: false };
    assert!(sources.ocsf_deploy_admission(created.id, &huge).await.is_err());
    assert!(sources.ocsf_publish_admission(created.id, None, &huge).await.is_err());
}
