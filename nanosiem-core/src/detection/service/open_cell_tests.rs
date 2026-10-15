// SPDX-License-Identifier: AGPL-3.0-or-later

//! Open Postgres + mocked cell wire protocol. Native part/query proofs live in
//! lake-worker; this test verifies the scheduler's durable product side effects.
use super::*;
use crate::detection::{DistributedDetectionScheduler, DistributedSchedulerConfig};
use crate::models::NewDetectionRule;
use crate::search::{InMemoryJobStore, LakeCellRoute};
use crate::shutdown::ShutdownToken;
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
#[ignore = "requires disposable loopback NANO_OPEN_CELL_TEST_PG and open build"]
#[cfg(not(feature = "enterprise"))]
async fn open_scheduler_cell_lifecycle() {
    let url = std::env::var("NANO_OPEN_CELL_TEST_PG").unwrap();
    assert!(
        url.starts_with("postgres://postgres@127.0.0.1:") && url.ends_with("/opencelldetecttest")
    );
    let pg = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::run_postgres_migrations(&pg).await.unwrap();
    let server = MockServer::start().await;
    let tenant = Uuid::from_u128(1);
    // Keep env changes isolated: this ignored test is run alone.
    std::env::set_var("NANO_LOG_QUERY_BACKEND", "lake");
    std::env::set_var("NANO_SCHEMA_PROFILE", "ocsf");
    std::env::set_var("NANO_LAKE_TENANT_ID", tenant.to_string());
    // NAN-3492: findings carry the lake tenant as security tenant only on
    // the explicitly trusted-local install.
    std::env::set_var("NANO_TRUSTED_LOCAL", "1");
    std::env::set_var("NANO_LAKE_QUERY_URL", server.uri());
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("router.token");
    std::fs::write(&token, "local-cell-test-router-token-32-characters").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o400)).unwrap();
    }
    std::env::set_var("NANO_LAKE_QUERY_TOKEN_FILE", &token);
    let dual = DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
        &url,
        "http://127.0.0.1:1",
        "unused",
        "unused",
        "unused",
    ))
    .await
    .unwrap();
    let lookup =
        crate::lookup::LookupService::new(crate::lookup::PostgresLookupRepository::new(pg.clone()));
    let prevalence = PrevalenceService::new(dual.clickhouse().clone(), dual.table_names());
    let mut service = DetectionService::with_dual_pool_prevalence_and_profile(
        &dual,
        lookup,
        prevalence,
        Arc::new(crate::schema::OcsfProfile::lake_1_9()),
    );
    let route = LakeCellRoute::for_test(tenant, &server.uri(), token);
    // Pin the mock cell route. The open adapter preserves the dedicated
    // rule/alert/finding repositories.
    service.search_service = service
        .search_service
        .pinned_to_cell_route_for_test(&route, Arc::new(InMemoryJobStore::new()))
        .unwrap();
    let service = service.open_cell_scheduler_view().unwrap();
    assert!(
        service.finding_logger.is_some(),
        "scheduler must retain signal logging"
    );
    let detect = format!("/v1/tenants/{tenant}/detect");
    let late_start = (Utc::now() - Duration::minutes(45)).timestamp_micros();
    let late_end = (Utc::now() - Duration::minutes(30)).timestamp_micros();
    Mock::given(method("POST"))
        .and(path(format!("{detect}/v1/detections/plan")))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"run":false,"reason":"no_new_data","log_seq":1,"rerun_windows":[{"start_us":late_start,"end_us":late_end}]}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{detect}/v1/detections/commit")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok":true})))
        .mount(&server)
        .await;
    let event = json!({"time":(Utc::now()-Duration::minutes(1)).to_rfc3339(),"class_uid":3002,
        "metadata":{"uid":Uuid::new_v4(),"tenant_uid":tenant,"log_source":"auth","log_name":"auth","version":"1.9.0"},
        "user":{"name":"alice"},"src_endpoint":{"ip":"10.34.92.1"},"message":"fixture"});
    Mock::given(method("POST")).and(path(format!("{detect}/v1/query")))
        .respond_with(move|request:&wiremock::Request| {
            let body:Value=serde_json::from_slice(&request.body).unwrap();
            ResponseTemplate::new(200).set_body_json(json!({"ok":true,"request_id":body["request_id"],
                "tenant_id":body["tenant_id"],"route":"broad_npl","source_mode":"parts",
                "result":{"result_rows":1,"rows":[event],"page_offset":0,"page_limit":1000000,"page_has_more":false}}))
        }).mount(&server).await;
    let rule:NewDetectionRule=serde_json::from_value(json!({"name":"open lean lifecycle","query":"metadata.log_source=auth",
        "severity":"high","mode":"staging","lookback_minutes":15,"risk_score":75,"risk_entity_field":"user.name"})).unwrap();
    let rule = service.create_rule(rule).await.unwrap();
    let scheduler = Arc::new(
        DistributedDetectionScheduler::new(
            service.clone(),
            pg.clone(),
            DistributedSchedulerConfig {
                poll_interval_secs: 1,
                phase_max_secs: 0,
                late_replay_poll_interval_secs: 1,
                ..Default::default()
            },
            "local-cell-fixture".into(),
        )
        .with_realtime_microbatches(true)
        .with_late_arrival_reconciliation(true),
    );
    let shutdown = ShutdownToken::new();
    let handle = scheduler.clone().start_with_shutdown(shutdown.clone());
    let repair_handle = scheduler
        .clone()
        .start_late_arrival_with_shutdown(shutdown.clone());
    sqlx::query("UPDATE detection_rules SET next_run_at=NOW()-INTERVAL '1 second' WHERE id=$1")
        .bind(rule.id)
        .execute(&pg)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let last: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT last_run_at FROM detection_rules WHERE id=$1")
            .bind(rule.id)
            .fetch_one(&pg)
            .await
            .unwrap();
    assert!(last.is_none(), "staging must not run");
    for mode in ["live", "alerting"] {
        service.set_mode(rule.id, mode).await.unwrap();
        sqlx::query("UPDATE detection_rules SET next_run_at=NOW()-INTERVAL '1 second' WHERE id=$1")
            .bind(rule.id)
            .execute(&pg)
            .await
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM detection_finding_lake_outbox WHERE tenant_id=$1 AND ocsf_event->'finding_info'->'types' ? $2")
                .bind(tenant.to_string()).bind(if mode=="live" {"detection_match"} else {"alert"}).fetch_one(&pg).await.unwrap();
            if count > 0 {
                let completed: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM detection_late_replay_jobs WHERE rule_id=$1 AND status='completed')")
                    .bind(rule.id).fetch_one(&pg).await.unwrap();
                if completed {
                    break;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{mode} did not emit a finding"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let alerts: i64 = sqlx::query_scalar("SELECT count(*) FROM alerts WHERE rule_id=$1")
            .bind(rule.id)
            .fetch_one(&pg)
            .await
            .unwrap();
        assert_eq!(alerts, if mode == "live" { 0 } else { 1 });
    }
    shutdown.cancel();
    handle.await.unwrap();
    repair_handle.await.unwrap();
    let repairs: i64 = sqlx::query_scalar("SELECT count(*) FROM detection_late_replay_jobs WHERE rule_id=$1 AND bronze_store_id='open-cell:late-part:v1'")
        .bind(rule.id).fetch_one(&pg).await.unwrap();
    assert_eq!(
        repairs, 1,
        "unchanged part head must not duplicate a late repair"
    );
    let findings:Vec<(Uuid,Value)>=sqlx::query_as("SELECT security_tenant_id,ocsf_event FROM detection_finding_lake_outbox WHERE tenant_id=$1")
        .bind(tenant.to_string()).fetch_all(&pg).await.unwrap();
    assert!(findings
        .iter()
        .all(|(security, event)| *security == tenant && event["class_uid"] == 2004));
    assert!(
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.url.path().starts_with(&detect)),
        "all scheduler reads use detect leaf"
    );
}
