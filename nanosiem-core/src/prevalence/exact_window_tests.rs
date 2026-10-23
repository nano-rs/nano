// SPDX-License-Identifier: AGPL-3.0-or-later
//! Production cell client constructor, real HTTP mock, and no alternative route.
use super::*;
use crate::auth::{ArtifactScope, ScopeSet};
use crate::search::LakeCellRoute;
use serde_json::json;
use std::time::Duration;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn assigned(
    server: &MockServer,
    root: &tempfile::TempDir,
    tenant: uuid::Uuid,
) -> LakePrevalenceClient {
    let token = root.path().join("router.token");
    std::fs::write(&token, "fixture-token-fixture-token-fixture-token").unwrap();
    let route = LakeCellRoute {
        tenant_id: tenant,
        assignment_generation: 1,
        part_log_writer_epoch: 1,
        worker_revision: 1,
        assignment_fenced: true,
        cell_origin: server.uri(),
        query_base_url: format!("{}/v1/tenants/{tenant}/query", server.uri()),
        router_token_file: token,
    };
    LakePrevalenceClient::from_lake_cell_route(&route, 3, Duration::from_secs(5))
        .unwrap()
        .with_rarity_setting(RarityThresholdSetting::fixed(7))
}
fn bounds() -> ExactPrevalenceWindow {
    ExactPrevalenceWindow::parse(
        Some("2026-10-16T04:00:00.000Z"),
        Some("2026-10-17T04:00:00.000Z"),
    )
    .unwrap()
    .unwrap()
}
#[tokio::test]
async fn exact_prevalence_production_client_preserves_bounds_scope_and_settings() {
    let server = MockServer::start().await;
    let root = tempfile::tempdir().unwrap();
    let tenant = uuid::Uuid::from_u128(0xa);
    let b = bounds();
    let (start, end) = b.micros().unwrap();
    Mock::given(method("POST")).and(path(format!("/v1/tenants/{tenant}/query/v1/prevalence/lookup")))
        .and(body_partial_json(json!({"tenant_id": tenant.to_string(), "start": b.start, "end": b.end,
            "rarity_threshold": 7, "artifacts": ["example.test"]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true, "tenant_id": tenant.to_string(),
            "route": "prevalence_lookup", "window": "24h", "window_start_us": start, "window_end_exclusive_us": end,
            "requested_window": b, "effective_window": b, "note": "prevalence counted over whole parts; effective window shown",
            "results": [{"artifact": "example.test", "artifact_type": "domain", "host_count": 5, "total_occurrences": 5,
                "first_seen": "2026-10-16T05:00:00Z", "last_seen": "2026-10-16T06:00:00Z", "is_rare": false, "prevalence_score": 99}]})))
        .expect(1).mount(&server).await;
    let scope = ArtifactScope::from_scope(&ScopeSet::from_denied(
        ["private".to_string()].into_iter().collect(),
    ));
    let result = assigned(&server, &root, tenant)
        .lookup_between(&["example.test".into()], &b, &scope)
        .await
        .unwrap();
    assert!(
        result.data[0].is_rare,
        "Settings threshold wins over the constructor default"
    );
    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let denied = body["deny_source_types"].as_array().unwrap();
    assert!(denied.contains(&json!("private")));
    assert!(denied.contains(&json!(crate::auth::scope::UNRESOLVED_SOURCE_SENTINEL)));
}
#[tokio::test]
async fn exact_prevalence_refuses_foreign_tenant_and_ignored_or_shifted_bounds() {
    let root = tempfile::tempdir().unwrap();
    let tenant = uuid::Uuid::from_u128(0xa);
    let (start, end) = bounds().micros().unwrap();
    for body in [
        json!({"tenant_id": uuid::Uuid::from_u128(0xb).to_string(), "window_start_us": start, "window_end_exclusive_us": end}),
        json!({"tenant_id": tenant.to_string()}),
        json!({"tenant_id": tenant.to_string(), "window_start_us": start - 1, "window_end_exclusive_us": end}),
        json!({"tenant_id": tenant.to_string(), "window_start_us": start, "window_end_exclusive_us": end}),
    ] {
        let server = MockServer::start().await;
        let mut envelope =
            json!({"ok": true, "route": "prevalence_lookup", "window": "24h", "results": []});
        envelope
            .as_object_mut()
            .unwrap()
            .extend(body.as_object().unwrap().clone());
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(envelope))
            .expect(1)
            .mount(&server)
            .await;
        assert!(assigned(&server, &root, tenant)
            .lookup_between(
                &["example.test".into()],
                &bounds(),
                &ArtifactScope::system()
            )
            .await
            .is_err());
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests[0].url.path(),
            format!("/v1/tenants/{tenant}/query/v1/prevalence/lookup")
        );
    }
}
