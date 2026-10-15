// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3475: negative cross-tenant tests for the prevalence rarity threshold.
//!
//! On hosted-shared, one Search process (and one API process) serves every
//! tenant. The process singleton may carry a deployment-global
//! `PrevalenceService` whose Settings threshold (`RarityThresholdSetting`, an
//! `Arc<AtomicU64>` shared by every clone) was read from `system_settings`.
//! Each tenant must still judge rarity by its OWN threshold: a gen1 tenant by
//! its worker-registry `prevalence_rarity_threshold`, a lean-lake tenant by
//! the fixed cell contract. Never by the process value, and never by another
//! tenant's, including on back-to-back requests that would hit a shared cache.

use super::*;
use crate::auth::ArtifactScope;
use crate::prevalence::{PrevalenceConfig, PrevalenceLookup, PrevalenceService, TimeWindow};
use crate::search::lake_cell::{LakeCellRoute, LAKE_CELL_PREVALENCE_RARITY_THRESHOLD};
use crate::search::{InMemoryJobStore, LakeBackend, SearchTenantScope, SharedLakeWorkerAssignment};
use serde_json::json;
use std::sync::Arc;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The deployment-global Settings value the process singleton holds. No
/// tenant threshold below equals it, so any leak is visible.
const PROCESS_SETTINGS_THRESHOLD: u64 = 50;
const TENANT_A_THRESHOLD: u64 = 2;
const TENANT_B_THRESHOLD: u64 = 7;
/// Every worker double answers this host count: rare for B (4 < 7), not for
/// A (4 >= 2), and rare under the process value (4 < 50).
const HOST_COUNT: u64 = 4;
const WORKER_REVISION: u64 = 1;

fn tenant_a() -> uuid::Uuid {
    uuid::Uuid::from_u128(0xa11ce)
}

fn tenant_b() -> uuid::Uuid {
    uuid::Uuid::from_u128(0xb0b)
}

fn worker_identity(tenant: uuid::Uuid) -> String {
    format!("prevalence-worker-{tenant}")
}

fn artifact(name: &str, host_count: u64) -> serde_json::Value {
    json!({
        "artifact": name, "artifact_type": "domain", "host_count": host_count,
        "total_occurrences": 9, "first_seen": "2026-10-09T00:00:00Z",
        "last_seen": "2026-10-09T01:00:00Z", "is_rare": true, "prevalence_score": 10,
    })
}

/// A gen1 lake worker for exactly one tenant: echoes the request binding,
/// signs its assignment headers, and answers lookup / explorer / export.
/// Export filters by the request's `max_prevalence` like the real worker.
struct Gen1Worker {
    tenant: uuid::Uuid,
}

impl Respond for Gen1Worker {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(
            body["tenant_id"],
            json!(self.tenant.to_string()),
            "a request reached another tenant's worker"
        );
        let envelope = match request.url.path() {
            "/v1/prevalence/lookup" => json!({
                "ok": true, "tenant_id": self.tenant.to_string(), "snapshot_id": body["snapshot_id"],
                "results": body["artifacts"].as_array().unwrap().iter()
                    .map(|name| artifact(name.as_str().unwrap(), HOST_COUNT)).collect::<Vec<_>>(),
            }),
            "/v1/prevalence/explorer" => json!({
                "ok": true, "tenant_id": self.tenant.to_string(), "snapshot_id": body["snapshot_id"],
                "window": body["window"],
                "result": {
                    "artifacts": [], "total": 0, "limit": body["limit"], "offset": body["offset"],
                    "has_more": false, "next_cursor": null, "rarity_threshold": 3, "rare_count": 0,
                    "new_count": 0, "high_risk_asset_count": 0, "counts_approximate": false,
                },
            }),
            "/v1/prevalence/export" => {
                let max = body["max_prevalence"].as_u64().unwrap();
                json!({
                    "ok": true, "tenant_id": self.tenant.to_string(), "snapshot_id": body["snapshot_id"],
                    "window": body["window"], "truncated": false,
                    "results": (1..=6u64).filter(|count| *count <= max)
                        .map(|count| artifact(&format!("h{count}.example"), count)).collect::<Vec<_>>(),
                })
            }
            other => panic!("unexpected worker path {other}"),
        };
        ResponseTemplate::new(200)
            .set_body_json(envelope)
            .insert_header(
                "x-nano-worker-assignment-id",
                worker_identity(self.tenant).as_str(),
            )
            .insert_header(
                "x-nano-worker-assignment-revision",
                WORKER_REVISION.to_string().as_str(),
            )
    }
}

/// A lean-lake cell's query[T] for exactly one tenant (lookup only).
struct CellQuery {
    tenant: uuid::Uuid,
}

impl Respond for CellQuery {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["tenant_id"], json!(self.tenant.to_string()));
        ResponseTemplate::new(200).set_body_json(json!({
            "ok": true, "tenant_id": self.tenant.to_string(), "route": "prevalence_lookup",
            "source_mode": "parts", "window": body["window"],
            "results": body["artifacts"].as_array().unwrap().iter()
                .map(|name| artifact(name.as_str().unwrap(), HOST_COUNT)).collect::<Vec<_>>(),
        }))
    }
}

async fn never_connecting_pool() -> crate::db::DualPool {
    crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
        "postgres://fixture:fixture@127.0.0.1:1/never_connect",
        "http://127.0.0.1:1",
        "fixture",
        "fixture",
        "fixture",
    ))
    .await
    .unwrap()
}

/// The process singleton as a shared Search process holds it: a
/// deployment-global `PrevalenceService` whose Settings threshold was read
/// (here: set) to [`PROCESS_SETTINGS_THRESHOLD`].
async fn process_singleton(pool: &crate::db::DualPool) -> (SearchService, PrevalenceService) {
    let process_prevalence = PrevalenceService::with_config(
        pool.clickhouse().clone(),
        pool.table_names(),
        PrevalenceConfig::default(),
    );
    process_prevalence
        .update_config(PrevalenceConfig {
            rarity_threshold: PROCESS_SETTINGS_THRESHOLD,
            ..PrevalenceConfig::default()
        })
        .await;
    assert_eq!(
        process_prevalence.rarity_setting().get(),
        Some(PROCESS_SETTINGS_THRESHOLD)
    );
    let mut service = SearchService::with_dual_pool(pool);
    service.set_prevalence_service(process_prevalence.clone());
    // Whatever lookup the singleton was wired with, it judges by the process
    // Settings value. A tenant view must never keep it.
    service.set_prevalence_lookup(Arc::new(process_prevalence.clone()));
    assert_eq!(
        service.tree_rarity_threshold().await,
        PROCESS_SETTINGS_THRESHOLD
    );
    (service, process_prevalence)
}

fn gen1_assignment(
    tenant: uuid::Uuid,
    server: &MockServer,
    dir: &std::path::Path,
    threshold: u64,
) -> SharedLakeWorkerAssignment {
    let credential = dir.join(format!("worker-{tenant}.token"));
    std::fs::write(&credential, format!("credential-{tenant}-0123456789abcdef")).unwrap();
    SharedLakeWorkerAssignment {
        tenant_id: tenant,
        internal_endpoint: server.uri(),
        credential_file: credential,
        expected_worker_identity: worker_identity(tenant),
        expected_worker_revision: WORKER_REVISION,
        timeout_secs: 10,
        prevalence_snapshots: crate::prevalence::LakePrevalenceSnapshots {
            one_hour: format!("{tenant}-1h"),
            twenty_four_hours: format!("{tenant}-24h"),
            seven_days: format!("{tenant}-7d"),
            thirty_days: format!("{tenant}-30d"),
        },
        prevalence_rarity_threshold: threshold,
        prevalence_timeout_secs: 10,
        enrichment_coordinator: None,
        otel_ingest: None,
        erasure_executor: None,
    }
}

#[cfg(feature = "enterprise")]
fn scope(tenant: uuid::Uuid) -> SearchTenantScope {
    SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0).unwrap()
}

fn tree_info() -> TreeCommandInfo {
    TreeCommandInfo {
        parent_field: "parent".into(),
        child_field: "child".into(),
        label_field: "label".into(),
        detail_field: None,
        prevalence_field: None,
        root_filter: None,
        preset: None,
    }
}

/// `is_rare` of a one-node tree whose node has `prevalence_min = HOST_COUNT`.
async fn tree_is_rare(view: &SearchService) -> serde_json::Value {
    let rows =
        vec![json!({"child": "c", "parent": "p", "label": "c", "prevalence_min": HOST_COUNT})];
    let out = view
        .build_tree_visualization(rows, &tree_info())
        .await
        .unwrap();
    out[0]["_tree_nodes"][0]["children"][0]["prevalence"]["is_rare"].clone()
}

async fn lookup_is_rare(view: &SearchService) -> bool {
    let lookup = view
        .prevalence_lookup()
        .expect("tenant view has a prevalence lookup");
    let rows = lookup
        .lookup(
            &["probe.example".to_string()],
            TimeWindow::TwentyFourHours,
            &ArtifactScope::system(),
        )
        .await
        .unwrap();
    assert_eq!(rows[0].host_count, HOST_COUNT);
    rows[0].is_rare
}

#[cfg(feature = "enterprise")]
/// Two gen1 tenants with different registry thresholds behind one shared
/// Search process whose singleton holds a third, deployment-global Settings
/// value. Search views, tree `is_rare`, point lookups, explorer and export
/// (the hosted `/api/prevalence/*` construction, `LakeBackend::prevalence_client`)
/// each answer with the caller's own threshold, interleaved A/B/A/B, and a
/// later change to the process Settings value reaches neither tenant.
#[tokio::test]
async fn gen1_tenants_never_share_a_rarity_threshold() {
    let pool = never_connecting_pool().await;
    let (singleton, process_prevalence) = process_singleton(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let (server_a, server_b) = (MockServer::start().await, MockServer::start().await);
    Mock::given(wiremock::matchers::method("POST"))
        .respond_with(Gen1Worker { tenant: tenant_a() })
        .mount(&server_a)
        .await;
    Mock::given(wiremock::matchers::method("POST"))
        .respond_with(Gen1Worker { tenant: tenant_b() })
        .mount(&server_b)
        .await;
    let assignment_a = gen1_assignment(tenant_a(), &server_a, dir.path(), TENANT_A_THRESHOLD);
    let assignment_b = gen1_assignment(tenant_b(), &server_b, dir.path(), TENANT_B_THRESHOLD);
    let view = |assignment: &SharedLakeWorkerAssignment| {
        singleton
            .enterprise_shared_backend_view(
                &LakeBackend::Gen1(assignment),
                scope(assignment.tenant_id),
                Arc::new(InMemoryJobStore::new()),
            )
            .unwrap()
    };
    let (view_a, view_b) = (view(&assignment_a), view(&assignment_b));
    // The process-global ClickHouse service is stripped, not inherited.
    assert!(view_a.prevalence_service.is_none());
    assert!(view_b.prevalence_service.is_none());

    for round in 0..2 {
        if round == 1 {
            // A Settings change on the process after the views exist must not
            // propagate through any shared Arc.
            process_prevalence
                .update_config(PrevalenceConfig {
                    rarity_threshold: 1,
                    ..PrevalenceConfig::default()
                })
                .await;
            assert_eq!(singleton.tree_rarity_threshold().await, 1);
        }
        for _ in 0..2 {
            assert_eq!(view_a.tree_rarity_threshold().await, TENANT_A_THRESHOLD);
            assert_eq!(view_b.tree_rarity_threshold().await, TENANT_B_THRESHOLD);
            assert_eq!(
                view_a.prevalence_lookup().unwrap().rarity_threshold().await,
                TENANT_A_THRESHOLD
            );
            assert_eq!(
                view_b.prevalence_lookup().unwrap().rarity_threshold().await,
                TENANT_B_THRESHOLD
            );
            assert_eq!(
                tree_is_rare(&view_a).await,
                json!(false),
                "A: 4 < 2 is not rare"
            );
            assert_eq!(tree_is_rare(&view_b).await, json!(true), "B: 4 < 7 is rare");
            assert!(!lookup_is_rare(&view_a).await);
            assert!(lookup_is_rare(&view_b).await);
        }
    }

    // The hosted `/api/prevalence/*` handlers and the export runtime build
    // their client per request from the tenant's backend.
    for _ in 0..2 {
        for (assignment, threshold, expected_export) in [
            (&assignment_a, TENANT_A_THRESHOLD, vec!["h1.example"]),
            (
                &assignment_b,
                TENANT_B_THRESHOLD,
                vec![
                    "h1.example",
                    "h2.example",
                    "h3.example",
                    "h4.example",
                    "h5.example",
                    "h6.example",
                ],
            ),
        ] {
            let client = LakeBackend::Gen1(assignment).prevalence_client().unwrap();
            assert_eq!(client.rarity_threshold().await, threshold);
            client
                .explore(
                    None,
                    TimeWindow::TwentyFourHours,
                    Some("rare"),
                    None,
                    None,
                    50,
                    0,
                    None,
                    &ArtifactScope::system(),
                )
                .await
                .unwrap();
            // The export handler's default `max_prevalence` is the client threshold.
            let exported = client
                .export(
                    None,
                    TimeWindow::TwentyFourHours,
                    client.rarity_threshold().await,
                    100,
                    &ArtifactScope::system(),
                )
                .await
                .unwrap();
            let names: Vec<_> = exported
                .artifacts
                .iter()
                .map(|item| item.artifact.as_str())
                .collect();
            assert_eq!(names, expected_export, "tenant {}", assignment.tenant_id);
        }
    }

    // On the wire: every request went to its own tenant's worker (asserted in
    // the double), explorer requests never carried a threshold (the worker
    // uses the tenant's own snapshot threshold), and exports were bounded by
    // the tenant's own threshold, never the process value (50 or 1).
    for (server, threshold) in [
        (&server_a, TENANT_A_THRESHOLD),
        (&server_b, TENANT_B_THRESHOLD),
    ] {
        let requests = server.received_requests().await.unwrap();
        assert!(!requests.is_empty());
        for request in requests {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            match request.url.path() {
                "/v1/prevalence/lookup" => {
                    assert!(body.get("rarity_threshold").is_none(), "{body}")
                }
                "/v1/prevalence/explorer" => assert!(
                    body.get("rarity_threshold")
                        .is_none_or(serde_json::Value::is_null),
                    "a gen1 explorer request carried a threshold: {body}"
                ),
                "/v1/prevalence/export" => assert_eq!(body["max_prevalence"], json!(threshold)),
                other => panic!("unexpected path {other}"),
            }
        }
    }
}

#[cfg(feature = "enterprise")]
/// Lean-lake cell tenants share one fixed rarity contract, never the process
/// Settings value: the tenant view, its tree and the query[T] lookup request
/// all carry [`LAKE_CELL_PREVALENCE_RARITY_THRESHOLD`], and each tenant's
/// request reaches only its own query prefix.
#[tokio::test]
async fn lean_cell_tenants_use_the_cell_contract_not_the_process_settings() {
    let pool = never_connecting_pool().await;
    let (singleton, _process_prevalence) = process_singleton(&pool).await;
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("router.token");
    std::fs::write(&token, "router-token-router-token-router-token-xyz").unwrap();
    let server = MockServer::start().await;
    for tenant in [tenant_a(), tenant_b()] {
        Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(format!(
                "/v1/tenants/{tenant}/query/v1/prevalence/lookup"
            )))
            .respond_with(CellQuery { tenant })
            .mount(&server)
            .await;
    }
    let route = |tenant| {
        Arc::new(LakeCellRoute::for_test(
            tenant,
            &server.uri(),
            token.clone(),
        ))
    };
    let (route_a, route_b) = (route(tenant_a()), route(tenant_b()));
    let view = |route: &Arc<LakeCellRoute>| {
        singleton
            .enterprise_shared_backend_view(
                &LakeBackend::Cell(Arc::clone(route)),
                scope(route.tenant_id),
                Arc::new(InMemoryJobStore::new()),
            )
            .unwrap()
    };
    let (view_a, view_b) = (view(&route_a), view(&route_b));
    assert!(view_a.prevalence_service.is_none() && view_b.prevalence_service.is_none());
    // 4 < 3 is not rare under the cell contract; it would be under the
    // process value (50).
    assert!(HOST_COUNT >= LAKE_CELL_PREVALENCE_RARITY_THRESHOLD);
    for view in [&view_a, &view_b, &view_a, &view_b] {
        assert_eq!(
            view.tree_rarity_threshold().await,
            LAKE_CELL_PREVALENCE_RARITY_THRESHOLD
        );
        assert_eq!(tree_is_rare(view).await, json!(false));
        assert!(!lookup_is_rare(view).await);
    }
    for route in [&route_a, &route_b] {
        let client = LakeBackend::Cell(Arc::clone(route))
            .prevalence_client()
            .unwrap();
        assert_eq!(
            client.rarity_threshold().await,
            LAKE_CELL_PREVALENCE_RARITY_THRESHOLD
        );
    }
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 4);
    for request in requests {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(
            body["rarity_threshold"],
            json!(LAKE_CELL_PREVALENCE_RARITY_THRESHOLD),
            "{body}"
        );
    }
}
