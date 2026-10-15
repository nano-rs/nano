// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3503: the identity-writer token on the lean enrichment coordinator.
//!
//! The hosted connector runner holds only each tenant's identity-writer
//! token. It must reach exactly the four identity write routes (deltas,
//! staged run rows, run commit, run abort) plus feed delete of a connector
//! sub-feed (`<feed uuid>:users|groups`, uninstall) and nothing else; the full token
//! keeps working everywhere; a token from another tenant's coordinator is
//! worthless here even when the body names this tenant.

use nanosiem_lake_worker::lean_enrichment_coordinator::{
    auth_digest, router, CoordinatorAuth, LeanCoordinatorState,
};
use nanosiem_lake_worker::lean_identity_snapshot::{IdentityRow, IdentityStore, SourceKind};
use nanosiem_lake_worker::parts::part_log::{LocalObjectStore, ObjectStore};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

const TENANT_A: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1a0a";
const TENANT_B: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1b0b";
const FULL_A: &str = "tenant-a-full-coordinator-bearer-token-000001";
const IDENTITY_A: &str = "tenant-a-identity-writer-bearer-token-000001";
const FULL_B: &str = "tenant-b-full-coordinator-bearer-token-000002";
const IDENTITY_B: &str = "tenant-b-identity-writer-bearer-token-000002";
const WRONG: &str = "not-a-token-any-coordinator-was-given-0000000";
/// A connector identity feed (its sub-feeds are `<id>:users`, `<id>:groups`).
const CONNECTOR_FEED: &str = "0199a0c4-2222-7000-8000-000000000001";

fn tenant_prefix(r2: &Path, tenant: &str) -> PathBuf {
    r2.join("lake/enrichment/v1")
        .join(format!("tenant_id={tenant}"))
}

struct Coordinator {
    url: String,
    state: LeanCoordinatorState,
    objects: Arc<dyn ObjectStore>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Coordinator {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn coordinator(
    r2: &Path,
    scratch: &Path,
    tenant: &str,
    full: &str,
    identity: Option<&str>,
) -> Coordinator {
    let objects: Arc<dyn ObjectStore> =
        Arc::new(LocalObjectStore::new(tenant_prefix(r2, tenant)).unwrap());
    let state = LeanCoordinatorState::with_auth(
        tenant.parse().unwrap(),
        CoordinatorAuth::from_tokens(full, identity).unwrap(),
        objects.clone(),
        scratch.to_path_buf(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = router(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Coordinator {
        url,
        state,
        objects,
        task,
    }
}

fn row(feed: &str, id: &str) -> IdentityRow {
    let mut row = IdentityRow::new(feed, id, SourceKind::Pull, 1);
    row.email = format!("{id}@example.com");
    row
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Bearer {
    Full,
    Identity,
    Wrong,
    None,
}

async fn call(
    c: &Coordinator,
    bearer: Option<&str>,
    method: Method,
    path: &str,
    body: Option<Vec<u8>>,
    tenant_header: &str,
) -> (StatusCode, Value) {
    let mut request = reqwest::Client::new()
        .request(method, format!("{}{path}", c.url))
        .header("X-Nano-Tenant-ID", tenant_header);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.body(body);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

struct Route {
    method: Method,
    path: String,
    body: Option<Vec<u8>>,
    identity_ok: bool,
}

fn routes(tenant: &str) -> Vec<Route> {
    let tenant_body = || Some(serde_json::to_vec(&json!({"tenant_id": tenant})).unwrap());
    let source = Uuid::new_v4();
    let route = |method: Method, path: String, body: Option<Vec<u8>>, identity_ok| Route {
        method,
        path,
        body,
        identity_ok,
    };
    vec![
        // The runner's write path: identity-writer allowed.
        route(
            Method::POST,
            "/v1/identity/directory/deltas".into(),
            Some(
                serde_json::to_vec(&json!({"tenant_id": tenant, "rows": [row("okta", "d")]}))
                    .unwrap(),
            ),
            true,
        ),
        route(
            Method::POST,
            "/v1/identity/directory/feeds/okta/runs/matrix/rows".into(),
            Some(
                serde_json::to_vec(
                    &json!({"tenant_id": tenant, "chunk": 0, "rows": [row("okta", "s")]}),
                )
                .unwrap(),
            ),
            true,
        ),
        route(
            Method::POST,
            "/v1/identity/directory/feeds/okta/runs/matrix/commit".into(),
            Some(serde_json::to_vec(&json!({"tenant_id": tenant, "expected_rows": 1})).unwrap()),
            true,
        ),
        route(
            Method::DELETE,
            "/v1/identity/directory/feeds/okta/runs/matrix".into(),
            tenant_body(),
            true,
        ),
        // Uninstall: a connector feed's own sub-feeds.
        route(
            Method::DELETE,
            format!("/v1/identity/directory/feeds/{CONNECTOR_FEED}:users"),
            tenant_body(),
            true,
        ),
        route(
            Method::DELETE,
            format!("/v1/identity/directory/feeds/{CONNECTOR_FEED}:groups"),
            tenant_body(),
            true,
        ),
        // Everything else: full token only. Any other feed id (a push feed,
        // an observed feed, another sub-feed name, a non-canonical uuid).
        route(
            Method::DELETE,
            "/v1/identity/directory/feeds/okta".into(),
            tenant_body(),
            false,
        ),
        route(
            Method::DELETE,
            "/v1/identity/directory/feeds/push:okta".into(),
            tenant_body(),
            false,
        ),
        route(
            Method::DELETE,
            "/v1/identity/directory/feeds/observed".into(),
            tenant_body(),
            false,
        ),
        route(
            Method::DELETE,
            format!("/v1/identity/directory/feeds/{CONNECTOR_FEED}:roles"),
            tenant_body(),
            false,
        ),
        route(
            Method::DELETE,
            format!(
                "/v1/identity/directory/feeds/{}:users",
                CONNECTOR_FEED.to_uppercase()
            ),
            tenant_body(),
            false,
        ),
        route(
            Method::POST,
            "/v1/identity/directory/compact".into(),
            tenant_body(),
            false,
        ),
        route(
            Method::PUT,
            format!("/v1/enrichment/sources/{source}"),
            Some(
                serde_json::to_vec(&json!({"tenant_id": tenant, "records": [{
                    "ioc_value": "8.8.8.8", "ioc_type": "ip", "source_id": source.to_string()
                }]}))
                .unwrap(),
            ),
            false,
        ),
        route(
            Method::DELETE,
            format!("/v1/enrichment/sources/{source}"),
            tenant_body(),
            false,
        ),
        route(
            Method::POST,
            "/v1/ip-context/batch".into(),
            Some(
                serde_json::to_vec(&json!({
                    "network": "10.0.0.0/8", "source_id": "cmdb", "country_code": "US",
                    "asn": "AS64512", "as_name": "x", "updated_at": "2026-10-12T00:00:00Z"
                }))
                .unwrap(),
            ),
            false,
        ),
        route(
            Method::DELETE,
            "/v1/ip-context/sources/cmdb".into(),
            tenant_body(),
            false,
        ),
        route(
            Method::GET,
            format!("/v1/ip-context/stats?tenant_id={tenant}"),
            None,
            false,
        ),
        route(
            Method::PUT,
            "/v1/internal-domains".into(),
            Some(serde_json::to_vec(&json!({"tenant_id": tenant, "suffixes": ["corp"]})).unwrap()),
            false,
        ),
    ]
}

/// Every route x {full, identity-writer, wrong, none}. Refusals carry no
/// detail beyond a generic word; accepted calls are never 401/403.
#[tokio::test]
async fn identity_writer_token_reaches_only_the_runner_write_routes() {
    let dir = tempfile::tempdir().unwrap();
    let r2 = dir.path().join("r2");
    let a = coordinator(
        &r2,
        &dir.path().join("a"),
        TENANT_A,
        FULL_A,
        Some(IDENTITY_A),
    )
    .await;
    // Seed a feed so a wrongly accepted feed delete or compact would show.
    let (status, _) = call(
        &a,
        Some(FULL_A),
        Method::POST,
        "/v1/identity/directory/deltas",
        Some(
            serde_json::to_vec(&json!({"tenant_id": TENANT_A, "rows": [row("okta", "seed")]}))
                .unwrap(),
        ),
        TENANT_A,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    for bearer in [Bearer::None, Bearer::Wrong, Bearer::Identity, Bearer::Full] {
        for route in routes(TENANT_A) {
            let token = match bearer {
                Bearer::Full => Some(FULL_A),
                Bearer::Identity => Some(IDENTITY_A),
                Bearer::Wrong => Some(WRONG),
                Bearer::None => None,
            };
            let (status, body) = call(
                &a,
                token,
                route.method.clone(),
                &route.path,
                route.body.clone(),
                TENANT_A,
            )
            .await;
            let case = format!("{bearer:?} {} {}", route.method, route.path);
            match bearer {
                Bearer::None | Bearer::Wrong => {
                    assert_eq!(status, StatusCode::UNAUTHORIZED, "{case}");
                    assert_eq!(body, json!({"error": "unauthorized"}), "{case}");
                }
                Bearer::Identity if !route.identity_ok => {
                    assert_eq!(status, StatusCode::FORBIDDEN, "{case}");
                    assert_eq!(body, json!({"error": "forbidden"}), "{case}");
                }
                Bearer::Identity | Bearer::Full => {
                    assert!(
                        status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
                        "{case}: {status} {body}"
                    );
                }
            }
            if bearer == Bearer::Identity && route.identity_ok {
                // The runner's flow really works with only this token
                // (deltas 200, stage 200, commit 200, abort 204).
                assert!(status.is_success(), "{case}: {status} {body}");
            }
        }
        if bearer != Bearer::Full {
            // Nothing a refused call could have done: the seeded feed is
            // intact and no IOC / IP-context / internal-domains snapshot exists.
            let keys = a.objects.list("").await.unwrap();
            assert!(
                keys.iter().all(|key| key.starts_with("identity/")),
                "{bearer:?} wrote outside identity/: {keys:?}"
            );
            let store =
                IdentityStore::new(a.state.tenant_id, &*a.objects, &dir.path().join("read"))
                    .unwrap();
            let view = store
                .load_view(&store.current().await.unwrap().unwrap())
                .await
                .unwrap();
            assert!(!view.is_empty(), "{bearer:?} removed the seeded feed");
        }
    }
}

/// Cross-tenant negatives. B's coordinator refuses A's identity-writer (and
/// full) token on the runner routes even when the body names B; A's
/// coordinator refuses a body naming B with A's own valid tokens.
#[tokio::test]
async fn tokens_and_bodies_never_cross_tenants() {
    let dir = tempfile::tempdir().unwrap();
    let r2 = dir.path().join("r2");
    let a = coordinator(
        &r2,
        &dir.path().join("a"),
        TENANT_A,
        FULL_A,
        Some(IDENTITY_A),
    )
    .await;
    let b = coordinator(
        &r2,
        &dir.path().join("b"),
        TENANT_B,
        FULL_B,
        Some(IDENTITY_B),
    )
    .await;

    let runner_routes = |tenant: &str| -> Vec<(Method, &'static str, Vec<u8>)> {
        vec![
            (
                Method::POST,
                "/v1/identity/directory/deltas",
                serde_json::to_vec(&json!({"tenant_id": tenant, "rows": [row("okta", "x")]}))
                    .unwrap(),
            ),
            (
                Method::POST,
                "/v1/identity/directory/feeds/okta/runs/cross/rows",
                serde_json::to_vec(
                    &json!({"tenant_id": tenant, "chunk": 0, "rows": [row("okta", "x")]}),
                )
                .unwrap(),
            ),
            (
                Method::POST,
                "/v1/identity/directory/feeds/okta/runs/cross/commit",
                serde_json::to_vec(&json!({"tenant_id": tenant, "expected_rows": 1})).unwrap(),
            ),
            (
                Method::DELETE,
                "/v1/identity/directory/feeds/okta/runs/cross",
                serde_json::to_vec(&json!({"tenant_id": tenant})).unwrap(),
            ),
            // Uninstall: the pattern matches, the tenant still must.
            (
                Method::DELETE,
                "/v1/identity/directory/feeds/0199a0c4-2222-7000-8000-000000000001:users",
                serde_json::to_vec(&json!({"tenant_id": tenant})).unwrap(),
            ),
        ]
    };

    for token in [IDENTITY_A, FULL_A] {
        for (method, path, body) in runner_routes(TENANT_B) {
            let (status, reply) =
                call(&b, Some(token), method.clone(), path, Some(body), TENANT_B).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "B accepted A's token on {method} {path}"
            );
            assert_eq!(reply, json!({"error": "unauthorized"}));
        }
    }
    for token in [IDENTITY_A, FULL_A] {
        for (method, path, body) in runner_routes(TENANT_B) {
            let (status, reply) =
                call(&a, Some(token), method.clone(), path, Some(body), TENANT_A).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "A accepted B's tenant on {method} {path}"
            );
            assert_eq!(
                reply,
                json!({"error": "tenant identity differs from assignment"})
            );
        }
    }
    // Nothing reached either tenant's identity directory.
    assert!(a.objects.list("identity/").await.unwrap().is_empty());
    assert!(b.objects.list("identity/").await.unwrap().is_empty());
    assert!(std::fs::read_dir(tenant_prefix(&r2, TENANT_B))
        .map(|entries| entries.count() == 0)
        .unwrap_or(true));

    // B's own identity-writer token does work on B (the control).
    let (status, _) = call(
        &b,
        Some(IDENTITY_B),
        Method::POST,
        "/v1/identity/directory/deltas",
        Some(
            serde_json::to_vec(&json!({"tenant_id": TENANT_B, "rows": [row("okta", "x")]}))
                .unwrap(),
        ),
        TENANT_B,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// Absent identity-writer token: today's behavior exactly; a token that is
/// nobody's is 401 on the runner routes too.
#[tokio::test]
async fn without_identity_writer_only_the_full_token_works() {
    let dir = tempfile::tempdir().unwrap();
    let r2 = dir.path().join("r2");
    let a = coordinator(&r2, &dir.path().join("a"), TENANT_A, FULL_A, None).await;
    assert!(!a.state.auth.load().has_identity_writer());
    // `new` (the pre-NAN-3503 constructor) builds the same full-only set.
    let legacy = LeanCoordinatorState::new(
        TENANT_A.parse().unwrap(),
        auth_digest(FULL_A),
        a.objects.clone(),
        dir.path().join("legacy"),
    )
    .unwrap();
    assert_eq!(**legacy.auth.load(), **a.state.auth.load());
    let deltas = || {
        Some(
            serde_json::to_vec(&json!({"tenant_id": TENANT_A, "rows": [row("okta", "x")]}))
                .unwrap(),
        )
    };
    let (status, _) = call(
        &a,
        Some(IDENTITY_A),
        Method::POST,
        "/v1/identity/directory/deltas",
        deltas(),
        TENANT_A,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(
        &a,
        Some(FULL_A),
        Method::POST,
        "/v1/identity/directory/deltas",
        deltas(),
        TENANT_A,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// Rotation swaps both tokens in place; the old ones stop working at once.
#[tokio::test]
async fn rotation_replaces_both_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let r2 = dir.path().join("r2");
    let a = coordinator(
        &r2,
        &dir.path().join("a"),
        TENANT_A,
        FULL_A,
        Some(IDENTITY_A),
    )
    .await;
    let next_full = "tenant-a-full-coordinator-bearer-token-rotated";
    let next_identity = "tenant-a-identity-writer-bearer-token-rotated";
    assert!(a
        .state
        .rotate_auth(CoordinatorAuth::from_tokens(next_full, Some(next_identity)).unwrap())
        .unwrap());
    // Unchanged set: no-op.
    assert!(!a
        .state
        .rotate_auth(CoordinatorAuth::from_tokens(next_full, Some(next_identity)).unwrap())
        .unwrap());
    // Presence of the identity-writer token is fixed at boot.
    assert!(a
        .state
        .rotate_auth(CoordinatorAuth::from_tokens(next_full, None).unwrap())
        .is_err());
    let deltas = || {
        Some(
            serde_json::to_vec(&json!({"tenant_id": TENANT_A, "rows": [row("okta", "x")]}))
                .unwrap(),
        )
    };
    for (token, expected) in [
        (FULL_A, StatusCode::UNAUTHORIZED),
        (IDENTITY_A, StatusCode::UNAUTHORIZED),
        (next_identity, StatusCode::OK),
        (next_full, StatusCode::OK),
    ] {
        let (status, _) = call(
            &a,
            Some(token),
            Method::POST,
            "/v1/identity/directory/deltas",
            deltas(),
            TENANT_A,
        )
        .await;
        assert_eq!(status, expected);
    }
    let (status, _) = call(
        &a,
        Some(next_identity),
        Method::POST,
        "/v1/identity/directory/compact",
        Some(serde_json::to_vec(&json!({"tenant_id": TENANT_A})).unwrap()),
        TENANT_A,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[test]
fn token_validation_refuses_short_and_equal_tokens() {
    assert!(CoordinatorAuth::from_tokens(FULL_A, Some(FULL_A)).is_err());
    assert!(CoordinatorAuth::from_tokens(FULL_A, Some("short-identity-token")).is_err());
    assert!(CoordinatorAuth::from_tokens("short-full-token", Some(IDENTITY_A)).is_err());
    assert!(CoordinatorAuth::from_tokens("short-full-token", None).is_err());
    assert!(CoordinatorAuth::from_digests(auth_digest(FULL_A), Some(auth_digest(FULL_A))).is_err());
    let auth = CoordinatorAuth::from_tokens(FULL_A, Some(IDENTITY_A)).unwrap();
    assert!(auth.has_identity_writer());
    // Debug never prints digest material.
    let debug = format!("{auth:?}");
    assert!(!debug.contains('['), "{debug}");
}
