// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5077: when the allowlist rules cannot be loaded, the nanosiem-api
//! middleware refuses with 503 — it used to let every request through.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{ConnectInfo, Request},
    http::StatusCode,
    middleware::from_fn_with_state,
    routing::get,
    Router,
};
use nanosiem_core::ip_allowlist::{IpAllowlistScope, IpAllowlistService};
use tower::ServiceExt;

use super::{ip_allowlist_middleware, IpAllowlistState};

/// A service whose PostgreSQL is unreachable (nothing listens on port 1).
fn unloadable_allowlist() -> Arc<IpAllowlistService> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(500))
        .connect_lazy("postgres://unused@127.0.0.1:1/unused")
        .expect("lazy pool");
    Arc::new(IpAllowlistService::new(pool))
}

fn app() -> Router {
    let state = IpAllowlistState {
        service: unloadable_allowlist(),
        scope: IpAllowlistScope::Api,
    };
    Router::new()
        .route("/api/thing", get(|| async { "ok" }))
        .route("/health", get(|| async { "ok" }))
        .layer(from_fn_with_state(state, ip_allowlist_middleware))
}

async fn call(path: &str, peer: &str) -> (StatusCode, String) {
    let mut request = Request::builder().uri(path).body(Body::empty()).unwrap();
    let peer: SocketAddr = peer.parse().unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = app().oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 12).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn an_unloadable_allowlist_answers_503_to_remote_clients() {
    let (status, body) = call("/api/thing", "198.51.100.7:40000").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("IP_ALLOWLIST_UNAVAILABLE"), "{body}");
}

#[tokio::test]
async fn loopback_and_probes_still_pass_while_rules_cannot_load() {
    assert_eq!(call("/api/thing", "127.0.0.1:40000").await.0, StatusCode::OK);
    assert_eq!(call("/api/thing", "[::1]:40000").await.0, StatusCode::OK);
    assert_eq!(call("/health", "198.51.100.7:40000").await.0, StatusCode::OK);
}
