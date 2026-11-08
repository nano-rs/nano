// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2042: `/metrics` is a private service route. Served over real TCP;
//! the peer address is injected with `MockConnectInfo` to model a caller on
//! the pod / container network.

use super::SearchMetrics;
use axum::extract::connect_info::MockConnectInfo;
use nanosiem_core::auth::service_credential::ServiceCredential;
use std::net::SocketAddr;
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The Prometheus recorder is process-global: build it once per test binary.
fn metrics() -> &'static SearchMetrics {
    static METRICS: OnceLock<SearchMetrics> = OnceLock::new();
    METRICS.get_or_init(|| SearchMetrics::new().0)
}

async fn status(credential: ServiceCredential, peer: &str, authorization: &[&str]) -> u16 {
    let peer: SocketAddr = peer.parse().unwrap();
    let app = metrics()
        .metrics_router_with(credential)
        .layer(MockConnectInfo(peer));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut request = format!("GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for value in authorization {
        request.push_str(&format!("Authorization: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    server.abort();
    response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("HTTP status line")
}

fn token() -> ServiceCredential {
    ServiceCredential::new(Some("svc-token".into()), None)
}

#[tokio::test]
async fn pod_network_caller_without_credential_gets_401() {
    assert_eq!(status(ServiceCredential::default(), "10.42.0.9:40000", &[]).await, 401);
    assert_eq!(status(token(), "10.42.0.9:40000", &[]).await, 401);
    assert_eq!(status(token(), "10.42.0.9:40000", &["Bearer wrong"]).await, 401);
}

#[tokio::test]
async fn service_credential_admits_remote_scraper() {
    assert_eq!(status(token(), "10.42.0.9:40000", &["Bearer svc-token"]).await, 200);
}

#[tokio::test]
async fn repeated_authorization_header_is_refused() {
    assert_eq!(
        status(token(), "10.42.0.9:40000", &["Bearer svc-token", "Bearer svc-token"]).await,
        401
    );
}

#[tokio::test]
async fn search_listener_requires_the_token_even_from_loopback() {
    // P2-6: a same-host reverse proxy makes remote requests arrive from
    // loopback, so the search listener never admits tokenless loopback.
    assert_eq!(status(ServiceCredential::default(), "127.0.0.1:40000", &[]).await, 401);
    assert_eq!(status(token(), "127.0.0.1:40000", &[]).await, 401);
    assert_eq!(status(token(), "127.0.0.1:40000", &["Bearer svc-token"]).await, 200);
}
