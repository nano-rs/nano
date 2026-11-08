// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2042: `/metrics` is a private service route. Served over real TCP;
//! the peer address is injected with `MockConnectInfo` to model a caller on
//! the pod / container network.

use super::AppMetrics;
use axum::extract::connect_info::MockConnectInfo;
use nanosiem_core::auth::service_credential::{LoopbackPolicy, ServiceCredential};
use std::net::SocketAddr;
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The Prometheus recorder is process-global: build it once per test binary.
fn metrics() -> &'static AppMetrics {
    static METRICS: OnceLock<AppMetrics> = OnceLock::new();
    METRICS.get_or_init(|| AppMetrics::new().0)
}

async fn status(credential: ServiceCredential, peer: &str, authorization: &[&str]) -> u16 {
    status_with(credential, peer, authorization, LoopbackPolicy::RequireToken).await
}

/// `RequireToken` is the user-facing api listener; `AllowWhenUnconfigured`
/// is the jobs loopback-only listener.
async fn status_with(
    credential: ServiceCredential,
    peer: &str,
    authorization: &[&str],
    loopback: LoopbackPolicy,
) -> u16 {
    let peer: SocketAddr = peer.parse().unwrap();
    let app = metrics()
        .metrics_router_with(credential, loopback)
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
async fn jobs_listener_admits_tokenless_loopback_only_when_unconfigured() {
    let jobs = LoopbackPolicy::AllowWhenUnconfigured;
    assert_eq!(status_with(ServiceCredential::default(), "127.0.0.1:40000", &[], jobs).await, 200);
    assert_eq!(status_with(ServiceCredential::default(), "10.42.0.9:40000", &[], jobs).await, 401);
    // With a credential configured, loopback is not a bypass.
    assert_eq!(status_with(token(), "127.0.0.1:40000", &[], jobs).await, 401);
}

/// P2-6: on the user-facing api listener a same-host reverse proxy makes every
/// remote request arrive from 127.0.0.1, so tokenless loopback is refused.
#[tokio::test]
async fn api_listener_requires_the_token_even_from_loopback() {
    assert_eq!(status(ServiceCredential::default(), "127.0.0.1:40000", &[]).await, 401);
    assert_eq!(status(token(), "127.0.0.1:40000", &[]).await, 401);
    assert_eq!(status(token(), "127.0.0.1:40000", &["Bearer svc-token"]).await, 200);
}

/// Wiring guard for the jobs binary: its health/metrics listener binds through
/// the private-bind resolver (loopback by default) and serves with
/// ConnectInfo so the metrics guard sees the real TCP peer.
#[test]
fn jobs_listener_is_private_by_default() {
    let src = include_str!("bin/jobs.rs");
    assert!(src.contains("service_credential::private_bind_addr("));
    assert!(src.contains("into_make_service_with_connect_info::<std::net::SocketAddr>()"));
    assert!(src.contains("LoopbackPolicy::AllowWhenUnconfigured"));
    let api_main = include_str!("main.rs");
    assert!(api_main.contains("LoopbackPolicy::RequireToken"));
    assert!(!src.contains("format!(\"0.0.0.0:{}\", jobs_port)"));
    let default = nanosiem_core::auth::service_credential::private_bind_addr(None, 3001).unwrap();
    assert!(default.ip().is_loopback());
}

/// P1-3 guard: every shipped Prometheus config that scrapes api/search/jobs
/// presents the service credential. Read at runtime (not `include_str!`):
/// `deploy/` and `ludus/` are stripped from the open-core mirror, where the
/// missing files are skipped.
#[test]
fn every_prometheus_manifest_scrapes_with_the_service_credential() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let manifests = [
        "config/prometheus/prometheus.yml",
        "deploy/k8s/prometheus/prometheus.yaml",
        "deploy/k8s/rackspace/monitoring.yaml",
        "ludus/roles/nanosiem_stack/templates/prometheus.yml.j2",
        "deploy/src/deploy.js",
    ];
    let mut checked = 0;
    for rel in manifests {
        let Ok(text) = std::fs::read_to_string(root.join(rel)) else { continue };
        checked += 1;
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let is_app_job = line.contains("job_name:")
                && ["-api'", "-search'", "-jobs'"].iter().any(|s| line.contains(s));
            if !is_app_job {
                continue;
            }
            // The job's block ends at the next job_name.
            let block: Vec<&str> = lines[i + 1..]
                .iter()
                .take_while(|l| !l.contains("job_name:"))
                .copied()
                .collect();
            assert!(
                block.iter().any(|l| l.contains("credentials_file:")),
                "{rel}: {} scrapes /metrics without the service credential",
                line.trim()
            );
        }
    }
    assert!(checked >= 1);
}
