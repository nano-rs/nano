// SPDX-License-Identifier: AGPL-3.0-or-later

//! A pinned SSRF client for a user-controlled destination (ProxyPolicy::Direct)
//! must never go through a proxy: the proxy re-resolves
//! the hostname and reqwest drops `resolve_to_addrs` for proxied requests, so
//! a configured HTTPS_PROXY / HTTP_PROXY would undo the pin.
//!
//! The builder gets an explicit proxy at a dead port (the same effect as an
//! env proxy, without mutating process env under parallel tests). A pinned
//! request must still reach the pinned local listener directly.

use super::*;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn one_shot_http_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\nconnection: close\r\n\r\npinned")
                .await;
        }
    });
    addr
}

fn dead_proxy() -> reqwest::Proxy {
    // Port 9 (discard) on loopback: nothing listens, so a proxied request fails.
    reqwest::Proxy::all("http://127.0.0.1:9").unwrap()
}

#[tokio::test]
async fn pinned_hostname_client_bypasses_a_configured_proxy() {
    let server = one_shot_http_server().await;
    let url = Url::parse(&format!("http://pinned.nano.invalid:{}/", server.port())).unwrap();
    let client = pin_resolved_addrs(reqwest::Client::builder().proxy(dead_proxy()), &url, &[server], ProxyPolicy::Direct)
        .unwrap()
        .build()
        .unwrap();
    let body = client.get(url).send().await.expect("pinned request went to the proxy").text().await.unwrap();
    assert_eq!(body, "pinned");
}

#[tokio::test]
async fn pinned_ip_literal_client_bypasses_a_configured_proxy() {
    let server = one_shot_http_server().await;
    let url = Url::parse(&format!("http://{server}/")).unwrap();
    let client = pin_resolved_addrs(reqwest::Client::builder().proxy(dead_proxy()), &url, &[], ProxyPolicy::Direct)
        .unwrap()
        .build()
        .unwrap();
    let body = client.get(url).send().await.expect("literal request went to the proxy").text().await.unwrap();
    assert_eq!(body, "pinned");
}

#[tokio::test]
async fn environment_policy_keeps_the_operator_proxy() {
    // Operator-configured destinations (feeds, OIDC, identity directories)
    // must still go through the proxy: on a proxy-only egress install it is
    // the only way out. The dead proxy therefore makes this request fail.
    let server = one_shot_http_server().await;
    let url = Url::parse(&format!("http://pinned.nano.invalid:{}/", server.port())).unwrap();
    let client = pin_resolved_addrs(
        reqwest::Client::builder().proxy(dead_proxy()),
        &url,
        &[server],
        ProxyPolicy::Environment,
    )
    .unwrap()
    .build()
    .unwrap();
    assert!(client.get(url).send().await.is_err(), "Environment policy bypassed the proxy");
}

#[tokio::test]
async fn control_unpinned_builder_does_use_the_proxy() {
    // Proves the dead proxy actually intercepts: without no_proxy the same
    // request fails, so the two tests above are not vacuous.
    let server = one_shot_http_server().await;
    let client = reqwest::Client::builder().proxy(dead_proxy()).build().unwrap();
    assert!(client.get(format!("http://{server}/")).send().await.is_err());
}
