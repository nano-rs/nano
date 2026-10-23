//! NAN-4369: the broker tunnels through a CONNECT egress proxy. A fake proxy
//! (allow-listed by exact host, like the platform check) splices allowed
//! tunnels to the TLS mock; TLS and every vendor header stay end to end.
mod common;

use std::sync::{Arc, Mutex};

use common::*;
use nano_connector::broker::{BodyCaps, Broker, BrokerConfig, BrokerError, EgressGrant, GrantPurpose, OutboundRequest};
use nano_connector::egress_proxy::{ProxyDialer, ProxyRefusal};
use nano_connector::policy::HostPolicy;
use nano_connector::spec::AllowRule;
use nano_connector::template::Scope;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const KEY: &[u8] = b"connector-egress-key-32-bytes-min!!";

/// Answers 200 and splices to `upstream` for hosts in `allow`; 403 otherwise.
async fn fake_proxy(upstream: u16, allow: &'static [&'static str]) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = heads.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else { break };
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let Ok(b) = client.read_u8().await else { return };
                    head.push(b);
                }
                let head = String::from_utf8(head).unwrap();
                let host = head.split_whitespace().nth(1).unwrap().rsplit_once(':').unwrap().0.to_string();
                seen.lock().unwrap().push(head);
                if !allow.contains(&host.as_str()) {
                    let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n").await;
                    return;
                }
                let Ok(mut vendor) = tokio::net::TcpStream::connect(("127.0.0.1", upstream)).await else { return };
                if client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_err() {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut vendor).await;
            });
        }
    });
    (url, heads)
}

fn broker(mock: &Mock, proxy: &str, grant: EgressGrant) -> Broker {
    let cfg = BrokerConfig {
        resolver: ScriptedResolver::public_for_all(),
        dialer: Arc::new(ProxyDialer::new(proxy, KEY).unwrap()),
        egress_grant: Some(grant),
        extra_roots: vec![mock.pki.ca_der.clone()],
        ..Default::default()
    };
    Broker::new(cfg, None).unwrap()
}

fn policy() -> HostPolicy {
    let rules: Vec<AllowRule> = serde_json::from_value(json!([{"host": "{{config.base_url}}", "host_suffixes": [".okta.com"]}])).unwrap();
    let scope = Scope { config: json!({"base_url": "https://acme.okta.com"}), ..Default::default() };
    HostPolicy::compile(&rules, &scope).unwrap()
}

fn get(url: &str) -> OutboundRequest {
    OutboundRequest {
        method: http::Method::GET,
        url: url::Url::parse(url).unwrap(),
        headers: vec![("Authorization".into(), "SSWS vendor-secret-token".into())],
        body: Default::default(),
    }
}

const CAPS: BodyCaps = BodyCaps { max_response_bytes: 1 << 20, max_decompressed_bytes: 1 << 20 };

fn grant() -> EgressGrant {
    EgressGrant { tenant: uuid::Uuid::new_v4(), connection: uuid::Uuid::new_v4(), revision: 4, purpose: GrantPurpose::Soar }
}

#[tokio::test]
async fn allowed_host_tunnels_end_to_end_and_the_proxy_sees_no_vendor_bytes() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({"id": "00u1"}))), false).await;
    let (proxy, heads) = fake_proxy(mock.port, &["acme.okta.com"]).await;
    let grant = grant();
    let broker = broker(&mock, &proxy, grant);
    for _ in 0..2 {
        let response = broker.send_once(&get("https://acme.okta.com/api/v1/users/00u1"), &policy(), CAPS).await.unwrap();
        assert_eq!(response.status, 200);
    }
    // One tunnel, reused for the second exchange of the run.
    let heads = heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1);
    assert!(heads[0].starts_with("CONNECT acme.okta.com:443 HTTP/1.1\r\n"));
    assert!(heads[0].contains(&format!("X-Nano-Tenant: {}\r\n", grant.tenant)));
    assert!(!heads[0].contains("vendor-secret-token") && !heads[0].contains("/api/v1"));
    // The vendor got the request (and its credential) inside TLS.
    let requests = mock.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].headers.get("authorization").map(String::as_str), Some("SSWS vendor-secret-token"));
}

#[tokio::test]
async fn a_proxy_denial_is_a_typed_refusal_before_send() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({}))), false).await;
    let (proxy, _) = fake_proxy(mock.port, &[]).await;
    let error = broker(&mock, &proxy, grant()).send_once(&get("https://acme.okta.com/api/v1/users/00u1"), &policy(), CAPS).await.unwrap_err();
    assert!(matches!(error, BrokerError::EgressProxy(ProxyRefusal::Denied)), "{error}");
    assert!(mock.requests().is_empty());
}

#[tokio::test]
async fn proxy_down_is_unreachable_and_never_direct() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({}))), false).await;
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let error = broker(&mock, &format!("http://{closed}"), grant())
        .send_once(&get("https://acme.okta.com/api/v1/users/00u1"), &policy(), CAPS)
        .await
        .unwrap_err();
    assert!(matches!(error, BrokerError::EgressProxy(ProxyRefusal::Unreachable)), "{error}");
    assert!(mock.requests().is_empty());
}

#[tokio::test]
async fn no_grant_is_refused_without_contacting_the_proxy() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({}))), false).await;
    let (proxy, heads) = fake_proxy(mock.port, &["acme.okta.com"]).await;
    let cfg = BrokerConfig {
        resolver: ScriptedResolver::public_for_all(),
        dialer: Arc::new(ProxyDialer::new(&proxy, KEY).unwrap()),
        extra_roots: vec![mock.pki.ca_der.clone()],
        ..Default::default()
    };
    let error = Broker::new(cfg, None).unwrap().send_once(&get("https://acme.okta.com/api/v1/users/00u1"), &policy(), CAPS).await.unwrap_err();
    assert!(matches!(error, BrokerError::EgressProxy(ProxyRefusal::NoGrant)), "{error}");
    assert!(heads.lock().unwrap().is_empty());
}
