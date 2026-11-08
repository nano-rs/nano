//! NAN-4918: egress proxy mode. `pinned_ip` (default) tunnels to the
//! broker's verified pinned address; the opt-in `hostname` mode sends
//! `CONNECT host:port` and lets the proxy resolve and enforce egress, while
//! the connector still applies its allowlist / deny list and refuses literal
//! IPs. A mock proxy records the CONNECT target in each mode.
mod common;

use std::sync::Arc;

use common::*;
use nano_connector::broker::{BodyCaps, Broker, BrokerConfig, BrokerError, Dialer, OutboundRequest};
use nano_connector::egress::{self, ProxyConfigError, ProxyDialer, ProxyMode, ProxyRefusal};
use nano_connector::policy::{EgressDeny, HostPolicy};
use nano_connector::spec::AllowRule;
use nano_connector::template::Scope;
use serde_json::json;

const CAPS: BodyCaps = BodyCaps { max_response_bytes: 1 << 20, max_decompressed_bytes: 1 << 20 };
const URL: &str = "https://acme.okta.com/api/v1/users/00u1";

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

fn broker(mock: &Mock, dialer: Arc<dyn Dialer>, resolver: Arc<ScriptedResolver>) -> Broker {
    let cfg = BrokerConfig {
        resolver,
        dialer,
        extra_roots: vec![mock.pki.ca_der.clone()],
        ..Default::default()
    };
    Broker::new(cfg, None).unwrap()
}

#[tokio::test]
async fn pinned_ip_mode_connects_to_the_verified_pinned_address() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({"ok": true}))), false).await;
    let pinned = format!("{PUBLIC_IP}:443");
    let (proxy, heads) = fake_proxy(mock.port, vec![pinned.clone()]).await;
    let resolver = ScriptedResolver::public_for_all();
    let dialer = egress::dialer_from_values(Some(&proxy), Some("pinned_ip")).unwrap();
    let response = broker(&mock, dialer, resolver.clone()).send_once(&get(URL), &policy(), CAPS).await.unwrap();
    assert_eq!(response.status, 200);
    let heads = heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1);
    assert!(heads[0].starts_with(&format!("CONNECT {pinned} HTTP/1.1\r\nHost: {pinned}\r\n")), "{}", heads[0]);
    assert!(!heads[0].contains("acme.okta.com"), "{}", heads[0]);
    // The broker resolved and pinned the name itself.
    assert_eq!(resolver.calls_for("acme.okta.com"), 1);
}

#[tokio::test]
async fn hostname_mode_connects_to_host_and_port_and_never_resolves_locally() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({"ok": true}))), false).await;
    let (proxy, heads) = fake_proxy(mock.port, vec!["acme.okta.com:443".into()]).await;
    let resolver = ScriptedResolver::public_for_all();
    // A private answer would be refused in pinned_ip mode; in hostname mode
    // the broker never asks, the proxy resolves.
    resolver.set("acme.okta.com", vec![vec!["10.0.0.5"]]);
    let dialer = egress::dialer_from_values(Some(&proxy), Some("hostname")).unwrap();
    let b = broker(&mock, dialer, resolver.clone());
    for _ in 0..2 {
        assert_eq!(b.send_once(&get(URL), &policy(), CAPS).await.unwrap().status, 200);
    }
    let heads = heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1, "one tunnel, reused within the run");
    assert!(
        heads[0].starts_with("CONNECT acme.okta.com:443 HTTP/1.1\r\nHost: acme.okta.com:443\r\n"),
        "{}",
        heads[0]
    );
    // TLS stays end to end: the proxy sees no path or credential.
    assert!(!heads[0].contains("/api/v1") && !heads[0].contains("vendor-secret-token"), "{}", heads[0]);
    assert_eq!(resolver.calls_for("acme.okta.com"), 0, "hostname mode must not resolve locally");
    let requests = mock.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].headers.get("host").map(String::as_str), Some("acme.okta.com"));
}

#[tokio::test]
async fn hostname_mode_still_applies_the_allowlist_deny_list_and_literal_ip_refusal() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({}))), false).await;
    let (proxy, heads) = fake_proxy(mock.port, vec![
        "evil.example.com:443".into(),
        "10.0.0.5:443".into(),
        "169.254.169.254:443".into(),
        "acme.okta.com:443".into(),
    ])
    .await;
    let dialer = egress::dialer_from_values(Some(&proxy), Some("hostname")).unwrap();
    let b = broker(&mock, dialer, ScriptedResolver::public_for_all());
    // Host outside the spec allowlist.
    let error = b.send_once(&get("https://evil.example.com/x"), &policy(), CAPS).await.unwrap_err();
    assert!(matches!(error, BrokerError::Policy(_)), "{error}");
    // Literal IPs, private or public, never reach the proxy.
    for literal in ["https://10.0.0.5/x", "https://169.254.169.254/latest", "https://[fd00::1]/x", "https://93.184.215.14/x"] {
        let error = b.send_once(&get(literal), &policy(), CAPS).await.unwrap_err();
        assert!(matches!(error, BrokerError::Policy(_)), "{literal}: {error}");
    }
    // The operator deny list applies to the host name.
    // (A second allowed host keeps the policy compilable with the deny.)
    let rules: Vec<AllowRule> = serde_json::from_value(json!([
        {"host": "{{config.base_url}}", "host_suffixes": [".okta.com"]},
        {"host": "status.okta.com"}
    ]))
    .unwrap();
    let scope = Scope { config: json!({"base_url": "https://acme.okta.com"}), ..Default::default() };
    let deny = EgressDeny::parse(&["acme.okta.com"], &[]).unwrap();
    let denied = HostPolicy::compile(&rules, &scope).unwrap().with_deny(deny).unwrap();
    let error = b.send_once(&get(URL), &denied, CAPS).await.unwrap_err();
    assert!(matches!(error, BrokerError::Policy(_)), "{error}");
    assert!(heads.lock().unwrap().is_empty(), "no CONNECT may be sent");
    assert!(mock.requests().is_empty());
}

#[tokio::test]
async fn hostname_mode_proxy_denial_is_fail_closed() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({}))), false).await;
    // The proxy's own hostname policy denies the destination.
    let (proxy, heads) = fake_proxy(mock.port, vec![]).await;
    let dialer = egress::dialer_from_values(Some(&proxy), Some("hostname")).unwrap();
    let error = broker(&mock, dialer, ScriptedResolver::public_for_all())
        .send_once(&get(URL), &policy(), CAPS)
        .await
        .unwrap_err();
    assert!(matches!(error, BrokerError::EgressProxy(ProxyRefusal::Denied)), "{error}");
    assert_eq!(heads.lock().unwrap().len(), 1);
    assert!(mock.requests().is_empty());
}

#[test]
fn mode_parsing_defaults_to_pinned_ip_and_fails_closed_on_unknown_values() {
    for v in [None, Some(""), Some("  "), Some("pinned_ip"), Some(" pinned_ip ")] {
        assert_eq!(ProxyMode::parse(v), Ok(ProxyMode::PinnedIp), "{v:?}");
    }
    assert_eq!(ProxyMode::parse(Some("hostname")), Ok(ProxyMode::Hostname));
    for bad in ["Hostname", "HOSTNAME", "host", "pinned", "ip", "direct", "hostname,pinned_ip"] {
        assert_eq!(ProxyMode::parse(Some(bad)), Err(ProxyConfigError::Mode), "{bad}");
        // Even without a proxy URL an unknown mode is a configuration error.
        assert_eq!(egress::dialer_from_values(None, Some(bad)).err(), Some(ProxyConfigError::Mode), "{bad}");
        assert_eq!(egress::dialer_from_values(Some("http://proxy:3128"), Some(bad)).err(), Some(ProxyConfigError::Mode));
    }
    assert_eq!(ProxyDialer::new("http://proxy:3128").unwrap().mode(), ProxyMode::PinnedIp);
    assert_eq!(ProxyDialer::with_mode("http://proxy:3128", ProxyMode::Hostname).unwrap().mode(), ProxyMode::Hostname);
    assert_eq!(egress::CONNECTOR_PROXY_MODE_ENV, "CONNECTOR_EGRESS_PROXY_MODE");
    // The mode alone never routes anything: no URL is a direct dialer, which
    // always resolves and pins.
    let direct = egress::dialer_from_values(None, Some("hostname")).unwrap();
    assert!(!direct.resolves_remotely("acme.okta.com"));
    let hostname = egress::dialer_from_values(Some("http://proxy:3128"), Some("hostname")).unwrap();
    assert!(hostname.resolves_remotely("acme.okta.com"));
    let pinned = egress::dialer_from_values(Some("http://proxy:3128"), None).unwrap();
    assert!(!pinned.resolves_remotely("acme.okta.com"));
}
