//! NAN-4914: the broker tunnels through an operator-configured forward
//! proxy (`CONNECTOR_EGRESS_PROXY_URL`). A fake
//! proxy (allow-listed by exact CONNECT authority) splices allowed tunnels
//! to the TLS mock; TLS and every vendor header stay end to end, the tunnel
//! targets the pinned address (no re-resolution at the proxy), and every
//! failure is fail-closed (never direct).
mod common;

use std::sync::Arc;

use common::*;
use nano_connector::broker::{BodyCaps, Broker, BrokerConfig, BrokerError, DirectDialer, OutboundRequest};
use nano_connector::egress::{self, ProxyConfigError, ProxyDialer, ProxyRefusal};
use nano_connector::policy::HostPolicy;
use nano_connector::spec::AllowRule;
use nano_connector::template::Scope;
use serde_json::json;

/// The CONNECT authority the broker must use: the pinned address.
fn pinned_authority() -> String {
    format!("{PUBLIC_IP}:443")
}

fn broker_via(mock: &Mock, dialer: ProxyDialer, resolver: Arc<ScriptedResolver>) -> Broker {
    let cfg = BrokerConfig {
        resolver,
        dialer: Arc::new(dialer),
        extra_roots: vec![mock.pki.ca_der.clone()],
        ..Default::default()
    };
    Broker::new(cfg, None).unwrap()
}

fn broker(mock: &Mock, proxy: &str) -> Broker {
    broker_via(mock, ProxyDialer::new(proxy).unwrap(), ScriptedResolver::public_for_all())
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
const URL: &str = "https://acme.okta.com/api/v1/users/00u1";

#[tokio::test]
async fn tunnel_targets_the_pinned_address_and_the_proxy_sees_no_vendor_bytes() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({"id": "00u1"}))), false).await;
    let (proxy, heads) = fake_proxy(mock.port, vec![pinned_authority()]).await;
    let broker = broker(&mock, &proxy);
    for _ in 0..2 {
        let response = broker.send_once(&get(URL), &policy(), CAPS).await.unwrap();
        assert_eq!(response.status, 200);
    }
    // One tunnel, reused for the second exchange of the run.
    let heads = heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1);
    assert!(heads[0].starts_with(&format!("CONNECT {} HTTP/1.1\r\n", pinned_authority())), "{}", heads[0]);
    // The proxy never learns the host name (so it cannot re-resolve it),
    // the path, or the credential.
    assert!(!heads[0].contains("acme.okta.com"), "{}", heads[0]);
    assert!(!heads[0].contains("vendor-secret-token") && !heads[0].contains("/api/v1"));
    assert!(!heads[0].contains("Proxy-Authorization"));
    // The vendor got the request (and its credential) inside TLS, with SNI /
    // Host = the vendor host.
    let requests = mock.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].headers.get("authorization").map(String::as_str), Some("SSWS vendor-secret-token"));
    assert_eq!(requests[0].headers.get("host").map(String::as_str), Some("acme.okta.com"));
}

#[tokio::test]
async fn proxy_credentials_ride_on_connect_only_and_never_in_debug() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({}))), false).await;
    let (proxy, heads) = fake_proxy(mock.port, vec![pinned_authority()]).await;
    let with_auth = proxy.replace("http://", "http://svc%40corp:p%3Ass@");
    let dialer = ProxyDialer::new(&with_auth).unwrap();
    let debug = format!("{dialer:?}");
    assert!(!debug.contains("p:ss") && !debug.contains("svc@corp") && debug.contains("authenticated: true"), "{debug}");
    broker_via(&mock, dialer, ScriptedResolver::public_for_all()).send_once(&get(URL), &policy(), CAPS).await.unwrap();
    let head = heads.lock().unwrap()[0].clone();
    // base64("svc@corp:p:ss")
    assert!(head.contains("Proxy-Authorization: Basic c3ZjQGNvcnA6cDpzcw==\r\n"), "{head}");
    assert!(mock.requests()[0].headers.get("proxy-authorization").is_none(), "proxy credential leaked to the vendor");
}

#[tokio::test]
async fn a_proxy_denial_is_a_typed_refusal_before_send() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({}))), false).await;
    let (proxy, _) = fake_proxy(mock.port, vec![]).await;
    let error = broker(&mock, &proxy).send_once(&get(URL), &policy(), CAPS).await.unwrap_err();
    assert!(matches!(error, BrokerError::EgressProxy(ProxyRefusal::Denied)), "{error}");
    assert!(mock.requests().is_empty());
}

#[tokio::test]
async fn proxy_down_is_unreachable_and_never_direct() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({}))), false).await;
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let error = broker(&mock, &format!("http://{closed}")).send_once(&get(URL), &policy(), CAPS).await.unwrap_err();
    assert!(matches!(error, BrokerError::EgressProxy(ProxyRefusal::Unreachable)), "{error}");
    assert!(mock.requests().is_empty());
}

#[tokio::test]
async fn in_process_checks_run_before_the_proxy_is_contacted() {
    // A private DNS answer is refused by the broker itself: the proxy never
    // sees a CONNECT, whatever its own policy would have done.
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({}))), false).await;
    let (proxy, heads) = fake_proxy(mock.port, vec!["10.0.0.5:443".into(), "169.254.169.254:443".into()]).await;
    for answer in ["10.0.0.5", "169.254.169.254"] {
        let resolver = ScriptedResolver::public_for_all();
        resolver.set("acme.okta.com", vec![vec![answer]]);
        let error = broker_via(&mock, ProxyDialer::new(&proxy).unwrap(), resolver).send_once(&get(URL), &policy(), CAPS).await.unwrap_err();
        assert!(matches!(error, BrokerError::DnsBlocked { .. }), "{answer}: {error}");
    }
    // A host outside the allowlist never reaches DNS, let alone the proxy.
    let error = broker(&mock, &proxy).send_once(&get("https://evil.example.com/x"), &policy(), CAPS).await.unwrap_err();
    assert!(matches!(error, BrokerError::Policy(_)), "{error}");
    assert!(heads.lock().unwrap().is_empty());
    assert!(mock.requests().is_empty());
}

#[test]
fn proxy_url_must_be_a_plain_http_origin() {
    for ok in ["http://proxy.corp.example:3128", "http://10.0.0.1:8080", "http://[fd00::1]:3128", "http://user:pw@proxy:3128", "http://proxy"] {
        assert!(ProxyDialer::new(ok).is_ok(), "{ok}");
    }
    for bad in [
        "https://proxy:3128",
        "socks5://proxy:1080",
        "http://proxy:3128/x",
        "http://proxy:3128?q",
        "http://proxy:3128#f",
        "proxy:3128",
        "",
        "http://proxy:3128\r\nX: y",
        "http://us%0der:pw@proxy:3128",
    ] {
        assert_eq!(ProxyDialer::new(bad).unwrap_err(), ProxyConfigError::Url, "{bad}");
    }
}

#[test]
fn env_selection_is_direct_when_unset_and_an_error_when_invalid() {
    // Unset or blank: direct (the dialer is the broker's default).
    for v in [None, Some(""), Some("   ")] {
        assert!(egress::dialer_from_value(v).is_ok(), "{v:?}");
    }
    // An invalid setting is a startup error, never a silent direct fallback.
    assert_eq!(egress::dialer_from_value(Some("https://proxy:3128")).err(), Some(ProxyConfigError::Url));
    assert!(egress::dialer_from_value(Some("http://proxy:3128")).is_ok());
    assert_eq!(egress::CONNECTOR_PROXY_ENV, "CONNECTOR_EGRESS_PROXY_URL");
    let mut cfg = BrokerConfig { dialer: Arc::new(DirectDialer), ..Default::default() };
    assert!(egress::configure_from_env(&mut cfg, "NANO_CONNECTOR_TEST_UNSET_PROXY_VAR").is_ok());
}

#[tokio::test]
async fn a_refusing_dialer_never_connects() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({}))), false).await;
    let cfg = BrokerConfig {
        resolver: ScriptedResolver::public_for_all(),
        dialer: Arc::new(egress::RefusingDialer),
        extra_roots: vec![mock.pki.ca_der.clone()],
        ..Default::default()
    };
    let error = Broker::new(cfg, None).unwrap().send_once(&get(URL), &policy(), CAPS).await.unwrap_err();
    assert!(matches!(error, BrokerError::EgressProxy(ProxyRefusal::Misconfigured)), "{error}");
    assert!(mock.requests().is_empty());
}
