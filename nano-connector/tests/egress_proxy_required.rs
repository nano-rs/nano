//! NAN-5441: with "proxy required" on (`NANO_EGRESS_PROXY_REQUIRED`) and no
//! proxy URL, the connector never dials a public address directly: the
//! dialer refuses with `ProxyRefusal::Required` before any connection. The
//! settings are scoped per test (`with_egress_settings`), never the process
//! env, so these run safely alongside the direct-path tests.
mod common;

use std::sync::Arc;

use common::*;
use nano_connector::broker::{BodyCaps, Broker, BrokerConfig, BrokerError, DialTarget, Dialer, DirectDialer, OutboundRequest};
use nano_connector::egress::{self, ProxyRefusal};
use nano_connector::policy::HostPolicy;
use nano_connector::spec::AllowRule;
use nano_connector::template::Scope;
use nanosiem_core::egress_proxy::{with_egress_settings, EgressSettings};
use serde_json::json;

fn required() -> EgressSettings {
    EgressSettings { required: true, ..EgressSettings::default() }
}

fn policy() -> HostPolicy {
    let rules: Vec<AllowRule> = serde_json::from_value(json!([{"host": "{{config.base_url}}", "host_suffixes": [".okta.com"]}])).unwrap();
    let scope = Scope { config: json!({"base_url": "https://acme.okta.com"}), ..Default::default() };
    HostPolicy::compile(&rules, &scope).unwrap()
}

fn get() -> OutboundRequest {
    OutboundRequest {
        method: http::Method::GET,
        url: url::Url::parse("https://acme.okta.com/api/v1/users").unwrap(),
        headers: vec![],
        body: Default::default(),
    }
}

const CAPS: BodyCaps = BodyCaps { max_response_bytes: 1 << 20, max_decompressed_bytes: 1 << 20 };

#[tokio::test]
async fn no_proxy_url_under_required_refuses_every_public_dial() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({}))), false).await;
    let dialer = egress::dialer_from_values_required(None, None, true).unwrap();
    let cfg = BrokerConfig {
        resolver: ScriptedResolver::public_for_all(),
        dialer,
        extra_roots: vec![mock.pki.ca_der.clone()],
        ..Default::default()
    };
    let error = Broker::new(cfg, None).unwrap().send_once(&get(), &policy(), CAPS).await.unwrap_err();
    assert!(matches!(error, BrokerError::EgressProxy(ProxyRefusal::Required)), "{error}");
    assert!(mock.requests().is_empty());
}

#[tokio::test]
async fn env_reading_helpers_honor_a_required_scope() {
    // `dialer_from_values` (connector runner, engine, SOAR, TI providers,
    // the enrichment sandbox all build through it) reads "required".
    let dialer = with_egress_settings(required(), async { egress::dialer_from_values(None, None).unwrap() }).await;
    let target = DialTarget { host: "acme.okta.com", addr: format!("{PUBLIC_IP}:443").parse().unwrap() };
    let err = dialer.dial(target).await.unwrap_err();
    assert_eq!(ProxyRefusal::from_io(&err), Some(ProxyRefusal::Required));
}

#[tokio::test]
async fn direct_dialer_refuses_public_under_required_however_configured() {
    let target = DialTarget { host: "acme.okta.com", addr: format!("{PUBLIC_IP}:443").parse().unwrap() };
    let err = with_egress_settings(required(), DirectDialer.dial(target)).await.unwrap_err();
    assert_eq!(ProxyRefusal::from_io(&err), Some(ProxyRefusal::Required));
}

#[tokio::test]
async fn internal_addresses_stay_direct_under_required() {
    // SOAR self-managed hosts and internal SMTP relays: an internet egress
    // proxy cannot reach them, and the broker's policy already admitted them.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let target = DialTarget { host: "jira.corp.internal", addr };
    assert!(with_egress_settings(required(), DirectDialer.dial(target)).await.is_ok());
    let dialer = egress::dialer_from_values_required(None, None, true).unwrap();
    assert!(dialer.dial(DialTarget { host: "jira.corp.internal", addr }).await.is_ok());
}

#[tokio::test]
async fn defaults_are_unchanged() {
    let dialer = egress::dialer_from_values_required(None, None, false).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    assert!(dialer.dial(DialTarget { host: "x.example.com", addr }).await.is_ok());
}
