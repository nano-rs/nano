//! NAN-4914 (codex P1): the mTLS client identity is bound to the request's
//! authentication origin. A redirect to a second allowlisted host handshakes
//! with NO client certificate, so the tenant is never authenticated to an
//! origin it did not ask for (header/query auth was already dropped there).
mod common;

use std::sync::Arc;

use common::*;
use nano_connector::broker::{BodyCaps, Broker, BrokerConfig, BrokerError, OutboundRequest};
use nano_connector::engine::{EngineError, RunInput};
use nano_connector::policy::HostPolicy;
use nano_connector::spec::AllowRule;
use nano_connector::template::Scope;
use serde_json::json;

fn redirecting() -> Handler {
    Arc::new(|r: &MockReq| {
        if r.host == "mtls.example.com" {
            MockResp::status(307, json!({})).header("location", "https://api.example.com/v1/events")
        } else {
            MockResp::json(json!({"events": [{"ok": true}]}))
        }
    })
}

const SPEC: &str = r#"
version: 1
name: mtls_redirect
kind: collector
allow: [{ host: mtls.example.com }, { host: api.example.com }]
auth: { type: mtls, cert_credential: CERT, key_credential: KEY }
rate_limit: { max_retries_5xx: 0 }
streams:
  - id: s
    request: { url: "https://mtls.example.com/v1/events" }
    response: { events_path: events }
"#;

#[tokio::test]
async fn a_redirect_to_another_allowed_host_does_not_present_the_client_certificate() {
    // The mock requires a client certificate on EVERY connection: if the hop
    // to api.example.com presented the tenant's certificate it would succeed.
    let mock = start_mock(redirecting(), true).await;
    let h = harness(&mock);
    let input = RunInput { credentials: creds(&[("CERT", &mock.pki.client_cert_pem), ("KEY", &mock.pki.client_key_pem)]), ..Default::default() };
    let r = run(&h, &spec(SPEC), input).await;
    let err = r.out.expect_err("the hop must not authenticate with the tenant's certificate");
    // TLS 1.3 reports the server's certificate refusal on the first read.
    assert!(matches!(err, EngineError::Broker(BrokerError::Tls(..) | BrokerError::Http(_))), "{err}");
    let reqs = mock.requests();
    assert!(!reqs.is_empty() && reqs.iter().all(|q| q.host == "mtls.example.com"), "{reqs:?}");
    assert!(reqs.iter().all(|q| q.host != "api.example.com"), "the redirect target received a request");
}

#[tokio::test]
async fn the_origin_still_gets_the_certificate_and_anonymous_hops_work() {
    // Origin requires mTLS; a no-client-auth mock stands in for the hop.
    let mtls = start_mock(Arc::new(|_r| MockResp::json(json!({"events": [{"ok": true}]}))), true).await;
    let anon = start_mock(Arc::new(|_r| MockResp::json(json!({"ok": true}))), false).await;
    let policy = || {
        let rules: Vec<AllowRule> = serde_json::from_value(json!([{"host": "mtls.example.com"}])).unwrap();
        HostPolicy::compile(&rules, &Scope::default()).unwrap()
    };
    let identity = || nano_connector::broker::ClientIdentity::from_pem(&mtls.pki.client_cert_pem, &mtls.pki.client_key_pem).unwrap();
    let caps = BodyCaps { max_response_bytes: 1 << 20, max_decompressed_bytes: 1 << 20 };
    let req = OutboundRequest { method: http::Method::GET, url: url::Url::parse("https://mtls.example.com/v1/events").unwrap(), headers: vec![], body: Default::default() };
    let broker = |m: &Mock| {
        let cfg = BrokerConfig {
            resolver: ScriptedResolver::public_for_all(),
            dialer: Arc::new(MockDialer { port: m.port, dialed: Default::default() }),
            extra_roots: vec![m.pki.ca_der.clone()],
            ..Default::default()
        };
        Broker::new(cfg, Some(identity())).unwrap()
    };
    // The origin exchange presents the identity.
    assert_eq!(broker(&mtls).send_once(&req, &policy(), caps).await.unwrap().status, 200);
    // The same broker, asked for an anonymous exchange, does not: the mTLS
    // server refuses the handshake...
    let refused = |r: Result<_, BrokerError>| matches!(r, Err(BrokerError::Tls(..) | BrokerError::Http(_)));
    let b = broker(&mtls);
    assert!(refused(b.send_once_without_client_auth(&req, &policy(), caps).await));
    // ...and a pooled mTLS connection is never reused for it.
    assert_eq!(b.send_once(&req, &policy(), caps).await.unwrap().status, 200);
    assert!(refused(b.send_once_without_client_auth(&req, &policy(), caps).await));
    assert_eq!(mtls.requests().len(), 2, "only the two certificate-bearing exchanges reached the server");
    // A server that does not ask for a certificate accepts the anonymous hop.
    assert_eq!(broker(&anon).send_once_without_client_auth(&req, &policy(), caps).await.unwrap().status, 200);
}
