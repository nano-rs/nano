// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5286: the official Shodan lookup answers domains in two steps
//! (`/dns/resolve`, then `/shodan/host/<ip>`), against a fake Shodan over the
//! production TLS broker. The key rides in the query string of both requests
//! and must never come back out: not in the answer, not in error text, not in
//! the engine's logs.
mod common;

use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use common::*;
use nano_connector::lookup::{execute, official_spec, Artifact, ArtifactType, LookupOutcome, Verdict, RESOLVED_SUMMARY_KEY};
use serde_json::{json, Value};

const KEY: &str = "shodan-SECRET-key-5286-0123456789";
const DOMAIN: &str = "shop.example.org";
const ADDR: &str = "185.220.101.7";

/// A tracing writer that keeps everything the engine logs during a lookup.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Fake Shodan: `resolve` answers `/dns/resolve`, `host` answers `/shodan/host/*`.
/// Every request must carry the key; anything else is a 418.
async fn shodan(resolve: (u16, Value), host: (u16, Value)) -> Mock {
    start_mock(
        Arc::new(move |r: &MockReq| {
            assert_eq!(r.host.split(':').next(), Some("api.shodan.io"));
            assert_eq!(r.query.get("key").map(String::as_str), Some(KEY), "every Shodan request carries the key");
            if r.path == "/dns/resolve" {
                assert_eq!(r.query.get("hostnames").map(String::as_str), Some(DOMAIN));
                return MockResp::status(resolve.0, resolve.1.clone());
            }
            if r.path.starts_with("/shodan/host/") {
                return MockResp::status(host.0, host.1.clone());
            }
            MockResp::status(418, json!({"error": "unexpected path"}))
        }),
        false,
    )
    .await
}

async fn lookup(mock: &Mock) -> (LookupOutcome, String) {
    let h = harness(mock);
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE).with_writer(captured.clone()).with_ansi(false).finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let a = Artifact::parse(DOMAIN, None).unwrap();
    assert_eq!(a.kind, ArtifactType::Domain);
    let creds = HashMap::from([("API_KEY".to_string(), KEY.to_string())]);
    let out = execute(&h.cfg, &official_spec("shodan").unwrap(), &a, creds, None).await;
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    (out, logs)
}

fn assert_clean(what: &str, s: &str) {
    assert!(!s.contains(KEY), "{what} carries the Shodan key: {s}");
}

fn paths(mock: &Mock) -> Vec<String> {
    mock.requests().iter().map(|r| r.path.clone()).collect()
}

#[test]
fn shodan_supports_domains_through_its_pivot() {
    let spec = official_spec("shodan").unwrap();
    assert!(spec.supports(ArtifactType::Domain));
    assert_eq!(spec.supported_types(), vec![ArtifactType::Domain, ArtifactType::Ip]);
}

#[tokio::test]
async fn a_domain_is_resolved_then_its_address_is_looked_up() {
    let mock = shodan(
        (200, json!({ DOMAIN: ADDR })),
        (200, json!({"ip_str": ADDR, "org": "Example Hosting", "ports": [22, 443], "vulns": ["CVE-2024-3400"], "tags": ["cloud"]})),
    )
    .await;
    let (out, logs) = lookup(&mock).await;
    let LookupOutcome::Answered(v) = &out else { panic!("{out:?}") };
    assert_eq!((v.verdict, v.score), (Verdict::Suspicious, Some(40)));
    assert_eq!(v.summary[RESOLVED_SUMMARY_KEY], ADDR);
    assert_eq!(v.summary["org"], "Example Hosting");
    assert_eq!(v.link.as_deref(), Some(format!("https://www.shodan.io/host/{ADDR}").as_str()));
    assert_eq!(paths(&mock), vec!["/dns/resolve".to_string(), format!("/shodan/host/{ADDR}")]);
    assert_eq!(mock.requests()[1].query.get("minify").map(String::as_str), Some("true"));
    assert_clean("answer", &format!("{out:?}"));
    assert_clean("logs", &logs);
}

#[tokio::test]
async fn a_domain_that_does_not_resolve_is_not_found_without_a_host_lookup() {
    let mock = shodan((200, json!({ DOMAIN: null })), (500, json!({}))).await;
    let (out, logs) = lookup(&mock).await;
    let LookupOutcome::Answered(v) = &out else { panic!("{out:?}") };
    assert_eq!(v.verdict, Verdict::NotFound);
    assert_eq!(v.link.as_deref(), Some(format!("https://www.shodan.io/domain/{DOMAIN}").as_str()));
    assert_eq!(paths(&mock), vec!["/dns/resolve".to_string()]);
    assert_clean("logs", &logs);
}

#[tokio::test]
async fn an_internal_or_malformed_resolution_is_never_looked_up() {
    for resolved in [json!("10.0.0.5"), json!("127.0.0.1"), json!("169.254.169.254"), json!("1.2.3.4/../../account"), json!({"ip": ADDR})] {
        let mock = shodan((200, json!({ DOMAIN: resolved.clone() })), (200, json!({"ip_str": "x"}))).await;
        let (out, _) = lookup(&mock).await;
        let LookupOutcome::Answered(v) = &out else { panic!("{resolved}: {out:?}") };
        assert_eq!(v.verdict, Verdict::NotFound, "{resolved}");
        assert_eq!(paths(&mock), vec!["/dns/resolve".to_string()], "{resolved}");
    }
    // Another name's answer is not this domain's.
    let mock = shodan((200, json!({ "other.example.org": ADDR })), (200, json!({}))).await;
    let (out, _) = lookup(&mock).await;
    assert!(matches!(&out, LookupOutcome::Answered(v) if v.verdict == Verdict::NotFound), "{out:?}");
    assert_eq!(paths(&mock).len(), 1);
}

#[tokio::test]
async fn an_address_shodan_has_no_data_for_is_not_found_but_keeps_the_resolution() {
    let mock = shodan((200, json!({ DOMAIN: ADDR })), (404, json!({"error": "No information available for that IP."}))).await;
    let (out, _) = lookup(&mock).await;
    let LookupOutcome::Answered(v) = &out else { panic!("{out:?}") };
    assert_eq!(v.verdict, Verdict::NotFound);
    assert_eq!(v.summary[RESOLVED_SUMMARY_KEY], ADDR);
    assert_eq!(paths(&mock).len(), 2);
}

#[tokio::test]
async fn failures_in_either_step_never_carry_the_key() {
    let echo = json!({"error": format!("bad request for ?key={KEY}")});
    for (resolve, host, want) in [
        ((401, json!({"error": format!("Invalid API key {KEY}")})), (200, json!({})), "auth"),
        ((429, echo.clone()), (200, json!({})), "quota"),
        ((500, echo.clone()), (200, json!({})), "failed"),
        ((200, json!({ DOMAIN: ADDR })), (403, echo.clone()), "auth"),
        ((200, json!({ DOMAIN: ADDR })), (502, json!({"error": KEY})), "failed"),
    ] {
        let mock = shodan(resolve.clone(), host.clone()).await;
        let (out, logs) = lookup(&mock).await;
        let got = match &out {
            LookupOutcome::AuthFailed => "auth",
            LookupOutcome::QuotaExhausted { .. } => "quota",
            LookupOutcome::Failed(_) => "failed",
            other => panic!("{resolve:?}/{host:?}: {other:?}"),
        };
        assert_eq!(got, want, "{resolve:?}/{host:?}");
        assert_clean("outcome", &format!("{out:?}"));
        assert_clean("logs", &logs);
    }
}
