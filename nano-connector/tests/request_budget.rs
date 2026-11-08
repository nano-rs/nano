//! NAN-4914 (codex P2-7): every network exchange (redirect hops and
//! transport retries included) consumes `max_requests` and observes
//! `min_interval_ms`. Before the fix a redirect chain cost one request and
//! was sent in a burst.
mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use nano_connector::engine::{EngineError, RunInput};
use serde_json::json;

/// /hop/N redirects to /hop/N+1 up to /hop/3, which answers.
fn chain() -> Handler {
    Arc::new(|r: &MockReq| {
        let n: u32 = r.path.trim_start_matches("/v1/hop/").parse().unwrap_or(0);
        if n < 3 {
            MockResp::status(302, json!({})).header("location", &format!("/v1/hop/{}", n + 1))
        } else {
            MockResp::json(json!({"events": [{"id": "e1"}]}))
        }
    })
}

fn spec_yaml(limits: &str, rate: &str) -> String {
    format!(
        "version: 1\nname: t\nkind: collector\nallow: [{{ host: api.example.com }}]\n{limits}{rate}streams:\n  - id: s\n    request: {{ url: \"https://api.example.com/v1/hop/0\" }}\n    response: {{ events_path: events }}\n    ingest_id: {{ fields: [id] }}\n"
    )
}

#[tokio::test]
async fn redirect_hops_count_against_max_requests() {
    let mock = start_mock(chain(), false).await;
    let h = harness(&mock);
    // Four exchanges (0 -> 1 -> 2 -> 3); a cap of 3 must stop the chain.
    let r = run(&h, &spec(&spec_yaml("limits: { max_requests: 3, max_redirects: 10 }\n", "")), RunInput::default()).await;
    assert!(matches!(r.out, Err(EngineError::Cap(ref m)) if m.contains("3 requests")), "{:?}", r.out.as_ref().err());
    assert_eq!(mock.requests().len(), 3, "the 4th hop must not be sent");
    // With room for all four, the run reports four requests, not one.
    let mock = start_mock(chain(), false).await;
    let h = harness(&mock);
    let out = run(&h, &spec(&spec_yaml("limits: { max_requests: 4, max_redirects: 10 }\n", "")), RunInput::default()).await.out.expect("run");
    assert_eq!(out.requests, 4);
    assert_eq!(out.events, 1);
}

#[tokio::test]
async fn redirect_hops_are_paced() {
    let mock = start_mock(chain(), false).await;
    let h = harness(&mock);
    let started = Instant::now();
    run(&h, &spec(&spec_yaml("", "rate_limit: { min_interval_ms: 150 }\n")), RunInput::default()).await.out.expect("run");
    // Four exchanges, three gaps of at least 150 ms.
    assert!(started.elapsed() >= Duration::from_millis(450), "{:?}", started.elapsed());
}

#[tokio::test]
async fn transport_retries_count_against_max_requests() {
    // A port with nothing listening: every attempt is a connect failure,
    // retried up to max_retries_5xx. With a cap of 2 the third attempt is
    // refused by the budget, not sent.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let mock = Mock { port: closed.port(), log: Default::default(), pki: Arc::new(pki(MOCK_NAMES)) };
    let h = harness(&mock);
    let r = run(
        &h,
        &spec(&spec_yaml("limits: { max_requests: 2 }\n", "rate_limit: { max_retries_5xx: 5, backoff_ms: 1 }\n")),
        RunInput::default(),
    )
    .await;
    assert!(matches!(r.out, Err(EngineError::Cap(ref m)) if m.contains("2 requests")), "{:?}", r.out.as_ref().err());
    assert_eq!(h.dialer.dialed.lock().unwrap().len(), 2);
}
