// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4914 phase 4: the pull-feed runner end to end against a recorded
//! vendor (the TLS mock answering for acme.okta.com) and a local HEC
//! listener that behaves like Vector's `splunk_hec` source with
//! acknowledgements on.
//!
//! Proves: events land as HEC envelopes with the stream's sourcetype and the
//! event as JSON text; a cursor is committed only after the ack; an ingest
//! outage or a refused token never moves a cursor; a pause fences a run in
//! flight; and a restarted runner resumes from the stored cursor.

mod common;

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use common::{harness, start_mock, MockResp};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use nano_connector::service::feed::{spec_sha256, FeedDefinition, RunStatus, Secret};
use nano_connector::service::{MemoryFeedStore, Runner, RunnerConfig, StaticIngest};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use uuid::Uuid;

const OKTA: &str = include_str!("../specs/okta_system_log.yaml");

/// A Vector-like HEC listener: `/services/collector/event` answers an ackId
/// and `/services/collector/ack` reports it delivered. `status` overrides
/// the event answer (503 = outage, 401 = token refused).
struct Hec {
    url: String,
    status: Arc<AtomicU16>,
    /// When non-zero, a 200 answer reports this many events refused
    /// individually (`rejected-event-count`), like Vector for an oversized one.
    reject: Arc<AtomicU64>,
    events: Arc<Mutex<Vec<Value>>>,
    acked: Arc<Mutex<Vec<u64>>>,
    ack_seqs: Arc<Mutex<Vec<u64>>>,
}

/// The cursor a commit leaves the window at, or `None` for a commit that
/// carries no window position.
fn resume(c: &nano_connector::service::store::CommitLog) -> Option<i64> {
    c.state
        .pointer("/window/resume")
        .or_else(|| c.state.pointer("/window/watermark"))
        .and_then(Value::as_i64)
}

/// The activation record's initial cursor (ms). The engine records the
/// activation (`point_forward`, window resume = initial cursor) before it
/// reads anything; that is the starting position, not progress.
fn initial_cursor_ms(c: &nano_connector::service::store::CommitLog) -> Option<i64> {
    let s = c.state.pointer("/point_forward/initial_cursor")?.as_str()?;
    Some(chrono::DateTime::parse_from_rfc3339(s).ok()?.timestamp_millis())
}

/// No commit moved the window past its activation position.
fn never_advanced(commits: &[nano_connector::service::store::CommitLog]) -> bool {
    commits.iter().all(|c| match (resume(c), initial_cursor_ms(c)) {
        (Some(r), Some(ic)) => r <= ic + 1000,
        (None, _) => true,
        (Some(_), None) => false,
    })
}

async fn start_hec(token: &'static str, seq: Arc<AtomicU64>) -> Hec {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let status = Arc::new(AtomicU16::new(200));
    let reject = Arc::new(AtomicU64::new(0));
    let events = Arc::new(Mutex::new(Vec::new()));
    let acked = Arc::new(Mutex::new(Vec::new()));
    let ack_seqs = Arc::new(Mutex::new(Vec::new()));
    let next_ack = Arc::new(AtomicU64::new(0));
    let (st, ev, ak, sq, aks, rj) = (status.clone(), events.clone(), acked.clone(), seq.clone(), ack_seqs.clone(), reject.clone());
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { break };
            let (st, ev, ak, sq, aks, next_ack, rj) = (st.clone(), ev.clone(), ak.clone(), sq.clone(), aks.clone(), next_ack.clone(), rj.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let (st, ev, ak, sq, aks, next_ack, rj) = (st.clone(), ev.clone(), ak.clone(), sq.clone(), aks.clone(), next_ack.clone(), rj.clone());
                    async move {
                        let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                        let channel = req.headers().get("x-splunk-request-channel").is_some();
                        let path = req.uri().path().to_string();
                        let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                        let reply = |code: u16, v: Value| {
                            Ok::<_, Infallible>(
                                hyper::Response::builder().status(code).header("content-type", "application/json").body(Full::new(Bytes::from(v.to_string()))).unwrap(),
                            )
                        };
                        if auth != format!("Splunk {token}") {
                            return reply(401, json!({"text": "Invalid token", "code": 4}));
                        }
                        match path.as_str() {
                            "/services/collector/event" => {
                                let forced = st.load(Ordering::SeqCst);
                                if forced != 200 {
                                    return reply(forced, json!({"text": "forced", "code": 9}));
                                }
                                assert!(channel, "acknowledgements need a request channel");
                                let text = String::from_utf8_lossy(&body).to_string();
                                let de = serde_json::Deserializer::from_str(&text).into_iter::<Value>();
                                for v in de {
                                    ev.lock().unwrap().push(v.unwrap());
                                }
                                let id = next_ack.fetch_add(1, Ordering::SeqCst);
                                let refused = rj.load(Ordering::SeqCst);
                                if refused > 0 {
                                    return reply(200, json!({"text": "Success", "code": 0, "ackId": id, "rejected-event-count": refused}));
                                }
                                reply(200, json!({"text": "Success", "code": 0, "ackId": id}))
                            }
                            "/services/collector/ack" => {
                                let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                                let mut acks = serde_json::Map::new();
                                for id in req["acks"].as_array().cloned().unwrap_or_default() {
                                    let id = id.as_u64().unwrap();
                                    ak.lock().unwrap().push(id);
                                    aks.lock().unwrap().push(sq.fetch_add(1, Ordering::SeqCst));
                                    acks.insert(id.to_string(), Value::Bool(true));
                                }
                                reply(200, json!({"acks": acks}))
                            }
                            _ => reply(404, json!({})),
                        }
                    }
                });
                let _ = http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).await;
            });
        }
    });
    Hec { url, status, reject, events, acked, ack_seqs }
}

fn okta_vendor() -> common::Handler {
    let page1 = json!([
        {"uuid": "0c7a0000-0000-4000-8000-000000000001", "published": "2026-10-10T11:58:00.000Z", "eventType": "user.session.start"},
        {"uuid": "0c7a0000-0000-4000-8000-000000000002", "published": "2026-10-10T11:58:01.000Z", "eventType": "user.session.start"}
    ]);
    let page2 = json!([{"uuid": "0c7a0000-0000-4000-8000-000000000003", "published": "2026-10-10T11:58:02.000Z", "eventType": "user.session.end"}]);
    Arc::new(move |req: &common::MockReq| {
        assert_eq!(req.headers.get("authorization").map(String::as_str), Some("SSWS okta-token"), "vendor auth from the bound credential");
        if req.query.get("after").map(String::as_str) == Some("2") {
            MockResp::json(page2.clone())
        } else {
            MockResp::json(page1.clone()).header("link", "<https://acme.okta.com/api/v1/logs?after=2&limit=1000&sortOrder=ASCENDING>; rel=\"next\"")
        }
    })
}

fn okta_feed() -> FeedDefinition {
    let mut config = serde_json::Map::new();
    config.insert("OKTA_DOMAIN".into(), json!("acme.okta.com"));
    let mut vendor = HashMap::new();
    vendor.insert("API_TOKEN".to_string(), Secret::new("okta-token"));
    FeedDefinition {
        feed_id: Uuid::now_v7(),
        name: "Okta".into(),
        connector: "okta_system_log".into(),
        spec_yaml: OKTA.into(),
        spec_sha256: spec_sha256(OKTA),
        source_type: "okta".into(),
        schedule: None,
        config,
        credential_id: Some(Uuid::now_v7()),
        vendor_credentials: vendor,
        max_run_secs: Some(60),
        consecutive_failures: 0,
    }
}

async fn setup() -> (common::Mock, Hec, Arc<MemoryFeedStore>, Arc<Runner>, Arc<AtomicU64>, FeedDefinition) {
    let vendor = start_mock(okta_vendor(), false).await;
    let seq = Arc::new(AtomicU64::new(0));
    let hec = start_hec("ingest-token", seq.clone()).await;
    let s2 = seq.clone();
    let store = Arc::new(MemoryFeedStore::with_sequencer(Box::new(move || s2.fetch_add(1, Ordering::SeqCst))));
    let feed = okta_feed();
    store.add(feed.clone());
    let runner = runner_for(&vendor, &hec, store.clone(), "node-a");
    (vendor, hec, store, runner, seq, feed)
}

fn runner_for(vendor: &common::Mock, hec: &Hec, store: Arc<MemoryFeedStore>, node: &str) -> Arc<Runner> {
    let h = harness(vendor);
    let ingest = Arc::new(StaticIngest { url: hec.url.clone(), token: Secret::new("ingest-token") });
    let mut cfg = RunnerConfig::new(node, h.cfg, ingest);
    cfg.hec.allow_http = true;
    cfg.hec.max_retry_total = Duration::from_secs(3);
    cfg.hec.base_backoff = Duration::from_millis(50);
    cfg.hec.max_backoff = Duration::from_millis(200);
    Runner::new(store, cfg)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn events_land_through_hec_and_the_cursor_commits_after_the_ack() {
    let (_vendor, hec, store, runner, _seq, feed) = setup().await;
    let tick = runner.tick().await.unwrap();
    assert_eq!(tick.claimed, 1);
    let recs = runner.drain().await;
    assert_eq!(recs.len(), 1);
    let rec = &recs[0];
    assert_eq!(rec.status, RunStatus::Success, "{:?}", rec.error);
    assert_eq!(rec.events, 3);

    let events = hec.events.lock().unwrap().clone();
    assert_eq!(events.len(), 3);
    for e in &events {
        assert_eq!(e["sourcetype"], "okta");
        assert_eq!(e["source"], "nano-connector:okta_system_log");
        let inner: Value = serde_json::from_str(e["event"].as_str().expect("event is JSON text")).unwrap();
        assert!(inner["uuid"].as_str().unwrap().starts_with("0c7a0000"));
    }

    let commits = store.commits();
    assert!(!commits.is_empty(), "the window cursor is stored");
    let acks = hec.ack_seqs.lock().unwrap().clone();
    assert!(!acks.is_empty(), "the sink waited for Vector's ack");
    let first_ack = *acks.iter().min().unwrap();
    let last_commit = commits.iter().map(|c| c.seq).max().unwrap();
    let before_ack: Vec<_> = commits.iter().filter(|c| c.seq < first_ack).cloned().collect();
    assert!(
        never_advanced(&before_ack),
        "before the first acknowledgement only the activation position may be stored (acks {acks:?}, commits {before_ack:?})"
    );
    assert!(last_commit > first_ack);
    let last = commits.iter().max_by_key(|c| c.seq).unwrap();
    assert!(!never_advanced(std::slice::from_ref(last)), "after the ack the cursor moved: {last:?}");
    assert!(store.checkpoint(feed.feed_id, "system_log").is_some());
    // A healthy feed is next due on its schedule (*/2), not immediately.
    assert!(store.next_run_at(feed.feed_id).unwrap() > chrono::Utc::now());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ingest_outage_never_moves_the_cursor() {
    let (_vendor, hec, store, runner, _seq, feed) = setup().await;
    hec.status.store(503, Ordering::SeqCst);
    runner.tick().await.unwrap();
    let rec = runner.drain().await.remove(0);
    assert_eq!(rec.status, RunStatus::Failed);
    assert!(rec.error.as_deref().unwrap_or("").contains("ingest"), "{:?}", rec.error);
    assert!(rec.ingest_retries > 0, "back-pressure is retried inside the run");
    let commits = store.commits();
    assert!(never_advanced(&commits), "no cursor progress without an ack: {commits:?}");
    assert!(hec.acked.lock().unwrap().is_empty());
    assert!(store.next_run_at(feed.feed_id).unwrap() > chrono::Utc::now(), "backed off");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_ingest_token_backs_off_an_hour_without_a_cursor() {
    let vendor = start_mock(okta_vendor(), false).await;
    let seq = Arc::new(AtomicU64::new(0));
    let hec = start_hec("the-real-token", seq).await;
    let store = Arc::new(MemoryFeedStore::default());
    let feed = okta_feed();
    store.add(feed.clone());
    let runner = runner_for(&vendor, &hec, store.clone(), "node-a");
    runner.tick().await.unwrap();
    let rec = runner.drain().await.remove(0);
    assert_eq!(rec.status, RunStatus::Failed);
    let err = rec.error.unwrap();
    assert!(err.starts_with("credential_revoked: "), "{err}");
    assert!(!err.contains("ingest-token"), "the token never appears in an error");
    assert!(never_advanced(&store.commits()));
    let next = store.next_run_at(feed.feed_id).unwrap();
    assert!(next > chrono::Utc::now() + chrono::Duration::minutes(55), "{next}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pause_fences_a_run_in_flight() {
    let (_vendor, _hec, store, runner, _seq, feed) = setup().await;
    let claims = {
        use nano_connector::service::FeedStore;
        store.claim_due("node-a", 1, &|_| 120).await.unwrap()
    };
    assert_eq!(claims.len(), 1);
    // The operator pauses while the claim is held: the generation moves.
    store.set_enabled(feed.feed_id, false);
    let rec = runner.run_claimed(&claims[0]).await;
    assert_eq!(rec.status, RunStatus::LeaseLost, "{:?}", rec.error);
    assert!(store.checkpoint(feed.feed_id, "system_log").is_none(), "a fenced run commits nothing");
    // Paused: nothing is claimed.
    store.make_due(feed.feed_id);
    assert_eq!(runner.tick().await.unwrap().claimed, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_runner_resumes_from_the_stored_cursor() {
    let (vendor, hec, store, runner, _seq, feed) = setup().await;
    runner.tick().await.unwrap();
    assert_eq!(runner.drain().await.remove(0).status, RunStatus::Success);
    let first_requests = vendor.requests();
    let first_until = first_requests[0].query.get("until").cloned().expect("window end");
    let saved = store.checkpoint(feed.feed_id, "system_log").unwrap();
    drop(runner);

    // A new runner process (another node id), same durable store.
    let restarted = runner_for(&vendor, &hec, store.clone(), "node-b");
    store.make_due(feed.feed_id);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    restarted.tick().await.unwrap();
    assert_eq!(restarted.drain().await.remove(0).status, RunStatus::Success);
    let second: Vec<_> = vendor.requests().into_iter().skip(first_requests.len()).collect();
    assert!(!second.is_empty());
    let since = second[0].query.get("since").cloned().expect("window start");
    // Okta windows re-read a lookback overlap, so the resume starts at or
    // before the previous window's end, never at a fresh activation (a
    // second activation would record a new point_forward initial cursor).
    assert!(since <= first_until, "resume since {since} must not skip past {first_until}");
    let after = store.checkpoint(feed.feed_id, "system_log").unwrap();
    assert_eq!(after["point_forward"], saved["point_forward"], "the activation is recorded once and kept");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_individually_refused_event_withholds_the_cursor() {
    let (_vendor, hec, store, runner, _seq, feed) = setup().await;
    // Vector accepts the batch but refuses one event in it (e.g. oversized).
    hec.reject.store(1, Ordering::SeqCst);
    runner.tick().await.unwrap();
    let rec = runner.drain().await.remove(0);
    assert_eq!(rec.status, RunStatus::Failed);
    assert!(rec.error.as_deref().unwrap_or("").contains("events_rejected: "), "{:?}", rec.error);
    assert!(rec.rejected_events >= 1);
    assert!(never_advanced(&store.commits()), "no cursor past a refused record");
    assert!(store.next_run_at(feed.feed_id).unwrap() > chrono::Utc::now());

    // Once the ingest accepts everything, the same page is delivered and the
    // cursor moves.
    hec.reject.store(0, Ordering::SeqCst);
    store.make_due(feed.feed_id);
    runner.tick().await.unwrap();
    assert_eq!(runner.drain().await.remove(0).status, RunStatus::Success);
    assert!(!never_advanced(&store.commits()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_event_too_large_to_send_fails_the_page_without_skipping_it() {
    let big = "x".repeat(8 * 1024);
    let vendor = start_mock(
        Arc::new(move |_req: &common::MockReq| {
            MockResp::json(json!([
                {"uuid": "0c7a0000-0000-4000-8000-0000000000a1", "published": "2026-10-10T11:58:00.000Z", "eventType": "small"},
                {"uuid": "0c7a0000-0000-4000-8000-0000000000a2", "published": "2026-10-10T11:58:01.000Z", "eventType": "big", "blob": big},
                {"uuid": "0c7a0000-0000-4000-8000-0000000000a3", "published": "2026-10-10T11:58:02.000Z", "eventType": "small"}
            ]))
        }),
        false,
    )
    .await;
    let hec = start_hec("ingest-token", Arc::new(AtomicU64::new(0))).await;
    let store = Arc::new(MemoryFeedStore::default());
    let feed = okta_feed();
    store.add(feed.clone());
    let h = harness(&vendor);
    let ingest = Arc::new(StaticIngest { url: hec.url.clone(), token: Secret::new("ingest-token") });
    let mut cfg = RunnerConfig::new("node-a", h.cfg, ingest);
    cfg.hec.allow_http = true;
    cfg.hec.max_batch_bytes = 4 * 1024;
    let runner = Runner::new(store.clone(), cfg);
    runner.tick().await.unwrap();
    let rec = runner.drain().await.remove(0);
    assert_eq!(rec.status, RunStatus::Failed);
    assert!(rec.error.as_deref().unwrap_or("").contains("exceeds the 4096 byte"), "{:?}", rec.error);
    assert!(hec.events.lock().unwrap().is_empty(), "nothing of the page was sent around the oversized record");
    assert!(never_advanced(&store.commits()));
}

/// NAN-5217: while nano's ingestion pause is on, the runner claims nothing,
/// so the vendor is never read and no cursor moves; after resume the same
/// feed runs from where it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ingestion_pause_stops_pulling_until_resumed() {
    let (_vendor, hec, store, runner, _seq, feed) = setup().await;
    store.set_ingestion_paused(true);
    let tick = runner.tick().await.unwrap();
    assert!(tick.ingestion_paused);
    assert_eq!(tick.claimed, 0);
    assert!(runner.drain().await.is_empty(), "no run started");
    assert!(hec.events.lock().unwrap().is_empty());
    assert!(store.commits().is_empty(), "no cursor written while paused");
    assert!(store.checkpoint(feed.feed_id, "system_log").is_none());

    store.set_ingestion_paused(false);
    let tick = runner.tick().await.unwrap();
    assert!(!tick.ingestion_paused);
    assert_eq!(tick.claimed, 1);
    let rec = runner.drain().await.remove(0);
    assert_eq!(rec.status, RunStatus::Success, "{:?}", rec.error);
    assert_eq!(hec.events.lock().unwrap().len(), 3, "every event delivered once after resume");
}
