//! NAN-3490 L1 end to end: mock vendor (Okta System Log over TLS) → feed
//! runner (engine + HEC sink + fenced checkpoints) → mock HEC ingress.
//!
//! Proves:
//! - every checkpoint is written only after the ingress acknowledged every
//!   event the checkpoint covers (global sequence: ack < commit);
//! - ingress 429 / 503 back off and retry the same bytes (same
//!   Idempotency-Key) without moving the cursor;
//! - `_nano_ingest_id` is the vendor uuid;
//! - a crash between emit and ack, then a restart on another runner, is
//!   at-least-once with no gap, and the crashed claim can no longer move the
//!   cursor (lease fencing);
//! - an ingress refusal (4xx) fails the run, keeps the cursor, and backs the
//!   feed off.

mod common;

use std::collections::{BTreeSet, HashMap};
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use common::*;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use nano_connector::service::feed::spec_sha256;
use nano_connector::service::store::FeedStore;
use nano_connector::service::{
    FeedDefinition, MemoryFeedStore, RunStatus, Runner, RunnerConfig, Secret, StoreError,
};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use uuid::Uuid;

const N_EVENTS: usize = 180;
const PAGE: usize = 25;
const FEED_TOKEN: &str = "feed-ingest-token-0123456789";
const OKTA_TOKEN: &str = "okta-api-token-abcdef";

// ---------------------------------------------------------------- vendor mock

fn okta_events(now: DateTime<Utc>) -> Vec<Value> {
    (0..N_EVENTS)
        .map(|i| {
            let t = now - chrono::Duration::seconds(280) + chrono::Duration::milliseconds(i as i64 * 1000);
            json!({
                "uuid": format!("okta-{i:04}"),
                "published": t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "eventType": "user.session.start",
                "actor": { "id": "00u1", "alternateId": "alice@example.com" },
            })
        })
        .collect()
}

fn okta_handler(events: Arc<Vec<Value>>) -> Handler {
    Arc::new(move |r: &MockReq| {
        if r.headers.get("authorization").map(String::as_str) != Some(&format!("SSWS {OKTA_TOKEN}")) {
            return MockResp::status(401, json!({ "errorCode": "E0000011" }));
        }
        let parse = |k: &str| r.query.get(k).and_then(|v| DateTime::parse_from_rfc3339(v).ok()).map(|d| d.with_timezone(&Utc));
        let (since, until) = (parse("since"), parse("until"));
        let after: usize = r.query.get("after").and_then(|v| v.parse().ok()).unwrap_or(0);
        let in_window: Vec<&Value> = events
            .iter()
            .filter(|e| {
                let t = DateTime::parse_from_rfc3339(e["published"].as_str().unwrap()).unwrap().with_timezone(&Utc);
                since.is_none_or(|s| t >= s) && until.is_none_or(|u| t < u)
            })
            .collect();
        let page: Vec<Value> = in_window.iter().skip(after).take(PAGE).map(|v| (*v).clone()).collect();
        let mut resp = MockResp::json(Value::Array(page));
        if after + PAGE < in_window.len() {
            let mut next = url::Url::parse("https://acme.okta.com/api/v1/logs").unwrap();
            {
                let mut q = next.query_pairs_mut();
                for (k, v) in &r.query {
                    if k != "after" {
                        q.append_pair(k, v);
                    }
                }
                q.append_pair("after", &(after + PAGE).to_string());
            }
            resp = resp.header("link", &format!("<{next}>; rel=\"next\""));
        }
        resp
    })
}

// ------------------------------------------------------------------ HEC mock

#[derive(Clone, Copy, Debug)]
enum Act {
    Ok,
    Status(u16),
    /// Read the batch, never answer (the runner dies before the receipt).
    Hang,
}

#[derive(Debug, Clone)]
struct HecReq {
    auth: String,
    key: String,
    body: String,
    /// Global sequence of the 200 (None = not acknowledged).
    ack_seq: Option<u64>,
}

struct Hec {
    port: u16,
    log: Arc<Mutex<Vec<HecReq>>>,
}

impl Hec {
    fn reqs(&self) -> Vec<HecReq> {
        self.log.lock().unwrap().clone()
    }
    /// (ack sequence, ingest ids) of every acknowledged batch.
    fn acked(&self) -> Vec<(u64, Vec<String>)> {
        self.reqs().into_iter().filter_map(|r| r.ack_seq.map(|s| (s, ids(&r.body)))).collect()
    }
}

fn ids(body: &str) -> Vec<String> {
    body.lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            assert_eq!(v["sourcetype"], "okta");
            // NAN-3490: `event` is the event's JSON text.
            let event: Value = serde_json::from_str(v["event"].as_str().expect("event is JSON text")).unwrap();
            assert_eq!(event["_nano_ingest_id"], event["uuid"], "ingest id is the vendor uuid");
            event["_nano_ingest_id"].as_str().unwrap().to_string()
        })
        .collect()
}

async fn start_hec(seq: Arc<AtomicU64>, script: Arc<dyn Fn(usize) -> Act + Send + Sync>) -> Hec {
    start_hec_auth(seq, Arc::new(move |n, _: &str| script(n))).await
}

/// [`start_hec`] whose script also sees the request's `Authorization`.
async fn start_hec_auth(seq: Arc<AtomicU64>, script: Arc<dyn Fn(usize, &str) -> Act + Send + Sync>) -> Hec {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Arc<Mutex<Vec<HecReq>>> = Arc::new(Mutex::new(vec![]));
    let count = Arc::new(AtomicUsize::new(0));
    let log2 = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { break };
            let (log, count, seq, script) = (log2.clone(), count.clone(), seq.clone(), script.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let (log, count, seq, script) = (log.clone(), count.clone(), seq.clone(), script.clone());
                    async move {
                        let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                        let (auth, key) = (h("authorization"), h("idempotency-key"));
                        assert_eq!(req.uri().path(), "/services/collector/event");
                        let body = String::from_utf8(req.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
                        let n = count.fetch_add(1, Ordering::SeqCst);
                        let act = script(n, &auth);
                        let idx = {
                            let mut l = log.lock().unwrap();
                            l.push(HecReq { auth, key, body, ack_seq: None });
                            l.len() - 1
                        };
                        let resp = match act {
                            Act::Ok => {
                                let s = seq.fetch_add(1, Ordering::SeqCst);
                                log.lock().unwrap()[idx].ack_seq = Some(s);
                                hyper::Response::builder()
                                    .status(200)
                                    .header("x-nano-delivery-receipt", format!("tenant:{n:08}"))
                                    .body(Full::new(Bytes::from(json!({ "text": "Success", "code": 0, "ackId": n }).to_string())))
                                    .unwrap()
                            }
                            Act::Status(code) => hyper::Response::builder()
                                .status(code)
                                .header("retry-after", "0")
                                .header("x-nano-error-class", if code == 429 { "raw_handoff_queue_full" } else { "unavailable" })
                                .body(Full::new(Bytes::from(json!({ "text": "busy", "code": 9 }).to_string())))
                                .unwrap(),
                            Act::Hang => {
                                std::future::pending::<()>().await;
                                unreachable!()
                            }
                        };
                        Ok::<_, Infallible>(resp)
                    }
                });
                let _ = http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).await;
            });
        }
    });
    Hec { port, log }
}

// ------------------------------------------------------------------ fixtures

struct Fixture {
    store: Arc<MemoryFeedStore>,
    feed_id: Uuid,
    vendor: Mock,
    events: Arc<Vec<Value>>,
}

async fn fixture(hec_port: u16, seq: Arc<AtomicU64>) -> Fixture {
    let now = Utc::now();
    let events = Arc::new(okta_events(now));
    let vendor = start_mock(okta_handler(events.clone()), false).await;
    let seq2 = seq.clone();
    let store = Arc::new(MemoryFeedStore::with_sequencer(Box::new(move || seq2.fetch_add(1, Ordering::SeqCst))));
    let yaml = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/specs/okta_system_log.yaml")).unwrap();
    let feed_id = Uuid::now_v7();
    store.add(
        FeedDefinition {
            tenant_id: Uuid::now_v7(),
            feed_id,
            name: "Okta System Log".into(),
            connector: "okta_system_log".into(),
            spec_sha256: spec_sha256(&yaml),
            spec_yaml: yaml,
            source_slug: "okta".into(),
            schedule: None,
            config: config(json!({ "OKTA_DOMAIN": "acme.okta.com" })),
            vendor_credentials: HashMap::from([("API_TOKEN".to_string(), Secret::new(OKTA_TOKEN))]),
            ingest_url: format!("http://127.0.0.1:{hec_port}"),
            ingest_token: Secret::new(FEED_TOKEN),
            max_run_secs: Some(60),
            consecutive_failures: 0,
        },
        Uuid::now_v7(),
    );
    Fixture { store, feed_id, vendor, events }
}

fn runner(f: &Fixture, node: &str) -> Arc<Runner> {
    let mut cfg = RunnerConfig::new(node, harness(&f.vendor).cfg);
    cfg.hec.allow_http = true;
    cfg.hec.max_batch_events = 40; // > 1 POST per Okta page sometimes
    cfg.hec.base_backoff = Duration::from_millis(5);
    cfg.hec.max_retry_total = Duration::from_secs(10);
    Runner::new(f.store.clone(), cfg)
}

/// Every uid a checkpoint claims as delivered (`window.seen`) was acked
/// by the ingress before that checkpoint was written.
fn assert_commits_follow_acks(f: &Fixture, hec: &Hec) {
    let acked = hec.acked();
    let commits = f.store.commits();
    assert!(!commits.is_empty());
    for c in &commits {
        let seen: BTreeSet<String> = c.state.pointer("/window/seen").and_then(Value::as_object).map(|m| m.keys().cloned().collect()).unwrap_or_default();
        let acked_before: BTreeSet<String> = acked.iter().filter(|(s, _)| *s < c.seq).flat_map(|(_, ids)| ids.clone()).collect();
        let missing: Vec<_> = seen.difference(&acked_before).take(3).collect();
        assert!(missing.is_empty(), "commit seq {} claims {missing:?} before their ingress receipt", c.seq);
    }
}

fn all_uuids(f: &Fixture) -> BTreeSet<String> {
    f.events.iter().map(|e| e["uuid"].as_str().unwrap().to_string()).collect()
}

// --------------------------------------------------------------------- tests

#[tokio::test]
async fn cursor_commits_only_after_ack_and_backpressure_retries_same_bytes() {
    let seq = Arc::new(AtomicU64::new(0));
    // POST #1 (2nd) gets 503 twice, POST #4 gets a 429.
    let hec = start_hec(
        seq.clone(),
        Arc::new(|n| match n {
            1 | 2 => Act::Status(503),
            5 => Act::Status(429),
            _ => Act::Ok,
        }),
    )
    .await;
    let f = fixture(hec.port, seq).await;
    let r = runner(&f, "runner-a");
    let s = r.tick().await.unwrap();
    assert_eq!(s.claimed, 1);
    let recs = r.drain().await;
    assert_eq!(recs.len(), 1);
    let rec = &recs[0];
    assert_eq!(rec.status, RunStatus::Success, "{:?}", rec.error);
    assert_eq!(rec.events, N_EVENTS as u64);
    assert_eq!(rec.ingest_retries, 3);
    assert!(rec.pages >= (N_EVENTS / PAGE) as u32, "pages {}", rec.pages);
    assert!(rec.bytes > 0 && rec.batches >= (N_EVENTS / 40) as u64);
    assert!(rec.last_receipt.as_deref().is_some_and(|r| r.starts_with("tenant:")));
    assert!(rec.next_run_at > Utc::now(), "next run is scheduled in the future");

    // Exactly once at the ingress, keyed by the vendor uuid.
    let delivered: Vec<String> = hec.acked().into_iter().flat_map(|(_, i)| i).collect();
    assert_eq!(delivered.len(), N_EVENTS);
    assert_eq!(delivered.iter().cloned().collect::<BTreeSet<_>>(), all_uuids(&f));

    // Back-pressure retried the identical bytes under the identical key.
    let reqs = hec.reqs();
    assert!(reqs.iter().all(|r| r.auth == format!("Splunk {FEED_TOKEN}")));
    assert!(reqs.iter().all(|r| r.key.starts_with("nc1-") && r.key.len() == 64));
    assert_eq!((reqs[1].key.clone(), reqs[1].body.clone()), (reqs[2].key.clone(), reqs[2].body.clone()));
    assert_eq!((reqs[2].key.clone(), reqs[2].body.clone()), (reqs[3].key.clone(), reqs[3].body.clone()));
    assert_eq!(reqs[5].body, reqs[6].body);
    assert!(reqs.iter().all(|r| !r.body.contains(OKTA_TOKEN)));

    assert_commits_follow_acks(&f, &hec);
    let cp = f.store.checkpoint(f.feed_id, "system_log").unwrap();
    assert!(cp.pointer("/window/watermark").is_some(), "the pass completed: {cp}");
    eprintln!("L1 e2e: {} events, {} POSTs ({} retried), {} commits, all after their receipts", rec.events, reqs.len(), rec.ingest_retries, f.store.commits().len());
}

#[tokio::test]
async fn crash_between_emit_and_ack_then_restart_is_at_least_once_without_gap() {
    let seq = Arc::new(AtomicU64::new(0));
    let crashed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let c2 = crashed.clone();
    // Before the crash, POST #3 is read by the ingress and never answered.
    let hec = start_hec(
        seq.clone(),
        Arc::new(move |n| if n == 3 && !c2.load(Ordering::SeqCst) { Act::Hang } else { Act::Ok }),
    )
    .await;
    let f = fixture(hec.port, seq).await;
    let a = runner(&f, "runner-a");
    assert_eq!(a.tick().await.unwrap().claimed, 1);
    // Wait until the ingress holds the unanswered batch, then kill runner A.
    for _ in 0..500 {
        if hec.reqs().len() >= 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(hec.reqs().len(), 4, "runner A emitted the 4th batch");
    a.abort_all().await;
    crashed.store(true, Ordering::SeqCst);
    let hung = hec.reqs()[3].clone();
    assert!(hung.ack_seq.is_none());
    let hung_ids: BTreeSet<String> = ids(&hung.body).into_iter().collect();

    // The cursor never covered the unacknowledged batch.
    let before_restart = f.store.checkpoint(f.feed_id, "system_log").expect("earlier pages were committed");
    let seen: BTreeSet<String> = before_restart.pointer("/window/seen").and_then(Value::as_object).unwrap().keys().cloned().collect();
    assert!(seen.is_disjoint(&hung_ids), "a checkpoint covered events that never got a receipt");
    let crashed_claim_gen = 1;

    // The crashed runner's lease expires; runner B picks the feed up.
    f.store.expire_lease(f.feed_id);
    let b = runner(&f, "runner-b");
    assert_eq!(b.tick().await.unwrap().claimed, 1);
    let recs = b.drain().await;
    assert_eq!(recs[0].status, RunStatus::Success, "{:?}", recs[0].error);

    // No gap: every vendor event got a receipt. At-least-once: the batch
    // that was in flight at the crash was sent again with identical bytes.
    let delivered: Vec<String> = hec.acked().into_iter().flat_map(|(_, i)| i).collect();
    let unique: BTreeSet<String> = delivered.iter().cloned().collect();
    assert_eq!(unique, all_uuids(&f), "a gap after the restart");
    assert!(hung_ids.is_subset(&unique));
    assert!(hec.reqs().iter().skip(4).any(|r| r.key == hung.key && r.body == hung.body), "the in-flight batch was re-sent byte for byte");
    let dups = delivered.len() - unique.len();
    assert!(dups <= 2 * PAGE, "re-sends bounded by the uncommitted page(s): {dups}");
    assert_commits_follow_acks(&f, &hec);
    assert!(f.store.commits().iter().any(|c| c.lease_generation == 2));

    // Fencing: the dead runner's claim can no longer move the cursor.
    let stale = nano_connector::service::ClaimedFeed {
        slot: nano_connector::service::TenantSlot { tenant_id: Uuid::nil(), actor_id: Uuid::nil() },
        feed: FeedDefinition { feed_id: f.feed_id, ..fixture_feed(&f) },
        lease_generation: crashed_claim_gen,
        node: "runner-a".into(),
        run_id: Uuid::now_v7(),
        claimed_at: Utc::now(),
    };
    let err = f.store.save_checkpoint(&stale, "system_log", &json!({ "state": {} })).await.unwrap_err();
    assert!(matches!(err, StoreError::LeaseLost));
    eprintln!("L1 crash: {} in flight at the crash, {} delivered ({} unique, {} duplicate), no gap", hung_ids.len(), delivered.len(), unique.len(), dups);
}

fn fixture_feed(f: &Fixture) -> FeedDefinition {
    // Only feed_id matters for the fencing probe.
    FeedDefinition {
        tenant_id: Uuid::nil(),
        feed_id: f.feed_id,
        name: String::new(),
        connector: String::new(),
        spec_yaml: String::new(),
        spec_sha256: String::new(),
        source_slug: String::new(),
        schedule: None,
        config: Default::default(),
        vendor_credentials: HashMap::new(),
        ingest_url: String::new(),
        ingest_token: Secret::new(""),
        max_run_secs: None,
        consecutive_failures: 0,
    }
}

#[tokio::test]
async fn ingress_refusal_fails_the_run_keeps_the_cursor_and_backs_off() {
    let seq = Arc::new(AtomicU64::new(0));
    // First POST accepted, the second refused (credential revoked).
    let hec = start_hec(seq.clone(), Arc::new(|n| if n == 0 { Act::Ok } else { Act::Status(401) })).await;
    let f = fixture(hec.port, seq).await;
    let r = runner(&f, "runner-a");
    r.tick().await.unwrap();
    let rec = r.drain().await.remove(0);
    assert_eq!(rec.status, RunStatus::Failed);
    assert!(rec.error.as_deref().unwrap().contains("HTTP 401"), "{:?}", rec.error);
    assert_eq!(rec.ingest_retries, 0, "a 4xx is not retried");
    assert_eq!(hec.reqs().len(), 2);
    // Page 1 (2 POSTs at 40 events/POST for 25-event pages = 1 POST) was
    // acknowledged and committed; nothing after it.
    assert_commits_follow_acks(&f, &hec);
    let seen = f.store.checkpoint(f.feed_id, "system_log").and_then(|c| c.pointer("/window/seen").cloned()).unwrap();
    assert_eq!(seen.as_object().unwrap().len(), PAGE);
    assert!(f.store.next_run_at(f.feed_id).unwrap() > Utc::now() + chrono::Duration::seconds(20), "failure backs off");
    let runs = f.store.runs();
    assert_eq!(runs.len(), 1);
}

/// NAN-3660 acceptance (mock): the tenant revokes the feed's credential
/// mid-run → the run fails with `credential_revoked`, the cursor holds and
/// the feed stops posting (backs off an hour, never re-enrolls on its own)
/// → the rotate operation installs a new credential → the feed resumes from
/// its checkpoint: every event delivered, no gap, no duplicate.
#[tokio::test]
async fn revoked_credential_stops_the_feed_until_rotation_then_resumes_without_gap() {
    const NEW_TOKEN: &str = "feed-ingest-token-rotated-9876543210";
    let seq = Arc::new(AtomicU64::new(0));
    let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let gate = revoked.clone();
    // The old token is accepted for the first POST, then revoked; the new
    // token is always accepted.
    let hec = start_hec_auth(
        seq.clone(),
        Arc::new(move |n, auth: &str| {
            if auth == format!("Splunk {NEW_TOKEN}") {
                return Act::Ok;
            }
            if n >= 1 {
                gate.store(true, Ordering::SeqCst);
            }
            if gate.load(Ordering::SeqCst) { Act::Status(401) } else { Act::Ok }
        }),
    )
    .await;
    let f = fixture(hec.port, seq).await;
    let r = runner(&f, "runner-a");
    r.tick().await.unwrap();
    let rec = r.drain().await.remove(0);
    assert_eq!(rec.status, RunStatus::Failed);
    let error = rec.error.as_deref().unwrap();
    assert!(error.starts_with("credential_revoked: "), "the refusal itself, not the engine wrapper: {error}");
    assert!(error.ends_with("rotate the feed credential"), "{error}");
    assert!(revoked.load(Ordering::SeqCst));
    let next = f.store.next_run_at(f.feed_id).unwrap();
    assert!(next > Utc::now() + chrono::Duration::minutes(55), "backs off ~1 h, not per batch: {next}");
    let committed_before = f.store.checkpoint(f.feed_id, "system_log").and_then(|c| c.pointer("/window/seen").cloned()).unwrap();
    assert_eq!(committed_before.as_object().unwrap().len(), PAGE, "the acked page stays committed");

    // Not due: another tick posts nothing (no hot loop, no re-enroll).
    let posts = hec.reqs().len();
    r.tick().await.unwrap();
    assert!(r.drain().await.is_empty());
    assert_eq!(hec.reqs().len(), posts);

    // Rotate: the new credential is stored, the lease fenced, the feed due.
    f.store.rotate_ingest_token(f.feed_id, Secret::new(NEW_TOKEN));
    r.tick().await.unwrap();
    let rec = r.drain().await.remove(0);
    assert_eq!(rec.status, RunStatus::Success, "{:?}", rec.error);
    let after: Vec<HecReq> = hec.reqs().into_iter().skip(posts).collect();
    assert!(!after.is_empty() && after.iter().all(|r| r.auth == format!("Splunk {NEW_TOKEN}")));

    // Every event exactly once across both credentials: no gap, no duplicate.
    let delivered: Vec<String> = hec.acked().into_iter().flat_map(|(_, ids)| ids).collect();
    let unique: BTreeSet<String> = delivered.iter().cloned().collect();
    assert_eq!(unique, all_uuids(&f), "no gap");
    assert_eq!(delivered.len(), unique.len(), "no duplicate");
    assert_commits_follow_acks(&f, &hec);
}

#[tokio::test]
async fn tenant_budget_caps_concurrent_runs() {
    let seq = Arc::new(AtomicU64::new(0));
    let hec = start_hec(seq.clone(), Arc::new(|_| Act::Ok)).await;
    let f = fixture(hec.port, seq).await;
    // Two more feeds of the same tenant, and the runner allows 2 per tenant.
    let tenant = f.store.tenants().await.unwrap()[0];
    let base = FeedDefinition { tenant_id: tenant.tenant_id, ..fixture_feed(&f) };
    for _ in 0..2 {
        f.store.add(FeedDefinition { feed_id: Uuid::now_v7(), spec_sha256: "0".repeat(64), ..base.clone() }, tenant.actor_id);
    }
    let r = runner(&f, "runner-a");
    let s = r.tick().await.unwrap();
    assert_eq!(s.claimed, 2, "per-tenant budget is 2");
    let recs = r.drain().await;
    // The two bogus feeds fail on their pinned digest, without any I/O.
    assert!(recs.iter().any(|x| x.error.as_deref().is_some_and(|e| e.contains("digest mismatch"))));
    let s2 = r.tick().await.unwrap();
    assert_eq!(s2.claimed, 1, "the third feed runs on the next tick");
    r.drain().await;
}
