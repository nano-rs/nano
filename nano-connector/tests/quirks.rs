//! Rough-vendor quirks as reusable engine features, each against a mock that
//! misbehaves the way real pull APIs do. The invariant everywhere: across
//! restarts, overlaps, narrowing and expiries, every event ships exactly once.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, TimeZone, Utc};
use common::*;
use nano_connector::engine::{self, MemoryStore, RunInput, Sink};
use serde_json::{Value, json};

#[derive(Clone)]
struct Ev {
    uid: String,
    ts: i64,
    arrives: i64,
}

/// Feed of events; the API only shows those that have "arrived" by mock now.
#[derive(Clone)]
struct Feed {
    events: Arc<Mutex<Vec<Ev>>>,
    now: Arc<Mutex<DateTime<Utc>>>,
}

impl Feed {
    fn visible_in(&self, start: i64, end: i64) -> Vec<Ev> {
        let now = self.now.lock().unwrap().timestamp_millis();
        let mut v: Vec<Ev> = self
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.arrives <= now && e.ts >= start && e.ts < end)
            .cloned()
            .collect();
        v.sort_by_key(|e| (e.ts, e.uid.clone()));
        v
    }
    fn add(&self, n: usize, from: i64, to: i64, late_ms: i64, tag: &str) {
        let mut evs = self.events.lock().unwrap();
        for i in 0..n {
            let ts = from + (to - from) * i as i64 / n as i64;
            let late = if i % 10 == 3 { late_ms } else { 0 };
            evs.push(Ev { uid: format!("{tag}-{i}"), ts, arrives: ts + late });
        }
    }
}

fn ms(s: &str) -> i64 {
    DateTime::parse_from_rfc3339(s).unwrap().timestamp_millis()
}

fn iso(ms: i64) -> String {
    Utc.timestamp_millis_opt(ms).unwrap().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Sink that fails on chosen pushes (ingest outage mid-run).
struct FlakySink {
    fail_on: Vec<usize>,
    pushes: Mutex<usize>,
    got: Mutex<Vec<Value>>,
}

#[async_trait::async_trait]
impl Sink for FlakySink {
    async fn push(&self, _st: &str, events: &[Value]) -> Result<(), String> {
        let mut n = self.pushes.lock().unwrap();
        *n += 1;
        if self.fail_on.contains(&*n) {
            return Err(format!("ingest 503 on push {}", *n));
        }
        self.got.lock().unwrap().extend_from_slice(events);
        Ok(())
    }
}

async fn run_with(h: &Harness, spec: &nano_connector::spec::ConnectorSpec, sink: Arc<FlakySink>, cps: &mut HashMap<String, Value>, creds_: nano_connector::auth::Credentials) -> Result<engine::RunOutput, engine::EngineError> {
    let store = Arc::new(MemoryStore::default());
    let out = engine::run(&h.cfg, spec, RunInput { credentials: creds_, checkpoints: cps.clone(), ..Default::default() }, sink, store.clone()).await;
    // Persist what the engine committed, as the scheduler would.
    for (stream, st) in store.saves.lock().unwrap().iter() {
        cps.insert(stream.clone(), st.clone());
    }
    out
}

fn uid_counts(events: &[Value]) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for e in events {
        *m.entry(e["uid"].as_str().unwrap().to_string()).or_insert(0) += 1;
    }
    m
}

const WINDOW_SPEC: &str = r#"
version: 1
name: windowed
kind: collector
allow: [{ host: logs.example.com, path_prefixes: ["/v1/events"] }]
auth: { type: api_key_header, header: X-Key, credential: KEY }
rate_limit: { backoff_ms: 10 }
streams:
  - id: events
    request:
      url: "https://logs.example.com/v1/events"
      query: { start: "{{window.start}}", end: "{{window.end}}" }
    response: { events_path: data }
    pagination: { type: offset, param: offset, limit_param: limit, page_size: 50, max_offset: 100 }
    window: { time_field: ts, uid_field: uid, max_span_secs: 3600, lag_secs: 60, lookback_secs: 300, initial_lookback_secs: 7200 }
"#;

/// Time windows + lag + lookback + uid dedupe + offset-cap narrowing +
/// ingest failures and restarts: every arrived event ships exactly once.
#[tokio::test]
async fn time_windows_with_lag_lookback_narrowing_and_restarts_ship_each_event_once() {
    let t0 = ms("2026-10-10T12:00:00Z");
    let now = Arc::new(Mutex::new(Utc.timestamp_millis_opt(t0).unwrap()));
    let feed = Feed { events: Arc::new(Mutex::new(vec![])), now: now.clone() };
    // 600 events over the 2 h before t0; every 10th arrives 120 s late
    // (beyond the 60 s lag, inside the 300 s lookback).
    feed.add(600, t0 - 7_200_000, t0, 120_000, "a");
    let f2 = feed.clone();
    let mock = start_mock(
        Arc::new(move |r| {
            if r.headers.get("x-key").map(String::as_str) != Some("k-123456") {
                return MockResp::status(401, json!({}));
            }
            let (s, e) = (ms(&r.query["start"]), ms(&r.query["end"]));
            let off: usize = r.query["offset"].parse().unwrap();
            let lim: usize = r.query["limit"].parse().unwrap();
            if off > 100 {
                return MockResp::status(400, json!({"error": "offset too large"}));
            }
            let page: Vec<Value> = f2.visible_in(s, e).iter().skip(off).take(lim).map(|ev| json!({"uid": ev.uid, "ts": iso(ev.ts)})).collect();
            MockResp::json(json!({ "data": page }))
        }),
        false,
    )
    .await;
    let mut h = harness(&mock);
    h.now = now.clone();
    let now2 = now.clone();
    h.cfg.clock = Arc::new(move || *now2.lock().unwrap());
    let spec = spec(WINDOW_SPEC);
    let c = || creds(&[("KEY", "k-123456")]);
    // An existing cursor 2 h back (NAN-3697: a NEW stream would start at
    // now − 5 min; this test is about walking history it already owes).
    let mut cps = HashMap::from([("events".to_string(), engine::window_rewind_checkpoint(Utc.timestamp_millis_opt(t0 - 7_200_000).unwrap()))]);
    let sink = Arc::new(FlakySink { fail_on: vec![3, 9], pushes: Mutex::new(0), got: Mutex::new(vec![]) });

    // Run 1 dies on the 3rd push; run 2 dies on the 9th; run 3 finishes.
    let mut narrowed = 0;
    let mut dropped = 0;
    for expect_ok in [false, false, true] {
        let r = run_with(&h, &spec, sink.clone(), &mut cps, c()).await;
        assert_eq!(r.is_ok(), expect_ok, "{:?}", r.as_ref().err());
        if let Ok(o) = &r {
            narrowed += o.windows_narrowed;
            dropped += o.dropped_duplicates;
        }
    }
    // Time passes; late events arrive; new events land.
    *now.lock().unwrap() = Utc.timestamp_millis_opt(t0 + 600_000).unwrap();
    feed.add(200, t0, t0 + 540_000, 120_000, "b");
    for _ in 0..2 {
        let o = run_with(&h, &spec, sink.clone(), &mut cps, c()).await.expect("later run");
        narrowed += o.windows_narrowed;
        dropped += o.dropped_duplicates;
        *now.lock().unwrap() += Duration::seconds(400);
    }

    let horizon = now.lock().unwrap().timestamp_millis() - 400_000 - 60_000;
    let expected: Vec<String> = feed
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.ts < horizon && e.arrives <= horizon + 60_000)
        .map(|e| e.uid.clone())
        .collect();
    let got = uid_counts(&sink.got.lock().unwrap());
    let dups: Vec<_> = got.iter().filter(|(_, n)| **n > 1).collect();
    assert!(dups.is_empty(), "duplicates: {dups:?}");
    let missing: Vec<_> = expected.iter().filter(|u| !got.contains_key(*u)).collect();
    assert!(missing.is_empty(), "gaps: {} missing, e.g. {:?}", missing.len(), &missing[..missing.len().min(5)]);
    assert!(narrowed > 0, "offset cap must have forced narrowing");
    assert!(dropped > 0, "overlap re-reads must have been deduped");
    eprintln!(
        "windowed: {} events shipped once ({} expected), {} windows narrowed, {} overlap duplicates dropped, 2 ingest failures survived",
        got.len(),
        expected.len(),
        narrowed,
        dropped
    );
}

/// Page tokens that expire mid-walk: restart the window, dedupe, no dups.
#[tokio::test]
async fn expired_page_tokens_restart_the_window_without_duplicates() {
    let t0 = ms("2026-10-10T12:00:00Z");
    let now = Arc::new(Mutex::new(Utc.timestamp_millis_opt(t0).unwrap()));
    let feed = Feed { events: Arc::new(Mutex::new(vec![])), now: now.clone() };
    feed.add(90, t0 - 3_000_000, t0 - 120_000, 0, "p");
    let expired_once = Arc::new(Mutex::new(false));
    let (f2, e2) = (feed.clone(), expired_once.clone());
    let mock = start_mock(
        Arc::new(move |r| {
            let (s, e) = (ms(&r.query["since"]), ms(&r.query["until"]));
            let off: usize = r.query.get("pageToken").map(|t| t.trim_start_matches("tok-").parse().unwrap()).unwrap_or(0);
            if off == 40 && !*e2.lock().unwrap() {
                *e2.lock().unwrap() = true;
                return MockResp::status(400, json!({"error": {"message": "Page token expired"}}));
            }
            let all = f2.visible_in(s, e);
            let page: Vec<Value> = all.iter().skip(off).take(20).map(|ev| json!({"id": {"uid": ev.uid, "time": iso(ev.ts)}})).collect();
            let next = if off + 20 < all.len() { json!(format!("tok-{}", off + 20)) } else { Value::Null };
            MockResp::json(json!({ "items": page, "nextPageToken": next }))
        }),
        false,
    )
    .await;
    let mut h = harness(&mock);
    let n2 = now.clone();
    h.cfg.clock = Arc::new(move || *n2.lock().unwrap());
    let spec = spec(
        r#"
version: 1
name: tokens
kind: collector
allow: [{ host: api.example.com }]
streams:
  - id: s
    request: { url: "https://api.example.com/v1/items", query: { since: "{{window.start}}", until: "{{window.end}}" } }
    response: { events_path: items }
    pagination: { type: token, from: nextPageToken, param: pageToken }
    window: { time_field: id.time, uid_field: id.uid, max_span_secs: 86400, lag_secs: 60, lookback_secs: 0, initial_lookback_secs: 3600 }
    restart_window_on: { status: [400], body_contains: "expired" }
"#,
    );
    let sink = Arc::new(FlakySink { fail_on: vec![], pushes: Mutex::new(0), got: Mutex::new(vec![]) });
    // Resume an existing cursor 1 h back (a new stream starts at now − 5 min).
    let mut cps = HashMap::from([("s".to_string(), engine::window_rewind_checkpoint(Utc.timestamp_millis_opt(t0 - 3_600_000).unwrap()))]);
    let o = run_with(&h, &spec, sink.clone(), &mut cps, creds(&[])).await.expect("run");
    assert_eq!(o.window_restarts, 1);
    let got: BTreeMap<String, usize> = sink.got.lock().unwrap().iter().map(|e| (e["id"]["uid"].as_str().unwrap().to_string(), 1)).fold(BTreeMap::new(), |mut m, (k, _)| {
        *m.entry(k).or_insert(0) += 1;
        m
    });
    assert_eq!(got.len(), 90);
    assert!(got.values().all(|n| *n == 1), "duplicates after restart");
    assert_eq!(o.dropped_duplicates, 40, "the restarted window re-read two pages and dropped them");
}

/// OAuth2 token revoked server-side mid-pagination: 401 -> refresh -> retry.
#[tokio::test]
async fn token_refresh_mid_run() {
    let issued = Arc::new(Counter::default());
    let uses = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
    let (i2, u2) = (issued.clone(), uses.clone());
    let mock = start_mock(
        Arc::new(move |r| {
            if r.host == "auth.example.com" {
                let body = String::from_utf8_lossy(&r.body);
                assert!(body.contains("grant_type=client_credentials") && body.contains("client_secret=cs-SECRET-1"));
                let n = i2.inc();
                return MockResp::json(json!({"access_token": format!("at-{n}"), "expires_in": 3600}));
            }
            let tok = r.headers.get("authorization").cloned().unwrap_or_default().replace("Bearer ", "");
            let mut u = u2.lock().unwrap();
            let c = u.entry(tok.clone()).or_insert(0);
            *c += 1;
            if *c > 3 {
                return MockResp::status(401, json!({"error": "token expired"}));
            }
            let page: u32 = r.query.get("page").and_then(|p| p.parse().ok()).unwrap_or(0);
            let next = if page < 9 { json!(page + 1) } else { Value::Null };
            MockResp::json(json!({"items": [{"page": page}], "next": next}))
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let spec = spec(
        r#"
version: 1
name: oauth
kind: collector
allow: [{ host: api.example.com }, { host: auth.example.com, path_prefixes: ["/oauth2/token"] }]
auth: { type: oauth2_client_credentials, token_url: "https://auth.example.com/oauth2/token", client_id_credential: CID, client_secret_credential: CS }
streams:
  - id: s
    request: { url: "https://api.example.com/v1/items" }
    response: { events_path: items }
    pagination: { type: cursor, from: next, param: page }
"#,
    );
    let r = run(&h, &spec, RunInput { credentials: creds(&[("CID", "client-1"), ("CS", "cs-SECRET-1")]), ..Default::default() }).await;
    let o = r.out.expect("run survives token expiry");
    assert_eq!(o.events, 10);
    assert_eq!(issued.get(), 4, "10 pages at 3 uses per token = 4 tokens, one 401 each");
}

/// AWS SigV4 and mTLS as plugins, end to end.
#[tokio::test]
async fn aws_sigv4_and_mtls_plugins() {
    let mock = start_mock(
        Arc::new(|r| {
            let a = r.headers.get("authorization").cloned().unwrap_or_default();
            if !a.starts_with("AWS4-HMAC-SHA256 Credential=AKIDTEST/") || !a.contains("/us-east-1/logs/aws4_request") || !r.headers.contains_key("x-amz-date") {
                return MockResp::status(403, json!({"message": "bad signature"}));
            }
            MockResp::json(json!({"events": [{"m": 1}]}))
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let spec_v4 = spec(
        r#"
version: 1
name: sigv4
kind: collector
allow: [{ host: logs.us-east-1.amazonaws.com }]
auth: { type: aws_sigv4, region: us-east-1, service: logs, access_key_credential: AK, secret_key_credential: SK }
streams:
  - id: s
    request: { url: "https://logs.us-east-1.amazonaws.com/", method: POST, body: { json: { logGroupName: "{{config.GROUP}}" } } }
    response: { events_path: events }
"#,
    );
    let r = run(&h, &spec_v4, RunInput { credentials: creds(&[("AK", "AKIDTEST"), ("SK", "wJalrXUtnSECRETKEY")]), config: config(json!({"GROUP": "g"})), ..Default::default() }).await;
    assert_eq!(r.out.expect("sigv4").events, 1);

    let mtls = start_mock(Arc::new(|_r| MockResp::json(json!({"events": [{"ok": true}]}))), true).await;
    let h = harness(&mtls);
    let spec_m = spec(
        r#"
version: 1
name: mtls
kind: collector
allow: [{ host: mtls.example.com }]
auth: { type: mtls, cert_credential: CERT, key_credential: KEY }
streams:
  - id: s
    request: { url: "https://mtls.example.com/v1/events" }
    response: { events_path: events }
"#,
    );
    let ok = run(&h, &spec_m, RunInput { credentials: creds(&[("CERT", &mtls.pki.client_cert_pem), ("KEY", &mtls.pki.client_key_pem)]), ..Default::default() }).await;
    assert_eq!(ok.out.expect("mtls with client cert").events, 1);
    let spec_none = spec("version: 1\nname: mtls\nkind: collector\nallow: [{ host: mtls.example.com }]\nstreams:\n  - id: s\n    request: { url: \"https://mtls.example.com/v1/events\" }\n");
    let refused = run(&h, &spec_none, RunInput::default()).await;
    assert!(refused.out.is_err(), "server must refuse a client without a certificate");
}

/// HMAC signing plugin produces a verifiable signature.
#[tokio::test]
async fn hmac_plugin_signs_requests() {
    let mock = start_mock(
        Arc::new(|r| {
            use aws_lc_rs::hmac;
            let ts = r.headers.get("x-ts").cloned().unwrap_or_default();
            let path = if r.raw_query.is_empty() { r.path.clone() } else { format!("{}?{}", r.path, r.raw_query) };
            let msg = format!("{}\n{}\n{}", r.method, path, ts);
            let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, b"hmac-secret-xyz"), msg.as_bytes());
            if r.headers.get("x-signature") != Some(&hex::encode(tag.as_ref())) || r.headers.get("x-key-id").map(String::as_str) != Some("kid-1") {
                return MockResp::status(401, json!({}));
            }
            MockResp::json(json!({"data": [1, 2]}))
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let s = spec(
        r#"
version: 1
name: hmac
kind: collector
allow: [{ host: api.example.com }]
auth: { type: hmac, credential: SECRET, header: X-Signature, message: "{method}\n{path}\n{timestamp}", timestamp_header: X-Ts, key_id_header: X-Key-Id, key_id_credential: KID }
streams:
  - id: s
    request: { url: "https://api.example.com/v1/data", query: { a: "1" } }
    response: { events_path: data }
"#,
    );
    let r = run(&h, &s, RunInput { credentials: creds(&[("SECRET", "hmac-secret-xyz"), ("KID", "kid-1")]), ..Default::default() }).await;
    assert_eq!(r.out.expect("hmac").events, 2);
}
