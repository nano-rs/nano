//! NAN-3490 / NAN-3697: a tenant checkpoint reset (`service::reset::plan_reset`)
//! re-anchors a time-window stream point-forward: the engine's next run
//! starts its first window exactly at reset time − 5 min, never earlier. A
//! reset cannot backfill: `since` earlier than that anchor is refused.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeZone, Utc};
use common::*;
use nano_connector::engine::{self, MemoryStore, RunInput, Sink};
use nano_connector::service::reset::plan_reset;
use serde_json::{Value, json};

fn ms(s: &str) -> i64 {
    DateTime::parse_from_rfc3339(s).unwrap().timestamp_millis()
}

fn iso(ms: i64) -> String {
    Utc.timestamp_millis_opt(ms).unwrap().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[derive(Default)]
struct Collect(Mutex<Vec<Value>>);

#[async_trait::async_trait]
impl Sink for Collect {
    async fn push(&self, _st: &str, events: &[Value]) -> Result<(), String> {
        self.0.lock().unwrap().extend_from_slice(events);
        Ok(())
    }
}

const SPEC: &str = r#"
version: 1
name: resettable
kind: collector
allow: [{ host: logs.example.com, path_prefixes: ["/v1/events"] }]
auth: { type: api_key_header, header: X-Key, credential: KEY }
streams:
  - id: events
    request:
      url: "https://logs.example.com/v1/events"
      query: { start: "{{window.start}}", end: "{{window.end}}" }
    response: { events_path: data }
    window: { time_field: ts, uid_field: uid, max_span_secs: 3600, lag_secs: 60, lookback_secs: 60, initial_lookback_secs: 300, max_backfill_secs: 14400 }
"#;

async fn run_once(
    h: &Harness,
    spec: &nano_connector::spec::ConnectorSpec,
    cps: &mut HashMap<String, Value>,
) -> (engine::RunOutput, Vec<Value>) {
    let sink = Arc::new(Collect::default());
    let store = Arc::new(MemoryStore::default());
    let out = engine::run(
        &h.cfg,
        spec,
        RunInput { credentials: creds(&[("KEY", "k-123456")]), checkpoints: cps.clone(), ..Default::default() },
        sink.clone(),
        store.clone(),
    )
    .await
    .expect("run");
    for (stream, st) in store.saves.lock().unwrap().iter() {
        cps.insert(stream.clone(), st.clone());
    }
    let got = sink.0.lock().unwrap().clone();
    (out, got)
}

#[tokio::test]
async fn reset_re_anchors_at_now_minus_overlap_and_never_backfills() {
    let t0 = ms("2026-10-12T12:00:00Z");
    // One event per minute from 3 h before t0 to 1 h after it.
    let events: Vec<(String, i64)> = (0..240).map(|i| (format!("e{i}"), t0 - 10_800_000 + i * 60_000)).collect();
    let evs = events.clone();
    let mock = start_mock(
        Arc::new(move |r| {
            let (s, e) = (ms(&r.query["start"]), ms(&r.query["end"]));
            let page: Vec<Value> =
                evs.iter().filter(|(_, ts)| *ts >= s && *ts < e).map(|(uid, ts)| json!({"uid": uid, "ts": iso(*ts)})).collect();
            MockResp::json(json!({ "data": page }))
        }),
        false,
    )
    .await;
    let mut h = harness(&mock);
    let now = Arc::new(Mutex::new(Utc.timestamp_millis_opt(t0).unwrap()));
    let n2 = now.clone();
    h.cfg.clock = Arc::new(move || *n2.lock().unwrap());
    let spec = spec(SPEC);

    // Run 1: no checkpoint, so only the point-forward overlap (5 min,
    // NAN-3697) is read; the cursor is now a watermark at the horizon.
    let mut cps = HashMap::new();
    let (_, first) = run_once(&h, &spec, &mut cps).await;
    assert!(first.len() <= 5, "initial pass reads only the overlap: {}", first.len());
    assert!(cps["events"].pointer("/window/watermark").is_some());

    // Ten minutes later the tenant resets the stream.
    let reset_at = Utc.timestamp_millis_opt(t0 + 600_000).unwrap();
    *now.lock().unwrap() = reset_at;
    let anchor = nano_connector::point_forward::initial_cursor(reset_at);
    assert_eq!(anchor.timestamp_millis(), t0 + 300_000);

    // A 2 h rewind (within the spec's max_backfill_secs of 4 h) is a
    // backfill: refused, never clamped. So is anything before the anchor.
    for back_ms in [7_200_000, 300_001] {
        let since = Utc.timestamp_millis_opt(reset_at.timestamp_millis() - back_ms).unwrap();
        let e = plan_reset(SPEC, "events", Some(since), reset_at).unwrap_err();
        assert!(e.to_string().contains("never backfills"), "{back_ms}: {e}");
    }

    let plan = plan_reset(SPEC, "events", None, reset_at).expect("reset");
    assert_eq!((plan.anchor, plan.max_lookback_secs), (anchor, 300));
    // A since inside [anchor, now] is accepted and does not move the anchor.
    let within = plan_reset(SPEC, "events", Some(Utc.timestamp_millis_opt(t0 + 480_000).unwrap()), reset_at).unwrap();
    assert_eq!(within, plan);
    let before = mock.requests().len();
    cps.insert(plan.stream.clone(), plan.checkpoint.clone());
    let (_, replay) = run_once(&h, &spec, &mut cps).await;

    // The run after the reset starts its first window exactly at the anchor.
    let reqs = mock.requests();
    let first_after_reset = reqs.get(before).expect("the reset run made requests");
    assert_eq!(ms(&first_after_reset.query["start"]), anchor.timestamp_millis());
    assert!(reqs[before..].iter().all(|r| ms(&r.query["start"]) >= anchor.timestamp_millis()), "no request before the anchor");
    // Every event in [anchor, horizon) shipped, none before the anchor.
    let horizon = reset_at.timestamp_millis() - 60_000;
    let expected: Vec<&str> =
        events.iter().filter(|(_, ts)| *ts >= anchor.timestamp_millis() && *ts < horizon).map(|(u, _)| u.as_str()).collect();
    assert_eq!(expected.len(), 4);
    let got: Vec<&str> = replay.iter().map(|e| e["uid"].as_str().unwrap()).collect();
    assert_eq!(got, expected, "exactly [anchor, horizon)");
    // The pass completed (a watermark again, no resume left) and the status
    // shows the re-anchor.
    assert!(cps["events"].pointer("/window/watermark").is_some());
    assert!(cps["events"].pointer("/window/resume").is_none());
    assert_eq!(cps["events"]["point_forward"]["activated_at"], "2026-10-12T12:10:00Z");
    assert_eq!(cps["events"]["point_forward"]["initial_cursor"], "2026-10-12T12:05:00Z");
    assert_eq!(cps["events"]["point_forward"]["overlap_secs"], 300);
}
