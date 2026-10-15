//! NAN-3697: every collector starts point-forward.
//!
//! Per collector spec, with a fake clock:
//!   * no cursor: the first request starts at now − overlap (never earlier),
//!     and the activation is recorded in the stream's checkpoint;
//!   * an existing cursor: the request resumes from it and is never reset,
//!     however old it is;
//!   * a stream that activated but has not advanced keeps its initial cursor
//!     on later runs (no drift forward).

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, TimeZone, Utc};
use common::*;
use nano_connector::engine::RunInput;
use nano_connector::point_forward::{INITIAL_CURSOR_OVERLAP_SECS, POINT_FORWARD_KEY, initial_cursor};
use serde_json::{Value, json};

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 12, 14, 0, 0).unwrap()
}

/// now − 5 min.
fn ic() -> DateTime<Utc> {
    initial_cursor(now())
}

fn pinned(mock: &Mock, at: DateTime<Utc>) -> Harness {
    let h = harness(mock);
    *h.now.lock().unwrap() = at;
    h
}

fn rfc(v: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(v).unwrap_or_else(|e| panic!("{v}: {e}")).with_timezone(&Utc)
}

fn input(creds_: &[(&str, &str)], cfg: Value, cps: HashMap<String, Value>) -> RunInput {
    RunInput { credentials: creds(creds_), config: config(cfg), checkpoints: cps, ..Default::default() }
}

fn assert_activation(slot: &Value) {
    let pf = &slot[POINT_FORWARD_KEY];
    assert_eq!(pf["activated_at"], "2026-10-12T14:00:00Z", "{slot}");
    assert_eq!(pf["initial_cursor"], "2026-10-12T13:55:00Z", "{slot}");
    assert_eq!(pf["overlap_secs"], INITIAL_CURSOR_OVERLAP_SECS, "{slot}");
}

#[test]
fn the_overlap_is_five_minutes() {
    assert_eq!(INITIAL_CURSOR_OVERLAP_SECS, 300);
    assert_eq!(ic(), Utc.with_ymd_and_hms(2026, 10, 12, 13, 55, 0).unwrap());
}

// ------------------------------------------------------------------ Okta --

fn okta_mock() -> Handler {
    Arc::new(|_r: &MockReq| MockResp::json(json!([])))
}

fn okta_input(cps: HashMap<String, Value>) -> RunInput {
    input(&[("API_TOKEN", "00okta")], json!({"OKTA_DOMAIN": "acme.okta.com"}), cps)
}

#[tokio::test]
async fn okta_system_log_starts_at_now_minus_overlap() {
    let mock = start_mock(okta_mock(), false).await;
    let h = pinned(&mock, now());
    let spec = load_spec("okta_system_log.yaml");
    let out = run(&h, &spec, okta_input(HashMap::new())).await.out.expect("run");
    let first = &mock.requests()[0];
    assert_eq!(rfc(&first.query["since"]), ic(), "{:?}", first.query);
    assert!(mock.requests().iter().all(|r| rfc(&r.query["since"]) >= ic()), "never earlier than now − overlap");
    assert_activation(&out.checkpoints["system_log"]);
}

#[tokio::test]
async fn okta_system_log_resumes_an_old_cursor_and_never_resets_it() {
    let mock = start_mock(okta_mock(), false).await;
    let h = pinned(&mock, now());
    let spec = load_spec("okta_system_log.yaml");
    let wm = (now() - Duration::days(2)).timestamp_millis();
    let cps = HashMap::from([("system_log".to_string(), json!({"window": {"watermark": wm}}))]);
    let out = run(&h, &spec, okta_input(cps)).await.out.expect("run");
    // Resumes at the watermark minus the spec's 120 s lookback: two days ago.
    assert_eq!(rfc(&mock.requests()[0].query["since"]).timestamp_millis(), wm - 120_000);
    assert!(out.checkpoints["system_log"].get(POINT_FORWARD_KEY).is_none(), "an existing cursor is not an activation");
}

#[tokio::test]
async fn okta_system_log_activation_does_not_drift_when_the_first_run_fails() {
    let fail = start_mock(Arc::new(|_r: &MockReq| MockResp::status(500, json!({"errorSummary": "down"}))), false).await;
    let h = pinned(&fail, now());
    let mut spec = load_spec("okta_system_log.yaml");
    spec.rate_limit.backoff_ms = 1;
    let r1 = run(&h, &spec, okta_input(HashMap::new())).await;
    assert!(r1.out.is_err());
    let saved: HashMap<String, Value> = r1.store.saves.lock().unwrap().iter().cloned().collect();
    assert_activation(&saved["system_log"]);

    // An hour later the vendor is back: the stream still starts at its
    // recorded initial cursor, not at the new now − overlap.
    let mock = start_mock(okta_mock(), false).await;
    let h = pinned(&mock, now() + Duration::hours(1));
    run(&h, &spec, okta_input(saved)).await.out.expect("run 2");
    assert_eq!(rfc(&mock.requests()[0].query["since"]), ic());
}

// ------------------------------------------------------- Google Workspace --

/// The engine's cursor rule does not depend on auth; swap the service-account
/// plugin for a bearer token so the test needs no token endpoint.
fn gws_spec(file: &str) -> nano_connector::spec::ConnectorSpec {
    let yaml = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/specs").join(file)).unwrap();
    let start = yaml.find("\nauth:").expect("auth block") + 1;
    let end = start + yaml[start..].find("\nschedule:").expect("schedule after auth") + 1;
    let mut s = spec(&format!("{}auth: {{ type: bearer, credential: TOKEN }}\n{}", &yaml[..start], &yaml[end..]));
    s.rate_limit.min_interval_ms = 0;
    s
}

fn gws_input(cps: HashMap<String, Value>) -> RunInput {
    input(&[("TOKEN", "gws-token")], json!({"ADMIN_EMAIL": "admin@example.com", "STREAMS": "login,admin"}), cps)
}

#[tokio::test]
async fn google_workspace_starts_at_now_minus_overlap() {
    let mock = start_mock(Arc::new(|_r: &MockReq| MockResp::json(json!({"items": []}))), false).await;
    let h = pinned(&mock, now());
    let out = run(&h, &gws_spec("google_workspace.yaml"), gws_input(HashMap::new())).await.out.expect("run");
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 2, "one window per application");
    for r in &reqs {
        assert_eq!(rfc(&r.query["startTime"]), ic(), "{:?}", r.query);
    }
    for app in ["login", "admin"] {
        assert_activation(&out.checkpoints["activities"]["items"][app]);
    }
}

#[tokio::test]
async fn google_workspace_resumes_each_application_cursor() {
    let mock = start_mock(Arc::new(|_r: &MockReq| MockResp::json(json!({"items": []}))), false).await;
    let h = pinned(&mock, now());
    let wm = (now() - Duration::hours(30)).timestamp_millis();
    // `login` has an old cursor; `admin` is new (enabled later).
    let cps = HashMap::from([("activities".to_string(), json!({"items": {"login": {"window": {"watermark": wm}}}}))]);
    let out = run(&h, &gws_spec("google_workspace.yaml"), gws_input(cps)).await.out.expect("run");
    let start_of = |app: &str| {
        mock.requests().iter().filter(|r| r.path.ends_with(app)).map(|r| rfc(&r.query["startTime"])).min().unwrap()
    };
    // login: watermark − 600 s lookback, 30 h back; never reset.
    assert_eq!(start_of("login").timestamp_millis(), wm - 600_000);
    assert!(out.checkpoints["activities"]["items"]["login"].get(POINT_FORWARD_KEY).is_none());
    // admin: point-forward.
    assert_eq!(start_of("admin"), ic());
    assert_activation(&out.checkpoints["activities"]["items"]["admin"]);
}

#[tokio::test]
async fn google_workspace_hosted_spec_starts_at_now_minus_overlap() {
    // The hosted spec's 24 h `initial_lookback_secs` does not move the first
    // window either (its DWD auth itself is covered in google_dwd.rs).
    let spec = gws_spec("google_workspace_hosted.yaml");
    assert!(spec.streams[0].window.as_ref().unwrap().initial_lookback_secs > INITIAL_CURSOR_OVERLAP_SECS as u64);
    let mock = start_mock(Arc::new(|_r: &MockReq| MockResp::json(json!({"items": []}))), false).await;
    let h = pinned(&mock, now());
    run(&h, &spec, gws_input(HashMap::new())).await.out.expect("run");
    assert!(!mock.requests().is_empty());
    assert!(mock.requests().iter().all(|r| rfc(&r.query["startTime"]) == ic()), "{:?}", mock.requests());
}

// ----------------------------------------------------------- Slack audit --

fn slack_audit_input(cps: HashMap<String, Value>) -> RunInput {
    input(&[("SLACK_AUDIT_USER_TOKEN", "xoxp-audit")], json!({}), cps)
}

fn slack_audit_spec() -> nano_connector::spec::ConnectorSpec {
    let mut s = load_spec("generated/slack_audit_logs.yaml");
    s.rate_limit.min_interval_ms = 0;
    s
}

#[tokio::test]
async fn slack_audit_logs_starts_at_now_minus_overlap() {
    let mock = start_mock(Arc::new(|_r: &MockReq| MockResp::json(json!({"entries": []}))), false).await;
    let h = pinned(&mock, now());
    let out = run(&h, &slack_audit_spec(), slack_audit_input(HashMap::new())).await.out.expect("run");
    let first = &mock.requests()[0];
    assert_eq!(first.query["oldest"], ic().timestamp().to_string(), "{:?}", first.query);
    assert_activation(&out.checkpoints["audit_logs"]);
}

#[tokio::test]
async fn slack_audit_logs_resumes_an_old_cursor() {
    let mock = start_mock(Arc::new(|_r: &MockReq| MockResp::json(json!({"entries": []}))), false).await;
    let h = pinned(&mock, now());
    let resume = (now() - Duration::days(3)).timestamp_millis();
    let cps = HashMap::from([("audit_logs".to_string(), json!({"window": {"resume": resume}}))]);
    run(&h, &slack_audit_spec(), slack_audit_input(cps)).await.out.expect("run");
    assert_eq!(mock.requests()[0].query["oldest"], (resume / 1000).to_string());
}

// ---------------------------------------------------- Slack access_logs --

fn login(i: usize, date_last: i64) -> Value {
    json!({"user_id": format!("U{i:06}"), "username": "u", "date_first": date_last - 60, "date_last": date_last, "count": 1,
           "ip": "203.0.113.7", "user_agent": "mock", "isp": "x", "country": "CA", "region": "ON"})
}

/// Newest first, as Slack returns them: 3 sign-ins since the initial cursor,
/// then history going back two days.
fn slack_access_mock() -> (Handler, Arc<Mutex<usize>>) {
    let t = now().timestamp();
    let mut all: Vec<Value> = (0..3).map(|i| login(i, t - 60 - i as i64 * 30)).collect();
    all.extend((0..20).map(|i| login(100 + i, t - 400 - i as i64 * 9000)));
    let calls = Arc::new(Mutex::new(0));
    let c = calls.clone();
    let h: Handler = Arc::new(move |r: &MockReq| {
        *c.lock().unwrap() += 1;
        let off: usize = r.query.get("cursor").and_then(|v| v.parse().ok()).unwrap_or(0);
        let page: Vec<Value> = all.iter().skip(off).take(5).cloned().collect();
        let next = if off + 5 < all.len() { (off + 5).to_string() } else { String::new() };
        MockResp::json(json!({"ok": true, "logins": page, "response_metadata": {"next_cursor": next}}))
    });
    (h, calls)
}

fn slack_access_spec() -> nano_connector::spec::ConnectorSpec {
    let mut s = load_spec("slack_access_logs.yaml");
    s.rate_limit.min_interval_ms = 0;
    s
}

fn slack_access_input(cps: HashMap<String, Value>) -> RunInput {
    input(&[("USER_TOKEN", "xoxp-mock")], json!({"TEAM_ID": "T1"}), cps)
}

#[tokio::test]
async fn slack_access_logs_does_not_read_history_without_a_cursor() {
    let (handler, _) = slack_access_mock();
    let mock = start_mock(handler, false).await;
    let h = pinned(&mock, now());
    let r = run(&h, &slack_access_spec(), slack_access_input(HashMap::new())).await;
    let out = r.out.expect("run");
    let shipped = r.sink.events();
    assert_eq!(shipped.len(), 3, "only sign-ins since now − overlap: {shipped:?}");
    assert!(shipped.iter().all(|e| e["date_last"].as_i64().unwrap() >= ic().timestamp()));
    assert_eq!(mock.requests().len(), 1, "stops at the initial cursor instead of paging through history");
    let cp = &out.checkpoints["access_logs"];
    assert_activation(cp);
    assert!(cp["state"]["wm"].as_i64().unwrap() >= ic().timestamp(), "{cp}");
}

#[tokio::test]
async fn slack_access_logs_resumes_an_old_watermark() {
    let (handler, _) = slack_access_mock();
    let mock = start_mock(handler, false).await;
    let h = pinned(&mock, now());
    // A saved watermark from a day ago is resumed, not reset to now.
    let wm = now().timestamp() - 86_400;
    let cps = HashMap::from([("access_logs".to_string(), json!({"state": {"wm": wm}}))]);
    let r = run(&h, &slack_access_spec(), slack_access_input(cps)).await;
    r.out.expect("run");
    let shipped = r.sink.events();
    let want = 3 + (0..20).filter(|i| now().timestamp() - 400 - i * 9000 > wm).count();
    assert_eq!(shipped.len(), want, "every sign-in after the saved watermark");
    assert!(shipped.iter().any(|e| e["date_last"].as_i64().unwrap() < ic().timestamp()), "older than the initial cursor: resumed");
}

#[tokio::test]
async fn slack_access_logs_initial_cursor_is_pinned_across_empty_runs() {
    let empty = start_mock(Arc::new(|_r: &MockReq| MockResp::json(json!({"ok": true, "logins": []}))), false).await;
    let r1 = run(&pinned(&empty, now()), &slack_access_spec(), slack_access_input(HashMap::new())).await;
    let o1 = r1.out.expect("run 1");
    assert_eq!(o1.checkpoints["access_logs"]["state"]["wm"], json!(ic().timestamp()));

    // Two hours later: the 3 recent sign-ins ship, the history before the
    // ORIGINAL initial cursor still does not.
    let (handler, _) = slack_access_mock();
    let mock = start_mock(handler, false).await;
    let r2 = run(&pinned(&mock, now() + Duration::hours(2)), &slack_access_spec(), slack_access_input(o1.checkpoints.clone())).await;
    r2.out.expect("run 2");
    assert_eq!(r2.sink.events().len(), 3);
}

// -------------------------------------------------------------- Netskope --

fn netskope_input(cps: HashMap<String, Value>) -> RunInput {
    input(&[("API_TOKEN", "ns-token")], json!({"TENANT_HOST": "acme.goskope.com", "INDEX_NAME": "nano", "STREAMS": "alert"}), cps)
}

fn netskope_spec() -> nano_connector::spec::ConnectorSpec {
    let mut s = load_spec("netskope.yaml");
    s.rate_limit.min_interval_ms = 0;
    s
}

fn netskope_mock() -> Handler {
    Arc::new(|_r: &MockReq| MockResp::json(json!({"ok": 1, "result": [], "wait_time": 0})))
}

#[tokio::test]
async fn netskope_opens_a_new_iterator_at_now_minus_overlap() {
    let mock = start_mock(netskope_mock(), false).await;
    let h = pinned(&mock, now());
    let out = run(&h, &netskope_spec(), netskope_input(HashMap::new())).await.out.expect("run");
    let first = &mock.requests()[0];
    assert_eq!(first.query["operation"], ic().timestamp().to_string(), "{:?}", first.query);
    let slot = &out.checkpoints["dataexport"]["items"]["alert"];
    assert_activation(slot);
    assert_eq!(slot["state"], json!({"op": "open", "opened": true}));
}

#[tokio::test]
async fn netskope_resumes_an_open_iterator_and_a_pinned_start() {
    // Open iterator: walk on with `next`, never re-open at a new time.
    let mock = start_mock(netskope_mock(), false).await;
    let cps = HashMap::from([("dataexport".to_string(), json!({"items": {"alert": {"state": {"op": "open", "opened": true}}}}))]);
    run(&pinned(&mock, now()), &netskope_spec(), netskope_input(cps)).await.out.expect("run");
    assert_eq!(mock.requests()[0].query["operation"], "next");

    // A start pinned days ago by a run that crashed before the iterator
    // opened: re-open at that start, not at now − overlap.
    let old = (now() - Duration::days(2)).timestamp().to_string();
    let mock = start_mock(netskope_mock(), false).await;
    let cps = HashMap::from([("dataexport".to_string(), json!({"items": {"alert": {"state": {"op": "resend", "start": old}}}}))]);
    run(&pinned(&mock, now()), &netskope_spec(), netskope_input(cps)).await.out.expect("run");
    assert_eq!(mock.requests()[0].query["operation"], old);
}

// ------------------------------------------------- templates and VRL input --

/// A plain (no window, no program) spec reads the rule through
/// `{{initial_cursor}}`; `{{backfill_from}}` is the same value, never an
/// operator backfill.
#[tokio::test]
async fn initial_state_templates_render_the_initial_cursor() {
    let yaml = r#"
version: 1
name: plain
kind: collector
allow: [{ host: api.example.com, path_prefixes: ["/events"] }]
auth: { type: bearer, credential: TOKEN }
streams:
  - id: events
    source_type: plain
    request:
      url: "https://api.example.com/events"
      query: { since: "{{state.since}}", alias: "{{state.alias}}" }
    response: { events_path: data }
    pagination: { type: none }
    ingest_id: { fields: [id] }
    initial_state: { since: "{{initial_cursor}}", alias: "{{backfill_from}}" }
"#;
    let mock = start_mock(Arc::new(|_r: &MockReq| MockResp::json(json!({"data": []}))), false).await;
    let h = pinned(&mock, now());
    let out = run(&h, &spec(yaml), input(&[("TOKEN", "t")], json!({}), HashMap::new())).await.out.expect("run");
    let q = &mock.requests()[0].query;
    assert_eq!(q["since"], "2026-10-12T13:55:00Z");
    assert_eq!(q["alias"], "2026-10-12T13:55:00Z");
    assert_activation(&out.checkpoints["events"]);
}
