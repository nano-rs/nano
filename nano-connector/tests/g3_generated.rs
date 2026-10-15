//! G3: a connector generated ONE-SHOT by a fresh agent that had only
//! docs/AUTHORING.md, docs/connector.schema.json and Slack's public docs
//! (tests/fixtures/specs/generated/slack_audit_logs.yaml, committed unedited). Run against a
//! Slack Audit Logs mock built from Slack's documented behaviour: newest
//! first, `oldest`/`latest` epoch-second filters, `limit`, opaque `cursor`,
//! `response_metadata.next_cursor`, user-token Bearer auth.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::*;
use nano_connector::engine::RunInput;
use serde_json::{Value, json};

const TOKEN: &str = "xoxp-g3-audit-token";

fn entry(i: u64, t: i64) -> Value {
    json!({
        "id": format!("0123a45b-6c7d-8e9f-a0b1-{i:012}"),
        "date_create": t,
        "action": if i % 3 == 0 { "user_login" } else { "file_downloaded" },
        "actor": {"type": "user", "user": {"id": format!("W{i:08}"), "name": "mock", "email": "mock@example.com"}},
        "entity": {"type": "workspace", "workspace": {"id": "T0MOCK", "name": "mock", "domain": "mock"}},
        "context": {"location": {"type": "enterprise", "id": "E0MOCK"}, "ua": "Mozilla/5.0 (mock)", "ip_address": "203.0.113.9"}
    })
}

fn audit_mock(entries: Arc<Mutex<Vec<Value>>>, requests: Arc<Mutex<Vec<HashMap<String, String>>>>) -> Handler {
    Arc::new(move |r: &MockReq| {
        if r.headers.get("authorization").map(String::as_str) != Some(&format!("Bearer {TOKEN}")) {
            return MockResp::status(401, json!({"ok": false, "error": "invalid_auth"}));
        }
        if r.host != "api.slack.com" || r.path != "/audit/v1/logs" {
            return MockResp::status(404, json!({"ok": false, "error": "unknown_method"}));
        }
        requests.lock().unwrap().push(r.query.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
        let num = |k: &str| r.query.get(k).and_then(|v| v.parse::<i64>().ok());
        let (oldest, latest) = (num("oldest").unwrap_or(0), num("latest").unwrap_or(i64::MAX));
        let limit = num("limit").unwrap_or(100).clamp(1, 9999) as usize;
        let mut all: Vec<Value> = entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| {
                let t = e["date_create"].as_i64().unwrap();
                t >= oldest && t <= latest
            })
            .cloned()
            .collect();
        all.sort_by(|a, b| b["date_create"].as_i64().cmp(&a["date_create"].as_i64()).then(b["id"].as_str().cmp(&a["id"].as_str())));
        let off: usize = r.query.get("cursor").and_then(|c| c.strip_prefix("Y3Vyc29y")).and_then(|v| v.parse().ok()).unwrap_or(0);
        let page: Vec<Value> = all.iter().skip(off).take(limit).cloned().collect();
        let next = if off + limit < all.len() { format!("Y3Vyc29y{}", off + limit) } else { String::new() };
        MockResp::json(json!({"entries": page, "response_metadata": {"next_cursor": next}}))
    })
}

#[tokio::test]
async fn g3_generated_slack_audit_logs_runs_without_gaps_or_duplicates() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/specs/generated/slack_audit_logs.yaml");
    let spec = spec(&std::fs::read_to_string(&path).expect("generated spec"));
    nano_connector::engine::compile(&spec, &Default::default()).expect("generated spec compiles as written");
    let cred_field = spec.auth.params.get("credential").and_then(Value::as_str).expect("bearer-style credential field").to_string();

    let now = chrono::Utc::now();
    // Point-forward (NAN-3697): a new feed reads from now − 5 min. 1,200
    // entries over [now − 290 s, now − 70 s), several sharing a second, plus
    // 3 h of older history that must never ship.
    let t0 = now.timestamp() - 290;
    let mut all: Vec<Value> = (0..1200u64).map(|i| entry(i, t0 + (i as i64 * 11) / 60)).collect();
    all.extend((0..200u64).map(|i| entry(9000 + i, now.timestamp() - 3 * 3600 + i as i64 * 50)));
    let entries = Arc::new(Mutex::new(all));
    let requests = Arc::new(Mutex::new(vec![]));
    let mock = start_mock(audit_mock(entries.clone(), requests.clone()), false).await;
    let h = harness(&mock);
    *h.now.lock().unwrap() = now;
    let input = |cps: HashMap<String, Value>| RunInput {
        credentials: creds(&[(cred_field.as_str(), TOKEN)]),
        checkpoints: cps,
        ..Default::default()
    };

    let r1 = run(&h, &spec, input(HashMap::new())).await;
    let o1 = r1.out.unwrap_or_else(|e| panic!("run 1: {e}"));
    let shipped: Vec<Value> = r1.sink.events();
    let mut ids: Vec<&str> = shipped.iter().map(|e| e["id"].as_str().unwrap_or("?")).collect();
    let visible = 1200usize; // the in-window entries, all older than the lag
    ids.sort();
    ids.dedup();
    eprintln!("G3 run 1: {} events shipped ({} unique) of {visible}, {} requests", shipped.len(), ids.len(), o1.requests);

    // New entries arrive; a later run ships exactly those.
    {
        let mut e = entries.lock().unwrap();
        for i in 0..25u64 {
            e.push(entry(5000 + i, now.timestamp() + 60 + i as i64));
        }
    }
    *h.now.lock().unwrap() = now + chrono::Duration::minutes(30);
    let r2 = run(&h, &spec, input(o1.checkpoints.clone())).await;
    let o2 = r2.out.unwrap_or_else(|e| panic!("run 2: {e}"));
    eprintln!("G3 run 2: {} events shipped, {} overlap dropped", o2.events, o2.dropped_duplicates);

    assert_eq!(shipped.len(), visible, "run 1 ships every entry once");
    assert_eq!(ids.len(), visible, "no duplicates in run 1");
    assert_eq!(o2.events, 25, "run 2 ships exactly the new entries");
    assert!(r1.sink.batches.lock().unwrap().iter().all(|(st, _)| st == "slack_audit"));
}
