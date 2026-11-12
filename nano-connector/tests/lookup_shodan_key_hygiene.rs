// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5090 / Shodan: the official Shodan lookup (`lookups/shodan.yaml`) sends
//! its key as `?key=` in the URL (`api_key_query`). That is the reason Shodan
//! runs on the connector path, not in the wasm sandbox (which only places
//! credentials in headers). Pin that the key, although it rides in the query
//! string, never comes back out: not in the answer, not in any error text a
//! caller, audit record or notebook receives, and not in the request log.

use std::collections::HashMap;
use std::sync::Arc;

use nano_connector::engine::EngineConfig;
use nano_connector::lookup::{execute, official_spec, Artifact, LookupOutcome};
use nano_connector::preview::{Recorded, ReplayTransport};
use serde_json::{json, Value};

const KEY: &str = "shodan-SECRET-key-0123456789";

fn cfg(entries: Vec<Recorded>) -> (EngineConfig, Arc<ReplayTransport>) {
    let t = Arc::new(ReplayTransport::new(entries));
    let mut cfg = EngineConfig::with_sandbox(
        std::path::PathBuf::from("/nonexistent"),
        nano_connector::sandbox::SandboxPolicy::strict(),
        nano_connector::vrl_exec::PoolConfig::default(),
    );
    cfg.transport = Some(t.clone());
    (cfg, t)
}

fn rec(status: u16, body: Value) -> Recorded {
    serde_json::from_value(json!({"host": "api.shodan.io", "path": "/shodan/host/185.220.101.1", "status": status, "body": body}))
        .unwrap()
}

async fn lookup(entries: Vec<Recorded>) -> (LookupOutcome, String) {
    let (cfg, t) = cfg(entries);
    let a = Artifact::parse("185.220.101.1", None).unwrap();
    let creds = HashMap::from([("API_KEY".to_string(), KEY.to_string())]);
    let out = execute(&cfg, &official_spec("shodan").unwrap(), &a, creds, None).await;
    let log = t.log.lock().unwrap().join("\n");
    (out, log)
}

fn assert_clean(what: &str, s: &str) {
    assert!(!s.contains(KEY), "{what} carries the Shodan key: {s}");
    assert!(!s.contains("key=shodan"), "{what} carries the key query value: {s}");
}

#[tokio::test]
async fn the_key_is_sent_in_the_query_but_the_log_keeps_only_its_name() {
    let (out, log) = lookup(vec![rec(200, json!({"ip_str": "185.220.101.1", "ports": [80]}))]).await;
    assert!(matches!(out, LookupOutcome::Answered(_)), "{out:?}");
    // The query keeps parameter NAMES only (`?minify&key`): the key was sent.
    let query = log.split_once("/shodan/host/185.220.101.1?").map(|(_, q)| q).unwrap_or_default();
    assert!(query.split('&').any(|p| p == "key"), "the key param was not sent: {log}");
    assert_clean("request log", &log);
}

#[tokio::test]
async fn a_vendor_echoing_the_key_in_a_success_body_does_not_leak_it_into_the_answer() {
    let body = json!({
        "ip_str": "185.220.101.1", "org": KEY, "ports": [22, 443], "vulns": ["CVE-2021-44228"],
        "tags": [KEY], "hostnames": [format!("https://api.shodan.io/shodan/host/185.220.101.1?key={KEY}")],
    });
    let (out, log) = lookup(vec![rec(200, body)]).await;
    assert_clean("answer", &format!("{out:?}"));
    assert_clean("request log", &log);
}

#[tokio::test]
async fn error_answers_never_carry_the_key() {
    for (status, body) in [
        (500, json!({"error": format!("internal error for request ?key={KEY}")})),
        (502, json!({"error": KEY})),
        (401, json!({"error": format!("Invalid API key {KEY}")})),
        (429, json!({"error": format!("rate limited key={KEY}")})),
    ] {
        let (out, log) = lookup(vec![rec(status, body)]).await;
        assert!(!matches!(out, LookupOutcome::Answered(_)) || status == 404, "{status}: {out:?}");
        assert_clean(&format!("HTTP {status} outcome"), &format!("{out:?}"));
        assert_clean("request log", &log);
    }
}
