//! `validate` / `preview` / `schema` CLI: compile-check every shipped spec and
//! dry-run specs offline against recorded responses.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

fn exe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nano-connector"))
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/specs")
}

fn recordings() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/recordings")
}

#[test]
fn validate_accepts_shipped_specs_and_rejects_bad_vrl() {
    let mut specs: Vec<PathBuf> = std::fs::read_dir(dir()).unwrap().map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|x| x == "yaml")).collect();
    specs.sort();
    let out = exe().arg("validate").args(&specs).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));

    let bad = std::env::temp_dir().join(format!("nc-bad-{}.yaml", std::process::id()));
    std::fs::write(&bad, "version: 1\nname: bad\nkind: collector\nallow: [{host: api.example.com}]\nstreams:\n  - id: s\n    program: 'http_request(\"https://x\")'\n").unwrap();
    let out = exe().arg("validate").arg(&bad).output().unwrap();
    let _ = std::fs::remove_file(&bad);
    assert!(!out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["error"].as_str().unwrap().contains("http_request"), "{v}");
}

#[test]
fn preview_runs_an_agent_enrichment_offline() {
    let out = exe()
        .args(["preview"])
        .arg(dir().join("virustotal.yaml"))
        .arg(recordings().join("virustotal_hash.json"))
        .args(["--cred", "API_KEY=preview-key-1", "--artifact", "44d88612fea8a8f36de82e1278abb02f", "--type", "hash"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["result"]["risk_score"], 86);
    assert_eq!(v["result"]["data"]["threat_label"], "eicar/test");
}

#[test]
fn preview_runs_a_paged_windowed_collector_offline() {
    let out = exe()
        .args(["preview"])
        .arg(dir().join("okta_system_log.yaml"))
        .arg(recordings().join("okta_system_log.json"))
        .args(["--cred", "API_TOKEN=preview-token-1", "--config", "OKTA_DOMAIN=acme.okta.com", "--now", "2026-10-10T11:05:00Z", "--show", "3"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(v["ok"], true, "{v}");
    // Every window replays the same recording; dedupe ships each uuid once.
    assert_eq!(v["events"], 3, "{v}");
    assert!(v["requests"].as_array().unwrap().iter().all(|r| r.as_str().unwrap().contains("https://acme.okta.com/api/v1/logs")));
}

#[test]
fn preview_refuses_a_request_outside_the_allowlist() {
    let out = exe()
        .args(["preview"])
        .arg(dir().join("okta_system_log.yaml"))
        .arg(recordings().join("okta_system_log.json"))
        .args(["--cred", "API_TOKEN=preview-token-1", "--config", "OKTA_DOMAIN=metadata.google.internal"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["ok"], false);
    assert!(v["error"].as_str().unwrap().to_lowercase().contains("host") || v["error"].as_str().unwrap().contains("denied"), "{v}");
}

/// A per-test scratch file under the target dir (the cargo sandbox cannot
/// see /tmp).
fn scratch(name: &str, body: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let p = d.join(format!("{}-{name}", std::process::id()));
    std::fs::write(&p, body).unwrap();
    p
}

#[test]
fn validate_rejects_a_collector_with_no_ingest_id_or_window() {
    let bad = scratch(
        "no-ingest-id.yaml",
        "version: 1\nname: bad\nkind: collector\nallow: [{host: api.example.com}]\nstreams:\n  - id: s\n    source_type: x\n    request: {url: 'https://api.example.com/x'}\n    records: response.items\n",
    );
    let out = exe().arg("validate").arg(&bad).output().unwrap();
    assert!(!out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["error"].as_str().unwrap().contains("ingest_id"), "{v}");
}

#[test]
fn preview_stamps_the_provider_uid_as_nano_ingest_id() {
    let out = exe()
        .args(["preview"])
        .arg(dir().join("okta_system_log.yaml"))
        .arg(recordings().join("okta_system_log.json"))
        .args(["--cred", "API_TOKEN=preview-token-1", "--config", "OKTA_DOMAIN=acme.okta.com", "--now", "2026-10-10T11:05:00Z", "--show", "3"])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["content_hash_ingest_ids"], 0, "{v}");
    let sample = v["sample"].as_array().unwrap();
    assert!(!sample.is_empty(), "{v}");
    for e in sample {
        assert_eq!(e["_nano_ingest_id"], e["uuid"], "okta's ingest id is its uuid: {e}");
    }
}

#[test]
fn shadow_only_talks_to_a_loopback_mock() {
    for url in ["http://10.0.0.1:8080", "https://127.0.0.1:8080", "http://localhost.example:80"] {
        let out = exe()
            .args(["shadow"])
            .arg(dir().join("okta_system_log.yaml"))
            .args(["--mock-url", url, "--cred", "API_TOKEN=t", "--config", "OKTA_DOMAIN=acme.okta.com"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{url}: {}", String::from_utf8_lossy(&out.stdout));
        assert!(String::from_utf8_lossy(&out.stderr).contains("loopback"), "{url}: {}", String::from_utf8_lossy(&out.stderr));
    }
}

#[test]
fn check_uids_rejects_random_and_shared_uids() {
    let events = scratch("events.json", r#"[["x", [{"id": "a"}, {"id": "b"}, {"id": "a", "_nano_ingest_id": "a"}]]]"#);
    let run = |vrl: &str| {
        let parser = scratch(&format!("parser-{}.yaml", vrl.len()), &format!("name: t\nparser_vrl: |\n  {vrl}\n"));
        let out = exe().arg("check-uids").arg(&parser).arg(&events).output().unwrap();
        (out.status.success(), serde_json::from_slice::<Value>(&out.stdout).unwrap_or(Value::Null))
    };
    // The third event is the first again, plus the engine stamp: same uid is fine.
    let (ok, v) = run(r#".metadata.uid = string!(parse_json!(.message).id)"#);
    assert!(ok, "{v}");
    assert_eq!(v["distinct_uids"], 2, "{v}");
    let (ok, v) = run(".metadata.uid = uuid_v4()");
    assert!(!ok, "a random uid must fail: {v}");
    let (ok, v) = run(r#".metadata.uid = "constant""#);
    assert!(!ok, "a shared uid must fail: {v}");
}

#[test]
fn schema_is_emitted() {
    let out = exe().arg("schema").output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v.to_string().contains("google_service_account"));
}
