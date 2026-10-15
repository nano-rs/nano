//! G1: shipped Deno scripts vs their spec(+VRL) ports, end to end against the
//! same TLS mocks. Each Deno script runs UNMODIFIED under Deno 2.9.7 with the
//! production auth wrapper (tests/deno/driver.ts); the engine runs the
//! `connector.yaml` that sits next to it in the content repo (NAN-3490: the
//! specs live with the scripts they replace). Emitted events are diffed after
//! normalisation (null == absent, numbers as f64, key order ignored, the
//! engine's `_nano_ingest_id` stamp ignored but required on collectors).
//!
//! Skipped (with a note) when Deno or the content repos are not present.
//! `NANO_G1_HOME` (default `~/.cache/nano-g1`) holds the defaults below:
//!   NANO_DENO              default $NANO_G1_HOME/tools/deno-2.9.7/deno
//!   NANO_ENRICHMENTS_DIR   default $NANO_G1_HOME/repos/nano-enrichments/enrichments
//!   NANO_INTEGRATIONS_DIR  default $NANO_G1_HOME/repos/nano-integrations (repo root)

mod common;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use chrono::{Duration, SecondsFormat, Utc};
use common::*;
use nano_connector::engine::{MemoryStore, RunInput};
use nano_connector::point_forward::initial_cursor;
use serde_json::{Value, json};

// ---------------------------------------------------------------- harness --

struct Env {
    deno: PathBuf,
    enrichments: PathBuf,
    integrations: PathBuf,
    deno_dir: PathBuf,
}

fn path_var(var: &str, default: PathBuf) -> PathBuf {
    std::env::var_os(var).map(PathBuf::from).unwrap_or(default)
}

fn env() -> Option<Env> {
    let base = std::env::var_os("NANO_G1_HOME").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".cache/nano-g1")
    });
    let e = Env {
        deno: path_var("NANO_DENO", base.join("tools/deno-2.9.7/deno")),
        enrichments: path_var("NANO_ENRICHMENTS_DIR", base.join("repos/nano-enrichments/enrichments")),
        integrations: path_var("NANO_INTEGRATIONS_DIR", base.join("repos/nano-integrations")),
        deno_dir: base.join("deno-dir"),
    };
    let markers = [
        e.deno.clone(),
        e.enrichments.join("agent/virustotal/connector.yaml"),
        e.integrations.join("integrations/okta_system_log/connector.yaml"),
    ];
    for p in &markers {
        if !p.exists() {
            eprintln!("G1 SKIPPED: {} not found (see the header of tests/g1_compat.rs)", p.display());
            return None;
        }
    }
    Some(e)
}

/// `<content dir>/connector.yaml`: `integrations/<slug>` or `agent|data/<dir>`.
fn content_spec(e: &Env, rel: &str) -> nano_connector::spec::ConnectorSpec {
    let path = if let Some(slug) = rel.strip_prefix("integrations/") {
        e.integrations.join("integrations").join(slug).join("connector.yaml")
    } else {
        e.enrichments.join(rel).join("connector.yaml")
    };
    spec(&std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display())))
}

/// Every collector event carries the engine's `_nano_ingest_id` stamp.
fn assert_ingest_ids(label: &str, events: &[Value]) {
    // `h:` is the engine's content-hash fallback: the vendor id was missing.
    let missing = events.iter().filter(|e| e[nano_connector::engine::INGEST_ID_FIELD].as_str().is_none_or(|v| v.is_empty() || v.starts_with("h:"))).count();
    assert_eq!(missing, 0, "{label}: {missing} of {} events lack a vendor _nano_ingest_id", events.len());
}

fn tmp(name: &str, content: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("g1");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(format!("{}-{}-{name}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    std::fs::write(&p, content).unwrap();
    p
}

fn deno_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/deno")
}

fn file_url(p: &Path) -> String {
    format!("file://{}", p.display())
}

/// Run a shipped script under the Deno driver against `mock`.
async fn deno(e: &Env, mock: &Mock, mut input: Value) -> Value {
    input["mock_port"] = json!(mock.port);
    let ca = tmp("ca.pem", &mock.pki.ca_pem);
    let inp = tmp("input.json", &input.to_string());
    let out = tokio::process::Command::new(&e.deno)
        .args(["run", "--quiet", "--no-prompt", "--allow-net=127.0.0.1", "--allow-read"])
        .arg(deno_dir().join("driver.ts"))
        .arg(&inp)
        .env("DENO_CERT", &ca)
        .env("DENO_NO_UPDATE_CHECK", "1")
        .env("DENO_DIR", &e.deno_dir)
        .output()
        .await
        .expect("spawn deno");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "deno failed: {}\n{}", stdout, String::from_utf8_lossy(&out.stderr));
    let line = stdout.lines().rev().find(|l| l.starts_with('{')).unwrap_or_else(|| panic!("no deno output: {stdout}"));
    let v: Value = serde_json::from_str(line).unwrap();
    assert!(v.get("error").is_none(), "deno script error: {v}");
    v
}

fn deno_emits(v: &Value) -> HashMap<String, Vec<Value>> {
    let mut m: HashMap<String, Vec<Value>> = HashMap::new();
    for e in v["emits"].as_array().cloned().unwrap_or_default() {
        m.entry(e[0].as_str().unwrap().to_string()).or_default().extend(e[1].as_array().cloned().unwrap_or_default());
    }
    m
}

fn strip(v: &Value, keys: &[&str]) -> Value {
    match v {
        Value::Object(m) => Value::Object(m.iter().filter(|(k, _)| !keys.contains(&k.as_str())).map(|(k, v)| (k.clone(), strip(v, keys))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(|x| strip(x, keys)).collect()),
        o => o.clone(),
    }
}

/// Key-order-independent canonical text.
fn canon(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let sorted: BTreeMap<_, _> = m.iter().collect();
            format!("{{{}}}", sorted.iter().map(|(k, v)| format!("{}:{}", json!(k), canon(v))).collect::<Vec<_>>().join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(canon).collect::<Vec<_>>().join(",")),
        o => o.to_string(),
    }
}

/// Assert both sides emitted the same multiset of events.
fn same_events(label: &str, deno: &[Value], engine: &[Value], ignore: &[&str]) -> usize {
    // `_nano_ingest_id` is the engine's own ingest stamp (Deno had none).
    let ignore: Vec<&str> = ignore.iter().copied().chain([nano_connector::engine::INGEST_ID_FIELD]).collect();
    let c = |v: &[Value]| {
        let mut x: Vec<String> = v.iter().map(|e| canon(&normalize(&strip(e, &ignore)))).collect();
        x.sort();
        x
    };
    let (a, b) = (c(deno), c(engine));
    if a != b {
        let only_d: Vec<_> = a.iter().filter(|x| !b.contains(x)).take(2).collect();
        let only_e: Vec<_> = b.iter().filter(|x| !a.contains(x)).take(2).collect();
        panic!("G1 {label}: deno {} vs engine {} events differ\n deno-only: {only_d:#?}\n engine-only: {only_e:#?}", a.len(), b.len());
    }
    eprintln!("G1 {label}: {} events identical", a.len());
    a.len()
}

fn iso(t: chrono::DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

// ------------------------------------------------------ enrichment mocks --

fn enrichment_vendor(r: &MockReq) -> MockResp {
    let form: HashMap<String, String> = url::form_urlencoded::parse(&r.body).into_owned().collect();
    match (r.host.as_str(), r.path.as_str()) {
        ("www.virustotal.com", p) if r.headers.get("x-apikey").map(String::as_str) == Some("vt-key-123456") => {
            let attrs = |extra: Value| {
                let mut a = json!({
                    "last_analysis_stats": {"malicious": 12, "suspicious": 3, "undetected": 50, "harmless": 5},
                    "tags": ["peexe", "signed"], "reputation": -20, "categories": {"Forcepoint": "malicious"},
                    "popular_threat_classification": {"suggested_threat_label": "trojan.emotet/x"},
                    "last_analysis_date": 1_760_000_000,
                });
                a.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
                MockResp::json(json!({"data": {"attributes": a}}))
            };
            let url_id = base64::engine::general_purpose::STANDARD.encode("http://evil.example/x?y=1").trim_end_matches('=').to_string();
            if p == "/api/v3/files/44d88612fea8a8f36de82e1278abb02f" {
                attrs(json!({"type_description": "Win32 EXE", "size": 68, "names": ["a.exe", "b.exe", "c.exe", "d.exe", "e.exe", "f.exe"]}))
            } else if p == "/api/v3/domains/evil.example" {
                attrs(json!({"registrar": "Mock Registrar", "creation_date": 1_600_000_000, "whois": "w".repeat(700)}))
            } else if p == "/api/v3/ip_addresses/198.51.100.7" {
                attrs(json!({"country": "NL", "as_owner": "Mock AS", "network": "198.51.100.0/24"}))
            } else if p == format!("/api/v3/urls/{url_id}") {
                attrs(json!({"tags": []}))
            } else {
                MockResp::status(404, json!({"error": {"code": "NotFoundError"}}))
            }
        }
        ("api.abuseipdb.com", "/api/v2/check") if r.headers.get("key").map(String::as_str) == Some("abuse-key-123456") => MockResp::json(json!({"data": {
            "ipAddress": r.query.get("ipAddress"), "abuseConfidenceScore": 87, "totalReports": 14, "countryCode": "NL",
            "isp": "Mock ISP", "domain": "mock.example", "usageType": "Data Center/Web Hosting/Transit", "isTor": true,
            "isWhitelisted": false, "lastReportedAt": "2026-10-09T12:00:00+00:00"
        }})),
        ("api.shodan.io", p) if r.query.get("key").map(String::as_str) == Some("shodan-key-123456") => {
            if p == "/dns/resolve" {
                let h = r.query.get("hostnames").cloned().unwrap_or_default();
                MockResp::json(json!({ h.clone(): if h == "evil.example" { json!("198.51.100.9") } else { Value::Null } }))
            } else if p == "/shodan/host/198.51.100.7" || p == "/shodan/host/198.51.100.9" {
                MockResp::json(json!({"ip_str": &p[13..], "hostnames": ["evil.example"], "country_code": "NL", "city": "Amsterdam",
                    "org": "Mock Org", "isp": "Mock ISP", "os": null, "ports": [22, 80, 443, 3389], "vulns": ["CVE-2024-0001", "CVE-2024-0002"],
                    "tags": ["cloud"], "last_update": "2026-10-09T00:00:00.000000"}))
            } else {
                MockResp::status(404, json!({"error": "No information available for that IP."}))
            }
        }
        ("api.greynoise.io", p) if r.headers.get("key").map(String::as_str) == Some("gn-key-123456") => {
            if p == "/v3/community/198.51.100.7" {
                MockResp::json(json!({"ip": "198.51.100.7", "noise": true, "riot": false, "classification": "malicious",
                    "name": "unknown", "link": "https://viz.greynoise.io/ip/198.51.100.7", "last_seen": "2026-10-09", "message": "Success"}))
            } else {
                MockResp::status(404, json!({"message": "IP not observed scanning the internet or contained in RIOT data set."}))
            }
        }
        ("otx.alienvault.com", "/api/v1/indicators/domain/evil.example/general") if r.headers.get("x-otx-api-key").map(String::as_str) == Some("otx-key-123456") => {
            let pulses: Vec<Value> = (0..7).map(|i| json!({"name": format!("pulse {i}"), "created": "2026-10-01T00:00:00", "tags": ["c2"], "id": i})).collect();
            MockResp::json(json!({"pulse_info": {"count": 7, "pulses": pulses}, "reputation": 0, "country_code": null}))
        }
        ("urlhaus-api.abuse.ch", "/v1/url/") if form.get("url").map(String::as_str) == Some("http://evil.example/x") => MockResp::json(json!({
            "query_status": "ok", "threat": "malware_download", "url_status": "online", "tags": ["elf", "mirai"],
            "blacklists": {"spamhaus_dbl": "abused_legit_malware", "surbl": "not listed"}, "date_added": "2026-10-01 00:00:00 UTC",
            "host": "evil.example"
        })),
        ("urlhaus-api.abuse.ch", "/v1/host/") if form.get("host").map(String::as_str) == Some("evil.example") => MockResp::json(json!({
            "query_status": "ok", "url_count": 3, "urls_online": 1, "blacklists": {"spamhaus_dbl": "not listed"}, "host": "evil.example"
        })),
        ("urlhaus-api.abuse.ch", _) => MockResp::json(json!({"query_status": "no_results"})),
        ("mb-api.abuse.ch", "/api/v1/") if form.get("query").map(String::as_str) == Some("get_info") => {
            if form.get("hash").map(String::as_str) == Some("44d88612fea8a8f36de82e1278abb02f") {
                MockResp::json(json!({"query_status": "ok", "data": [{
                    "sha256_hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "sha1_hash": "3395856ce81f2b7382dee72602f798b642f14140",
                    "md5_hash": "44d88612fea8a8f36de82e1278abb02f", "file_type": "exe", "file_type_mime": "application/x-dosexec", "file_size": 68,
                    "signature": "Emotet", "reporter": "mock", "first_seen": "2026-10-01 00:00:00", "last_seen": null, "delivery_method": "email_attachment",
                    "tags": ["exe", "emotet"], "intelligence": {"clamav": ["Win.Test.EICAR_HDB-1"], "downloads": "10"}
                }]}))
            } else {
                MockResp::json(json!({"query_status": "hash_not_found"}))
            }
        }
        ("threatfox-api.abuse.ch", "/api/v1/") => {
            let b: Value = serde_json::from_slice(&r.body).unwrap_or_default();
            assert_eq!(b["query"], "get_iocs");
            let days = b["days"].as_i64().unwrap_or(0);
            MockResp::json(json!({"query_status": "ok", "data": [
                {"ioc": "198.51.100.20:443", "ioc_type": "ip:port", "threat_type": "botnet_cc", "malware": "win.cobalt_strike", "confidence_level": 100,
                 "reporter": "mock", "reference": null, "first_seen_utc": "2026-10-09 00:00:00", "last_seen_utc": null, "tags": ["cs"]},
                {"ioc": "[2001:db8::7]:8443", "ioc_type": "ip:port", "threat_type": "botnet_cc", "malware": "elf.mirai", "confidence_level": 60,
                 "reporter": "mock", "reference": "https://example.org/r", "first_seen_utc": "2026-10-09 00:00:00", "last_seen_utc": null, "tags": null},
                {"ioc": format!("days{days}.evil.example"), "ioc_type": "domain", "threat_type": "payload_delivery", "malware": "js.socgholish", "confidence_level": 40,
                 "reporter": "mock", "reference": null, "first_seen_utc": "2026-10-09 00:00:00", "last_seen_utc": null, "tags": ["fakeupdate"]},
                {"ioc": "", "ioc_type": "domain", "threat_type": "x", "malware": "y", "confidence_level": 10},
                {"ioc_type": "url", "threat_type": "x"}
            ]}))
        }
        ("check.torproject.org", "/torbulkexitlist") => MockResp::text("# exit list\n198.51.100.30\n198.51.100.31\n\n  198.51.100.32  \n"),
        _ => MockResp::status(401, json!({"error": "mock: bad auth or unknown route"})),
    }
}

// ---------------------------------------------------------------- G1: agent --

/// Every shipped agent enrichment (7 scripts, 15 artifacts incl. not-found
/// paths): Deno result == engine result.
#[tokio::test]
async fn g1_agent_enrichments_match_deno() {
    let Some(e) = env() else { return };
    let mock = start_mock(Arc::new(enrichment_vendor), false).await;
    let h = harness(&mock);
    let cases: &[(&str, &str, &str, &str, (&str, &str))] = &[
        ("virustotal", "virustotal", "44d88612fea8a8f36de82e1278abb02f", "hash", ("API_KEY", "vt-key-123456")),
        ("virustotal", "virustotal", "evil.example", "domain", ("API_KEY", "vt-key-123456")),
        ("virustotal", "virustotal", "198.51.100.7", "ip", ("API_KEY", "vt-key-123456")),
        ("virustotal", "virustotal", "http://evil.example/x?y=1", "url", ("API_KEY", "vt-key-123456")),
        ("virustotal", "virustotal", "00000000000000000000000000000000", "hash", ("API_KEY", "vt-key-123456")),
        ("abuseipdb", "abuseipdb", "198.51.100.7", "ip", ("API_KEY", "abuse-key-123456")),
        ("shodan", "shodan", "198.51.100.7", "ip", ("API_KEY", "shodan-key-123456")),
        ("shodan", "shodan", "evil.example", "domain", ("API_KEY", "shodan-key-123456")),
        ("shodan", "shodan", "nothing.example", "domain", ("API_KEY", "shodan-key-123456")),
        ("greynoise", "greynoise", "198.51.100.7", "ip", ("API_KEY", "gn-key-123456")),
        ("greynoise", "greynoise", "198.51.100.8", "ip", ("API_KEY", "gn-key-123456")),
        ("otx", "otx", "evil.example", "domain", ("API_KEY", "otx-key-123456")),
        ("urlhaus", "urlhaus", "http://evil.example/x", "url", ("API_KEY", "unused-123456")),
        ("urlhaus", "urlhaus", "evil.example", "domain", ("API_KEY", "unused-123456")),
        ("urlhaus", "urlhaus", "clean.example", "domain", ("API_KEY", "unused-123456")),
        ("malwarebazaar", "malwarebazaar", "44d88612fea8a8f36de82e1278abb02f", "hash", ("API_KEY", "unused-123456")),
        ("malwarebazaar", "malwarebazaar", "ffffffffffffffffffffffffffffffff", "hash", ("API_KEY", "unused-123456")),
    ];
    for (spec_name, dir, artifact, typ, (ck, cv)) in cases {
        let d = deno(&e, &mock, json!({
            "script": file_url(&e.enrichments.join("agent").join(dir).join("code.ts")),
            "kind": "agent", "artifact": artifact, "artifact_type": typ, "credentials": {*ck: cv},
        }))
        .await;
        let spec = content_spec(&e, &format!("agent/{dir}"));
        let r = run(&h, &spec, RunInput { credentials: creds(&[(ck, cv)]), artifact: Some((artifact.to_string(), typ.to_string())), ..Default::default() }).await;
        let out = r.out.unwrap_or_else(|err| panic!("{spec_name} {artifact}: {err}"));
        same_events(&format!("{spec_name}/{typ} {artifact}"), &[d["result"].clone()], &[out.result.unwrap()], &[]);
    }
}

// ----------------------------------------------------------------- G1: data --

#[tokio::test]
async fn g1_data_enrichments_match_deno() {
    let Some(e) = env() else { return };
    let mock = start_mock(Arc::new(enrichment_vendor), false).await;
    let h = harness(&mock);
    for (spec_name, dir, wm) in [
        ("threatfox", "threatfox", None),
        ("threatfox", "threatfox", Some("2026-10-09T00:00:00.000Z")),
        ("tor_exit_nodes", "tor-exit-nodes", None),
    ] {
        let d = deno(&e, &mock, json!({
            "script": file_url(&e.enrichments.join("data").join(dir).join("code.ts")),
            "kind": "data", "credentials": {"API_KEY": "tf-key-123456"}, "last_watermark": wm,
        }))
        .await;
        let spec = content_spec(&e, &format!("data/{dir}"));
        let mut cps = HashMap::new();
        if let Some(w) = wm {
            cps.insert(spec.streams[0].id.clone(), json!({"state": {"watermark": w}}));
        }
        let r = run(&h, &spec, RunInput { credentials: creds(&[("API_KEY", "tf-key-123456")]), checkpoints: cps, ..Default::default() }).await;
        let res = r.out.unwrap_or_else(|err| panic!("{spec_name}: {err}")).result.unwrap();
        assert!(res["watermark"].is_string(), "{spec_name}: watermark advanced");
        let n = same_events(
            &format!("{spec_name} (watermark {wm:?})"),
            d["result"]["records"].as_array().unwrap(),
            res["records"].as_array().unwrap(),
            &["fetched_at"],
        );
        assert!(n > 0);
    }
}

// --------------------------------------------------------------- G1: Okta --

struct DenoServer(tokio::process::Child);
impl Drop for DenoServer {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

/// The shipped NAN-3483 MockOkta, served by Deno over TLS.
async fn okta_mock(e: &Env, events: usize, users: usize) -> (DenoServer, Mock) {
    use tokio::io::AsyncBufReadExt;
    let pki = Arc::new(pki(MOCK_NAMES));
    let cfg = tmp("okta.json", &json!({
        "mock_module": file_url(&e.integrations.join("testing/okta-mock/mock.ts")),
        "cert_pem": pki.leaf_cert_pem, "key_pem": pki.leaf_key_pem,
        "events": events, "users": users, "page_max": 200, "shift_ms": 60_000,
    }).to_string());
    let mut child = tokio::process::Command::new(&e.deno)
        .args(["run", "--quiet", "--no-prompt", "--allow-net=127.0.0.1", "--allow-read"])
        .arg(deno_dir().join("okta_mock_server.ts"))
        .arg(&cfg)
        .env("DENO_NO_UPDATE_CHECK", "1")
        .env("DENO_DIR", &e.deno_dir)
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn okta mock");
    let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
    let line = tokio::time::timeout(std::time::Duration::from_secs(30), lines.next_line()).await.expect("okta mock start").unwrap().unwrap();
    let port = serde_json::from_str::<Value>(&line).unwrap()["port"].as_u64().unwrap() as u16;
    (DenoServer(child), external_mock(port, pki))
}

/// Append events to the Deno MockOkta through its local control endpoint
/// (test-only loopback call, so certificate checks are skipped).
async fn okta_append(mock: &Mock, n: usize) {
    let st = tokio::process::Command::new("curl")
        .args(["-sSfk", "-o", "/dev/null", "-X", "POST", "-d"])
        .arg(json!({"append": n}).to_string())
        .arg(format!("https://127.0.0.1:{}/__mock/mode", mock.port))
        .status()
        .await
        .expect("curl");
    assert!(st.success());
}

#[tokio::test]
async fn g1_okta_system_log_and_users() {
    let Some(e) = env() else { return };
    // The mock publishes its history ~60 s behind the wall clock, inside the
    // point-forward window (NAN-3697).
    let (_srv, mock) = okta_mock(&e, 2500, 450).await;
    let h = harness(&mock);
    let now = *h.now.lock().unwrap();

    // Deno: the shipped collector, cursor-less first run from the host's
    // point-forward initial cursor.
    let d = deno(&e, &mock, json!({
        "script": file_url(&e.integrations.join("integrations/okta_system_log/code.ts")),
        "kind": "collector", "credentials": {"API_TOKEN": "mock-token"}, "config": {"OKTA_DOMAIN": "acme.okta.com"},
        "streams": ["system_log"], "initial_cursor": iso(initial_cursor(now)),
    }))
    .await;
    let deno_events = deno_emits(&d).remove("system_log").unwrap_or_default();

    // Engine: same mock, same clock.
    let spec = content_spec(&e, "integrations/okta_system_log");
    let input = |cps: HashMap<String, Value>| RunInput {
        credentials: creds(&[("API_TOKEN", "mock-token")]),
        config: config(json!({"OKTA_DOMAIN": "acme.okta.com"})),
        checkpoints: cps,
        ..Default::default()
    };
    let r1 = run(&h, &spec, input(HashMap::new())).await;
    let o1 = r1.out.expect("okta run 1");
    let n = same_events("okta_system_log first run", &deno_events, &r1.sink.events(), &[]);
    assert_ingest_ids("okta_system_log", &r1.sink.events());
    assert!(r1.sink.events().iter().all(|ev| ev["_nano_ingest_id"] == ev["uuid"]), "okta ingest id is the event uuid");
    assert_eq!(n, 2500);
    assert!(r1.sink.batches.lock().unwrap().iter().all(|(st, _)| st == "okta"));

    // Restart with the committed checkpoint: the lookback re-read is deduped.
    // (Engine clock = wall clock; the mock publishes 60 s behind it, past
    // the spec's 30 s lag.)
    *h.now.lock().unwrap() = Utc::now();
    let r2 = run(&h, &spec, input(o1.checkpoints.clone())).await;
    let o2 = r2.out.expect("okta run 2");
    assert_eq!(o2.events, 0, "nothing new: no duplicates across restart");

    // New events arrive; the next run ships exactly those.
    okta_append(&mock, 300).await;
    *h.now.lock().unwrap() = Utc::now();
    let r3 = run(&h, &spec, input(o2.checkpoints.clone())).await;
    let o3 = r3.out.expect("okta run 3");
    assert_eq!(o3.events, 300, "exactly the appended events");
    let mut uids: Vec<String> = r1.sink.events().iter().chain(r3.sink.events().iter()).map(|e| e["uuid"].as_str().unwrap().to_string()).collect();
    let total = uids.len();
    uids.sort();
    uids.dedup();
    assert_eq!(uids.len(), total, "no uid shipped twice across three runs");
    eprintln!("G1 okta_system_log: 2500 + 0 + 300 events over 3 runs, {} overlap rows dropped", o2.dropped_duplicates + o3.dropped_duplicates);

    // Okta users (directory): engine-only (no Deno original), link paging.
    let users = content_spec(&e, "integrations/okta_users");
    let ru = run(&h, &users, input(HashMap::new())).await;
    let ou = ru.out.expect("okta users");
    assert_eq!(ou.events, 450);
    assert_eq!(ou.pages, 3);
    let shipped = ru.sink.events();
    assert_ingest_ids("okta_users", &shipped);
    assert!(shipped.iter().all(|u| u["kind"] == "identity" && u["source"] == "okta" && u["id"].is_string()), "identity-lane records");
    assert!(ru.sink.batches.lock().unwrap().iter().all(|(st, _)| st == "nano_enrich"));
    eprintln!("G1 okta_users: 450 users in 3 pages, as nano_enrich identity records");
}

// ------------------------------------------------------ G1: Google Workspace --

struct Gws {
    apps: Mutex<BTreeMap<String, Vec<Value>>>,
    public_key: Vec<u8>,
    tokens: Counter,
}

fn gws_event(app: &str, i: usize, t: chrono::DateTime<Utc>) -> Value {
    json!({
        "kind": "admin#reports#activity",
        "id": {"time": iso(t), "uniqueQualifier": format!("{}{:06}", app.len(), i), "applicationName": app, "customerId": "C0mock"},
        "actor": {"email": format!("user{}@example.com", i % 17), "profileId": format!("1{:08}", i % 17)},
        "ipAddress": format!("203.0.113.{}", i % 250 + 1),
        "events": [{"type": app, "name": if i % 5 == 0 { "login_failure" } else { "login_success" }}]
    })
}

fn gws_handler(g: Arc<Gws>) -> Handler {
    Arc::new(move |r: &MockReq| {
        use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        if r.host == "oauth2.googleapis.com" && r.path == "/token" {
            let form: HashMap<String, String> = url::form_urlencoded::parse(&r.body).into_owned().collect();
            let Some(jwt) = form.get("assertion") else { return MockResp::status(400, json!({"error": "invalid_request"})) };
            let parts: Vec<&str> = jwt.split('.').collect();
            let ok = parts.len() == 3
                && form.get("grant_type").map(String::as_str) == Some("urn:ietf:params:oauth:grant-type:jwt-bearer")
                && b64.decode(parts[2]).ok().is_some_and(|sig| {
                    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &g.public_key)
                        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
                        .is_ok()
                });
            let claims: Value = b64.decode(parts.get(1).unwrap_or(&"")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
            if !ok
                || claims["iss"] != "svc@mock-project.iam.gserviceaccount.com"
                || claims["sub"] != "admin@example.com"
                || claims["aud"] != "https://oauth2.googleapis.com/token"
                || claims["scope"] != "https://www.googleapis.com/auth/admin.reports.audit.readonly"
            {
                return MockResp::status(400, json!({"error": "invalid_grant", "claims": claims}));
            }
            let n = g.tokens.inc();
            return MockResp::json(json!({"access_token": format!("ya29.mock-{n}"), "expires_in": 3600, "token_type": "Bearer"}));
        }
        if !r.headers.get("authorization").is_some_and(|a| a.starts_with("Bearer ya29.mock-")) {
            return MockResp::status(401, json!({"error": {"code": 401, "message": "Invalid Credentials"}}));
        }
        let prefix = "/admin/reports/v1/activity/users/all/applications/";
        let Some(app) = r.path.strip_prefix(prefix) else { return MockResp::status(404, json!({})) };
        let ms = |k: &str| r.query.get(k).and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok()).map(|t| t.timestamp_millis());
        let (start, end) = (ms("startTime").unwrap_or(0), ms("endTime").unwrap_or(i64::MAX));
        let apps = g.apps.lock().unwrap();
        let Some(all) = apps.get(app) else { return MockResp::status(400, json!({"error": {"message": "Invalid value for applicationName"}})) };
        // Newest first; startTime inclusive, endTime exclusive.
        let mut matching: Vec<&Value> = all
            .iter()
            .filter(|e| {
                let t = chrono::DateTime::parse_from_rfc3339(e["id"]["time"].as_str().unwrap()).unwrap().timestamp_millis();
                t >= start && t < end
            })
            .collect();
        matching.sort_by(|a, b| b["id"]["time"].as_str().cmp(&a["id"]["time"].as_str()).then(b["id"]["uniqueQualifier"].as_str().cmp(&a["id"]["uniqueQualifier"].as_str())));
        let page = 100usize.min(r.query.get("maxResults").and_then(|v| v.parse().ok()).unwrap_or(1000));
        let off: usize = r.query.get("pageToken").and_then(|t| t.strip_prefix("pt-")).and_then(|v| v.parse().ok()).unwrap_or(0);
        let items: Vec<&Value> = matching.iter().skip(off).take(page).copied().collect();
        let mut body = json!({"kind": "admin#reports#activities", "items": items});
        if off + page < matching.len() {
            body["nextPageToken"] = json!(format!("pt-{}", off + page));
        }
        if items.is_empty() {
            body.as_object_mut().unwrap().remove("items");
        }
        MockResp::json(body)
    })
}

#[tokio::test]
async fn g1_google_workspace_fanout() {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::signature::KeyPair as _;
    let Some(e) = env() else { return };
    let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let pkcs8 = key.as_der().unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref());
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\n")
    );
    let now = Utc::now();
    // Point-forward (NAN-3697): a new feed reads [now − 5 min, now − lag).
    // Everything the first run must ship sits inside that; one older event
    // per app must never ship.
    let base = now - Duration::seconds(70);
    let mut apps = BTreeMap::new();
    for (app, n) in [("login", 260usize), ("admin", 140), ("token", 75)] {
        // Pairs share an instant (the inclusive-boundary case) 1 s apart.
        let mut evs: Vec<Value> = (0..n).map(|i| gws_event(app, i, base - Duration::seconds((i / 2) as i64))).collect();
        evs.push(gws_event(app, 800_000, now - Duration::hours(2)));
        apps.insert(app.to_string(), evs);
    }
    let g = Arc::new(Gws { apps: Mutex::new(apps), public_key: key.public_key().as_ref().to_vec(), tokens: Counter::default() });
    let mock = start_mock(gws_handler(g.clone()), false).await;
    let cred_pairs = [("PRIVATE_KEY", pem.as_str()), ("CLIENT_EMAIL", "svc@mock-project.iam.gserviceaccount.com")];

    let d = deno(&e, &mock, json!({
        "script": file_url(&e.integrations.join("integrations/google_workspace/code.ts")),
        "kind": "collector",
        "auth": {"type": "service_account_jwt", "token_url": "https://oauth2.googleapis.com/token", "private_key": pem,
                 "client_email": "svc@mock-project.iam.gserviceaccount.com", "subject": "admin@example.com",
                 "scope": "https://www.googleapis.com/auth/admin.reports.audit.readonly"},
        "credentials": {"PRIVATE_KEY": pem, "CLIENT_EMAIL": "svc@mock-project.iam.gserviceaccount.com"},
        "config": {"ADMIN_EMAIL": "admin@example.com"},
        "streams": ["login", "admin", "token"], "initial_cursor": iso(initial_cursor(now)),
    }))
    .await;
    let deno_by_app = deno_emits(&d);

    let h = harness(&mock);
    *h.now.lock().unwrap() = now;
    let spec = content_spec(&e, "integrations/google_workspace");
    let input = |cps: HashMap<String, Value>| RunInput {
        credentials: creds(&cred_pairs),
        config: config(json!({"ADMIN_EMAIL": "admin@example.com", "STREAMS": "login,admin,token"})),
        checkpoints: cps,
        ..Default::default()
    };
    let tokens_before = g.tokens.get();
    let r1 = run(&h, &spec, input(HashMap::new())).await;
    let o1 = r1.out.expect("gws run 1");
    assert_eq!(g.tokens.get() - tokens_before, 1, "one cached token shared by the fan-out");
    let mut by_type: HashMap<String, Vec<Value>> = HashMap::new();
    for (st, evs) in r1.sink.batches.lock().unwrap().iter() {
        by_type.entry(st.clone()).or_default().extend(evs.iter().cloned());
    }
    for app in ["login", "admin", "token"] {
        let n = same_events(
            &format!("google_workspace/{app}"),
            deno_by_app.get(app).map(Vec::as_slice).unwrap_or_default(),
            by_type.get(&format!("gws_{app}")).map(Vec::as_slice).unwrap_or_default(),
            &[],
        );
        assert_eq!(n, by_type[&format!("gws_{app}")].len());
        assert!(by_type[&format!("gws_{app}")].iter().all(|ev| ev["id"]["uniqueQualifier"] != json!(format!("{}{:06}", app.len(), 800_000))), "history before the initial cursor never ships");
        assert!(n > 0);
    }
    assert_ingest_ids("google_workspace", &r1.sink.events());
    let cp = &o1.checkpoints["activities"];
    assert!(cp["items"]["login"].is_object() && cp["items"]["token"].is_object(), "per-application checkpoints: {cp}");

    // Restart: the lookback re-reads the tail, all deduped.
    *h.now.lock().unwrap() += Duration::minutes(10);
    let r2 = run(&h, &spec, input(o1.checkpoints.clone())).await;
    let o2 = r2.out.expect("gws run 2");
    assert_eq!(o2.events, 0);

    // Late arrivals: 4 login events surface after run 2 with times BEFORE its
    // committed watermark (now0+9m) but inside the 10-minute lookback. The
    // next run ships exactly those.
    {
        let mut apps = g.apps.lock().unwrap();
        let login = apps.get_mut("login").unwrap();
        for i in 0..4 {
            login.push(gws_event("login", 900_000 + i, now + Duration::minutes(4)));
        }
    }
    *h.now.lock().unwrap() += Duration::minutes(10);
    let r3 = run(&h, &spec, input(o2.checkpoints.clone())).await;
    let o3 = r3.out.expect("gws run 3");
    assert_eq!(o3.events, 4, "late events inside the lookback are picked up once");
    eprintln!(
        "G1 google_workspace: 475 events over 3 apps match Deno; restart 0 new ({} overlap dropped); 4 late arrivals recovered",
        o2.dropped_duplicates
    );
}

// ------------------------------------------------------------- G1: Slack --

fn slack_login(i: usize, t: i64) -> Value {
    json!({"user_id": format!("U{i:08}"), "username": format!("user{i}"), "date_first": t - 3600, "date_last": t, "count": 1 + i % 4,
           "ip": format!("203.0.113.{}", i % 250 + 1), "user_agent": "Mozilla/5.0 (mock)", "isp": "Mock ISP", "country": "CA", "region": "ON"})
}

fn slack_handler(logins: Arc<Mutex<Vec<Value>>>) -> Handler {
    Arc::new(move |r: &MockReq| {
        if r.headers.get("authorization").map(String::as_str) != Some("Bearer xoxp-mock-token") {
            return MockResp::json(json!({"ok": false, "error": "invalid_auth"}));
        }
        if r.path != "/api/team.accessLogs" {
            return MockResp::status(404, json!({}));
        }
        let all = logins.lock().unwrap();
        let limit: usize = r.query.get("limit").and_then(|v| v.parse().ok()).unwrap_or(100);
        let off: usize = r.query.get("cursor").and_then(|c| c.strip_prefix("dXNlcj")).and_then(|v| v.parse().ok()).unwrap_or(0);
        let page: Vec<Value> = all.iter().skip(off).take(limit).cloned().collect();
        let next = if off + limit < all.len() { format!("dXNlcj{}", off + limit) } else { String::new() };
        MockResp::json(json!({"ok": true, "logins": page, "paging": {"count": limit, "total": all.len()}, "response_metadata": {"next_cursor": next}}))
    })
}

#[tokio::test]
async fn g1_slack_access_logs() {
    let Some(e) = env() else { return };
    let now = Utc::now();
    let t0 = now.timestamp() - 70;
    // Newest first, as Slack returns them: 450 sign-ins inside the
    // point-forward window, then 50 hours-old ones that must never ship
    // (NAN-3697: a new collector does not read Slack's history).
    let mut all: Vec<Value> = (0..450).map(|i| slack_login(i, t0 - (i / 2) as i64)).collect();
    all.extend((0..50).map(|i| slack_login(5000 + i, t0 - 7200 - 60 * i as i64)));
    let logins = Arc::new(Mutex::new(all));
    let mock = start_mock(slack_handler(logins.clone()), false).await;
    let d = deno(&e, &mock, json!({
        "script": file_url(&e.integrations.join("integrations/slack/code.ts")),
        "kind": "collector", "auth": {"type": "bearer", "token": "xoxp-mock-token"},
        "credentials": {"USER_TOKEN": "xoxp-mock-token"}, "config": {}, "streams": ["access_logs"],
        "initial_cursor": iso(initial_cursor(now)),
    }))
    .await;
    let h = harness(&mock);
    *h.now.lock().unwrap() = now;
    let spec = content_spec(&e, "integrations/slack");
    let input = |cps: HashMap<String, Value>| RunInput { credentials: creds(&[("USER_TOKEN", "xoxp-mock-token")]), checkpoints: cps, ..Default::default() };
    let r1 = run(&h, &spec, input(HashMap::new())).await;
    let o1 = r1.out.expect("slack run 1");
    let n = same_events("slack access_logs", &deno_emits(&d).remove("access_logs").unwrap_or_default(), &r1.sink.events(), &[]);
    assert_eq!(n, 450, "only sign-ins since the initial cursor; no history");
    assert_ingest_ids("slack", &r1.sink.events());
    assert!(mock.requests().iter().all(|r| !r.raw_query.contains("team_id")), "empty TEAM_ID is omitted");

    // 7 new sign-ins; the next run stops at the watermark.
    {
        let mut l = logins.lock().unwrap();
        for i in 0..7 {
            l.insert(0, slack_login(1000 + i, t0 + 60 * (i as i64 + 1)));
        }
    }
    let r2 = run(&h, &spec, input(o1.checkpoints.clone())).await;
    let o2 = r2.out.expect("slack run 2");
    assert_eq!(o2.events, 7);
    assert_eq!(o2.pages, 1);
    eprintln!("G1 slack: 450 match Deno; second run ships exactly the 7 new sign-ins in 1 page");
}

// -------------------------------------------------- every spec compiles --

/// Every `connector.yaml` in both content repos passes `validate` (compile +
/// the shipped-spec lints, e.g. a collector must name its ingest id).
#[tokio::test]
async fn every_shipped_spec_validates() {
    let Some(e) = env() else { return };
    let mut found = vec![];
    for (root, depth) in [(e.integrations.join("integrations"), 1), (e.enrichments.clone(), 2)] {
        let mut dirs = vec![(root, 0)];
        while let Some((d, lvl)) = dirs.pop() {
            for entry in std::fs::read_dir(&d).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() && lvl < depth {
                    dirs.push((p, lvl + 1));
                } else if p.file_name().is_some_and(|n| n == "connector.yaml") {
                    found.push(p);
                }
            }
        }
    }
    for p in &found {
        let spec = spec(&std::fs::read_to_string(p).unwrap());
        // VRL programs compile in sandboxed workers, as in production.
        nano_connector::preview::validate(worker_exe(), &spec).await.unwrap_or_else(|err| panic!("{}: {err}", p.display()));
    }
    assert!(found.len() >= 14, "{} specs: {found:?}", found.len());
    let _ = MemoryStore::default();
}

// ------------------------------------------------------------ G1: Netskope --

/// Mock of the Netskope v2 dataexport iterator. The read position lives here,
/// per `index`, and ADVANCES WHEN A PAGE IS SERVED:
///   operation=<epoch>  open (or re-open) at the first event >= epoch
///   operation=next     serve the page after the last one served
///   operation=resend   re-serve the last page; refused on an index that was
///                      never opened (the real API has nothing to resend)
/// `fail_after_serve` makes the next N `next` requests advance the index and
/// then answer 502, the way a gateway timeout loses a served page.
struct Netskope {
    events: BTreeMap<String, Vec<Value>>,
    /// index -> (position after the last served page, start of that page)
    iters: Mutex<HashMap<String, (usize, usize)>>,
    fail_after_serve: AtomicUsize,
    unopened_resends: Counter,
    log: Mutex<Vec<String>>,
    page: usize,
}

fn netskope_event(kind: &str, i: usize, ts: i64) -> Value {
    json!({"_id": format!("{:024x}", (kind.len() << 40) + i), "record_type": kind, "timestamp": ts,
           "user": format!("user{}@corp.example", i % 13), "srcip": format!("203.0.113.{}", i % 250 + 1),
           "app": "Box", "activity": if i % 3 == 0 { "Upload" } else { "Download" }, "action": "allow"})
}

impl Netskope {
    fn new(t0: i64, counts: &[(&str, usize)]) -> Arc<Self> {
        let events = counts.iter().map(|(k, n)| (k.to_string(), (0..*n).map(|i| netskope_event(k, i, t0 + i as i64)).collect())).collect();
        Arc::new(Self { events, iters: Mutex::default(), fail_after_serve: AtomicUsize::new(0), unopened_resends: Counter::default(), log: Mutex::default(), page: 100 })
    }

    fn handler(self: &Arc<Self>) -> Handler {
        let me = self.clone();
        Arc::new(move |r: &MockReq| {
            if r.headers.get("netskope-api-token").map(String::as_str) != Some("ns-token-123456") {
                return MockResp::status(401, json!({"ok": 0, "message": "invalid token"}));
            }
            let Some(kind) = r.path.strip_prefix("/api/v2/events/dataexport/events/") else { return MockResp::status(404, json!({})) };
            let Some(all) = me.events.get(kind) else { return MockResp::status(400, json!({"ok": 0, "message": "unknown event type"})) };
            let (index, op) = (r.query.get("index").cloned().unwrap_or_default(), r.query.get("operation").cloned().unwrap_or_default());
            me.log.lock().unwrap().push(format!("{index} {op}"));
            let mut iters = me.iters.lock().unwrap();
            let start = match op.as_str() {
                "next" => match iters.get(&index) {
                    Some((pos, _)) => *pos,
                    None => return MockResp::json(json!({"ok": 0, "message": "iterator not initialized"})),
                },
                "resend" => match iters.get(&index) {
                    Some((_, last)) => *last,
                    None => {
                        me.unopened_resends.inc();
                        return MockResp::json(json!({"ok": 0, "message": "resend on an iterator that was never opened"}));
                    }
                },
                epoch => {
                    let Ok(e) = epoch.parse::<i64>() else { return MockResp::status(400, json!({"ok": 0, "message": "bad operation"})) };
                    all.iter().position(|ev| ev["timestamp"].as_i64().unwrap() >= e).unwrap_or(all.len())
                }
            };
            let page: Vec<Value> = all.iter().skip(start).take(me.page).cloned().collect();
            iters.insert(index, (start + page.len(), start));
            if op == "next" && !page.is_empty() && me.fail_after_serve.load(Ordering::SeqCst) > 0 {
                me.fail_after_serve.fetch_sub(1, Ordering::SeqCst);
                return MockResp::status(502, json!({"message": "bad gateway"}));
            }
            MockResp::json(json!({"ok": 1, "result": page, "wait_time": 0}))
        })
    }
}

fn netskope_input(cps: HashMap<String, Value>) -> RunInput {
    RunInput {
        credentials: creds(&[("API_TOKEN", "ns-token-123456")]),
        config: config(json!({"TENANT_HOST": "acme.goskope.com", "INDEX_NAME": "nano", "STREAMS": "alert,application"})),
        checkpoints: cps,
        ..Default::default()
    }
}

fn by_source_type(r: &Ran) -> HashMap<String, Vec<Value>> {
    let mut m: HashMap<String, Vec<Value>> = HashMap::new();
    for (st, evs) in r.sink.batches.lock().unwrap().iter() {
        m.entry(st.clone()).or_default().extend(evs.iter().cloned());
    }
    m
}

/// The shipped Netskope collector vs its spec, each against a fresh iterator:
/// identical events per stream; then a restart walks on with `next` and ships
/// nothing twice.
#[tokio::test]
async fn g1_netskope_matches_deno() {
    let Some(e) = env() else { return };
    // Events from 290 s ago: inside the point-forward window (NAN-3697).
    let now = Utc::now();
    let t0 = now.timestamp() - 290;
    let counts = [("alert", 230usize), ("application", 140)];

    let dmock_state = Netskope::new(t0, &counts);
    let dmock = start_mock(dmock_state.handler(), false).await;
    let d = deno(&e, &dmock, json!({
        "script": file_url(&e.integrations.join("integrations/netskope/code.ts")),
        "kind": "collector", "auth": {"type": "api_key_header", "header_name": "Netskope-API-Token", "api_key": "ns-token-123456"},
        "credentials": {"API_TOKEN": "ns-token-123456"}, "config": {"TENANT_HOST": "acme.goskope.com", "INDEX_NAME": "nano"},
        "streams": ["alert", "application"], "initial_cursor": iso(initial_cursor(now)),
    }))
    .await;
    let deno_by = deno_emits(&d);

    let state = Netskope::new(t0, &counts);
    let mock = start_mock(state.handler(), false).await;
    let h = harness(&mock);
    *h.now.lock().unwrap() = now;
    let spec = content_spec(&e, "integrations/netskope");
    let r1 = run(&h, &spec, netskope_input(HashMap::new())).await;
    let o1 = r1.out.as_ref().expect("netskope run 1");
    let eng = by_source_type(&r1);
    for (stream, n) in counts {
        let got = same_events(
            &format!("netskope/{stream}"),
            deno_by.get(stream).map(Vec::as_slice).unwrap_or_default(),
            eng.get(&format!("netskope_{stream}")).map(Vec::as_slice).unwrap_or_default(),
            &[],
        );
        assert_eq!(got, n);
        assert_ingest_ids(&format!("netskope/{stream}"), &eng[&format!("netskope_{stream}")]);
    }
    let cp = &o1.checkpoints["dataexport"]["items"];
    assert_eq!(cp["alert"]["state"], json!({"op": "open", "opened": true}), "{cp}");

    let r2 = run(&h, &spec, netskope_input(o1.checkpoints.clone())).await;
    assert_eq!(r2.out.expect("netskope run 2").events, 0);
    assert!(state.log.lock().unwrap().iter().rev().take(2).all(|l| l.ends_with(" next")), "restart walks on with next");
    assert_eq!(state.unopened_resends.get(), 0);
    eprintln!("G1 netskope: {} events over 2 streams match Deno; restart ships 0", o1.events);
}

/// A crash during the very first fetch leaves the write-ahead `op: resend` on
/// an index Netskope never opened. The next run must re-open at the SAME
/// pinned epoch (not resend, not a later `now`), and ship everything.
#[tokio::test]
async fn netskope_crash_during_first_fetch_reopens_at_the_pinned_epoch() {
    let Some(e) = env() else { return };
    let now = Utc::now();
    let t0 = now.timestamp() - 290;
    let spec = content_spec(&e, "integrations/netskope");

    // Run 1: the vendor is unreachable, so the first request never completes
    // and the run fails with only the write-ahead state committed.
    let down = start_mock(Arc::new(|_r: &MockReq| MockResp::status(503, json!({"message": "unavailable"}))), false).await;
    let mut spec_fast = spec.clone();
    spec_fast.rate_limit.backoff_ms = 10;
    let h_down = harness(&down);
    *h_down.now.lock().unwrap() = now;
    let r1 = run(&h_down, &spec_fast, netskope_input(HashMap::new())).await;
    assert!(r1.out.is_err(), "run 1 fails");
    let saved: HashMap<String, Value> = r1.store.saves.lock().unwrap().iter().cloned().collect();
    let alert = &saved["dataexport"]["items"]["alert"]["state"];
    assert_eq!(alert["op"], "resend", "write-ahead committed: {alert}");
    assert!(alert["opened"].is_null(), "the iterator never opened: {alert}");
    let pinned = alert["start"].as_str().expect("start epoch pinned").to_string();
    // Pinned at the point-forward initial cursor (NAN-3697).
    assert_eq!(pinned, initial_cursor(now).timestamp().to_string());

    // Run 2, an hour later against a healthy vendor: re-open at the pinned epoch.
    let state = Netskope::new(t0, &[("alert", 230), ("application", 140)]);
    let mock = start_mock(state.handler(), false).await;
    let h = harness(&mock);
    *h.now.lock().unwrap() = Utc::now() + Duration::hours(1);
    let r2 = run(&h, &spec, netskope_input(saved)).await;
    let o2 = r2.out.expect("run 2");
    assert_eq!(state.unopened_resends.get(), 0, "never resends on an unopened iterator");
    assert!(state.log.lock().unwrap().iter().any(|l| *l == format!("nano_alert {pinned}")), "re-opened at the pinned epoch");
    assert_eq!(o2.events, 370, "nothing skipped");
    eprintln!("G1 netskope first-fetch crash: re-opened at {pinned}, 370/370 shipped, 0 unopened resends");
}

/// A 502 on `next` after Netskope already advanced the index: the engine
/// retries with `resend` (retry_rewrite), so the served-but-lost page is not
/// skipped. A crash after a page was served but before it was acknowledged
/// (write-ahead `op: resend`, `opened: true`) resends on restart.
#[tokio::test]
async fn netskope_lost_pages_are_resent_not_skipped() {
    let Some(e) = env() else { return };
    let t0 = Utc::now().timestamp() - 290;
    let mut spec = content_spec(&e, "integrations/netskope");
    spec.rate_limit.backoff_ms = 10;

    let state = Netskope::new(t0, &[("alert", 330)]);
    state.fail_after_serve.store(2, Ordering::SeqCst);
    let mock = start_mock(state.handler(), false).await;
    let h = harness(&mock);
    let mut input = netskope_input(HashMap::new());
    input.config.insert("STREAMS".into(), json!("alert"));
    let r = run(&h, &spec, input).await;
    let o = r.out.expect("run");
    let mut ids: Vec<String> = r.sink.events().iter().map(|e| e["_id"].as_str().unwrap().to_string()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!((o.events, ids.len()), (330, 330), "every event once, none skipped");
    let resends = state.log.lock().unwrap().iter().filter(|l| l.ends_with(" resend")).count();
    assert_eq!(resends, 2, "each failed next was retried as resend");

    // Crash between a served page and its ack.
    let state = Netskope::new(t0, &[("alert", 150)]);
    let mock = start_mock(state.handler(), false).await;
    let h = harness(&mock);
    state.iters.lock().unwrap().insert("nano_alert".into(), (100, 0));
    let cps = HashMap::from([("dataexport".to_string(), json!({"items": {"alert": {"state": {"op": "resend", "opened": true}}}}))]);
    let mut input = netskope_input(cps);
    input.config.insert("STREAMS".into(), json!("alert"));
    let o = run(&h, &spec, input).await.out.expect("restart");
    assert_eq!(state.log.lock().unwrap()[0], "nano_alert resend");
    assert_eq!(o.events, 150, "the unacked page is re-served, then the rest");
    eprintln!("G1 netskope: 2 lost pages resent (330/330 once); crash-before-ack resends the page");
}
