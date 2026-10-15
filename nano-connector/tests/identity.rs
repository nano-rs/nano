//! NAN-3503: `kind: identity` end to end. Mock vendors (Okta-style users and
//! groups, Entra-style Graph users/delta) over TLS through the engine's
//! egress broker, a mock platform pull broker, and mock tenant coordinators
//! that enforce the coordinator's identity contract (bearer, tenant binding,
//! the `IdentityRow` field set with unknown fields refused, staged chunks,
//! `expected_rows`, deltas, tombstones).
//!
//! Proves:
//! - full run: staged chunks, commit with the snapshot-end count, manager
//!   ids resolved to UPNs (forward references through the spill), the
//!   checkpoint saved only after commit 200 (global sequence), never on a
//!   failed commit (abandoned run deleted);
//! - delta run: adds / changes / Okta deprovision and Entra `@removed`
//!   tombstones as deltas, one checkpoint per page after the delta 200, none
//!   after a failed delta; Graph 410 restarts the stream as a full run;
//! - memberships: aggregated per member (sorted, unique), `is_admin` from a
//!   privileged membership (when the coordinator accepts the column);
//! - vendor 401 refreshes the broker token once; vendor 429 honours
//!   `Retry-After` inside the run;
//! - `entra_fic_broker`: exact broker body and headers, wrong resource /
//!   directory refused, broker 429 honoured;
//! - two tenants: each run reaches only its own tenant's coordinator, with
//!   its own tenant id, whatever the spec, config or rows claim;
//! - 500k users (ignored; run in release): completes with bounded memory.

mod common;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use common::*;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use nano_connector::engine::{self, CheckpointStore, RunInput, RunOutput};
use nano_connector::identity::{CoordinatorClient, IdentitySink, IdentitySinkOptions};
use nano_connector::pull_broker::PlatformBroker;
use nano_connector::service::feed::spec_sha256;
use nano_connector::service::{FeedDefinition, MemoryFeedStore, RunStatus, Runner, RunnerConfig, Secret};
use nano_connector::spec::IdentityMode;
use serde_json::{Map, Value, json};
use tokio::net::TcpListener;
use uuid::Uuid;

const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const TENANT: &str = "858f3709-a703-4b29-97a6-dd0ea314b84a";
const TENANT_B: &str = "1b6f0e0a-2c4d-4e8f-9a1b-3c5d7e9f0a2b";
const FEED: &str = "0199a0c4-2222-7000-8000-000000000001";
const COORD_TOKEN: &str = "coordinator-bearer-token-0123456789abcdef";
const OKTA_TOKEN: &str = "okta-api-token-abcdef0123";
const DIRECTORY: &str = "e6800ccd-d972-42ce-b555-dbf0a25ed9a7";
const CLIENT: &str = "5e30aef4-9c37-4841-997d-0324ff914452";

/// The coordinator's `IdentityRow` columns (`deny_unknown_fields`).
const ROW_FIELDS: &[&str] = &[
    "feed_id", "external_id", "source_kind", "version", "deleted", "snapshot_id", "observed_at", "username", "upn",
    "email", "display_name", "first_name", "last_name", "department", "title", "manager_upn", "manager_display_name",
    "company", "office_location", "city", "country", "groups", "account_enabled", "account_status", "mfa_enabled",
    "last_sign_in_at", "created_in_directory_at", "phone", "employee_id", "employee_type", "last_observed_at",
];
const STATUSES: &[&str] = &["", "active", "disabled", "suspended", "deleted", "anonymized", "unknown"];
/// Accepted only by a v2 coordinator (#6294).
const V2_STATUSES: &[&str] = &["deprovisioned", "locked", "staged"];

static SEQ: AtomicU64 = AtomicU64::new(1);
fn seq() -> u64 {
    SEQ.fetch_add(1, Ordering::SeqCst)
}

// ------------------------------------------------------------ coordinator

#[derive(Debug, Clone)]
struct Logged {
    seq: u64,
    method: String,
    path: String,
    status: u16,
    tenant: Option<String>,
    /// Rows of the request (empty in count-only mode).
    rows: Vec<Value>,
    expected_rows: Option<u64>,
    /// Delta requests: the patch flag and manager references.
    patch: bool,
    manager_refs: Vec<Value>,
    /// Commit requests: `allow_empty`.
    allow_empty: bool,
}

#[derive(Default)]
struct CoordState {
    dir: BTreeMap<(String, String), Value>,
    staged: HashMap<(String, String), BTreeMap<u64, (u64, Vec<Value>)>>,
    log: Vec<Logged>,
    fail_commit: u32,
    /// Commits applied whose answer is lost (a 503 after the commit).
    lose_commit_answer: u32,
    /// `(feed) -> (run, expected_rows)` of the last commit: a repeat is a
    /// 200 (the coordinator's idempotent commit).
    committed: HashMap<String, (String, u64)>,
    fail_deltas: u32,
    /// Feed deletes answered 500 (uninstall retry).
    fail_delete: u32,
    /// A v2 coordinator (#6294): `is_admin` and the v2 statuses.
    v2: bool,
    count_only: bool,
    rows_seen: u64,
}

struct Coord {
    port: u16,
    tenant: Uuid,
    st: Arc<Mutex<CoordState>>,
}

impl Coord {
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
    fn log(&self) -> Vec<Logged> {
        self.st.lock().unwrap().log.clone()
    }
    fn dir(&self) -> BTreeMap<(String, String), Value> {
        self.st.lock().unwrap().dir.clone()
    }
    fn client(&self) -> CoordinatorClient {
        CoordinatorClient::new(&self.url(), self.tenant, COORD_TOKEN, Duration::from_secs(30)).unwrap()
    }
    fn rows_of(&self, feed: &str) -> BTreeMap<String, Value> {
        self.dir().into_iter().filter(|((f, _), _)| f == feed).map(|((_, e), v)| (e, v)).collect()
    }
}

fn check_row(row: &Value, v2: bool) -> Result<(), String> {
    let o = row.as_object().ok_or("row is not an object")?;
    for (k, v) in o {
        let known = ROW_FIELDS.contains(&k.as_str()) || (v2 && k == "is_admin");
        if !known {
            return Err(format!("unknown field `{k}`"));
        }
        let ok = match k.as_str() {
            "version" | "observed_at" | "last_sign_in_at" | "created_in_directory_at" | "last_observed_at" => v.is_i64() || v.is_null(),
            "deleted" | "account_enabled" | "mfa_enabled" | "is_admin" => v.is_boolean() || v.is_null(),
            "groups" => v.as_array().is_some_and(|a| a.iter().all(Value::is_string)),
            "source_kind" => v == "pull",
            "account_status" => v.as_str().is_some_and(|s| STATUSES.contains(&s) || (v2 && V2_STATUSES.contains(&s))),
            _ => v.is_string(),
        };
        if !ok {
            return Err(format!("field `{k}` has the wrong type: {v}"));
        }
    }
    for k in ["feed_id", "external_id", "source_kind", "version"] {
        if !o.contains_key(k) {
            return Err(format!("missing `{k}`"));
        }
    }
    Ok(())
}

fn apply(dir: &mut BTreeMap<(String, String), Value>, row: Value) {
    let key = (row["feed_id"].as_str().unwrap().to_string(), row["external_id"].as_str().unwrap().to_string());
    let v = row["version"].as_i64().unwrap();
    if dir.get(&key).is_some_and(|old| old["version"].as_i64().unwrap() > v) {
        return;
    }
    if row["deleted"] == json!(true) {
        dir.remove(&key);
    } else {
        dir.insert(key, row);
    }
}

/// The coordinator's patch semantics (`prepare_delta`): absent fields of a
/// live row keep the current value; `manager_refs` resolve against the
/// request, then the directory (upn, else email, else username).
fn patch_rows(dir: &BTreeMap<(String, String), Value>, mut rows: Vec<Value>, patch: bool, refs: &[Value]) -> Vec<Value> {
    let key = |r: &Value, id: &str| (r["feed_id"].as_str().unwrap().to_string(), r[id].as_str().unwrap().to_string());
    if patch {
        for r in rows.iter_mut().filter(|r| r["deleted"] != json!(true)) {
            if let Some(Value::Object(old)) = dir.get(&key(r, "external_id")) {
                let o = r.as_object_mut().unwrap();
                for (k, v) in old {
                    if !o.contains_key(k) {
                        o.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }
    let reference = |r: &Value| ["upn", "email", "username"].iter().find_map(|k| r.get(*k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string));
    for m in refs {
        let target = key(m, "external_id");
        let manager = key(m, "manager_external_id");
        let found = rows.iter().find(|r| key(r, "external_id") == manager && r["deleted"] != json!(true)).and_then(reference).or_else(|| dir.get(&manager).and_then(reference));
        if let Some(upn) = found {
            for r in rows.iter_mut().filter(|r| key(r, "external_id") == target) {
                r["manager_upn"] = json!(upn);
            }
        }
    }
    rows
}

fn coord_answer(tenant: Uuid, st: &mut CoordState, method: &str, path: &str, auth: Option<&str>, body: &[u8]) -> (u16, Value) {
    let err = |s: u16, m: &str| (s, json!({ "error": m }));
    if auth != Some(&format!("Bearer {COORD_TOKEN}")) {
        return err(401, "unauthorized");
    }
    let Ok(req) = serde_json::from_slice::<Value>(body) else { return err(400, "invalid identity request") };
    let t = tenant.hyphenated().to_string();
    if req["tenant_id"].as_str() != Some(t.as_str()) {
        return err(400, "tenant identity differs from assignment");
    }
    let rows = req.get("rows").and_then(Value::as_array).cloned().unwrap_or_default();
    for r in &rows {
        if let Err(e) = check_row(r, st.v2) {
            return (400, json!({ "error": "invalid identity request", "detail": e }));
        }
    }
    let seg: Vec<&str> = path.trim_start_matches("/v1/identity/directory/").split('/').collect();
    match (method, seg.as_slice()) {
        ("POST", ["deltas"]) => {
            if st.fail_deltas > 0 {
                st.fail_deltas -= 1;
                return err(500, "injected delta failure");
            }
            let patch = req.get("patch").and_then(Value::as_bool).unwrap_or(false);
            let refs = req.get("manager_refs").and_then(Value::as_array).cloned().unwrap_or_default();
            if !st.v2 && (req.get("patch").is_some() || req.get("manager_refs").is_some()) {
                return err(400, "invalid identity request");
            }
            st.rows_seen += rows.len() as u64;
            let rows = patch_rows(&st.dir, rows, patch, &refs);
            for r in rows {
                apply(&mut st.dir, r);
            }
            (200, json!({ "status": "published", "tenant_id": t, "changed": true }))
        }
        ("POST", ["feeds", feed, "runs", run, "rows"]) => {
            if rows.is_empty() || rows.len() > 100_000 || rows.iter().any(|r| r["feed_id"].as_str() != Some(feed)) {
                return err(400, "staged identity rows belong to another feed");
            }
            let chunk = req["chunk"].as_u64().unwrap_or(u64::MAX);
            if chunk >= 256 {
                return err(413, "tenant identity input exceeds its cap");
            }
            st.rows_seen += rows.len() as u64;
            let n = rows.len() as u64;
            let keep = if st.count_only { vec![] } else { rows };
            let run_rows = st.staged.entry((feed.to_string(), run.to_string())).or_default();
            run_rows.insert(chunk, (n, keep));
            let staged: u64 = run_rows.values().map(|(n, _)| n).sum();
            (200, json!({ "status": "staged", "tenant_id": t, "feed_id": feed, "run_id": run, "staged_rows": staged, "chunks": run_rows.len() }))
        }
        ("POST", ["feeds", feed, "runs", run, "commit"]) => {
            if st.fail_commit > 0 {
                st.fail_commit -= 1;
                return err(500, "injected commit failure");
            }
            let expected = req["expected_rows"].as_u64().unwrap_or(u64::MAX);
            let allow_empty = req.get("allow_empty").and_then(Value::as_bool).unwrap_or(false);
            if expected == 0 && !allow_empty {
                return err(400, "an empty identity snapshot needs allow_empty");
            }
            let Some(run_rows) = st.staged.remove(&(feed.to_string(), run.to_string())) else {
                if st.committed.get(*feed) == Some(&(run.to_string(), expected)) {
                    return (200, json!({ "status": "unchanged", "tenant_id": t, "changed": false }));
                }
                if expected == 0 {
                    // An allowed empty snapshot stages nothing.
                    st.dir.retain(|(f, _), _| f != feed);
                    st.committed.insert(feed.to_string(), (run.to_string(), 0));
                    return (200, json!({ "status": "published", "tenant_id": t, "changed": true }));
                }
                return err(409, "staged run is unknown");
            };
            let staged: u64 = run_rows.values().map(|(n, _)| n).sum();
            if Some(staged) != req["expected_rows"].as_u64() {
                return err(409, "staged row count differs from the run's snapshot-end count");
            }
            if !st.count_only {
                st.dir.retain(|(f, _), _| f != feed);
                for (_, (_, rows)) in run_rows {
                    for r in rows {
                        apply(&mut st.dir, r);
                    }
                }
            }
            st.committed.insert(feed.to_string(), (run.to_string(), expected));
            if st.lose_commit_answer > 0 {
                st.lose_commit_answer -= 1;
                return err(503, "answer lost");
            }
            (200, json!({ "status": "published", "tenant_id": t, "changed": true }))
        }
        ("DELETE", ["feeds", feed, "runs", run]) => {
            st.staged.remove(&(feed.to_string(), run.to_string()));
            (204, Value::Null)
        }
        ("DELETE", ["feeds", feed]) => {
            if st.fail_delete > 0 {
                st.fail_delete -= 1;
                return err(500, "injected delete failure");
            }
            if st.dir.is_empty() {
                return err(404, "tenant identity directory is empty");
            }
            st.dir.retain(|(f, _), _| f != feed);
            (200, json!({ "status": "published", "tenant_id": t, "changed": true }))
        }
        _ => err(404, "not found"),
    }
}

#[derive(serde::Deserialize)]
struct CountReq {
    tenant_id: String,
    #[serde(default)]
    chunk: Option<u64>,
    #[serde(default)]
    expected_rows: Option<u64>,
    #[serde(default)]
    rows: Vec<serde::de::IgnoredAny>,
}

/// Count-only stage / commit (no row validation, nothing kept).
fn count_answer(tenant: Uuid, st: &mut CoordState, path: &str, auth: Option<&str>, body: &[u8]) -> (u16, Value, Option<String>, Option<u64>) {
    let t = tenant.hyphenated().to_string();
    if auth != Some(&format!("Bearer {COORD_TOKEN}")) {
        return (401, json!({"error": "unauthorized"}), None, None);
    }
    let Ok(req) = serde_json::from_slice::<CountReq>(body) else { return (400, json!({"error": "invalid identity request"}), None, None) };
    if req.tenant_id != t {
        return (400, json!({"error": "tenant identity differs from assignment"}), Some(req.tenant_id), None);
    }
    let seg: Vec<&str> = path.trim_start_matches("/v1/identity/directory/").split('/').collect();
    let answer = match seg.as_slice() {
        ["feeds", feed, "runs", run, "rows"] => {
            st.rows_seen += req.rows.len() as u64;
            let run_rows = st.staged.entry((feed.to_string(), run.to_string())).or_default();
            run_rows.insert(req.chunk.unwrap_or(0), (req.rows.len() as u64, vec![]));
            let staged: u64 = run_rows.values().map(|(n, _)| n).sum();
            (200, json!({"status": "staged", "tenant_id": t, "feed_id": feed, "run_id": run, "staged_rows": staged, "chunks": run_rows.len()}))
        }
        ["feeds", feed, "runs", run, "commit"] => match st.staged.remove(&(feed.to_string(), run.to_string())) {
            Some(r) if Some(r.values().map(|(n, _)| n).sum::<u64>()) == req.expected_rows => (200, json!({"status": "published", "tenant_id": t, "changed": true})),
            _ => (409, json!({"error": "staged row count differs"})),
        },
        _ => (404, json!({"error": "not found"})),
    };
    (answer.0, answer.1, Some(req.tenant_id), req.expected_rows)
}

async fn start_coord(tenant: &str) -> Coord {
    let tenant = Uuid::parse_str(tenant).unwrap();
    let st = Arc::new(Mutex::new(CoordState { v2: true, ..Default::default() }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let st2 = st.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { break };
            let st = st2.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let st = st.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body.collect().await.map(|b| b.to_bytes().to_vec()).unwrap_or_default();
                        let auth = parts.headers.get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string);
                        let method = parts.method.to_string();
                        let path = parts.uri.path().to_string();
                        let (status, answer) = {
                            let mut g = st.lock().unwrap();
                            if g.count_only {
                                // Scale runs: count rows without building them
                                // (the mock must not dominate the memory reading).
                                let (status, answer, tenant, expected) = count_answer(tenant, &mut g, &path, auth.as_deref(), &body);
                                g.log.push(Logged { seq: seq(), method: method.clone(), path: path.clone(), status, tenant, rows: vec![], expected_rows: expected, patch: false, manager_refs: vec![], allow_empty: false });
                                drop(g);
                                return Ok::<_, Infallible>(
                                    hyper::Response::builder().status(status).header("content-type", "application/json").body(Full::new(Bytes::from(answer.to_string()))).unwrap(),
                                );
                            }
                            let (status, answer) = coord_answer(tenant, &mut g, &method, &path, auth.as_deref(), &body);
                            let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                            let rows = if g.count_only { vec![] } else { req.get("rows").and_then(Value::as_array).cloned().unwrap_or_default() };
                            g.log.push(Logged {
                                seq: seq(),
                                method: method.clone(),
                                path: path.clone(),
                                status,
                                tenant: req.get("tenant_id").and_then(Value::as_str).map(str::to_string),
                                rows,
                                expected_rows: req.get("expected_rows").and_then(Value::as_u64),
                                patch: req.get("patch").and_then(Value::as_bool).unwrap_or(false),
                                manager_refs: req.get("manager_refs").and_then(Value::as_array).cloned().unwrap_or_default(),
                                allow_empty: req.get("allow_empty").and_then(Value::as_bool).unwrap_or(false),
                            });
                            (status, answer)
                        };
                        let body = if answer.is_null() { Bytes::new() } else { Bytes::from(answer.to_string()) };
                        Ok::<_, Infallible>(
                            hyper::Response::builder().status(status).header("content-type", "application/json").body(Full::new(body)).unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).await;
            });
        }
    });
    Coord { port, tenant, st }
}

/// Checkpoints with the global sequence number of each save.
#[derive(Default)]
struct SeqStore {
    saves: Mutex<Vec<(u64, String, Value)>>,
}

#[async_trait::async_trait]
impl CheckpointStore for SeqStore {
    async fn save(&self, stream: &str, state: &Value) -> Result<(), String> {
        self.saves.lock().unwrap().push((seq(), stream.to_string(), state.clone()));
        Ok(())
    }
}

impl SeqStore {
    fn all(&self) -> Vec<(u64, String, Value)> {
        self.saves.lock().unwrap().clone()
    }
}

// ------------------------------------------------------------ vendors

#[derive(Clone, Debug)]
struct OktaUser {
    id: String,
    login: String,
    title: String,
    manager: Option<String>,
    status: &'static str,
    updated: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct Group {
    id: String,
    name: String,
    members: Vec<String>,
}

#[derive(Clone, Debug)]
struct GraphUser {
    id: String,
    upn: String,
    manager: Option<String>,
    removed: bool,
    /// Change number (delta token) of the last change.
    changed: u64,
}

struct Vendor {
    okta_users: Mutex<Vec<OktaUser>>,
    groups: Mutex<Vec<Group>>,
    graph: Mutex<Vec<GraphUser>>,
    graph_version: AtomicU64,
    graph_expired: AtomicBool,
    graph_401_once: AtomicBool,
    okta_429_once: Mutex<Option<u64>>,
    okta_429_at: Mutex<Vec<Instant>>,
    broker: Mutex<BrokerMode>,
    broker_calls: AtomicU32,
    broker_bad: AtomicU32,
    issued: AtomicU32,
    /// Lazily generated Okta directory of this many users (500k test).
    lazy_users: AtomicU64,
    okta: OktaOauth,
}

#[derive(Default)]
struct OktaOauth {
    /// What the broker signs into the assertion (`aud` override, DPoP demand).
    bad_aud: AtomicBool,
    dpop: AtomicBool,
    assertions: AtomicU32,
    broker_bodies: Mutex<Vec<Value>>,
    token_forms: Mutex<Vec<BTreeMap<String, String>>>,
    entra_forms: Mutex<Vec<BTreeMap<String, String>>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BrokerMode {
    Ok,
    WrongResource,
    WrongDirectory,
    RateLimitedOnce(u64),
}

fn npc(tenant: &str) -> String {
    PlatformBroker::new("https://pull-broker.nano.rs", "1", KEY).unwrap().caller_token(tenant).unwrap()
}

fn fake_jwt(tid: &str, appid: &str, n: u32) -> String {
    let b = |v: Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
    format!(
        "{}.{}.GRAPH-SIG-{n}",
        b(json!({"alg": "RS256", "typ": "JWT"})),
        b(json!({"aud": "https://graph.microsoft.com", "tid": tid, "appid": appid, "n": n}))
    )
}

fn page_link(base: &str, after: usize, extra: &[(&str, &str)]) -> String {
    let mut u = url::Url::parse(base).unwrap();
    u.query_pairs_mut().append_pair("after", &after.to_string());
    for (k, v) in extra {
        u.query_pairs_mut().append_pair(k, v);
    }
    format!("<{u}>; rel=\"next\"")
}

fn okta_json(u: &OktaUser) -> Value {
    json!({
        "id": u.id, "status": u.status, "created": "2024-01-02T03:04:05.000Z", "lastLogin": "2026-10-01T10:00:00.000Z",
        "lastUpdated": u.updated.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "profile": { "login": u.login, "email": u.login, "firstName": "F", "lastName": "L", "displayName": format!("User {}", u.id),
                     "title": u.title, "department": "Eng", "managerId": u.manager, "userType": "member" },
    })
}

fn lazy_user(i: u64, n: u64) -> Value {
    // Even users report to the next user (a forward reference, resolved
    // from the spill), odd users to an earlier one.
    let manager = if i % 2 == 0 { (i + 1 < n).then(|| i + 1) } else { Some(i / 2) };
    json!({
        "id": format!("00u{i:07}"), "status": "ACTIVE", "created": "2024-01-02T03:04:05.000Z",
        "lastUpdated": "2026-10-01T00:00:00.000Z",
        "profile": { "login": format!("user{i}@example.com"), "email": format!("user{i}@example.com"), "firstName": "First",
                     "lastName": format!("Last{i}"), "displayName": format!("User Number {i}"), "title": "Engineer",
                     "department": "Engineering", "managerId": manager.map(|m| format!("00u{m:07}")), "userType": "member" },
    })
}

fn vendor_handler(v: Arc<Vendor>) -> Handler {
    Arc::new(move |r: &MockReq| {
        match (r.host.as_str(), r.path.as_str()) {
            ("pull-broker.nano.rs", "/v1/azure/graph-token") => {
                let n = v.broker_calls.fetch_add(1, Ordering::SeqCst);
                let body: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
                let ok = r.method == "POST"
                    && r.headers.get("authorization") == Some(&format!("Bearer {}", npc(TENANT)))
                    && r.headers.get("x-nano-pull-broker-object").map(String::as_str) == Some(&format!("pull-broker:{TENANT}"))
                    && body == json!({"feed_id": FEED, "directory_id": DIRECTORY, "client_id": CLIENT});
                if !ok {
                    v.broker_bad.fetch_add(1, Ordering::SeqCst);
                    return MockResp::status(401, json!({"error": "unauthorized"}));
                }
                let mode = *v.broker.lock().unwrap();
                if let BrokerMode::RateLimitedOnce(secs) = mode {
                    if n == 0 {
                        return MockResp::status(429, json!({"error": "graph_token_rate_limited"})).header("retry-after", &secs.to_string());
                    }
                }
                let i = v.issued.fetch_add(1, Ordering::SeqCst);
                let tid = if mode == BrokerMode::WrongDirectory { "11111111-2222-4333-8444-555555555555" } else { DIRECTORY };
                let resource = if mode == BrokerMode::WrongResource { "https://management.azure.com" } else { "https://graph.microsoft.com" };
                MockResp::json(json!({
                    "kind": "azure_access_token", "access_token": fake_jwt(tid, CLIENT, i), "expires_in": 3599,
                    "expires_on": (Utc::now().timestamp() + 3599).to_string(), "resource": resource,
                }))
            }
            ("pull-broker.nano.rs", "/v1/okta/client-assertion") => {
                let body: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
                v.okta.broker_bodies.lock().unwrap().push(body.clone());
                let ok = r.method == "POST"
                    && r.headers.get("authorization") == Some(&format!("Bearer {}", npc(TENANT)))
                    && r.headers.get("x-nano-pull-broker-object").map(String::as_str) == Some(&format!("pull-broker:{TENANT}"));
                if !ok {
                    return MockResp::status(401, json!({"error": "unauthorized"}));
                }
                let domain = body["okta_domain"].as_str().unwrap_or_default();
                let aud = if v.okta.bad_aud.load(Ordering::SeqCst) { "https://evil.okta.com/oauth2/v1/token".to_string() } else { format!("https://{domain}/oauth2/v1/token") };
                let n = v.okta.assertions.fetch_add(1, Ordering::SeqCst);
                let b = |v: Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
                let assertion = format!(
                    "{}.{}.OKTA-ASSERTION-SIG-{n}",
                    b(json!({"alg": "RS256", "kid": "k1"})),
                    b(json!({"iss": body["client_id"], "sub": body["client_id"], "aud": aud, "exp": t0().timestamp() + 300, "jti": format!("j{n}")}))
                );
                MockResp::json(json!({"kind": "okta_client_assertion", "assertion": assertion, "expires_in": 300}))
            }
            ("login.microsoftonline.com", p) if p == format!("/{DIRECTORY}/oauth2/v2.0/token") => {
                let form: BTreeMap<String, String> = url::form_urlencoded::parse(&r.body).into_owned().collect();
                v.okta.entra_forms.lock().unwrap().push(form);
                MockResp::json(json!({"token_type": "Bearer", "access_token": "GRAPH-SIG-oauth2", "expires_in": 3599}))
            }
            ("graph.microsoft.com", p) if p.starts_with("/v1.0/groups") => {
                let auth = r.headers.get("authorization").cloned().unwrap_or_default();
                if !auth.contains("GRAPH-SIG-") {
                    return MockResp::status(401, json!({"error": {"code": "InvalidAuthenticationToken"}}));
                }
                let gs = v.groups.lock().unwrap().clone();
                if p == "/v1.0/groups" {
                    let skip: usize = r.query.get("$skiptoken").and_then(|t| t.parse().ok()).unwrap_or(0);
                    let page: Vec<Value> = gs.iter().skip(skip).take(2).map(|g| json!({"id": g.id, "displayName": g.name})).collect();
                    let mut body = json!({"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#groups", "value": page});
                    if skip + 2 < gs.len() {
                        body["@odata.nextLink"] = json!(format!("https://graph.microsoft.com/v1.0/groups?$skiptoken={}", skip + 2));
                    }
                    return MockResp::json(body);
                }
                let gid = p.trim_start_matches("/v1.0/groups/").trim_end_matches("/members");
                let members: Vec<Value> =
                    gs.iter().find(|g| g.id == gid).map(|g| g.members.iter().map(|m| json!({"id": m})).collect()).unwrap_or_default();
                MockResp::json(json!({"value": members}))
            }
            ("graph.microsoft.com", "/v1.0/users/delta") => {
                let auth = r.headers.get("authorization").cloned().unwrap_or_default();
                if !auth.starts_with("Bearer ") || !auth.contains("GRAPH-SIG-") {
                    return MockResp::status(401, json!({"error": {"code": "InvalidAuthenticationToken"}}));
                }
                if v.graph_401_once.swap(false, Ordering::SeqCst) {
                    return MockResp::status(401, json!({"error": {"code": "InvalidAuthenticationToken"}}));
                }
                let base = "https://graph.microsoft.com/v1.0/users/delta";
                let since: Option<u64> = r.query.get("$deltatoken").and_then(|t| t.parse().ok());
                if since.is_some() && v.graph_expired.load(Ordering::SeqCst) {
                    return MockResp::status(410, json!({"error": {"code": "syncStateNotFound", "message": "Resync required"}}));
                }
                let all = v.graph.lock().unwrap().clone();
                let picked: Vec<&GraphUser> = match since {
                    None => all.iter().filter(|u| !u.removed).collect(),
                    Some(t) => all.iter().filter(|u| u.changed > t).collect(),
                };
                let skip: usize = r.query.get("$skiptoken").and_then(|t| t.parse().ok()).unwrap_or(0);
                let page: Vec<Value> = picked
                    .iter()
                    .skip(skip)
                    .take(2)
                    .map(|u| {
                        if u.removed {
                            json!({"id": u.id, "@removed": {"reason": "changed"}})
                        } else {
                            let mut o = json!({"id": u.id, "userPrincipalName": u.upn, "mail": u.upn, "displayName": format!("G {}", u.id),
                                               "accountEnabled": true, "jobTitle": "Analyst", "department": "SOC"});
                            if let Some(m) = &u.manager {
                                o["manager@delta"] = json!([{"@odata.type": "#microsoft.graph.user", "id": m}]);
                            }
                            o
                        }
                    })
                    .collect();
                let mut body = json!({"value": page});
                if skip + 2 < picked.len() {
                    let tok = since.map(|t| format!("&$deltatoken={t}")).unwrap_or_default();
                    body["@odata.nextLink"] = json!(format!("{base}?$skiptoken={}{tok}", skip + 2));
                } else {
                    body["@odata.deltaLink"] = json!(format!("{base}?$deltatoken={}", v.graph_version.load(Ordering::SeqCst)));
                }
                MockResp::json(body)
            }
            (h, "/oauth2/v1/token") if h.ends_with(".okta.com") => {
                let form: BTreeMap<String, String> = url::form_urlencoded::parse(&r.body).into_owned().collect();
                v.okta.token_forms.lock().unwrap().push(form);
                if v.okta.dpop.load(Ordering::SeqCst) {
                    return MockResp::status(400, json!({"error": "invalid_dpop_proof", "error_description": "The DPoP proof JWT header is missing."}));
                }
                MockResp::json(json!({"token_type": "Bearer", "access_token": "OKTA-AT-1", "expires_in": 3600, "scope": "okta.users.read okta.groups.read"}))
            }
            (h, path) if h.ends_with(".okta.com") => {
                let auth = r.headers.get("authorization").cloned().unwrap_or_default();
                if auth != format!("SSWS {OKTA_TOKEN}") && auth != "Bearer OKTA-AT-1" {
                    return MockResp::status(401, json!({"errorCode": "E0000011"}));
                }
                let base = format!("https://{h}{path}");
                let after: usize = r.query.get("after").and_then(|a| a.parse().ok()).unwrap_or(0);
                let limit: usize = r.query.get("limit").and_then(|a| a.parse().ok()).unwrap_or(200);
                if path == "/api/v1/users" {
                    if let Some(secs) = v.okta_429_once.lock().unwrap().take() {
                        v.okta_429_at.lock().unwrap().push(Instant::now());
                        return MockResp::status(429, json!({"errorCode": "E0000047"})).header("retry-after", &secs.to_string());
                    }
                    v.okta_429_at.lock().unwrap().push(Instant::now());
                    let lazy = v.lazy_users.load(Ordering::SeqCst);
                    if lazy > 0 {
                        let end = (after as u64 + limit as u64).min(lazy);
                        let page: Vec<Value> = (after as u64..end).map(|i| lazy_user(i, lazy)).collect();
                        let mut resp = MockResp::json(Value::Array(page));
                        if end < lazy {
                            resp = resp.header("link", &page_link(&base, end as usize, &[("limit", &limit.to_string())]));
                        }
                        return resp;
                    }
                    let since = r.query.get("filter").and_then(|f| f.split('"').nth(1)).and_then(|t| DateTime::parse_from_rfc3339(t).ok());
                    let users: Vec<OktaUser> = v
                        .okta_users
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|u| since.is_none_or(|s| u.updated > s))
                        .filter(|u| since.is_some() || u.status != "DEPROVISIONED")
                        .cloned()
                        .collect();
                    let page: Vec<Value> = users.iter().skip(after).take(limit).map(okta_json).collect();
                    let mut resp = MockResp::json(Value::Array(page));
                    if after + limit < users.len() {
                        let mut extra = vec![("limit", limit.to_string())];
                        if let Some(f) = r.query.get("filter") {
                            extra.push(("filter", f.clone()));
                        }
                        let extra: Vec<(&str, &str)> = extra.iter().map(|(k, v)| (*k, v.as_str())).collect();
                        resp = resp.header("link", &page_link(&base, after + limit, &extra));
                    }
                    return resp;
                }
                if path == "/api/v1/groups" {
                    let gs: Vec<Value> = v.groups.lock().unwrap().iter().map(|g| json!({"id": g.id, "profile": {"name": g.name}})).collect();
                    return MockResp::json(Value::Array(gs));
                }
                if let Some(gid) = path.strip_prefix("/api/v1/groups/").and_then(|p| p.strip_suffix("/users")) {
                    let members: Vec<Value> = v
                        .groups
                        .lock()
                        .unwrap()
                        .iter()
                        .find(|g| g.id == gid)
                        .map(|g| g.members.iter().map(|m| json!({"id": m, "status": "ACTIVE"})).collect())
                        .unwrap_or_default();
                    return MockResp::json(Value::Array(members));
                }
                MockResp::status(404, json!({"errorCode": "E0000007"}))
            }
            _ => MockResp::status(404, json!({"error": "not found"})),
        }
    })
}

fn t0() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-10-12T12:00:00Z").unwrap().with_timezone(&Utc)
}

fn okta_users() -> Vec<OktaUser> {
    let u = |i: u32, manager: Option<u32>| OktaUser {
        id: format!("00u{i}"),
        login: format!("user{i}@acme.example"),
        title: "Engineer".into(),
        manager: manager.map(|m| format!("00u{m}")),
        status: "ACTIVE",
        updated: t0() - chrono::Duration::days(3),
    };
    // 00u0 reports to 00u5 (a forward reference across pages).
    vec![u(0, Some(5)), u(1, Some(0)), u(2, Some(0)), u(3, None), u(4, Some(9)), u(5, None)]
}

fn groups() -> Vec<Group> {
    let g = |id: &str, name: &str, m: &[&str]| Group { id: id.into(), name: name.into(), members: m.iter().map(|s| s.to_string()).collect() };
    vec![
        g("00gA", "Engineering", &["00u0", "00u1", "00u2"]),
        g("00gB", "Okta Super Admin", &["00u0"]),
        g("00gC", "All Staff", &["00u0", "00u3"]),
    ]
}

async fn vendor() -> (Arc<Vendor>, Mock, Harness) {
    let v = Arc::new(Vendor {
        okta_users: Mutex::new(okta_users()),
        groups: Mutex::new(groups()),
        graph: Mutex::new(vec![]),
        graph_version: AtomicU64::new(1),
        graph_expired: AtomicBool::new(false),
        graph_401_once: AtomicBool::new(false),
        okta_429_once: Mutex::new(None),
        okta_429_at: Mutex::new(vec![]),
        broker: Mutex::new(BrokerMode::Ok),
        broker_calls: AtomicU32::new(0),
        broker_bad: AtomicU32::new(0),
        issued: AtomicU32::new(0),
        lazy_users: AtomicU64::new(0),
        okta: OktaOauth::default(),
    });
    let mock = start_mock(vendor_handler(v.clone()), false).await;
    let mut h = harness(&mock);
    #[cfg(feature = "enterprise")]
    { h.cfg.pull_broker = Some(Arc::new(PlatformBroker::new("https://pull-broker.nano.rs", "1", KEY).unwrap())); }
    *h.now.lock().unwrap() = t0();
    (v, mock, h)
}

// ------------------------------------------------------------ specs

const OKTA_USERS_PROGRAM: &str = r#"
      status = to_int(.response.status) ?? 0
      st = object(.state) ?? {}
      if status != 200 {
        {"error": "Okta answered HTTP " + to_string(status)}
      } else {
        if st.next_since == null { st.next_since = .now }
        rows = []
        for_each(array(.response.body) ?? []) -> |_i, u| {
          p = object(u.profile) ?? {}
          s = string(u.status) ?? ""
          rows = push(rows, {
            "external_id": u.id, "username": p.login, "upn": p.login, "email": p.email,
            "display_name": p.displayName, "first_name": p.firstName, "last_name": p.lastName,
            "department": p.department, "title": p.title, "manager_external_id": p.managerId,
            "account_status": downcase(s), "account_enabled": s == "ACTIVE", "deleted": s == "DEPROVISIONED",
            "created_in_directory_at": u.created, "last_sign_in_at": u.lastLogin, "employee_type": p.userType,
            "vendor_noise": {"nested": true}
          })
        }
        next = .response.links.next
        if is_string(next) {
          {"events": rows, "state": st, "next_request": {"url": next}}
        } else {
          st.filter = "lastUpdated gt \"" + string!(st.next_since) + "\""
          del(st.next_since)
          {"events": rows, "state": st}
        }
      }
"#;

const OKTA_MEMBERS_PROGRAM: &str = r#"
      status = to_int(.response.status) ?? 0
      if status != 200 {
        {"error": "Okta answered HTTP " + to_string(status)}
      } else {
        g = string(.item.profile.name) ?? ""
        priv = contains(g, "Admin")
        evs = []
        for_each(array(.response.body) ?? []) -> |_i, u| {
          evs = push(evs, {"member": u.id, "group": g, "privileged": priv})
        }
        {"events": evs}
      }
"#;

fn indent(program: &str) -> String {
    program.to_string()
}

fn okta_spec(mode: &str, with_groups: bool, page: usize) -> nano_connector::spec::ConnectorSpec {
    let mut y = format!(
        r#"version: 1
name: okta_directory
kind: identity
allow:
  - host: "{{{{config.OKTA_DOMAIN}}}}"
    host_suffixes: [".okta.com"]
    path_prefixes: ["/api/v1/users", "/api/v1/groups"]
auth: {{ type: okta_ssws, credential: API_TOKEN }}
limits: {{ max_run_secs: 1800, max_pages: 5000, max_requests: 20000, max_events: 5000000, max_event_bytes: 1073741824 }}
rate_limit: {{ backoff_ms: 50, max_wait_ms: 5000 }}
identity: {{ full_every_secs: 86400 }}
streams:
  - id: users
    identity: {{ role: users, mode: {mode} }}
    request:
      url: "https://{{{{config.OKTA_DOMAIN}}}}/api/v1/users"
      query: {{ limit: "{page}", filter: "{{{{state.filter}}}}" }}
      headers: {{ Accept: application/json }}
    program: |{}"#,
        indent(OKTA_USERS_PROGRAM)
    );
    if with_groups {
        y.push_str(&format!(
            r#"  - id: memberships
    identity: {{ role: memberships }}
    fanout:
      discover: {{ from: request, request: {{ url: "https://{{{{config.OKTA_DOMAIN}}}}/api/v1/groups" }} }}
      item_key: id
    request: {{ url: "https://{{{{config.OKTA_DOMAIN}}}}/api/v1/groups/{{{{item.id}}}}/users" }}
    program: |{}"#,
            indent(OKTA_MEMBERS_PROGRAM)
        ));
    }
    spec(&y)
}

const ENTRA_PROGRAM: &str = r#"
      status = to_int(.response.status) ?? 0
      st = object(.state) ?? {}
      if .response == null {
        if .identity.mode == "delta" && is_string(st.delta_link) {
          {"next_request": {"url": st.delta_link}, "state": st}
        } else {
          {"next_request": {"url": "https://graph.microsoft.com/v1.0/users/delta?$select=id,userPrincipalName,mail,displayName,accountEnabled,jobTitle,department,manager"}, "state": {}}
        }
      } else if status == 410 {
        {"restart_full": true}
      } else if status != 200 {
        {"error": "Graph answered HTTP " + to_string(status)}
      } else {
        rows = []
        for_each(array(.response.body.value) ?? []) -> |_i, u| {
          if u."@removed" != null {
            rows = push(rows, {"external_id": u.id, "deleted": true})
          } else {
            mgr = array(u."manager@delta") ?? []
            m = if length(mgr) > 0 { mgr[0].id } else { null }
            rows = push(rows, {"external_id": u.id, "upn": u.userPrincipalName, "email": u.mail,
              "display_name": u.displayName, "account_enabled": u.accountEnabled, "title": u.jobTitle,
              "department": u.department, "manager_external_id": m})
          }
        }
        next = .response.body."@odata.nextLink"
        if is_string(next) {
          {"events": rows, "state": st, "next_request": {"url": next}}
        } else {
          st.delta_link = .response.body."@odata.deltaLink"
          {"events": rows, "state": st}
        }
      }
"#;

fn entra_spec() -> nano_connector::spec::ConnectorSpec {
    spec(&format!(
        r#"version: 1
name: entra_directory
kind: identity
allow:
  - host: graph.microsoft.com
    path_prefixes: ["/v1.0/users", "/v1.0/groups"]
auth: {{ type: entra_fic_broker, directory_id: "{{{{config.DIRECTORY_ID}}}}", client_id: "{{{{config.CLIENT_ID}}}}" }}
limits: {{ max_run_secs: 120 }}
rate_limit: {{ backoff_ms: 50, max_wait_ms: 5000 }}
streams:
  - id: users
    identity: {{ role: users, mode: delta }}
    program: |{}"#,
        indent(ENTRA_PROGRAM)
    ))
}

fn okta_input(checkpoints: HashMap<String, Value>) -> RunInput {
    RunInput {
        config: config(json!({"OKTA_DOMAIN": "acme.okta.com"})),
        credentials: creds(&[("API_TOKEN", OKTA_TOKEN)]),
        checkpoints,
        tenant: Some(TENANT.into()),
        feed_id: Some(FEED.into()),
        ..Default::default()
    }
}

fn entra_input(checkpoints: HashMap<String, Value>) -> RunInput {
    RunInput {
        config: config(json!({"DIRECTORY_ID": DIRECTORY, "CLIENT_ID": CLIENT})),
        checkpoints,
        tenant: Some(TENANT.into()),
        feed_id: Some(FEED.into()),
        ..Default::default()
    }
}

fn opts() -> IdentitySinkOptions {
    IdentitySinkOptions { chunk_rows: 4, spill_dir: Some(std::env::temp_dir()), v2_fields: true, ..Default::default() }
}

struct Ran {
    out: Result<RunOutput, engine::EngineError>,
    store: Arc<SeqStore>,
    sink: Arc<IdentitySink>,
}

async fn run_identity(h: &Harness, coord: &Coord, spec: &nano_connector::spec::ConnectorSpec, input: RunInput, o: IdentitySinkOptions) -> Ran {
    let sink = Arc::new(IdentitySink::new(coord.client(), Uuid::parse_str(FEED).unwrap(), *h.now.lock().unwrap(), o));
    let store = Arc::new(SeqStore::default());
    let out = engine::run(&h.cfg, spec, input, sink.clone(), store.clone()).await;
    Ran { out, store, sink }
}

fn last_checkpoints(store: &SeqStore) -> HashMap<String, Value> {
    store.all().into_iter().map(|(_, s, v)| (s, v)).collect()
}

fn users_feed() -> String {
    format!("{FEED}:users")
}

// ------------------------------------------------------------ tests

#[tokio::test]
async fn okta_full_then_delta_stages_commits_and_moves_the_cursor_only_after_200() {
    let (v, _mock, h) = vendor().await;
    let coord = start_coord(TENANT).await;
    let spec = okta_spec("delta", false, 2);

    // ---- run 1: no checkpoint -> full
    let r = run_identity(&h, &coord, &spec, okta_input(HashMap::new()), opts()).await;
    let out = r.out.unwrap_or_else(|e| panic!("full run: {e}"));
    assert_eq!(out.identity_modes, vec![("users".to_string(), IdentityMode::Full)]);
    let log = coord.log();
    assert!(log.iter().all(|l| l.status < 300), "{log:?}");
    assert!(log.iter().all(|l| l.tenant.as_deref() == Some(TENANT)));
    let stage: Vec<&Logged> = log.iter().filter(|l| l.path.ends_with("/rows")).collect();
    let commit: Vec<&Logged> = log.iter().filter(|l| l.path.ends_with("/commit")).collect();
    assert_eq!(stage.len(), 2, "6 rows in chunks of 4: {log:?}");
    assert_eq!(commit.len(), 1);
    assert_eq!(commit[0].expected_rows, Some(6));
    assert!(commit[0].path.contains(&format!("/feeds/{}/runs/{}/commit", users_feed(), r.sink.run_id())));
    assert!(log.iter().all(|l| !l.path.ends_with("/deltas")));
    let rows = coord.rows_of(&users_feed());
    assert_eq!(rows.len(), 6);
    let u0 = &rows["00u0"];
    assert_eq!(u0["upn"], "user0@acme.example");
    assert_eq!(u0["manager_upn"], "user5@acme.example", "forward manager reference resolved: {u0}");
    assert_eq!(rows["00u1"]["manager_upn"], "user0@acme.example");
    assert!(rows["00u4"].get("manager_upn").is_none(), "manager 00u9 is not in the directory");
    assert_eq!(u0["source_kind"], "pull");
    assert_eq!(u0["snapshot_id"], r.sink.run_id());
    assert_eq!(u0["version"], json!(t0().timestamp_millis()));
    assert_eq!(u0["account_status"], "active");
    assert_eq!(u0["created_in_directory_at"], json!(1704164645000i64));
    assert!(u0.get("manager_external_id").is_none() && u0.get("is_admin").is_none() && u0.get("vendor_noise").is_none());
    assert!(r.sink.stats.spilled_rows.load(Ordering::SeqCst) >= 1);
    // The checkpoint: once, after the commit 200, with the last full time.
    let saves = r.store.all();
    assert_eq!(saves.len(), 1, "{saves:?}");
    assert!(saves[0].0 > commit[0].seq, "checkpoint before commit");
    assert_eq!(saves[0].2["identity_last_full_at"], "2026-10-12T12:00:00.000Z");
    assert_eq!(saves[0].2["state"]["filter"], "lastUpdated gt \"2026-10-12T12:00:00.000Z\"");

    // ---- run 2 (a minute later): changes -> delta
    {
        let mut users = v.okta_users.lock().unwrap();
        let later = t0() + chrono::Duration::seconds(30);
        users[1].title = "Staff Engineer".into();
        users[1].updated = later;
        users[2].status = "DEPROVISIONED";
        users[2].updated = later;
        users.push(OktaUser { id: "00u7".into(), login: "user7@acme.example".into(), title: "New".into(), manager: Some("00u5".into()), status: "ACTIVE", updated: later });
    }
    *h.now.lock().unwrap() = t0() + chrono::Duration::minutes(1);
    let before = coord.log().len();
    let r2 = run_identity(&h, &coord, &spec, okta_input(last_checkpoints(&r.store)), opts()).await;
    let out2 = r2.out.unwrap_or_else(|e| panic!("delta run: {e}"));
    assert_eq!(out2.identity_modes, vec![("users".to_string(), IdentityMode::Delta)]);
    let log2: Vec<Logged> = coord.log().into_iter().skip(before).collect();
    let deltas: Vec<&Logged> = log2.iter().filter(|l| l.path.ends_with("/deltas")).collect();
    assert_eq!(deltas.len(), 2, "3 changed users at 2 per page: {log2:?}");
    assert!(log2.iter().all(|l| !l.path.contains("/runs/")), "a delta run stages nothing");
    let sent: Vec<Value> = deltas.iter().flat_map(|l| l.rows.clone()).collect();
    assert_eq!(sent.len(), 3);
    let tomb = sent.iter().find(|r| r["external_id"] == "00u2").unwrap();
    assert_eq!(tomb["deleted"], true);
    assert_eq!(tomb["account_status"], "deprovisioned");
    let new = sent.iter().find(|r| r["external_id"] == "00u7").unwrap();
    assert!(new.get("manager_upn").is_none() && new.get("manager_external_id").is_none(), "00u5 did not change: sent by id, not as a row field");
    // Patch deltas whose managers outside the delta go by id.
    let body_refs: Vec<Value> = deltas.iter().flat_map(|l| l.manager_refs.clone()).collect();
    assert!(deltas.iter().all(|l| l.patch), "{deltas:?}");
    assert!(body_refs.contains(&json!({"feed_id": users_feed(), "external_id": "00u1", "manager_external_id": "00u0"})), "{body_refs:?}");
    assert!(body_refs.contains(&json!({"feed_id": users_feed(), "external_id": "00u7", "manager_external_id": "00u5"})), "{body_refs:?}");
    assert_eq!(r2.sink.stats.manager_refs.load(Ordering::SeqCst), 2);
    let rows = coord.rows_of(&users_feed());
    assert_eq!(rows.len(), 6, "-00u2 +00u7");
    assert!(!rows.contains_key("00u2"));
    assert_eq!(rows["00u1"]["title"], "Staff Engineer");
    // The coordinator review's P1: a delta row whose manager did not change
    // keeps its manager (and every field the delta did not resend).
    assert_eq!(rows["00u1"]["manager_upn"], "user0@acme.example", "{}", rows["00u1"]);
    assert_eq!(rows["00u1"]["upn"], "user1@acme.example");
    assert_eq!(rows["00u7"]["manager_upn"], "user5@acme.example", "resolved by id at the coordinator");
    // One checkpoint per delta page, each after its 200, keeping the full time.
    let saves2 = r2.store.all();
    assert_eq!(saves2.len(), 2, "{saves2:?}");
    for (save, delta) in saves2.iter().zip(&deltas) {
        assert!(save.0 > delta.seq);
        assert_eq!(save.2["identity_last_full_at"], "2026-10-12T12:00:00.000Z");
    }
    assert_eq!(saves2[1].2["state"]["filter"], "lastUpdated gt \"2026-10-12T12:01:00.000Z\"");

    // ---- run 3: a delta 500 fails the run and keeps the cursor
    {
        let mut users = v.okta_users.lock().unwrap();
        users[3].title = "Lead".into();
        users[3].updated = t0() + chrono::Duration::seconds(90);
    }
    *h.now.lock().unwrap() = t0() + chrono::Duration::minutes(2);
    coord.st.lock().unwrap().fail_deltas = 1;
    let r3 = run_identity(&h, &coord, &spec, okta_input(last_checkpoints(&r2.store)), opts()).await;
    let e = r3.out.unwrap_err().to_string();
    assert!(e.contains("HTTP 500"), "{e}");
    assert!(r3.store.all().is_empty(), "no checkpoint after a failed delta");

    // ---- run 4: past full_every_secs -> full; a commit 500 keeps the old
    // directory and the cursor, and abandons the staged run
    *h.now.lock().unwrap() = t0() + chrono::Duration::days(2);
    coord.st.lock().unwrap().fail_commit = 1;
    let r4 = run_identity(&h, &coord, &spec, okta_input(last_checkpoints(&r2.store)), opts()).await;
    let e = r4.out.unwrap_err().to_string();
    assert!(e.contains("commit") && e.contains("HTTP 500"), "{e}");
    assert!(r4.store.all().is_empty(), "no checkpoint after a failed commit");
    let aborts: Vec<Logged> = coord.log().into_iter().filter(|l| l.method == "DELETE" && l.path.contains(r4.sink.run_id())).collect();
    assert_eq!(aborts.len(), 1, "the staged run is abandoned");
    assert!(coord.st.lock().unwrap().staged.is_empty());
    assert_eq!(coord.rows_of(&users_feed()).len(), 6, "directory unchanged");

    // ---- run 5: the same full run succeeds and replaces the snapshot
    let r5 = run_identity(&h, &coord, &spec, okta_input(last_checkpoints(&r2.store)), opts()).await;
    let out5 = r5.out.unwrap_or_else(|e| panic!("full rerun: {e}"));
    assert_eq!(out5.identity_modes, vec![("users".to_string(), IdentityMode::Full)]);
    let rows = coord.rows_of(&users_feed());
    assert_eq!(rows.len(), 6);
    assert_eq!(rows["00u7"]["manager_upn"], "user5@acme.example", "resolved again in a full run");
    assert_eq!(r5.store.all()[0].2["identity_last_full_at"], "2026-10-14T12:00:00.000Z");
}

#[tokio::test]
async fn a_lost_commit_answer_is_retried_and_a_large_shrink_is_refused() {
    let (v, _mock, h) = vendor().await;
    let coord = start_coord(TENANT).await;
    let spec = okta_spec("full", false, 200);

    // ---- run 1: the commit lands but its answer is lost; the retry is a
    // 200 (idempotent commit), so the run succeeds and saves its cursor.
    coord.st.lock().unwrap().lose_commit_answer = 1;
    let r = run_identity(&h, &coord, &spec, okta_input(HashMap::new()), opts()).await;
    r.out.unwrap_or_else(|e| panic!("lost commit answer: {e}"));
    let commits: Vec<u16> = coord.log().iter().filter(|l| l.path.ends_with("/commit")).map(|l| l.status).collect();
    assert_eq!(commits, vec![503, 200]);
    let saved = last_checkpoints(&r.store);
    assert_eq!(saved["users"]["identity_last_full_rows"], 6);
    assert_eq!(coord.rows_of(&users_feed()).len(), 6);

    // ---- run 2: the vendor lists 2 of 6 users: refused before the
    // commit, the staged run abandoned, the directory and cursor kept.
    v.okta_users.lock().unwrap().truncate(2);
    *h.now.lock().unwrap() = t0() + chrono::Duration::minutes(1);
    let before = coord.log().len();
    let r2 = run_identity(&h, &coord, &spec, okta_input(saved.clone()), opts()).await;
    let e = r2.out.unwrap_err().to_string();
    assert!(e.contains("identity_shrink_refused") && e.contains("found 2 users") && e.contains("previous 6"), "{e}");
    let log2: Vec<Logged> = coord.log().into_iter().skip(before).collect();
    assert!(log2.iter().all(|l| !l.path.ends_with("/commit")), "{log2:?}");
    assert!(log2.iter().any(|l| l.method == "DELETE" && l.path.contains(r2.sink.run_id())));
    assert!(r2.store.all().is_empty());
    assert_eq!(coord.rows_of(&users_feed()).len(), 6);

    // ---- run 3: the feed config allows it.
    let mut input = okta_input(saved);
    input.config.insert("identity_allow_shrink".into(), json!(true));
    let r3 = run_identity(&h, &coord, &spec, input, opts()).await;
    r3.out.unwrap_or_else(|e| panic!("allowed shrink: {e}"));
    assert_eq!(coord.rows_of(&users_feed()).len(), 2);
    let saved3 = last_checkpoints(&r3.store);
    assert_eq!(saved3["users"]["identity_last_full_rows"], 2);

    // ---- run 4: the vendor lists no users. Without the feed config the
    // run fails and nothing commits; the coordinator would refuse it too.
    v.okta_users.lock().unwrap().clear();
    let before = coord.log().len();
    let r4 = run_identity(&h, &coord, &spec, okta_input(saved3.clone()), opts()).await;
    let e = r4.out.unwrap_err().to_string();
    assert!(e.contains("returned no users"), "{e}");
    assert!(coord.log().iter().skip(before).all(|l| !l.path.ends_with("/commit")));
    assert_eq!(coord.rows_of(&users_feed()).len(), 2);

    // ---- run 5: allowed: an empty snapshot, committed with allow_empty
    // and nothing staged.
    let mut input = okta_input(saved3);
    input.config.insert("identity_allow_shrink".into(), json!(true));
    let before = coord.log().len();
    let r5 = run_identity(&h, &coord, &spec, input, opts()).await;
    r5.out.unwrap_or_else(|e| panic!("allowed empty: {e}"));
    let log5: Vec<Logged> = coord.log().into_iter().skip(before).collect();
    assert!(log5.iter().all(|l| !l.path.ends_with("/rows")), "{log5:?}");
    let commit = log5.iter().find(|l| l.path.ends_with("/commit")).unwrap();
    assert_eq!((commit.expected_rows, commit.allow_empty, commit.status), (Some(0), true, 200));
    assert!(coord.rows_of(&users_feed()).is_empty());
    // Every non-empty commit went without the flag.
    assert!(coord.log().iter().filter(|l| l.path.ends_with("/commit") && l.expected_rows != Some(0)).all(|l| !l.allow_empty));
}

/// One full run (a locked and a staged user) then a second run (a
/// deprovisioned user), with the sink's v2 switch and the coordinator's
/// v2 support as given. With v2 the second run is a delta; without it,
/// users streams always run full. Returns the coordinator and the rows the
/// second run sent.
async fn status_runs(v2_sink: bool, v2_coord: bool) -> (Coord, Result<Vec<Value>, String>) {
    let (v, _mock, h) = vendor().await;
    let coord = start_coord(TENANT).await;
    coord.st.lock().unwrap().v2 = v2_coord;
    {
        let mut users = v.okta_users.lock().unwrap();
        users[3].status = "LOCKED_OUT";
        users[4].status = "STAGED";
    }
    let o = || IdentitySinkOptions { v2_fields: v2_sink, ..opts() };
    let spec = okta_spec("delta", false, 200);
    let r = run_identity(&h, &coord, &spec, okta_input(HashMap::new()), o()).await;
    if let Err(e) = r.out {
        return (coord, Err(e.to_string()));
    }
    {
        let mut users = v.okta_users.lock().unwrap();
        users[2].status = "DEPROVISIONED";
        users[2].updated = t0() + chrono::Duration::seconds(30);
    }
    *h.now.lock().unwrap() = t0() + chrono::Duration::minutes(1);
    let before = coord.log().len();
    let r2 = run_identity(&h, &coord, &spec, okta_input(last_checkpoints(&r.store)), o()).await;
    let out2 = match r2.out {
        Ok(out) => out,
        Err(e) => return (coord, Err(e.to_string())),
    };
    let mode = if v2_sink { IdentityMode::Delta } else { IdentityMode::Full };
    assert_eq!(out2.identity_modes, vec![("users".to_string(), mode)]);
    let sent = coord.log().into_iter().skip(before).filter(|l| l.path.ends_with("/deltas") || l.path.ends_with("/rows")).flat_map(|l| l.rows).collect();
    (coord, Ok(sent))
}

#[tokio::test]
async fn v2_fields_off_maps_statuses_onto_the_v1_set() {
    let (coord, sent) = status_runs(false, false).await;
    let sent = sent.unwrap_or_else(|e| panic!("v1: {e}"));
    let rows = coord.rows_of(&users_feed());
    assert_eq!(rows["00u3"]["account_status"], "suspended");
    assert_eq!(rows["00u4"]["account_status"], "unknown");
    // The second run was full (no deltas without v2): the deprovisioned
    // user is not listed, so the snapshot replace drops it.
    assert_eq!(sent.len(), 5, "{sent:?}");
    assert!(sent.iter().all(|r| r["external_id"] != "00u2"));
    assert!(!rows.contains_key("00u2"));
    assert!(coord.log().iter().all(|l| !l.path.ends_with("/deltas") && !l.patch));
    assert!(coord.log().iter().flat_map(|l| l.rows.clone()).all(|r| r.get("is_admin").is_none()));
    // Off is also safe against a v2 coordinator.
    let (_, sent) = status_runs(false, true).await;
    assert!(sent.is_ok());
}

#[tokio::test]
async fn v2_fields_on_passes_raw_statuses_and_needs_a_v2_coordinator() {
    let (coord, sent) = status_runs(true, true).await;
    let sent = sent.unwrap_or_else(|e| panic!("v2: {e}"));
    let rows = coord.rows_of(&users_feed());
    assert_eq!(rows["00u3"]["account_status"], "locked");
    assert_eq!(rows["00u4"]["account_status"], "staged");
    assert_eq!(rows["00u0"]["account_status"], "active");
    let tomb = sent.iter().find(|r| r["external_id"] == "00u2").unwrap();
    assert_eq!((tomb["account_status"].as_str(), tomb["deleted"].as_bool()), (Some("deprovisioned"), Some(true)));
    // Why the switch stays off until every cell has #6294: a v1 coordinator
    // refuses the raw statuses, so the full run fails and nothing commits.
    let (coord, sent) = status_runs(true, false).await;
    let e = sent.unwrap_err();
    assert!(e.contains("HTTP 400"), "{e}");
    assert!(coord.rows_of(&users_feed()).is_empty());
}

#[tokio::test]
async fn memberships_aggregate_per_member_with_is_admin_from_privileged_groups() {
    let (_v, _mock, h) = vendor().await;
    let coord = start_coord(TENANT).await;
    coord.st.lock().unwrap().v2 = true;
    let spec = okta_spec("full", true, 200);
    let r = run_identity(&h, &coord, &spec, okta_input(HashMap::new()), IdentitySinkOptions { v2_fields: true, ..opts() }).await;
    r.out.unwrap_or_else(|e| panic!("run: {e}"));
    let groups = coord.rows_of(&format!("{FEED}:groups"));
    assert_eq!(groups.len(), 4, "{groups:?}");
    let u0 = &groups["00u0"];
    assert_eq!(u0["groups"], json!(["All Staff", "Engineering", "Okta Super Admin"]));
    assert_eq!(u0["is_admin"], true);
    assert_eq!(groups["00u1"]["groups"], json!(["Engineering"]));
    assert_eq!(groups["00u1"]["is_admin"], false);
    assert_eq!(groups["00u3"]["groups"], json!(["All Staff"]));
    // Group rows carry only identity, provenance and groups.
    let keys: BTreeSet<&str> = u0.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, BTreeSet::from(["external_id", "feed_id", "groups", "is_admin", "observed_at", "snapshot_id", "source_kind", "version"]));
    // Users first, then memberships; both committed; no checkpoint for memberships.
    let commits: Vec<String> = coord.log().into_iter().filter(|l| l.path.ends_with("/commit")).map(|l| l.path).collect();
    assert_eq!(commits.len(), 2);
    assert!(commits[0].contains(":users/") && commits[1].contains(":groups/"), "{commits:?}");
    assert!(r.store.all().iter().all(|(_, s, _)| s == "users"));

    // Without the coordinator column, `is_admin` is never sent (the
    // coordinator refuses unknown fields).
    let coord2 = start_coord(TENANT).await;
    coord2.st.lock().unwrap().v2 = false;
    let r = run_identity(&h, &coord2, &spec, okta_input(HashMap::new()), IdentitySinkOptions { v2_fields: false, ..opts() }).await;
    r.out.unwrap_or_else(|e| panic!("run without is_admin: {e}"));
    assert!(coord2.log().iter().flat_map(|l| l.rows.clone()).all(|r| r.get("is_admin").is_none()));
    assert_eq!(coord2.rows_of(&format!("{FEED}:groups")).len(), 4);
}

#[tokio::test]
async fn vendor_429_retry_after_is_honoured_inside_the_run() {
    let (v, _mock, h) = vendor().await;
    let coord = start_coord(TENANT).await;
    *v.okta_429_once.lock().unwrap() = Some(1);
    let started = Instant::now();
    let r = run_identity(&h, &coord, &okta_spec("full", false, 200), okta_input(HashMap::new()), opts()).await;
    r.out.unwrap_or_else(|e| panic!("run: {e}"));
    let at = v.okta_429_at.lock().unwrap().clone();
    assert!(at.len() >= 2);
    assert!(at[1].duration_since(at[0]) >= Duration::from_secs(1), "Retry-After: 1 honoured");
    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(coord.rows_of(&users_feed()).len(), 6);
}

#[cfg(feature = "enterprise")]
#[tokio::test]
async fn entra_full_delta_removed_tombstones_and_410_restart_full() {
    let (v, mock, h) = vendor().await;
    let coord = start_coord(TENANT).await;
    {
        let mut g = v.graph.lock().unwrap();
        let u = |id: &str, m: Option<&str>| GraphUser { id: id.into(), upn: format!("{id}@contoso.example"), manager: m.map(Into::into), removed: false, changed: 1 };
        *g = vec![u("a1", Some("a3")), u("a2", Some("a1")), u("a3", None)];
    }
    let spec = entra_spec();
    let r = run_identity(&h, &coord, &spec, entra_input(HashMap::new()), opts()).await;
    let out = r.out.unwrap_or_else(|e| panic!("entra full: {e}"));
    assert_eq!(out.identity_modes, vec![("users".to_string(), IdentityMode::Full)]);
    let rows = coord.rows_of(&users_feed());
    assert_eq!(rows.len(), 3);
    assert_eq!(rows["a1"]["manager_upn"], "a3@contoso.example");
    assert_eq!(rows["a2"]["manager_upn"], "a1@contoso.example");
    let cp = last_checkpoints(&r.store);
    assert!(cp["users"]["state"]["delta_link"].as_str().unwrap().contains("$deltatoken=1"));
    assert_eq!(v.broker_calls.load(Ordering::SeqCst), 1, "one Graph token for the run");
    assert_eq!(v.broker_bad.load(Ordering::SeqCst), 0);
    // The token reaches only Graph; never the coordinator or a checkpoint.
    for l in coord.log() {
        assert!(!format!("{:?}", l.rows).contains("GRAPH-SIG"));
    }
    assert!(!format!("{cp:?}").contains("GRAPH-SIG"));
    assert!(mock.requests().iter().filter(|r| r.host != "graph.microsoft.com").all(|r| !format!("{:?}", r.headers).contains("GRAPH-SIG")));

    // ---- delta: a2 removed, a4 added (manager a3 unchanged)
    {
        let mut g = v.graph.lock().unwrap();
        g[1].removed = true;
        g[1].changed = 2;
        g.push(GraphUser { id: "a4".into(), upn: "a4@contoso.example".into(), manager: Some("a3".into()), removed: false, changed: 2 });
        v.graph_version.store(2, Ordering::SeqCst);
    }
    *h.now.lock().unwrap() = t0() + chrono::Duration::hours(1);
    v.graph_401_once.store(true, Ordering::SeqCst);
    let r2 = run_identity(&h, &coord, &spec, entra_input(cp.clone()), opts()).await;
    let out2 = r2.out.unwrap_or_else(|e| panic!("entra delta: {e}"));
    assert_eq!(out2.identity_modes, vec![("users".to_string(), IdentityMode::Delta)]);
    assert_eq!(v.broker_calls.load(Ordering::SeqCst), 3, "the Graph 401 refreshed the token once");
    let rows = coord.rows_of(&users_feed());
    assert_eq!(rows.keys().cloned().collect::<Vec<_>>(), vec!["a1", "a3", "a4"]);
    let sent: Vec<Value> = coord.log().into_iter().filter(|l| l.path.ends_with("/deltas")).flat_map(|l| l.rows).collect();
    assert_eq!(sent.iter().find(|r| r["external_id"] == "a2").unwrap()["deleted"], true);
    let cp2 = last_checkpoints(&r2.store);
    assert!(cp2["users"]["state"]["delta_link"].as_str().unwrap().contains("$deltatoken=2"));
    assert_eq!(cp2["users"]["identity_last_full_at"], cp["users"]["identity_last_full_at"]);

    // ---- 410 Gone: the program asks for a full run; the engine reruns it.
    v.graph_expired.store(true, Ordering::SeqCst);
    *h.now.lock().unwrap() = t0() + chrono::Duration::hours(2);
    let commits_before = coord.log().iter().filter(|l| l.path.ends_with("/commit")).count();
    let r3 = run_identity(&h, &coord, &spec, entra_input(cp2), opts()).await;
    let out3 = r3.out.unwrap_or_else(|e| panic!("entra 410 restart: {e}"));
    assert_eq!(out3.identity_modes, vec![("users".to_string(), IdentityMode::Full)]);
    assert_eq!(coord.log().iter().filter(|l| l.path.ends_with("/commit")).count(), commits_before + 1);
    let cp3 = last_checkpoints(&r3.store);
    assert_eq!(cp3["users"]["identity_last_full_at"], "2026-10-12T14:00:00.000Z");
    assert_eq!(coord.rows_of(&users_feed()).len(), 3);
}

#[cfg(feature = "enterprise")]
#[tokio::test]
async fn entra_fic_broker_refuses_wrong_resource_and_directory_and_honours_broker_429() {
    let (v, _mock, h) = vendor().await;
    let coord = start_coord(TENANT).await;
    v.graph.lock().unwrap().push(GraphUser { id: "a1".into(), upn: "a1@contoso.example".into(), manager: None, removed: false, changed: 1 });
    let spec = entra_spec();

    *v.broker.lock().unwrap() = BrokerMode::WrongResource;
    let e = run_identity(&h, &coord, &spec, entra_input(HashMap::new()), opts()).await.out.unwrap_err().to_string();
    assert!(e.contains("entra_fic_broker_failed") && e.contains("another resource"), "{e}");
    assert!(!e.contains("GRAPH-SIG"), "{e}");

    *v.broker.lock().unwrap() = BrokerMode::WrongDirectory;
    let e = run_identity(&h, &coord, &spec, entra_input(HashMap::new()), opts()).await.out.unwrap_err().to_string();
    assert!(e.contains("another directory"), "{e}");
    assert!(coord.log().is_empty(), "nothing reached the coordinator");

    *v.broker.lock().unwrap() = BrokerMode::RateLimitedOnce(1);
    v.broker_calls.store(0, Ordering::SeqCst);
    let t = Instant::now();
    run_identity(&h, &coord, &spec, entra_input(HashMap::new()), opts()).await.out.unwrap_or_else(|e| panic!("after broker 429: {e}"));
    assert!(t.elapsed() >= Duration::from_secs(1));
    assert_eq!(v.broker_calls.load(Ordering::SeqCst), 2);
    assert_eq!(v.broker_bad.load(Ordering::SeqCst), 0, "exact body and headers");

    // A non-GUID directory id never reaches the broker.
    *v.broker.lock().unwrap() = BrokerMode::Ok;
    v.broker_calls.store(0, Ordering::SeqCst);
    let mut input = entra_input(HashMap::new());
    input.config = config(json!({"DIRECTORY_ID": "contoso.onmicrosoft.com", "CLIENT_ID": CLIENT}));
    let e = run_identity(&h, &coord, &spec, input, opts()).await.out.unwrap_err().to_string();
    assert!(e.contains("directory_id must be a GUID"), "{e}");
    assert_eq!(v.broker_calls.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "enterprise")]
#[tokio::test]
async fn google_dwd_broker_sends_space_separated_scopes_as_an_array() {
    let seen = Arc::new(Mutex::new(None::<Value>));
    let seen2 = seen.clone();
    let mock = start_mock(
        Arc::new(move |r: &MockReq| {
            if r.path == "/v1/google/dwd-assertion" {
                *seen2.lock().unwrap() = serde_json::from_slice(&r.body).ok();
            }
            MockResp::status(403, json!({"error": "stop"}))
        }),
        false,
    )
    .await;
    let mut h = harness(&mock);
    #[cfg(feature = "enterprise")]
    { h.cfg.pull_broker = Some(Arc::new(PlatformBroker::new("https://pull-broker.nano.rs", "1", KEY).unwrap())); }
    let s = spec(
        r#"version: 1
name: gws_directory
kind: identity
allow:
  - host: admin.googleapis.com
  - host: oauth2.googleapis.com
auth: { type: google_dwd_broker, token_url: "https://oauth2.googleapis.com/token", subject: "admin@example.com",
        scope: "https://www.googleapis.com/auth/admin.directory.user.readonly  https://www.googleapis.com/auth/admin.directory.group.readonly" }
streams:
  - id: users
    identity: { role: users }
    request: { url: "https://admin.googleapis.com/admin/directory/v1/users" }
    response: { events_path: users }
"#,
    );
    let coord = start_coord(TENANT).await;
    let r = run_identity(&h, &coord, &s, okta_input(HashMap::new()), opts()).await;
    assert!(r.out.unwrap_err().to_string().contains("google_dwd_broker_denied"));
    assert_eq!(
        seen.lock().unwrap().clone().unwrap()["scope"],
        json!(["https://www.googleapis.com/auth/admin.directory.user.readonly", "https://www.googleapis.com/auth/admin.directory.group.readonly"])
    );
}

#[test]
fn identity_spec_shape_is_validated() {
    let ceil = engine::default_ceilings();
    let compile = |y: &str| engine::compile(&spec(y), &ceil).map(|_| ()).map_err(|e| e.to_string());
    let head = "version: 1\nname: x\nallow: [{host: api.example.com}]\n";
    let users = "  - id: users\n    identity: { role: users }\n    request: { url: \"https://api.example.com/u\" }\n";
    assert!(compile(&format!("{head}kind: identity\nstreams:\n{users}")).is_ok());
    let e = compile(&format!("{head}kind: collector\nstreams:\n{users}")).unwrap_err();
    assert!(e.contains("only valid under `kind: identity`"), "{e}");
    let e = compile(&format!("{head}kind: collector\nidentity: {{ full_every_secs: 3600 }}\nstreams:\n  - id: s\n    request: {{ url: \"https://api.example.com/u\" }}\n")).unwrap_err();
    assert!(e.contains("only valid under `kind: identity`"), "{e}");
    let e = compile(&format!("{head}kind: identity\nstreams:\n  - id: s\n    request: {{ url: \"https://api.example.com/u\" }}\n")).unwrap_err();
    assert!(e.contains("needs `identity"), "{e}");
    let e = compile(&format!("{head}kind: identity\nstreams:\n  - id: m\n    identity: {{ role: memberships, mode: delta }}\n    request: {{ url: \"https://api.example.com/u\" }}\n")).unwrap_err();
    assert!(e.contains("always full"), "{e}");
    let e = compile(&format!("{head}kind: identity\nstreams:\n  - id: groups\n    identity: {{ role: users }}\n    request: {{ url: \"https://api.example.com/u\" }}\n")).unwrap_err();
    assert!(e.contains("must have id `users`"), "{e}");
    let e = compile(&format!(
        "{head}kind: identity\nstreams:\n  - id: users\n    identity: {{ role: users }}\n    fanout: {{ discover: {{ from: static, items: [a] }} }}\n    request: {{ url: \"https://api.example.com/u\" }}\n"
    ))
    .unwrap_err();
    assert!(e.contains("cannot fan out"), "{e}");
    let e = compile(&format!("{head}kind: identity\nidentity: {{ full_every_secs: 10 }}\nstreams:\n{users}")).unwrap_err();
    assert!(e.contains("full_every_secs"), "{e}");
    let e = compile(&format!("{head}kind: identity\nstreams:\n  - id: \"a/b\"\n    identity: {{ role: users }}\n    request: {{ url: \"https://api.example.com/u\" }}\n")).unwrap_err();
    assert!(e.contains("must be 1-64"), "{e}");
    // The schema documents the new shapes.
    let docs = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/connector.schema.json")).unwrap();
    let now = serde_json::to_string_pretty(&nano_connector::spec::ConnectorSpec::json_schema()).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&docs).unwrap(), serde_json::from_str::<Value>(&now).unwrap(), "regenerate docs/connector.schema.json");
    assert!(docs.contains("entra_fic_broker") && docs.contains("\"identity\""));
}

// ------------------------------------------------------------ runner, two tenants

fn assignments_file(dir: &std::path::Path, entries: &[(&str, &Coord)]) -> std::path::PathBuf {
    std::fs::create_dir_all(dir.join("tokens")).unwrap();
    let mut map = Map::new();
    for (tenant, coord) in entries {
        let tok = dir.join("tokens").join(tenant);
        std::fs::write(&tok, COORD_TOKEN).unwrap();
        map.insert(tenant.to_string(), json!({"internal_endpoint": coord.url(), "credential_file": tok, "timeout_secs": 30}));
    }
    let p = dir.join("assignments.json");
    std::fs::write(&p, Value::Object(map).to_string()).unwrap();
    p
}

fn identity_feed(tenant: &str, feed: Uuid, yaml: &str, cfg: Value) -> FeedDefinition {
    FeedDefinition {
        tenant_id: Uuid::parse_str(tenant).unwrap(),
        feed_id: feed,
        name: "Okta directory".into(),
        connector: "okta_directory".into(),
        spec_sha256: spec_sha256(yaml),
        spec_yaml: yaml.to_string(),
        source_slug: "okta_directory".into(),
        schedule: None,
        config: config(cfg),
        vendor_credentials: HashMap::from([("API_TOKEN".to_string(), Secret::new(OKTA_TOKEN))]),
        ingest_url: String::new(),
        ingest_token: Secret::new(""),
        max_run_secs: Some(120),
        consecutive_failures: 0,
    }
}

#[tokio::test]
async fn runner_two_tenants_each_reach_only_their_own_coordinator() {
    let (_v, _mock, h) = vendor().await;
    let coord_a = start_coord(TENANT).await;
    // B's coordinator answers only B's tenant, with the same token on purpose:
    // the tenant binding is in the body, not the bearer.
    let coord_b = start_coord(TENANT_B).await;
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("nan3503-assign-{}", Uuid::new_v4().simple()));
    // Distinct token files per tenant (aliasing is refused).
    let path = assignments_file(&dir, &[(TENANT, &coord_a), (TENANT_B, &coord_b)]);
    let (feed_a, feed_b, feed_c) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    // Tenant A's spec, config and rows all claim tenant B and B's feed.
    let spoof = OKTA_USERS_PROGRAM.replace(
        "\"vendor_noise\": {\"nested\": true}",
        &format!("\"tenant_id\": \"{TENANT_B}\", \"feed_id\": \"{feed_b}:users\", \"source_kind\": \"push\", \"snapshot_id\": \"spoof\""),
    );
    let yaml_a = {
        let mut s = okta_spec("full", true, 200);
        s.streams[0].program = Some(spoof.clone());
        serde_yaml::to_string(&s).unwrap()
    };
    let yaml_b = serde_yaml::to_string(&okta_spec("full", false, 200)).unwrap();
    let store = Arc::new(MemoryFeedStore::default());
    store.add(identity_feed(TENANT, feed_a, &yaml_a, json!({"OKTA_DOMAIN": "acme.okta.com", "tenant_id": TENANT_B, "TENANT_ID": TENANT_B})), Uuid::now_v7());
    store.add(identity_feed(TENANT_B, feed_b, &yaml_b, json!({"OKTA_DOMAIN": "acme.okta.com"})), Uuid::now_v7());
    // A third tenant has no coordinator assignment.
    let tenant_c = "3c3c3c3c-3c3c-4c3c-8c3c-3c3c3c3c3c3c";
    store.add(identity_feed(tenant_c, feed_c, &yaml_b, json!({"OKTA_DOMAIN": "acme.okta.com"})), Uuid::now_v7());

    let mut cfg = RunnerConfig::new("runner-a", h.cfg.clone());
    cfg.identity_assignments = Some(Arc::new(nanosiem_core::enrichment::lean_assignments::LeanAssignmentSource::with_interval(&path, Duration::from_secs(10))));
    cfg.identity.spill_dir = Some(dir.clone());
    let runner = Runner::new(store.clone(), cfg);
    let tick = runner.tick().await.unwrap();
    assert_eq!(tick.claimed, 3, "identity feeds are claimed without an ingest token");
    let records = runner.drain().await;
    let by_status: Vec<RunStatus> = records.iter().map(|r| r.status).collect();
    assert_eq!(by_status.iter().filter(|s| **s == RunStatus::Success).count(), 2, "{records:?}");
    let failed = records.iter().find(|r| r.status == RunStatus::Failed).unwrap();
    assert!(failed.error.as_deref().unwrap().starts_with("identity_coordinator_unassigned"), "{failed:?}");

    let a = coord_a.log();
    let b = coord_b.log();
    assert!(!a.is_empty() && !b.is_empty());
    assert!(a.iter().all(|l| l.tenant.as_deref() == Some(TENANT) && l.status < 300), "{a:?}");
    assert!(b.iter().all(|l| l.tenant.as_deref() == Some(TENANT_B) && l.status < 300), "{b:?}");
    // Paths and every row of A name A's feed only; the spoofed fields lost.
    let a_prefix = format!("{feed_a}:");
    assert!(a.iter().all(|l| !l.path.contains("/feeds/") || l.path.contains(&a_prefix)), "{a:?}");
    for row in a.iter().flat_map(|l| l.rows.clone()) {
        assert!(row["feed_id"].as_str().unwrap().starts_with(&a_prefix), "{row}");
        assert_eq!(row["source_kind"], "pull");
        assert_ne!(row["snapshot_id"], "spoof");
        assert!(row.get("tenant_id").is_none());
    }
    assert!(b.iter().all(|l| !l.path.contains(&a_prefix)));
    assert_eq!(coord_a.rows_of(&format!("{feed_a}:users")).len(), 6);
    assert_eq!(coord_a.rows_of(&format!("{feed_a}:groups")).len(), 4);
    assert_eq!(coord_b.rows_of(&format!("{feed_b}:users")).len(), 6);
    assert!(coord_b.rows_of(&format!("{feed_a}:users")).is_empty());
    // The checkpoint moved for the successful feeds only.
    assert!(store.checkpoint(feed_a, "users").is_some() && store.checkpoint(feed_b, "users").is_some());
    assert!(store.checkpoint(feed_c, "users").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Uninstall: the API sets pending delete (and disables the feed); the
/// runner removes `<feed>:users` and `<feed>:groups` at the claimed
/// tenant's coordinator, then hard-deletes the row. A failed delete is
/// recorded and retried after its backoff; another tenant is untouched.
#[tokio::test]
async fn an_uninstalled_identity_feed_is_removed_from_the_directory_and_retried_on_failure() {
    let (_v, _mock, h) = vendor().await;
    let coord_a = start_coord(TENANT).await;
    let coord_b = start_coord(TENANT_B).await;
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("nan3503-uninstall-{}", Uuid::new_v4().simple()));
    let path = assignments_file(&dir, &[(TENANT, &coord_a), (TENANT_B, &coord_b)]);
    let (feed_a, feed_b, feed_idle) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    let yaml = serde_yaml::to_string(&okta_spec("full", true, 200)).unwrap();
    let cfg = || json!({"OKTA_DOMAIN": "acme.okta.com"});
    let store = Arc::new(MemoryFeedStore::default());
    store.add(identity_feed(TENANT, feed_a, &yaml, cfg()), Uuid::now_v7());
    store.add(identity_feed(TENANT_B, feed_b, &yaml, cfg()), Uuid::now_v7());
    let mut rc = RunnerConfig::new("runner-u", h.cfg.clone());
    rc.identity_assignments = Some(Arc::new(nanosiem_core::enrichment::lean_assignments::LeanAssignmentSource::with_interval(&path, Duration::from_secs(10))));
    rc.identity.spill_dir = Some(dir.clone());
    let runner = Runner::new(store.clone(), rc);
    assert_eq!(runner.tick().await.unwrap().claimed, 2);
    assert!(runner.drain().await.iter().all(|r| r.status == RunStatus::Success));
    let (a_users, a_groups) = (format!("{feed_a}:users"), format!("{feed_a}:groups"));
    assert_eq!((coord_a.rows_of(&a_users).len(), coord_a.rows_of(&a_groups).len()), (6, 4));
    let b_before = coord_b.dir();
    assert_eq!(b_before.len(), 10);

    // ---- uninstall A's feed; the first delete fails.
    store.mark_pending_delete(feed_a, true);
    coord_a.st.lock().unwrap().fail_delete = 1;
    let tick = runner.tick().await.unwrap();
    assert_eq!((tick.claimed, tick.deletes), (0, 1), "a pending delete never runs: {tick:?}");
    runner.drain().await;
    assert!(store.has_feed(feed_a), "kept after a failed delete");
    let (attempts, error) = store.delete_state(feed_a).unwrap();
    assert_eq!(attempts, 1);
    assert!(error.as_deref().unwrap().contains("HTTP 500"), "{error:?}");
    // Backing off: the next tick leaves it alone.
    assert_eq!(runner.tick().await.unwrap().deletes, 0);
    runner.drain().await;

    // ---- reinstall while A's delete is pending: a new feed uuid, so new
    // sub-feeds, which A's delete never touches.
    let feed_a2 = Uuid::now_v7();
    store.add(identity_feed(TENANT, feed_a2, &yaml, cfg()), Uuid::now_v7());
    let tick = runner.tick().await.unwrap();
    assert_eq!((tick.claimed, tick.deletes), (1, 0), "{tick:?}");
    assert!(runner.drain().await.iter().all(|r| r.status == RunStatus::Success));
    let (a2_users, a2_groups) = (format!("{feed_a2}:users"), format!("{feed_a2}:groups"));
    assert_eq!((coord_a.rows_of(&a2_users).len(), coord_a.rows_of(&a2_groups).len()), (6, 4));

    // ---- the backoff passed: both sub-feeds go, then the row.
    store.make_delete_due(feed_a);
    assert_eq!(runner.tick().await.unwrap().deletes, 1);
    runner.drain().await;
    assert!(!store.has_feed(feed_a), "hard-deleted once the directory is clean");
    assert!(store.checkpoint(feed_a, "users").is_none());
    assert!(coord_a.rows_of(&a_users).is_empty() && coord_a.rows_of(&a_groups).is_empty());
    // The reinstalled feed survives.
    assert!(store.has_feed(feed_a2));
    assert_eq!((coord_a.rows_of(&a2_users).len(), coord_a.rows_of(&a2_groups).len()), (6, 4));
    let deletes: Vec<String> = coord_a.log().into_iter().filter(|l| l.method == "DELETE" && l.status < 300).map(|l| l.path).collect();
    assert_eq!(deletes, vec![format!("/v1/identity/directory/feeds/{a_users}"), format!("/v1/identity/directory/feeds/{a_groups}")]);
    assert!(coord_a.log().iter().all(|l| l.tenant.as_deref() == Some(TENANT)));
    // Tenant B: untouched, never called for A.
    assert_eq!(coord_b.dir(), b_before);
    assert!(coord_b.log().iter().all(|l| l.method != "DELETE"));
    assert!(store.has_feed(feed_b));

    // ---- uninstall the reinstall too: tenant A's directory is now empty.
    store.mark_pending_delete(feed_a2, true);
    assert_eq!(runner.tick().await.unwrap().deletes, 1);
    runner.drain().await;
    assert!(!store.has_feed(feed_a2));
    assert!(coord_a.dir().is_empty());

    // ---- a feed that never wrote, against an empty directory: the
    // coordinator answers 404, which counts as removed.
    store.add(identity_feed(TENANT, feed_idle, &yaml, cfg()), Uuid::now_v7());
    store.mark_pending_delete(feed_idle, true);
    assert_eq!(runner.tick().await.unwrap().deletes, 1);
    runner.drain().await;
    assert!(!store.has_feed(feed_idle));
    assert!(coord_a.log().iter().any(|l| l.method == "DELETE" && l.status == 404));
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------ scale

fn vm_kib(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix(field).map(|v| v.trim().trim_end_matches(" kB").trim().parse().unwrap_or(0)))
        .unwrap_or(0)
}

/// 500k Okta-style users through a full run: lazily generated pages, a
/// count-only coordinator. Run with
/// `cargo test --release -p nano-connector --test identity -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "500k users: minutes in debug; run in release"]
#[allow(non_snake_case)]
async fn five_hundred_thousand_users_full_run_bounded_memory() {
    // NANO_IDENTITY_SCALE_USERS overrides the size for quicker local probes.
    let n_users: u64 = std::env::var("NANO_IDENTITY_SCALE_USERS").ok().and_then(|v| v.parse().ok()).unwrap_or(500_000);
    let N = n_users;
    let sampler = tokio::spawn(async {
        let t = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            println!("  t={:>4}s VmRSS {} MiB", t.elapsed().as_secs(), vm_kib("VmRSS:") / 1024);
        }
    });
    let (v, _mock, h) = vendor().await;
    v.lazy_users.store(N, Ordering::SeqCst);
    let coord = start_coord(TENANT).await;
    coord.st.lock().unwrap().count_only = true;
    let spill = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let hwm0 = vm_kib("VmHWM:");
    let rss0 = vm_kib("VmRSS:");
    let t = Instant::now();
    let r = run_identity(
        &h,
        &coord,
        &okta_spec("full", false, 1000),
        okta_input(HashMap::new()),
        IdentitySinkOptions { spill_dir: Some(spill), ..Default::default() },
    )
    .await;
    let elapsed = t.elapsed();
    sampler.abort();
    let out = r.out.unwrap_or_else(|e| panic!("500k run: {e}"));
    let s = &r.sink.stats;
    let (hwm1, rss1) = (vm_kib("VmHWM:"), vm_kib("VmRSS:"));
    let commit = coord.log().into_iter().find(|l| l.path.ends_with("/commit")).unwrap();
    println!(
        "500k: {:.1} s, pages {}, requests {}, rows {}, chunks staged {}, spilled {}, managers resolved {} unresolved {}, map entries {}, peak buffered rows {}, VmHWM {} -> {} MiB (+{}), VmRSS {} -> {} MiB",
        elapsed.as_secs_f64(),
        out.pages,
        out.requests,
        s.rows.load(Ordering::SeqCst),
        coord.log().iter().filter(|l| l.path.ends_with("/rows")).count(),
        s.spilled_rows.load(Ordering::SeqCst),
        s.managers_resolved.load(Ordering::SeqCst),
        s.managers_unresolved.load(Ordering::SeqCst),
        s.manager_map_entries.load(Ordering::SeqCst),
        s.peak_buffered_rows.load(Ordering::SeqCst),
        hwm0 / 1024,
        hwm1 / 1024,
        (hwm1 - hwm0) / 1024,
        rss0 / 1024,
        rss1 / 1024,
    );
    assert_eq!(commit.expected_rows, Some(N));
    assert_eq!(coord.st.lock().unwrap().rows_seen, N);
    assert_eq!(s.managers_unresolved.load(Ordering::SeqCst), 0);
    assert_eq!(s.managers_resolved.load(Ordering::SeqCst), N, "every lazy user has a manager in the directory");
    assert!(s.peak_buffered_rows.load(Ordering::SeqCst) <= nano_connector::identity::CHUNK_ROWS as u64);
    assert_eq!(s.manager_map_entries.load(Ordering::SeqCst), N);
    // The sink holds one chunk plus the id -> manager map; the spill is on
    // disk. The whole process (mock vendor and mock coordinator included)
    // stays well under the size of the directory as JSON (~250 MiB).
    assert!(hwm1 - hwm0 < 400 * 1024, "peak RSS grew by {} MiB", (hwm1 - hwm0) / 1024);
}

// ------------------------------------------------------------ auth and paging (lane C specs)

const GRAPH_MEMBERS_PROGRAM: &str = r#"
      status = to_int(.response.status) ?? 0
      if status != 200 {
        {"error": "Graph answered HTTP " + to_string(status)}
      } else {
        g = string(.item.displayName) ?? ""
        evs = []
        for_each(array(.response.body.value) ?? []) -> |_i, u| {
          evs = push(evs, {"member": u.id, "group": g, "privileged": contains(g, "Admin")})
        }
        {"events": evs}
      }
"#;

fn entra_oauth2_spec(max_items: Option<u32>) -> nano_connector::spec::ConnectorSpec {
    let cap = max_items.map(|m| format!("\n      max_items: {m}")).unwrap_or_default();
    spec(&format!(
        r#"version: 1
name: entra_directory_selfhosted
kind: identity
allow:
  - host: graph.microsoft.com
    path_prefixes: ["/v1.0/users", "/v1.0/groups"]
  - host: login.microsoftonline.com
auth:
  type: oauth2_client_credentials
  token_url: "https://login.microsoftonline.com/{{{{config.DIRECTORY_ID}}}}/oauth2/v2.0/token"
  client_id: "{{{{config.CLIENT_ID}}}}"
  client_secret_credential: CLIENT_SECRET
  scope: "https://graph.microsoft.com/.default"
rate_limit: {{ backoff_ms: 50, max_wait_ms: 5000 }}
streams:
  - id: users
    identity: {{ role: users, mode: delta }}
    program: |{ENTRA_PROGRAM}  - id: memberships
    identity: {{ role: memberships }}
    fanout:
      discover:
        from: request
        request: {{ url: "https://graph.microsoft.com/v1.0/groups" }}
        response: {{ events_path: value }}
        pagination: {{ type: next_url, pointer: "/@odata.nextLink" }}
      item_key: id{cap}
    request: {{ url: "https://graph.microsoft.com/v1.0/groups/{{{{item.id}}}}/members" }}
    program: |{GRAPH_MEMBERS_PROGRAM}"#
    ))
}

fn selfhosted_input() -> RunInput {
    let mut i = entra_input(HashMap::new());
    i.credentials = creds(&[("CLIENT_SECRET", "entra-client-secret-value")]);
    i
}

#[tokio::test]
async fn oauth2_templated_token_url_and_next_url_discovery_for_entra_memberships() {
    let (v, _mock, h) = vendor().await;
    let coord = start_coord(TENANT).await;
    {
        let mut g = v.graph.lock().unwrap();
        for id in ["00u0", "00u1", "00u2", "00u3"] {
            g.push(GraphUser { id: id.into(), upn: format!("{id}@contoso.example"), manager: None, removed: false, changed: 1 });
        }
    }
    let r = run_identity(&h, &coord, &entra_oauth2_spec(None), selfhosted_input(), opts()).await;
    r.out.unwrap_or_else(|e| panic!("self-hosted entra: {e}"));
    // The token request went to the directory's templated endpoint with the
    // config client id and the secret credential.
    let forms = v.okta.entra_forms.lock().unwrap().clone();
    assert_eq!(forms.len(), 1);
    assert_eq!(forms[0]["client_id"], CLIENT);
    assert_eq!(forms[0]["client_secret"], "entra-client-secret-value");
    assert_eq!(forms[0]["grant_type"], "client_credentials");
    // 3 groups over 2 discovery pages (followed via /@odata.nextLink).
    let groups = coord.rows_of(&format!("{FEED}:groups"));
    assert_eq!(groups["00u0"]["groups"], json!(["All Staff", "Engineering", "Okta Super Admin"]));
    assert_eq!(groups.len(), 4);
    // Memberships never checkpoint (no per-group state).
    assert!(r.store.all().iter().all(|(_, s, _)| s == "users"), "{:?}", r.store.all());

    // A memberships discovery over its item cap fails instead of committing
    // a partial groups snapshot.
    let coord2 = start_coord(TENANT).await;
    let r = run_identity(&h, &coord2, &entra_oauth2_spec(Some(2)), selfhosted_input(), opts()).await;
    let e = r.out.unwrap_err().to_string();
    assert!(e.contains("more than 2 items"), "{e}");
    assert!(coord2.log().iter().all(|l| !l.path.contains(":groups/runs/") || l.method == "DELETE" || !l.path.ends_with("/commit")));
    assert!(coord2.rows_of(&format!("{FEED}:groups")).is_empty());

    // Only config.* may be templated into the token URL.
    let mut s = entra_oauth2_spec(None);
    s.auth.params.insert("token_url".into(), json!("https://login.microsoftonline.com/{{state.x}}/oauth2/v2.0/token"));
    let e = engine::compile(&s, &engine::default_ceilings()).map(|_| ()).unwrap_err().to_string();
    assert!(e.contains("config.*"), "{e}");
    s.auth.params.insert("token_url".into(), json!("https://login.microsoftonline.com/x/oauth2/v2.0/token"));
    s.auth.params.insert("client_id_credential".into(), json!("CLIENT_ID"));
    let e = engine::compile(&s, &engine::default_ceilings()).map(|_| ()).unwrap_err().to_string();
    assert!(e.contains("exactly one of"), "{e}");
}

fn okta_jwt_spec() -> nano_connector::spec::ConnectorSpec {
    let mut s = okta_spec("full", false, 200);
    s.auth = serde_json::from_value(json!({
        "type": "okta_broker_jwt", "okta_domain": "{{config.OKTA_DOMAIN}}", "client_id": "{{config.CLIENT_ID}}",
        "scope": "okta.users.read  okta.groups.read okta.roles.read"
    }))
    .unwrap();
    s.allow[0].path_prefixes.push("/oauth2/v1/token".into());
    s
}

fn okta_jwt_input() -> RunInput {
    let mut i = okta_input(HashMap::new());
    i.credentials = creds(&[]);
    i.config = config(json!({"OKTA_DOMAIN": "Acme.okta.com", "CLIENT_ID": "0oa1b2c3d4e5f6g7h8i9"}));
    i
}

#[cfg(feature = "enterprise")]
#[tokio::test]
async fn okta_broker_jwt_trades_a_broker_assertion_and_refuses_dpop_and_foreign_audience() {
    let (v, mock, h) = vendor().await;
    let coord = start_coord(TENANT).await;
    let r = run_identity(&h, &coord, &okta_jwt_spec(), okta_jwt_input(), opts()).await;
    r.out.unwrap_or_else(|e| panic!("okta_broker_jwt: {e}"));
    assert_eq!(coord.rows_of(&users_feed()).len(), 6);
    let bodies = v.okta.broker_bodies.lock().unwrap().clone();
    assert_eq!(bodies, vec![json!({"feed_id": FEED, "okta_domain": "acme.okta.com", "client_id": "0oa1b2c3d4e5f6g7h8i9"})]);
    let forms = v.okta.token_forms.lock().unwrap().clone();
    assert_eq!(forms.len(), 1, "one token for the run");
    let f = &forms[0];
    assert_eq!(f["grant_type"], "client_credentials");
    assert_eq!(f["scope"], "okta.users.read okta.groups.read okta.roles.read");
    assert_eq!(f["client_assertion_type"], "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    assert!(f["client_assertion"].ends_with("OKTA-ASSERTION-SIG-0"));
    assert!(!f.contains_key("client_secret") && !f.contains_key("client_id"));
    // The assertion went only to the org's token endpoint.
    for req in mock.requests() {
        let leaked = String::from_utf8_lossy(&req.body).contains("OKTA-ASSERTION-SIG") || format!("{:?}", req.headers).contains("OKTA-ASSERTION-SIG");
        assert!(!leaked || req.path == "/oauth2/v1/token", "{} {}", req.host, req.path);
    }

    // The app demands DPoP: a fix-it error, nothing staged.
    v.okta.dpop.store(true, Ordering::SeqCst);
    let coord2 = start_coord(TENANT).await;
    let e = run_identity(&h, &coord2, &okta_jwt_spec(), okta_jwt_input(), opts()).await.out.unwrap_err().to_string();
    assert!(e.contains("okta_dpop_required"), "{e}");
    assert!(!e.contains("OKTA-ASSERTION-SIG"), "{e}");
    assert!(coord2.log().is_empty());
    v.okta.dpop.store(false, Ordering::SeqCst);

    // An assertion for another org is refused before it is ever sent.
    v.okta.bad_aud.store(true, Ordering::SeqCst);
    let sent = v.okta.token_forms.lock().unwrap().len();
    let e = run_identity(&h, &coord2, &okta_jwt_spec(), okta_jwt_input(), opts()).await.out.unwrap_err().to_string();
    assert!(e.contains("another Okta org"), "{e}");
    assert_eq!(v.okta.token_forms.lock().unwrap().len(), sent);

    // A domain that is not a plain host never reaches the broker.
    v.okta.bad_aud.store(false, Ordering::SeqCst);
    let n = v.okta.broker_bodies.lock().unwrap().len();
    let mut i = okta_jwt_input();
    i.config = config(json!({"OKTA_DOMAIN": "acme.okta.com/evil", "CLIENT_ID": "0oa1"}));
    let e = run_identity(&h, &coord2, &okta_jwt_spec(), i, opts()).await.out.unwrap_err().to_string();
    assert!(e.contains("okta_domain") || e.contains("allow"), "{e}");
    assert_eq!(v.okta.broker_bodies.lock().unwrap().len(), n);
}

#[test]
fn identity_runs_get_higher_but_bounded_limits() {
    let ceil = engine::default_ceilings();
    let head = "version: 1\nname: x\nallow: [{host: api.example.com}]\n";
    let users = "  - id: users\n    identity: { role: users }\n    request: { url: \"https://api.example.com/u\" }\n";
    let c = engine::compile(&spec(&format!("{head}kind: identity\nstreams:\n{users}")), &ceil).unwrap();
    assert_eq!((c.limits.max_pages, c.limits.max_requests, c.limits.max_events), (20_000, 100_000, 10_000_000));
    let c = engine::compile(&spec(&format!("{head}kind: identity\nlimits: {{ max_pages: 900000, max_requests: 900000 }}\nstreams:\n{users}")), &ceil).unwrap();
    assert_eq!((c.limits.max_pages, c.limits.max_requests), (50_000, 200_000), "clamped to the identity ceiling");
    let c = engine::compile(&spec(&format!("{head}kind: collector\nlimits: {{ max_pages: 900000 }}\nstreams:\n  - id: s\n    request: {{ url: \"https://api.example.com/u\" }}\n")), &ceil).unwrap();
    assert_eq!(c.limits.max_pages, 5000, "collectors keep the platform ceiling");
}

#[tokio::test]
async fn a_run_cannot_reach_another_tenants_coordinator_through_its_spec() {
    let (_v, _mock, h) = vendor().await;
    let coord_b = start_coord(TENANT_B).await;
    let coord_a = start_coord(TENANT).await;
    // Tenant A's spec points a request at B's coordinator, naming B.
    let s = spec(&format!(
        r#"version: 1
name: sneaky
kind: identity
allow: [{{ host: "127.0.0.1" }}]
streams:
  - id: users
    identity: {{ role: users }}
    request: {{ url: "{}/v1/identity/directory/deltas?tenant_id={TENANT_B}", method: POST }}
"#,
        coord_b.url()
    ));
    let r = run_identity(&h, &coord_a, &s, okta_input(HashMap::new()), opts()).await;
    let e = r.out.unwrap_err().to_string();
    assert!(e.contains("allow rule is invalid") && e.contains("is not a host name"), "{e}");

    // By name: the coordinators are cluster services in a private range,
    // which the egress policy refuses on the resolved address before any
    // connection. `internal.example.com` stands in for B's coordinator
    // service name, resolving to a service-CIDR address.
    h.resolver.set("internal.example.com", vec![vec!["10.96.12.34"]]);
    let s = spec(
        r#"version: 1
name: sneaky
kind: identity
allow: [{ host: "internal.example.com" }]
streams:
  - id: users
    identity: { role: users }
    request: { url: "https://internal.example.com/v1/identity/directory/deltas", method: POST }
"#,
    );
    let r = run_identity(&h, &coord_a, &s, okta_input(HashMap::new()), opts()).await;
    let e = r.out.unwrap_err().to_string();
    assert!(e.contains("DNS for internal.example.com returned a non-public address 10.96.12.34"), "{e}");
    assert!(h.dialer.dialed.lock().unwrap().iter().all(|a| a.ip().to_string() != "10.96.12.34"), "dialed B's address");
    assert!(coord_b.log().is_empty(), "B's coordinator was reached");
    assert!(coord_a.log().iter().all(|l| l.tenant.as_deref() == Some(TENANT)));
}

// ------------------------------------------------------------ lane C specs + recordings

/// nano-integrations PR #13 (784c91d): the shipped directory specs replayed
/// against their recordings into the mock coordinator. Every row the specs
/// produce must pass the coordinator's `IdentityRow` contract.
mod recorded {
    use super::*;
    use nano_connector::preview::{Recorded, ReplayTransport};

    fn fixture(name: &str) -> String {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/directory").join(name);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    fn replay_cfg(recording: &str, now: DateTime<Utc>) -> engine::EngineConfig {
        let mut entries: Vec<Recorded> = serde_json::from_str(&fixture(recording)).unwrap();
        if recording == "graph_delta.json" {
            // The delta recording was taken with a cached token: reuse the
            // full recording's token exchange.
            let full: Vec<Recorded> = serde_json::from_str(&fixture("graph_full.json")).unwrap();
            entries.insert(0, full.into_iter().next().unwrap());
        }
        let mut cfg = engine::EngineConfig::with_sandbox(worker_exe(), require_seccomp(), nano_connector::vrl_exec::PoolConfig::default());
        cfg.transport = Some(Arc::new(ReplayTransport::new(entries)));
        cfg.clock = Arc::new(move || now);
        cfg
    }

    /// Lane C's state files hold program state; an identity checkpoint wraps
    /// it with the last full time.
    fn delta_checkpoint(state_file: &str, last_full: DateTime<Utc>) -> HashMap<String, Value> {
        let st: Map<String, Value> = serde_json::from_str(&fixture(state_file)).unwrap();
        let at = last_full.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        st.into_iter().map(|(k, v)| (k, json!({"state": v, "identity_last_full_at": at}))).collect()
    }

    async fn replay(spec_file: &str, recording: &str, input: RunInput) -> (Coord, RunOutput, Arc<IdentitySink>) {
        let now = DateTime::parse_from_rfc3339("2026-10-11T10:30:00Z").unwrap().with_timezone(&Utc);
        let cfg = replay_cfg(recording, now);
        let s = spec(&fixture(spec_file));
        let coord = start_coord(TENANT).await;
        let sink = Arc::new(IdentitySink::new(coord.client(), Uuid::parse_str(FEED).unwrap(), now, opts()));
        let out = engine::run(&cfg, &s, input, sink.clone(), Arc::new(SeqStore::default()))
            .await
            .unwrap_or_else(|e| panic!("{spec_file} on {recording}: {e}"));
        let bad: Vec<Logged> = coord.log().into_iter().filter(|l| l.status >= 300).collect();
        assert!(bad.is_empty(), "{spec_file} on {recording}: coordinator refused {bad:?}");
        (coord, out, sink)
    }

    fn input(cfg: Value, creds_: &[(&str, &str)], checkpoints: HashMap<String, Value>) -> RunInput {
        RunInput {
            config: config(cfg),
            credentials: creds(creds_),
            checkpoints,
            tenant: Some(TENANT.into()),
            feed_id: Some(FEED.into()),
            ..Default::default()
        }
    }

    fn okta_cfg() -> Value {
        json!({"OKTA_DOMAIN": "acme.okta.com", "PRIVILEGED_GROUPS": "Okta Super Admins"})
    }

    /// NAN-3767: an Okta feed's PRIVILEGED_GROUPS (read only by the spec's
    /// VRL) is an accepted, optional config key, and its members come out
    /// privileged (`is_admin`) in the `:groups` sub-feed.
    #[tokio::test]
    async fn okta_users_privileged_groups_mark_members_privileged() {
        let plan = nano_connector::first_party::plan("okta_users").unwrap();
        let mut feed = nano_connector::service::admin::NewFeed {
            name: "Okta directory".into(),
            config: config(json!({"OKTA_DOMAIN": "acme.okta.com", "PRIVILEGED_GROUPS": "Okta Admins"})),
            vendor_credentials: HashMap::from([("API_TOKEN".to_string(), "t".to_string())]),
            ..Default::default()
        };
        nano_connector::service::admin::check_inputs(&plan, &feed).unwrap();
        feed.config.remove("PRIVILEGED_GROUPS");
        nano_connector::service::admin::check_inputs(&plan, &feed).unwrap();

        let now = DateTime::parse_from_rfc3339("2026-10-11T10:30:00Z").unwrap().with_timezone(&Utc);
        let cfg = replay_cfg("okta_full.json", now);
        let s = spec(&fixture("okta_users.connector.yaml"));
        let coord = start_coord(TENANT).await;
        coord.st.lock().unwrap().v2 = true;
        let sink = Arc::new(IdentitySink::new(coord.client(), Uuid::parse_str(FEED).unwrap(), now, opts()));
        let cfg_in = json!({"OKTA_DOMAIN": "acme.okta.com", "PRIVILEGED_GROUPS": "okta admins"});
        engine::run(&cfg, &s, input(cfg_in, &[("API_TOKEN", "t")], HashMap::new()), sink, Arc::new(SeqStore::default()))
            .await
            .unwrap_or_else(|e| panic!("okta privileged groups: {e}"));
        let groups = coord.rows_of(&format!("{FEED}:groups"));
        let admin = &groups["00udir00000000000000"];
        assert!(admin["groups"].as_array().unwrap().contains(&json!("Okta Admins")), "{admin:?}");
        assert_eq!(admin["is_admin"], true, "{admin:?}");
        assert_eq!(groups["00udir00000000000005"]["is_admin"], false);
    }

    #[tokio::test]
    async fn okta_users_spec_full_and_delta_recordings() {
        let (coord, out, _) = replay("okta_users.connector.yaml", "okta_full.json", input(okta_cfg(), &[("API_TOKEN", "t")], HashMap::new())).await;
        assert_eq!(out.identity_modes, vec![("users".to_string(), IdentityMode::Full)]);
        let users = coord.rows_of(&users_feed());
        let groups = coord.rows_of(&format!("{FEED}:groups"));
        println!("okta full: {} users, {} group rows", users.len(), groups.len());
        assert!(users.len() >= 10 && !groups.is_empty());
        assert!(users.values().any(|u| u.get("manager_upn").is_some()), "managers resolved");

        let cp = delta_checkpoint("okta_delta.state.json", DateTime::parse_from_rfc3339("2026-10-11T06:00:00Z").unwrap().with_timezone(&Utc));
        let (coord, out, _) = replay("okta_users.connector.yaml", "okta_delta.json", input(okta_cfg(), &[("API_TOKEN", "t")], cp)).await;
        assert_eq!(out.identity_modes, vec![("users".to_string(), IdentityMode::Delta)]);
        let log = coord.log();
        assert!(log.iter().any(|l| l.path.ends_with("/deltas")));
        assert!(log.iter().all(|l| !l.path.contains(":users/runs/")), "a delta run stages no users");
        assert!(log.iter().any(|l| l.path.contains(":groups/runs/") && l.path.ends_with("/commit")), "memberships still full");
    }

    fn entra_cfg() -> Value {
        json!({"DIRECTORY_ID": "e6800ccd-0000-4000-8000-000000000000", "CLIENT_ID": CLIENT, "PRIVILEGED_GROUPS": ""})
    }

    #[tokio::test]
    async fn entra_directory_spec_full_and_delta_recordings() {
        let (coord, out, _) = replay("entra_directory.connector.yaml", "graph_full.json", input(entra_cfg(), &[("CLIENT_SECRET", "s")], HashMap::new())).await;
        assert_eq!(out.identity_modes, vec![("users".to_string(), IdentityMode::Full)]);
        let users = coord.rows_of(&users_feed());
        println!("entra full: {} users, {} group rows", users.len(), coord.rows_of(&format!("{FEED}:groups")).len());
        assert!(users.len() >= 10);

        let cp = delta_checkpoint("graph_delta.state.json", DateTime::parse_from_rfc3339("2026-10-11T06:00:00Z").unwrap().with_timezone(&Utc));
        let (coord, out, _) = replay("entra_directory.connector.yaml", "graph_delta.json", input(entra_cfg(), &[("CLIENT_SECRET", "s")], cp)).await;
        assert_eq!(out.identity_modes, vec![("users".to_string(), IdentityMode::Delta)]);
        let deltas: Vec<Value> = coord.log().into_iter().filter(|l| l.path.ends_with("/deltas")).flat_map(|l| l.rows).collect();
        assert!(!deltas.is_empty());
        println!("entra delta: {} rows, {} tombstones", deltas.len(), deltas.iter().filter(|r| r["deleted"] == true).count());
    }

    #[tokio::test]
    async fn google_workspace_directory_spec_full_recording() {
        use aws_lc_rs::encoding::AsDer;
        let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(key.as_der().unwrap().as_ref());
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\n")
        );
        let creds_ = [("PRIVATE_KEY", pem.as_str()), ("CLIENT_EMAIL", "svc@mock-project.iam.gserviceaccount.com")];
        let cfg = json!({"ADMIN_EMAIL": "admin@example.com", "PRIVILEGED_GROUPS": ""});
        let (coord, out, _) = replay("google_workspace_directory.connector.yaml", "google_directory.json", input(cfg, &creds_, HashMap::new())).await;
        assert_eq!(out.identity_modes, vec![("users".to_string(), IdentityMode::Full)]);
        let users = coord.rows_of(&users_feed());
        println!("google full: {} users, {} group rows", users.len(), coord.rows_of(&format!("{FEED}:groups")).len());
        assert!(users.len() >= 10);
    }
}

// ------------------------------------------------------------ dedicated (NAN-3767)

const VECTOR_TOKEN: &str = "vector-ingest-token-0123456789";

/// A stand-in for the deployment's Vector enrichment lane: checks the
/// ingress contract (bearer, `X-Source-Type: nano_enrich`, NDJSON of
/// `kind: identity_directory` envelopes), then forwards each request to the
/// coordinator the way the `lake_identity_directory` sink does (stage lines
/// per run, delta lines with their manager references) and answers only
/// once the coordinator did (end-to-end acknowledgement).
struct FakeVector {
    port: u16,
    lines: Arc<Mutex<Vec<Value>>>,
}

async fn start_vector(coord_url: String, tenant: Uuid) -> FakeVector {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let seen = lines.clone();
    let chunk = Arc::new(AtomicU32::new(0));
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { break };
            let (seen, coord_url, chunk) = (seen.clone(), coord_url.clone(), chunk.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let (seen, coord_url, chunk) = (seen.clone(), coord_url.clone(), chunk.clone());
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = body.collect().await.map(|b| b.to_bytes().to_vec()).unwrap_or_default();
                        let hdr = |n: &str| parts.headers.get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
                        let reply = |s: u16| Ok::<_, Infallible>(hyper::Response::builder().status(s).body(Full::new(Bytes::new())).unwrap());
                        if hdr("authorization") != Some(format!("Bearer {VECTOR_TOKEN}")) || hdr("x-source-type").as_deref() != Some("nano_enrich") {
                            return reply(401);
                        }
                        let batch: Vec<Value> = body.split(|b| *b == b'\n').filter(|l| !l.is_empty()).map(|l| serde_json::from_slice(l).unwrap()).collect();
                        seen.lock().unwrap().extend(batch.iter().cloned());
                        let http = reqwest::Client::new();
                        let t = tenant.hyphenated().to_string();
                        let mut staged: BTreeMap<(String, String), Vec<Value>> = BTreeMap::new();
                        let (mut deltas, mut refs) = (Vec::new(), Vec::new());
                        for l in batch {
                            assert_eq!(l["kind"], "identity_directory", "{l}");
                            match l["op"].as_str() {
                                Some("stage") => staged.entry((l["feed_id"].as_str().unwrap().into(), l["run_id"].as_str().unwrap().into())).or_default().push(l["row"].clone()),
                                Some("delta") => {
                                    assert_eq!(l["patch"], true);
                                    if l.get("manager_ref").is_some() {
                                        refs.push(l["manager_ref"].clone());
                                    }
                                    deltas.push(l["row"].clone());
                                }
                                other => panic!("unexpected op {other:?}"),
                            }
                        }
                        let mut calls = Vec::new();
                        for ((feed, run), rows) in staged {
                            let n = chunk.fetch_add(1, Ordering::SeqCst);
                            calls.push((format!("{coord_url}/v1/identity/directory/feeds/{feed}/runs/{run}/rows"), json!({"tenant_id": t, "chunk": n, "rows": rows})));
                        }
                        if !deltas.is_empty() {
                            calls.push((format!("{coord_url}/v1/identity/directory/deltas"), json!({"tenant_id": t, "rows": deltas, "patch": true, "manager_refs": refs})));
                        }
                        for (url, body) in calls {
                            let r = http.post(url).bearer_auth(COORD_TOKEN).json(&body).send().await.unwrap();
                            if !r.status().is_success() {
                                return reply(400);
                            }
                        }
                        reply(200)
                    }
                });
                let _ = http1::Builder::new().serve_connection(TokioIo::new(tcp), svc).await;
            });
        }
    });
    FakeVector { port, lines }
}

fn local_identity(dir: &std::path::Path, coord: &Coord, vector_port: u16, vector_token: &str) -> Arc<nano_connector::identity::LocalIdentity> {
    std::fs::create_dir_all(dir).unwrap();
    let token = dir.join("enrichment.token");
    std::fs::write(&token, COORD_TOKEN).unwrap();
    Arc::new(nano_connector::identity::LocalIdentity {
        claim_tenant: nanosiem_core::reports::COMPATIBILITY_TENANT_ID,
        lake_tenant: coord.tenant,
        coordinator_url: coord.url(),
        coordinator_token_file: token,
        timeout: Duration::from_secs(30),
        vector: Arc::new(
            nano_connector::identity::VectorEnrichment::new(&format!("http://127.0.0.1:{vector_port}/"), vector_token, Duration::from_secs(30)).unwrap(),
        ),
    })
}

/// Open core: a feed of the compatibility tenant syncs through Vector into
/// the deployment's own coordinator (lake tenant); commits are direct
/// control calls; a feed of any other tenant is refused.
#[tokio::test]
async fn dedicated_runner_sends_rows_through_vector_and_maps_the_compatibility_tenant() {
    let (_v, _mock, h) = vendor().await;
    let coord = start_coord(TENANT).await;
    let vector = start_vector(coord.url(), coord.tenant).await;
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("nan3767-local-{}", Uuid::new_v4().simple()));
    let compat = nanosiem_core::reports::COMPATIBILITY_TENANT_ID.hyphenated().to_string();
    let yaml = serde_yaml::to_string(&okta_spec("full", true, 2)).unwrap();
    let (feed, stray) = (Uuid::now_v7(), Uuid::now_v7());
    let store = Arc::new(MemoryFeedStore::default());
    store.add(identity_feed(&compat, feed, &yaml, json!({"OKTA_DOMAIN": "acme.okta.com"})), Uuid::now_v7());
    store.add(identity_feed(TENANT_B, stray, &yaml, json!({"OKTA_DOMAIN": "acme.okta.com"})), Uuid::now_v7());
    let mut cfg = RunnerConfig::new("runner-open", h.cfg.clone());
    cfg.identity_local = Some(local_identity(&dir, &coord, vector.port, VECTOR_TOKEN));
    cfg.identity.spill_dir = Some(dir.clone());
    cfg.identity.v2_fields = true;
    let runner = Runner::new(store.clone(), cfg);
    assert_eq!(runner.tick().await.unwrap().claimed, 2);
    let records = runner.drain().await;
    let ok = records.iter().find(|r| r.status == RunStatus::Success).unwrap_or_else(|| panic!("{records:?}"));
    assert_eq!(ok.errors, 0);
    let refused = records.iter().find(|r| r.status == RunStatus::Failed).unwrap();
    assert!(refused.error.as_deref().unwrap().starts_with("identity_coordinator_unassigned"), "{refused:?}");

    // Every row went through Vector; the coordinator saw only the lake tenant.
    let lines = vector.lines.lock().unwrap().clone();
    let users = format!("{feed}:users");
    let groups = format!("{feed}:groups");
    assert_eq!(lines.iter().filter(|l| l["op"] == "stage" && l["feed_id"] == users.as_str()).count(), 6, "{lines:?}");
    assert!(lines.iter().any(|l| l["op"] == "stage" && l["feed_id"] == groups.as_str()));
    assert!(lines.iter().all(|l| l["row"].get("tenant_id").is_none()));
    let log = coord.log();
    assert!(log.iter().all(|l| l.tenant.as_deref() == Some(TENANT) && l.status < 300), "{log:?}");
    let commits: Vec<_> = log.iter().filter(|l| l.path.ends_with("/commit")).collect();
    assert_eq!(commits.len(), 2, "users and groups committed directly: {log:?}");
    assert_eq!(commits.iter().find(|l| l.path.contains(":users")).unwrap().expected_rows, Some(6));
    assert_eq!(coord.rows_of(&users).len(), 6);
    assert_eq!(coord.rows_of(&groups).len(), 4);
    assert!(store.checkpoint(feed, "users").is_some());
    assert!(store.checkpoint(stray, "users").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A Vector ingress that refuses the rows (wrong token here) fails the run
/// with the ingress answer; nothing is committed and the cursor stays.
#[tokio::test]
async fn dedicated_runner_fails_clearly_when_vector_refuses_the_rows() {
    let (_v, _mock, h) = vendor().await;
    let coord = start_coord(TENANT).await;
    let vector = start_vector(coord.url(), coord.tenant).await;
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("nan3767-refused-{}", Uuid::new_v4().simple()));
    let compat = nanosiem_core::reports::COMPATIBILITY_TENANT_ID.hyphenated().to_string();
    let yaml = serde_yaml::to_string(&okta_spec("full", false, 200)).unwrap();
    let feed = Uuid::now_v7();
    let store = Arc::new(MemoryFeedStore::default());
    store.add(identity_feed(&compat, feed, &yaml, json!({"OKTA_DOMAIN": "acme.okta.com"})), Uuid::now_v7());
    let mut cfg = RunnerConfig::new("runner-open", h.cfg.clone());
    cfg.identity_local = Some(local_identity(&dir, &coord, vector.port, "not-the-vector-token"));
    cfg.identity.spill_dir = Some(dir.clone());
    let runner = Runner::new(store.clone(), cfg);
    runner.tick().await.unwrap();
    let records = runner.drain().await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].status, RunStatus::Failed);
    assert!(records[0].error.as_deref().unwrap().contains("Vector enrichment ingress answered HTTP 401"), "{records:?}");
    assert!(coord.log().iter().all(|l| !l.path.ends_with("/commit")));
    assert!(store.checkpoint(feed, "users").is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Negative: a runner with no identity path (neither the local settings nor
/// the hosted assignments) fails an identity feed with an error naming what
/// to configure; it never touches the vendor's directory data.
#[tokio::test]
async fn an_unconfigured_runner_fails_identity_feeds_clearly() {
    let (_v, _mock, h) = vendor().await;
    let compat = nanosiem_core::reports::COMPATIBILITY_TENANT_ID.hyphenated().to_string();
    let yaml = serde_yaml::to_string(&okta_spec("full", false, 200)).unwrap();
    let feed = Uuid::now_v7();
    let store = Arc::new(MemoryFeedStore::default());
    store.add(identity_feed(&compat, feed, &yaml, json!({"OKTA_DOMAIN": "acme.okta.com"})), Uuid::now_v7());
    let runner = Runner::new(store.clone(), RunnerConfig::new("runner-bare", h.cfg.clone()));
    runner.tick().await.unwrap();
    let records = runner.drain().await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].status, RunStatus::Failed);
    let error = records[0].error.as_deref().unwrap();
    assert!(error.starts_with("identity_coordinator_unconfigured"), "{error}");
    assert!(error.contains("CONNECTOR_IDENTITY_VECTOR_URL"), "{error}");
    assert_eq!(records[0].requests, 0, "no vendor call without a directory path");
    assert!(store.checkpoint(feed, "users").is_none());
}
