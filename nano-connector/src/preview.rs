//! Validate and preview: compile a spec (+VRL) and run it once against a
//! recorded/mock response set, with no network. Requests still pass the host
//! policy, so a preview also proves the spec stays inside its allowlist.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::Credentials;
use crate::broker::{BodyCaps, BrokerError, InboundResponse, OutboundRequest};
use crate::engine::{self, EngineConfig, MemorySink, MemoryStore, RunInput, Transport};
use crate::policy::HostPolicy;
use crate::spec::ConnectorSpec;

/// One recorded exchange. `host`/`path` must match; `query` entries, when
/// given, must all be present with equal values. Entries are consumed in
/// order; the last match for a route repeats.
#[derive(Debug, Clone, Deserialize)]
pub struct Recorded {
    #[serde(default)]
    pub method: Option<String>,
    pub host: String,
    pub path: String,
    #[serde(default)]
    pub query: HashMap<String, String>,
    #[serde(default = "ok")]
    pub status: u16,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// JSON value (serialized) or a string (sent as-is).
    pub body: Value,
}

fn ok() -> u16 {
    200
}

pub struct ReplayTransport {
    entries: Vec<Recorded>,
    used: Mutex<Vec<bool>>,
    pub log: Mutex<Vec<String>>,
    expected: Option<Vec<ExpectedRequest>>,
    session_id: uuid::Uuid,
}

/// Exact request contract for mechanical fixture validation. Authentication
/// is applied normally, but credential-bearing headers/query keys may be
/// omitted from expectations with `auth_query_keys`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedRequest {
    pub method: String,
    pub url: String,
    #[serde(default)] pub query: std::collections::BTreeMap<String,String>,
    #[serde(default)] pub json: Option<Value>,
    #[serde(default)] pub form: Option<std::collections::BTreeMap<String,String>>,
    #[serde(default)] pub auth_query_keys: Vec<String>,
}

impl ReplayTransport {
    pub fn new(entries: Vec<Recorded>) -> Self {
        let n = entries.len();
        Self { entries, used: Mutex::new(vec![false; n]), log: Mutex::new(vec![]), expected:None, session_id:uuid::Uuid::new_v4() }
    }

    /// Consume exchanges strictly in order, without route repetition. Every
    /// method, origin, path, query and request body must match exactly.
    pub fn strict(exchanges: Vec<(ExpectedRequest,Recorded)>) -> Self {
        let (expected,entries) = exchanges.into_iter().unzip();
        let mut transport = Self::new(entries);
        transport.expected = Some(expected);
        transport
    }

    pub fn assert_complete(&self) -> Result<(),String> {
        if self.used.lock().map_err(|_| "replay state unavailable")?.iter().all(|v| *v) { Ok(()) }
        else { Err("recorded exchanges were not all consumed".into()) }
    }

    /// Stable identity for isolating auth state across independent recordings.
    pub fn session_id(&self) -> uuid::Uuid { self.session_id }
}

#[async_trait::async_trait]
impl Transport for ReplayTransport {
    async fn send_once(&self, req: &OutboundRequest, hosts: &HostPolicy, _caps: BodyCaps) -> Result<InboundResponse, BrokerError> {
        hosts.check(&req.url)?;
        let q: HashMap<String, String> = req.url.query_pairs().into_owned().collect();
        let host = req.url.host_str().unwrap_or_default();
        let matches = |e: &Recorded| {
            e.host == host
                && e.path == req.url.path()
                && e.method.as_deref().is_none_or(|m| m.eq_ignore_ascii_case(req.method.as_str()))
                && e.query.iter().all(|(k, v)| q.get(k) == Some(v))
        };
        let mut used = self.used.lock().expect("replay");
        let idx = if let Some(expected) = &self.expected {
            let idx = used.iter().position(|v| !*v).ok_or_else(|| BrokerError::Http("strict replay exhausted".into()))?;
            let e = &expected[idx];
            let mut url = req.url.clone(); url.set_query(None);
            let actual_pairs:Vec<_> = req.url.query_pairs().filter(|(k,_)| !e.auth_query_keys.iter().any(|n| n == k)).map(|(k,v)| (k.into_owned(),v.into_owned())).collect();
            let actual_query:std::collections::BTreeMap<_,_> = actual_pairs.iter().cloned().collect();
            let body_ok = if let Some(body) = &e.json {
                serde_json::from_slice::<Value>(&req.body).ok().as_ref() == Some(body)
            } else if let Some(form) = &e.form {
                let pairs:Vec<_> = url::form_urlencoded::parse(&req.body).into_owned().collect();
                pairs.len() == form.len() && pairs.into_iter().collect::<std::collections::BTreeMap<_,_>>() == *form
            } else { req.body.is_empty() };
            if !matches(&self.entries[idx]) || req.method.as_str() != e.method || url.as_str() != e.url || actual_pairs.len()!=e.query.len() || actual_query != e.query || !body_ok {
                return Err(BrokerError::Http("strict replay request mismatch".into()));
            }
            Some(idx)
        } else {
            (0..self.entries.len()).find(|&i| !used[i] && matches(&self.entries[i]))
                .or_else(|| (0..self.entries.len()).rev().find(|&i| matches(&self.entries[i])))
        };
        // Query VALUES are dropped from the log: after auth, an api_key_query
        // plugin has put the credential there.
        let keys: Vec<String> = req.url.query_pairs().map(|(k, _)| k.into_owned()).collect();
        let shown = format!("{}://{}{}{}{}", req.url.scheme(), host, req.url.path(), if keys.is_empty() { "" } else { "?" }, keys.join("&"));
        self.log.lock().expect("replay").push(format!("{} {}", req.method, shown.chars().take(300).collect::<String>()));
        let Some(i) = idx else {
            return Ok(InboundResponse { status: 404, headers: Default::default(), body: Bytes::from_static(b"{\"preview\":\"no recorded response\"}") });
        };
        used[i] = true;
        let e = &self.entries[i];
        let mut headers = http::HeaderMap::new();
        for (k, v) in &e.headers {
            if let (Ok(k), Ok(v)) = (http::HeaderName::try_from(k.as_str()), http::HeaderValue::try_from(v.as_str())) {
                headers.append(k, v);
            }
        }
        let body = match &e.body {
            Value::String(s) => Bytes::from(s.clone()),
            v => Bytes::from(v.to_string()),
        };
        Ok(InboundResponse { status: e.status, headers, body })
    }
}

/// Last committed checkpoint per stream, as a restart would load them.
fn checkpoints_so_far(store: &MemoryStore) -> Value {
    let mut m = serde_json::Map::new();
    for (k, v) in store.saves.lock().expect("store").iter() {
        m.insert(k.clone(), v.clone());
    }
    Value::Object(m)
}

/// Compile-check a spec. VRL programs are compiled in sandboxed workers
/// (`worker_exe vrl-worker`), never in this process. Returns a short summary.
pub async fn validate(worker_exe: PathBuf, spec: &ConnectorSpec) -> Result<Value, engine::EngineError> {
    let cfg = EngineConfig::try_new(worker_exe).map_err(|e| engine::EngineError::Vrl(crate::vrl_exec::VrlError::Sandbox(e)))?;
    engine::compile(spec, &cfg.ceilings)?;
    // Programs first (in sandboxed workers): a refused function is the more
    // useful error than a missing ingest_id.
    engine::check_programs(&cfg, spec).await?;
    validate_static(spec)
}

/// The in-process half of [`validate`]: the spec compiles (HTTP, auth,
/// pagination, ceilings) and collectors name an ingest identity. Does NOT
/// compile VRL: that only ever happens in a sandboxed worker, so callers
/// that admit a spec must also run [`validate`] (or the runner's first run
/// will refuse it).
pub fn validate_static(spec: &ConnectorSpec) -> Result<Value, engine::EngineError> {
    engine::compile(spec, &engine::default_ceilings())?;
    // Shipped collectors must name the vendor identity they stamp as
    // `_nano_ingest_id`; without one, a re-read becomes new rows downstream.
    if spec.kind == crate::spec::Kind::Collector {
        if let Some(s) = spec.streams.iter().find(|s| match &s.ingest_id {
            Some(i) => i.fields.is_empty() || i.fields.iter().any(String::is_empty),
            None => s.window.is_none(),
        }) {
            return Err(engine::EngineError::Spec(format!(
                "collector stream `{}` needs `ingest_id` with non-empty fields (or a `window` with `uid_field`)",
                s.id
            )));
        }
    }
    Ok(json!({
        "name": spec.name,
        "kind": spec.kind,
        "auth": spec.auth.kind,
        "streams": spec.streams.iter().map(|s| json!({
            "id": s.id,
            "pagination": s.pagination.kind,
            "vrl": s.program.is_some(),
            "window": s.window.is_some(),
            "fanout": s.fanout.is_some(),
            "ingest_id": s.ingest_id.as_ref().map(|i| i.fields.clone())
                .or_else(|| s.window.as_ref().map(|w| vec![w.uid_field.clone()])),
        })).collect::<Vec<_>>(),
    }))
}

#[derive(Default)]
pub struct PreviewInput {
    pub config: serde_json::Map<String, Value>,
    pub credentials: Credentials,
    pub artifact: Option<(String, String)>,
    /// Pin the engine clock (replays and shadow runs against fixed data).
    /// A new stream still starts at `now` − the point-forward overlap.
    pub now: Option<chrono::DateTime<chrono::Utc>>,
    pub max_events_shown: usize,
    /// Saved checkpoints per stream id (a restart).
    pub checkpoints: HashMap<String, Value>,
    /// Include every shipped batch as `batches: [[source_type, [events]]]`.
    pub all_batches: bool,
}

/// Run once against `recording`. Never touches the network.
pub async fn preview(worker_exe: PathBuf, spec: &ConnectorSpec, recording: Vec<Recorded>, input: PreviewInput) -> Value {
    let replay = Arc::new(ReplayTransport::new(recording));
    let log = replay.clone();
    run_once(worker_exe, spec, replay, input, move || log.log.lock().expect("replay").clone()).await
}

/// Run once against a vendor mock on a loopback port (shadow runs).
pub async fn shadow(worker_exe: PathBuf, spec: &ConnectorSpec, mock_url: &str, input: PreviewInput) -> Result<Value, String> {
    let t = Arc::new(crate::loopback::LoopbackTransport::new(mock_url)?);
    Ok(run_once(worker_exe, spec, t, input, Vec::new).await)
}

async fn run_once(
    worker_exe: PathBuf,
    spec: &ConnectorSpec,
    transport: Arc<dyn Transport>,
    input: PreviewInput,
    requests: impl FnOnce() -> Vec<String>,
) -> Value {
    let mut cfg = match EngineConfig::try_new(worker_exe) {
        Ok(c) => c,
        Err(e) => return json!({ "ok": false, "error": e, "events_before_error": 0, "requests": [] }),
    };
    cfg.transport = Some(transport);
    if let Some(t) = input.now {
        cfg.clock = Arc::new(move || t);
    }
    let sink = Arc::new(MemorySink::default());
    let store = Arc::new(MemoryStore::default());
    let out = engine::run(
        &cfg,
        spec,
        RunInput {
            config: input.config,
            credentials: input.credentials,
            artifact: input.artifact,
            checkpoints: input.checkpoints,
            ..Default::default()
        },
        sink.clone(),
        store.clone(),
    )
    .await;
    let events = sink.events();
    let requests = requests();
    let batches = || if input.all_batches { json!(sink.batches.lock().expect("sink").clone()) } else { Value::Null };
    match out {
        Ok(o) => json!({
            "ok": true,
            "events": o.events,
            "sample": events.iter().take(input.max_events_shown).collect::<Vec<_>>(),
            "result": o.result,
            "checkpoints": o.checkpoints,
            // Events whose ingest_id fields were missing, so the engine fell
            // back to a content hash (`h:...`) instead of the vendor's id.
            "content_hash_ingest_ids": events.iter().filter(|e| e[engine::INGEST_ID_FIELD].as_str().is_some_and(|v| v.starts_with("h:"))).count(),
            "dropped_duplicates": o.dropped_duplicates,
            "requests": requests,
            "sandbox": o.sandbox.iter().map(|(id, r)| json!({ "stream": id, "isolation": r })).collect::<Vec<_>>(),
            "batches": batches(),
        }),
        Err(e) => json!({
            "ok": false, "error": e.to_string(), "events_before_error": events.len(), "requests": requests,
            "checkpoints": checkpoints_so_far(&store), "batches": batches(),
        }),
    }
}
