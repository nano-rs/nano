//! The run loop: request -> broker -> (VRL | declarative extraction) ->
//! dedupe -> ingest -> ack -> checkpoint -> next request.
//!
//! Invariants:
//! - Every outbound request, `next_request`, Link URL and redirect hop goes
//!   through `HostPolicy::check` and the broker's IP pinning.
//! - Secrets reach a request only through an auth plugin. A URL or body that
//!   already contains a secret value is refused, and secret values are
//!   redacted from responses before VRL or ingest see them.
//! - State is checkpointed only after ingest acknowledged the page's events.
//! - Every cap (requests, pages, events, bytes, body, decompression, VRL
//!   budget, checkpoint size, wall clock) is enforced by the host.
//! - Tenant VRL is never compiled or run in this process: only in sandboxed,
//!   single-use workers from the [`VrlPool`].
//! - An error that would carry a secret (in any encoding) is replaced by a
//!   redacted one before it leaves [`run`].

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Map, Value, json};
use tokio::sync::Mutex;

use crate::auth::{self, AuthContext, AuthError, AuthPlugin, Credentials, TokenFetch};
use crate::broker::{BodyCaps, Broker, BrokerConfig, BrokerError, InboundResponse, OutboundRequest};
use crate::paging::{self, PageCtx, PageState, Step, Stepper};
use crate::policy::{EgressDeny, HostPolicy, PolicyError};
use crate::sandbox::{SandboxPolicy, SandboxReport};
use crate::secrets::SecretSet;
use crate::identity::IdentityTarget;
use crate::spec::{
    Body, ConnectorSpec, CursorReduce, Discover, Format, IdentityMode, IdentityRole, Kind, Limits, Method,
    NextRequest, ProgramOutput, RequestTemplate, RetryRewrite, Stream, TimeFormat, WindowSpec,
};
use crate::point_forward::{self, POINT_FORWARD_KEY, PointForward};
use crate::template::{self, Scope, TemplateError};
use crate::vrl_exec::{PoolConfig, PooledWorker, Reservation, VrlError, VrlPool, WorkerLimits};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("spec is invalid: {0}")]
    Spec(String),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Broker(#[from] BrokerError),
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Template(#[from] TemplateError),
    #[error(transparent)]
    Vrl(#[from] VrlError),
    #[error("program returned an invalid answer: {0}")]
    ProgramShape(String),
    #[error("connector reported: {0}")]
    Program(String),
    #[error("upstream returned HTTP {status}: {body}")]
    Upstream { status: u16, body: String },
    #[error("cap reached: {0}")]
    Cap(String),
    #[error("refused: a request would carry a credential outside its auth plugin")]
    CredentialExfil,
    #[error("refused: the response carries a credential in a form that cannot be redacted")]
    CredentialInResponse,
    #[error("ingest did not acknowledge: {0}")]
    Sink(String),
    #[error("run exceeded its {0} s wall clock")]
    WallClock(u64),
    #[error("page token expired {0} times in one window")]
    Restarts(u32),
    /// The original error text contained a credential; this is it with
    /// every secret shape replaced.
    #[error("{0}")]
    Scrubbed(String),
}

/// Ingest for a run's events. `push` returns only once the events are
/// acknowledged; the engine checkpoints after that.
#[async_trait::async_trait]
pub trait Sink: Send + Sync {
    async fn push(&self, source_type: &str, events: &[Value]) -> Result<(), String>;
    /// `kind: identity` runs deliver through this target (staged snapshots,
    /// deltas, membership aggregation). `None` (preview, tests): identity
    /// streams' program events go to [`Sink::push`] under the stream id.
    fn identity(&self) -> Option<&dyn IdentityTarget> {
        None
    }
}

/// Durable per-stream state.
#[async_trait::async_trait]
pub trait CheckpointStore: Send + Sync {
    async fn save(&self, stream: &str, state: &Value) -> Result<(), String>;
}

/// Server-derived request semantics, independent of URL or credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestPurpose {
    Authentication,
    Read,
    VendorMutation,
    /// Callers without semantic evidence must retain conservative behavior.
    Unknown,
}

/// An exchange: the broker in production, a recording in preview.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn send_once(&self, req: &OutboundRequest, hosts: &HostPolicy, caps: BodyCaps) -> Result<InboundResponse, BrokerError>;
    /// Existing transports keep their behavior; authority wrappers can retain
    /// the purpose through admission until actual IO starts.
    async fn send_once_with_purpose(
        &self,
        req: &OutboundRequest,
        hosts: &HostPolicy,
        caps: BodyCaps,
        _purpose: RequestPurpose,
    ) -> Result<InboundResponse, BrokerError> {
        self.send_once(req, hosts, caps).await
    }
}

#[async_trait::async_trait]
impl Transport for Broker {
    async fn send_once(&self, req: &OutboundRequest, hosts: &HostPolicy, caps: BodyCaps) -> Result<InboundResponse, BrokerError> {
        Broker::send_once(self, req, hosts, caps).await
    }
}

pub type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

#[derive(Clone)]
pub struct EngineConfig {
    pub broker: BrokerConfig,
    /// Replaces the broker (preview against recorded responses).
    pub transport: Option<Arc<dyn Transport>>,
    pub vrl_worker_exe: PathBuf,
    pub worker_address_space: u64,
    /// Sandboxed VRL workers, shared by every run of this process.
    pub vrl_pool: Arc<VrlPool>,
    /// Egress the platform forbids for every run (cluster CIDRs, node and
    /// ingest addresses, internal names). Merged with the tenant's deny.
    pub platform_deny: EgressDeny,
    pub clock: Clock,
    /// Engine ceilings; spec limits are clamped to these.
    pub ceilings: Limits,
    /// The platform pull broker (hosted runner only; from the runner's
    /// environment, never from a spec). `None`: `google_dwd_broker` fails
    /// with `google_dwd_broker_unconfigured`.
    pub pull_broker: Option<Arc<crate::pull_broker::PlatformBroker>>,
}

impl EngineConfig {
    /// With the sandbox policy from the environment
    /// ([`SandboxPolicy::from_env`]). An invalid setting fails closed: the
    /// strict policy is used and the error is logged. Services should call
    /// [`EngineConfig::try_new`] and refuse to start instead.
    pub fn new(vrl_worker_exe: PathBuf) -> Self {
        let policy = SandboxPolicy::from_env().unwrap_or_else(|e| {
            tracing::error!(target: "nano_connector::sandbox", error = %e, "invalid sandbox setting; requiring every isolation layer");
            SandboxPolicy::strict()
        });
        Self::with_sandbox(vrl_worker_exe, policy, PoolConfig::default())
    }

    /// Like [`EngineConfig::new`], but an invalid sandbox setting is an error.
    pub fn try_new(vrl_worker_exe: PathBuf) -> Result<Self, String> {
        Ok(Self::with_sandbox(vrl_worker_exe, SandboxPolicy::from_env()?, PoolConfig::default()))
    }

    pub fn with_sandbox(vrl_worker_exe: PathBuf, policy: SandboxPolicy, pool: PoolConfig) -> Self {
        Self {
            broker: BrokerConfig::default(),
            transport: None,
            vrl_pool: Arc::new(VrlPool::new(vrl_worker_exe.clone(), policy, pool)),
            platform_deny: EgressDeny::default(),
            vrl_worker_exe,
            worker_address_space: 1024 * 1024 * 1024,
            clock: Arc::new(Utc::now),
            ceilings: default_ceilings(),
            pull_broker: None,
        }
    }
}

/// The platform ceilings a spec's `limits` may not exceed.
pub fn default_ceilings() -> Limits {
    Limits {
        max_run_secs: 3600,
        max_pages: 5000,
        max_requests: 20_000,
        max_events: 5_000_000,
        max_event_bytes: 1024 * 1024 * 1024,
        max_response_bytes: 64 * 1024 * 1024,
        max_decompressed_bytes: 256 * 1024 * 1024,
        vrl_timeout_ms: 10_000,
        max_redirects: 10,
        max_checkpoint_bytes: 16 * 1024 * 1024,
        max_identity_memberships: 5_000_000,
    }
}

impl EngineConfig {
    /// Boot-time check: spawn one worker under the configured policy, run
    /// one trivial call through it, and return what isolation it got. A
    /// service calls this before taking work, so a host that cannot provide
    /// a required layer fails the pod at boot, not every run later.
    pub async fn sandbox_self_test(&self) -> Result<SandboxReport, String> {
        let limits = WorkerLimits {
            address_space_bytes: self.worker_address_space,
            cpu_secs: 10,
            call_timeout: Duration::from_secs(10),
            max_output_bytes: 4096,
        };
        let mut w = self.vrl_pool.spawn("__sandbox_self_test__", r#"{"ok": true}"#, limits).await.map_err(|e| e.to_string())?;
        let out = w.call(&json!({})).await.map_err(|e| e.to_string())?;
        if out != json!({"ok": true}) {
            return Err(format!("self-test worker answered {out}"));
        }
        Ok(w.report.clone())
    }
}

#[derive(Default)]
pub struct RunInput {
    pub config: Map<String, Value>,
    pub credentials: Credentials,
    /// Saved checkpoint per stream id.
    pub checkpoints: HashMap<String, Value>,
    /// Agent enrichment input.
    pub artifact: Option<(String, String)>,
    /// Agent enrichment: extra `input.*` template values derived by the host
    /// from the artifact (e.g. NAN-3763 `artifact_b64url`). Never secrets:
    /// templates may place them in URLs. `artifact` / `artifact_type` win.
    pub artifact_extra: Map<String, Value>,
    /// Collectors: the enabled stream ids (default: all).
    pub enabled_streams: Option<Vec<String>>,
    /// The tenant this run belongs to (VRL worker fairness and audit).
    pub tenant: Option<String>,
    /// The tenant's egress deny list, on top of the spec allowlist.
    pub egress_deny: EgressDeny,
    /// The feed this run belongs to (hosted runner), for platform-brokered
    /// auth.
    pub feed_id: Option<String>,
}

#[derive(Debug, Default)]
pub struct RunOutput {
    pub events: u64,
    pub requests: u32,
    pub pages: u32,
    /// Agent enrichment: the result. Data enrichment: `{records, watermark}`.
    pub result: Option<Value>,
    pub checkpoints: HashMap<String, Value>,
    pub dropped_duplicates: u64,
    pub windows_narrowed: u32,
    pub window_restarts: u32,
    /// Isolation each VRL stream actually ran with (stream id, report).
    pub sandbox: Vec<(String, SandboxReport)>,
    /// `kind: identity`: the mode each users stream ran in (a delta stream
    /// that asked for `restart_full` reports `full`).
    pub identity_modes: Vec<(String, IdentityMode)>,
}

/// A validated spec with its plugins built.
pub struct Compiled {
    pub spec: ConnectorSpec,
    pub auth: Arc<dyn AuthPlugin>,
    pub limits: Limits,
}

const FORBIDDEN_HEADERS: &[&str] = &[
    "authorization", "proxy-authorization", "cookie", "host", "content-length", "transfer-encoding",
    "connection", "te", "upgrade", "x-api-key", "api-key", "x-apikey",
];

/// Compile-time checks: plugins exist, templates only read allowed
/// namespaces, programs compile, headers carry no auth.
pub fn compile(spec: &ConnectorSpec, ceilings: &Limits) -> Result<Compiled, EngineError> {
    let bad = |m: String| EngineError::Spec(m);
    if spec.version != crate::spec::SPEC_VERSION {
        return Err(bad(format!("version must be {}", crate::spec::SPEC_VERSION)));
    }
    if spec.allow.is_empty() {
        return Err(bad("`allow` must list at least one host".into()));
    }
    if spec.streams.is_empty() {
        return Err(bad("`streams` is empty".into()));
    }
    if !matches!(spec.kind, Kind::Collector | Kind::Identity) && spec.streams.len() != 1 {
        return Err(bad("enrichments have exactly one stream".into()));
    }
    check_identity(spec)?;
    let mut auth = auth::build(&spec.auth.kind, &spec.auth.params)?;
    let check_req = |r: &RequestTemplate| -> Result<(), EngineError> {
        template::references(&r.url)?;
        for (k, v) in &r.query {
            template::references(k)?;
            template::references(v)?;
        }
        for (k, v) in &r.headers {
            if FORBIDDEN_HEADERS.contains(&k.to_ascii_lowercase().as_str()) {
                return Err(bad(format!("header `{k}` is reserved; use `auth`")));
            }
            for p in template::references(v)? {
                if !p.starts_with("config.") {
                    return Err(bad(format!("header `{k}` may only template config.*")));
                }
            }
        }
        match &r.body {
            Some(Body { form: Some(m), json: None }) => m.values().try_for_each(|v| template::references(v).map(|_| ()))?,
            Some(Body { form: None, json: Some(v) }) => check_json_templates(v)?,
            Some(_) => return Err(bad("body needs exactly one of `form` or `json`".into())),
            None => {}
        }
        Ok(())
    };
    for s in &spec.streams {
        match (&s.request, &s.program) {
            (None, None) => return Err(bad(format!("stream `{}` needs `request` or `program`", s.id))),
            (Some(r), _) => check_req(r)?,
            _ => {}
        }
        paging::build(&s.pagination.kind, &s.pagination.params).map_err(bad)?;
        // VRL is compiled only inside a sandboxed worker (see
        // `check_programs` and `run`); here only the size is checked.
        if let Some(p) = &s.program {
            if p.len() > crate::vrl_exec::MAX_PROGRAM_BYTES {
                return Err(bad(format!("stream `{}` program exceeds {} bytes", s.id, crate::vrl_exec::MAX_PROGRAM_BYTES)));
            }
        }
        if let Some(f) = &s.fanout {
            if let Discover::Request { request, pagination, .. } = &f.discover {
                check_req(request)?;
                paging::build(&pagination.kind, &pagination.params).map_err(bad)?;
            }
        }
        if let Some(w) = &s.window {
            if w.lookback_secs >= w.max_span_secs {
                return Err(bad("window.lookback_secs must be smaller than max_span_secs".into()));
            }
            if w.max_seen > MAX_SEEN_CEILING {
                return Err(bad(format!("window.max_seen may be at most {MAX_SEEN_CEILING}")));
            }
        }
        for v in s.initial_state.values() {
            check_json_templates(v)?;
        }
    }
    let (l, c) = if spec.kind == Kind::Identity {
        (identity_limits(&spec.limits), identity_ceilings(ceilings))
    } else {
        (spec.limits.clone(), ceilings.clone())
    };
    let (l, c) = (&l, &c);
    let limits = Limits {
        max_run_secs: l.max_run_secs.min(c.max_run_secs),
        max_pages: l.max_pages.min(c.max_pages),
        max_requests: l.max_requests.min(c.max_requests),
        max_events: l.max_events.min(c.max_events),
        max_event_bytes: l.max_event_bytes.min(c.max_event_bytes),
        max_response_bytes: l.max_response_bytes.min(c.max_response_bytes),
        max_decompressed_bytes: l.max_decompressed_bytes.min(c.max_decompressed_bytes),
        vrl_timeout_ms: l.vrl_timeout_ms.min(c.vrl_timeout_ms),
        max_redirects: l.max_redirects.min(c.max_redirects),
        max_checkpoint_bytes: l.max_checkpoint_bytes.min(c.max_checkpoint_bytes),
        max_identity_memberships: l.max_identity_memberships.min(c.max_identity_memberships),
    };
    auth.set_request_limit(limits.max_requests);
    Ok(Compiled { spec: spec.clone(), auth: Arc::from(auth), limits })
}

/// `kind: identity` walks whole directories (a 500k-user Okta org is ~2,500
/// user pages plus one or more pages per group), so its ceilings are the
/// platform's scaled up: 10x pages and requests, 2x events, 8x event bytes.
/// Run time stays the runner's. Still bounded; an operator that lowers the
/// platform ceilings lowers these too.
pub fn identity_ceilings(base: &Limits) -> Limits {
    Limits {
        max_pages: base.max_pages.saturating_mul(10),
        max_requests: base.max_requests.saturating_mul(10),
        max_events: base.max_events.saturating_mul(2),
        max_event_bytes: base.max_event_bytes.saturating_mul(8),
        ..base.clone()
    }
}

/// `kind: identity` spec limits: a field left at the collector default gets
/// the identity default (then the identity ceiling clamps it).
fn identity_limits(l: &Limits) -> Limits {
    let d = Limits::default();
    let pick = |v: u64, default: u64, identity: u64| if v == default { identity } else { v };
    Limits {
        max_run_secs: pick(l.max_run_secs, d.max_run_secs, 3600),
        max_pages: pick(l.max_pages as u64, d.max_pages as u64, 20_000) as u32,
        max_requests: pick(l.max_requests as u64, d.max_requests as u64, 100_000) as u32,
        max_events: pick(l.max_events, d.max_events, 10_000_000),
        max_event_bytes: pick(l.max_event_bytes, d.max_event_bytes, 8 * 1024 * 1024 * 1024),
        ..l.clone()
    }
}

/// Fan-out item ceiling: collectors 10k; identity memberships (one item per
/// group) 100k, and a memberships discovery over the cap fails the run
/// instead of committing a partial snapshot.
pub const MAX_FANOUT_ITEMS: u32 = 10_000;
pub const MAX_IDENTITY_FANOUT_ITEMS: u32 = 100_000;

/// `kind: identity` shape rules: identity streams only under that kind and
/// every stream of it has a role; users streams are plain walks (no fan-out,
/// window or write-ahead), memberships are always full; stream ids are
/// coordinator feed-id tokens and the users stream is `users` (the
/// memberships sub-feed is `groups`).
fn check_identity(spec: &ConnectorSpec) -> Result<(), EngineError> {
    let bad = |m: String| EngineError::Spec(m);
    if spec.kind != Kind::Identity {
        if spec.identity.is_some() {
            return Err(bad("`identity` is only valid under `kind: identity`".into()));
        }
        if let Some(s) = spec.streams.iter().find(|s| s.identity.is_some()) {
            return Err(bad(format!("stream `{}`: identity streams are only valid under `kind: identity`", s.id)));
        }
        return Ok(());
    }
    if let Some(c) = &spec.identity {
        if !(300..=30 * 86_400).contains(&c.full_every_secs) {
            return Err(bad("identity.full_every_secs must be between 300 and 2592000".into()));
        }
    }
    let mut ids = std::collections::BTreeSet::new();
    for s in &spec.streams {
        let Some(id) = &s.identity else {
            return Err(bad(format!("stream `{}` needs `identity: {{role: users|memberships}}` under `kind: identity`", s.id)));
        };
        let token = !s.id.is_empty()
            && s.id.len() <= 64
            && s.id.as_bytes()[0].is_ascii_alphanumeric()
            && s.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !token {
            return Err(bad(format!("identity stream id `{}` must be 1-64 of [A-Za-z0-9_-], starting alphanumeric", s.id)));
        }
        if !ids.insert(s.id.as_str()) {
            return Err(bad(format!("identity stream id `{}` is used twice", s.id)));
        }
        if s.window.is_some() || s.write_ahead_state.is_some() || s.restart_window_on.is_some() {
            return Err(bad(format!("identity stream `{}` cannot use window, write_ahead_state or restart_window_on", s.id)));
        }
        match id.role {
            IdentityRole::Users => {
                // The feed's sub-feeds are exactly `<feed>:users` and
                // `<feed>:groups`: what an uninstall removes, and all the
                // runner's token may delete (NAN-3503).
                if s.id != crate::identity::USERS_SUBFEED {
                    return Err(bad(format!(
                        "the identity users stream must have id `{}` (got `{}`): one users stream per feed",
                        crate::identity::USERS_SUBFEED,
                        s.id
                    )));
                }
                if s.fanout.is_some() {
                    return Err(bad(format!("identity users stream `{}` cannot fan out", s.id)));
                }
            }
            IdentityRole::Memberships => {
                if id.mode == Some(IdentityMode::Delta) {
                    return Err(bad(format!("identity memberships stream `{}` is always full", s.id)));
                }
            }
        }
    }
    Ok(())
}

/// Upper bound for a window's remembered uids (they live in the checkpoint).
pub const MAX_SEEN_CEILING: usize = 200_000;

/// Compile every stream program in a sandboxed worker and discard it.
/// Errors are reported as [`EngineError::Spec`].
pub async fn check_programs(cfg: &EngineConfig, spec: &ConnectorSpec) -> Result<(), EngineError> {
    for s in &spec.streams {
        if let Some(p) = &s.program {
            spawn_program(&cfg.vrl_pool, "validate", &s.id, p, &cfg.ceilings, cfg.worker_address_space).await?;
        }
    }
    Ok(())
}

fn worker_limits(limits: &Limits, address_space: u64) -> WorkerLimits {
    WorkerLimits {
        address_space_bytes: address_space,
        cpu_secs: limits.max_run_secs,
        call_timeout: Duration::from_millis(limits.vrl_timeout_ms),
        max_output_bytes: limits.max_response_bytes as usize * 2,
    }
}

fn program_error(stream: &str, e: VrlError) -> EngineError {
    match e {
        VrlError::Compile(m) => EngineError::Spec(format!("stream `{stream}` program: {m}")),
        // The compiler making a forbidden syscall is the host's sandbox
        // speaking, not a spec problem.
        VrlError::WorkerDied(m) if m.contains("seccomp") => EngineError::Vrl(VrlError::Sandbox(format!("stream `{stream}`: VRL worker {m}"))),
        VrlError::WorkerDied(m) => EngineError::Spec(format!("stream `{stream}` program: the VRL compiler {m}")),
        VrlError::Budget(ms) => EngineError::Spec(format!("stream `{stream}` program: compiling took longer than {ms} ms")),
        other => EngineError::Vrl(other),
    }
}

async fn spawn_program(pool: &VrlPool, tenant: &str, stream: &str, program: &str, limits: &Limits, address_space: u64) -> Result<PooledWorker, EngineError> {
    pool.spawn(tenant, program, worker_limits(limits, address_space)).await.map_err(|e| program_error(stream, e))
}

fn check_json_templates(v: &Value) -> Result<(), EngineError> {
    match v {
        Value::String(s) => {
            template::references(s)?;
        }
        Value::Array(a) => a.iter().try_for_each(check_json_templates)?,
        Value::Object(m) => m.values().try_for_each(check_json_templates)?,
        _ => {}
    }
    Ok(())
}

/// Shared per-run machinery.
struct Run {
    compiled: Compiled,
    transport: Arc<dyn Transport>,
    hosts: HostPolicy,
    creds: Credentials,
    config: Value,
    input: Value,
    clock: Clock,
    sink: Arc<dyn Sink>,
    store: Arc<dyn CheckpointStore>,
    requests: AtomicU32,
    pages: AtomicU32,
    events: AtomicU64,
    event_bytes: AtomicU64,
    dropped: AtomicU64,
    narrowed: AtomicU32,
    restarts: AtomicU32,
    last_request: Mutex<Option<Instant>>,
    /// One sandboxed worker per VRL stream, spawned before the first request.
    workers: HashMap<String, Mutex<PooledWorker>>,
    /// The pool slots those workers occupy, held for the whole run.
    _vrl_slots: Option<Reservation>,
    checkpoints: StdMutex<HashMap<String, Value>>,
    /// (derived secrets seen, matcher) for [`Run::secrets`].
    secret_cache: StdMutex<Option<(usize, Arc<SecretSet>)>>,
    feed_id: Option<String>,
    /// The platform pull broker call for this run's tenant, when the runner
    /// has a broker and the run has a tenant.
    pull_broker: Option<PullBrokerCall>,
    /// When the run started (identity: `identity_last_full_at`).
    started: DateTime<Utc>,
    /// Identity users streams: the mode each one ran in.
    identity_modes: StdMutex<Vec<(String, IdentityMode)>>,
}

/// One run's pull-broker identity: endpoint, fixed policy and caller token.
/// The token is a run secret (redacted, refused in vendor requests).
struct PullBrokerCall {
    endpoint: url::Url,
    graph_endpoint: url::Url,
    okta_endpoint: url::Url,
    hosts: HostPolicy,
    token: String,
    object: String,
}

impl Run {
    fn now(&self) -> DateTime<Utc> {
        (self.clock)()
    }

    fn caps(&self) -> BodyCaps {
        BodyCaps {
            max_response_bytes: self.compiled.limits.max_response_bytes,
            max_decompressed_bytes: self.compiled.limits.max_decompressed_bytes,
        }
    }

    fn scope(&self, state: &Value, item: &Value, window: &Value) -> Scope {
        Scope {
            config: self.config.clone(),
            state: state.clone(),
            item: item.clone(),
            input: self.input.clone(),
            window: window.clone(),
            now: self.now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            // Outside a sequence (discovery, item rendering): a stream
            // activated by this run.
            initial_cursor: Some(point_forward::fmt_rfc3339(point_forward::initial_cursor(self.started))),
            ..Default::default()
        }
    }

    /// [`Run::scope`] for a sequence: its own (possibly recorded) initial
    /// cursor.
    fn seq_scope(&self, seq: &Seq<'_>, state: &Value, window: &Value) -> Scope {
        Scope { initial_cursor: Some(seq.point_forward.initial_cursor_rfc3339()), ..self.scope(state, &seq.item, window) }
    }

    /// Every secret this run holds: the credentials plus tokens the auth
    /// plugin derived from them (OAuth access tokens).
    /// Cached; rebuilt only when the plugin minted a new token.
    fn secrets(&self) -> Arc<SecretSet> {
        let derived = self.compiled.auth.derived_secrets();
        let mut cache = self.secret_cache.lock().expect("secret cache");
        if let Some((n, set)) = cache.as_ref() {
            if *n == derived.len() {
                return set.clone();
            }
        }
        let platform = self.pull_broker.as_ref().map(|p| p.token.as_str());
        let set = Arc::new(SecretSet::with_derived(self.creds.values(), derived.iter().map(String::as_str).chain(platform)));
        *cache = Some((derived.len(), set.clone()));
        set
    }

    /// A credential may only enter a request through the auth plugin, in
    /// any encoding (matched raw and percent-/JSON-decoded).
    fn refuse_secrets(&self, req: &OutboundRequest) -> Result<(), EngineError> {
        let set = self.secrets();
        if set.is_empty() {
            return Ok(());
        }
        if set.contains_decoded(req.url.as_str().as_bytes())
            || set.contains_decoded(&req.body)
            || req.headers.iter().any(|(k, v)| set.contains_decoded(k.as_bytes()) || set.contains_decoded(v.as_bytes()))
        {
            return Err(EngineError::CredentialExfil);
        }
        Ok(())
    }

    /// Scrub every secret shape from a response before VRL, ingest or a
    /// checkpoint sees it. What the shape list misses but a decoded view
    /// still shows is handled per JSON string (the whole string goes); a
    /// non-JSON body that still carries a secret is refused.
    fn redact(&self, mut resp: InboundResponse) -> Result<InboundResponse, EngineError> {
        let set = self.secrets();
        if set.is_empty() {
            return Ok(resp);
        }
        if set.contains(&resp.body) {
            resp.body = Bytes::from(set.redact(&resp.body));
        }
        if set.contains_decoded(&resp.body) {
            let mut v: Value = serde_json::from_slice(&resp.body).map_err(|_| EngineError::CredentialInResponse)?;
            redact_json(&set, &mut v);
            let body = serde_json::to_vec(&v).map_err(|_| EngineError::CredentialInResponse)?;
            if set.contains_decoded(&body) {
                return Err(EngineError::CredentialInResponse);
            }
            resp.body = Bytes::from(body);
        }
        for v in resp.headers.values_mut() {
            if set.contains_decoded(v.as_bytes()) {
                *v = http::HeaderValue::from_static("[REDACTED]");
            }
        }
        Ok(resp)
    }

    async fn pace(&self, extra: Option<Duration>) {
        let min = Duration::from_millis(self.compiled.spec.rate_limit.min_interval_ms);
        let mut last = self.last_request.lock().await;
        if let Some(t) = *last {
            let due = t + min.max(extra.unwrap_or_default());
            let now = Instant::now();
            if due > now {
                tokio::time::sleep(due - now).await;
            }
        }
        *last = Some(Instant::now());
    }

    /// One logical request: auth, redirects (re-validated per hop), 401
    /// refresh, 429 / 5xx retry. `Ok(None)` means the page token expired.
    async fn exchange(
        &self,
        mut base: OutboundRequest,
        restart: Option<&crate::spec::RestartOn>,
        rewrite: Option<&RetryRewrite>,
        scope: &Scope,
    ) -> Result<Option<InboundResponse>, EngineError> {
        self.refuse_secrets(&base)?;
        let rl = &self.compiled.spec.rate_limit;
        let (mut n429, mut n5xx, mut refreshed) = (0u32, 0u32, false);
        let origin_host = base.url.host_str().unwrap_or_default().to_string();
        loop {
            if self.requests.fetch_add(1, Ordering::SeqCst) >= self.compiled.limits.max_requests {
                return Err(EngineError::Cap(format!("{} requests", self.compiled.limits.max_requests)));
            }
            self.pace(None).await;
            let mut req = base.clone();
            let mut hops = 0;
            let resp = loop {
                if req.url.host_str() == Some(origin_host.as_str()) {
                    let cx = AuthContext { creds: &self.creds, fetch: self, scope, now: self.now(), feed_id: self.feed_id.as_deref() };
                    self.compiled.auth.apply(&mut req, &cx).await.map_err(|e| match e {
                        AuthError::RateLimited => EngineError::Upstream {
                            status: 429,
                            body: "session login rate limited".into(),
                        },
                        e => EngineError::Auth(e),
                    })?;
                }
                let r = match self.transport.send_once(&req, &self.hosts, self.caps()).await {
                    Ok(r) => r,
                    Err(e @ (BrokerError::Connect(..) | BrokerError::Timeout(_) | BrokerError::Http(_))) => {
                        n5xx += 1;
                        if n5xx > rl.max_retries_5xx {
                            return Err(e.into());
                        }
                        tokio::time::sleep(Duration::from_millis(rl.backoff_ms * n5xx as u64)).await;
                        // The request may have reached the vendor before the
                        // connection failed.
                        rewrite_for_retry(&mut base, rewrite);
                        req = base.clone();
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                if (300..400).contains(&r.status) && r.status != 304 {
                    if let Some(loc) = r.header("location") {
                        hops += 1;
                        if hops > self.compiled.limits.max_redirects {
                            return Err(EngineError::Cap(format!("{} redirects", self.compiled.limits.max_redirects)));
                        }
                        let next = req.url.join(loc).map_err(|e| PolicyError::BadUrl(e.to_string()))?;
                        // Fail closed here, before any connection to the hop.
                        self.hosts.check(&next)?;
                        // A vendor may echo a query-string key into Location;
                        // that is fine on its own host, never on another one.
                        if next.host_str() != Some(origin_host.as_str()) && self.secrets().contains_decoded(next.as_str().as_bytes()) {
                            return Err(EngineError::CredentialExfil);
                        }
                        let to_get = r.status == 303 || ((r.status == 301 || r.status == 302) && req.method == http::Method::POST);
                        req = OutboundRequest {
                            method: if to_get { http::Method::GET } else { base.method.clone() },
                            url: next,
                            headers: base.headers.clone(),
                            body: if to_get { Bytes::new() } else { base.body.clone() },
                        };
                        continue;
                    }
                }
                break r;
            };
            let resp = self.redact(resp)?;
            match resp.status {
                401 if !refreshed && self.compiled.auth.invalidate(&req).await => {
                    refreshed = true;
                    continue;
                }
                429 => {
                    n429 += 1;
                    if n429 > rl.max_retries_429 {
                        return Err(EngineError::Upstream { status: 429, body: format!("rate limit persisted after {n429} attempts") });
                    }
                    let max_wait = Duration::from_millis(rl.max_wait_ms);
                    // A server-demanded wait longer than we accept fails fast;
                    // our own backoff (no Retry-After) doubles per attempt and
                    // is capped at max_wait_ms instead of failing the run.
                    let wait = match self.server_wait(&resp) {
                        Some(w) if w > max_wait => {
                            return Err(EngineError::Upstream {
                                status: 429,
                                body: format!("rate limit persisted: server asked to wait {} s, above max_wait_ms {}", w.as_secs(), rl.max_wait_ms),
                            });
                        }
                        Some(w) => w,
                        None => Duration::from_millis(rl.backoff_ms.saturating_mul(1u64 << (n429 - 1).min(20))).min(max_wait),
                    };
                    tokio::time::sleep(wait).await;
                    continue;
                }
                s if s >= 500 => {
                    n5xx += 1;
                    if n5xx > rl.max_retries_5xx {
                        return Err(EngineError::Upstream { status: s, body: snippet(&resp.body) });
                    }
                    tokio::time::sleep(Duration::from_millis(rl.backoff_ms * n5xx as u64)).await;
                    rewrite_for_retry(&mut base, rewrite);
                    continue;
                }
                s => {
                    if let Some(r) = restart {
                        if r.status.contains(&s)
                            && r.body_contains.as_ref().is_none_or(|b| String::from_utf8_lossy(&resp.body).contains(b.as_str()))
                        {
                            return Ok(None);
                        }
                    }
                    self.after_response(&resp).await;
                    return Ok(Some(resp));
                }
            }
        }
    }

    fn server_wait(&self, resp: &InboundResponse) -> Option<Duration> {
        if let Some(h) = &self.compiled.spec.rate_limit.reset_header {
            if let Some(reset) = resp.header(h).and_then(|v| v.trim().parse::<i64>().ok()) {
                let ms = (reset * 1000 - self.now().timestamp_millis()).max(0) as u64 + 1000;
                return Some(Duration::from_millis(ms));
            }
        }
        resp.header("retry-after")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs)
    }

    /// Slow down before the quota runs out.
    async fn after_response(&self, resp: &InboundResponse) {
        let rl = &self.compiled.spec.rate_limit;
        if let Some(h) = &rl.remaining_header {
            if let Some(rem) = resp.header(h).and_then(|v| v.trim().parse::<u64>().ok()) {
                if rem <= rl.remaining_floor {
                    let wait = self.server_wait(resp).unwrap_or_default().min(Duration::from_millis(rl.max_wait_ms));
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }

    fn build_request(&self, tpl: &RequestTemplate, scope: &Scope, extra_query: &BTreeMap<String, String>) -> Result<OutboundRequest, EngineError> {
        let mut guarded = scope.clone();
        guarded.secret_guard = Some(template::SecretGuard::new(self.secrets().as_ref().clone(), SecretSet::default()));
        let scope = &guarded;
        let mut url = template::render_url(&tpl.url, scope)?;
        {
            let mut q: BTreeMap<String, String> = BTreeMap::new();
            for (k, v) in &tpl.query {
                let v = template::render_str(v, scope)?;
                if !v.is_empty() {
                    q.insert(template::render_str(k, scope)?, v);
                }
            }
            for (k, v) in extra_query {
                q.insert(k.clone(), v.clone());
            }
            if !q.is_empty() {
                url.query_pairs_mut().extend_pairs(q);
            }
        }
        let mut headers: Vec<(String, String)> = Vec::new();
        for (k, v) in &tpl.headers {
            headers.push((k.clone(), template::render_str(v, scope)?));
        }
        let body = match &tpl.body {
            None | Some(Body { form: None, json: None }) => Bytes::new(),
            Some(Body { form: Some(m), .. }) => {
                headers.push(("Content-Type".into(), "application/x-www-form-urlencoded".into()));
                let mut ser = url::form_urlencoded::Serializer::new(String::new());
                for (k, v) in m {
                    ser.append_pair(k, &template::render_str(v, scope)?);
                }
                Bytes::from(ser.finish())
            }
            Some(Body { json: Some(v), .. }) => {
                headers.push(("Content-Type".into(), "application/json".into()));
                Bytes::from(template::render_json(v, scope)?.to_string())
            }
        };
        Ok(OutboundRequest { method: method(tpl.method), url, headers, body })
    }

    /// Turn a program's `next_request` into a request. No headers can be set.
    fn build_next(&self, base: Option<&OutboundRequest>, tpl: Option<&RequestTemplate>, n: &NextRequest, scope: &Scope) -> Result<OutboundRequest, EngineError> {
        let mut guarded = scope.clone();
        guarded.secret_guard = Some(template::SecretGuard::new(self.secrets().as_ref().clone(), SecretSet::default()));
        let scope = &guarded;
        let static_headers: Vec<(String, String)> = match tpl {
            Some(t) => t
                .headers
                .iter()
                .map(|(k, v)| Ok((k.clone(), template::render_str(v, scope)?)))
                .collect::<Result<_, EngineError>>()?,
            None => vec![("Accept".into(), "application/json".into())],
        };
        let mut url = match (&n.url, tpl) {
            (Some(u), _) => url::Url::parse(u).map_err(|e| PolicyError::BadUrl(e.to_string()))?,
            (None, Some(t)) => template::render_url(&t.url, scope)?,
            (None, None) => match base {
                Some(b) => {
                    let mut u = b.url.clone();
                    u.set_query(None);
                    u
                }
                None => return Err(EngineError::ProgramShape("first next_request needs `url`".into())),
            },
        };
        let mut q: BTreeMap<String, String> = BTreeMap::new();
        if n.url.is_none() {
            if let Some(t) = tpl {
                for (k, v) in &t.query {
                    let v = template::render_str(v, scope)?;
                    if !v.is_empty() {
                        q.insert(k.clone(), v);
                    }
                }
            }
        }
        if let Some(extra) = &n.query {
            for (k, v) in extra {
                match v {
                    Value::Null => {
                        q.remove(k);
                    }
                    v => {
                        q.insert(k.clone(), template::value_to_string(v));
                    }
                }
            }
        }
        if !q.is_empty() {
            let existing: Vec<(String, String)> = url.query_pairs().map(|(a, b)| (a.into_owned(), b.into_owned())).collect();
            let mut merged: BTreeMap<String, String> = existing.into_iter().collect();
            merged.extend(q);
            url.query_pairs_mut().clear().extend_pairs(merged);
        }
        let mut headers = static_headers;
        let (m, body) = if let Some(form) = &n.form {
            headers.push(("Content-Type".into(), "application/x-www-form-urlencoded".into()));
            let mut ser = url::form_urlencoded::Serializer::new(String::new());
            for (k, v) in form {
                ser.append_pair(k, &template::value_to_string(v));
            }
            (n.method.unwrap_or(Method::Post), Bytes::from(ser.finish()))
        } else if let Some(j) = &n.json {
            headers.push(("Content-Type".into(), "application/json".into()));
            (n.method.unwrap_or(Method::Post), Bytes::from(j.to_string()))
        } else {
            (n.method.or(tpl.map(|t| t.method)).unwrap_or(Method::Get), Bytes::new())
        };
        Ok(OutboundRequest { method: method(m), url, headers, body })
    }

    fn count_events(&self, events: &[Value]) -> Result<(), EngineError> {
        let bytes: u64 = events.iter().map(|e| e.to_string().len() as u64).sum();
        let n = self.events.fetch_add(events.len() as u64, Ordering::SeqCst) + events.len() as u64;
        let b = self.event_bytes.fetch_add(bytes, Ordering::SeqCst) + bytes;
        if n > self.compiled.limits.max_events {
            return Err(EngineError::Cap(format!("{} events", self.compiled.limits.max_events)));
        }
        if b > self.compiled.limits.max_event_bytes {
            return Err(EngineError::Cap(format!("{} event bytes", self.compiled.limits.max_event_bytes)));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl TokenFetch for Run {
    async fn session_login(&self, request: &OutboundRequest) -> Result<InboundResponse, String> {
        if self
            .secrets()
            .contains_decoded(request.url.as_str().as_bytes())
        {
            return Err("login URL would expose a credential".into());
        }
        if self.requests.fetch_add(1, Ordering::SeqCst) >= self.compiled.limits.max_requests {
            return Err("request cap reached".into());
        }
        self.pace(None).await;
        self.transport
            .send_once_with_purpose(
                request,
                &self.hosts,
                self.caps(),
                RequestPurpose::Authentication,
            )
            .await
            .map_err(|_| "session exchange failed".into())
    }
    async fn post_form(&self, url: &str, form: &[(String, String)]) -> Result<(u16, Vec<u8>), String> {
        let url = url::Url::parse(url).map_err(|e| e.to_string())?;
        let encoded = {
            let mut ser = url::form_urlencoded::Serializer::new(String::new());
            for (k, v) in form {
                ser.append_pair(k, v);
            }
            ser.finish()
        };
        let req = OutboundRequest {
            method: http::Method::POST,
            url,
            headers: vec![("Content-Type".into(), "application/x-www-form-urlencoded".into()), ("Accept".into(), "application/json".into())],
            body: Bytes::from(encoded),
        };
        if self.requests.fetch_add(1, Ordering::SeqCst) >= self.compiled.limits.max_requests {
            return Err("request cap reached".into());
        }
        let r = self.transport.send_once(&req, &self.hosts, self.caps()).await.map_err(|e| e.to_string())?;
        Ok((r.status, r.body.to_vec()))
    }

    /// The platform broker call: the engine transport (pinning, TLS,
    /// timeouts) under the broker's fixed single-route policy, never the
    /// spec allowlist. Small bodies only; no redirects.
    async fn post_dwd_assertion(&self, body: &Value) -> Result<auth::BrokerReply, String> {
        let Some(p) = &self.pull_broker else {
            return Err(crate::pull_broker::UNCONFIGURED.into());
        };
        self.post_broker(p.endpoint.clone(), body).await
    }

    async fn post_graph_token(&self, body: &Value) -> Result<auth::BrokerReply, String> {
        let Some(p) = &self.pull_broker else {
            return Err(crate::pull_broker::UNCONFIGURED.into());
        };
        self.post_broker(p.graph_endpoint.clone(), body).await
    }

    async fn post_okta_assertion(&self, body: &Value) -> Result<auth::BrokerReply, String> {
        let Some(p) = &self.pull_broker else {
            return Err(crate::pull_broker::UNCONFIGURED.into());
        };
        self.post_broker(p.okta_endpoint.clone(), body).await
    }
}

impl Run {
    async fn post_broker(&self, url: url::Url, body: &Value) -> Result<auth::BrokerReply, String> {
        let Some(p) = &self.pull_broker else {
            return Err(crate::pull_broker::UNCONFIGURED.into());
        };
        let req = OutboundRequest {
            method: http::Method::POST,
            url,
            headers: vec![
                ("Authorization".into(), format!("Bearer {}", p.token)),
                ("x-nano-pull-broker-object".into(), p.object.clone()),
                ("Content-Type".into(), "application/json".into()),
                ("Accept".into(), "application/json".into()),
            ],
            body: Bytes::from(body.to_string()),
        };
        if self.requests.fetch_add(1, Ordering::SeqCst) >= self.compiled.limits.max_requests {
            return Err("request cap reached".into());
        }
        let caps = BodyCaps { max_response_bytes: 64 * 1024, max_decompressed_bytes: 64 * 1024 };
        let r = self.transport.send_once(&req, &p.hosts, caps).await.map_err(|e| e.to_string())?;
        let retry_after = r.header("retry-after").and_then(|v| v.trim().parse::<u64>().ok());
        Ok(auth::BrokerReply { status: r.status, retry_after, body: r.body.to_vec() })
    }
}

/// Redact every string (and key) of a JSON value; a string that still
/// decodes to a secret is replaced whole.
fn redact_json(set: &SecretSet, v: &mut Value) {
    let scrub = |s: &str| -> String {
        let r = set.redact_str(s);
        if set.contains_decoded(r.as_bytes()) { "[REDACTED]".to_string() } else { r }
    };
    match v {
        Value::String(s) => *s = scrub(s),
        Value::Array(a) => a.iter_mut().for_each(|x| redact_json(set, x)),
        Value::Object(m) => {
            let old = std::mem::take(m);
            for (k, mut x) in old {
                redact_json(set, &mut x);
                m.insert(scrub(&k), x);
            }
        }
        _ => {}
    }
}

/// Apply a stream's `retry_rewrite` to a request about to be retried.
fn rewrite_for_retry(req: &mut OutboundRequest, rewrite: Option<&RetryRewrite>) {
    let Some(rw) = rewrite else { return };
    let pairs: Vec<(String, String)> = req.url.query_pairs().into_owned().collect();
    if !pairs.iter().any(|(k, v)| *k == rw.param && *v == rw.from) {
        return;
    }
    let mut q = req.url.query_pairs_mut();
    q.clear();
    for (k, v) in &pairs {
        q.append_pair(k, if *k == rw.param && *v == rw.from { &rw.to } else { v });
    }
}

fn method(m: Method) -> http::Method {
    match m {
        Method::Get => http::Method::GET,
        Method::Post => http::Method::POST,
        Method::Put => http::Method::PUT,
        Method::Patch => http::Method::PATCH,
        Method::Delete => http::Method::DELETE,
        Method::Head => http::Method::HEAD,
    }
}

fn snippet(b: &[u8]) -> String {
    String::from_utf8_lossy(&b[..b.len().min(300)]).to_string()
}

fn parse_body(fmt: Format, body: &[u8]) -> Value {
    let text = String::from_utf8_lossy(body);
    match fmt {
        Format::Json => serde_json::from_slice(body).unwrap_or(Value::String(text.into_owned())),
        Format::Ndjson => Value::Array(text.lines().filter(|l| !l.trim().is_empty()).filter_map(|l| serde_json::from_str(l).ok()).collect()),
        Format::Lines => Value::Array(text.lines().map(str::trim).filter(|l| !l.is_empty()).map(|l| Value::String(l.into())).collect()),
        Format::Text => Value::String(text.into_owned()),
    }
}

fn response_value(resp: &InboundResponse, body: &Value) -> Value {
    let mut headers = Map::new();
    for (k, v) in &resp.headers {
        if let Ok(v) = v.to_str() {
            headers.insert(k.as_str().to_ascii_lowercase(), Value::String(v.to_string()));
        }
    }
    let next = resp.header("link").and_then(paging::link_next);
    json!({ "status": resp.status, "headers": headers, "body": body, "links": { "next": next } })
}

/// Parse an event timestamp: RFC 3339, or epoch seconds / millis (number or
/// numeric string; > 1e11 is millis).
pub fn event_time_ms(v: &Value) -> Option<i64> {
    match v {
        Value::String(s) => DateTime::parse_from_rfc3339(s)
            .map(|d| d.timestamp_millis())
            .ok()
            .or_else(|| s.parse::<f64>().ok().map(epoch_ms)),
        Value::Number(n) => n.as_f64().map(epoch_ms),
        _ => None,
    }
}

fn epoch_ms(x: f64) -> i64 {
    if x > 1e11 { x as i64 } else { (x * 1000.0) as i64 }
}

fn fmt_time(ms: i64, f: TimeFormat) -> Value {
    match f {
        TimeFormat::Rfc3339 => Value::String(
            Utc.timestamp_millis_opt(ms).single().unwrap_or_default().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        ),
        TimeFormat::EpochSecs => json!(ms / 1000),
        TimeFormat::EpochMillis => json!(ms),
    }
}

/// Outcome of one request sequence (one window or one plain walk).
enum Walk {
    Complete,
    CapReached,
    Restart,
    /// An identity program asked for a full run (`restart_full: true`).
    RestartFull,
}

/// Per-sequence mutable context.
struct Seq<'a> {
    stream: &'a Stream,
    stepper: &'a dyn Stepper,
    worker: Option<&'a Mutex<PooledWorker>>,
    item: Value,
    item_key: Option<String>,
    source_type: String,
    /// The stream's checkpoint, shared by fan-out tasks.
    shared: &'a Mutex<Value>,
    /// `kind: identity`: the stream's role and this run's mode.
    identity: Option<(IdentityRole, IdentityMode)>,
    /// NAN-3697: this sequence's initial cursor and whether this run
    /// activates it.
    point_forward: PointForward,
}

impl Seq<'_> {
    /// Identity full runs and memberships save no per-page checkpoint: a
    /// full run's cursor moves only after the coordinator committed it.
    fn defers_checkpoint(&self) -> bool {
        matches!(self.identity, Some((IdentityRole::Memberships, _) | (_, IdentityMode::Full)))
    }
}

/// The checkpoint object a sequence owns: the stream's, or its fan-out item's.
fn checkpoint_slot<'a>(cp: &'a mut Value, item_key: Option<&str>) -> &'a mut Map<String, Value> {
    let slot = match item_key {
        Some(k) => {
            let items = cp.as_object_mut().expect("checkpoint object").entry("items").or_insert_with(|| json!({}));
            items.as_object_mut().expect("items object").entry(k.to_string()).or_insert_with(|| json!({}))
        }
        None => cp,
    };
    slot.as_object_mut().expect("slot object")
}

/// NAN-3697: the sequence's initial cursor. Only collector streams record an
/// activation: identity streams are directory syncs, not time cursors, and
/// enrichment specs keep no cursor.
fn seq_point_forward(run: &Run, saved: &Value, identity: bool) -> PointForward {
    let p = PointForward::from_saved(saved, run.started);
    let collector = run.compiled.spec.kind == Kind::Collector;
    PointForward { activating: p.activating && collector && !identity, ..p }
}

impl Run {
    /// Commit `user_state` (and window bookkeeping) for this sequence.
    async fn commit(&self, seq: &Seq<'_>, user_state: &Value, window: Option<&Value>) -> Result<(), EngineError> {
        if seq.defers_checkpoint() {
            return Ok(());
        }
        let mut cp = seq.shared.lock().await;
        let obj = checkpoint_slot(&mut cp, seq.item_key.as_deref());
        if seq.point_forward.activating && !obj.contains_key(POINT_FORWARD_KEY) {
            obj.insert(POINT_FORWARD_KEY.into(), seq.point_forward.record(self.started));
        }
        obj.insert("state".into(), user_state.clone());
        if let Some(w) = window {
            obj.insert("window".into(), w.clone());
        }
        let snapshot = cp.clone();
        drop(cp);
        self.save_checkpoint(&seq.stream.id, snapshot).await
    }

    async fn save_checkpoint(&self, stream: &str, snapshot: Value) -> Result<(), EngineError> {
        let size = serde_json::to_vec(&snapshot).map(|v| v.len() as u64).unwrap_or(u64::MAX);
        if size > self.compiled.limits.max_checkpoint_bytes {
            return Err(EngineError::Cap(format!(
                "checkpoint of {size} bytes exceeds {} bytes",
                self.compiled.limits.max_checkpoint_bytes
            )));
        }
        self.store.save(stream, &snapshot).await.map_err(EngineError::Sink)?;
        self.checkpoints.lock().expect("checkpoints").insert(stream.to_string(), snapshot);
        Ok(())
    }

    /// Walk pages until done. `window` = (start_ms, end_ms) when windowed;
    /// `seen` = uid -> event time for dedupe.
    async fn walk(
        &self,
        seq: &Seq<'_>,
        state: &mut Value,
        window: Option<(i64, i64)>,
        seen: &mut BTreeMap<String, i64>,
        wspec: Option<&WindowSpec>,
        wstate: &mut Value,
    ) -> Result<Walk, EngineError> {
        let s = seq.stream;
        let window_v = match (window, wspec) {
            (Some((a, b)), Some(w)) => json!({ "start": fmt_time(a, w.format), "end": fmt_time(b, w.format) }),
            _ => Value::Null,
        };
        let mut page_state = PageState::default();
        let first_q = seq.stepper.first(&mut page_state);
        let scope = self.seq_scope(seq, state, &window_v);

        let mut req = match &s.request {
            Some(t) => self.build_request(t, &scope, &first_q)?,
            None => {
                let out = self.call_program(seq, state, Value::Null, &Value::Null, &window_v).await?;
                if let Some(st) = out.state {
                    *state = Value::Object(st);
                }
                match out.next_request {
                    Some(n) => self.build_next(None, None, &n, &scope)?,
                    None => return Err(EngineError::ProgramShape("program returned no first request".into())),
                }
            }
        };

        loop {
            if self.pages.fetch_add(1, Ordering::SeqCst) >= self.compiled.limits.max_pages {
                return Err(EngineError::Cap(format!("{} pages", self.compiled.limits.max_pages)));
            }
            if let Some(patch) = &s.write_ahead_state {
                let mut ws = state.clone();
                if let Some(o) = ws.as_object_mut() {
                    for (k, v) in patch {
                        o.insert(k.clone(), v.clone());
                    }
                }
                self.commit(seq, &ws, wspec.map(|_| &*wstate)).await?;
            }
            let scope = self.seq_scope(seq, state, &window_v);
            let Some(resp) = self.exchange(req.clone(), s.restart_window_on.as_ref(), s.retry_rewrite.as_ref(), &scope).await? else {
                return Ok(Walk::Restart);
            };
            let body = parse_body(s.response.format, &resp.body);

            let (mut events, step, new_state, wait) = if s.program.is_some() {
                let reqv = json!({ "url": req.url.as_str(), "method": req.method.as_str() });
                let out = self.call_program(seq, state, response_value(&resp, &body), &reqv, &window_v).await?;
                if out.restart_full == Some(true) {
                    // Nothing from this page is delivered; the caller reruns
                    // the stream as a full run (or fails it).
                    return Ok(Walk::RestartFull);
                }
                let st = out.state.map(Value::Object).unwrap_or_else(|| state.clone());
                let step = match out.next_request {
                    None => None,
                    Some(n) => {
                        let sc = self.seq_scope(seq, &st, &window_v);
                        Some(self.build_next(Some(&req), s.request.as_ref(), &n, &sc)?)
                    }
                };
                (out.events, step, st, out.wait_ms)
            } else {
                if !(200..300).contains(&resp.status) {
                    return Err(EngineError::Upstream { status: resp.status, body: snippet(&resp.body) });
                }
                let mut events = match paging::get_path(&body, &s.response.events_path) {
                    Some(Value::Array(a)) => a.clone(),
                    Some(Value::Null) | None => vec![],
                    Some(other) => vec![other.clone()],
                };
                let cx = PageCtx { resp: &resp, body: &body, events: &events };
                let step = match seq.stepper.next(&cx, &mut page_state).map_err(EngineError::Spec)? {
                    Step::Done => None,
                    Step::CapReached => {
                        self.deliver(seq, &mut events, seen, wspec)?;
                        self.flush(seq, &events).await?;
                        let st = self.reduce_cursor(s, state, &events);
                        *state = st;
                        self.commit(seq, state, wspec.map(|_| &*sync_seen(wstate, seen))).await?;
                        return Ok(Walk::CapReached);
                    }
                    Step::Url(u) => {
                        self.hosts.check(&u)?;
                        Some(OutboundRequest { url: u, ..req.clone() })
                    }
                    Step::Query(q) => {
                        let sc = self.seq_scope(seq, state, &window_v);
                        let t = s.request.as_ref().ok_or_else(|| EngineError::Spec("pagination needs `request`".into()))?;
                        Some(self.build_request(t, &sc, &q)?)
                    }
                };
                let st = self.reduce_cursor(s, state, &events);
                (events, step, st, None)
            };

            self.deliver(seq, &mut events, seen, wspec)?;
            self.flush(seq, &events).await?;
            *state = new_state;
            // Acknowledged: now (and only now) the cursor may move.
            self.commit(seq, state, wspec.map(|_| &*sync_seen(wstate, seen))).await?;

            match step {
                None => return Ok(Walk::Complete),
                Some(next) => {
                    if let Some(ms) = wait {
                        let max = self.compiled.spec.rate_limit.max_wait_ms;
                        tokio::time::sleep(Duration::from_millis(ms.min(max))).await;
                    }
                    req = next;
                }
            }
        }
    }

    /// Dedupe by uid (windowed streams) and count against caps.
    fn deliver(&self, seq: &Seq<'_>, events: &mut Vec<Value>, seen: &mut BTreeMap<String, i64>, wspec: Option<&WindowSpec>) -> Result<(), EngineError> {
        if let Some(w) = wspec {
            let before = events.len();
            events.retain(|e| {
                let Some(uid) = paging::get_path(e, &w.uid_field).map(template::value_to_string).filter(|u| !u.is_empty()) else {
                    return true;
                };
                if seen.contains_key(&uid) {
                    return false;
                }
                let t = paging::get_path(e, &w.time_field).and_then(event_time_ms).unwrap_or(0);
                seen.insert(uid, t);
                true
            });
            self.dropped.fetch_add((before - events.len()) as u64, Ordering::SeqCst);
            if seen.len() > w.max_seen {
                let mut by_time: Vec<(i64, String)> = seen.iter().map(|(k, t)| (*t, k.clone())).collect();
                by_time.sort();
                for (_, k) in by_time.iter().take(seen.len() - w.max_seen) {
                    seen.remove(k);
                }
            }
        }
        let _ = seq;
        self.count_events(events)
    }

    async fn flush(&self, seq: &Seq<'_>, events: &[Value]) -> Result<(), EngineError> {
        if events.is_empty() {
            return Ok(());
        }
        if let (Some((role, mode)), Some(t)) = (seq.identity, self.sink.identity()) {
            let id = &seq.stream.id;
            return match role {
                IdentityRole::Users => t.users_page(id, mode, events).await,
                IdentityRole::Memberships => t.memberships_page(id, events).await,
            }
            .map_err(EngineError::Sink);
        }
        if self.compiled.spec.kind != Kind::Collector {
            return self.sink.push(&seq.source_type, events).await.map_err(EngineError::Sink);
        }
        let fields = seq.stream.ingest_id_fields();
        let stamped: Vec<Value> = events.iter().map(|e| stamp_ingest_id(e, &fields)).collect();
        self.sink.push(&seq.source_type, &stamped).await.map_err(EngineError::Sink)
    }

    fn reduce_cursor(&self, s: &Stream, state: &Value, events: &[Value]) -> Value {
        let mut st = state.clone();
        if let (Some(c), Some(obj)) = (&s.cursor, st.as_object_mut()) {
            let vals = events.iter().filter_map(|e| paging::get_path(e, &c.field)).filter(|v| !v.is_null());
            let pick = match c.reduce {
                CursorReduce::Last => vals.last().cloned(),
                CursorReduce::Max => vals.max_by(|a, b| match (event_time_ms(a), event_time_ms(b)) {
                    (Some(x), Some(y)) => x.cmp(&y),
                    _ => template::value_to_string(a).cmp(&template::value_to_string(b)),
                }).cloned(),
            };
            if let Some(v) = pick {
                let replace = match obj.get(&c.state_key) {
                    Some(old) if matches!(c.reduce, CursorReduce::Max) => match (event_time_ms(old), event_time_ms(&v)) {
                        (Some(o), Some(n)) => n > o,
                        _ => true,
                    },
                    _ => true,
                };
                if replace {
                    obj.insert(c.state_key.clone(), v);
                }
            }
        }
        st
    }

    async fn call_program(&self, seq: &Seq<'_>, state: &Value, response: Value, request: &Value, window: &Value) -> Result<ProgramOutput, EngineError> {
        let w = seq.worker.ok_or_else(|| EngineError::Spec("no program".into()))?;
        let input = json!({
            "state": state,
            "response": response,
            "request": request,
            "config": self.config,
            "input": self.input,
            "item": seq.item,
            "window": window,
            "now": self.now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "initial_cursor": seq.point_forward.initial_cursor_rfc3339(),
            // Deprecated alias (NAN-3697): same value, never an operator backfill.
            "backfill_from": seq.point_forward.initial_cursor_rfc3339(),
            "identity": seq.identity.map(|(role, mode)| json!({ "role": role, "mode": mode.as_str() })),
        });
        let out = w.lock().await.call(&input).await?;
        let parsed: ProgramOutput = serde_json::from_value(out).map_err(|e| EngineError::ProgramShape(e.to_string()))?;
        if let Some(e) = parsed.error {
            return Err(EngineError::Program(e));
        }
        if parsed.restart_full == Some(true) && !matches!(seq.identity, Some((IdentityRole::Users, IdentityMode::Delta))) {
            return Err(EngineError::ProgramShape("restart_full is honored only on identity users streams running in delta mode".into()));
        }
        Ok(parsed)
    }

    /// Plain walk, or time-window stepping with narrowing and restarts.
    async fn run_sequence(&self, seq: &Seq<'_>, saved: Value) -> Result<(), EngineError> {
        let s = seq.stream;
        let mut state = saved.get("state").cloned().unwrap_or_else(|| {
            let scope = self.seq_scope(seq, &json!({}), &Value::Null);
            let init: Map<String, Value> = s
                .initial_state
                .iter()
                .map(|(k, v)| (k.clone(), template::render_json(v, &scope).unwrap_or(Value::Null)))
                .collect();
            Value::Object(init)
        });
        let Some(w) = &s.window else {
            if seq.point_forward.activating {
                // Record the activation (and the initial state rendered from
                // the initial cursor) before the first request, so a run that
                // ships nothing still pins the stream's start.
                self.commit(seq, &state, None).await?;
            }
            let mut seen = BTreeMap::new();
            let mut ws = Value::Null;
            return match self.walk(seq, &mut state, None, &mut seen, None, &mut ws).await? {
                Walk::Complete => Ok(()),
                Walk::CapReached => Err(EngineError::Cap("offset cap reached outside a time window".into())),
                Walk::Restart => Err(EngineError::Upstream { status: 0, body: "page token expired".into() }),
                Walk::RestartFull => Err(EngineError::ProgramShape("restart_full outside an identity users stream".into())),
            };
        };

        let mut wstate = saved.get("window").cloned().unwrap_or_else(|| json!({}));
        let initial_ms = seq.point_forward.initial_cursor.timestamp_millis();
        if seq.point_forward.activating {
            // NAN-3697: a new stream's first window starts at its initial
            // cursor (activation − overlap). Pinned now, so it never drifts.
            wstate.as_object_mut().expect("window state").insert("resume".into(), json!(initial_ms));
            self.commit(seq, &state, Some(&wstate)).await?;
        }
        let mut seen: BTreeMap<String, i64> = wstate
            .get("seen")
            .and_then(Value::as_object)
            .map(|m| m.iter().filter_map(|(k, v)| v.as_i64().map(|t| (k.clone(), t))).collect())
            .unwrap_or_default();
        let span = (w.max_span_secs * 1000) as i64;
        let lookback = (w.lookback_secs * 1000) as i64;
        // `watermark` = end of the last completed pass (everything before it
        // was read up to the lag). A pass re-reads `lookback` before it for
        // late arrivals, then walks consecutive windows up to the horizon;
        // `resume` is the next window start inside a pass (survives crashes).
        let horizon = self.now().timestamp_millis() - (w.lag_secs * 1000) as i64;
        loop {
            let watermark = wstate.get("watermark").and_then(Value::as_i64);
            let resume = wstate.get("resume").and_then(Value::as_i64);
            let start = match (resume, watermark) {
                (Some(r), _) => r,
                (None, Some(wm)) => {
                    if horizon <= wm {
                        return Ok(());
                    }
                    wm - lookback
                }
                // No pass completed and no resume point: never earlier than
                // the initial cursor (`initial_lookback_secs` is only the
                // checkpoint-reset bound now).
                (None, None) => initial_ms,
            };
            if start >= horizon {
                return Ok(());
            }
            let mut end = (start + span).min(horizon);
            let mut restarts = 0;
            loop {
                match self.walk(seq, &mut state, Some((start, end)), &mut seen, Some(w), &mut wstate).await? {
                    Walk::Complete => break,
                    Walk::CapReached => {
                        self.narrowed.fetch_add(1, Ordering::SeqCst);
                        let mid = start + (end - start) / 2;
                        if mid <= start + 1000 {
                            return Err(EngineError::Cap("offset cap reached in a one-second window".into()));
                        }
                        end = mid;
                    }
                    Walk::RestartFull => {
                        return Err(EngineError::ProgramShape("restart_full outside an identity users stream".into()));
                    }
                    Walk::Restart => {
                        restarts += 1;
                        self.restarts.fetch_add(1, Ordering::SeqCst);
                        if restarts > w_max_restarts(s) {
                            return Err(EngineError::Restarts(restarts));
                        }
                    }
                }
            }
            // Window done and acknowledged.
            let obj = wstate.as_object_mut().expect("window state");
            if end >= horizon {
                // Pass complete: next run re-reads `lookback` before here, so
                // only uids that can reappear in that overlap are kept.
                obj.insert("watermark".into(), json!(end));
                obj.remove("resume");
                seen.retain(|_, t| *t >= end - lookback);
            } else {
                obj.insert("resume".into(), json!(end));
            }
            sync_seen(&mut wstate, &seen);
            self.commit(seq, &state, Some(&wstate)).await?;
        }
    }
}

/// NAN-3490: the window part of the checkpoint a tenant reset writes for a
/// time-window stream (the reset passes the point-forward anchor, now − 5
/// min, NAN-3697, and adds a `point_forward` record):
/// the next pass starts at `since` (the `resume` window start) with the
/// stream's `initial_state` and no remembered uids, exactly as if a crash had
/// interrupted a pass there. [`Run::run_sequence`] is the only reader; keep
/// the two together.
pub fn window_rewind_checkpoint(since: DateTime<Utc>) -> Value {
    json!({ "window": { "resume": since.timestamp_millis() } })
}

/// Field every emitted collector event carries: the vendor's event identity.
pub const INGEST_ID_FIELD: &str = "_nano_ingest_id";

/// `_nano_ingest_id` for one event: the `fields` values joined with `:`, or
/// `h:<sha256 of the event JSON>` when there are none or one is missing. The
/// fallback is stable across re-reads of identical content. A non-object
/// event is wrapped as `{message, _nano_ingest_id}`; an existing value is
/// overwritten (the engine owns the field).
pub fn stamp_ingest_id(event: &Value, fields: &[String]) -> Value {
    let mut parts = Vec::with_capacity(fields.len());
    for f in fields {
        match paging::get_path(event, f).filter(|v| !v.is_null()).map(template::value_to_string) {
            Some(s) if !s.is_empty() => parts.push(s),
            _ => {
                parts.clear();
                break;
            }
        }
    }
    let id = if parts.is_empty() {
        let mut body = event.clone();
        if let Some(o) = body.as_object_mut() {
            o.remove(INGEST_ID_FIELD);
        }
        let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, body.to_string().as_bytes());
        format!("h:{}", hex::encode(d.as_ref()))
    } else {
        parts.join(":")
    };
    match event {
        Value::Object(m) => {
            let mut m = m.clone();
            m.insert(INGEST_ID_FIELD.into(), Value::String(id));
            Value::Object(m)
        }
        other => json!({ "message": other, INGEST_ID_FIELD: id }),
    }
}

fn w_max_restarts(s: &Stream) -> u32 {
    s.restart_window_on.as_ref().map(|r| r.max_restarts).unwrap_or(0)
}

fn sync_seen<'a>(wstate: &'a mut Value, seen: &BTreeMap<String, i64>) -> &'a Value {
    if !wstate.is_object() {
        *wstate = json!({});
    }
    wstate
        .as_object_mut()
        .expect("object")
        .insert("seen".into(), Value::Object(seen.iter().map(|(k, t)| (k.clone(), json!(t))).collect()));
    wstate
}

/// Collects events in memory (enrichments, preview, tests).
#[derive(Default)]
pub struct MemorySink {
    pub batches: StdMutex<Vec<(String, Vec<Value>)>>,
}

#[async_trait::async_trait]
impl Sink for MemorySink {
    async fn push(&self, source_type: &str, events: &[Value]) -> Result<(), String> {
        self.batches.lock().expect("sink").push((source_type.to_string(), events.to_vec()));
        Ok(())
    }
}

impl MemorySink {
    pub fn events(&self) -> Vec<Value> {
        self.batches.lock().expect("sink").iter().flat_map(|(_, e)| e.clone()).collect()
    }
}

#[derive(Default)]
pub struct MemoryStore {
    pub saves: StdMutex<Vec<(String, Value)>>,
}

#[async_trait::async_trait]
impl CheckpointStore for MemoryStore {
    async fn save(&self, stream: &str, state: &Value) -> Result<(), String> {
        self.saves.lock().expect("store").push((stream.to_string(), state.clone()));
        Ok(())
    }
}

/// Run a connector once.
pub async fn run(
    cfg: &EngineConfig,
    spec: &ConnectorSpec,
    input: RunInput,
    sink: Arc<dyn Sink>,
    store: Arc<dyn CheckpointStore>,
) -> Result<RunOutput, EngineError> {
    let compiled = compile(spec, &cfg.ceilings)?;
    let config = Value::Object(input.config.clone());
    let base_scope = Scope { config: config.clone(), ..Default::default() };
    // The platform broker host is never a vendor: a spec that allowlists it
    // is still refused when it targets it.
    let broker_deny = EgressDeny { hosts: cfg.pull_broker.iter().map(|b| b.host().to_string()).collect(), cidrs: vec![] };
    let hosts = HostPolicy::compile(&spec.allow, &base_scope)?
        .with_deny(cfg.platform_deny.merged(&input.egress_deny).merged(&broker_deny))?;
    for t in compiled.auth.token_endpoints() {
        // Token URLs may template `config.*` (an Entra directory id, an Okta
        // domain); the plugin renders the same template at fetch time.
        let t = template::render_str(&t, &base_scope).map_err(|e| PolicyError::BadUrl(e.to_string()))?;
        hosts.check(&url::Url::parse(&t).map_err(|e| PolicyError::BadUrl(e.to_string()))?)?;
    }
    for c in compiled.auth.credential_fields() {
        input.credentials.get(&c)?;
    }
    // The platform broker identity is built only for a hosted run whose spec
    // uses it (a broker configured on the runner, a tenant on the run, the
    // `google_dwd_broker` plugin). Its policy carries the platform deny list
    // only: a tenant's own deny list governs its vendors, not the platform.
    // Any failure here leaves the broker unset, so only this plugin fails
    // (`google_dwd_broker_unconfigured`); no other run is affected.
    let pull_broker = match (&cfg.pull_broker, &input.tenant) {
        (Some(b), Some(t)) if matches!(spec.auth.kind.as_str(), "google_dwd_broker" | "entra_fic_broker" | "okta_broker_jwt") => {
            match (b.caller_token(t), crate::pull_broker::PlatformBroker::object_header(t), b.host_policy(cfg.platform_deny.clone())) {
                (Ok(token), Ok(object), Ok(hosts)) => Some(PullBrokerCall {
                    endpoint: b.endpoint().clone(),
                    graph_endpoint: b.graph_token_endpoint(),
                    okta_endpoint: b.okta_assertion_endpoint(),
                    hosts,
                    token,
                    object,
                }),
                (_, _, Err(e)) => {
                    tracing::warn!(target: "nano_connector::audit", error = %e, "platform pull broker is denied by the platform egress policy for this run");
                    None
                }
                _ => None,
            }
        }
        _ => None,
    };
    let transport: Arc<dyn Transport> = match &cfg.transport {
        Some(t) => t.clone(),
        None => {
            let identity = compiled.auth.client_identity(&input.credentials)?;
            Arc::new(Broker::new(cfg.broker.clone(), identity)?)
        }
    };
    let artifact = input.artifact.clone();
    let memory = Arc::new(MemorySink::default());
    // Every VRL stream gets its sandboxed worker before the first request,
    // so a program that does not compile fails the run before any egress.
    let tenant = input.tenant.clone().unwrap_or_else(|| "default".into());
    let programs: Vec<(&str, &str)> = compiled
        .spec
        .streams
        .iter()
        .filter(|s| input.enabled_streams.as_ref().is_none_or(|en| en.contains(&s.id)))
        .filter_map(|s| s.program.as_deref().map(|p| (s.id.as_str(), p)))
        .collect();
    let mut workers = HashMap::new();
    let mut sandbox = Vec::new();
    let slots = if programs.is_empty() {
        None
    } else {
        if programs.len() > cfg.vrl_pool.max_per_tenant() {
            return Err(EngineError::Spec(format!(
                "{} VRL streams exceed the {} VRL workers a run may hold",
                programs.len(),
                cfg.vrl_pool.max_per_tenant()
            )));
        }
        let slots = cfg.vrl_pool.reserve(&tenant, programs.len()).await?;
        for (id, p) in &programs {
            let w = cfg
                .vrl_pool
                .spawn_reserved(&slots, p, worker_limits(&compiled.limits, cfg.worker_address_space))
                .await
                .map_err(|e| program_error(id, e))?;
            sandbox.push((id.to_string(), w.report.clone()));
            workers.insert(id.to_string(), Mutex::new(PooledWorker::new(w)));
        }
        Some(slots)
    };
    let run = Arc::new(Run {
        input: match &artifact {
            Some((a, t)) => {
                let mut m = input.artifact_extra.clone();
                m.insert("artifact".into(), Value::String(a.clone()));
                m.insert("artifact_type".into(), Value::String(t.clone()));
                Value::Object(m)
            }
            None => Value::Null,
        },
        compiled,
        transport,
        hosts,
        creds: input.credentials.clone(),
        config,
        clock: cfg.clock.clone(),
        sink: if matches!(spec.kind, Kind::Collector | Kind::Identity) { sink.clone() } else { memory.clone() },
        store,
        requests: AtomicU32::new(0),
        pages: AtomicU32::new(0),
        events: AtomicU64::new(0),
        event_bytes: AtomicU64::new(0),
        dropped: AtomicU64::new(0),
        narrowed: AtomicU32::new(0),
        restarts: AtomicU32::new(0),
        last_request: Mutex::new(None),
        workers,
        _vrl_slots: slots,
        checkpoints: StdMutex::new(HashMap::new()),
        secret_cache: StdMutex::new(None),
        feed_id: input.feed_id.clone(),
        pull_broker,
        started: (cfg.clock)(),
        identity_modes: StdMutex::new(Vec::new()),
    });
    let limit = run.compiled.limits.max_run_secs;

    let body = {
        let run = run.clone();
        let input = &input;
        async move {
            if run.compiled.spec.kind == Kind::Identity {
                return run_identity(&run, input).await;
            }
            for s in &run.compiled.spec.streams {
                if let Some(en) = &input.enabled_streams {
                    if !en.contains(&s.id) {
                        continue;
                    }
                }
                run_stream(&run, s, input.checkpoints.get(&s.id).cloned().unwrap_or_else(|| json!({}))).await?;
            }
            Ok::<_, EngineError>(())
        }
    };
    let outcome = match tokio::time::timeout(Duration::from_secs(limit), body).await {
        Ok(r) => r,
        Err(_) => Err(EngineError::WallClock(limit)),
    };
    if outcome.is_err() {
        if let Some(t) = run.sink.identity() {
            // Best effort: staged runs that will never be committed (the
            // coordinator also expires them after 6 h).
            let _ = tokio::time::timeout(Duration::from_secs(15), t.abort()).await;
        }
    }
    if let Err(e) = outcome {
        // Last line of defense for error text: whatever path produced it,
        // no secret shape leaves the engine in an error message.
        let set = run.secrets();
        let msg = e.to_string();
        return Err(if set.contains_str(&msg) { EngineError::Scrubbed(set.redact_str(&msg)) } else { e });
    }

    let mut out = RunOutput {
        events: run.events.load(Ordering::SeqCst),
        requests: run.requests.load(Ordering::SeqCst),
        pages: run.pages.load(Ordering::SeqCst),
        dropped_duplicates: run.dropped.load(Ordering::SeqCst),
        windows_narrowed: run.narrowed.load(Ordering::SeqCst),
        window_restarts: run.restarts.load(Ordering::SeqCst),
        checkpoints: run.checkpoints.lock().expect("checkpoints").clone(),
        result: None,
        sandbox,
        identity_modes: run.identity_modes.lock().expect("identity modes").clone(),
    };
    if !matches!(spec.kind, Kind::Collector | Kind::Identity) {
        let events = memory.events();
        out.result = Some(match spec.kind {
            Kind::AgentEnrichment => events.into_iter().next().unwrap_or(Value::Null),
            _ => {
                let wm = out
                    .checkpoints
                    .values()
                    .next()
                    .and_then(|c| c.pointer("/state/watermark").cloned())
                    .unwrap_or(Value::Null);
                json!({ "records": events, "watermark": wm })
            }
        });
    }
    Ok(out)
}

async fn run_stream(run: &Arc<Run>, s: &Stream, saved: Value) -> Result<(), EngineError> {
    let stepper = paging::build(&s.pagination.kind, &s.pagination.params).map_err(EngineError::Spec)?;
    let worker = match &s.program {
        Some(_) => Some(run.workers.get(&s.id).ok_or_else(|| EngineError::Spec(format!("stream `{}` has no VRL worker", s.id)))?),
        None => None,
    };
    let shared = Mutex::new(if saved.is_object() { saved.clone() } else { json!({}) });
    let source_type_tpl = s.source_type.clone().unwrap_or_else(|| s.id.clone());

    let Some(f) = &s.fanout else {
        let seq = Seq {
            stream: s,
            stepper: stepper.as_ref(),
            worker,
            item: Value::Null,
            item_key: None,
            source_type: source_type_tpl,
            shared: &shared,
            identity: membership_seq(s),
            point_forward: seq_point_forward(run, &saved, membership_seq(s).is_some()),
        };
        return run.run_sequence(&seq, saved).await;
    };

    let items = discover(run, f, membership_seq(s).is_some()).await?;
    let sem = tokio::sync::Semaphore::new(f.concurrency.clamp(1, 16) as usize);
    let tasks = items.into_iter().map(|item| {
        let key = paging::get_path(&item, &f.item_key).map(template::value_to_string).unwrap_or_default();
        let scope = run.scope(&json!({}), &item, &Value::Null);
        let st = template::render_str(&source_type_tpl, &scope);
        let saved_item = saved.pointer(&format!("/items/{}", key.replace('~', "~0").replace('/', "~1"))).cloned().unwrap_or_else(|| json!({}));
        let (sem, stepper, shared) = (&sem, stepper.as_ref(), &shared);
        async move {
            let _permit = sem.acquire().await.map_err(|e| EngineError::Spec(e.to_string()))?;
            let point_forward = seq_point_forward(run, &saved_item, membership_seq(s).is_some());
            let seq = Seq { stream: s, stepper, worker, item, item_key: Some(key), source_type: st?, shared, identity: membership_seq(s), point_forward };
            run.run_sequence(&seq, saved_item).await
        }
    });
    let results = futures_join_all(tasks).await;
    results.into_iter().collect::<Result<Vec<_>, _>>()?;
    Ok(())
}

/// Memberships streams always run full; other streams have no identity.
fn membership_seq(s: &Stream) -> Option<(IdentityRole, IdentityMode)> {
    s.identity.as_ref().filter(|i| i.role == IdentityRole::Memberships).map(|_| (IdentityRole::Memberships, IdentityMode::Full))
}

/// Checkpoint key of the last completed full run of an identity users stream.
pub const IDENTITY_LAST_FULL_AT: &str = "identity_last_full_at";
/// Checkpoint key of the user count that run committed (the shrink guard).
pub const IDENTITY_LAST_FULL_ROWS: &str = "identity_last_full_rows";

/// A `kind: identity` run: every users stream (full or delta), then every
/// memberships stream (always full), then the memberships sub-feed commit.
async fn run_identity(run: &Arc<Run>, input: &RunInput) -> Result<(), EngineError> {
    let enabled = |s: &&Stream| input.enabled_streams.as_ref().is_none_or(|en| en.contains(&s.id));
    let role = |s: &Stream| s.identity.as_ref().map(|i| i.role);
    let streams = &run.compiled.spec.streams;
    for s in streams.iter().filter(enabled).filter(|s| role(s) == Some(IdentityRole::Users)) {
        let allow_shrink = input.config.get(crate::identity::ALLOW_SHRINK_CONFIG).and_then(Value::as_bool).unwrap_or(false);
        run_identity_users(run, s, input.checkpoints.get(&s.id).cloned().unwrap_or_else(|| json!({})), allow_shrink).await?;
    }
    let mut memberships = false;
    for s in streams.iter().filter(enabled).filter(|s| role(s) == Some(IdentityRole::Memberships)) {
        memberships = true;
        // Always full: the saved checkpoint is never read.
        run_stream(run, s, json!({})).await?;
    }
    if memberships {
        if let Some(t) = run.sink.identity() {
            t.memberships_finish().await.map_err(EngineError::Sink)?;
        }
    }
    Ok(())
}

/// One identity users stream. Mode: `full` when the stream is full-only,
/// there is no saved cursor, the last full run is older than
/// `identity.full_every_secs`, or the program answers `restart_full`;
/// `delta` otherwise. A full run's checkpoint (cursor + last full time) is
/// saved only after the coordinator committed the snapshot; a delta run
/// saves one per page after the coordinator acknowledged its rows.
async fn run_identity_users(run: &Arc<Run>, s: &Stream, saved: Value, allow_shrink: bool) -> Result<(), EngineError> {
    let stepper = paging::build(&s.pagination.kind, &s.pagination.params).map_err(EngineError::Spec)?;
    let worker = match &s.program {
        Some(_) => Some(run.workers.get(&s.id).ok_or_else(|| EngineError::Spec(format!("stream `{}` has no VRL worker", s.id)))?),
        None => None,
    };
    let full_every = run.compiled.spec.identity.as_ref().map(|c| c.full_every_secs).unwrap_or(86_400);
    let last_full = saved
        .get(IDENTITY_LAST_FULL_AT)
        .and_then(Value::as_str)
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&Utc));
    let sink = run.sink.identity();
    let wants_delta = s.identity.as_ref().and_then(|i| i.mode) == Some(IdentityMode::Delta);
    if wants_delta && sink.is_some_and(|t| !t.delta_supported()) {
        tracing::debug!(stream = %s.id, "identity delta runs need the v2 coordinator contract; running full");
    }
    let wants_delta = wants_delta && sink.is_none_or(|t| t.delta_supported());
    let guard = crate::identity::ShrinkGuard { previous_rows: saved.get(IDENTITY_LAST_FULL_ROWS).and_then(Value::as_u64), allow: allow_shrink };
    let fresh = last_full.is_some_and(|t| run.started - t < chrono::Duration::seconds(full_every as i64));
    let mut mode = if wants_delta && saved.get("state").is_some_and(Value::is_object) && fresh { IdentityMode::Delta } else { IdentityMode::Full };
    loop {
        // A delta run keeps the saved checkpoint (and its last full time)
        // and moves the cursor page by page; a full run starts over.
        let base = match mode {
            IdentityMode::Delta => saved.clone(),
            IdentityMode::Full => json!({}),
        };
        let shared = Mutex::new(base.clone());
        let seq = Seq {
            stream: s,
            stepper: stepper.as_ref(),
            worker,
            item: Value::Null,
            item_key: None,
            source_type: s.id.clone(),
            shared: &shared,
            identity: Some((IdentityRole::Users, mode)),
            point_forward: seq_point_forward(run, &base, true),
        };
        let mut state = match (mode, base.get("state")) {
            (IdentityMode::Delta, Some(st)) => st.clone(),
            _ => {
                let scope = run.scope(&json!({}), &Value::Null, &Value::Null);
                Value::Object(
                    s.initial_state.iter().map(|(k, v)| (k.clone(), template::render_json(v, &scope).unwrap_or(Value::Null))).collect(),
                )
            }
        };
        if let Some(t) = sink {
            t.users_begin(&s.id, mode, guard).await.map_err(EngineError::Sink)?;
        }
        let (mut seen, mut ws) = (BTreeMap::new(), Value::Null);
        match run.walk(&seq, &mut state, None, &mut seen, None, &mut ws).await? {
            Walk::Complete => {}
            Walk::RestartFull if mode == IdentityMode::Delta => {
                tracing::info!(target: "nano_connector::audit", stream = %s.id, "identity delta sync state is gone; rerunning the stream as a full run");
                mode = IdentityMode::Full;
                continue;
            }
            Walk::RestartFull => return Err(EngineError::ProgramShape("restart_full during a full run".into())),
            Walk::CapReached => return Err(EngineError::Cap("offset cap reached in an identity stream".into())),
            Walk::Restart => return Err(EngineError::Upstream { status: 0, body: "page token expired".into() }),
        }
        let committed = match sink {
            Some(t) => t.users_finish(&s.id, mode).await.map_err(EngineError::Sink)?,
            None => None,
        };
        run.identity_modes.lock().expect("identity modes").push((s.id.clone(), mode));
        if mode == IdentityMode::Full {
            // Committed: now (and only now) the cursor and the full-run
            // time move.
            let mut cp = json!({
                "state": state,
                IDENTITY_LAST_FULL_AT: run.started.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            });
            if let Some(rows) = committed {
                cp[IDENTITY_LAST_FULL_ROWS] = json!(rows);
            }
            run.save_checkpoint(&s.id, cp).await?;
        }
        return Ok(());
    }
}

async fn futures_join_all<F: std::future::Future>(fs: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    // Polls all futures concurrently on this task; concurrency is bounded by
    // the semaphore inside each future.
    let mut pinned: Vec<std::pin::Pin<Box<F>>> = fs.into_iter().map(Box::pin).collect();
    let mut outs: Vec<Option<F::Output>> = (0..pinned.len()).map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (i, f) in pinned.iter_mut().enumerate() {
            if outs[i].is_none() {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(o) => outs[i] = Some(o),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending { std::task::Poll::Pending } else { std::task::Poll::Ready(()) }
    })
    .await;
    outs.into_iter().map(|o| o.expect("completed")).collect()
}

async fn discover(run: &Arc<Run>, f: &crate::spec::Fanout, memberships: bool) -> Result<Vec<Value>, EngineError> {
    // Memberships: an unset `max_items` (the collector default) means the
    // identity ceiling, and discovering more items than allowed is an error
    // (a truncated group list would commit a partial snapshot).
    let max = if memberships {
        let asked = if f.max_items == crate::spec::Fanout::DEFAULT_MAX_ITEMS { MAX_IDENTITY_FANOUT_ITEMS } else { f.max_items };
        asked.min(MAX_IDENTITY_FANOUT_ITEMS) as usize
    } else {
        f.max_items.min(MAX_FANOUT_ITEMS) as usize
    };
    let over = |n: usize| -> Result<(), EngineError> {
        if memberships && n > max {
            return Err(EngineError::Cap(format!("memberships fan-out discovered more than {max} items")));
        }
        Ok(())
    };
    let items: Vec<Value> = match &f.discover {
        Discover::Static { items } => items.clone(),
        Discover::Config { key } => run
            .config
            .get(key)
            .map(template::value_to_string)
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| Value::String(s.into()))
            .collect(),
        Discover::Request { request, response, pagination } => {
            let stepper = paging::build(&pagination.kind, &pagination.params).map_err(EngineError::Spec)?;
            let mut ps = PageState::default();
            let scope = run.scope(&json!({}), &Value::Null, &Value::Null);
            let mut req = run.build_request(request, &scope, &stepper.first(&mut ps))?;
            let mut out = Vec::new();
            loop {
                if run.pages.fetch_add(1, Ordering::SeqCst) >= run.compiled.limits.max_pages {
                    return Err(EngineError::Cap("pages during discovery".into()));
                }
                let resp = run
                    .exchange(req.clone(), None, None, &scope)
                    .await?
                    .ok_or_else(|| EngineError::Upstream { status: 0, body: "discovery restarted".into() })?;
                if !(200..300).contains(&resp.status) {
                    return Err(EngineError::Upstream { status: resp.status, body: snippet(&resp.body) });
                }
                let body = parse_body(response.format, &resp.body);
                let page: Vec<Value> = match paging::get_path(&body, &response.events_path) {
                    Some(Value::Array(a)) => a.clone(),
                    _ => vec![],
                };
                let cx = PageCtx { resp: &resp, body: &body, events: &page };
                let step = stepper.next(&cx, &mut ps).map_err(EngineError::Spec)?;
                out.extend(page);
                over(out.len())?;
                // Collectors stop at the cap; memberships read on (and fail
                // above it).
                if !memberships && out.len() >= max {
                    break;
                }
                req = match step {
                    Step::Done | Step::CapReached => break,
                    Step::Url(u) => {
                        run.hosts.check(&u)?;
                        OutboundRequest { url: u, ..req }
                    }
                    Step::Query(q) => run.build_request(request, &scope, &q)?,
                };
            }
            out
        }
    };
    over(items.len())?;
    Ok(items.into_iter().take(max).collect())
}
