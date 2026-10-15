//! The connector spec: a declarative description of one API integration.
//!
//! A spec says *what* to call and *how to page*; the engine owns every socket,
//! credential, retry, cap and checkpoint. An optional VRL `program` handles the
//! parts a declaration cannot (mapping a response into events, an unusual
//! cursor), but it only ever sees `{state, response, ...}` and can only answer
//! with `{events, next_request, state}`.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Spec format version understood by this engine.
pub const SPEC_VERSION: u32 = 1;

/// One connector: an agent enrichment, a data enrichment, a collector or an
/// identity directory sync.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSpec {
    /// Must be 1.
    pub version: u32,
    /// Slug, e.g. `okta_system_log`.
    pub name: String,
    pub kind: Kind,
    /// Outbound policy. Every request, every `next_request` and every redirect
    /// hop must match one rule. Nothing else is reachable.
    pub allow: Vec<AllowRule>,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub rate_limit: RateLimit,
    /// Cron expression for the scheduler (informational in the PoC).
    #[serde(default)]
    pub schedule: Option<String>,
    /// `kind: identity` only: directory sync settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityConfig>,
    /// Collectors and identity: one entry per stream. Enrichments: exactly one.
    pub streams: Vec<Stream>,
}

/// `kind: identity` settings (NAN-3503).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// Force a full run (snapshot replace) at least this often, even for
    /// `mode: delta` users streams. Default 86400 (one day).
    #[serde(default = "default_full_every")]
    pub full_every_secs: u64,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self { full_every_secs: default_full_every() }
    }
}

fn default_full_every() -> u64 {
    86_400
}

/// What an identity stream's events are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityRole {
    /// Canonical user rows (`external_id`, `upn`, `email`, ...).
    Users,
    /// `{member, group, privileged?}` pairs, aggregated by the engine into
    /// one row per member on the `<feed>:groups` sub-feed. Always full.
    Memberships,
}

/// How a users stream syncs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMode {
    /// Every run is a complete snapshot that replaces the feed.
    #[default]
    Full,
    /// Runs after the first full one send only changes (adds, updates,
    /// `deleted: true` tombstones); a full run still happens every
    /// `identity.full_every_secs` or when the program returns
    /// `restart_full: true`.
    Delta,
}

impl IdentityMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Delta => "delta",
        }
    }
}

/// Per-stream identity role (`kind: identity` only).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamIdentity {
    pub role: IdentityRole,
    /// Users streams only; memberships are always full.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<IdentityMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Per-artifact lookup (`input.artifact`, `input.artifact_type`); the
    /// first event is the enrichment result.
    AgentEnrichment,
    /// Scheduled feed pull; events are the records, `state.watermark` the
    /// watermark.
    DataEnrichment,
    /// Streaming pull into the tenant's ingest, checkpointed per stream.
    Collector,
    /// Directory sync (users, group memberships) into the tenant's identity
    /// directory through its enrichment coordinator. No ingest, no parser.
    Identity,
}

/// One allowed destination. `host` and `host_suffix` are mutually exclusive.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AllowRule {
    /// Exact host name. May be a single `{{config.X}}` reference (for
    /// per-tenant hosts such as an Okta org); the resolved value must then
    /// also end with one of `host_suffixes`.
    #[serde(default)]
    pub host: Option<String>,
    /// Suffixes a `{{config.X}}` host must end with, e.g. `.okta.com`.
    #[serde(default)]
    pub host_suffixes: Vec<String>,
    /// Path prefixes, matched on whole segments. Default: `/` (any path).
    #[serde(default)]
    pub path_prefixes: Vec<String>,
}

/// Native authentication, resolved through the auth plugin registry
/// (`crate::auth::registry`). `type` picks the plugin; the remaining fields
/// are that plugin's parameters. Secrets are named by credential field; the
/// engine applies them to requests. Specs, templates and VRL never see them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(flatten)]
    pub params: serde_json::Map<String, serde_json::Value>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            kind: "none".into(),
            params: Default::default(),
        }
    }
}

impl JsonSchema for AuthConfig {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "AuthConfig".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        crate::auth::registry_schema()
    }
}

/// Inner page stepping, resolved through the stepper registry
/// (`crate::paging::registry`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationConfig {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(flatten)]
    pub params: serde_json::Map<String, serde_json::Value>,
}

impl Default for PaginationConfig {
    fn default() -> Self {
        Self {
            kind: "none".into(),
            params: Default::default(),
        }
    }
}

impl JsonSchema for PaginationConfig {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PaginationConfig".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        crate::paging::registry_schema()
    }
}

/// Host-enforced caps. The engine clamps every value to its own ceiling.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub max_run_secs: u64,
    pub max_pages: u32,
    pub max_requests: u32,
    pub max_events: u64,
    pub max_event_bytes: u64,
    pub max_response_bytes: u64,
    pub max_decompressed_bytes: u64,
    /// Per-invocation VRL budget (wall ms, enforced on an isolated worker).
    pub vrl_timeout_ms: u64,
    pub max_redirects: u32,
    /// Largest checkpoint (program state, window bookkeeping, seen uids)
    /// the engine will persist, in bytes of JSON.
    pub max_checkpoint_bytes: u64,
    /// `kind: identity`: most (member, group) pairs one run may aggregate.
    pub max_identity_memberships: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_run_secs: 600,
            max_pages: 500,
            max_requests: 2000,
            max_events: 1_000_000,
            max_event_bytes: 256 * 1024 * 1024,
            max_response_bytes: 32 * 1024 * 1024,
            max_decompressed_bytes: 64 * 1024 * 1024,
            vrl_timeout_ms: 2_000,
            max_redirects: 5,
            max_checkpoint_bytes: 4 * 1024 * 1024,
            max_identity_memberships: 5_000_000,
        }
    }
}

/// Engine-owned rate limiting and retry.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct RateLimit {
    /// Minimum spacing between requests across the whole run (fan-out
    /// included).
    pub min_interval_ms: u64,
    /// Retries on 429 before the run fails.
    pub max_retries_429: u32,
    /// Retries on 5xx / connection errors before the run fails.
    pub max_retries_5xx: u32,
    /// Backoff base: 5xx waits this times the attempt number; a 429 without
    /// `Retry-After` waits this doubled per attempt, capped at `max_wait_ms`.
    pub backoff_ms: u64,
    /// Longest single wait the engine will accept from the server.
    pub max_wait_ms: u64,
    /// Header holding a reset time in epoch seconds (e.g.
    /// `x-rate-limit-reset`). `retry-after` is always honored.
    #[serde(default)]
    pub reset_header: Option<String>,
    /// Header holding the remaining quota; when it drops to
    /// `remaining_floor` the engine pauses until the reset.
    #[serde(default)]
    pub remaining_header: Option<String>,
    pub remaining_floor: u64,
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            min_interval_ms: 0,
            max_retries_429: 5,
            max_retries_5xx: 3,
            backoff_ms: 5_000,
            max_wait_ms: 120_000,
            reset_header: None,
            remaining_header: None,
            remaining_floor: 0,
        }
    }
}

/// One stream of events (one `source_type` in ingest).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Stream {
    pub id: String,
    /// `X-Source-Type` for ingest. May use `{{item.X}}` under fan-out.
    #[serde(default)]
    pub source_type: Option<String>,
    /// The first request. Optional only when `program` is set: the program is
    /// then called once with `response: null` and must return the first
    /// `next_request`.
    #[serde(default)]
    pub request: Option<RequestTemplate>,
    #[serde(default)]
    pub response: ResponseSpec,
    #[serde(default)]
    pub pagination: PaginationConfig,
    /// Declarative cursor, used when there is no `program`.
    #[serde(default)]
    pub cursor: Option<CursorSpec>,
    /// Initial state for a first run (no saved checkpoint). Values are
    /// templates (`{{config.X}}`, `{{initial_cursor}}`, `{{now}}`).
    #[serde(default)]
    pub initial_state: BTreeMap<String, serde_json::Value>,
    /// Optional VRL. Input `.` is `{state, response, request, config, input,
    /// item, now}`; it must evaluate to `{events, next_request, state}` and
    /// may set `error` to fail the run with a message.
    #[serde(default)]
    pub program: Option<String>,
    /// Discover-then-collect: run this stream once per discovered item.
    #[serde(default)]
    pub fanout: Option<Fanout>,
    /// Before each request, commit this state patch (write-ahead). Needed by
    /// server-side iterators that advance when a page is *served* (Netskope):
    /// the patch records "resend" until the page is acknowledged.
    #[serde(default)]
    pub write_ahead_state: Option<serde_json::Map<String, serde_json::Value>>,
    /// Time-window stepping for APIs without a usable cursor.
    #[serde(default)]
    pub window: Option<WindowSpec>,
    /// Restart the current window (deduped by uid) when a page token expires.
    #[serde(default)]
    pub restart_window_on: Option<RestartOn>,
    /// Which event fields make up `_nano_ingest_id` (default: the window's
    /// `uid_field`). The engine stamps it on every emitted event. It is an
    /// ingest-side identity only: production Vector and the lake do not read
    /// it today, and lake dedupe keys on the parser's `metadata.uid`.
    #[serde(default)]
    pub ingest_id: Option<IngestId>,
    /// Rewrite one query parameter when a request is retried after a 5xx or a
    /// connection failure. For server-side iterators that may have advanced
    /// before the failure (Netskope: `operation=next` becomes `resend`).
    #[serde(default)]
    pub retry_rewrite: Option<RetryRewrite>,
    /// `kind: identity` only: the stream's role (`users` or `memberships`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<StreamIdentity>,
}

/// `_nano_ingest_id` = the listed dotted paths, joined with `:`. An event
/// missing any of them gets a content hash (`h:<sha256>`) instead. Include a
/// version field (`lastUpdated`) when the vendor re-serves a changed record
/// under the same id: lake dedupe keeps the FIRST row per `metadata.uid` and
/// drops later ones even when their content differs.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IngestId {
    pub fields: Vec<String>,
}

impl Stream {
    /// The fields `_nano_ingest_id` is built from: `ingest_id.fields`, else
    /// the window's `uid_field`, else none (content hash).
    pub fn ingest_id_fields(&self) -> Vec<String> {
        match (&self.ingest_id, &self.window) {
            (Some(i), _) if !i.fields.is_empty() => i.fields.clone(),
            (_, Some(w)) => vec![w.uid_field.clone()],
            _ => vec![],
        }
    }
}

/// On a retry, replace query parameter `param` when it currently equals
/// `from` with `to`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetryRewrite {
    pub param: String,
    pub from: String,
    pub to: String,
}

/// Step through `[start, end)` windows. Request templates read
/// `{{window.start}}` and `{{window.end}}`. Each window is paged with the
/// stream's `pagination`; when it completes and is acknowledged, the next
/// window starts at `end - lookback`. Events in the re-read overlap are
/// dropped by `uid_field`, so a restart or overlap never ships a duplicate.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WindowSpec {
    /// Dotted path of the event timestamp (RFC 3339, epoch s or epoch ms).
    pub time_field: String,
    /// Dotted path of the vendor's unique event id.
    pub uid_field: String,
    /// Longest window per request sequence.
    #[serde(default = "default_max_span")]
    pub max_span_secs: u64,
    /// Late-arrival lag: never query past `now - lag_secs`.
    #[serde(default)]
    pub lag_secs: u64,
    /// Re-read this much before the previous window end (late arrivals).
    #[serde(default)]
    pub lookback_secs: u64,
    /// Format of `{{window.start}}` / `{{window.end}}`.
    #[serde(default)]
    pub format: TimeFormat,
    /// Unused, kept so existing specs parse (NAN-3697). It does NOT move a
    /// new stream's first window (every stream starts at activation − the
    /// point-forward overlap) and does not bound a checkpoint reset (a reset
    /// always re-anchors at now − the overlap).
    #[serde(default = "default_initial_lookback")]
    pub initial_lookback_secs: u64,
    /// Reserved, unused (NAN-3697): no backfill. A tenant checkpoint reset
    /// always re-anchors the stream at now − the point-forward overlap
    /// (5 minutes) and this value does not widen it. Kept so specs that set
    /// it still parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_backfill_secs: Option<u64>,
    /// Cap on remembered uids (oldest dropped first).
    #[serde(default = "default_max_seen")]
    pub max_seen: usize,
}

fn default_max_span() -> u64 {
    3600
}
fn default_initial_lookback() -> u64 {
    3600
}
fn default_max_seen() -> usize {
    50_000
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimeFormat {
    #[default]
    Rfc3339,
    EpochSecs,
    EpochMillis,
}

/// Which responses mean "the page token expired".
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RestartOn {
    pub status: Vec<u16>,
    /// Optional substring the body must contain as well.
    #[serde(default)]
    pub body_contains: Option<String>,
    #[serde(default = "default_restarts")]
    pub max_restarts: u32,
}

fn default_restarts() -> u32 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestTemplate {
    #[serde(default)]
    pub method: Method,
    /// Absolute `https://` URL. Templates in the path are percent-encoded as
    /// one segment; a template may form the whole host only as
    /// `{{config.X}}`.
    pub url: String,
    /// Query parameters. Values are templates; empty results are omitted.
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    /// Static headers. Values may use `{{config.X}}` only. Auth headers and
    /// hop-by-hop headers are refused.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<Body>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    #[default]
    Get,
    Post,
}

/// Request body: set exactly one of `form` or `json`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Body {
    /// `application/x-www-form-urlencoded`; values are templates.
    #[serde(default)]
    pub form: Option<BTreeMap<String, String>>,
    /// `application/json`; string leaves are templates.
    #[serde(default)]
    pub json: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseSpec {
    #[serde(default)]
    pub format: Format,
    /// Dotted path to the event array in the body. Empty = the body itself.
    #[serde(default)]
    pub events_path: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    #[default]
    Json,
    Ndjson,
    /// Text body split into non-empty lines; each line is a string event.
    Lines,
    Text,
}

/// Declarative cursor: `state[state_key] = <reduce>(event[field])` after
/// each acknowledged page.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CursorSpec {
    pub state_key: String,
    pub field: String,
    #[serde(default)]
    pub reduce: CursorReduce,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CursorReduce {
    #[default]
    Max,
    Last,
}

/// Discover items, then run the stream once per item with bounded
/// concurrency. Each item gets its own state under `state.items[<key>]`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Fanout {
    pub discover: Discover,
    /// Dotted path in an item that identifies it (state key). Empty = the item
    /// itself (strings).
    #[serde(default)]
    pub item_key: String,
    /// Concurrent per-item pulls (clamped to 1..=16).
    #[serde(default = "default_concurrency")]
    pub concurrency: u32,
    /// Maximum items (clamped to the engine ceiling: 10k; 100k for identity
    /// memberships, where unset means 100k and more items fail the run).
    #[serde(default = "default_max_items")]
    pub max_items: u32,
}

fn default_concurrency() -> u32 {
    4
}

impl Fanout {
    pub const DEFAULT_MAX_ITEMS: u32 = 1000;
}

fn default_max_items() -> u32 {
    Fanout::DEFAULT_MAX_ITEMS
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "from", rename_all = "snake_case", deny_unknown_fields)]
pub enum Discover {
    /// A fixed list.
    Static { items: Vec<serde_json::Value> },
    /// A comma-separated config field (e.g. the enabled applications).
    Config { key: String },
    /// A list request, paged like a stream; its events are the items.
    Request {
        request: RequestTemplate,
        #[serde(default)]
        response: ResponseSpec,
        #[serde(default)]
        pagination: PaginationConfig,
    },
}

/// The VRL program's answer.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramOutput {
    #[serde(default)]
    pub events: Vec<serde_json::Value>,
    #[serde(default)]
    pub next_request: Option<NextRequest>,
    #[serde(default)]
    pub state: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    pub error: Option<String>,
    /// Ask the engine to wait before `next_request` (clamped to max_wait_ms).
    #[serde(default)]
    pub wait_ms: Option<u64>,
    /// Identity delta streams: the vendor's sync state is gone (Graph 410
    /// Gone / `syncStateNotFound`); rerun this stream as a full run now.
    #[serde(default)]
    pub restart_full: Option<bool>,
}

/// What a program may ask for next. There is deliberately no `headers`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NextRequest {
    /// Absolute URL; replaces the template URL and its query.
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub method: Option<Method>,
    /// Query parameters. Merged over the stream template's query unless `url`
    /// is set.
    #[serde(default)]
    pub query: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default)]
    pub form: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default)]
    pub json: Option<serde_json::Value>,
}

impl ConnectorSpec {
    pub fn from_yaml(text: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(text)
    }

    /// JSON schema of the spec format (for editors and AI generation).
    pub fn json_schema() -> serde_json::Value {
        serde_json::to_value(schemars::schema_for!(ConnectorSpec)).unwrap_or_default()
    }
}
