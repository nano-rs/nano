//! `kind: identity` delivery (NAN-3503): directory sync into the tenant's
//! identity directory through its lean enrichment coordinator.
//!
//! ```text
//!  users stream, full  ─► normalize ─► chunk (≤ 20k rows / 16 MiB) ─► POST …/feeds/<feed>:<stream>/runs/<run>/rows
//!                                         └─ manager not seen yet ─► spill file ─┐ (resolved at end of stream)
//!                         end of stream ─► stage the rest ─► POST …/commit {expected_rows} ─► engine saves cursor
//!  users stream, delta ─► normalize ─► POST /v1/identity/directory/deltas {patch, manager_refs} (per page) ─► engine saves cursor
//!  memberships streams ─► {member, group, privileged} ─► interned per-member groups (bounded)
//!                         end of run ─► stage `<feed>:groups` rows ─► commit
//! ```
//!
//! Memory: one chunk of rows, the run's `external_id -> manager reference`
//! map (a keyed 64-bit hash and one string per user), and the membership
//! aggregate (interned group names, a `u32` per membership). Rows whose
//! manager has not been seen yet are spilled to a private temporary file
//! (or, when no file can be created, held in memory up to 64 MiB) and
//! staged once the users stream is complete.
//!
//! Delta runs need the v2 coordinator contract ([`IdentitySinkOptions::v2_fields`]):
//! a vendor delta carries only changed users (Graph: only their changed
//! properties), so delta rows are patches (absent = unchanged) and a manager
//! outside the delta is sent by id (`manager_refs`) for the coordinator to
//! resolve against the directory. Without it users streams always run full.
//!
//! Shrink guard: a full run that would replace a users sub-feed with fewer
//! than half the users of the previous full run fails before the commit,
//! unless the feed config sets `identity_allow_shrink: true`.
//!
//! Tenant guard: the [`CoordinatorClient`] is built only from the claimed
//! feed's tenant id (the store's inventory, never a spec, config or event)
//! through the server-owned assignments map; every request body carries
//! that tenant id, the coordinator refuses a mismatch, and every answer must
//! name it back.

use std::collections::{BTreeSet, HashMap};
use std::hash::{BuildHasher, RandomState};
use std::io::{BufRead, BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use nanosiem_core::enrichment::lean_assignments::{LeanAssignmentLookup, LeanAssignmentSource, LeanAssignments};
use nanosiem_core::lake_http::LakeRequestBuilderExt;
use serde_json::{Map, Value, json};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::engine::Sink;
use crate::spec::IdentityMode;

/// The memberships sub-feed suffix (`<feed>:groups`).
pub const GROUPS_SUBFEED: &str = "groups";
/// The users stream id, and so the users sub-feed `<feed>:users`.
pub const USERS_SUBFEED: &str = "users";
/// Rows per staged chunk (the coordinator caps a chunk at 100k rows and a
/// run at 256 chunks).
pub const CHUNK_ROWS: usize = 20_000;
/// JSON bytes per staged chunk or delta (the coordinator accepts 64 MiB).
pub const CHUNK_BYTES: usize = 16 << 20;
/// Groups kept per member (the coordinator refuses more).
pub const MAX_GROUPS_PER_MEMBER: usize = 4096;
/// Text bytes per field (the coordinator refuses more).
const MAX_TEXT: usize = 4096;
/// Spilled rows held in memory when no spill file can be created.
const MAX_SPILL_MEMORY: usize = 64 << 20;
/// Floor of the commit / patch-delta request timeout.
const SLOW_TIMEOUT_FLOOR: Duration = Duration::from_secs(600);
/// Spill files carry this prefix (swept at runner startup).
const SPILL_PREFIX: &str = "nano-identity-";
/// In the shared temp dir only files this old are swept (another process
/// may own a fresh one); a dedicated spill dir is swept entirely.
const SHARED_TEMP_SWEEP_AGE: Duration = Duration::from_secs(24 * 3600);

/// Free-text columns of the coordinator's `IdentityRow`, copied as strings.
const TEXT_FIELDS: &[&str] = &[
    "username", "upn", "email", "display_name", "first_name", "last_name", "department", "title", "manager_upn",
    "manager_display_name", "company", "office_location", "city", "country", "phone", "employee_id", "employee_type",
];
/// Boolean columns.
const BOOL_FIELDS: &[&str] = &["account_enabled", "mfa_enabled", "deleted"];
/// Time columns: RFC 3339 or epoch in, epoch milliseconds out.
const TIME_FIELDS: &[&str] = &["last_sign_in_at", "created_in_directory_at"];

/// Engine-facing delivery of identity streams. Calls arrive in order: per
/// users stream `users_begin`, its pages, `users_finish`; then membership
/// pages (possibly concurrent, from fan-out), then `memberships_finish`.
/// `abort` may come at any point after a failure.
#[async_trait::async_trait]
pub trait IdentityTarget: Send + Sync {
    /// Whether delta runs are safe (patch deltas with manager references).
    /// `false`: the engine runs every users stream full.
    fn delta_supported(&self) -> bool {
        true
    }
    /// `guard`: the shrink guard for a full run.
    async fn users_begin(&self, stream: &str, mode: IdentityMode, guard: ShrinkGuard) -> Result<(), String>;
    /// One acknowledged page of canonical user rows. Returns once the rows
    /// are durable at the coordinator (delta) or buffered / staged (full).
    async fn users_page(&self, stream: &str, mode: IdentityMode, rows: &[Value]) -> Result<(), String>;
    /// Full: stage what is left and commit the snapshot (only then may the
    /// engine save the cursor); returns the committed row count. Delta:
    /// nothing (`None`).
    async fn users_finish(&self, stream: &str, mode: IdentityMode) -> Result<Option<u64>, String>;
    async fn memberships_page(&self, stream: &str, events: &[Value]) -> Result<(), String>;
    /// Stage and commit the `<feed>:groups` sub-feed.
    async fn memberships_finish(&self) -> Result<(), String>;
    /// Abandon every staged, uncommitted run (best effort).
    async fn abort(&self);
}

/// A full run's shrink guard: the previous full run's user count (from
/// the checkpoint) and whether the feed config allows a large drop.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShrinkGuard {
    pub previous_rows: Option<u64>,
    pub allow: bool,
}

/// Feed config key that lets a full run drop more than half the users.
pub const ALLOW_SHRINK_CONFIG: &str = "identity_allow_shrink";

impl ShrinkGuard {
    /// `Err` when `rows` is less than half of the previous full run.
    fn check(&self, stream: &str, rows: u64) -> Result<(), String> {
        let Some(previous) = self.previous_rows else { return Ok(()) };
        if self.allow || rows.saturating_mul(2) >= previous {
            return Ok(());
        }
        tracing::error!(
            target: "nano_connector::audit",
            stream, previous_rows = previous, rows,
            "identity full run would drop more than half the directory; refused (set feed config `{ALLOW_SHRINK_CONFIG}: true` if intended)"
        );
        Err(format!(
            "identity_shrink_refused: the full run of `{stream}` found {rows} users, less than half of the previous {previous}; the directory was left unchanged (set feed config `{ALLOW_SHRINK_CONFIG}: true` if this is intended)"
        ))
    }
}

// ------------------------------------------------------------ coordinator

/// The tenant coordinator's identity routes, for one tenant.
pub struct CoordinatorClient {
    http: reqwest::Client,
    /// Per-request timeout of commits and patch deltas (a 500k-user commit
    /// merges and uploads the directory): `max(4 x timeout, 10 min)`.
    slow_timeout: Duration,
    base: url::Url,
    tenant: Uuid,
    token: zeroize::Zeroizing<String>,
}

impl std::fmt::Debug for CoordinatorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoordinatorClient").field("base", &self.base.as_str()).field("tenant", &self.tenant).field("token", &"[REDACTED]").finish()
    }
}

/// An `http(s)` origin with no credentials, query, fragment or path.
fn coordinator_origin(raw: &str) -> Result<url::Url, String> {
    let mut url = url::Url::parse(raw.trim()).map_err(|_| "the coordinator endpoint is not a URL".to_string())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err("the coordinator endpoint must be an http(s) origin without credentials, query, fragment or path".into());
    }
    url.set_path("");
    Ok(url)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// 200 with a JSON body naming the tenant.
    Json,
    /// 204 (or 200).
    NoContent,
    /// [`Expect::Json`], or 404 (nothing there to remove).
    JsonOrNotFound,
}

impl CoordinatorClient {
    /// A client for `tenant` from explicit settings (tests, tooling). The
    /// token must be at least 32 characters.
    pub fn new(endpoint: &str, tenant: Uuid, token: &str, timeout: Duration) -> Result<Self, String> {
        if tenant.is_nil() {
            return Err("identity coordinator: nil tenant".into());
        }
        let base = coordinator_origin(endpoint)?;
        let token = zeroize::Zeroizing::new(token.trim().to_string());
        if token.len() < 32 {
            return Err("identity coordinator: the coordinator token is too short".into());
        }
        // Platform traffic to the assignment's validated internal endpoint:
        // not the vendor egress broker or its deny list (the coordinators
        // live in the cluster's private range), no proxy, no redirects.
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("identity coordinator client: {e}"))?;
        Ok(Self { http, slow_timeout: (timeout * 4).max(SLOW_TIMEOUT_FLOOR), base, tenant, token })
    }

    /// This tenant's client from the live assignments map (the
    /// `NANO_LAKE_LEAN_ENRICHMENT_ASSIGNMENTS_FILE` source the API uses).
    pub fn for_tenant(source: &LeanAssignmentSource, tenant: Uuid) -> Result<Self, String> {
        let map = source.current().map_err(|e| format!("identity coordinator: {e}"))?;
        Self::from_assignments(&map, tenant)
    }

    /// This tenant's client from a parsed map, with the guards of
    /// `EnrichmentLakeClient::from_lean_assignments`: only this tenant's own
    /// entry, which may not alias another tenant's endpoint or credential
    /// file; the token is read now.
    pub fn from_assignments(assignments: &LeanAssignments, tenant: Uuid) -> Result<Self, String> {
        let invalid = || "identity coordinator: this tenant's lean coordinator assignment is invalid".to_string();
        let a = match assignments.get(tenant) {
            LeanAssignmentLookup::Assigned(a) => a,
            LeanAssignmentLookup::NotAssigned => {
                return Err("identity_coordinator_unassigned: this tenant has no lean enrichment coordinator; identity feeds run only on lean tenants".into());
            }
            LeanAssignmentLookup::Invalid => return Err(invalid()),
        };
        let base = coordinator_origin(&a.internal_endpoint).map_err(|_| invalid())?;
        let own = std::fs::canonicalize(&a.credential_file).ok();
        if assignments.others(tenant).any(|o| {
            o.internal_endpoint == a.internal_endpoint
                || coordinator_origin(&o.internal_endpoint).is_ok_and(|other| other == base)
                || o.credential_file == a.credential_file
                || own.as_ref().is_some_and(|own| std::fs::canonicalize(&o.credential_file).is_ok_and(|other| other == *own))
        }) {
            return Err(invalid());
        }
        let token = zeroize::Zeroizing::new(
            std::fs::read_to_string(&a.credential_file).map_err(|e| format!("identity coordinator: credential unreadable ({})", e.kind()))?,
        );
        Self::new(base.as_str(), tenant, &token, Duration::from_secs(a.timeout_secs))
    }

    pub fn tenant(&self) -> Uuid {
        self.tenant
    }

    /// The coordinator host (denied to the vendor side of a run).
    pub fn host(&self) -> Option<String> {
        self.base.host_str().map(|h| h.trim_end_matches('.').to_ascii_lowercase())
    }

    async fn call(&self, method: reqwest::Method, segments: &[&str], mut body: Map<String, Value>, expect: Expect, slow: bool) -> Result<Value, String> {
        body.insert("tenant_id".into(), json!(self.tenant.hyphenated().to_string()));
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| "identity coordinator URL cannot take a path".to_string())?
            .extend(["v1", "identity", "directory"])
            .extend(segments);
        let path = url.path().to_string();
        let mut req = self.http.request(method, url);
        if slow {
            req = req.timeout(self.slow_timeout);
        }
        let resp = req
            .bearer_auth(self.token.as_str())
            .json(&body)
            .send_idempotent_with_recovery()
            .await
            .map_err(|e| format!("identity coordinator {path}: {}", e.without_url()))?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| format!("identity coordinator {path}: {}", e.without_url()))?;
        let ok = match expect {
            Expect::Json => status == reqwest::StatusCode::OK,
            Expect::NoContent => status.is_success(),
            Expect::JsonOrNotFound => status == reqwest::StatusCode::OK || status == reqwest::StatusCode::NOT_FOUND,
        };
        if !ok {
            let msg = serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_else(|| String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).into_owned());
            return Err(format!("identity coordinator {path} answered HTTP {}: {msg}", status.as_u16()));
        }
        if expect == Expect::NoContent || status == reqwest::StatusCode::NOT_FOUND {
            return Ok(Value::Null);
        }
        let v: Value = serde_json::from_slice(&bytes).map_err(|e| format!("identity coordinator {path}: invalid answer ({e})"))?;
        if v.get("tenant_id").and_then(Value::as_str) != Some(self.tenant.hyphenated().to_string().as_str()) {
            return Err(format!("identity coordinator {path} answered for another tenant"));
        }
        Ok(v)
    }

    /// Stage chunk `chunk` of run `run` of sub-feed `feed`.
    pub async fn stage(&self, feed: &str, run: &str, chunk: u32, rows: Vec<Value>) -> Result<(), String> {
        let mut body = Map::new();
        body.insert("chunk".into(), json!(chunk));
        body.insert("rows".into(), Value::Array(rows));
        let v = self.call(reqwest::Method::POST, &["feeds", feed, "runs", run, "rows"], body, Expect::Json, false).await?;
        if v.get("feed_id").and_then(Value::as_str) != Some(feed) {
            return Err("identity coordinator staged a different feed".into());
        }
        Ok(())
    }

    /// Replace sub-feed `feed` with run `run`'s staged rows. Idempotent at
    /// the coordinator: a retry after a lost answer is a 200 again.
    /// `allow_empty`: an empty snapshot (`expected_rows` 0, nothing staged)
    /// that empties the sub-feed; the coordinator refuses zero rows without it.
    pub async fn commit(&self, feed: &str, run: &str, expected_rows: u64, allow_empty: bool) -> Result<(), String> {
        let mut body = Map::new();
        body.insert("expected_rows".into(), json!(expected_rows));
        if allow_empty {
            body.insert("allow_empty".into(), json!(true));
        }
        self.call(reqwest::Method::POST, &["feeds", feed, "runs", run, "commit"], body, Expect::Json, true).await.map(|_| ())
    }

    /// One delta (adds, updates, tombstones). `patch`: the v2 contract,
    /// where an absent field keeps the current value and `manager_refs`
    /// (`{feed_id, external_id, manager_external_id}`) are resolved by the
    /// coordinator.
    pub async fn deltas(&self, rows: Vec<Value>, patch: bool, manager_refs: Vec<Value>) -> Result<(), String> {
        let mut body = Map::new();
        body.insert("rows".into(), Value::Array(rows));
        if patch {
            body.insert("patch".into(), json!(true));
            body.insert("manager_refs".into(), Value::Array(manager_refs));
        }
        self.call(reqwest::Method::POST, &["deltas"], body, Expect::Json, patch).await.map(|_| ())
    }

    /// Remove every row of sub-feed `feed` (`<feed uuid>:users|groups`, an
    /// uninstalled feed). Idempotent: a feed (or directory) with nothing to
    /// remove answers 404, which is success here.
    pub async fn delete_feed(&self, feed: &str) -> Result<(), String> {
        self.call(reqwest::Method::DELETE, &["feeds", feed], Map::new(), Expect::JsonOrNotFound, true).await.map(|_| ())
    }

    /// Abandon a staged run.
    pub async fn abort(&self, feed: &str, run: &str) -> Result<(), String> {
        self.call(reqwest::Method::DELETE, &["feeds", feed, "runs", run], Map::new(), Expect::NoContent, false).await.map(|_| ())
    }

}


// ------------------------------------------------------------ dedicated (NAN-3767)

/// The Vector record kind of a directory-sync envelope (Vector routes it to
/// `enrichment_identity_envelope`, then the `lake_identity_directory` sink).
pub const VECTOR_IDENTITY_KIND: &str = "identity_directory";

/// The deployment's Vector enrichment ingress (`:8090`, `X-Source-Type:
/// nano_enrich`): where a dedicated runner sends staged rows and deltas, so
/// identity takes the same ingest path as every other record. Vector answers
/// a request only once the coordinator acknowledged every line (end-to-end
/// acknowledgements, memory-buffered sink), so a 2xx means the rows are
/// staged or applied.
pub struct VectorEnrichment {
    http: reqwest::Client,
    url: url::Url,
    token: zeroize::Zeroizing<String>,
}

impl std::fmt::Debug for VectorEnrichment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VectorEnrichment").field("url", &self.url.as_str()).field("token", &"[REDACTED]").finish()
    }
}

impl VectorEnrichment {
    /// `url`: an http(s) URL without credentials, query or fragment.
    pub fn new(url: &str, token: &str, timeout: Duration) -> Result<Self, String> {
        let url = url::Url::parse(url.trim()).map_err(|_| "the Vector enrichment URL is not a URL".to_string())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("the Vector enrichment URL must be http(s) without credentials, query or fragment".into());
        }
        let token = zeroize::Zeroizing::new(token.trim().to_string());
        if token.is_empty() {
            return Err("the Vector enrichment ingress needs its ingest token (VECTOR_AUTH_TOKEN)".into());
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("Vector enrichment client: {e}"))?;
        Ok(Self { http, url, token })
    }

    pub fn host(&self) -> Option<String> {
        self.url.host_str().map(|h| h.trim_end_matches('.').to_ascii_lowercase())
    }

    /// One NDJSON request of `kind: identity_directory` envelopes.
    async fn post(&self, lines: Vec<Value>) -> Result<(), String> {
        let mut body = Vec::new();
        for mut line in lines {
            if let Value::Object(o) = &mut line {
                o.insert("kind".into(), json!(VECTOR_IDENTITY_KIND));
            }
            serde_json::to_writer(&mut body, &line).map_err(|e| format!("identity line: {e}"))?;
            body.push(b'\n');
        }
        let resp = self
            .http
            .post(self.url.clone())
            .bearer_auth(self.token.as_str())
            .header("X-Source-Type", "nano_enrich")
            .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
            .body(body)
            .send()
            .await
            .map_err(|e| format!("Vector enrichment ingress: {}", e.without_url()))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let bytes = resp.bytes().await.unwrap_or_default();
        Err(format!(
            "Vector enrichment ingress answered HTTP {}: {} (the identity rows were not delivered to the directory)",
            status.as_u16(),
            String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).trim()
        ))
    }
}

/// A dedicated (single-tenant, trusted-local) deployment's identity path:
/// its own lean enrichment coordinator for control calls (commit, abort,
/// feed delete) and its Vector enrichment ingress for the rows. Feeds are
/// stored under the compatibility tenant; the coordinator serves the lake
/// tenant, so the claim's tenant is mapped here and nowhere else.
#[derive(Debug)]
pub struct LocalIdentity {
    /// The only claimed tenant this deployment serves.
    pub claim_tenant: Uuid,
    /// The coordinator's tenant (`NANO_LAKE_TENANT_ID`).
    pub lake_tenant: Uuid,
    pub coordinator_url: String,
    /// Read at every client build, so a rotated token is picked up.
    pub coordinator_token_file: PathBuf,
    pub timeout: Duration,
    pub vector: std::sync::Arc<VectorEnrichment>,
}

impl LocalIdentity {
    /// The coordinator client for a claimed feed of `claim_tenant`.
    pub fn client(&self, claim_tenant: Uuid) -> Result<CoordinatorClient, String> {
        if claim_tenant != self.claim_tenant {
            return Err("identity_coordinator_unassigned: this dedicated runner serves only its own deployment's feeds".into());
        }
        let token = zeroize::Zeroizing::new(
            std::fs::read_to_string(&self.coordinator_token_file)
                .map_err(|e| format!("identity coordinator: credential unreadable ({})", e.kind()))?,
        );
        CoordinatorClient::new(&self.coordinator_url, self.lake_tenant, &token, self.timeout)
    }
}

// ------------------------------------------------------------ the sink

/// Sink behavior switches.
#[derive(Debug, Clone)]
pub struct IdentitySinkOptions {
    /// The coordinator's v2 identity contract (NAN-3503 #6294, #6302): send
    /// `is_admin`, pass `deprovisioned`, `locked` and `staged` through as
    /// account statuses, and run delta users streams as patch deltas with
    /// `manager_refs`. Off until every cell's coordinator accepts them
    /// (`IdentityRow` refuses unknown fields and values): `is_admin` is
    /// omitted, those statuses map to `disabled`, `suspended`, `unknown`,
    /// and users streams always run full (a whole-row delta would erase
    /// fields the vendor did not resend, managers among them).
    pub v2_fields: bool,
    /// Where pending-manager rows spill (`CONNECTOR_IDENTITY_SPILL_DIR`;
    /// default: the system temp dir).
    pub spill_dir: Option<PathBuf>,
    pub chunk_rows: usize,
    pub chunk_bytes: usize,
    /// Most (member, group) pairs one run aggregates.
    pub max_memberships: u64,
}

impl Default for IdentitySinkOptions {
    fn default() -> Self {
        Self { v2_fields: false, spill_dir: None, chunk_rows: CHUNK_ROWS, chunk_bytes: CHUNK_BYTES, max_memberships: 5_000_000 }
    }
}

/// What a run delivered (runner metrics and the 500k test).
#[derive(Debug, Default)]
pub struct IdentityStats {
    /// Rows the coordinator acknowledged (staged, delta or groups).
    pub rows: AtomicU64,
    /// Coordinator requests that succeeded.
    pub requests: AtomicU64,
    /// JSON bytes of acknowledged rows.
    pub bytes: AtomicU64,
    pub tombstones: AtomicU64,
    pub managers_resolved: AtomicU64,
    /// Rows staged without a manager reference that `manager_external_id`
    /// named (not in the directory, or not resolvable in a delta run).
    pub managers_unresolved: AtomicU64,
    /// Delta rows whose manager was sent by id for the coordinator.
    pub manager_refs: AtomicU64,
    /// Rows that waited for their manager in the spill.
    pub spilled_rows: AtomicU64,
    /// Most rows ever held in a chunk buffer.
    pub peak_buffered_rows: AtomicU64,
    pub manager_map_entries: AtomicU64,
    pub members: AtomicU64,
    pub groups: AtomicU64,
}

/// Delivers a `kind: identity` run for one claimed feed of one tenant.
pub struct IdentitySink {
    client: CoordinatorClient,
    /// Dedicated deployments (NAN-3767): rows and deltas go through Vector;
    /// `client` keeps the control calls. `None`: the coordinator's JSON
    /// routes (hosted).
    vector: Option<std::sync::Arc<VectorEnrichment>>,
    feed_id: String,
    run_id: String,
    /// Row version: the run start in epoch milliseconds.
    version: i64,
    opts: IdentitySinkOptions,
    state: Mutex<State>,
    seen_hasher: RandomState,
    pub stats: IdentityStats,
}

#[derive(Default)]
struct State {
    hasher: RandomState,
    /// keyed hash of a user's `external_id` -> its manager reference (upn,
    /// else email, else username).
    managers: HashMap<u64, Box<str>>,
    full: HashMap<String, FullRun>,
    /// Sub-feeds with staged, uncommitted chunks.
    open: BTreeSet<String>,
    members: Members,
}

struct FullRun {
    subfeed: String,
    chunk: Vec<Value>,
    chunk_bytes: usize,
    next_chunk: u32,
    staged_rows: u64,
    spill: Spill,
    guard: ShrinkGuard,
    /// Through Vector a row may reach the coordinator twice; it counts
    /// distinct users, so the run does too (keyed `external_id` hashes).
    seen: Option<std::collections::HashSet<u64>>,
}

#[derive(Default)]
struct Members {
    names: HashMap<Box<str>, u32>,
    list: Vec<Box<str>>,
    by_member: HashMap<Box<str>, (Vec<u32>, bool)>,
    pairs: u64,
}

/// Rows waiting for their manager: a private temp file, else memory.
struct Spill {
    dir: Option<PathBuf>,
    tag: String,
    file: Option<(PathBuf, BufWriter<std::fs::File>)>,
    tried: bool,
    mem: Vec<String>,
    mem_bytes: usize,
    rows: u64,
    /// Rows that found no room (their manager is dropped).
    dropped: u64,
}

impl Spill {
    fn new(dir: Option<PathBuf>, tag: String) -> Self {
        Self { dir, tag, file: None, tried: false, mem: Vec::new(), mem_bytes: 0, rows: 0, dropped: 0 }
    }

    fn open(&mut self) {
        self.tried = true;
        let dir = self.dir.clone().unwrap_or_else(std::env::temp_dir);
        let path = dir.join(format!("{SPILL_PREFIX}{}-{}.ndjson", self.tag, Uuid::new_v4().simple()));
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        match o.open(&path) {
            Ok(f) => self.file = Some((path, BufWriter::new(f))),
            Err(e) => tracing::warn!(error = %e.kind(), "identity spill file unavailable; holding pending rows in memory"),
        }
    }

    /// Keep one line. `false`: nowhere to keep it.
    fn push(&mut self, line: String) -> bool {
        if !self.tried {
            self.open();
        }
        if let Some((_, w)) = &mut self.file {
            if w.write_all(line.as_bytes()).and_then(|_| w.write_all(b"\n")).is_ok() {
                self.rows += 1;
                return true;
            }
            tracing::warn!("identity spill file write failed; holding pending rows in memory");
            self.close();
        }
        if self.mem_bytes + line.len() > MAX_SPILL_MEMORY {
            if self.dropped == 0 {
                tracing::error!(
                    held_rows = self.mem.len(), held_bytes = self.mem_bytes,
                    "identity spill file unavailable and the in-memory fallback is full; rows are staged without their manager (set CONNECTOR_IDENTITY_SPILL_DIR to a writable, sized volume)"
                );
            }
            self.dropped += 1;
            return false;
        }
        self.mem_bytes += line.len();
        self.mem.push(line);
        self.rows += 1;
        true
    }

    fn close(&mut self) {
        if let Some((path, _)) = self.file.take() {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Every kept line (file first, then memory), streamed, then forget
    /// them. The file is unlinked once opened for reading.
    fn drain(&mut self) -> Result<SpillLines, String> {
        let file = match self.file.take() {
            Some((path, mut w)) => {
                let opened = w.flush().and_then(|_| std::fs::File::open(&path));
                let _ = std::fs::remove_file(&path);
                Some(std::io::BufReader::new(opened.map_err(|e| format!("identity spill file unreadable ({})", e.kind()))?).lines())
            }
            None => None,
        };
        let mem = std::mem::take(&mut self.mem).into_iter();
        self.mem_bytes = 0;
        self.rows = 0;
        Ok(SpillLines { file, mem })
    }
}

/// The spilled lines, read one at a time.
struct SpillLines {
    file: Option<std::io::Lines<std::io::BufReader<std::fs::File>>>,
    mem: std::vec::IntoIter<String>,
}

impl Iterator for SpillLines {
    type Item = Result<String, String>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(lines) = &mut self.file {
            match lines.next() {
                Some(l) => return Some(l.map_err(|e| format!("identity spill file unreadable ({})", e.kind()))),
                None => self.file = None,
            }
        }
        self.mem.next().map(Ok)
    }
}

impl Drop for Spill {
    fn drop(&mut self) {
        if self.dropped > 0 {
            tracing::error!(rows = self.dropped, "identity run staged rows without their manager: the spill had no room");
        }
        self.close();
    }
}

/// Remove spill files a dead runner left in `dir` (default: the system
/// temp dir, where only files older than a day go). Returns the count.
pub fn sweep_spill_dir(dir: Option<&std::path::Path>) -> usize {
    let (dir, min_age) = match dir {
        Some(d) => (d.to_path_buf(), Duration::ZERO),
        None => (std::env::temp_dir(), SHARED_TEMP_SWEEP_AGE),
    };
    let Ok(entries) = std::fs::read_dir(&dir) else { return 0 };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(SPILL_PREFIX) || !name.ends_with(".ndjson") {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let old = meta.modified().ok().and_then(|m| m.elapsed().ok()).is_some_and(|age| age >= min_age);
        if meta.is_file() && old && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Strip control characters and cap the length (on a char boundary).
fn clean_text(s: &str) -> String {
    let mut out: String = s.chars().filter(|c| !c.is_control()).collect();
    if out.len() > MAX_TEXT {
        let mut end = MAX_TEXT;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }
    out.trim().to_string()
}

fn text_of(v: &Value) -> Option<String> {
    let s = match v {
        Value::String(s) => clean_text(s),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => return None,
    };
    (!s.is_empty()).then_some(s)
}

fn bool_of(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => Some(true),
            "false" | "no" | "0" => Some(false),
            _ => None,
        },
        Value::Number(n) => n.as_i64().map(|n| n != 0),
        _ => None,
    }
}

/// The contract's statuses onto the coordinator's (`active`, `disabled`,
/// `suspended`, `deleted`, `anonymized`, `unknown`; with `v2` also
/// `deprovisioned`, `locked`, `staged`).
fn account_status(s: &str, v2: bool) -> &'static str {
    match s.trim().to_ascii_lowercase().as_str() {
        "active" | "enabled" => "active",
        "deprovisioned" if v2 => "deprovisioned",
        "locked" | "locked_out" if v2 => "locked",
        "staged" if v2 => "staged",
        "disabled" | "deprovisioned" | "deactivated" => "disabled",
        "suspended" | "locked" | "locked_out" => "suspended",
        "deleted" => "deleted",
        "anonymized" => "anonymized",
        _ => "unknown",
    }
}

/// One normalized users row.
struct UserRow {
    row: Map<String, Value>,
    external_id: String,
    /// What a report of this user would carry as `manager_upn`.
    reference: Option<String>,
    /// The manager to resolve, when the row names one by id only.
    manager_external_id: Option<String>,
}

fn json_len(v: &Value) -> usize {
    serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0)
}

impl IdentitySink {
    pub fn new(client: CoordinatorClient, feed_id: Uuid, started: DateTime<Utc>, opts: IdentitySinkOptions) -> Self {
        Self {
            client,
            vector: None,
            feed_id: feed_id.hyphenated().to_string(),
            run_id: Uuid::now_v7().hyphenated().to_string(),
            version: started.timestamp_millis().max(1),
            opts,
            state: Mutex::new(State::default()),
            seen_hasher: RandomState::new(),
            stats: IdentityStats::default(),
        }
    }

    /// Send rows and deltas through the deployment's Vector enrichment
    /// ingress instead of the coordinator's JSON routes (NAN-3767).
    pub fn with_vector(mut self, vector: std::sync::Arc<VectorEnrichment>) -> Self {
        self.vector = Some(vector);
        self
    }

    /// The Vector enrichment ingress host, when rows go through Vector.
    pub fn vector_host(&self) -> Option<String> {
        self.vector.as_ref().and_then(|v| v.host())
    }

    pub fn tenant(&self) -> Uuid {
        self.client.tenant()
    }

    pub fn coordinator_host(&self) -> Option<String> {
        self.client.host()
    }

    /// The coordinator run id (= `snapshot_id` on every row of this run).
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    fn subfeed(&self, stream: &str) -> String {
        format!("{}:{stream}", self.feed_id)
    }

    fn provenance(&self, subfeed: &str, external_id: &str) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("feed_id".into(), json!(subfeed));
        m.insert("external_id".into(), json!(external_id));
        m.insert("source_kind".into(), json!("pull"));
        m.insert("version".into(), json!(self.version));
        m.insert("snapshot_id".into(), json!(self.run_id));
        m.insert("observed_at".into(), json!(Utc::now().timestamp_millis()));
        m
    }

    /// A program's canonical user row as a coordinator `IdentityRow`. Only
    /// known columns are sent; provenance is the engine's.
    fn normalize(&self, ev: &Value, subfeed: &str) -> Result<UserRow, String> {
        let o = ev.as_object().ok_or("an identity users event must be an object")?;
        let external_id = o.get("external_id").and_then(text_of).filter(|s| s.len() <= 1024).ok_or("an identity users row needs a non-empty `external_id` (at most 1024 bytes)")?;
        let mut row = self.provenance(subfeed, &external_id);
        if let Some(v) = o.get("version").and_then(Value::as_i64).filter(|v| *v > 0) {
            row.insert("version".into(), json!(v));
        }
        for f in TEXT_FIELDS {
            if let Some(t) = o.get(*f).and_then(text_of) {
                row.insert((*f).into(), json!(t));
            }
        }
        if let Some(st) = o.get("account_status").and_then(text_of) {
            row.insert("account_status".into(), json!(account_status(&st, self.opts.v2_fields)));
        }
        for f in BOOL_FIELDS {
            if let Some(b) = o.get(*f).and_then(bool_of) {
                row.insert((*f).into(), json!(b));
            }
        }
        if self.opts.v2_fields {
            if let Some(b) = o.get("is_admin").and_then(bool_of) {
                row.insert("is_admin".into(), json!(b));
            }
        }
        for f in TIME_FIELDS {
            if let Some(ms) = o.get(*f).filter(|v| !v.is_null()).and_then(crate::engine::event_time_ms) {
                row.insert((*f).into(), json!(ms));
            }
        }
        if let Some(Value::Array(gs)) = o.get("groups") {
            let mut groups: Vec<String> = gs.iter().filter_map(text_of).collect();
            groups.sort();
            groups.dedup();
            groups.truncate(MAX_GROUPS_PER_MEMBER);
            if !groups.is_empty() {
                row.insert("groups".into(), json!(groups));
            }
        }
        if row.get("deleted") == Some(&Value::Bool(true)) {
            self.stats.tombstones.fetch_add(1, Ordering::Relaxed);
        }
        let reference = ["upn", "email", "username"].iter().find_map(|k| row.get(*k).and_then(Value::as_str).map(str::to_string));
        let manager_external_id = if row.contains_key("manager_upn") { None } else { o.get("manager_external_id").and_then(text_of) };
        Ok(UserRow { row, external_id, reference, manager_external_id })
    }

    fn key(st: &State, id: &str) -> u64 {
        st.hasher.hash_one(id)
    }

    /// The run's distinct-user key (a per-sink keyed hash).
    fn seen_key(&self, id: &str) -> u64 {
        self.seen_hasher.hash_one(id)
    }

    /// Record the row's own reference and fill its manager when known.
    /// Returns whether the row still waits for its manager.
    fn resolve(&self, st: &mut State, r: &mut UserRow) -> bool {
        if let Some(reference) = &r.reference {
            let k = Self::key(st, &r.external_id);
            st.managers.insert(k, reference.clone().into_boxed_str());
        }
        let Some(m) = &r.manager_external_id else { return false };
        match st.managers.get(&Self::key(st, m)) {
            Some(upn) => {
                r.row.insert("manager_upn".into(), json!(upn.as_ref()));
                self.stats.managers_resolved.fetch_add(1, Ordering::Relaxed);
                false
            }
            None => true,
        }
    }

    async fn stage_chunk(&self, open: &mut BTreeSet<String>, run: &mut FullRun) -> Result<(), String> {
        if run.chunk.is_empty() {
            return Ok(());
        }
        let rows = std::mem::take(&mut run.chunk);
        let (n, bytes) = (rows.len() as u64, std::mem::take(&mut run.chunk_bytes) as u64);
        open.insert(run.subfeed.clone());
        match &self.vector {
            Some(vector) => {
                let seen = run.seen.get_or_insert_with(Default::default);
                for row in &rows {
                    if let Some(id) = row.get("external_id").and_then(Value::as_str) {
                        seen.insert(self.seen_key(id));
                    }
                }
                let lines = rows
                    .into_iter()
                    .map(|row| json!({ "op": "stage", "feed_id": run.subfeed, "run_id": self.run_id, "row": row }))
                    .collect();
                vector.post(lines).await?;
                run.staged_rows = seen.len() as u64;
            }
            None => {
                self.client.stage(&run.subfeed, &self.run_id, run.next_chunk, rows).await?;
                run.staged_rows += n;
            }
        }
        run.next_chunk += 1;
        self.stats.rows.fetch_add(n, Ordering::Relaxed);
        self.stats.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.stats.requests.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn buffer(&self, open: &mut BTreeSet<String>, run: &mut FullRun, row: Map<String, Value>) -> Result<(), String> {
        let row = Value::Object(row);
        let len = json_len(&row);
        if !run.chunk.is_empty() && run.chunk_bytes + len > self.opts.chunk_bytes {
            self.stage_chunk(open, run).await?;
        }
        run.chunk.push(row);
        run.chunk_bytes += len;
        self.stats.peak_buffered_rows.fetch_max(run.chunk.len() as u64, Ordering::Relaxed);
        if run.chunk.len() >= self.opts.chunk_rows {
            self.stage_chunk(open, run).await?;
        }
        Ok(())
    }

    /// Delta rows, each with the manager id the coordinator resolves.
    async fn post_deltas(&self, rows: Vec<(Value, Option<String>)>) -> Result<(), String> {
        let mut batch = Vec::new();
        let mut bytes = 0usize;
        for row in rows {
            let len = json_len(&row.0);
            if !batch.is_empty() && (batch.len() >= self.opts.chunk_rows || bytes + len > self.opts.chunk_bytes) {
                self.send_deltas(std::mem::take(&mut batch), std::mem::take(&mut bytes)).await?;
            }
            batch.push(row);
            bytes += len;
        }
        self.send_deltas(batch, bytes).await
    }

    async fn send_deltas(&self, rows: Vec<(Value, Option<String>)>, bytes: usize) -> Result<(), String> {
        if rows.is_empty() {
            return Ok(());
        }
        let n = rows.len() as u64;
        let mut refs = Vec::new();
        let rows: Vec<Value> = rows
            .into_iter()
            .map(|(row, manager)| {
                if let Some(m) = manager {
                    refs.push(json!({ "feed_id": row["feed_id"], "external_id": row["external_id"], "manager_external_id": m }));
                }
                row
            })
            .collect();
        let sent_refs = refs.len() as u64;
        match &self.vector {
            Some(vector) => {
                let mut by_row: HashMap<(String, String), Value> = refs
                    .into_iter()
                    .map(|r| ((r["feed_id"].as_str().unwrap_or_default().to_string(), r["external_id"].as_str().unwrap_or_default().to_string()), r))
                    .collect();
                let lines = rows
                    .into_iter()
                    .map(|row| {
                        let key = (row["feed_id"].as_str().unwrap_or_default().to_string(), row["external_id"].as_str().unwrap_or_default().to_string());
                        let mut line = json!({ "op": "delta", "patch": true, "row": row });
                        if let Some(r) = by_row.remove(&key) {
                            line["manager_ref"] = r;
                        }
                        line
                    })
                    .collect();
                vector.post(lines).await?;
            }
            None => self.client.deltas(rows, true, refs).await?,
        }
        self.stats.manager_refs.fetch_add(sent_refs, Ordering::Relaxed);
        self.stats.rows.fetch_add(n, Ordering::Relaxed);
        self.stats.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.stats.requests.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[async_trait::async_trait]
impl Sink for IdentitySink {
    async fn push(&self, _source_type: &str, _events: &[Value]) -> Result<(), String> {
        Err("the identity sink takes rows only from kind: identity streams".into())
    }
    fn identity(&self) -> Option<&dyn IdentityTarget> {
        Some(self)
    }
}

#[async_trait::async_trait]
impl IdentityTarget for IdentitySink {
    fn delta_supported(&self) -> bool {
        self.opts.v2_fields
    }

    async fn users_begin(&self, stream: &str, mode: IdentityMode, guard: ShrinkGuard) -> Result<(), String> {
        let mut st = self.state.lock().await;
        if mode == IdentityMode::Full {
            let subfeed = self.subfeed(stream);
            // A delta that turned into a full run starts a clean staged run.
            if st.open.remove(&subfeed) {
                let _ = self.client.abort(&subfeed, &self.run_id).await;
            }
            st.full.insert(
                stream.to_string(),
                FullRun { subfeed, chunk: Vec::new(), chunk_bytes: 0, next_chunk: 0, staged_rows: 0, spill: Spill::new(self.opts.spill_dir.clone(), self.run_id.clone()), guard, seen: None },
            );
        }
        Ok(())
    }

    async fn users_page(&self, stream: &str, mode: IdentityMode, rows: &[Value]) -> Result<(), String> {
        let subfeed = self.subfeed(stream);
        let mut guard = self.state.lock().await;
        let st = &mut *guard;
        match mode {
            IdentityMode::Delta => {
                if !self.opts.v2_fields {
                    return Err("identity delta rows need the v2 coordinator contract (CONNECTOR_IDENTITY_V2_FIELDS)".into());
                }
                let mut out = Vec::with_capacity(rows.len());
                for ev in rows {
                    let mut r = self.normalize(ev, &subfeed)?;
                    // A manager outside this run's rows is resolved by the
                    // coordinator against the directory.
                    let live = r.row.get("deleted") != Some(&Value::Bool(true));
                    let manager = if self.resolve(st, &mut r) && live { r.manager_external_id.take() } else { None };
                    out.push((Value::Object(r.row), manager));
                }
                self.stats.manager_map_entries.store(st.managers.len() as u64, Ordering::Relaxed);
                drop(guard);
                self.post_deltas(out).await
            }
            IdentityMode::Full => {
                let mut run = st.full.remove(stream).ok_or("identity users page outside a full run")?;
                let result = async {
                    for ev in rows {
                        let mut r = self.normalize(ev, &subfeed)?;
                        if self.resolve(st, &mut r) {
                            let m = r.manager_external_id.clone().unwrap_or_default();
                            let line = json!({ "m": m, "r": Value::Object(r.row.clone()) }).to_string();
                            if run.spill.push(line) {
                                self.stats.spilled_rows.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            self.stats.managers_unresolved.fetch_add(1, Ordering::Relaxed);
                        }
                        self.buffer(&mut st.open, &mut run, r.row).await?;
                    }
                    Ok::<_, String>(())
                }
                .await;
                self.stats.manager_map_entries.store(st.managers.len() as u64, Ordering::Relaxed);
                st.full.insert(stream.to_string(), run);
                result
            }
        }
    }

    async fn users_finish(&self, stream: &str, mode: IdentityMode) -> Result<Option<u64>, String> {
        if mode == IdentityMode::Delta {
            return Ok(None);
        }
        let mut guard = self.state.lock().await;
        let st = &mut *guard;
        let mut run = st.full.remove(stream).ok_or("identity users stream finished outside a full run")?;
        for line in run.spill.drain()? {
            let line = line?;
            let v: Value = serde_json::from_str(&line).map_err(|e| format!("identity spill line unreadable: {e}"))?;
            let mut row = match v.get("r") {
                Some(Value::Object(r)) => r.clone(),
                _ => return Err("identity spill line has no row".into()),
            };
            let m = v.get("m").and_then(Value::as_str).unwrap_or_default();
            match st.managers.get(&Self::key(st, m)) {
                Some(upn) => {
                    row.insert("manager_upn".into(), json!(upn.as_ref()));
                    self.stats.managers_resolved.fetch_add(1, Ordering::Relaxed);
                }
                None => {
                    self.stats.managers_unresolved.fetch_add(1, Ordering::Relaxed);
                }
            }
            self.buffer(&mut st.open, &mut run, row).await?;
        }
        self.stage_chunk(&mut st.open, &mut run).await?;
        if run.staged_rows == 0 && !run.guard.allow {
            // A vendor answering "no users" must not wipe the directory.
            return Err(format!(
                "identity full run of `{stream}` returned no users; the directory was left unchanged (set feed config `{ALLOW_SHRINK_CONFIG}: true` if this is intended)"
            ));
        }
        // Staged but not committed: the engine abandons the run.
        run.guard.check(stream, run.staged_rows)?;
        // Zero rows reach here only when the feed config allows a shrink:
        // the coordinator then needs `allow_empty`.
        self.client.commit(&run.subfeed, &self.run_id, run.staged_rows, run.staged_rows == 0).await?;
        self.stats.requests.fetch_add(1, Ordering::Relaxed);
        st.open.remove(&run.subfeed);
        Ok(Some(run.staged_rows))
    }

    async fn memberships_page(&self, _stream: &str, events: &[Value]) -> Result<(), String> {
        let mut st = self.state.lock().await;
        let m = &mut st.members;
        for ev in events {
            let (Some(member), Some(group)) = (ev.get("member").and_then(text_of), ev.get("group").and_then(text_of)) else {
                return Err("an identity membership event needs `member` and `group`".into());
            };
            if member.len() > 1024 {
                return Err("an identity membership `member` exceeds 1024 bytes".into());
            }
            m.pairs += 1;
            if m.pairs > self.opts.max_memberships {
                return Err(format!("cap reached: more than {} identity memberships (limits.max_identity_memberships)", self.opts.max_memberships));
            }
            let gid = match m.names.get(group.as_str()) {
                Some(id) => *id,
                None => {
                    let id = m.list.len() as u32;
                    m.list.push(group.clone().into_boxed_str());
                    m.names.insert(group.into_boxed_str(), id);
                    id
                }
            };
            let privileged = ev.get("privileged").and_then(bool_of).unwrap_or(false);
            let e = m.by_member.entry(member.into_boxed_str()).or_default();
            e.0.push(gid);
            e.1 |= privileged;
        }
        self.stats.members.store(m.by_member.len() as u64, Ordering::Relaxed);
        self.stats.groups.store(m.list.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    async fn memberships_finish(&self) -> Result<(), String> {
        let mut guard = self.state.lock().await;
        let st = &mut *guard;
        let members = std::mem::take(&mut st.members);
        let subfeed = self.subfeed(GROUPS_SUBFEED);
        if members.by_member.is_empty() {
            // The writer token may only stage, commit, abort and post deltas,
            // and a commit needs at least one chunk: an empty memberships
            // walk leaves the previous groups snapshot in place.
            tracing::warn!(target: "nano_connector::audit", feed = %subfeed, "identity memberships walk found no memberships; the previous groups snapshot is kept");
            return Ok(());
        }
        let mut run = FullRun { subfeed: subfeed.clone(), chunk: Vec::new(), chunk_bytes: 0, next_chunk: 0, staged_rows: 0, spill: Spill::new(None, String::new()), guard: ShrinkGuard::default(), seen: None };
        let Members { list, by_member, .. } = members;
        for (member, (mut gids, privileged)) in by_member {
            gids.sort_unstable_by(|a, b| list[*a as usize].cmp(&list[*b as usize]));
            gids.dedup();
            if gids.len() > MAX_GROUPS_PER_MEMBER {
                tracing::warn!(groups = gids.len(), "identity member has more groups than the directory keeps; truncating");
                gids.truncate(MAX_GROUPS_PER_MEMBER);
            }
            let mut row = self.provenance(&subfeed, &member);
            row.insert("groups".into(), Value::Array(gids.iter().map(|g| json!(list[*g as usize].as_ref())).collect()));
            if self.opts.v2_fields {
                row.insert("is_admin".into(), json!(privileged));
            }
            self.buffer(&mut st.open, &mut run, row).await?;
        }
        self.stage_chunk(&mut st.open, &mut run).await?;
        self.client.commit(&subfeed, &self.run_id, run.staged_rows, false).await?;
        self.stats.requests.fetch_add(1, Ordering::Relaxed);
        st.open.remove(&subfeed);
        Ok(())
    }

    async fn abort(&self) {
        let open: Vec<String> = {
            let mut st = self.state.lock().await;
            st.full.clear();
            st.members = Members::default();
            std::mem::take(&mut st.open).into_iter().collect()
        };
        for feed in open {
            if let Err(e) = self.client.abort(&feed, &self.run_id).await {
                tracing::warn!(error = %e, "identity staged run could not be abandoned; the coordinator expires it");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_map_onto_the_coordinator_set() {
        for (i, o) in [("ACTIVE", "active"), ("deprovisioned", "disabled"), ("LOCKED_OUT", "suspended"), ("locked", "suspended"), ("staged", "unknown"), ("x", "unknown")] {
            assert_eq!(account_status(i, false), o, "v1 {i}");
        }
        for (i, o) in [("ACTIVE", "active"), ("DEPROVISIONED", "deprovisioned"), ("LOCKED_OUT", "locked"), ("locked", "locked"), ("staged", "staged"), ("deactivated", "disabled"), ("suspended", "suspended"), ("x", "unknown")] {
            assert_eq!(account_status(i, true), o, "v2 {i}");
        }
    }

    #[test]
    fn text_is_cleaned_and_capped() {
        assert_eq!(clean_text(" a\u{0}b\nc "), "abc");
        assert_eq!(clean_text(&"é".repeat(3000)).len(), 4096);
    }

    #[test]
    fn stale_spill_files_are_swept_from_the_spill_dir() {
        let dir = std::env::temp_dir().join(format!("spill-sweep-{}", Uuid::new_v4().simple()));
        std::fs::create_dir(&dir).unwrap();
        for name in ["nano-identity-run-1.ndjson", "nano-identity-run-2.ndjson", "other.ndjson", "nano-identity-x.txt"] {
            std::fs::write(dir.join(name), "x").unwrap();
        }
        assert_eq!(sweep_spill_dir(Some(&dir)), 2);
        let mut left: Vec<String> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        assert_eq!(left, ["nano-identity-x.txt", "other.ndjson"]);
        assert_eq!(sweep_spill_dir(Some(&dir.join("missing"))), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shrink_guard_refuses_more_than_half() {
        let g = ShrinkGuard { previous_rows: Some(10), allow: false };
        assert!(g.check("users", 5).is_ok());
        assert!(g.check("users", 4).unwrap_err().starts_with("identity_shrink_refused"));
        assert!(ShrinkGuard { allow: true, ..g }.check("users", 1).is_ok());
        assert!(ShrinkGuard::default().check("users", 1).is_ok(), "no previous full run");
    }

    #[test]
    fn origins_are_validated() {
        assert!(coordinator_origin("http://coord.lean.svc:8080").is_ok());
        for bad in ["ftp://x", "http://u:p@x", "http://x/path", "http://x?q", "nope"] {
            assert!(coordinator_origin(bad).is_err(), "{bad}");
        }
    }
}
