// SPDX-License-Identifier: AGPL-3.0-or-later

//! The cell's HTTP front (NAN-2871): nanosiem-api / nanosiem-search route
//! query RPCs, wakes and drains here; operators read health, metrics and
//! signals.
//!
//! | Method | Path | full token | cluster query token (legacy†) | tenant `query`/`detect`/`status` token for `{t}` | alerts-read token |
//! |---|---|---|---|---|---|
//! | GET | `/healthz` (token digests and tenant counts only with the full or cluster query token) | – (no auth) | – | – | 403 if presented |
//! | GET | `/readyz` (NAN-3004: 503 until warm, and while draining) | – (no auth) | – | – | 403 if presented |
//! | GET | `/v1/handover` (NAN-3004: peer view, writer handover) | yes | 403 | 403 | 403 |
//! | GET | `/metrics` | yes (public cell-level view if `metrics_public`) | 403 | 403 | 403 |
//! | GET | `/v1/status` (lists every placed tenant) | yes | yes | 403 | 403 |
//! | GET | `/v1/tenants/{t}/status` (that tenant only) | yes | yes† | `status` | 403 |
//! | GET | `/v1/signals` | yes | 403 | 403 | 403 |
//! | GET | `/v1/lean-cell-alerts` | yes | 403 | 403 | yes |
//! | POST | `/v1/tenants/{t}/landing` (fixed aggregate only) | yes | yes | 403 | 403 |
//! | POST | `/v1/tenants/{t}/wake` `{"role":"query",..}` | yes | yes | `query` | 403 |
//! | POST | `/v1/tenants/{t}/wake` `{"role":"ingest"\|"detect",..}` | yes | 403 | 403 | 403 |
//! | POST | `/v1/tenants/{t}/drain` | yes | 403 | 403 | 403 |
//! | any | `/v1/tenants/{t}/query[/{rest…}]` → `query[T]` `/{rest…}` | yes | yes† | `query` | 403 |
//! | any | `/v1/tenants/{t}/detect[/{rest…}]` → `detect[T]` `/{rest…}` with `detect_runs_rules` (NAN-3047), else `query[T]` | yes | yes† | `detect` | 403 |
//! | POST | `/v1/tenants/{t}/detect/v1/detections/reset` (operator reset, NAN-3289) | yes | 403 | `detect` | 403 |
//! | any | `/v1/tenants/{t}/query/v1/debug/{rest…}` (operator probes, NAN-3715) | yes | yes† | 403 | 403 |
//! | anything else | | 404 | 403 | 403 | 403 |
//!
//! † Only while `router_accept_cluster_query_token` is on (the default during
//! the NAN-3289 rollout). Off, the cluster query token reaches `/healthz`,
//! `GET /v1/status`, a query-role wake and fixed landing aggregates only.
//!
//! **Per-tenant tokens (NAN-3289, completes NAN-2904).** A `nct1.` bearer is
//! derived from the full token for one tenant, one cell and one scope
//! ([`crate::tenant_token`]) and is checked, in constant time, against the
//! `{t}` path segment and this cell's id: tenant A's token on tenant B's
//! path, on another cell, or on a route outside its scope is a 403. A
//! `POST /v1/tenants/{t}/query/v1/jobs/search` body must carry a signature
//! by `{t}`'s `job` key (`x-nano-cell-job-signature`); the router verifies it
//! before query[T] sees the spec and tells query[T] how the spec was
//! admitted (`x-nano-cell-job-auth`, which callers can never set).
//!
//! Authentication is a bearer token from a mounted Secret, compared in
//! constant time. The **full** token
//! (`router_token_file`: wake, drain, signals, metrics)
//! and optional **query-only** and **alerts-read** tokens (`router_query_token_file`,
//! `router_alerts_token_file`). The alerts token reaches only the feed.
//! The query-only token is used by nanosiem-api / jobs / search and the
//! control plane's lean-assignment probe; it reaches the tenants' query and
//! detect processes, cell status, and a wake whose body role is `query`
//! (the prewarm probe, `router-query-token-wake`). All loaded
//! tokens must differ. On the unix listener
//! the peer's `SO_PEERCRED` uid must also not be a tenant uid. The router
//! token is **stripped** before a request is forwarded: a tenant process
//! never sees it. Tenant processes never listen; each routed request is a
//! fresh socketpair whose far end is passed to `query[T]` over its control
//! socket.

use crate::contract::{Role, TenantId, WakeReason};
use crate::supervisor::{CellError, InflightGuard, SearchGuard, Supervisor};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type Body = BoxBody<Bytes, hyper::Error>;

/// What a presented token may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The control plane: every route.
    Full,
    /// The cluster-wide query token (nanosiem-api / jobs / search, the
    /// control plane's probe): see [`permits_with`].
    Query,
    AlertsRead,
    /// A per-tenant `query` token, already verified against the path tenant.
    TenantQuery,
    /// A per-tenant `detect` token, already verified against the path tenant.
    TenantDetect,
    /// A per-tenant `status` token, already verified against the path tenant.
    TenantStatus,
}

/// The route a request addresses, for authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteClass {
    Health,
    Metrics,
    Status,
    Signals,
    LeanCellAlerts,
    Landing,
    Wake,
    Drain,
    Query,
    Detect,
    /// `GET /v1/handover`: the peer view (NAN-3004), full token only.
    Handover,
    /// `GET /v1/tenants/{t}/status`: one tenant's status (NAN-3289).
    TenantStatus,
    Other,
}

/// Classify `method path` (the path without the query string).
pub fn classify(method: &Method, path: &str) -> RouteClass {
    match (method, path) {
        (_, "/healthz") | (_, "/readyz") => RouteClass::Health,
        (&Method::GET, "/v1/handover") => RouteClass::Handover,
        (&Method::GET, "/metrics") => RouteClass::Metrics,
        (&Method::GET, "/v1/status") => RouteClass::Status,
        (&Method::GET, "/v1/signals") => RouteClass::Signals,
        (&Method::GET, "/v1/lean-cell-alerts") => RouteClass::LeanCellAlerts,
        _ => match path.strip_prefix("/v1/tenants/").map(|r| r.split_once('/').map(|(_, t)| t).unwrap_or("")) {
            Some("landing") if method == Method::POST => RouteClass::Landing,
            Some("wake") if method == Method::POST => RouteClass::Wake,
            Some("drain") if method == Method::POST => RouteClass::Drain,
            Some("status") if method == Method::GET => RouteClass::TenantStatus,
            Some(t) if t == "query" || t.starts_with("query/") => RouteClass::Query,
            Some(t) if t == "detect" || t.starts_with("detect/") => RouteClass::Detect,
            _ => RouteClass::Other,
        },
    }
}

/// May `scope` use `route`, with the cluster query token in its legacy reach
/// (the `router_accept_cluster_query_token` default)?
pub fn permits(scope: Scope, route: RouteClass) -> bool {
    permits_with(scope, route, true)
}

/// May `scope` use `route`? `accept_cluster_query` is the cell's
/// `router_accept_cluster_query_token`. A tenant scope has already been
/// verified against the path tenant, so it only needs the route class here.
pub fn permits_with(scope: Scope, route: RouteClass, accept_cluster_query: bool) -> bool {
    match scope {
        Scope::Full => true,
        Scope::Query if accept_cluster_query => matches!(route,
            RouteClass::Query | RouteClass::Detect | RouteClass::Status | RouteClass::TenantStatus | RouteClass::Health | RouteClass::Landing),
        Scope::Query => matches!(route, RouteClass::Status | RouteClass::Health | RouteClass::Landing),
        Scope::AlertsRead => route == RouteClass::LeanCellAlerts,
        Scope::TenantQuery => matches!(route, RouteClass::Query | RouteClass::Health),
        Scope::TenantDetect => matches!(route, RouteClass::Detect | RouteClass::Health),
        Scope::TenantStatus => matches!(route, RouteClass::TenantStatus | RouteClass::Health),
    }
}

/// May `scope` reach `route` before the request body is read? Like
/// [`permits`], except that a query-scope wake is admitted here and then
/// held to [`permits_wake`] once its body's role is known.
pub fn admits(scope: Scope, route: RouteClass) -> bool {
    admits_with(scope, route, true)
}

/// [`admits`] with the cell's `router_accept_cluster_query_token`.
pub fn admits_with(scope: Scope, route: RouteClass, accept_cluster_query: bool) -> bool {
    permits_with(scope, route, accept_cluster_query)
        || (matches!(scope, Scope::Query | Scope::TenantQuery) && route == RouteClass::Wake)
}

/// May `scope` wake `role`? The full token wakes any role; the query-only
/// token (and its grace-window predecessor) and a tenant's own `query` token
/// only `query`, which is all the control plane's prewarm probe needs.
/// Ingest/detect wakes stay full-only.
pub fn permits_wake(scope: Scope, role: Role) -> bool {
    match scope {
        Scope::Full => true,
        Scope::Query | Scope::TenantQuery => role == Role::Query,
        Scope::AlertsRead | Scope::TenantDetect | Scope::TenantStatus => false,
    }
}

/// The detection-gate operator reset (NAN-3289 P2-1).
pub const DETECTION_RESET_PATH: &str = "/v1/detections/reset";
/// The detection-gate commit.
pub const DETECTION_COMMIT_PATH: &str = "/v1/detections/commit";

/// May `scope` call `sub` (the path below `/v1/tenants/{t}/detect`)? Moving a
/// rule's watermark needs detect scope (P2-1): a tenant `detect` token or the
/// full token; the cluster query token keeps commit only in its legacy reach.
/// The operator reset never takes the cluster query token.
pub fn permits_detect_call(scope: Scope, sub: &str, accept_cluster_query: bool) -> bool {
    let sub = sub.trim_end_matches('/');
    if sub == DETECTION_RESET_PATH {
        return matches!(scope, Scope::Full | Scope::TenantDetect);
    }
    if sub == DETECTION_COMMIT_PATH {
        return matches!(scope, Scope::Full | Scope::TenantDetect) || (scope == Scope::Query && accept_cluster_query);
    }
    true
}

/// The `{t}` segment of a `/v1/tenants/{t}/…` path (unvalidated).
pub fn path_tenant(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/v1/tenants/")?;
    let tenant = rest.split_once('/').map_or(rest, |(t, _)| t);
    (!tenant.is_empty()).then_some(tenant)
}

/// Why a request is refused before it reaches a handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deny {
    /// 401: no token, or not one of this cell's.
    Unauthorized,
    /// 403: a valid token that does not reach this route or tenant.
    Forbidden(&'static str),
}

/// How an unsigned or signed durable-job spec is admitted at the router
/// (P2-2). `Ok` is the `x-nano-cell-job-auth` value to hand query[T].
pub fn job_spec_decision(
    key: Option<&crate::tenant_token::TenantKey>,
    tenant: &str,
    cell_id: &str,
    body: &[u8],
    signature: Option<&str>,
    accept_cluster_query: bool,
) -> Result<&'static str, &'static str> {
    use crate::tenant_token::{JOB_AUTH_LEGACY, JOB_AUTH_SIGNED};
    match (signature, key) {
        (Some(sig), Some(key)) if key.verify_job_spec(tenant, cell_id, body, sig) => Ok(JOB_AUTH_SIGNED),
        (Some(_), _) => Err("the job spec signature does not verify for this tenant on this cell"),
        (None, _) if accept_cluster_query => Ok(JOB_AUTH_LEGACY),
        (None, _) => Err("unsigned job specs are refused (router_accept_cluster_query_token is off)"),
    }
}

/// Which scope `presented` authenticates as for the original two-token
/// contract. Alerts-read is checked by `Tokens::check`.
pub fn authenticate(presented: Option<&str>, full: &str, query: Option<&str>) -> Option<Scope> {
    let given = presented?.as_bytes();
    let is_full = bool::from(given.ct_eq(full.as_bytes())) & !full.is_empty();
    let is_query = query.is_some_and(|q| bool::from(given.ct_eq(q.as_bytes())) & !q.is_empty());
    match (is_full, is_query) {
        (true, _) => Some(Scope::Full),
        (false, true) => Some(Scope::Query),
        _ => None,
    }
}

/// The full router token (peer `/v1/handover` reads, NAN-3004).
pub(crate) fn read_full_token(path: &std::path::Path) -> anyhow::Result<Zeroizing<String>> {
    read_token(path, false)
}

fn read_token(path: &std::path::Path, strict_mode: bool) -> anyhow::Result<Zeroizing<String>> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        anyhow::ensure!(!strict_mode, "{} is mode {:o}: must not grant group/other access (use 0400)", path.display(), mode & 0o777);
        tracing::warn!(path = %path.display(), mode = format!("{:o}", mode & 0o777), "router token file readable beyond its owner");
    }
    let t = Zeroizing::new(std::fs::read_to_string(path)?);
    let t = Zeroizing::new(t.trim().to_owned());
    anyhow::ensure!(t.len() >= 32, "router token in {} must be at least 32 characters", path.display());
    Ok(t)
}

fn read_alerts_token(path: &std::path::Path) -> anyhow::Result<Zeroizing<String>> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    anyhow::ensure!(mode == 0o400, "{} is mode {:o}: alerts token file must be mode 0400", path.display(), mode);
    read_token(path, true)
}

/// The query-only token must not be the full token (it would silently
/// grant full scope).
pub fn distinct_tokens(full: &str, query: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !bool::from(query.as_bytes().ct_eq(full.as_bytes())),
        "router_query_token_file holds the same token as router_token_file; they must differ"
    );
    Ok(())
}

/// First 12 hex of sha256(token): enough for a probe to confirm which
/// token is loaded, never the token.
pub fn token_digest(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token.as_bytes()))[..12].to_owned()
}

/// What `/healthz` shows about the loaded tokens (digests only).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TokenDigests {
    pub full: String,
    pub query: Option<String>,
    /// The query token being retired: accepted until it expires.
    pub query_previous: Option<String>,
    pub query_previous_expires_in_secs: Option<u64>,
    pub alerts: Option<String>,
    pub alerts_previous: Option<String>,
    pub alerts_previous_expires_in_secs: Option<u64>,
}

/// The loaded router tokens and their bounded grace windows.
#[derive(Default)]
pub struct Tokens {
    full: Zeroizing<String>,
    query: Option<Zeroizing<String>>,
    previous: Option<(Zeroizing<String>, Instant)>,
    alerts: Option<Zeroizing<String>>,
    alerts_previous: Option<(Zeroizing<String>, Instant)>,
    /// Derived from the full token: verifies per-tenant tokens (NAN-3289).
    tenant_key: Option<crate::tenant_token::TenantKey>,
}

impl Tokens {
    /// Install freshly read tokens atomically. The full token has no grace.
    pub fn rotate(
        &mut self,
        full: Zeroizing<String>,
        query: Option<Zeroizing<String>>,
        alerts: Option<Zeroizing<String>>,
        now: Instant,
        grace: Duration,
        alerts_grace: Duration,
    ) -> anyhow::Result<()> {
        if let Some(q) = &query {
            distinct_tokens(&full, q)?;
        }
        if let Some(a) = &alerts {
            distinct_tokens(&full, a)?;
            if let Some(q) = &query {
                anyhow::ensure!(!bool::from(a.as_bytes().ct_eq(q.as_bytes())),
                    "router_alerts_token_file holds the same token as router_query_token_file; they must differ");
            }
        }
        let changed = match (&self.query, &query) {
            (Some(old), Some(new)) => !bool::from(old.as_bytes().ct_eq(new.as_bytes())),
            (Some(_), None) => true,
            _ => false,
        };
        if changed {
            let old = self.query.take().expect("changed implies an old token");
            tracing::info!(previous = %token_digest(&old), grace_secs = grace.as_secs(),
                "router query token rotated; the previous one is accepted during the grace window");
            self.previous = Some((old, now + grace));
        }
        // A previous query token must never equal the (new) full token.
        if self.previous.as_ref().is_some_and(|(p, _)| bool::from(p.as_bytes().ct_eq(full.as_bytes()))) {
            self.previous = None;
        }
        let alerts_changed = match (&self.alerts, &alerts) {
            (Some(old), Some(new)) => !bool::from(old.as_bytes().ct_eq(new.as_bytes())),
            (Some(_), None) => true,
            _ => false,
        };
        if alerts_changed {
            let old = self.alerts.take().expect("changed implies an old alerts token");
            self.alerts_previous = Some((old, now + alerts_grace));
        }
        if self.alerts_previous.as_ref().is_some_and(|(p, _)|
            bool::from(p.as_bytes().ct_eq(full.as_bytes())) ||
            query.as_ref().is_some_and(|q| bool::from(p.as_bytes().ct_eq(q.as_bytes())))) {
            self.alerts_previous = None;
        }
        if self.previous.as_ref().is_some_and(|(p, _)| alerts.as_ref().is_some_and(|a|
            bool::from(p.as_bytes().ct_eq(a.as_bytes())))) {
            self.previous = None;
        }
        self.tenant_key = Some(crate::tenant_token::TenantKey::from_router_token(&full));
        self.full = full;
        self.query = query;
        self.alerts = alerts;
        Ok(())
    }

    /// The per-tenant derivation key (none before the first load).
    pub fn tenant_key(&self) -> Option<&crate::tenant_token::TenantKey> {
        self.tenant_key.as_ref()
    }

    /// Authenticate and authorize `presented` for `method path` on cell
    /// `cell_id`. A per-tenant (`nct1.`) token is verified against the
    /// path's `{t}` and this cell only; any other token goes through
    /// [`Tokens::check`]. `Ok` carries the scope and whether it was the
    /// previous (grace-window) query token. Wake roles and detection-gate
    /// writes are checked by the handler ([`permits_wake`],
    /// [`permits_detect_call`]).
    pub fn authorize(
        &self,
        presented: Option<&str>,
        method: &Method,
        path: &str,
        cell_id: &str,
        accept_cluster_query: bool,
        now: Instant,
    ) -> Result<(Scope, bool), Deny> {
        use crate::tenant_token::{is_tenant_token, TenantScope};
        let route = classify(method, path);
        if let Some(token) = presented.filter(|p| is_tenant_token(p)) {
            let Some(tenant) = path_tenant(path) else {
                return Err(Deny::Forbidden("a per-tenant router token reaches only its own tenant's routes"));
            };
            let Some(key) = &self.tenant_key else {
                return Err(Deny::Unauthorized);
            };
            let scope = match key.bearer_scope(token, tenant, cell_id) {
                Some(TenantScope::Query) => Scope::TenantQuery,
                Some(TenantScope::Detect) => Scope::TenantDetect,
                Some(TenantScope::Status) => Scope::TenantStatus,
                Some(TenantScope::Job) | None => {
                    return Err(Deny::Forbidden("the router token is not valid for this tenant on this cell"))
                }
            };
            if !admits_with(scope, route, accept_cluster_query) {
                return Err(Deny::Forbidden("this per-tenant token's scope does not reach this route"));
            }
            return Ok((scope, false));
        }
        let (scope, previous) = self.check(presented, now).ok_or(Deny::Unauthorized)?;
        if !admits_with(scope, route, accept_cluster_query) {
            return Err(Deny::Forbidden("this router token does not reach this route"));
        }
        Ok((scope, previous))
    }

    /// Scope of `presented`, and whether it was the previous query token.
    /// Every comparison runs every time (constant time, no early exit).
    pub fn check(&self, presented: Option<&str>, now: Instant) -> Option<(Scope, bool)> {
        let live_prev = self.previous.as_ref().filter(|(_, until)| now < *until).map(|(p, _)| p.as_str());
        let live_alerts_prev = self.alerts_previous.as_ref().filter(|(_, until)| now < *until).map(|(p, _)| p.as_str());
        let prev_hit = match (presented, live_prev) {
            (Some(g), Some(p)) => bool::from(g.as_bytes().ct_eq(p.as_bytes())) & !p.is_empty(),
            _ => false,
        };
        let alerts_hit = presented.is_some_and(|g| self.alerts.as_ref().is_some_and(|a|
            bool::from(g.as_bytes().ct_eq(a.as_bytes())) && !a.is_empty()));
        let alerts_prev_hit = presented.is_some_and(|g| live_alerts_prev.is_some_and(|a|
            bool::from(g.as_bytes().ct_eq(a.as_bytes())) && !a.is_empty()));
        match authenticate(presented, &self.full, self.query.as_ref().map(|q| q.as_str())) {
            Some(s) => Some((s, false)),
            None if prev_hit => Some((Scope::Query, true)),
            None if alerts_hit => Some((Scope::AlertsRead, false)),
            None if alerts_prev_hit => Some((Scope::AlertsRead, true)),
            None => None,
        }
    }

    pub fn digests(&self, now: Instant) -> TokenDigests {
        let live = self.previous.as_ref().filter(|(_, until)| now < *until);
        let alerts_live = self.alerts_previous.as_ref().filter(|(_, until)| now < *until);
        TokenDigests {
            full: token_digest(&self.full),
            query: self.query.as_ref().map(|q| token_digest(q)),
            query_previous: live.map(|(p, _)| token_digest(p)),
            query_previous_expires_in_secs: live.map(|(_, until)| until.duration_since(now).as_secs()),
            alerts: self.alerts.as_ref().map(|a| token_digest(a)),
            alerts_previous: alerts_live.map(|(a, _)| token_digest(a)),
            alerts_previous_expires_in_secs: alerts_live.map(|(_, until)| until.duration_since(now).as_secs()),
        }
    }
}

pub struct Router {
    sup: Arc<Supervisor>,
    tokens: RwLock<Tokens>,
    /// Last time a use of the previous query token was logged.
    prev_logged: std::sync::Mutex<Option<Instant>>,
    /// Set by [`Router::close`]: the listeners stop accepting and every open
    /// connection finishes its in-flight request, then closes.
    closing: tokio::sync::watch::Sender<bool>,
    /// Accepted connections not yet closed.
    open_conns: std::sync::atomic::AtomicUsize,
}

fn full(status: StatusCode, ctype: &'static str, body: impl Into<Bytes>) -> Response<Body> {
    let mut r = Response::new(Full::new(body.into()).map_err(|never| match never {}).boxed());
    *r.status_mut() = status;
    r.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static(ctype));
    r
}

fn json(status: StatusCode, v: &impl serde::Serialize) -> Response<Body> {
    full(status, "application/json", serde_json::to_vec(v).unwrap_or_default())
}

fn error(status: StatusCode, msg: &str) -> Response<Body> {
    json(status, &serde_json::json!({ "error": msg }))
}

fn cell_error(e: CellError) -> Response<Body> {
    match e {
        CellError::NotPlaced(_) => error(StatusCode::NOT_FOUND, &e.to_string()),
        CellError::Spawn(_) | CellError::Unavailable(_) => error(StatusCode::SERVICE_UNAVAILABLE, &e.to_string()),
        CellError::Standby(_) => {
            let mut r = json(StatusCode::SERVICE_UNAVAILABLE, &serde_json::json!({"error": e.to_string(), "reason": "writer_standby"}));
            r.headers_mut().insert(hyper::header::RETRY_AFTER, HeaderValue::from_static("1"));
            r
        }
        CellError::AdmissionRefused { retry_after_secs, .. } => {
            let mut r = json(StatusCode::SERVICE_UNAVAILABLE, &serde_json::json!({
                "error": e.to_string(), "reason": "pooled_admission_refused", "retry_after_secs": retry_after_secs,
            }));
            if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                r.headers_mut().insert(hyper::header::RETRY_AFTER, v);
            }
            r
        }
        CellError::SpawnBlocked { role, status, ref code, retry_after_secs } => {
            let mut r = json(StatusCode::SERVICE_UNAVAILABLE, &serde_json::json!({
                "error": e.to_string(), "reason": "role_spawn_blocked", "role": role,
                "refusal": code, "refusal_status": status, "retry_after_secs": retry_after_secs,
            }));
            if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                r.headers_mut().insert(hyper::header::RETRY_AFTER, v);
            }
            r
        }
        // NAN-3523: over the soft disk ceiling; the caller retries and the
        // backlog stays queued upstream (no data is dropped).
        CellError::DiskPressure { bytes, soft_bytes, retry_after_secs } => {
            let mut r = json(StatusCode::SERVICE_UNAVAILABLE, &serde_json::json!({
                "error": e.to_string(), "reason": "tenant_disk_pressure", "bytes": bytes, "soft_bytes": soft_bytes,
                "retry_after_secs": retry_after_secs,
            }));
            if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                r.headers_mut().insert(hyper::header::RETRY_AFTER, v);
            }
            r
        }
    }
}

/// Largest accepted `POST /v1/tenants/{t}/wake` body.
const WAKE_BODY_LIMIT: usize = 4096;
/// Largest durable-job spec the router buffers to verify (query[T]'s own
/// request body limit).
const JOB_SPEC_BODY_LIMIT: usize = 1024 * 1024;

fn presented(req: &Request<Incoming>) -> Option<&str> {
    req.headers().get(AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|h| h.strip_prefix("Bearer "))
}

#[derive(Deserialize)]
struct WakeBody {
    role: Role,
    reason: WakeReason,
}

impl Router {
    pub fn new(sup: Arc<Supervisor>) -> anyhow::Result<Arc<Self>> {
        let r = Arc::new(Self {
            sup,
            tokens: RwLock::new(Tokens::default()),
            prev_logged: Default::default(),
            closing: tokio::sync::watch::Sender::new(false),
            open_conns: std::sync::atomic::AtomicUsize::new(0),
        });
        r.reload_token()?;
        Ok(r)
    }

    /// Re-read the token files (rotation without restart). All are read
    /// and checked before either is swapped in; equal tokens are refused
    /// (at startup that stops the cell).
    pub fn reload_token(&self) -> anyhow::Result<()> {
        let cfg = self.sup.config();
        let full = read_token(&cfg.router_token_file, false)?;
        let query = match &cfg.router_query_token_file {
            Some(p) => Some(read_token(p, true)?),
            None => None,
        };
        let alerts = match &cfg.router_alerts_token_file {
            Some(p) => Some(read_alerts_token(p)?),
            None => None,
        };
        let grace = Duration::from_secs(cfg.router_query_token_grace_secs);
        let alerts_grace = Duration::from_secs(cfg.router_alerts_token_grace_secs);
        self.tokens.write().unwrap().rotate(full, query, alerts, Instant::now(), grace, alerts_grace)
    }

    /// Digests of the loaded tokens (for `/healthz`).
    pub fn token_digests(&self) -> TokenDigests {
        self.tokens.read().unwrap().digests(Instant::now())
    }

    fn scope(&self, req: &Request<Incoming>) -> Option<Scope> {
        let now = Instant::now();
        let (scope, previous) = self.tokens.read().unwrap().check(presented(req), now)?;
        self.note_previous(req, previous, now);
        Some(scope)
    }

    /// [`Tokens::authorize`] for this request on this cell.
    fn authorize(&self, req: &Request<Incoming>) -> Result<Scope, Deny> {
        let now = Instant::now();
        let cfg = self.sup.config();
        let (scope, previous) = self.tokens.read().unwrap().authorize(
            presented(req), req.method(), req.uri().path(), &cfg.cell_id, cfg.router_accept_cluster_query_token, now)?;
        self.note_previous(req, previous, now);
        if scope == Scope::Query && cfg.router_accept_cluster_query_token
            && !permits_with(scope, classify(req.method(), req.uri().path()), false)
        {
            // NAN-3289: who still needs the legacy reach before the flip.
            tracing::debug!(path = %req.uri().path(), "cluster query token used on a tenant route (legacy reach)");
        }
        Ok(scope)
    }

    fn note_previous(&self, req: &Request<Incoming>, previous: bool, now: Instant) {
        if previous {
            let mut last = self.prev_logged.lock().unwrap();
            if last.is_none_or(|t| now.duration_since(t) >= Duration::from_secs(60)) {
                *last = Some(now);
                tracing::warn!(path = %req.uri().path(),
                    "request authenticated with a PREVIOUS router token (grace window); caller not rolled yet");
            }
        }
    }

    /// Whether responses must end their connection: the pod is draining
    /// (readiness withdrawn, see [`Supervisor::draining`]) or the router is
    /// closing.
    pub fn closes_connections(&self) -> bool {
        self.sup.draining() || *self.closing.borrow()
    }

    /// Connections accepted and not yet closed.
    pub fn open_connections(&self) -> usize {
        self.open_conns.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Stop accepting, let every open connection finish the request it is
    /// serving (an idle keep-alive connection closes at once), and wait up
    /// to `within` for them. Returns the connections still open. Called at
    /// the end of the drain, BEFORE the tenant processes stop: a request on
    /// a keep-alive connection pinned to this pod then never meets a
    /// stopped cell (503) or a socket torn down by process exit (reset, seen
    /// by the caller as a 502).
    pub async fn close(&self, within: Duration) -> usize {
        self.closing.send_replace(true);
        let deadline = Instant::now() + within;
        while self.open_connections() > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        self.open_connections()
    }

    /// Serve one request: [`Router::route`], plus `Connection: close` while
    /// the pod drains so the caller's pooled connection is retired cleanly
    /// after this response instead of being reset later.
    pub async fn handle(self: Arc<Self>, req: Request<Incoming>) -> Result<Response<Body>, hyper::Error> {
        let mut resp = self.clone().route(req).await?;
        if self.closes_connections() {
            resp.headers_mut().insert(hyper::header::CONNECTION, HeaderValue::from_static("close"));
        }
        Ok(resp)
    }

    async fn route(self: Arc<Self>, req: Request<Incoming>) -> Result<Response<Body>, hyper::Error> {
        let path = req.uri().path().to_owned();
        let method = req.method().clone();
        if path == "/healthz" {
            // Health is normally public, but a presented alerts token is
            // explicitly forbidden here, including during its grace window.
            let scope = self.scope(&req);
            if scope == Some(Scope::AlertsRead) {
                return Ok(error(StatusCode::FORBIDDEN, "alerts-read token does not reach this route"));
            }
            let s = self.sup.status();
            let mut body = serde_json::json!({
                "status": "ok",
                "cell_id": s.cell_id,
                "limits_mode": s.limits_mode,
                // NAN-2993: whether the kernel really enforces limits.
                "enforcement": s.enforcement,
                "enforcement_reason": s.enforcement_reason,
                "unenforced_secs": s.unenforced_secs,
                // NAN-3523: `refused_unenforced` on a pooled cell without kernel limits.
                "admission": s.admission,
                "role_budgets": s.role_budgets,
                "landlock_abi": s.landlock_abi,
                "cell_features": crate::features::CELL_FEATURES,
                // NAN-3523: supervisor OOM ordering and cgroup reserve.
                "supervisor_reserve": s.supervisor_reserve,
            });
            stamp_build_version(&mut body);
            // NAN-3440: the upstream verdict is a SIGNAL only (never readiness:
            // a cluster-wide R2/control outage must not drop every cell's
            // endpoints; stale-but-serving beats an outage). Only the boolean
            // is public (no targets, URLs or errors); the platform's egress
            // controller reads it as the ingest-stall corroboration.
            if let Some(v) = self.sup.upstream_verdict() {
                body["upstream_ready"] = v.ready.into();
            }
            // NAN-3289 P3-2: token digests (a leaked-token confirmation
            // oracle) and tenant counts only for the full or cluster query
            // token; the unauthenticated liveness view carries neither.
            if healthz_shows_private(scope) {
                body["tenants_placed"] = s.tenants.len().into();
                body["tenants_running"] = s.tenants.iter().filter(|t| !t.processes.is_empty()).count().into();
                // sha256 prefixes only, so a probe can confirm a rotation.
                body["router_tokens"] = serde_json::to_value(self.token_digests()).unwrap_or_default();
            }
            return Ok(json(StatusCode::OK, &body));
        }
        if path == "/readyz" {
            // NAN-3004: the Service sends traffic here only when this is
            // 200. A single-pod cell (no `zero_downtime_roll`) is always ready.
            if self.scope(&req) == Some(Scope::AlertsRead) {
                return Ok(error(StatusCode::FORBIDDEN, "alerts-read token does not reach this route"));
            }
            let ready = self.sup.ready();
            let body = match self.sup.handover() {
                Some(h) => serde_json::json!({
                    "ready": ready,
                    "phase": h.phase(),
                    "warm": h.warm(),
                    "warm_pending": h.warm_pending().len(),
                }),
                None => serde_json::json!({"ready": ready}),
            };
            return Ok(json(if ready { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE }, &body));
        }
        let authz = self.authorize(&req);
        if path == "/metrics" && self.sup.config().metrics_public {
            let scope = authz.ok();
            if scope == Some(Scope::AlertsRead) {
                return Ok(error(StatusCode::FORBIDDEN, "alerts-read token does not reach this route"));
            }
            // Unauthenticated: cell-level series only; the per-tenant view
            // needs the full token.
            let full_view = scope == Some(Scope::Full);
            return Ok(full(StatusCode::OK, "text/plain; version=0.0.4", self.sup.metrics(full_view)));
        }
        let accept_cluster_query = self.sup.config().router_accept_cluster_query_token;
        let scope = match authz {
            Ok(scope) => scope,
            Err(Deny::Unauthorized) => return Ok(error(StatusCode::UNAUTHORIZED, "unauthorized")),
            Err(Deny::Forbidden(why)) => return Ok(error(StatusCode::FORBIDDEN, why)),
        };
        match (method.clone(), path.as_str()) {
            (Method::GET, "/metrics") => return Ok(full(StatusCode::OK, "text/plain; version=0.0.4", self.sup.metrics(true))),
            (Method::GET, "/v1/status") => return Ok(json(StatusCode::OK, &self.sup.status())),
            (Method::GET, "/v1/signals") => return Ok(json(StatusCode::OK, &self.sup.signals())),
            (Method::GET, "/v1/handover") => {
                return Ok(match self.sup.handover_view() {
                    Some(v) => json(StatusCode::OK, &v),
                    None => error(StatusCode::NOT_FOUND, "zero_downtime_roll is not configured"),
                })
            }
            (Method::GET, "/v1/lean-cell-alerts") => return Ok(json(StatusCode::OK,
                &crate::signals::LeanCellAlertFeed::from_signals(&self.sup.config().cell_id, self.sup.alert_signals()))),
            _ => {}
        }
        let Some(rest) = path.strip_prefix("/v1/tenants/") else {
            return Ok(error(StatusCode::NOT_FOUND, "not found"));
        };
        let (tenant, tail) = rest.split_once('/').unwrap_or((rest, ""));
        let tenant = match TenantId::new(tenant) {
            Ok(t) => t,
            Err(e) => return Ok(error(StatusCode::BAD_REQUEST, &e.to_string())),
        };
        match (method, tail) {
            (Method::POST, "landing") => {
                // Only fixed scalar queries are accepted here, including when the legacy
                // cluster query token can no longer execute arbitrary tenant searches.
                let bytes = match http_body_util::Limited::new(req.into_body(), 4096)
                    .collect()
                    .await
                {
                    Ok(b) => b.to_bytes(),
                    Err(_) => return Ok(error(StatusCode::BAD_REQUEST, "invalid landing request")),
                };
                let payload = match landing_query(&tenant, &bytes) {
                    Ok(p) => p,
                    Err(()) => {
                        return Ok(error(StatusCode::BAD_REQUEST, "invalid landing request"))
                    }
                };
                let req = Request::builder()
                    .method(Method::POST)
                    .uri("/v1/query")
                    .header(CONTENT_TYPE, "application/json")
                    .body(
                        Full::new(Bytes::from(payload.to_string()))
                            .map_err(|never| match never {})
                            .boxed(),
                    )
                    .expect("fixed landing request");
                self.forward(
                    tenant,
                    Role::Query,
                    "/v1/query".into(),
                    req,
                    None,
                    None,
                    false,
                )
                .await
            }
            (Method::POST | Method::GET, "admin/count-backfill") => {
                if scope != Scope::Full {
                    return Ok(error(StatusCode::FORBIDDEN, "count backfill requires the full operator token"));
                }
                self.forward(tenant, Role::Ingest, "/v1/admin/count-backfill".into(), req.map(|body| body.boxed()), None, None, true).await
            }
            // NAN-3864: operator restamp of hours ingested unstamped.
            (Method::POST | Method::GET, "admin/prevalence-restamp") => {
                if scope != Scope::Full {
                    return Ok(error(StatusCode::FORBIDDEN, "prevalence restamp requires the full operator token"));
                }
                self.forward(tenant, Role::Ingest, "/v1/admin/prevalence-restamp".into(), req.map(|body| body.boxed()), None, None, true).await
            }
            (Method::POST, "wake") => {
                // `{"role","reason"}` is tiny; the query-only token now reaches
                // this route, so never buffer an unbounded body for it.
                let body = match http_body_util::Limited::new(req.into_body(), WAKE_BODY_LIMIT).collect().await {
                    Ok(b) => b.to_bytes(),
                    Err(e) if e.is::<http_body_util::LengthLimitError>() => {
                        return Ok(error(StatusCode::PAYLOAD_TOO_LARGE, "wake body too large"))
                    }
                    Err(_) => return Ok(error(StatusCode::BAD_REQUEST, "unreadable wake body")),
                };
                let Ok(w) = serde_json::from_slice::<WakeBody>(&body) else {
                    return Ok(error(StatusCode::BAD_REQUEST, "want {\"role\":..,\"reason\":..}"));
                };
                if !permits_wake(scope, w.role) {
                    return Ok(error(StatusCode::FORBIDDEN, "the query-only token may wake only the query role"));
                }
                Ok(match self.sup.wake(&tenant, w.role, w.reason).await {
                    Ok(pid) => json(StatusCode::OK, &serde_json::json!({"tenant_id": tenant, "role": w.role, "pid": pid})),
                    Err(e) => cell_error(e),
                })
            }
            (Method::POST, "drain") => {
                let found = self.sup.drain(&tenant);
                Ok(json(StatusCode::OK, &serde_json::json!({"tenant_id": tenant, "draining": found})))
            }
            (Method::GET, "status") => {
                // NAN-3289 P3-1: one tenant's view, never its co-tenants.
                let s = self.sup.status();
                Ok(match s.tenants.into_iter().find(|t| t.tenant_id == tenant) {
                    Some(t) => json(StatusCode::OK, &serde_json::json!({"cell_id": s.cell_id, "tenant": t})),
                    None => error(StatusCode::NOT_FOUND, "tenant is not placed on this cell"),
                })
            }
            (method, t) if t == "query" || t.starts_with("query/") => {
                let sub = t.strip_prefix("query").unwrap_or("");
                let sub = if sub.is_empty() { "/" } else { sub };
                if query_route_forbidden(sub) {
                    return Ok(error(StatusCode::FORBIDDEN, "detection state requires the detect route"));
                }
                if !permits_query_call(scope, sub) {
                    return Ok(error(StatusCode::FORBIDDEN, "operator probes need the full or cluster query token"));
                }
                if method == Method::POST && sub == JOB_SEARCH_PATH {
                    // NAN-3289 P2-2: verify the spec's signature here, so
                    // query[T] takes retention and deny scope only from a
                    // spec its tenant's dispatcher signed.
                    let (parts, body) = req.into_parts();
                    let signature = parts.headers.get(crate::tenant_token::JOB_SIGNATURE_HEADER)
                        .and_then(|v| v.to_str().ok()).map(str::to_owned);
                    let bytes = match http_body_util::Limited::new(body, JOB_SPEC_BODY_LIMIT).collect().await {
                        Ok(b) => b.to_bytes(),
                        Err(e) if e.is::<http_body_util::LengthLimitError>() => {
                            return Ok(error(StatusCode::PAYLOAD_TOO_LARGE, "job spec too large"))
                        }
                        Err(_) => return Ok(error(StatusCode::BAD_REQUEST, "unreadable job spec")),
                    };
                    let key = self.tokens.read().unwrap().tenant_key().cloned();
                    let admitted = job_spec_decision(key.as_ref(), tenant.as_str(), &self.sup.config().cell_id, &bytes,
                        signature.as_deref(), accept_cluster_query);
                    let auth = match admitted {
                        Ok(auth) => auth,
                        Err(why) => return Ok(error(StatusCode::FORBIDDEN, why)),
                    };
                    if auth == crate::tenant_token::JOB_AUTH_LEGACY {
                        tracing::warn!(tenant = %tenant, "unsigned durable-job spec admitted (legacy; router_accept_cluster_query_token is on)");
                    }
                    let req = Request::from_parts(parts, Full::new(bytes).map_err(|never| match never {}).boxed());
                    return self.forward(tenant, Role::Query, sub.to_owned(), req, None, Some(auth), false).await;
                }
                let operator_debug = is_operator_debug(sub);
                self.forward(tenant, Role::Query, sub.to_owned(), req.map(|b| b.boxed()), None, None, operator_debug).await
            }
            (_, t) if t == "detect" || t.starts_with("detect/") => {
                let sub = t.strip_prefix("detect").unwrap_or("");
                let sub = if sub.is_empty() { "/" } else { sub };
                if !permits_detect_call(scope, sub, accept_cluster_query) {
                    // P2-1 / P3-3: checked before the wake, so a refused
                    // caller cannot spawn detect[T] either.
                    return Ok(error(StatusCode::FORBIDDEN, "moving a detection watermark requires the tenant's detect token"));
                }
                // Wake detect first so a due schedule cannot silently run
                // without its finding drain. NAN-3047: a detect[T] assigned
                // `detect_runs_rules` then serves the request itself (rule
                // searches, gate, prevalence) under detect's own budget;
                // otherwise (legacy) the read/plan RPC goes to query[T].
                let reason = if matches!(sub.trim_end_matches('/'), DETECTION_COMMIT_PATH | DETECTION_RESET_PATH) {
                    crate::contract::WakeReason::Detection
                } else {
                    crate::contract::WakeReason::Query
                };
                // NAN-3004: on a standby pod (the writer is on the other pod
                // of a roll), wait a bounded time for it to move here.
                let wait = self.sup.handover().map_or(Duration::ZERO, |h| Duration::from_secs(h.cfg.standby_request_wait_secs));
                let deadline = Instant::now() + wait;
                loop {
                    match self.sup.wake(&tenant, Role::Detect, reason).await {
                        Ok(_) => break,
                        Err(CellError::Standby(_))
                            if Instant::now() < deadline && !self.sup.handover().is_some_and(|h| h.draining()) =>
                        {
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        }
                        Err(error) => return Ok(cell_error(error)),
                    }
                }
                let detect_guard = match self.sup.hold_inflight(&tenant, Role::Detect).await {
                    Ok(guard) => guard,
                    Err(error) => return Ok(cell_error(error)),
                };
                let req = req.map(|b| b.boxed());
                match detect_target(detect_guard.runs_rules()) {
                    // The RPC's own guard keeps detect in flight.
                    Role::Detect => self.forward(tenant, Role::Detect, sub.to_owned(), req, None, None, false).await,
                    role => self.forward(tenant, role, sub.to_owned(), req, Some(detect_guard), None, false).await,
                }
            }
            _ => Ok(error(StatusCode::NOT_FOUND, "not found")),
        }
    }

    async fn forward(&self, tenant: TenantId, role: Role, sub: String, req: Request<Body>, related_guard: Option<InflightGuard>,
        job_auth: Option<&'static str>, operator_debug: bool) -> Result<Response<Body>, hyper::Error> {
        let started = std::time::Instant::now();
        let (guard, request_id, stream) = match self.sup.open_rpc(&tenant, role).await {
            Ok(x) => x,
            Err(e) => return Ok(cell_error(e)),
        };
        // NAN-3795: only real searches make a count backfill yield.
        let search_guard = if role == Role::Query && crate::supervisor::is_search_rpc(&sub) { self.sup.begin_search(&tenant) } else { None };
        let (mut parts, body) = req.into_parts();
        let pq = match parts.uri.query() {
            Some(q) => format!("{sub}?{q}"),
            None => sub,
        };
        parts.uri = match pq.parse() {
            Ok(u) => u,
            Err(_) => return Ok(error(StatusCode::BAD_REQUEST, "bad path")),
        };
        // Never forward the router credential to a tenant process. Only the
        // query route, past `permits_query_call`, stamps an operator probe.
        sanitize_forward_headers(&mut parts.headers, job_auth, operator_debug);
        parts.headers.insert("x-nano-cell-tenant", HeaderValue::from_str(tenant.as_str()).expect("validated"));
        parts.headers.insert("x-nano-cell-request-id", HeaderValue::from(request_id));
        let req = Request::from_parts(parts, body);
        let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(stream)).await {
            Ok(x) => x,
            Err(e) => return Ok(error(StatusCode::BAD_GATEWAY, &format!("tenant handshake: {e}"))),
        };
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let resp = match sender.send_request(req).await {
            Ok(r) => r,
            Err(e) => return Ok(error(StatusCode::BAD_GATEWAY, &format!("tenant rpc: {e}"))),
        };
        // The request stays "in flight" (no idle reap) until the response
        // body has been fully sent or dropped.
        let recorder = (role == Role::Query).then(|| (self.sup.clone(), tenant, started));
        Ok(resp.map(|b| GuardedBody { inner: b, _guard: guard, _related_guard: related_guard, _search_guard: search_guard, recorder }.boxed()))
    }
}

/// Which process serves a `/v1/tenants/{t}/detect/...` request, given
/// whether the tenant's running detect[T] runs rule searches itself.
pub fn detect_target(detect_runs_rules: bool) -> Role {
    if detect_runs_rules { Role::Detect } else { Role::Query }
}

/// NAN-3715: query[T] sub-paths for operator probes (`/v1/debug/sql-probe`).
pub const OPERATOR_DEBUG_PREFIX: &str = "/v1/debug/";
/// Set by the router (never by a caller: stripped on every forward) on a
/// [`OPERATOR_DEBUG_PREFIX`] request it admitted with an operator scope.
pub const OPERATOR_DEBUG_HEADER: &str = "x-nano-cell-operator-debug";
/// The one value of [`OPERATOR_DEBUG_HEADER`].
pub const OPERATOR_DEBUG_ADMITTED: &str = "admitted";

/// May `scope` call the query sub-path `sub`? Operator probes take the full
/// token or the cluster query token (the credentials nanosiem-search and
/// operators hold inside the cluster), never a per-tenant token.
pub fn permits_query_call(scope: Scope, sub: &str) -> bool {
    !is_operator_debug(sub) || matches!(scope, Scope::Full | Scope::Query)
}

/// Whether `sub` (below `/v1/tenants/{t}/query`) is an operator probe.
pub fn is_operator_debug(sub: &str) -> bool {
    let sub = sub.split('?').next().unwrap_or(sub);
    sub.starts_with(OPERATOR_DEBUG_PREFIX) || sub.trim_end_matches('/') == OPERATOR_DEBUG_PREFIX.trim_end_matches('/')
}

/// The headers a tenant process receives: never the router credential or
/// a caller's claim of how the router admitted the request.
pub fn sanitize_forward_headers(headers: &mut hyper::HeaderMap, job_auth: Option<&'static str>, operator_debug: bool) {
    headers.remove(AUTHORIZATION);
    headers.remove(hyper::header::PROXY_AUTHORIZATION);
    headers.remove(hyper::header::COOKIE);
    // Only the router says how a job spec was admitted (NAN-3289 P2-2).
    headers.remove(crate::tenant_token::JOB_AUTH_HEADER);
    headers.remove(crate::tenant_token::JOB_SIGNATURE_HEADER);
    headers.remove(OPERATOR_DEBUG_HEADER);
    if let Some(auth) = job_auth {
        headers.insert(crate::tenant_token::JOB_AUTH_HEADER, HeaderValue::from_static(auth));
    }
    if operator_debug {
        headers.insert(OPERATOR_DEBUG_HEADER, HeaderValue::from_static(OPERATOR_DEBUG_ADMITTED));
    }
}

/// query[T]'s durable-job dispatch route.
pub const JOB_SEARCH_PATH: &str = "/v1/jobs/search";

/// NAN-3518: the build this cell runs, on the public `/healthz` view, so an
/// operator can confirm a roll landed without a token (the version is not a
/// secret, unlike the token digests below).
fn stamp_build_version(body: &mut serde_json::Value) {
    body["version"] = env!("CARGO_PKG_VERSION").into();
}

/// Whether `/healthz` adds token digests and tenant counts (NAN-3289 P3-2).
pub fn healthz_shows_private(scope: Option<Scope>) -> bool {
    matches!(scope, Some(Scope::Full | Scope::Query))
}

fn query_route_forbidden(path: &str) -> bool {
    path == "/v1/detections" || path.starts_with("/v1/detections/")
}

/// A response body that holds the process's in-flight guard.
struct GuardedBody {
    inner: Incoming,
    _guard: InflightGuard,
    _related_guard: Option<InflightGuard>,
    _search_guard: Option<SearchGuard>,
    recorder: Option<(Arc<Supervisor>, TenantId, std::time::Instant)>,
}

impl Drop for GuardedBody {
    fn drop(&mut self) {
        if let Some((supervisor, tenant, started)) = self.recorder.take() {
            supervisor.observe_query_duration(&tenant, started.elapsed().as_secs_f64());
        }
    }
}

impl hyper::body::Body for GuardedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, hyper::Error>>> {
        std::pin::Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Counts an accepted connection until it closes.
struct OpenConn(Arc<Router>);

impl OpenConn {
    fn new(r: &Arc<Router>) -> Self {
        r.open_conns.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(r.clone())
    }
}

impl Drop for OpenConn {
    fn drop(&mut self) {
        self.0.open_conns.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Serve one accepted connection (HTTP/1.1 keep-alive). When the router
/// closes, hyper's graceful shutdown lets the in-flight request (if any)
/// finish and then closes; an idle connection closes at once.
async fn serve_conn<IO>(router: Arc<Router>, io: IO)
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let _open = OpenConn::new(&router);
    let mut closing = router.closing.subscribe();
    let r = router.clone();
    let svc = hyper::service::service_fn(move |req| r.clone().handle(req));
    let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, svc);
    let mut conn = std::pin::pin!(conn);
    tokio::select! {
        _ = conn.as_mut() => return,
        _ = closing.wait_for(|c| *c) => {}
    }
    conn.as_mut().graceful_shutdown();
    let _ = conn.await;
}

/// Resolves once the router is closing.
async fn until_closing(router: &Router) {
    let mut rx = router.closing.subscribe();
    let _ = rx.wait_for(|c| *c).await;
}

/// Serve the router on a TCP listener until [`Router::close`].
pub async fn serve_tcp(router: Arc<Router>, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    loop {
        let (stream, _) = tokio::select! {
            r = listener.accept() => r?,
            _ = until_closing(&router) => return Ok(()),
        };
        tokio::spawn(serve_conn(router.clone(), TokioIo::new(stream)));
    }
}

/// Serve the router on a unix listener, refusing tenant uids by
/// SO_PEERCRED, until [`Router::close`].
pub async fn serve_unix(router: Arc<Router>, listener: tokio::net::UnixListener) -> std::io::Result<()> {
    loop {
        let (stream, _) = tokio::select! {
            r = listener.accept() => r?,
            _ = until_closing(&router) => return Ok(()),
        };
        let uid = stream.peer_cred().map(|c| c.uid()).ok();
        if uid.is_none_or(|u| router.sup.is_tenant_uid(u)) {
            tracing::warn!(?uid, "refusing router connection from a tenant uid");
            continue;
        }
        tokio::spawn(serve_conn(router.clone(), TokioIo::new(stream)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_backfill_is_operator_only_for_every_tenant() {
        for (method, admin) in [Method::GET, Method::POST].into_iter()
            .flat_map(|method| ["count-backfill", "prevalence-restamp"].map(|admin| (method.clone(), admin))) {
            for tenant in ["00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"] {
                let path = format!("/v1/tenants/{tenant}/admin/{admin}");
                let route = classify(&method, &path);
                assert!(admits(Scope::Full, route));
                for scope in [Scope::Query, Scope::AlertsRead, Scope::TenantQuery, Scope::TenantDetect, Scope::TenantStatus] {
                    assert!(!admits(scope, route), "{scope:?} reached {path}");
                }
            }
        }
    }

    const FULL: &str = "full-router-token-0123456789abcdef0123456789";
    const QUERY: &str = "query-router-token-0123456789abcdef012345678";

    /// NAN-3523: a refused pooled admission is retryable (the upstream
    /// queues), never a 4xx.
    #[tokio::test]
    async fn pooled_admission_refused_is_a_retryable_503() {
        let r = cell_error(CellError::AdmissionRefused { reason: "cgroup delegation not adopted yet".into(), retry_after_secs: 5 });
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r.headers().get(hyper::header::RETRY_AFTER).unwrap(), "5");
        let body = r.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["reason"], "pooled_admission_refused");
        assert_eq!(v["retry_after_secs"], 5);
    }

    #[tokio::test]
    async fn spawn_blocked_is_a_503_with_the_refusal_code_and_retry_after() {
        let r = cell_error(CellError::SpawnBlocked {
            role: crate::contract::Role::Detect, status: 403, code: "detect_drain_disabled".into(), retry_after_secs: 64,
        });
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r.headers().get(hyper::header::RETRY_AFTER).unwrap(), "64");
        let body = r.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["reason"], "role_spawn_blocked");
        assert_eq!(v["role"], "detect");
        assert_eq!(v["refusal"], "detect_drain_disabled");
        assert_eq!(v["refusal_status"], 403);
    }

    /// NAN-3523: a tenant over its soft disk ceiling gets a retryable 503
    /// on ingest admission, never a drop.
    #[tokio::test]
    async fn disk_pressure_is_a_retryable_503() {
        let r = cell_error(CellError::DiskPressure { bytes: 10, soft_bytes: 9, retry_after_secs: 30 });
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(r.headers().get(hyper::header::RETRY_AFTER).unwrap(), "30");
        let body = r.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["reason"], "tenant_disk_pressure");
        assert_eq!(v["soft_bytes"], 9);
    }

    /// NAN-3047: with `detect_runs_rules`, no `/detect/...` request (rule
    /// search, gate, prevalence, status) is served by query[T]; a tenant on
    /// a legacy detect budget keeps the query[T] path.
    #[test]
    fn detect_searches_never_reach_query_when_detect_runs_rules() {
        use crate::budget::{GIB, MIB};
        let t = TenantId::new("t1").unwrap();
        let sized = |detect_bytes: u64| crate::config::TenantPlacement {
            detect_request_millicores: Some(250), detect_limit_millicores: Some(1_000),
            detect_request_memory_bytes: Some(512 * MIB), detect_limit_memory_bytes: Some(detect_bytes),
            ingest_request_millicores: Some(400), ingest_limit_millicores: Some(2_000),
            ingest_request_memory_bytes: Some(2 * GIB), ingest_limit_memory_bytes: Some(3 * GIB),
            query_request_millicores: Some(250), query_limit_millicores: Some(3_000),
            query_request_memory_bytes: Some(256 * MIB), query_limit_memory_bytes: Some(3 * GIB),
            ..crate::config::TenantPlacement::legacy(t.clone(), 300.0)
        };
        for sub in ["/v1/query", "/v1/prevalence/lookup", "/v1/detections/plan", "/v1/detections/commit",
            "/v1/risk", "/v1/status", "/"] {
            let path = format!("/v1/tenants/t1/detect{sub}");
            assert_eq!(classify(&Method::POST, &path), RouteClass::Detect, "{path}");
            // The mode the supervisor assigns detect[T] is the mode routed.
            let runs = sized(3 * GIB / 2).detect_runs_rules(true);
            assert!(runs);
            assert_eq!(detect_target(runs), Role::Detect, "{path}");
            assert_ne!(detect_target(runs), Role::Query, "{path}");
        }
        // Cell flag off, or a detect budget that cannot hold the engine: legacy.
        assert!(!sized(3 * GIB / 2).detect_runs_rules(false));
        assert!(!sized(256 * MIB).detect_runs_rules(true));
        assert!(!sized(GIB).detect_runs_rules(true), "below the 1.5 GiB engine floor");
        assert!(sized(2 * GIB).detect_runs_rules(true), "the proposed 300 eps budget");
        assert!(!crate::config::TenantPlacement::legacy(t, 300.0).detect_runs_rules(true));
        assert_eq!(detect_target(false), Role::Query);
    }

    #[test]
    fn detection_gate_is_reachable_only_through_the_detect_route() {
        for path in ["/v1/detections", "/v1/detections/plan", "/v1/detections/commit",
            "/v1/detections/commit/"] {
            assert!(query_route_forbidden(path), "{path}");
        }
        for path in ["/v1/query", "/v1/risk", "/v1/detection", "/v1/status"] {
            assert!(!query_route_forbidden(path), "{path}");
        }
    }

    /// Every route the router serves (and a few it does not).
    fn routes() -> Vec<(Method, &'static str, RouteClass)> {
        vec![
            (Method::GET, "/healthz", RouteClass::Health),
            (Method::GET, "/readyz", RouteClass::Health),
            (Method::GET, "/v1/handover", RouteClass::Handover),
            (Method::POST, "/v1/handover", RouteClass::Other),
            (Method::GET, "/metrics", RouteClass::Metrics),
            (Method::GET, "/v1/status", RouteClass::Status),
            (Method::GET, "/v1/signals", RouteClass::Signals),
            (Method::GET, "/v1/lean-cell-alerts", RouteClass::LeanCellAlerts),
            (Method::POST, "/v1/lean-cell-alerts", RouteClass::Other),
            (Method::POST, "/v1/tenants/t1/wake", RouteClass::Wake),
            (Method::POST, "/v1/tenants/t1/drain", RouteClass::Drain),
            (Method::GET, "/v1/tenants/t1/status", RouteClass::TenantStatus),
            (Method::POST, "/v1/tenants/t1/status", RouteClass::Other),
            (Method::GET, "/v1/tenants/t1/query", RouteClass::Query),
            (Method::POST, "/v1/tenants/t1/query", RouteClass::Query),
            (Method::GET, "/v1/tenants/t1/query/v1/search", RouteClass::Query),
            (Method::POST, "/v1/tenants/t1/query/v1/search", RouteClass::Query),
            (Method::GET, "/v1/tenants/t1/query/v1/field-stats", RouteClass::Query),
            (Method::POST, "/v1/tenants/t1/detect/v1/search", RouteClass::Detect),
            (Method::POST, "/v1/tenants/t1/detect/v1/detections/plan", RouteClass::Detect),
            // Near misses: never query scope.
            (Method::GET, "/v1/tenants/t1/wake", RouteClass::Other),
            (Method::GET, "/v1/tenants/t1/drain", RouteClass::Other),
            (Method::GET, "/v1/tenants/t1/queryx", RouteClass::Other),
            (Method::GET, "/v1/tenants/t1", RouteClass::Other),
            (Method::GET, "/v1/tenants/query", RouteClass::Other),
            (Method::POST, "/v1/status", RouteClass::Other),
            (Method::POST, "/v1/signals", RouteClass::Other),
            (Method::POST, "/metrics", RouteClass::Other),
            (Method::GET, "/v1/tenants/t1/wake/../query", RouteClass::Other),
            (Method::GET, "/v1/other", RouteClass::Other),
            (Method::GET, "/", RouteClass::Other),
        ]
    }

    #[test]
    fn classification() {
        for (m, p, want) in routes() {
            assert_eq!(classify(&m, p), want, "{m} {p}");
        }
    }

    /// The router's decision for a request: 200-class (allowed through to
    /// the handler), 401 or 403. A wake carries the body's role (the handler
    /// checks it after reading the body); other routes pass `None`.
    fn decide_scope(scope: Option<Scope>, m: &Method, p: &str, wake_role: Option<Role>) -> u16 {
        match scope {
            None => 401,
            Some(s) if !admits(s, classify(m, p)) => 403,
            Some(s) if classify(m, p) == RouteClass::Wake && !permits_wake(s, wake_role.expect("wake needs a role")) => 403,
            Some(_) => 200,
        }
    }

    /// `every_route_by_every_token` wakes the ingest role (still full-only).
    fn decide(presented: Option<&str>, query_configured: bool, m: &Method, p: &str) -> u16 {
        decide_scope(authenticate(presented, FULL, query_configured.then_some(QUERY)), m, p, Some(Role::Ingest))
    }

    #[test]
    fn query_token_wakes_only_the_query_role() {
        let now = Instant::now();
        let grace = Duration::from_secs(600);
        let mut t = Tokens::default();
        t.rotate(z(FULL), Some(z(QUERY)), Some(z(ALERTS)), now, grace, grace).unwrap();
        let wake = |t: &Tokens, tok: &str, role: Role| {
            decide_scope(t.check(Some(tok), now).map(|(s, _)| s), &Method::POST, "/v1/tenants/t1/wake", Some(role))
        };
        // The control plane's prewarm probe: query token + role=query.
        assert_eq!(wake(&t, QUERY, Role::Query), 200);
        // Any other role with the query token is refused.
        assert_eq!(wake(&t, QUERY, Role::Ingest), 403);
        assert_eq!(wake(&t, QUERY, Role::Detect), 403);
        // The alerts token never wakes anything.
        for role in Role::ALL {
            assert_eq!(wake(&t, ALERTS, role), 403, "alerts {role:?}");
        }
        // The full token keeps waking every role.
        for role in Role::ALL {
            assert_eq!(wake(&t, FULL, role), 200, "full {role:?}");
        }
        // Drain, signals and metrics stay full-only.
        for (m, p) in [(Method::POST, "/v1/tenants/t1/drain"), (Method::GET, "/v1/signals"), (Method::GET, "/metrics")] {
            assert_eq!(decide_scope(t.check(Some(QUERY), now).map(|(s, _)| s), &m, p, None), 403, "{m} {p}");
            assert_eq!(decide_scope(t.check(Some(FULL), now).map(|(s, _)| s), &m, p, None), 200, "full {m} {p}");
        }
        // The previous query token (grace window) has exactly query scope.
        t.rotate(z(FULL), Some(z(QUERY2)), Some(z(ALERTS)), now, grace, grace).unwrap();
        assert_eq!(t.check(Some(QUERY), now), Some((Scope::Query, true)));
        assert_eq!(wake(&t, QUERY, Role::Query), 200, "grace token: query wake");
        assert_eq!(wake(&t, QUERY, Role::Ingest), 403, "grace token: ingest wake");
        assert_eq!(wake(&t, QUERY2, Role::Query), 200);
        assert_eq!(wake(&t, QUERY2, Role::Detect), 403);
        // An unknown token.
        assert_eq!(wake(&t, "not-a-router-token-0123456789abcdef0123", Role::Query), 401);
    }

    #[test]
    fn every_route_by_every_token() {
        for (m, p, class) in routes() {
            if class == RouteClass::Health {
                continue; // no auth at all
            }
            // Full token: everything.
            assert_eq!(decide(Some(FULL), true, &m, p), 200, "full {m} {p}");
            assert_eq!(decide(Some(FULL), false, &m, p), 200, "full (no query token) {m} {p}");
            // Query token: query routes and status only; the rest 403.
            let want = if matches!(class, RouteClass::Query | RouteClass::Detect | RouteClass::Status | RouteClass::TenantStatus) { 200 } else { 403 };
            assert_eq!(decide(Some(QUERY), true, &m, p), want, "query {m} {p}");
            // Query token not configured: it is just a wrong token.
            assert_eq!(decide(Some(QUERY), false, &m, p), 401, "query (unconfigured) {m} {p}");
            // Wrong / missing / prefix tokens.
            for bad in [None, Some(""), Some("nope"), Some(&FULL[..FULL.len() - 1]), Some(&QUERY[..10])] {
                assert_eq!(decide(bad, true, &m, p), 401, "{bad:?} {m} {p}");
            }
        }
    }

    #[test]
    fn equal_tokens_are_refused() {
        assert!(distinct_tokens(FULL, FULL).is_err());
        distinct_tokens(FULL, QUERY).unwrap();
    }

    #[test]
    fn empty_tokens_never_match() {
        assert_eq!(authenticate(Some(""), "", Some("")), None);
        assert_eq!(authenticate(Some(FULL), FULL, Some(FULL)), Some(Scope::Full), "full wins on a (refused) collision");
    }

    #[test]
    fn token_files_are_checked() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("q.token");
        std::fs::write(&p, format!("{QUERY}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(read_token(&p, true).unwrap().as_str(), QUERY);
        assert_eq!(read_alerts_token(&p).unwrap().as_str(), QUERY);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_token(&p, true).is_err(), "group/other-readable query token refused");
        assert!(read_alerts_token(&p).is_err());
        assert!(read_token(&p, false).is_ok(), "full token: warned only");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_alerts_token(&p).is_err(), "alerts token requires exactly mode 0400");
        std::fs::write(&p, "short").unwrap();
        assert!(read_token(&p, true).is_err());
    }

    fn z(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_owned())
    }

    const QUERY2: &str = "query-router-token-2-0123456789abcdef01234567";
    const ALERTS: &str = "alerts-router-token-0123456789abcdef01234567";
    const ALERTS2: &str = "alerts-router-token-2-0123456789abcdef012345";

    #[test]
    fn alerts_read_token_only_reaches_get_feed() {
        let now = Instant::now();
        let grace = Duration::from_secs(600);
        let mut t = Tokens::default();
        t.rotate(z(FULL), Some(z(QUERY)), Some(z(ALERTS)), now, grace, grace).unwrap();
        for (method, path, class) in routes() {
            let allowed = permits(t.check(Some(ALERTS), now).unwrap().0, classify(&method, path));
            assert_eq!(allowed, class == RouteClass::LeanCellAlerts, "{method} {path}");
        }
        assert!(!permits(Scope::AlertsRead, RouteClass::Health));
        assert!(!permits(Scope::AlertsRead, RouteClass::Metrics));
        assert!(t.rotate(z(FULL), Some(z(QUERY)), Some(z(FULL)), now, grace, grace).is_err());
        assert!(t.rotate(z(FULL), Some(z(QUERY)), Some(z(QUERY)), now, grace, grace).is_err());
        assert_eq!(t.check(Some(ALERTS), now), Some((Scope::AlertsRead, false)));
        t.rotate(z(FULL), Some(z(QUERY)), Some(z(ALERTS2)), now, grace, grace).unwrap();
        assert_eq!(t.check(Some(ALERTS), now + grace - Duration::from_secs(1)), Some((Scope::AlertsRead, true)));
        assert_eq!(t.check(Some(ALERTS), now + grace), None);
        let d = t.digests(now + Duration::from_secs(10));
        assert_eq!(d.alerts.as_deref(), Some(token_digest(ALERTS2).as_str()));
        assert_eq!(d.alerts_previous.as_deref(), Some(token_digest(ALERTS).as_str()));
        assert_eq!(d.alerts_previous_expires_in_secs, Some(590));
        let serialized = serde_json::to_string(&d).unwrap();
        assert!(!serialized.contains(ALERTS));
        assert!(!serialized.contains(ALERTS2));
    }

    #[test]
    fn previous_query_token_has_a_bounded_grace_window() {
        let t0 = Instant::now();
        let grace = Duration::from_secs(600);
        let mut t = Tokens::default();
        t.rotate(z(FULL), Some(z(QUERY)), None, t0, grace, grace).unwrap();
        assert_eq!(t.check(Some(QUERY), t0), Some((Scope::Query, false)));
        assert!(t.digests(t0).query_previous.is_none(), "no previous at first load");
        // Rotate the query token.
        let t1 = t0 + Duration::from_secs(30);
        t.rotate(z(FULL), Some(z(QUERY2)), None, t1, grace, grace).unwrap();
        assert_eq!(t.check(Some(QUERY2), t1), Some((Scope::Query, false)));
        assert_eq!(t.check(Some(QUERY), t1), Some((Scope::Query, true)), "old token accepted, flagged");
        // The old token only ever has query scope.
        assert!(!permits(t.check(Some(QUERY), t1).unwrap().0, RouteClass::Wake));
        assert!(!permits_wake(t.check(Some(QUERY), t1).unwrap().0, Role::Ingest));
        // A reload with the same token does not restart the window.
        t.rotate(z(FULL), Some(z(QUERY2)), None, t1 + Duration::from_secs(300), grace, grace).unwrap();
        assert_eq!(t.check(Some(QUERY), t1 + Duration::from_secs(599)), Some((Scope::Query, true)));
        assert_eq!(t.check(Some(QUERY), t1 + Duration::from_secs(600)), None, "rejected after the window");
        assert_eq!(t.check(Some(QUERY2), t1 + Duration::from_secs(600)), Some((Scope::Query, false)));
        // Full token: no grace at all.
        const FULL2: &str = "full-router-token-2-0123456789abcdef012345678";
        t.rotate(z(FULL2), Some(z(QUERY2)), None, t1, grace, grace).unwrap();
        assert_eq!(t.check(Some(FULL), t1), None, "old full token refused immediately");
        assert_eq!(t.check(Some(FULL2), t1), Some((Scope::Full, false)));
        // A rotation that makes query == full is refused and changes nothing.
        assert!(t.rotate(z(FULL2), Some(z(FULL2)), None, t1, grace, grace).is_err());
        assert_eq!(t.check(Some(QUERY2), t1), Some((Scope::Query, false)));
        // Removing the query token also retires it through the grace window.
        let t2 = t1 + Duration::from_secs(1000);
        t.rotate(z(FULL2), None, None, t2, grace, grace).unwrap();
        assert_eq!(t.check(Some(QUERY2), t2), Some((Scope::Query, true)));
        assert_eq!(t.check(Some(QUERY2), t2 + grace), None);
    }

    #[test]
    fn healthz_digests_never_leak_tokens() {
        let t0 = Instant::now();
        let mut t = Tokens::default();
        t.rotate(z(FULL), Some(z(QUERY)), None, t0, Duration::from_secs(600), Duration::from_secs(600)).unwrap();
        t.rotate(z(FULL), Some(z(QUERY2)), None, t0, Duration::from_secs(600), Duration::from_secs(600)).unwrap();
        let d = t.digests(t0 + Duration::from_secs(10));
        assert_eq!(d.full, token_digest(FULL));
        assert_eq!(d.query.as_deref(), Some(token_digest(QUERY2).as_str()));
        assert_eq!(d.query_previous.as_deref(), Some(token_digest(QUERY).as_str()));
        assert_eq!(d.query_previous_expires_in_secs, Some(590));
        assert_eq!(d.full.len(), 12);
        assert!(d.full.bytes().all(|b| b.is_ascii_hexdigit()));
        // sha256("abc") = ba7816bf8f01…
        assert_eq!(token_digest("abc"), "ba7816bf8f01");
        let json = serde_json::to_string(&d).unwrap();
        for secret in [FULL, QUERY, QUERY2] {
            assert!(!json.contains(secret));
        }
        assert!(t.digests(t0 + Duration::from_secs(600)).query_previous.is_none());
    }

    // ---- NAN-3289: per-tenant router tokens -------------------------------

    const CELL: &str = "cell-us-d-1";

    fn loaded() -> Tokens {
        let mut t = Tokens::default();
        let g = Duration::from_secs(600);
        t.rotate(z(FULL), Some(z(QUERY)), Some(z(ALERTS)), Instant::now(), g, g).unwrap();
        t
    }

    fn tok(t: &Tokens, tenant: &str, scope: crate::tenant_token::TenantScope) -> String {
        t.tenant_key().unwrap().token(tenant, CELL, scope).to_string()
    }

    fn authz(t: &Tokens, presented: &str, m: Method, p: &str, accept: bool) -> Result<Scope, Deny> {
        t.authorize(Some(presented), &m, p, CELL, accept, Instant::now()).map(|(s, _)| s)
    }

    /// P1 negative tests: tenant A's token never reaches tenant B, for any
    /// scope, with or without the legacy cluster token accepted.
    #[test]
    fn tenant_token_on_another_tenants_path_is_403() {
        use crate::tenant_token::TenantScope;
        let t = loaded();
        for accept in [true, false] {
            for scope in TenantScope::BEARERS {
                let a = tok(&t, "alpha", scope);
                for (m, p) in [
                    (Method::POST, "/v1/tenants/bravo/query/v1/query"),
                    (Method::POST, "/v1/tenants/bravo/query/v1/jobs/search"),
                    (Method::POST, "/v1/tenants/bravo/detect/v1/query"),
                    (Method::POST, "/v1/tenants/bravo/detect/v1/detections/commit"),
                    (Method::POST, "/v1/tenants/bravo/detect/v1/detections/reset"),
                    (Method::GET, "/v1/tenants/bravo/status"),
                    (Method::POST, "/v1/tenants/bravo/wake"),
                ] {
                    assert!(matches!(authz(&t, &a, m.clone(), p, accept), Err(Deny::Forbidden(_))),
                        "{scope:?} token of alpha on {m} {p} (accept={accept})");
                }
                // Cell-wide routes are never reachable with a tenant token.
                for (m, p) in [(Method::GET, "/v1/status"), (Method::GET, "/metrics"), (Method::GET, "/v1/signals"),
                    (Method::GET, "/v1/handover"), (Method::GET, "/v1/lean-cell-alerts")] {
                    assert!(matches!(authz(&t, &a, m.clone(), p, accept), Err(Deny::Forbidden(_))), "{scope:?} {m} {p}");
                }
            }
        }
        // The same tenant's token minted for another cell.
        let elsewhere = t.tenant_key().unwrap().token("alpha", "cell-other", TenantScope::Query);
        assert!(matches!(authz(&t, &elsewhere, Method::POST, "/v1/tenants/alpha/query/v1/query", true), Err(Deny::Forbidden(_))));
        // A token derived from another full token (another cluster).
        let foreign = crate::tenant_token::TenantKey::from_router_token("another-full-router-token-0123456789abcdef")
            .token("alpha", CELL, TenantScope::Query);
        assert!(matches!(authz(&t, &foreign, Method::POST, "/v1/tenants/alpha/query/v1/query", true), Err(Deny::Forbidden(_))));
    }

    /// Scope separation: a query token is not a detect or status token and
    /// vice versa; the `job` key is never a bearer.
    #[test]
    fn tenant_token_scope_confusion_is_403() {
        use crate::tenant_token::TenantScope;
        let t = loaded();
        let q = tok(&t, "alpha", TenantScope::Query);
        let d = tok(&t, "alpha", TenantScope::Detect);
        let st = tok(&t, "alpha", TenantScope::Status);
        let j = tok(&t, "alpha", TenantScope::Job);
        for accept in [true, false] {
            assert_eq!(authz(&t, &q, Method::POST, "/v1/tenants/alpha/query/v1/query", accept), Ok(Scope::TenantQuery));
            assert_eq!(authz(&t, &q, Method::POST, "/v1/tenants/alpha/query/v1/jobs/search", accept), Ok(Scope::TenantQuery));
            assert_eq!(authz(&t, &d, Method::POST, "/v1/tenants/alpha/detect/v1/detections/commit", accept), Ok(Scope::TenantDetect));
            assert_eq!(authz(&t, &st, Method::GET, "/v1/tenants/alpha/status", accept), Ok(Scope::TenantStatus));
            // query token on detect (incl. the gate) and status: 403.
            for (m, p) in [(Method::POST, "/v1/tenants/alpha/detect/v1/query"),
                (Method::POST, "/v1/tenants/alpha/detect/v1/detections/commit"), (Method::GET, "/v1/tenants/alpha/status"),
                (Method::POST, "/v1/tenants/alpha/drain")] {
                assert!(matches!(authz(&t, &q, m.clone(), p, accept), Err(Deny::Forbidden(_))), "query token {m} {p}");
            }
            // detect / status tokens on query: 403.
            for tokn in [&d, &st] {
                assert!(matches!(authz(&t, tokn, Method::POST, "/v1/tenants/alpha/query/v1/query", accept), Err(Deny::Forbidden(_))));
                assert!(matches!(authz(&t, tokn, Method::POST, "/v1/tenants/alpha/wake", accept), Err(Deny::Forbidden(_))));
            }
            assert!(matches!(authz(&t, &st, Method::POST, "/v1/tenants/alpha/detect/v1/query", accept), Err(Deny::Forbidden(_))));
            // The job key is never a bearer.
            for (m, p) in [(Method::POST, "/v1/tenants/alpha/query/v1/query"), (Method::POST, "/v1/tenants/alpha/detect/v1/query")] {
                assert!(matches!(authz(&t, &j, m.clone(), p, accept), Err(Deny::Forbidden(_))), "job key {m} {p}");
            }
        }
        // A tenant query token wakes only its tenant's query role.
        assert_eq!(authz(&t, &q, Method::POST, "/v1/tenants/alpha/wake", false), Ok(Scope::TenantQuery));
        assert!(permits_wake(Scope::TenantQuery, Role::Query));
        assert!(!permits_wake(Scope::TenantQuery, Role::Detect) && !permits_wake(Scope::TenantQuery, Role::Ingest));
        assert!(!permits_wake(Scope::TenantDetect, Role::Detect), "detect wakes stay full-only");
        // Unknown tenant-shaped garbage and an empty prefix: 403, not a scope.
        for bad in ["nct1.", "nct1.00", &format!("{q}0")] {
            assert!(matches!(authz(&t, bad, Method::POST, "/v1/tenants/alpha/query/v1/query", true), Err(Deny::Forbidden(_))), "{bad}");
        }
    }

    /// The migration switch: on (default) the cluster query token keeps its
    /// legacy reach; off it keeps only status, health and a query wake.
    #[test]
    fn cluster_query_token_reach_follows_the_migration_switch() {
        let t = loaded();
        for (m, p) in [(Method::POST, "/v1/tenants/bravo/query/v1/query"), (Method::POST, "/v1/tenants/bravo/detect/v1/query"),
            (Method::GET, "/v1/tenants/bravo/status")] {
            assert_eq!(authz(&t, QUERY, m.clone(), p, true), Ok(Scope::Query), "legacy {m} {p}");
            assert!(matches!(authz(&t, QUERY, m.clone(), p, false), Err(Deny::Forbidden(_))), "flipped {m} {p}");
        }
        assert_eq!(authz(&t, QUERY, Method::GET, "/v1/status", false), Ok(Scope::Query));
        assert_eq!(authz(&t, QUERY, Method::POST, "/v1/tenants/bravo/wake", false), Ok(Scope::Query), "control prewarm probe");
        // The full token is unaffected; an unknown token is still a 401.
        assert_eq!(authz(&t, FULL, Method::POST, "/v1/tenants/bravo/query/v1/query", false), Ok(Scope::Full));
        assert_eq!(authz(&t, "not-a-router-token-0123456789abcdef0123", Method::GET, "/v1/status", true), Err(Deny::Unauthorized));
        assert_eq!(authz(&t, ALERTS, Method::GET, "/v1/lean-cell-alerts", false), Ok(Scope::AlertsRead));
    }

    /// P2-1: moving a watermark needs detect scope; the reset never takes
    /// the cluster query token.
    #[test]
    fn detection_gate_writes_need_detect_scope() {
        for sub in [DETECTION_COMMIT_PATH, "/v1/detections/commit/"] {
            assert!(permits_detect_call(Scope::Full, sub, false));
            assert!(permits_detect_call(Scope::TenantDetect, sub, false));
            assert!(permits_detect_call(Scope::Query, sub, true), "legacy reach during the rollout");
            assert!(!permits_detect_call(Scope::Query, sub, false));
            assert!(!permits_detect_call(Scope::TenantQuery, sub, true));
        }
        assert!(permits_detect_call(Scope::Full, DETECTION_RESET_PATH, true));
        assert!(permits_detect_call(Scope::TenantDetect, DETECTION_RESET_PATH, false));
        assert!(!permits_detect_call(Scope::Query, DETECTION_RESET_PATH, true));
        assert!(permits_detect_call(Scope::Query, "/v1/detections/plan", true));
        assert_eq!(classify(&Method::POST, "/v1/tenants/t1/detect/v1/detections/reset"), RouteClass::Detect);
    }

    /// P2-2: a job spec reaches query[T] only signed by its tenant's job key
    /// on this cell (or unsigned while the legacy switch is on).
    #[test]
    fn job_specs_are_verified_at_the_router() {
        use crate::tenant_token::{sign_job_spec, TenantScope, JOB_AUTH_LEGACY, JOB_AUTH_SIGNED};
        let t = loaded();
        let key = t.tenant_key();
        let body = br#"{"tenant_id":"alpha","retention_proof":{}}"#;
        let job = tok(&t, "alpha", TenantScope::Job);
        let sig = sign_job_spec(&job, "alpha", CELL, body);
        assert_eq!(job_spec_decision(key, "alpha", CELL, body, Some(&sig), false), Ok(JOB_AUTH_SIGNED));
        assert!(job_spec_decision(key, "bravo", CELL, body, Some(&sig), true).is_err(), "A's signature on B");
        assert!(job_spec_decision(key, "alpha", "cell-other", body, Some(&sig), true).is_err(), "another cell");
        assert!(job_spec_decision(key, "alpha", CELL, br#"{"tenant_id":"alpha"}"#, Some(&sig), true).is_err(), "edited body");
        let q = tok(&t, "alpha", TenantScope::Query);
        assert!(job_spec_decision(key, "alpha", CELL, body, Some(&sign_job_spec(&q, "alpha", CELL, body)), true).is_err(),
            "the query bearer cannot sign");
        assert_eq!(job_spec_decision(key, "alpha", CELL, body, None, true), Ok(JOB_AUTH_LEGACY));
        assert!(job_spec_decision(key, "alpha", CELL, body, None, false).is_err(), "unsigned after the flip");
        assert!(job_spec_decision(None, "alpha", CELL, body, Some(&sig), true).is_err());
    }

    /// NAN-3715: operator probes take only the full or cluster query token,
    /// and only the router can say a request was operator-admitted.
    #[test]
    fn operator_probes_need_an_operator_scope_and_a_router_stamp() {
        for scope in [Scope::Full, Scope::Query] {
            assert!(permits_query_call(scope, "/v1/debug/sql-probe"), "{scope:?}");
        }
        for scope in [Scope::TenantQuery, Scope::TenantDetect, Scope::TenantStatus, Scope::AlertsRead] {
            assert!(!permits_query_call(scope, "/v1/debug/sql-probe"), "{scope:?}");
            assert!(!permits_query_call(scope, "/v1/debug/sql-probe?x=1"), "{scope:?}");
            assert!(!permits_query_call(scope, "/v1/debug"), "{scope:?}");
            assert!(permits_query_call(scope, "/v1/query"), "ordinary query routes are unchanged ({scope:?})");
        }
        assert!(is_operator_debug("/v1/debug/slow-queries") && !is_operator_debug("/v1/debugger") && !is_operator_debug("/v1/query"));
        let mut headers = hyper::HeaderMap::new();
        headers.insert(OPERATOR_DEBUG_HEADER, HeaderValue::from_static(OPERATOR_DEBUG_ADMITTED));
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
        sanitize_forward_headers(&mut headers, None, false);
        assert!(headers.get(OPERATOR_DEBUG_HEADER).is_none(), "a caller's stamp is stripped");
        assert!(headers.get(AUTHORIZATION).is_none());
        sanitize_forward_headers(&mut headers, None, true);
        assert_eq!(headers.get(OPERATOR_DEBUG_HEADER).unwrap(), OPERATOR_DEBUG_ADMITTED);
    }

    /// NAN-3518: `/healthz` reports the crate version and keeps the rest.
    #[test]
    fn healthz_reports_build_version() {
        let mut body = serde_json::json!({"status": "ok", "cell_id": "cell-a"});
        stamp_build_version(&mut body);
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        assert!(!body["version"].as_str().unwrap().is_empty());
        assert_eq!(body["status"], "ok");
        assert_eq!(body["cell_id"], "cell-a");
    }

    /// P3-2: no token digests or tenant counts without a cluster token.
    #[test]
    fn healthz_private_fields_need_a_cluster_token() {
        assert!(healthz_shows_private(Some(Scope::Full)));
        assert!(healthz_shows_private(Some(Scope::Query)));
        for s in [None, Some(Scope::AlertsRead), Some(Scope::TenantQuery), Some(Scope::TenantDetect), Some(Scope::TenantStatus)] {
            assert!(!healthz_shows_private(s), "{s:?}");
        }
    }
}

/// Aggregate-only observation capability. No caller-supplied nPL, tenant, dataset,
/// pagination, cache setting or arbitrary time range can reach query[T].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LandingBody {
    request_id: uuid::Uuid,
    source: String,
    bundle: String,
    since: chrono::DateTime<chrono::Utc>,
}

fn landing_query(tenant: &TenantId, bytes: &[u8]) -> Result<serde_json::Value, ()> {
    let r: LandingBody = serde_json::from_slice(bytes).map_err(|_| ())?;
    let now = chrono::Utc::now();
    if r.request_id.is_nil()
        || r.source.is_empty()
        || r.source.len() > 100
        || !r.source.as_bytes()[0].is_ascii_alphanumeric()
        || !r
            .source
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        || r.bundle.len() != 64
        || !r
            .bundle
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || r.since >= now
        || r.since < now - chrono::Duration::days(30)
    {
        return Err(());
    }
    let query = format!("source_type=\"{}\" | eval pending=if(metadata.nano_parser_bundle_sha256=\"{}\",1,0) | eval failed=if(pending=1 AND (class_uid=0 OR unmapped.parse_error!=\"\"),1,0) | stats count() as rows, sum(pending) as n, sum(failed) as errors", r.source, r.bundle);
    Ok(
        serde_json::json!({"request_id":r.request_id, "tenant_id":tenant.as_str(),
        "route":"broad_npl", "dataset":"logs", "query":query,
        "start":r.since.to_rfc3339(), "end":now.to_rfc3339(), "limit":2, "offset":0,
        "table_view":false, "use_cache":false, "deny_source_types":[]}),
    )
}

#[cfg(test)]
mod native_landing_tests {
    use super::*;
    #[test]
    fn native_landing_is_aggregate_only_even_with_legacy_queries_disabled() {
        let route = classify(&Method::POST, "/v1/tenants/t/landing");
        assert_eq!(route, RouteClass::Landing);
        assert!(permits_with(Scope::Query, route, false));
        assert!(!permits_with(Scope::Query, RouteClass::Query, false));
        for scope in [
            Scope::TenantQuery,
            Scope::TenantDetect,
            Scope::TenantStatus,
            Scope::AlertsRead,
        ] {
            assert!(!permits_with(scope, route, false));
        }
        assert_eq!(
            classify(&Method::GET, "/v1/tenants/t/landing"),
            RouteClass::Other
        );
    }
    #[test]
    fn native_landing_pins_new_tenant_and_rejects_query_injection() {
        let tenant = TenantId::new("22222222-2222-4222-8222-222222222222").unwrap();
        let body = serde_json::json!({"request_id":uuid::Uuid::now_v7(), "source":"new_source", "bundle":"a".repeat(64),
            "since":chrono::Utc::now() - chrono::Duration::minutes(5)});
        let query = landing_query(&tenant, &serde_json::to_vec(&body).unwrap()).unwrap();
        assert_eq!(query["tenant_id"], tenant.as_str());
        assert_eq!(query["use_cache"], false);
        assert_eq!(query["limit"], 2);
        assert!(query["query"]
            .as_str()
            .unwrap()
            .ends_with("stats count() as rows, sum(pending) as n, sum(failed) as errors"));
        for (key, value) in [
            ("query", serde_json::json!("*")),
            ("tenant_id", serde_json::json!("other")),
            ("source", serde_json::json!("x\" | head 1")),
            ("bundle", serde_json::json!("bad")),
            (
                "since",
                serde_json::json!(chrono::Utc::now() - chrono::Duration::days(31)),
            ),
        ] {
            let mut bad = body.clone();
            bad[key] = value;
            assert!(
                landing_query(&tenant, &serde_json::to_vec(&bad).unwrap()).is_err(),
                "{key}"
            );
        }
    }
}
