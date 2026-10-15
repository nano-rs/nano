// SPDX-License-Identifier: AGPL-3.0-or-later
//! Audit of searches that explicitly name a source the caller cannot see
//! (NAN-3222).
//!
//! The source gate ([`crate::search::query_processing::enforce_source_visibility_with_field`])
//! silently excludes denied sources: a source-restricted member who searches
//! `metadata.log_source=insider_threat` gets an empty result and no hint.
//! That silence is the product contract ("not visible means absent") and this
//! module does NOT change it. It only records the attempt so an administrator
//! can see someone probing for hidden sources.
//!
//! # Shape
//!
//! * [`denied_sources_named`] — a PURE function over the parsed AST: which
//!   denied labels does the query reference with POSITIVE polarity through a
//!   source field (`source_type`, `metadata.log_source`) by equality, IN,
//!   wildcard / LIKE / CONTAINS / STARTSWITH / ENDSWITH or regex? Broad
//!   searches (a keyword, `source_type=*`) name nothing.
//! * [`DeniedSourceAuditScope`] — installed per request by the search and API
//!   auth layers ([`with_scope`]) carrying the actor, tenant, the caller's
//!   per-source RBAC deny set, the entry point, the request id and a
//!   [`DeniedSourceAuditSink`]. Like the request actor it is a task-local and
//!   follows spawned work only through [`crate::search::request_actor::inherit`].
//! * [`observe_gated_query`] / [`observe_raw_sql_refused`] — the two hooks:
//!   the source gate calls the first for every query it gates, the raw-SQL
//!   refusal calls the second. Outside a scope (detection runtime, runners,
//!   lake workers, tests) both are no-ops.
//! * [`DeniedSourceAuditLimiter`] — in-process, bounded: at most one audit
//!   per (tenant, actor, label, entry point) per [`AUDIT_WINDOW`], so
//!   dashboards and live tail cannot flood the audit ledger. No table, no
//!   growth: the state is a capped per-pod map.
//!
//! The sink is fire-and-forget: nothing here can change, delay or fail the
//! user-facing response.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::json;
use uuid::Uuid;

use crate::audit::{actions, AuditEvent, AuditSource, ClientContext};
use crate::auth::TrustedTenantContext;
use crate::query::{Command, Comparator, Query, SearchExpr, Value};

/// One audit per (tenant, actor, label, entry point) per window.
pub const AUDIT_WINDOW: Duration = Duration::from_secs(300);
/// Per-pod bound on rate-limit keys. When full the OLDEST key is evicted,
/// which can only cause an extra audit row, never a missed one.
pub const LIMITER_CAPACITY: usize = 16_384;
/// Query text is truncated to this many bytes (on a char boundary).
pub const MAX_AUDIT_QUERY_BYTES: usize = 1024;
/// Request ids and entry points are client-influenced; bound them.
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_ENTRY_POINT_BYTES: usize = 96;
/// Rate-limit key used for a raw-SQL refusal that names no denied label.
const RAW_SQL_UNNAMED_KEY: &str = "*";

/// Fields that carry an event's source provenance in nPL.
const SOURCE_FIELDS: [&str; 2] = [
    "source_type",
    crate::search::query_processing::LAKE_SOURCE_FIELD,
];

/// What happened to the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeniedSourceOutcome {
    /// The query ran; the denied source's rows were withheld.
    Filtered,
    /// Raw SQL was refused because the caller is source-scoped.
    Refused,
}

impl DeniedSourceOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filtered => "filtered",
            Self::Refused => "refused",
        }
    }
}

/// One audit row, before it is shaped into an [`AuditEvent`].
#[derive(Debug, Clone)]
pub struct DeniedSourceAuditRecord {
    pub tenant: Option<TrustedTenantContext>,
    pub actor_id: Uuid,
    pub api_key_id: Option<Uuid>,
    /// Only the denied labels the query referenced (never the full deny set).
    pub labels: Vec<String>,
    pub query: String,
    pub entry_point: String,
    pub request_id: Option<String>,
    pub outcome: DeniedSourceOutcome,
    pub client: ClientContext,
}

impl DeniedSourceAuditRecord {
    /// The canonical audit event: action [`actions::SEARCH_SOURCE_SCOPE_DENIED`],
    /// source `search`, `success = false` (an access-denied record).
    pub fn to_audit_event(&self) -> AuditEvent {
        AuditEvent::builder(AuditSource::Search, actions::SEARCH_SOURCE_SCOPE_DENIED)
            .actor(Some(self.actor_id), None)
            .api_key(self.api_key_id, None)
            .resource("source_scope", None, Some(self.labels.join(",")))
            .client_context(&self.client)
            .success(false)
            .details(json!({
                "outcome": self.outcome.as_str(),
                "denied_sources": self.labels,
                "query": self.query,
                "entry_point": self.entry_point,
                "request_id": self.request_id,
                "tenant_id": self.tenant.as_ref().map(|t| t.tenant_id),
            }))
            .build()
    }
}

/// Where audit records go. Implementations MUST NOT block: they enqueue or
/// spawn. Dedicated deployments write the platform audit pipeline; shared
/// deployments append through a signed tenant transaction.
pub trait DeniedSourceAuditSink: Send + Sync {
    fn submit(&self, record: DeniedSourceAuditRecord);
}

/// Dedicated-deployment sink over the platform [`crate::audit::AuditEmitter`]
/// (background runners with no request; request paths use their service's
/// own audit queue). A tenant-scoped record is refused here: shared tenants
/// append through a signed tenant transaction, never the platform emitter.
pub struct EmitterDeniedSourceAuditSink {
    emitter: Arc<crate::audit::AuditEmitter>,
}

impl EmitterDeniedSourceAuditSink {
    pub fn new(emitter: Arc<crate::audit::AuditEmitter>) -> Arc<dyn DeniedSourceAuditSink> {
        Arc::new(Self { emitter })
    }
}

impl DeniedSourceAuditSink for EmitterDeniedSourceAuditSink {
    fn submit(&self, record: DeniedSourceAuditRecord) {
        if record.tenant.is_some() {
            tracing::error!(
                "denied-source audit for a shared tenant reached the platform emitter; dropped"
            );
            return;
        }
        let emitter = self.emitter.clone();
        let event = record.to_audit_event();
        tokio::spawn(async move {
            if let Err(error) = emitter.emit(&event).await {
                tracing::error!(%error, action = %event.action, "denied-source audit could not be emitted");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

type LimiterKey = (Option<Uuid>, Uuid, String, String);

/// Bounded in-process rate limiter. Windows are fixed length, so insertion
/// order is expiry order and the queue front is always the oldest key.
pub struct DeniedSourceAuditLimiter {
    window: Duration,
    capacity: usize,
    inner: Mutex<LimiterState>,
}

#[derive(Default)]
struct LimiterState {
    admitted: HashMap<LimiterKey, Instant>,
    order: VecDeque<(LimiterKey, Instant)>,
}

impl DeniedSourceAuditLimiter {
    pub fn new(window: Duration, capacity: usize) -> Self {
        Self {
            window,
            capacity: capacity.max(1),
            inner: Mutex::new(LimiterState::default()),
        }
    }

    /// The per-pod limiter every production scope shares.
    pub fn global() -> Arc<Self> {
        static GLOBAL: OnceLock<Arc<DeniedSourceAuditLimiter>> = OnceLock::new();
        GLOBAL
            .get_or_init(|| Arc::new(Self::new(AUDIT_WINDOW, LIMITER_CAPACITY)))
            .clone()
    }

    /// `true` when this key has not been admitted within the window (and
    /// records it as admitted now).
    pub fn admit(
        &self,
        tenant: Option<Uuid>,
        actor: Uuid,
        label: &str,
        entry_point: &str,
        now: Instant,
    ) -> bool {
        let mut state = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        while let Some((key, at)) = state.order.front() {
            if now.saturating_duration_since(*at) < self.window {
                break;
            }
            let (key, at) = (key.clone(), *at);
            state.order.pop_front();
            if state.admitted.get(&key) == Some(&at) {
                state.admitted.remove(&key);
            }
        }
        let key: LimiterKey = (tenant, actor, label.to_string(), entry_point.to_string());
        if state.admitted.contains_key(&key) {
            return false;
        }
        state.admitted.insert(key.clone(), now);
        state.order.push_back((key, now));
        while state.admitted.len() > self.capacity {
            let Some((oldest, at)) = state.order.pop_front() else {
                break;
            };
            if state.admitted.get(&oldest) == Some(&at) {
                state.admitted.remove(&oldest);
            }
        }
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().admitted.len()
    }
}

// ---------------------------------------------------------------------------
// Request scope
// ---------------------------------------------------------------------------

/// Everything a request's audit needs; installed by the auth layer.
pub struct DeniedSourceAuditScope {
    pub tenant: Option<TrustedTenantContext>,
    pub actor_id: Uuid,
    pub api_key_id: Option<Uuid>,
    /// The caller's per-source RBAC deny set (NOT the `audit:view` row gate),
    /// normalized and expanded over the Unattributed aliases.
    denied: BTreeSet<String>,
    pub entry_point: String,
    pub request_id: Option<String>,
    pub client: ClientContext,
    sink: Arc<dyn DeniedSourceAuditSink>,
    limiter: Arc<DeniedSourceAuditLimiter>,
}

impl DeniedSourceAuditScope {
    /// `None` when there is nothing to audit (an unrestricted caller or a nil
    /// actor), so callers skip installing a scope entirely.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: Option<TrustedTenantContext>,
        actor_id: Uuid,
        api_key_id: Option<Uuid>,
        denied: &BTreeSet<String>,
        path: &str,
        request_id: Option<&str>,
        client: ClientContext,
        sink: Arc<dyn DeniedSourceAuditSink>,
    ) -> Option<Self> {
        let denied = crate::auth::source_visibility::expand_unattributed_sources(denied);
        if denied.is_empty() || actor_id.is_nil() {
            return None;
        }
        Some(Self {
            tenant,
            actor_id,
            api_key_id,
            denied,
            entry_point: entry_point_from_path(path),
            request_id: request_id.map(|id| truncate_bytes(id, MAX_REQUEST_ID_BYTES)),
            client,
            sink,
            limiter: DeniedSourceAuditLimiter::global(),
        })
    }

    /// Replace the limiter (tests; isolated pods share [`DeniedSourceAuditLimiter::global`]).
    pub fn with_limiter(mut self, limiter: Arc<DeniedSourceAuditLimiter>) -> Self {
        self.limiter = limiter;
        self
    }

    fn submit(&self, labels: BTreeSet<String>, query: &str, outcome: DeniedSourceOutcome) {
        let now = Instant::now();
        let tenant_id = self.tenant.as_ref().map(|t| t.tenant_id);
        let fresh: Vec<String> = if labels.is_empty() {
            // Only a raw-SQL refusal reaches here without labels.
            if !self.limiter.admit(
                tenant_id,
                self.actor_id,
                RAW_SQL_UNNAMED_KEY,
                &self.entry_point,
                now,
            ) {
                return;
            }
            Vec::new()
        } else {
            let fresh: Vec<String> = labels
                .into_iter()
                .filter(|label| {
                    self.limiter
                        .admit(tenant_id, self.actor_id, label, &self.entry_point, now)
                })
                .collect();
            if fresh.is_empty() {
                return;
            }
            fresh
        };
        self.sink.submit(DeniedSourceAuditRecord {
            tenant: self.tenant.clone(),
            actor_id: self.actor_id,
            api_key_id: self.api_key_id,
            labels: fresh,
            query: truncate_bytes(query, MAX_AUDIT_QUERY_BYTES),
            entry_point: self.entry_point.clone(),
            request_id: self.request_id.clone(),
            outcome,
            client: self.client.clone(),
        });
    }
}

tokio::task_local! {
    static AUDIT_SCOPE: Arc<DeniedSourceAuditScope>;
}

/// Run `future` with `scope` installed.
pub async fn with_scope<F: Future>(scope: Arc<DeniedSourceAuditScope>, future: F) -> F::Output {
    AUDIT_SCOPE.scope(scope, future).await
}

/// The current request's scope, if any.
pub fn current() -> Option<Arc<DeniedSourceAuditScope>> {
    AUDIT_SCOPE.try_with(Arc::clone).ok()
}

/// Hook for the source gate: `parsed` is the caller's query as the gate
/// parsed it, `gate_deny_set` the (normalized) set that gate is excluding.
/// Only labels both in the caller's RBAC deny set AND excluded by this gate
/// are candidates, so the audit says "rows were withheld" truthfully.
pub fn observe_gated_query(query_text: &str, parsed: &Query, gate_deny_set: &BTreeSet<String>) {
    let Some(scope) = current() else { return };
    let candidates: BTreeSet<String> = scope.denied.intersection(gate_deny_set).cloned().collect();
    if candidates.is_empty() {
        return;
    }
    let named = denied_sources_named(parsed, &candidates);
    if named.is_empty() {
        return;
    }
    scope.submit(named, query_text, DeniedSourceOutcome::Filtered);
}

/// Hook for the raw-SQL refusal of a source-scoped caller. Always audited
/// (rate limited); `denied_sources` lists the denied labels the SQL quotes.
pub fn observe_raw_sql_refused(sql: &str) {
    let Some(scope) = current() else { return };
    let named = raw_sql_named_denied_sources(sql, &scope.denied);
    scope.submit(named, sql, DeniedSourceOutcome::Refused);
}

// ---------------------------------------------------------------------------
// Pure detection
// ---------------------------------------------------------------------------

/// Which labels of `denied` does `query` explicitly name, with positive
/// polarity, through a source field — anywhere: the base scan, every
/// subsearch (`join` / `append` / `IN [ … ]`) and `where` / `transaction` /
/// `sequence` / `funnel` conditions?
///
/// Matching (case-insensitive): `field=label`, `field IN (…)`, glob
/// wildcards in an equality (`insider*`), `LIKE`, `CONTAINS`, `STARTSWITH`,
/// `ENDSWITH` and regex. A pattern with no literal character (`*`, `%`,
/// `.*`) is broad, not a probe, and names nothing. Negated forms (`!=`,
/// `NOT IN`, `NOT …`) exclude a source and name nothing — which also makes
/// the gate's own injected `NOT IN` conjunct invisible here.
///
/// On the lake field the Unattributed spellings fold to the restriction label
/// (`unknown` → `default`). `denied` is normalized by the caller (lowercase).
pub fn denied_sources_named(query: &Query, denied: &BTreeSet<String>) -> BTreeSet<String> {
    let mut named = BTreeSet::new();
    if !denied.is_empty() {
        walk_query(query, denied, &mut named);
    }
    named
}

fn walk_query(query: &Query, denied: &BTreeSet<String>, named: &mut BTreeSet<String>) {
    match query {
        Query::Search(expr) => walk_expr(expr, true, denied, named),
        Query::Piped { source, command } => {
            walk_query(source, denied, named);
            walk_command(command, denied, named);
        }
    }
}

fn walk_command(command: &Command, denied: &BTreeSet<String>, named: &mut BTreeSet<String>) {
    match command {
        Command::Join { subsearch, .. } | Command::Append { subsearch, .. } => {
            walk_query(subsearch, denied, named)
        }
        Command::Where { condition } => walk_expr(condition, true, denied, named),
        Command::Transaction {
            startswith,
            endswith,
            ..
        } => {
            for expr in [startswith, endswith].into_iter().flatten() {
                walk_expr(expr, true, denied, named);
            }
        }
        Command::Sequence { conditions, .. } => {
            for expr in conditions {
                walk_expr(expr, true, denied, named);
            }
        }
        Command::Funnel { steps, .. } => {
            for (_, expr) in steps {
                walk_expr(expr, true, denied, named);
            }
        }
        _ => {}
    }
}

fn walk_expr(
    expr: &SearchExpr,
    positive: bool,
    denied: &BTreeSet<String>,
    named: &mut BTreeSet<String>,
) {
    match expr {
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            walk_expr(left, positive, denied, named);
            walk_expr(right, positive, denied, named);
        }
        SearchExpr::Not(inner) => walk_expr(inner, !positive, denied, named),
        SearchExpr::Group(inner) => walk_expr(inner, positive, denied, named),
        SearchExpr::InSubsearch { subsearch, .. } => walk_query(subsearch, denied, named),
        SearchExpr::FieldFilter {
            field, op, value, ..
        } => {
            let Some(lake) = source_field(field) else {
                return;
            };
            let Some((matcher, op_positive)) = matcher_for(op, value) else {
                return;
            };
            if op_positive == positive {
                collect_matches(&matcher, lake, denied, named);
            }
        }
        SearchExpr::InList {
            field,
            values,
            negated,
        } => {
            let Some(lake) = source_field(field) else {
                return;
            };
            if *negated == positive {
                return;
            }
            for value in values {
                if let Some((matcher, true)) = matcher_for(&Comparator::Eq, value) {
                    collect_matches(&matcher, lake, denied, named);
                }
            }
        }
        SearchExpr::Keyword(_)
        | SearchExpr::FunctionFilter { .. }
        | SearchExpr::FieldFunctionFilter { .. }
        | SearchExpr::BooleanFunction(_)
        | SearchExpr::EvalPredicate(_)
        | SearchExpr::LiteralComparison { .. }
        | SearchExpr::IocMatch { .. } => {}
    }
}

/// `Some(is_lake_field)` when `field` is a source field.
fn source_field(field: &str) -> Option<bool> {
    let field = field.trim();
    SOURCE_FIELDS
        .iter()
        .find(|candidate| field.eq_ignore_ascii_case(candidate))
        .map(|candidate| *candidate == crate::search::query_processing::LAKE_SOURCE_FIELD)
}

enum Matcher {
    Exact(String),
    Pattern(regex::Regex),
}

impl Matcher {
    fn matches(&self, label: &str) -> bool {
        match self {
            Self::Exact(value) => value == label,
            Self::Pattern(re) => re.is_match(label),
        }
    }
}

/// The matcher a comparison implies and whether it is a positive reference.
fn matcher_for(op: &Comparator, value: &Value) -> Option<(Matcher, bool)> {
    let text = match value {
        Value::String(s) | Value::Regex(s) => s.trim(),
        _ => return None,
    };
    if !text.chars().any(|c| c.is_alphanumeric()) {
        return None;
    }
    let is_regex_value = matches!(value, Value::Regex(_));
    let positive = matches!(
        op,
        Comparator::Eq
            | Comparator::Regex
            | Comparator::Like
            | Comparator::Contains
            | Comparator::StartsWith
            | Comparator::EndsWith
    );
    let negative = matches!(
        op,
        Comparator::Ne
            | Comparator::NotRegex
            | Comparator::NotLike
            | Comparator::NotContains
            | Comparator::NotStartsWith
            | Comparator::NotEndsWith
    );
    if !positive && !negative {
        return None;
    }
    let matcher = match op {
        Comparator::Regex | Comparator::NotRegex => regex_matcher(text)?,
        _ if is_regex_value => regex_matcher(text)?,
        Comparator::Eq | Comparator::Ne => {
            if text.contains(['*', '?']) {
                pattern_matcher(&glob_to_regex(text))?
            } else {
                Matcher::Exact(text.to_ascii_lowercase())
            }
        }
        Comparator::Like | Comparator::NotLike => pattern_matcher(&like_to_regex(text))?,
        Comparator::Contains | Comparator::NotContains => {
            pattern_matcher(&format!("^.*{}.*$", regex::escape(text)))?
        }
        Comparator::StartsWith | Comparator::NotStartsWith => {
            pattern_matcher(&format!("^{}.*$", regex::escape(text)))?
        }
        Comparator::EndsWith | Comparator::NotEndsWith => {
            pattern_matcher(&format!("^.*{}$", regex::escape(text)))?
        }
        _ => return None,
    };
    Some((matcher, positive))
}

fn regex_matcher(pattern: &str) -> Option<Matcher> {
    let compiled = regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(64 * 1024)
        .build()
        .ok()?;
    // A regex that matches anything (`.*`, `^`) names nothing.
    if compiled.is_match("") {
        return None;
    }
    Some(Matcher::Pattern(compiled))
}

fn pattern_matcher(anchored: &str) -> Option<Matcher> {
    regex::RegexBuilder::new(anchored)
        .case_insensitive(true)
        .size_limit(64 * 1024)
        .build()
        .ok()
        .map(Matcher::Pattern)
}

fn glob_to_regex(glob: &str) -> String {
    let mut out = String::from("^");
    for c in glob.chars() {
        match c {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            other => out.push_str(&regex::escape(&other.to_string())),
        }
    }
    out.push('$');
    out
}

fn like_to_regex(like: &str) -> String {
    let mut out = String::from("^");
    for c in like.chars() {
        match c {
            '%' | '*' => out.push_str(".*"),
            '_' => out.push('.'),
            other => out.push_str(&regex::escape(&other.to_string())),
        }
    }
    out.push('$');
    out
}

fn collect_matches(
    matcher: &Matcher,
    lake_field: bool,
    denied: &BTreeSet<String>,
    named: &mut BTreeSet<String>,
) {
    for label in denied {
        if matcher.matches(label) {
            named.insert(if lake_field {
                crate::auth::source_visibility::canonical_restriction_slug(label)
            } else {
                label.clone()
            });
        }
    }
}

/// Denied labels a raw SQL statement quotes as a string literal
/// (`'insider_threat'` / `"insider_threat"`), case-insensitive.
pub fn raw_sql_named_denied_sources(sql: &str, denied: &BTreeSet<String>) -> BTreeSet<String> {
    let lowered = sql.to_ascii_lowercase();
    denied
        .iter()
        .filter(|label| {
            let label = label.to_ascii_lowercase();
            lowered.contains(&format!("'{label}'")) || lowered.contains(&format!("\"{label}\""))
        })
        .map(|label| crate::auth::source_visibility::canonical_restriction_slug(label))
        .collect()
}

/// A bounded, low-cardinality entry-point label from a request path:
/// `/api/search/stream` → `search/stream`, ids (`{uuid}`, typeids, long
/// numeric / hex segments) → `{id}`.
pub fn entry_point_from_path(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    let trimmed = trimmed.strip_prefix("api/").unwrap_or(trimmed);
    let label = trimmed
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if looks_like_id(segment) {
                "{id}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    let label = if label.is_empty() {
        "search".to_string()
    } else {
        label
    };
    truncate_bytes(&label, MAX_ENTRY_POINT_BYTES)
}

fn looks_like_id(segment: &str) -> bool {
    if Uuid::parse_str(segment).is_ok() {
        return true;
    }
    let digits = segment.chars().filter(|c| c.is_ascii_digit()).count();
    // typeids (`search_01h…`), ULIDs, hashes and numeric ids all carry digits.
    digits > 0 && (segment.len() >= 16 || digits * 2 >= segment.len())
}

fn truncate_bytes(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[cfg(test)]
#[path = "denied_source_audit_tests.rs"]
mod tests;
