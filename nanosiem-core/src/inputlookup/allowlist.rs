// SPDX-License-Identifier: AGPL-3.0-or-later
//! The lookup URL allowlist: which hosts `inputlookup url=...` may fetch from
//! (NAN-5436, managed in Settings since NAN-5443).
//!
//! # Two sources
//!
//! | Source | Set by | Stored |
//! |---|---|---|
//! | deployment list | the operator, `INPUTLOOKUP_ALLOWED_DOMAINS` | process env |
//! | admin list | an administrator, Settings → Lookup URLs | `system_settings.inputlookup_allowed_domains` (migration 387) |
//!
//! # Precedence
//!
//! - By default the effective list is the UNION of both. The deployment list
//!   works as a seed the admin list adds to; deployment entries cannot be
//!   removed from Settings.
//! - `INPUTLOOKUP_ALLOWED_DOMAINS_LOCKED=true` makes the deployment list an
//!   override: the admin list is ignored and Settings is read-only.
//! - An empty effective list keeps the shipped behavior (any public host,
//!   subject to the SSRF guard). Deny-by-default is a separate decision
//!   (NAN-5436).
//!
//! # Propagation
//!
//! Every process that runs searches (api, jobs, search) reads the admin list
//! from PostgreSQL at boot and every [`REFRESH_INTERVAL`]. The api process
//! that saves a change applies it at once. Until a process has read the admin
//! list once, external lookups are refused: an unread list must not count as
//! empty, because empty means "any public host".
//!
//! # Fetch audit
//!
//! Every outbound fetch attempt and every allowlist / SSRF refusal is audited
//! (cache hits and rate-limited calls excluded: nothing leaves the process,
//! and every audited call passed the per-process rate limiter) as
//! [`crate::audit::actions::SEARCH_INPUTLOOKUP_FETCH`] with the host, the
//! acting member, the query class (`human` / `agent`) and the outcome. The URL
//! path and query string are never recorded.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use serde_json::json;

use crate::audit::{actions, AuditEvent, AuditSource};
use crate::search::ai_command_policy::AiCommandAuditSink;

/// Operator list (comma/whitespace separated).
pub const ENV_ALLOWED_DOMAINS: &str = "INPUTLOOKUP_ALLOWED_DOMAINS";
/// `true` = the operator list overrides the admin list.
pub const ENV_ALLOWED_DOMAINS_LOCKED: &str = "INPUTLOOKUP_ALLOWED_DOMAINS_LOCKED";
/// At most this many admin entries.
pub const MAX_ADMIN_DOMAINS: usize = 256;
/// How often every process re-reads the admin list.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
/// The Settings page that edits the admin list.
pub const SETTINGS_PATH: &str = "/settings/lookup-urls";

/// Why an entered host was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    #[error("host is empty")]
    Empty,
    #[error("`{0}` is not a host name (letters, digits, hyphens and dots; no scheme, port or path)")]
    Invalid(String),
    #[error(
        "`{0}` is a top-level domain: it would allow every host under it. Enter a specific \
         host or domain, such as feeds.example.com"
    )]
    TopLevel(String),
    #[error("at most {MAX_ADMIN_DOMAINS} hosts may be listed")]
    TooMany,
}

/// Normalize one entered host: trim, drop a leading `*.` / `.` and a trailing
/// root dot, lowercase IDNA A-labels. An IP literal is kept as written
/// (normalized); the SSRF guard still refuses private addresses. A bare
/// top-level label (`com`) is refused.
pub fn normalize_domain(raw: &str) -> Result<String, DomainError> {
    let mut s = raw.trim().to_lowercase();
    if let Some(rest) = s.strip_prefix("*.") {
        s = rest.to_string();
    }
    let s = s.trim_start_matches('.').trim_end_matches('.');
    if s.is_empty() {
        return Err(DomainError::Empty);
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(ip.to_string());
    }
    let host = crate::internal_domains::canonical_host(s)
        .ok_or_else(|| DomainError::Invalid(raw.trim().to_string()))?;
    if !host.contains('.') {
        return Err(DomainError::TopLevel(host));
    }
    Ok(host)
}

/// Normalize, validate, de-duplicate and sort an admin list.
pub fn normalize_domains<I, S>(raw: I) -> Result<Vec<String>, DomainError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = std::collections::BTreeSet::new();
    for item in raw {
        out.insert(normalize_domain(item.as_ref())?);
    }
    if out.len() > MAX_ADMIN_DOMAINS {
        return Err(DomainError::TooMany);
    }
    Ok(out.into_iter().collect())
}

/// Whether `host` equals an entry or is a subdomain of one, case-insensitively,
/// ignoring a trailing root dot on either side.
pub fn host_allowed(host: &str, entries: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    entries.iter().any(|entry| {
        let entry = entry.trim().trim_end_matches('.').to_ascii_lowercase();
        !entry.is_empty() && (host == entry || host.ends_with(&format!(".{entry}")))
    })
}

/// Split an env value on commas/whitespace, dropping empty entries.
pub(crate) fn parse_env_list(raw: &str) -> Vec<String> {
    raw.split([',', ' ', '\t', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .collect()
}

fn env_flag(raw: Option<&str>) -> bool {
    matches!(
        raw.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// The operator's deployment list and whether it overrides the admin list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeploymentAllowlist {
    /// `INPUTLOOKUP_ALLOWED_DOMAINS`, lowercased.
    pub domains: Vec<String>,
    /// `INPUTLOOKUP_ALLOWED_DOMAINS_LOCKED`.
    pub locked: bool,
}

impl DeploymentAllowlist {
    pub fn from_env() -> Self {
        Self::from_values(
            std::env::var(ENV_ALLOWED_DOMAINS).ok().as_deref(),
            std::env::var(ENV_ALLOWED_DOMAINS_LOCKED).ok().as_deref(),
        )
    }

    pub fn from_values(domains: Option<&str>, locked: Option<&str>) -> Self {
        Self {
            domains: domains.map(parse_env_list).unwrap_or_default(),
            locked: env_flag(locked),
        }
    }

    /// The effective list for a given admin list (see the module docs).
    pub fn effective(&self, admin: &[String]) -> Vec<String> {
        let mut out: std::collections::BTreeSet<String> = self.domains.iter().cloned().collect();
        if !self.locked {
            out.extend(admin.iter().cloned());
        }
        out.into_iter().collect()
    }
}

// ---------------------------------------------------------------------------
// Process-wide admin list
// ---------------------------------------------------------------------------

/// `None` until this process has read the admin list once.
static ADMIN_DOMAINS: RwLock<Option<Arc<Vec<String>>>> = RwLock::new(None);
static REFRESH_STARTED: AtomicBool = AtomicBool::new(false);

/// The admin list as last read, or `None` before the first read.
pub fn admin_domains() -> Option<Arc<Vec<String>>> {
    ADMIN_DOMAINS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Replace this process's copy of the admin list (after a read or a save).
pub fn set_admin_domains(domains: Vec<String>) {
    *ADMIN_DOMAINS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::new(domains));
}

/// Read the stored admin list. Stored entries that no longer validate are
/// dropped (a hand-edited row never widens the list).
pub async fn load_admin_domains(pool: &sqlx::PgPool) -> Result<Vec<String>, sqlx::Error> {
    let stored: Option<Vec<String>> = sqlx::query_scalar::<_, Option<Vec<String>>>(
        "SELECT inputlookup_allowed_domains FROM system_settings WHERE id = 'default'",
    )
    .fetch_optional(pool)
    .await?
    .flatten();
    let mut out: Vec<String> = stored
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| normalize_domain(entry).ok())
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

/// Store a NORMALIZED admin list ([`normalize_domains`]) and return the
/// previous one.
pub async fn store_admin_domains(
    pool: &sqlx::PgPool,
    domains: &[String],
) -> Result<Vec<String>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let previous: Vec<String> = sqlx::query_scalar::<_, Option<Vec<String>>>(
        "SELECT inputlookup_allowed_domains FROM system_settings WHERE id = 'default' FOR UPDATE",
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(sqlx::Error::RowNotFound)?
    .unwrap_or_default();
    sqlx::query(
        "UPDATE system_settings SET inputlookup_allowed_domains = $1, updated_at = NOW() \
         WHERE id = 'default'",
    )
    .bind(domains)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(previous)
}

/// Read the admin list into this process. Returns whether the read worked;
/// on failure the last good copy stays in force.
pub async fn refresh_admin_domains(pool: &sqlx::PgPool) -> bool {
    match load_admin_domains(pool).await {
        Ok(domains) => {
            set_admin_domains(domains);
            true
        }
        Err(error) => {
            tracing::warn!(%error, "could not read the lookup URL allowlist; keeping the last copy");
            false
        }
    }
}

/// Read the admin list now and keep it fresh every [`REFRESH_INTERVAL`].
/// Idempotent: the refresh task starts once per process.
pub async fn start_refresh(pool: sqlx::PgPool) {
    refresh_admin_domains(&pool).await;
    if REFRESH_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(REFRESH_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            refresh_admin_domains(&pool).await;
        }
    });
}

// ---------------------------------------------------------------------------
// Fetch audit
// ---------------------------------------------------------------------------

static FETCH_AUDIT_SINK: OnceLock<Arc<dyn AiCommandAuditSink>> = OnceLock::new();

/// Install the process's fetch-audit sink (once, at boot). Later calls are
/// ignored. Takes the same non-blocking sink the AI-search policy uses.
pub fn install_fetch_audit_sink(sink: Arc<dyn AiCommandAuditSink>) {
    let _ = FETCH_AUDIT_SINK.set(sink);
}

/// What became of one external lookup fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchOutcome {
    /// The host answered 2xx.
    Fetched,
    /// The host answered a non-2xx status.
    HttpError,
    /// The host (or a redirect target) is not on the allowlist.
    RefusedAllowlist,
    /// The SSRF guard refused the address, scheme or redirect.
    RefusedSsrf,
    /// The allowlist has not been read yet in this process.
    AllowlistUnavailable,
    /// The per-process fetch rate limit was hit (classified, not audited).
    RateLimited,
    /// The request timed out.
    Timeout,
    /// Any other transport or body error.
    Failed,
}

impl FetchOutcome {
    pub const fn label(self) -> &'static str {
        match self {
            FetchOutcome::Fetched => "fetched",
            FetchOutcome::HttpError => "http_error",
            FetchOutcome::RefusedAllowlist => "refused_allowlist",
            FetchOutcome::RefusedSsrf => "refused_ssrf",
            FetchOutcome::AllowlistUnavailable => "allowlist_unavailable",
            FetchOutcome::RateLimited => "rate_limited",
            FetchOutcome::Timeout => "timeout",
            FetchOutcome::Failed => "failed",
        }
    }
}

/// The host of a URL for the audit record: lowercased, no scheme, port, path
/// or query. `None` when the text does not parse as a URL with a host.
pub fn audit_host(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim_end_matches('.').to_ascii_lowercase()))
}

/// The audit event for one fetch. `host` must already be host-only.
pub fn fetch_audit_event(
    actor: Option<uuid::Uuid>,
    query_class: &str,
    host: &str,
    outcome: FetchOutcome,
    status: Option<u16>,
    refused_host: Option<&str>,
) -> AuditEvent {
    let mut details = json!({
        "host": host,
        "query_class": query_class,
        "outcome": outcome.label(),
    });
    if let Some(status) = status {
        details["status"] = json!(status);
    }
    if let Some(refused) = refused_host.filter(|r| *r != host) {
        details["refused_host"] = json!(refused);
    }
    AuditEvent::builder(AuditSource::Search, actions::SEARCH_INPUTLOOKUP_FETCH)
        .actor(actor, None)
        .resource("inputlookup_url", None, Some(host.to_string()))
        .success(outcome == FetchOutcome::Fetched)
        .details(details)
        .build()
}

/// Audit one fetch with the current request's caller (member, API key and
/// client IP, NAN-5456) and query class.
pub(crate) fn audit_fetch(
    host: &str,
    outcome: FetchOutcome,
    status: Option<u16>,
    refused_host: Option<&str>,
) {
    let Some(sink) = FETCH_AUDIT_SINK.get() else {
        return;
    };
    let caller = crate::search::ai_command_policy::current_search_audit_caller();
    let class = crate::search::admission::current_query_class().label();
    let mut event = fetch_audit_event(caller.actor_id, class, host, outcome, status, refused_host);
    event.api_key_id = caller.api_key_id;
    event.api_key_name = caller.api_key_name;
    event.ip_address = caller.client.ip_address;
    event.user_agent = caller.client.user_agent;
    sink.submit(event);
}

#[cfg(test)]
#[path = "allowlist_tests.rs"]
mod tests;
