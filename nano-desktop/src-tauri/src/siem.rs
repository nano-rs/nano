//! The SIEM client. Every HTTP request the app makes originates here, in Rust.
//!
//! This is not an implementation detail — it is the reason the app works at all.
//! `nanosiem-api` only allows CORS origins it has been explicitly configured
//! with (see `nanosiem-api/src/routes.rs` `build_cors_layer`). A webview's
//! origin is `tauri://localhost`, which no operator will have in their allowlist,
//! so `fetch()` from the frontend would be blocked against every real instance.
//! Requests issued from Rust are not subject to CORS at all.
//!
//! It also means the access token never enters JavaScript's reach.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{Timelike, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::ipc::Channel;
use tokio::sync::{Mutex, RwLock};

use crate::agent::NOTEBOOK_PREFIX as PIVT_NOTEBOOK_PREFIX;
use crate::error::{Error, Result};
use crate::store::{self, ServerConfig};

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const SEARCH_TIMEOUT: Duration = Duration::from_secs(180);
/// A single SSE frame this large means something has gone wrong upstream; large
/// row batches arrive as many frames, not one enormous one.
const MAX_SSE_BUFFER: usize = 64 * 1024 * 1024;

#[derive(Default)]
struct Inner {
    server: Option<ServerConfig>,
    http: Option<reqwest::Client>,
    /// In memory only, never persisted.
    access_token: Option<String>,
    user: Option<Value>,
}

#[derive(Default)]
pub struct Siem {
    inner: RwLock<Inner>,
    /// Serializes token refresh so a burst of 401s triggers one refresh, not N.
    refresh_lock: Mutex<()>,
    /// Whether a session is deliberately live. Gates the *background* 401→refresh
    /// path so it can never resurrect a session the user just Locked: a poll
    /// in-flight at the instant of Lock could otherwise 401, silently refresh
    /// (no Touch ID), and repopulate the token — leaving the tray polling and
    /// firing alert banners on a "locked" machine. `unlock` refreshes via
    /// `do_refresh` directly (Touch-ID-gated), so it is unaffected by this gate.
    session_active: AtomicBool,
    /// Cancel flags keyed by search id (one per tab). Keyed rather than single,
    /// because tabs stream concurrently: a global flag would mean running a
    /// query in one tab silently killed another tab's in-flight stream.
    active_searches: Mutex<HashMap<String, Arc<AtomicBool>>>,
}

/// Mirrors `LoginResult` in nanosiem-core/src/auth/types.rs, which is an
/// internally-tagged enum on `status`.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LoginOutcome {
    Authenticated { user: Value },
    MfaRequired { challenge_token: String },
    /// Admin-enforced first-time MFA enrollment. Enrollment itself is a web-app
    /// flow today, so the desktop app explains rather than pretends.
    MfaSetupRequired { challenge_token: String },
}

#[derive(Debug, Serialize)]
pub struct RestoreOutcome {
    pub server: Option<ServerConfig>,
    /// Present only after a successful unlock — launching the app no longer
    /// signs you in on its own.
    pub user: Option<Value>,
    /// The keychain holds a refresh token for this server: the device is
    /// trusted, and Touch ID will get us in without a password.
    pub trusted: bool,
    /// Whose session that token belongs to, for the trusted-device card.
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenPair {
    access_token: String,
    refresh_token: String,
}

/// One alert from the `/api/alerts/stream` feed. Only the handful of fields the
/// tray needs — the full row (with its heavy `matched_events` blob) is not
/// deserialized. Many fields are `skip_serializing_if = "Option::is_none"` on
/// the server, hence absent (not null); `#[serde(default)]` tolerates that.
#[derive(Debug, Deserialize)]
pub struct AlertSummary {
    // The alert `id` (typeid `alert_…`) is intentionally not captured yet: v1
    // notifications are click-to-focus, so nothing routes to a specific alert.
    // Add it back with the deferred "View" action. serde ignores it on the wire.
    /// Lowercase: critical | high | medium | low | informational.
    #[serde(default)]
    pub severity: String,
    /// Absent when the rule was deleted (FK set null); this is the closest thing
    /// to a title the alert has.
    #[serde(default)]
    pub rule_name: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    /// For risk notables, `"<entity_type>:<entity>"`; otherwise a rule/monitor id.
    #[serde(default)]
    pub source_id: Option<String>,
}

/// A page of the keyset alert feed. `next_cursor` is `None` on an empty page —
/// the caller must KEEP its previous cursor then, not reset (a missing cursor
/// replays from the beginning of time).
#[derive(Debug, Deserialize)]
pub struct AlertPage {
    #[serde(default)]
    pub alerts: Vec<AlertSummary>,
    #[serde(default)]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}

/// One asset (an internal host/IP) that communicated with an indicator, and how
/// many times — the "who has actually seen this" an analyst asks for first.
#[derive(Debug, Serialize)]
pub struct AssetHit {
    pub asset: String,
    pub hits: u64,
}

/// Quick Search's indicator peek, assembled from a SEARCH (`ioc = "<value>"`)
/// rather than the prevalence/enrichment REST endpoints. Answers "how much, on
/// which assets, since when" straight from the matching events. `seen` is simply
/// whether any event matched — no fabricated verdict, and CONTEXT not a
/// malicious/benign judgement (nano's open build has no per-indicator verdict).
#[derive(Debug, Serialize)]
pub struct IocPeek {
    pub indicator: String,
    pub seen: bool,
    pub events: u64,
    /// Distinct source assets that saw it — the honest prevalence signal.
    pub assets: u64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub top_assets: Vec<AssetHit>,
    pub window_days: u32,
}

/// How far back the peek searches. Wide enough to answer "have we seen this
/// recently" without scanning all retention; the `ioc =` filter is indexed, so
/// the aggregation stays cheap even over the window.
const IOC_PEEK_WINDOW_DAYS: i64 = 30;

/// One indicator's standing in the data. The bulk answer to "which of these 47
/// have we actually seen?".
#[derive(Debug, Serialize)]
pub struct BulkIocHit {
    pub indicator: String,
    pub seen: bool,
    pub events: u64,
    pub assets: u64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    /// Only populated for indicators we actually saw — see `bulk_ioc_peek`.
    pub top_assets: Vec<AssetHit>,
    /// This indicator's search failed. Deliberately distinct from `seen: false`,
    /// which means the search RAN and found nothing — conflating "we didn't see
    /// it" with "we couldn't look" is how a bulk lookup tells an analyst that a
    /// compromised host is clean.
    pub error: Option<String>,
}

/// Everything the SOC Overview shows, gathered in one round trip.
///
/// Assembled in Rust rather than as five calls from the webview, because the
/// webview cannot make them: all HTTP originates here. It also means the pinned
/// widget windows and the dashboard read exactly the same numbers.
#[derive(Debug, Serialize)]
pub struct Dashboard {
    pub events_24h: u64,
    /// Events per second, AVERAGED over the window — not an instantaneous rate,
    /// and labelled as an average wherever it is shown.
    pub eps: f64,
    pub ingest: Vec<Bucket>,
    pub top_talkers: Vec<AssetHit>,
    pub alerts_total: i64,
    pub alerts_new: i64,
    pub by_severity: HashMap<String, i64>,
    pub latest: Vec<Value>,
    pub sources: u64,
    /// So the UI can say how stale it is instead of implying it is live.
    pub generated_at: String,
    /// Which panels failed. A dashboard that renders a confident 0 because the
    /// request was refused is telling the analyst the SOC is quiet when in fact
    /// they simply aren't allowed to look.
    pub degraded: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Bucket {
    pub at: String,
    pub count: u64,
}

/// A pasted report is a few dozen indicators; a pasted feed can be thousands.
/// This runs one search per indicator, so the cap is what stops a careless paste
/// from becoming a query storm against the analyst's own cluster.
const MAX_BULK_INDICATORS: usize = 200;
/// How many of those searches are in flight at once.
const BULK_CONCURRENCY: usize = 8;
/// Top assets are a second query each, so they are fetched only for the
/// indicators that matched — for a threat report, the handful that matter.
const MAX_ASSET_LOOKUPS: usize = 25;
/// `| head 6` in the assets query, so six rows come back.
const ASSET_ROWS: u32 = 6;
/// `| head 8` in the top-talkers query.
const TOP_TALKERS: u32 = 8;
/// Hourly buckets over a 24h window: 25 at most, plus slack. This MUST exceed the
/// bucket count or the newest hours are cut and read as zero.
const INGEST_BUCKETS: u32 = 48;

/// Accepts `https://host`, `host`, `host:3000`, `https://host/nano` and
/// normalizes to a base with no trailing slash. A bare host defaults to https —
/// never silently downgrade a SIEM connection to cleartext.
fn normalize_url(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidUrl("Enter a server address.".into()));
    }

    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };

    let url = url::Url::parse(&candidate)
        .map_err(|e| Error::InvalidUrl(format!("That is not a valid URL: {e}")))?;

    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(Error::InvalidUrl(format!(
                "Unsupported scheme '{other}' — use http or https."
            )))
        }
    }
    let Some(host) = url.host() else {
        return Err(Error::InvalidUrl("That URL has no host.".into()));
    };
    // `http` sends the password on login and the bearer/refresh tokens on every
    // request in cleartext. Permit it only for loopback (local dev); to any
    // other host it is a credential-disclosure bug, not a convenience — refuse
    // it rather than silently transmitting secrets on the wire. (`allow_insecure`
    // governs TLS *cert* trust for self-signed HTTPS, a different concern.)
    if url.scheme() == "http" && !is_loopback_host(&host) {
        return Err(Error::InvalidUrl(
            "Refusing to connect over http to a remote host — credentials would be \
             sent in cleartext. Use https (accept a self-signed certificate if needed)."
                .into(),
        ));
    }

    let mut base = url.origin().ascii_serialization();
    let path = url.path().trim_end_matches('/');
    if !path.is_empty() {
        base.push_str(path);
    }
    Ok(base)
}

/// Loopback in the transport sense — the only place cleartext `http` is safe,
/// since the bytes never leave the machine. `localhost` resolves to a loopback
/// address by convention (RFC 6761).
fn is_loopback_host(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Ipv4(addr) => addr.is_loopback(),
        url::Host::Ipv6(addr) => addr.is_loopback(),
        url::Host::Domain(name) => {
            name.eq_ignore_ascii_case("localhost") || name.eq_ignore_ascii_case("localhost.")
        }
    }
}

/// Percent-encode a query-string value. Timestamps carry `:` and `+`, which
/// would otherwise be read as delimiters.
fn urlencoding(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn build_client(allow_insecure: bool) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(allow_insecure)
        .user_agent(concat!("nano-desktop/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| Error::Internal(format!("http client: {e}")))
}

/// `/health` is unauthenticated and returns `{"status": ...}` on both the API
/// and the search service — enough to tell a nano instance from an arbitrary
/// web server before we ask anyone for a password.
async fn probe_health(http: &reqwest::Client, base_url: &str) -> Result<()> {
    let response = http
        .get(format!("{base_url}/health"))
        .timeout(PROBE_TIMEOUT)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(Error::NotNano(format!(
            "{base_url} answered {} — check the address.",
            response.status()
        )));
    }

    let looks_like_nano = response
        .json::<Value>()
        .await
        .ok()
        .and_then(|v| v.get("status").cloned())
        .is_some();
    if !looks_like_nano {
        return Err(Error::NotNano(format!(
            "Something is running at {base_url}, but it is not a nano instance."
        )));
    }
    Ok(())
}

/// Pull the most useful message out of a non-2xx response body.
async fn api_error(response: reqwest::Response) -> Error {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    let message = serde_json::from_str::<Value>(&body)
        .ok()
        .and_then(|v| {
            let pick = |val: &Value| val.as_str().map(str::to_string);
            pick(v.get("message")?)
                .or_else(|| pick(v.get("error")?))
                .or_else(|| pick(v.get("error")?.get("message")?))
        })
        .unwrap_or_else(|| {
            if body.trim().is_empty() || body.len() > 300 {
                format!("The server returned {status}.")
            } else {
                body.trim().to_string()
            }
        });

    match status.as_u16() {
        401 | 403 => Error::Unauthorized(message),
        429 => Error::RateLimited(message),
        _ => Error::Server(message),
    }
}

impl Siem {
    async fn snapshot(&self) -> Result<(reqwest::Client, String, Option<String>)> {
        let inner = self.inner.read().await;
        let http = inner.http.clone().ok_or(Error::NotConnected)?;
        let base = inner
            .server
            .as_ref()
            .map(|s| s.base_url.clone())
            .ok_or(Error::NotConnected)?;
        Ok((http, base, inner.access_token.clone()))
    }

    /// Probe a candidate server. `/health` is unauthenticated and returns
    /// `{"status": ...}` (PublicHealthResponse) — enough to tell a nano
    /// instance from an arbitrary web server before we ask for a password.
    pub async fn connect(
        &self,
        app: &tauri::AppHandle,
        input_url: &str,
        search_url: Option<&str>,
        allow_insecure: bool,
    ) -> Result<ServerConfig> {
        let base_url = normalize_url(input_url)?;
        let search_url = match search_url.map(str::trim).filter(|s| !s.is_empty()) {
            Some(url) => Some(normalize_url(url)?),
            None => None,
        };
        let http = build_client(allow_insecure)?;

        probe_health(&http, &base_url).await?;
        // Verify the search service too — otherwise a wrong override only shows
        // up as a failed query later, which reads as "search is broken".
        if let Some(search) = &search_url {
            probe_health(&http, search).await?;
        }

        let server = ServerConfig {
            base_url,
            search_url,
            allow_insecure,
            // Cleared on purpose: a new server means a different identity, and
            // the old one's trusted-device card must not follow it here.
            last_email: None,
        };
        store::save_server(app, &server)?;

        // Point at a new server ⇒ any in-memory session belongs to the old one.
        self.session_active.store(false, Ordering::Relaxed);
        let mut inner = self.inner.write().await;
        inner.server = Some(server.clone());
        inner.http = Some(http);
        inner.access_token = None;
        inner.user = None;

        Ok(server)
    }

    /// Adopt an `{user, tokens}` payload: access token to memory, refresh token
    /// to the keychain.
    ///
    /// Also remembers the email, so the next launch can say *whose* device this
    /// is on the trusted-device card.
    async fn adopt_session(&self, app: &tauri::AppHandle, payload: &Value) -> Result<Value> {
        let user = payload
            .get("user")
            .cloned()
            .ok_or_else(|| Error::Internal("login response had no user".into()))?;
        let tokens: TokenPair = payload
            .get("tokens")
            .cloned()
            .ok_or_else(|| Error::Internal("login response had no tokens".into()))
            .and_then(|t| {
                serde_json::from_value(t)
                    .map_err(|e| Error::Internal(format!("malformed tokens: {e}")))
            })?;

        let server = {
            let mut inner = self.inner.write().await;
            inner.access_token = Some(tokens.access_token);
            inner.user = Some(user.clone());
            inner.server.clone().ok_or(Error::NotConnected)?
        };
        store::save_refresh_token(&server.base_url, &tokens.refresh_token)?;
        self.session_active.store(true, Ordering::Relaxed);

        // This device is now trusted for this identity.
        if let Some(email) = user.get("email").and_then(Value::as_str) {
            let mut updated = server.clone();
            updated.last_email = Some(email.to_string());
            store::save_server(app, &updated)?;
            self.inner.write().await.server = Some(updated);
        }

        Ok(user)
    }

    pub async fn login(
        &self,
        app: &tauri::AppHandle,
        email: &str,
        password: &str,
    ) -> Result<LoginOutcome> {
        let (http, base, _) = self.snapshot().await?;

        let response = http
            .post(format!("{base}/api/auth/login"))
            .timeout(AUTH_TIMEOUT)
            .json(&serde_json::json!({ "email": email, "password": password }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(api_error(response).await);
        }
        let payload: Value = response
            .json()
            .await
            .map_err(|e| Error::Internal(format!("malformed login response: {e}")))?;

        let challenge = |payload: &Value| -> Result<String> {
            payload
                .get("challenge_token")
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| Error::Internal("MFA response had no challenge token".into()))
        };

        match payload.get("status").and_then(Value::as_str) {
            Some("mfa_required") => Ok(LoginOutcome::MfaRequired {
                challenge_token: challenge(&payload)?,
            }),
            Some("mfa_setup_required") => Ok(LoginOutcome::MfaSetupRequired {
                challenge_token: challenge(&payload)?,
            }),
            // "authenticated", or an untagged {user, tokens} from an older server.
            _ => Ok(LoginOutcome::Authenticated {
                user: self.adopt_session(app, &payload).await?,
            }),
        }
    }

    pub async fn verify_mfa(
        &self,
        app: &tauri::AppHandle,
        challenge_token: &str,
        code: &str,
    ) -> Result<LoginOutcome> {
        let (http, base, _) = self.snapshot().await?;

        let response = http
            .post(format!("{base}/api/auth/mfa/challenge"))
            .timeout(AUTH_TIMEOUT)
            .json(&serde_json::json!({
                "challenge_token": challenge_token,
                "code": code,
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(api_error(response).await);
        }
        let payload: Value = response
            .json()
            .await
            .map_err(|e| Error::Internal(format!("malformed MFA response: {e}")))?;

        Ok(LoginOutcome::Authenticated {
            user: self.adopt_session(app, &payload).await?,
        })
    }

    /// Exchange the stored refresh token for a new pair.
    async fn do_refresh(&self) -> Result<()> {
        let (http, base, _) = self.snapshot().await?;
        let refresh_token = store::load_refresh_token(&base).ok_or(Error::SessionExpired)?;

        let response = http
            .post(format!("{base}/api/auth/refresh"))
            .timeout(AUTH_TIMEOUT)
            .json(&serde_json::json!({ "refresh_token": refresh_token }))
            .send()
            .await?;

        if !response.status().is_success() {
            // A rejected refresh token is dead weight — drop it so the next
            // launch goes straight to the login screen instead of retrying.
            let _ = store::clear_refresh_token(&base);
            self.inner.write().await.access_token = None;
            self.session_active.store(false, Ordering::Relaxed);
            return Err(Error::SessionExpired);
        }

        let tokens: TokenPair = response
            .json()
            .await
            .map_err(|e| Error::Internal(format!("malformed refresh response: {e}")))?;

        self.inner.write().await.access_token = Some(tokens.access_token);
        store::save_refresh_token(&base, &tokens.refresh_token)?;
        Ok(())
    }

    /// Refresh unless another task already did it while we were queued behind
    /// the lock (`stale` is the token that just got a 401).
    async fn refresh_if_stale(&self, stale: Option<String>) -> Result<()> {
        // A background 401 must not resurrect a locked/ended session. Only an
        // explicit, Touch-ID-gated `unlock` (which calls `do_refresh` directly)
        // may bring a session back.
        if !self.session_active.load(Ordering::Relaxed) {
            return Err(Error::SessionExpired);
        }
        let _guard = self.refresh_lock.lock().await;
        let current = self.inner.read().await.access_token.clone();
        if current.is_some() && current != stale {
            return Ok(());
        }
        self.do_refresh().await
    }

    /// Authenticated request with one transparent refresh-and-retry on 401.
    async fn authed(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
        timeout: Duration,
    ) -> Result<Value> {
        let (http, base, mut token) = self.snapshot().await?;

        for attempt in 0..2 {
            let token_used = token.clone().ok_or(Error::SessionExpired)?;

            let mut request = http
                .request(method.clone(), format!("{base}{path}"))
                .timeout(timeout)
                .bearer_auth(&token_used);
            if let Some(body) = body {
                request = request.json(body);
            }

            let response = request.send().await?;

            if response.status() == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
                self.refresh_if_stale(Some(token_used)).await?;
                token = self.inner.read().await.access_token.clone();
                continue;
            }
            if !response.status().is_success() {
                return Err(api_error(response).await);
            }
            return response
                .json()
                .await
                .map_err(|e| Error::Internal(format!("malformed response: {e}")));
        }

        Err(Error::SessionExpired)
    }

    /// What we know at launch — deliberately WITHOUT signing anyone in.
    ///
    /// Silently restoring a session meant anyone who opened the app on an
    /// unlocked Mac was inside the SIEM. A remembered device now surfaces as a
    /// trusted-device card that Touch ID unlocks (`unlock`).
    pub async fn restore(&self, app: &tauri::AppHandle) -> Result<RestoreOutcome> {
        let Some(server) = store::load_server(app) else {
            return Ok(RestoreOutcome {
                server: None,
                user: None,
                trusted: false,
                email: None,
            });
        };

        let http = build_client(server.allow_insecure)?;
        {
            let mut inner = self.inner.write().await;
            inner.server = Some(server.clone());
            inner.http = Some(http);
        }

        let trusted = store::load_refresh_token(&server.base_url).is_some();
        let email = server.last_email.clone();

        Ok(RestoreOutcome {
            server: Some(server),
            user: None,
            trusted,
            email,
        })
    }

    /// The trusted-device fast path: Touch ID, then exchange the stored refresh
    /// token for a live session. No password.
    pub async fn unlock(&self) -> Result<Value> {
        let server = self
            .inner
            .read()
            .await
            .server
            .clone()
            .ok_or(Error::NotConnected)?;

        let who = server
            .last_email
            .clone()
            .unwrap_or_else(|| "this device".to_string());
        crate::biometric::authenticate(format!("Unlock nano as {who}")).await?;

        // Only after the human proves they're there do we touch the token.
        self.do_refresh().await?;
        // The session is deliberately live again — re-enable background refresh.
        self.session_active.store(true, Ordering::Relaxed);

        let user = self
            .authed(reqwest::Method::GET, "/api/auth/me", None, AUTH_TIMEOUT)
            .await?;
        self.inner.write().await.user = Some(user.clone());
        Ok(user)
    }

    /// Lock: end the session, keep the device trusted.
    ///
    /// This distinction is what makes Touch ID reachable at all. Locking drops
    /// the live access token but leaves the refresh token in the keychain, so
    /// `unlock` (Touch ID) gets straight back in. Signing out destroys that
    /// token and demands a password next time.
    pub async fn lock(&self) -> Result<()> {
        // Stop the background refresh path first: an in-flight poll that 401s
        // right now must NOT be allowed to refresh and re-arm the session.
        self.session_active.store(false, Ordering::Relaxed);
        let mut inner = self.inner.write().await;
        inner.access_token = None;
        inner.user = None;
        Ok(())
    }

    pub async fn logout(&self) -> Result<()> {
        self.session_active.store(false, Ordering::Relaxed);
        if let Ok((http, base, _)) = self.snapshot().await {
            if let Some(refresh_token) = store::load_refresh_token(&base) {
                // Best-effort: revoke server-side, but never block sign-out on it.
                let _ = http
                    .post(format!("{base}/api/auth/logout"))
                    .timeout(AUTH_TIMEOUT)
                    .json(&serde_json::json!({ "refresh_token": refresh_token }))
                    .send()
                    .await;
            }
            let _ = store::clear_refresh_token(&base);
        }

        let mut inner = self.inner.write().await;
        inner.access_token = None;
        inner.user = None;
        Ok(())
    }

    /// Forget the server entirely (sign out, then drop the remembered address).
    pub async fn disconnect(&self, app: &tauri::AppHandle) -> Result<()> {
        self.logout().await?;
        store::clear_server(app)?;

        let mut inner = self.inner.write().await;
        inner.server = None;
        inner.http = None;
        Ok(())
    }

    /// The active schema profile (UDM or OCSF) and its promoted field universe.
    /// The same event is `user`/`src_ip` under one and `actor.user.name`/
    /// `src_endpoint.ip` under the other, so the row renderer has to know which.
    pub async fn schema_fields(&self) -> Result<Value> {
        self.authed(
            reqwest::Method::GET,
            "/api/schema/fields",
            None,
            AUTH_TIMEOUT,
        )
        .await
    }

    /// Source types present in the data — the values offered after `source_type=`.
    pub async fn source_types(&self, start: Option<&str>, end: Option<&str>) -> Result<Value> {
        let path = match (start, end) {
            (Some(start), Some(end)) => format!(
                "/api/source-types?start={}&end={}",
                urlencoding(start),
                urlencoding(end)
            ),
            _ => "/api/source-types".to_string(),
        };
        self.authed(reqwest::Method::GET, &path, None, AUTH_TIMEOUT)
            .await
    }

    /// UDM field universe. Unlike `/api/schema/fields` this carries the
    /// human-readable descriptions autocomplete shows next to each field.
    pub async fn udm_fields(&self) -> Result<Value> {
        self.authed(reqwest::Method::GET, "/api/udm/fields", None, AUTH_TIMEOUT)
            .await
    }

    /// Is there a live session right now? The tray watcher checks this before
    /// polling so a locked/signed-out app goes quiet instead of spewing
    /// `SessionExpired` — and, crucially, so `lock` actually PAUSES the watcher:
    /// with no access token, `authed` returns immediately without refreshing, so
    /// polling can never silently un-lock a device the user locked.
    pub async fn is_authenticated(&self) -> bool {
        self.inner.read().await.access_token.is_some()
    }

    /// One page of the "new alerts since cursor" keyset feed (`GET
    /// /api/alerts/stream`). Ordered ascending by `(created_at, id)`, so with a
    /// persisted cursor each alert is delivered exactly once. The server holds a
    /// ~5s safety lag, so a just-written alert surfaces a beat later, not
    /// instantly. `cursor = None` starts from the beginning of time — the caller
    /// (tray watcher) seeds a "now" cursor first so it doesn't replay history.
    pub async fn poll_alerts(&self, cursor: Option<&str>, limit: i64) -> Result<AlertPage> {
        let path = match cursor {
            Some(cursor) => format!(
                "/api/alerts/stream?cursor={}&limit={}",
                urlencoding(cursor),
                limit
            ),
            None => format!("/api/alerts/stream?limit={limit}"),
        };
        let value = self
            .authed(reqwest::Method::GET, &path, None, AUTH_TIMEOUT)
            .await?;
        serde_json::from_value(value)
            .map_err(|e| Error::Internal(format!("malformed alert stream page: {e}")))
    }

    /// Synchronous search against the search service (`POST /api/search`),
    /// returning the whole result JSON. For compact lookups (the Quick Search
    /// peek) where streaming would be overkill. Mirrors `run_stream`'s auth:
    /// bearer token against `search_base()` with one transparent refresh-retry.
    async fn search_json(&self, request: &Value) -> Result<Value> {
        let (http, server, mut token) = {
            let inner = self.inner.read().await;
            (
                inner.http.clone().ok_or(Error::NotConnected)?,
                inner.server.clone().ok_or(Error::NotConnected)?,
                inner.access_token.clone(),
            )
        };
        let url = format!("{}/api/search", server.search_base());

        for attempt in 0..2 {
            let token_used = token.clone().ok_or(Error::SessionExpired)?;
            let response = http
                .post(&url)
                .timeout(SEARCH_TIMEOUT)
                .bearer_auth(&token_used)
                .json(request)
                .send()
                .await?;
            if response.status() == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
                self.refresh_if_stale(Some(token_used)).await?;
                token = self.inner.read().await.access_token.clone();
                continue;
            }
            if !response.status().is_success() {
                return Err(api_error(response).await);
            }
            return response
                .json()
                .await
                .map_err(|e| Error::Internal(format!("malformed search response: {e}")));
        }
        Err(Error::SessionExpired)
    }

    /// Quick Search's indicator peek, from a SEARCH rather than the prevalence /
    /// enrichment REST endpoints. `ioc = "<value>"` matches the indicator across
    /// whatever columns hold it (profile-agnostic), and two small `| stats`
    /// aggregations answer "how much, on which assets, since when". This needs
    /// only the analyst's normal search auth (no `prevalence:view`), and isn't
    /// blind the way a 24h prevalence window is to data a few days old.
    pub async fn ioc_peek(&self, value: &str) -> Result<IocPeek> {
        let time_range = peek_window(IOC_PEEK_WINDOW_DAYS);

        // Bind the request bodies so they outlive the concurrent borrows in join!.
        let summary_req = peek_request(&summary_query(value), &time_range, 1);
        let assets_req = peek_request(&assets_query(value), &time_range, ASSET_ROWS);
        // Both aggregate the same matched set — run them at once.
        let (summary, assets) =
            tokio::join!(self.search_json(&summary_req), self.search_json(&assets_req));

        // The summary drives the peek; if the search itself failed, surface it.
        let summary = read_summary(&summary?).ok_or_else(malformed)?;

        Ok(IocPeek {
            indicator: value.to_string(),
            seen: summary.events > 0,
            events: summary.events,
            assets: summary.assets,
            first_seen: summary.first_seen,
            last_seen: summary.last_seen,
            // Top assets are a best-effort extra — never fail the peek over them.
            top_assets: assets.ok().as_ref().map(read_assets).unwrap_or_default(),
            window_days: IOC_PEEK_WINDOW_DAYS as u32,
        })
    }

    /// "Which of these 47 indicators have we actually seen?" — the question an
    /// analyst asks of a threat report.
    ///
    /// One search per indicator, run with bounded concurrency, over the SAME
    /// `ioc = "…"` path as the single peek. NOT `/api/prevalence/bulk`: that
    /// endpoint needs `prevalence:view` (which a normal analyst may not hold), is
    /// blind to anything outside its own window, and — worse — fabricates an
    /// all-zeros "seen" row for an artifact it has never heard of (NAN-1826). A
    /// bulk lookup that invents a clean verdict is the one failure mode this
    /// feature cannot have.
    pub async fn bulk_ioc_peek(&self, values: &[String], window_days: i64) -> Result<Vec<BulkIocHit>> {
        if values.len() > MAX_BULK_INDICATORS {
            return Err(Error::Internal(format!(
                "That's {} indicators. This looks up at most {MAX_BULK_INDICATORS} at a time \
                 — it runs one search each, and a bigger batch would be a query storm \
                 against your own cluster.",
                values.len()
            )));
        }
        let time_range = peek_window(window_days.clamp(1, 365));

        // Phase 1: does the data know this indicator at all, and how much.
        // Each task owns its indicator and its request — borrowing them out of the
        // caller's slice inside an async block is what a `#[tauri::command]`'s
        // higher-ranked lifetimes will not accept.
        let summaries: Vec<(usize, String, Value)> = values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                (index, value.clone(), peek_request(&summary_query(value), &time_range, 1))
            })
            .collect();

        let mut hits: Vec<(usize, BulkIocHit)> = futures_util::stream::iter(summaries)
            .map(|(index, indicator, request)| async move {
                // A 200 that isn't a result set is a FAILURE, not an empty answer —
                // `read_summary` returns None for it rather than a confident zero.
                let outcome = self
                    .search_json(&request)
                    .await
                    .and_then(|response| read_summary(&response).ok_or_else(malformed));

                let hit = match outcome {
                    Ok(summary) => BulkIocHit {
                        indicator,
                        seen: summary.events > 0,
                        events: summary.events,
                        assets: summary.assets,
                        first_seen: summary.first_seen,
                        last_seen: summary.last_seen,
                        top_assets: Vec::new(),
                        error: None,
                    },
                    // One indicator failing must not fail the batch — but it must
                    // not be reported as "not seen" either.
                    Err(e) => BulkIocHit {
                        indicator,
                        seen: false,
                        events: 0,
                        assets: 0,
                        first_seen: None,
                        last_seen: None,
                        top_assets: Vec::new(),
                        error: Some(e.to_string()),
                    },
                };
                (index, hit)
            })
            .buffer_unordered(BULK_CONCURRENCY)
            .collect()
            .await;

        // `buffer_unordered` yields them as they finish. The analyst pasted a list
        // in an order; give it back in that order.
        hits.sort_by_key(|(index, _)| *index);
        let mut hits: Vec<BulkIocHit> = hits.into_iter().map(|(_, hit)| hit).collect();

        // Phase 2: WHERE did we see it. Only for the ones we did — which, for a
        // threat report, is the handful that actually matter.
        let lookups: Vec<(usize, Value)> = hits
            .iter()
            .enumerate()
            .filter(|(_, hit)| hit.seen)
            .take(MAX_ASSET_LOOKUPS)
            .map(|(index, hit)| {
                (index, peek_request(&assets_query(&hit.indicator), &time_range, ASSET_ROWS))
            })
            .collect();

        let assets: Vec<(usize, Vec<AssetHit>)> = futures_util::stream::iter(lookups)
            .map(|(index, request)| async move {
                let found = self
                    .search_json(&request)
                    .await
                    .ok()
                    .as_ref()
                    .map(read_assets)
                    .unwrap_or_default();
                (index, found)
            })
            .buffer_unordered(BULK_CONCURRENCY)
            .collect()
            .await;

        for (index, found) in assets {
            hits[index].top_assets = found;
        }

        Ok(hits)
    }

    /// Open a notebook for a pivt session.
    ///
    /// Written with the USER's session, not the agent's API key: the agent's
    /// credential stays read-only (it cannot write anything, by design), while
    /// the record of what it did is attributed to the analyst who ran it — which
    /// is what an investigation trail needs anyway.
    pub async fn create_notebook(&self, title: &str) -> Result<Value> {
        let body = serde_json::json!({ "title": title, "visibility": "private" });
        self.authed(
            reqwest::Method::POST,
            "/api/notebooks",
            Some(&body),
            AUTH_TIMEOUT,
        )
        .await
    }

    /// The SOC Overview, in one call.
    ///
    /// Every panel is fetched concurrently and every one is allowed to fail on its
    /// own: a missing `alerts:view` permission should cost the analyst the alert
    /// cards, not the whole dashboard. What failed is named in `degraded` — a
    /// panel that quietly renders 0 because the request 403'd is a dashboard
    /// telling you the SOC is quiet when you simply aren't allowed to look.
    pub async fn dashboard(&self) -> Result<Dashboard> {
        let end = Utc::now();
        let start = end - chrono::Duration::hours(24);
        let time_range = serde_json::json!({
            "start": start.to_rfc3339(),
            "end": end.to_rfc3339(),
        });

        // One row per hour in the window, plus slack for a partial bucket at each
        // end. Under-asking here silently flatlines the newest hours of the chart.
        let ingest_req = peek_request("* | timechart span=1h count", &time_range, INGEST_BUCKETS);
        let talkers_req = peek_request(
            "* | stats count by src_ip | sort -count | head 8",
            &time_range,
            TOP_TALKERS,
        );

        let (ingest, talkers, counts, latest, sources) = tokio::join!(
            self.search_json(&ingest_req),
            self.search_json(&talkers_req),
            self.authed(
                reqwest::Method::GET,
                "/api/alerts/counts",
                None,
                AUTH_TIMEOUT
            ),
            self.authed(
                reqwest::Method::GET,
                "/api/alerts?limit=6",
                None,
                AUTH_TIMEOUT
            ),
            self.source_types(None, None),
        );

        let mut degraded = Vec::new();
        let mut events_24h: u64 = 0;

        // Ingest, hourly. `timechart` returns `{time_bucket, count}` — verified
        // against the live search service, not assumed.
        let buckets: Vec<Bucket> = match &ingest {
            Ok(response) => {
                let counts: HashMap<String, u64> = rows(response)
                    .iter()
                    .filter_map(|row| {
                        Some((
                            row.get("time_bucket").and_then(Value::as_str)?.to_string(),
                            row.get("count").and_then(Value::as_u64).unwrap_or(0),
                        ))
                    })
                    .collect();
                // The total comes from what the SERVER returned, not from the
                // padded series — so if the series is ever short, the KPI is still
                // the real number rather than quietly agreeing with the chart.
                events_24h = counts.values().sum();
                hourly_series(start, end, &counts)
            }
            Err(e) => {
                degraded.push(format!("ingest: {e}"));
                Vec::new()
            }
        };

        let top_talkers = match &talkers {
            Ok(response) => rows(response)
                .iter()
                .filter_map(|row| {
                    Some(AssetHit {
                        asset: row.get("src_ip").and_then(Value::as_str)?.to_string(),
                        hits: row.get("count").and_then(Value::as_u64).unwrap_or(0),
                    })
                })
                .collect(),
            Err(e) => {
                degraded.push(format!("top talkers: {e}"));
                Vec::new()
            }
        };

        let (alerts_total, alerts_new, by_severity) = match &counts {
            Ok(response) => (
                response.get("total").and_then(Value::as_i64).unwrap_or(0),
                response.get("new").and_then(Value::as_i64).unwrap_or(0),
                response
                    .get("by_severity")
                    .and_then(Value::as_object)
                    .map(|map| {
                        map.iter()
                            .filter_map(|(key, value)| Some((key.clone(), value.as_i64()?)))
                            .collect()
                    })
                    .unwrap_or_default(),
            ),
            Err(e) => {
                degraded.push(format!("alert counts: {e}"));
                (0, 0, HashMap::new())
            }
        };

        // `/api/alerts` returns a bare array.
        let latest = match &latest {
            Ok(response) => response.as_array().cloned().unwrap_or_default(),
            Err(e) => {
                degraded.push(format!("latest alerts: {e}"));
                Vec::new()
            }
        };

        let sources = match &sources {
            Ok(response) => response.as_array().map(|list| list.len() as u64).unwrap_or(0),
            Err(e) => {
                degraded.push(format!("sources: {e}"));
                0
            }
        };

        Ok(Dashboard {
            events_24h,
            // An average over the window, not an instantaneous rate — and labelled
            // as such in the UI. 86_400 seconds in the 24h window.
            eps: events_24h as f64 / 86_400.0,
            ingest: buckets,
            top_talkers,
            alerts_total,
            alerts_new,
            by_severity,
            latest,
            sources,
            generated_at: end.to_rfc3339(),
            degraded,
        })
    }

    /// The dashboards this analyst can see. Summaries — `panel_count`, no panels.
    pub async fn list_dashboards(&self) -> Result<Value> {
        self.authed(
            reqwest::Method::GET,
            "/api/dashboards?filter=all",
            None,
            AUTH_TIMEOUT,
        )
        .await
    }

    /// One dashboard in full: its `panels` and `layout` JSON.
    pub async fn get_dashboard(&self, id: &str) -> Result<Value> {
        let path = format!("/api/dashboards/{}", urlencoding(id));
        self.authed(reqwest::Method::GET, &path, None, AUTH_TIMEOUT)
            .await
    }

    /// Run ONE panel.
    ///
    /// This goes through `/api/dashboards/panel/query`, not the search path, and
    /// that is deliberate: the dashboard endpoint enforces per-source RBAC and the
    /// audit-log deny-set, and it substitutes `$variables` with the platform's own
    /// semantics (an empty value removes its whole clause; a bare `$var` becomes
    /// `*`; a `$token` inside a quoted string is left alone). Reimplementing that
    /// in the client would mean the desktop and the web app could render the same
    /// panel differently — which is the whole thing this feature exists to prevent.
    pub async fn dashboard_panel_query(
        &self,
        query: &str,
        query_mode: &str,
        time_range: &Value,
        variables: Option<&Value>,
        bypass_cache: bool,
    ) -> Result<Value> {
        let body = serde_json::json!({
            "query": query,
            "query_mode": query_mode,
            "time_range": time_range,
            "variables": variables,
            "bypass_cache": bypass_cache,
        });

        // A dashboard opens N panels at once and the search admission controller
        // sheds bursts with a 429. The web client retries every panel query for
        // exactly this reason; without it, opening a busy dashboard drops panels.
        let mut backoff = Duration::from_millis(400);
        for attempt in 0..3 {
            match self
                .authed(
                    reqwest::Method::POST,
                    "/api/dashboards/panel/query",
                    Some(&body),
                    SEARCH_TIMEOUT,
                )
                .await
            {
                Err(Error::RateLimited(_)) if attempt < 2 => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(4));
                }
                other => return other,
            }
        }
        Err(Error::Server(
            "The search service is shedding load; this panel could not be run.".into(),
        ))
    }

    /// Past pivt investigations.
    ///
    /// A pivt session IS a notebook — `agent::ask` opens one per session and
    /// records every question, tool call and answer to it — so "sessions" is a
    /// filtered notebook list, not a second store. Filtering by the title prefix
    /// `agent::notebook_title` writes is what separates pivt's notebooks from the
    /// analyst's hand-written ones.
    ///
    /// Notebooks are an Enterprise handler. On an instance without them this
    /// returns Unauthorized, and the caller says so plainly rather than showing
    /// an empty list that implies the analyst has never used pivt.
    pub async fn pivt_sessions(&self) -> Result<Vec<Value>> {
        let notebooks = self
            .authed(
                reqwest::Method::GET,
                "/api/notebooks?filter=my&status=all",
                None,
                AUTH_TIMEOUT,
            )
            .await?;

        let sessions = notebooks
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter(|notebook| {
                        notebook
                            .get("title")
                            .and_then(Value::as_str)
                            .is_some_and(|title| title.starts_with(PIVT_NOTEBOOK_PREFIX))
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        Ok(sessions)
    }

    /// One session's transcript: every question, tool call and answer, in order.
    pub async fn notebook_entries(&self, notebook_id: &str) -> Result<Value> {
        let path = format!("/api/notebooks/{}/entries", urlencoding(notebook_id));
        self.authed(reqwest::Method::GET, &path, None, AUTH_TIMEOUT)
            .await
    }

    /// Record something the AGENT did — an answer, a tool call, a result.
    ///
    /// A different endpoint from `add_notebook_entry` on purpose. The ordinary one
    /// refuses AI-typed entries (NAN-686): the notebook UI renders by entry type,
    /// so a client that could write them could forge entries wearing pivt's
    /// branding. This one accepts them and stamps `provenance: client_agent`
    /// SERVER-side, so what pivt recorded from the analyst's own machine can never
    /// masquerade as something a trusted server flow produced (NAN-1840).
    ///
    /// Requires `notebooks:agent_record`.
    pub async fn add_agent_entry(
        &self,
        notebook_id: &str,
        entry_type: &str,
        content: Value,
    ) -> Result<Value> {
        let path = format!("/api/notebooks/{}/agent-entries", urlencoding(notebook_id));
        let body = serde_json::json!({ "entry_type": entry_type, "content": content });
        self.authed(reqwest::Method::POST, &path, Some(&body), AUTH_TIMEOUT)
            .await
    }

    /// Append one timeline entry — a question, a tool call, or an answer.
    pub async fn add_notebook_entry(
        &self,
        notebook_id: &str,
        entry_type: &str,
        content: Value,
    ) -> Result<Value> {
        let path = format!("/api/notebooks/{}/entries", urlencoding(notebook_id));
        let body = serde_json::json!({ "entry_type": entry_type, "content": content });
        self.authed(reqwest::Method::POST, &path, Some(&body), AUTH_TIMEOUT)
            .await
    }

    pub async fn current_user(&self) -> Result<Value> {
        self.authed(reqwest::Method::GET, "/api/auth/me", None, AUTH_TIMEOUT)
            .await
    }

    /// Mint an API key for the MCP server (which authenticates with X-API-Key,
    /// not the JWT this app holds).
    ///
    /// The endpoint requires session auth — an API key cannot mint another key —
    /// and refuses to grant any permission the caller doesn't already hold, so
    /// this can only ever narrow the user's own access.
    /// Revoke a key we minted. Without this, "Revoke" would only forget the key
    /// locally while it stayed live on the server — a credential we handed out
    /// and then lost track of.
    pub async fn delete_api_key(&self, id: &str) -> Result<()> {
        let path = format!("/api/api-keys/{}", urlencoding(id));
        // A 404 means it's already gone — the desired end state either way.
        match self
            .authed(reqwest::Method::DELETE, &path, None, AUTH_TIMEOUT)
            .await
        {
            Ok(_) => Ok(()),
            Err(Error::Server(message)) if message.contains("404") => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub async fn create_api_key(&self, name: &str, permissions: &[String]) -> Result<Value> {
        let body = serde_json::json!({
            "name": name,
            "description": "Read-only key used by coding agents via the nano MCP server.",
            "permissions": permissions,
        });
        self.authed(
            reqwest::Method::POST,
            "/api/api-keys",
            Some(&body),
            AUTH_TIMEOUT,
        )
        .await
    }

    /// Supersede this search id's previous stream (if any) and hand out a fresh
    /// cancel flag. Scoped to the id: other tabs keep streaming.
    async fn begin_search(&self, search_id: &str) -> Arc<AtomicBool> {
        let mut active = self.active_searches.lock().await;
        if let Some(previous) = active.remove(search_id) {
            previous.store(true, Ordering::Relaxed);
        }
        let flag = Arc::new(AtomicBool::new(false));
        active.insert(search_id.to_string(), flag.clone());
        flag
    }

    pub async fn cancel_search(&self, search_id: &str) {
        if let Some(active) = self.active_searches.lock().await.remove(search_id) {
            active.store(true, Ordering::Relaxed);
        }
    }

    /// Drop this search's cancel flag once its stream is done, so closing and
    /// reopening tabs doesn't grow the map forever.
    async fn end_search(&self, search_id: &str, flag: &Arc<AtomicBool>) {
        let mut active = self.active_searches.lock().await;
        // Only remove our own flag — a newer run for this id may have replaced it.
        if active
            .get(search_id)
            .is_some_and(|current| Arc::ptr_eq(current, flag))
        {
            active.remove(search_id);
        }
    }

    /// `POST /api/search/stream` (SSE) — rows arrive in batches as ClickHouse
    /// produces them, so the table paints while the query is still running
    /// instead of blocking on the full result set.
    ///
    /// Lives on nanosiem-search, which a deployed instance exposes on the same
    /// origin; `search_base()` handles the split-service case.
    ///
    /// `bypass` forces a live recompute past the server-side cache — what the
    /// "refresh" affordance next to a cached result does.
    pub async fn search_stream(
        &self,
        search_id: &str,
        request: &Value,
        bypass: bool,
        channel: Channel<Value>,
    ) -> Result<()> {
        let cancel = self.begin_search(search_id).await;
        // Every exit path — success, HTTP error, dead session — must retire the
        // flag, or the map grows with every failed query.
        let result = self.run_stream(request, bypass, channel, cancel.clone()).await;
        self.end_search(search_id, &cancel).await;
        result
    }

    async fn run_stream(
        &self,
        request: &Value,
        bypass: bool,
        channel: Channel<Value>,
        cancel: Arc<AtomicBool>,
    ) -> Result<()> {
        let (http, server, mut token) = {
            let inner = self.inner.read().await;
            (
                inner.http.clone().ok_or(Error::NotConnected)?,
                inner.server.clone().ok_or(Error::NotConnected)?,
                inner.access_token.clone(),
            )
        };
        let url = format!("{}/api/search/stream", server.search_base());

        for attempt in 0..2 {
            let token_used = token.clone().ok_or(Error::SessionExpired)?;

            let mut builder = http
                .post(&url)
                .timeout(SEARCH_TIMEOUT)
                .header(reqwest::header::ACCEPT, "text/event-stream")
                .bearer_auth(&token_used)
                .json(request);
            if bypass {
                builder = builder.header("x-nano-cache-bypass", "1");
            }
            let response = builder.send().await?;

            if response.status() == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
                self.refresh_if_stale(Some(token_used)).await?;
                token = self.inner.read().await.access_token.clone();
                continue;
            }
            if !response.status().is_success() {
                return Err(api_error(response).await);
            }

            // Served from cache or recomputed? The UI has to say so rather than
            // present a stale result as live.
            let header = |name: &str| {
                response
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            let cache_meta = serde_json::json!({
                "hit": header("x-nano-cache").as_deref() == Some("hit"),
                "age_secs": header("x-nano-cache-age").and_then(|v| v.parse::<i64>().ok()),
            });
            emit(&channel, "cache_meta", cache_meta)?;

            return self.pump_sse(response, channel, cancel).await;
        }

        Err(Error::SessionExpired)
    }

    /// Parse the SSE frames off the wire and forward each one to the webview.
    async fn pump_sse(
        &self,
        response: reqwest::Response,
        channel: Channel<Value>,
        cancel: Arc<AtomicBool>,
    ) -> Result<()> {
        let mut stream = response.bytes_stream();
        let mut buffer: Vec<u8> = Vec::new();
        let mut event_type = String::new();

        while let Some(chunk) = stream.next().await {
            if cancel.load(Ordering::Relaxed) {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk?);

            // Split on newlines in the byte buffer — decoding the raw chunk would
            // corrupt any multi-byte character straddling a chunk boundary.
            while let Some(newline) = buffer.iter().position(|&b| b == b'\n') {
                // Re-check per LINE, not just per chunk: a single chunk can carry
                // a whole superseded run's tail (`rows` + `completed`), and once
                // this search has been cancelled/replaced those late frames must
                // not reach the panel — they'd corrupt the newer run's rows,
                // count, or status.
                if cancel.load(Ordering::Relaxed) {
                    return Ok(());
                }
                let line: Vec<u8> = buffer.drain(..=newline).collect();
                let line = String::from_utf8_lossy(&line);
                let line = line.trim_end_matches(['\n', '\r']);

                // Keepalive comment.
                if line.starts_with(':') || line.is_empty() {
                    continue;
                }
                if let Some(name) = line.strip_prefix("event:") {
                    event_type = name.trim().to_string();
                    continue;
                }
                let Some(data) = line.strip_prefix("data:") else {
                    continue;
                };
                let data = data.trim();
                if data.is_empty() {
                    continue;
                }

                let parsed: Value = serde_json::from_str(data)
                    .map_err(|e| Error::Internal(format!("malformed stream event: {e}")))?;
                // The service wraps some payloads in `data` and sends others bare.
                let payload = parsed.get("data").cloned().unwrap_or(parsed);

                emit(&channel, &event_type, payload)?;

                match event_type.as_str() {
                    "completed" | "error" | "done" => return Ok(()),
                    _ => {}
                }
            }

            if buffer.len() > MAX_SSE_BUFFER {
                return Err(Error::Server(
                    "The server sent a stream frame larger than this client will buffer.".into(),
                ));
            }
        }

        // The stream ended without a terminal frame: the connection was cut (a
        // proxy timeout, a restarted search service) partway through. Returning
        // Ok here reported SUCCESS — the tab kept its spinner forever, holding a
        // partial result set that the analyst had no reason to distrust. Say it
        // ended early instead.
        emit(
            &channel,
            "error",
            serde_json::json!({
                "message": "The search connection closed before the results were complete. \
                            What is shown is partial — run it again."
            }),
        )?;
        Ok(())
    }
}

/// What one `ioc = "…" | stats …` row says about an indicator.
struct PeekSummary {
    events: u64,
    assets: u64,
    first_seen: Option<String>,
    last_seen: Option<String>,
}

fn peek_window(days: i64) -> Value {
    let end = Utc::now();
    let start = end - chrono::Duration::days(days);
    serde_json::json!({ "start": start.to_rfc3339(), "end": end.to_rfc3339() })
}

/// Escape for the nPL double-quoted string. The classifier already forbids
/// quotes/backslashes/whitespace in an indicator, but don't rely on that — this
/// is the boundary where analyst-pasted text becomes a query.
fn escape_npl(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// How much, on how many assets, and over what span — one row.
fn summary_query(value: &str) -> String {
    format!(
        "ioc = \"{}\" | stats count as events, dc(src_ip) as assets, \
         min(timestamp) as first_seen, max(timestamp) as last_seen",
        escape_npl(value)
    )
}

/// Which of our assets saw it, most first.
fn assets_query(value: &str) -> String {
    format!(
        "ioc = \"{}\" | stats count as hits by src_ip | sort -hits | head 6",
        escape_npl(value)
    )
}

/// `limit` is EXPLICIT at every call site on purpose.
///
/// It applies to the final SELECT of an aggregated query, so it caps the number
/// of GROUPS, not the events behind them. A hidden default is therefore a silent
/// truncation of the answer: a 24h `| timechart span=1h` produces 25 buckets, and
/// a default of 20 would drop the five most recent hours — the dashboard would
/// draw ingest cliffing to zero for the last five hours of a perfectly healthy
/// cluster, with nothing marked degraded because the search itself succeeded.
fn peek_request(query: &str, time_range: &Value, limit: u32) -> Value {
    serde_json::json!({
        "query": query,
        "time_range": time_range,
        "limit": limit,
        "skip_histogram": true,
        "skip_field_stats": true,
        "table_view": true,
    })
}

/// `min(timestamp)` over an EMPTY match set does not come back null — ClickHouse
/// returns the zero value, which surfaces as `1970-01-01T00:00:00.000Z`. Rendered
/// naively, an indicator nobody has ever seen reads as "first seen 1 Jan 1970":
/// a fabricated fact about an artifact with no data behind it, which is precisely
/// the failure the prevalence endpoint has (NAN-1826) and the reason this feature
/// goes through search instead. An unseen indicator has NO first/last seen.
fn read_summary(response: &Value) -> Option<PeekSummary> {
    // A 2xx carrying something that ISN'T a result set — a proxy's error page, a
    // `{"error": …}` body, a schema change — must not read as "zero events". That
    // is a false CLEAN: the caller would report an indicator as not-seen when in
    // fact we never managed to look. An empty `results: []` is different, and
    // genuinely means no match.
    let results = response.get("results")?.as_array()?;
    let row = results.first();

    let num = |key: &str| row.and_then(|r| r.get(key)).and_then(Value::as_u64).unwrap_or(0);
    let events = num("events");

    let ts = |key: &str| {
        if events == 0 {
            return None;
        }
        row.and_then(|r| r.get(key))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && !s.starts_with("1970-01-01"))
            .map(str::to_string)
    };

    Some(PeekSummary {
        events,
        assets: num("assets"),
        first_seen: ts("first_seen"),
        last_seen: ts("last_seen"),
    })
}

/// The search returned 200 but not a result set. Refusing to guess is the point.
fn malformed() -> Error {
    Error::Server(
        "The search service answered, but not with a result set — refusing to report \
         this indicator as unseen on the strength of it."
            .into(),
    )
}

/// Every hour in the window, including the quiet ones.
///
/// `timechart` only returns hours that HAD events. Plotted as-is, an hour with 4
/// events and an hour with 1 — sixteen hours apart — become two adjacent bars,
/// and the chart reads as a continuous ingest rate that never dipped. A quiet
/// hour is a fact about the data; drawing it is the difference between a chart
/// and a decoration.
fn hourly_series(
    start: chrono::DateTime<Utc>,
    end: chrono::DateTime<Utc>,
    counts: &HashMap<String, u64>,
) -> Vec<Bucket> {
    // The bucket keys are hour-aligned (`2026-07-13T01:00:00Z`), so align to the
    // hour before matching — a window starting at 01:23 must look up 01:00.
    let Some(mut at) = start.with_minute(0).and_then(|t| t.with_second(0)).and_then(|t| t.with_nanosecond(0))
    else {
        return Vec::new();
    };

    let mut series = Vec::new();
    while at <= end {
        // ClickHouse renders the bucket with a `Z` and milliseconds elided; match
        // that form rather than chrono's default RFC3339 (`+00:00`).
        let key = at.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        series.push(Bucket {
            at: key.clone(),
            count: counts.get(&key).copied().unwrap_or(0),
        });
        at += chrono::Duration::hours(1);
    }
    series
}

/// The `results` array of a search response, or nothing.
fn rows(response: &Value) -> Vec<Value> {
    response
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn read_assets(response: &Value) -> Vec<AssetHit> {
    response
        .get("results")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(|row| {
                    Some(AssetHit {
                        asset: row.get("src_ip").and_then(Value::as_str)?.to_string(),
                        hits: row.get("hits").and_then(Value::as_u64).unwrap_or(0),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn emit(channel: &Channel<Value>, event: &str, data: Value) -> Result<()> {
    channel
        .send(serde_json::json!({ "event": event, "data": data }))
        .map_err(|e| Error::Internal(format!("stream channel closed: {e}")))
}

#[cfg(test)]
mod tests;
