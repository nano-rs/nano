// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rate limiting middleware for auth endpoints
//!
//! Uses PostgreSQL-backed sliding-window counters for cross-node rate limiting.
//! This protects against brute force attacks on authentication across all API nodes.

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{Response, StatusCode},
    middleware::Next,
};
use nanosiem_core::{auth::permissions, db::repository::RateLimitRepository};
use sqlx::PgPool;
use std::net::SocketAddr;

/// Rate limiter state shared across requests
#[derive(Clone)]
pub struct RateLimitState {
    repo: RateLimitRepository,
    /// Configuration
    config: RateLimitConfig,
}

/// Rate limit configuration
///
/// **NAT-aware defaults**: per-IP limits are sized so a single corporate
/// proxy serving thousands of seats won't self-DoS during a busy login
/// window. The real brute-force defence is the per-email / per-user
/// counterparts (login_email, password_reset_email) — those stay tight.
/// See NAN-592 for the audit that drove the values here.
#[derive(Clone)]
pub struct RateLimitConfig {
    /// Max login attempts per IP in the time window. Sized for NAT — at
    /// 20/5min a 1000-seat corp would 429 within minutes; 100/5min lets
    /// a busy Monday flow through while still catching outright DoS.
    pub login_max_requests: u32,
    /// Time window for login rate limiting
    pub login_window_seconds: u64,
    /// Max login attempts per email in the time window (per-account
    /// brute-force defence; tight on purpose).
    pub login_email_max_requests: u32,
    /// Time window for per-email login rate limiting
    pub login_email_window_seconds: u64,
    /// Max password reset requests per IP. NAT-sized; per-email below
    /// is the per-account defence.
    pub password_reset_max_requests: u32,
    /// Time window for password reset rate limiting
    pub password_reset_window_seconds: u64,
    /// Max password reset requests per email in the time window
    pub password_reset_email_max_requests: u32,
    /// Time window for per-email password reset rate limiting
    pub password_reset_email_window_seconds: u64,
    /// Max MFA-setup attempts per IP in the time window. Separate
    /// bucket from `login_ip` so a noisy login window doesn't exhaust
    /// the budget for users currently enrolling.
    pub mfa_setup_max_requests: u32,
    /// Time window for MFA-setup rate limiting
    pub mfa_setup_window_seconds: u64,
    /// Max upload requests per IP in the time window
    pub upload_max_requests: u32,
    /// Time window for upload rate limiting
    pub upload_window_seconds: u64,
    /// Max dry-resolve requests per authenticated user in the time window
    /// (NAN-474 — templating is CPU-amplifying against a large doc)
    pub dry_resolve_max_requests: u32,
    /// Time window for dry-resolve rate limiting
    pub dry_resolve_window_seconds: u64,
    /// Max Kafka broker-probe requests per authenticated user in the time
    /// window. The probe holds a worker for up to `(DNS + TCP) × N brokers`
    /// ms and dials caller-supplied addresses, so without a per-user cap it
    /// doubles as a port-scan amplifier (NAN-939 H3).
    pub kafka_probe_max_requests: u32,
    /// Time window for Kafka broker-probe rate limiting
    pub kafka_probe_window_seconds: u64,
    /// Max GitHub connection probes per authenticated principal and push target.
    /// The handler decrypts a stored PAT and makes an outbound request, so the
    /// bucket is deliberately tight and API keys are isolated from their owner.
    pub detection_code_probe_max_requests: u32,
    /// Time window for detection-code target connection probes.
    pub detection_code_probe_window_seconds: u64,
    /// Max marketplace previews per authenticated principal. Preview decrypts
    /// credentials and runs code, so API keys are isolated from their owners.
    pub marketplace_preview_principal_max_requests: u32,
    /// Max marketplace previews for one provider across all principals. This
    /// bounds spend against the provider's shared external API quota.
    pub marketplace_preview_provider_max_requests: u32,
    /// Time window for marketplace enrichment previews.
    pub marketplace_preview_window_seconds: u64,
}

impl Default for RateLimitConfig {
    /// Defaults are higher than single-node because the PostgreSQL-backed counters
    /// are shared across all API nodes — a single user's requests may land on
    /// different nodes but still count toward the same bucket.
    ///
    /// Per-IP caps are sized for NAT'd enterprise deployments. Per-email
    /// caps stay tight — they're the real brute-force defence.
    fn default() -> Self {
        Self {
            login_max_requests: 100,                   // 100 login attempts per IP
            login_window_seconds: 300,                 // per 5 minutes (NAT-sized)
            login_email_max_requests: 10,              // 10 login attempts per email
            login_email_window_seconds: 600, // per 10 minutes (stricter for enumeration prevention)
            password_reset_max_requests: 50, // 50 password reset requests per IP
            password_reset_window_seconds: 3600, // per hour (NAT-sized)
            password_reset_email_max_requests: 5, // 5 password reset requests per email
            password_reset_email_window_seconds: 3600, // per hour
            mfa_setup_max_requests: 60,      // 60 mfa-setup attempts per IP
            mfa_setup_window_seconds: 300,   // per 5 minutes (separate bucket from login)
            upload_max_requests: 30,         // 30 uploads per IP
            upload_window_seconds: 60,       // per minute (prevents DoS)
            dry_resolve_max_requests: 30,    // 30 dry-resolves per user
            dry_resolve_window_seconds: 60,  // per minute
            kafka_probe_max_requests: 6,     // 6 broker probes per user
            kafka_probe_window_seconds: 60,  // per minute (heavy: DNS + TCP × N)
            detection_code_probe_max_requests: 6, // 6 credentialed GitHub probes per principal/target
            detection_code_probe_window_seconds: 60, // per minute
            marketplace_preview_principal_max_requests: 6, // 6 sandbox runs per principal
            marketplace_preview_provider_max_requests: 30, // 30 runs per provider across principals
            marketplace_preview_window_seconds: 60, // per minute
        }
    }
}

impl RateLimitState {
    pub fn new(pool: PgPool, config: RateLimitConfig) -> Self {
        Self {
            repo: RateLimitRepository::new(pool),
            config,
        }
    }

    pub fn from_env(pool: PgPool) -> Self {
        let config = RateLimitConfig {
            login_max_requests: std::env::var("RATE_LIMIT_LOGIN_MAX")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
            login_window_seconds: std::env::var("RATE_LIMIT_LOGIN_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            login_email_max_requests: std::env::var("RATE_LIMIT_LOGIN_EMAIL_MAX")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            login_email_window_seconds: std::env::var("RATE_LIMIT_LOGIN_EMAIL_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(600),
            password_reset_max_requests: std::env::var("RATE_LIMIT_PASSWORD_RESET_MAX")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50),
            password_reset_window_seconds: std::env::var("RATE_LIMIT_PASSWORD_RESET_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            mfa_setup_max_requests: std::env::var("RATE_LIMIT_MFA_SETUP_MAX")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            mfa_setup_window_seconds: std::env::var("RATE_LIMIT_MFA_SETUP_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            password_reset_email_max_requests: std::env::var("RATE_LIMIT_PASSWORD_RESET_EMAIL_MAX")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            password_reset_email_window_seconds: std::env::var(
                "RATE_LIMIT_PASSWORD_RESET_EMAIL_WINDOW_SECS",
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600),
            upload_max_requests: std::env::var("RATE_LIMIT_UPLOAD_MAX")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            upload_window_seconds: std::env::var("RATE_LIMIT_UPLOAD_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            dry_resolve_max_requests: std::env::var("RATE_LIMIT_DRY_RESOLVE_MAX")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            dry_resolve_window_seconds: std::env::var("RATE_LIMIT_DRY_RESOLVE_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            kafka_probe_max_requests: std::env::var("RATE_LIMIT_KAFKA_PROBE_MAX")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(6),
            kafka_probe_window_seconds: std::env::var("RATE_LIMIT_KAFKA_PROBE_WINDOW_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            detection_code_probe_max_requests: std::env::var("RATE_LIMIT_DETECTION_CODE_PROBE_MAX")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(6),
            detection_code_probe_window_seconds: std::env::var(
                "RATE_LIMIT_DETECTION_CODE_PROBE_WINDOW_SECS",
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60),
            marketplace_preview_principal_max_requests: std::env::var(
                "RATE_LIMIT_MARKETPLACE_PREVIEW_PRINCIPAL_MAX",
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(6),
            marketplace_preview_provider_max_requests: std::env::var(
                "RATE_LIMIT_MARKETPLACE_PREVIEW_PROVIDER_MAX",
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30),
            marketplace_preview_window_seconds: std::env::var(
                "RATE_LIMIT_MARKETPLACE_PREVIEW_WINDOW_SECS",
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60),
        };
        Self::new(pool, config)
    }

    /// Check a rate limit bucket. Returns Ok(()) if allowed, Err(retry_after_secs) if exceeded.
    async fn check(
        &self,
        category: &str,
        key: &str,
        window_secs: u64,
        max_requests: u32,
    ) -> Result<(), u64> {
        match self
            .repo
            .check_rate_limit(category, key, window_secs as f64)
            .await
        {
            Ok(tokens) if tokens as u32 >= max_requests => {
                tracing::warn!(
                    category = %category,
                    key = %key,
                    tokens = tokens,
                    limit = max_requests,
                    "Rate limit exceeded"
                );
                Err(window_secs)
            }
            Ok(_) => Ok(()),
            Err(e) => {
                // On DB error, allow the request (fail open) but log the error
                tracing::error!("Rate limit check failed (allowing request): {}", e);
                Ok(())
            }
        }
    }

    /// Check login rate limits for both IP and email
    /// Returns Ok(()) if allowed, Err with retry_after if rate limited
    pub async fn check_login_rate_limit(&self, ip: &str, email: &str) -> Result<(), u64> {
        // Check IP limit first
        self.check(
            "login_ip",
            ip,
            self.config.login_window_seconds,
            self.config.login_max_requests,
        )
        .await?;

        // Check email limit
        let email_key = email.to_lowercase();
        self.check(
            "login_email",
            &email_key,
            self.config.login_email_window_seconds,
            self.config.login_email_max_requests,
        )
        .await
    }

    /// Check password reset rate limits for both IP and email
    /// Returns Ok(()) if allowed, Err with retry_after if rate limited
    pub async fn check_password_reset_rate_limit(&self, ip: &str, email: &str) -> Result<(), u64> {
        self.check(
            "reset_ip",
            ip,
            self.config.password_reset_window_seconds,
            self.config.password_reset_max_requests,
        )
        .await?;

        let email_key = email.to_lowercase();
        self.check(
            "reset_email",
            &email_key,
            self.config.password_reset_email_window_seconds,
            self.config.password_reset_email_max_requests,
        )
        .await
    }

    /// Clean up expired rate limit buckets (called from cleanup cycle)
    pub async fn cleanup_expired(&self) {
        match self.repo.cleanup_expired().await {
            Ok(deleted) if deleted > 0 => {
                tracing::debug!("Rate limit cleanup: removed {} expired buckets", deleted);
            }
            Err(e) => {
                tracing::warn!("Rate limit cleanup failed: {}", e);
            }
            _ => {}
        }
    }
}

/// Extract client IP from request for rate limiting.
/// Delegates to the shared `crate::utils::extract_client_ip` implementation.
/// SECURITY: Extracts ConnectInfo from request extensions to get the actual peer
/// address, preventing all requests from sharing a single "unknown" bucket.
fn extract_client_ip(req: &Request) -> String {
    let connect_info = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    crate::utils::extract_client_ip(req.headers(), connect_info.as_ref())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Rate limiting response
#[derive(serde::Serialize)]
struct RateLimitError {
    error: String,
    retry_after_seconds: u64,
}

/// Middleware for rate limiting login attempts
pub async fn login_rate_limit_middleware(
    State(state): State<RateLimitState>,
    req: Request,
    next: Next,
) -> Response<Body> {
    let ip = extract_client_ip(&req);

    match state
        .check(
            "login_ip",
            &ip,
            state.config.login_window_seconds,
            state.config.login_max_requests,
        )
        .await
    {
        Ok(_) => next.run(req).await,
        Err(retry_after) => {
            tracing::warn!(ip = %ip, "Login rate limit exceeded");

            let error = RateLimitError {
                error: "Too many login attempts. Please try again later.".to_string(),
                retry_after_seconds: retry_after,
            };

            let body = serde_json::to_string(&error)
                .unwrap_or_else(|_| r#"{"error":"Too many requests"}"#.to_string());

            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Content-Type", "application/json")
                .header("Retry-After", retry_after.to_string())
                .body(Body::from(body))
                .unwrap()
        }
    }
}

/// Middleware for rate limiting MFA setup + verify-setup attempts.
///
/// Separate bucket from `login_ip` so a busy login window doesn't exhaust
/// the budget for users currently enrolling. Limit is sized for NAT —
/// the per-IP cap is the outer DoS defence; per-user enforcement happens
/// at the handler layer (`resolve_setup_actor` already validates the
/// `mfa_challenge` token / Bearer and the handler can rate-limit on
/// `actor.user_id` before any expensive crypto work).
pub async fn mfa_setup_rate_limit_middleware(
    State(state): State<RateLimitState>,
    req: Request,
    next: Next,
) -> Response<Body> {
    let ip = extract_client_ip(&req);

    match state
        .check(
            "mfa_setup_ip",
            &ip,
            state.config.mfa_setup_window_seconds,
            state.config.mfa_setup_max_requests,
        )
        .await
    {
        Ok(_) => next.run(req).await,
        Err(retry_after) => {
            tracing::warn!(ip = %ip, "MFA setup rate limit exceeded");

            let error = RateLimitError {
                error: "Too many MFA setup attempts. Please try again later.".to_string(),
                retry_after_seconds: retry_after,
            };

            let body = serde_json::to_string(&error)
                .unwrap_or_else(|_| r#"{"error":"Too many requests"}"#.to_string());

            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Content-Type", "application/json")
                .header("Retry-After", retry_after.to_string())
                .body(Body::from(body))
                .unwrap()
        }
    }
}

/// Middleware for rate limiting password reset requests
pub async fn password_reset_rate_limit_middleware(
    State(state): State<RateLimitState>,
    req: Request,
    next: Next,
) -> Response<Body> {
    let ip = extract_client_ip(&req);

    match state
        .check(
            "reset_ip",
            &ip,
            state.config.password_reset_window_seconds,
            state.config.password_reset_max_requests,
        )
        .await
    {
        Ok(_) => next.run(req).await,
        Err(retry_after) => {
            tracing::warn!(ip = %ip, "Password reset rate limit exceeded");

            let error = RateLimitError {
                error: "Too many password reset requests. Please try again later.".to_string(),
                retry_after_seconds: retry_after,
            };

            let body = serde_json::to_string(&error)
                .unwrap_or_else(|_| r#"{"error":"Too many requests"}"#.to_string());

            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Content-Type", "application/json")
                .header("Retry-After", retry_after.to_string())
                .body(Body::from(body))
                .unwrap()
        }
    }
}

/// Middleware for rate limiting dry-resolve requests (NAN-474).
///
/// Per-user (not per-IP) because the endpoint is authenticated and per-IP
/// would clobber shared-NAT tenants. Runs inside the outer auth middleware,
/// so `AuthContext` is expected in request extensions. If it's missing we
/// fall back to IP — this shouldn't happen in practice, but the fail-open
/// path matches the DB-error handling in `check()`.
pub async fn dry_resolve_rate_limit_middleware(
    State(state): State<RateLimitState>,
    req: Request,
    next: Next,
) -> Response<Body> {
    let (category, key) = match req.extensions().get::<crate::middleware::AuthContext>() {
        Some(auth) => ("dry_resolve_user", auth.user_id().to_string()),
        None => {
            tracing::warn!(
                "dry_resolve_rate_limit_middleware: AuthContext missing, falling back to IP"
            );
            ("dry_resolve_ip", extract_client_ip(&req))
        }
    };

    match state
        .check(
            category,
            &key,
            state.config.dry_resolve_window_seconds,
            state.config.dry_resolve_max_requests,
        )
        .await
    {
        Ok(_) => next.run(req).await,
        Err(retry_after) => {
            tracing::warn!(key = %key, "Dry-resolve rate limit exceeded");

            let error = RateLimitError {
                error: "Too many dry-resolve requests. Please try again later.".to_string(),
                retry_after_seconds: retry_after,
            };

            let body = serde_json::to_string(&error)
                .unwrap_or_else(|_| r#"{"error":"Too many requests"}"#.to_string());

            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Content-Type", "application/json")
                .header("Retry-After", retry_after.to_string())
                .body(Body::from(body))
                .unwrap()
        }
    }
}

/// Middleware for rate limiting Kafka broker reachability probes (NAN-939 H3).
///
/// Per-user because the endpoint is authenticated, and per-user is what
/// prevents a single compromised tenant from pinning the runtime. Cost
/// model: each call does up to `(DNS_TIMEOUT + TCP_TIMEOUT) × MAX_BROKERS`
/// ms of work, so the default `6/min` keeps the worst-case worker hold
/// well below 30 s/min/user.
pub async fn kafka_probe_rate_limit_middleware(
    State(state): State<RateLimitState>,
    req: Request,
    next: Next,
) -> Response<Body> {
    let (category, key) = match req.extensions().get::<crate::middleware::AuthContext>() {
        Some(auth) => ("kafka_probe_user", auth.user_id().to_string()),
        None => {
            tracing::warn!(
                "kafka_probe_rate_limit_middleware: AuthContext missing, falling back to IP"
            );
            ("kafka_probe_ip", extract_client_ip(&req))
        }
    };

    match state
        .check(
            category,
            &key,
            state.config.kafka_probe_window_seconds,
            state.config.kafka_probe_max_requests,
        )
        .await
    {
        Ok(_) => next.run(req).await,
        Err(retry_after) => {
            tracing::warn!(key = %key, "Kafka broker-probe rate limit exceeded");

            let error = RateLimitError {
                error: "Too many broker-probe requests. Please try again later.".to_string(),
                retry_after_seconds: retry_after,
            };

            let body = serde_json::to_string(&error)
                .unwrap_or_else(|_| r#"{"error":"Too many requests"}"#.to_string());

            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Content-Type", "application/json")
                .header("Retry-After", retry_after.to_string())
                .body(Body::from(body))
                .unwrap()
        }
    }
}

/// Rate-limit detection-as-code target connection tests (NAN-2064).
///
/// The endpoint decrypts a stored GitHub PAT and spends third-party API budget.
/// Buckets include the target ID and distinguish an interactive user from each
/// delegated API key so one credential cannot exhaust another's allowance.
pub async fn detection_code_probe_rate_limit_middleware(
    State(state): State<RateLimitState>,
    req: Request,
    next: Next,
) -> Response<Body> {
    let target = req
        .uri()
        .path()
        .trim_end_matches('/')
        .strip_suffix("/test")
        .and_then(|path| path.rsplit('/').next())
        .filter(|segment| !segment.is_empty())
        .unwrap_or("unknown");

    let (category, principal) = match req.extensions().get::<crate::middleware::AuthContext>() {
        Some(auth) => match auth.api_key_id {
            Some(api_key_id) => ("detection_code_probe_api_key", api_key_id.to_string()),
            None => ("detection_code_probe_user", auth.user_id().to_string()),
        },
        None => {
            tracing::warn!(
                "detection_code_probe_rate_limit_middleware: AuthContext missing, falling back to IP"
            );
            ("detection_code_probe_ip", extract_client_ip(&req))
        }
    };
    let key = format!("{principal}:{target}");

    match state
        .check(
            category,
            &key,
            state.config.detection_code_probe_window_seconds,
            state.config.detection_code_probe_max_requests,
        )
        .await
    {
        Ok(_) => next.run(req).await,
        Err(retry_after) => {
            tracing::warn!(%key, "Detection-code connection-probe rate limit exceeded");
            let error = RateLimitError {
                error: "Too many connection-test requests. Please try again later.".to_string(),
                retry_after_seconds: retry_after,
            };
            let body = serde_json::to_string(&error)
                .unwrap_or_else(|_| r#"{"error":"Too many requests"}"#.to_string());

            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Content-Type", "application/json")
                .header("Retry-After", retry_after.to_string())
                .body(Body::from(body))
                .unwrap()
        }
    }
}

fn marketplace_preview_provider(path: &str) -> &str {
    path.trim_end_matches('/')
        .strip_suffix("/preview")
        .and_then(|path| path.rsplit('/').next())
        .filter(|segment| !segment.is_empty())
        .unwrap_or("unknown")
}

struct MarketplacePreviewBuckets {
    category: &'static str,
    principal: String,
    provider: String,
}

/// Return quota buckets only for callers authorized to execute a preview.
/// The handler remains the authoritative 403 boundary; this prevents a
/// low-privilege caller from exhausting shared provider quota with requests
/// that will never execute.
fn marketplace_preview_buckets(req: &Request) -> Option<MarketplacePreviewBuckets> {
    let auth = req.extensions().get::<crate::middleware::AuthContext>()?;
    if !auth.has_permission(permissions::ENRICHMENTS_CONFIGURE) {
        return None;
    }

    let (category, principal) = match auth.api_key_id {
        Some(api_key_id) => ("marketplace_preview_api_key", api_key_id.to_string()),
        None => ("marketplace_preview_user", auth.user_id().to_string()),
    };

    Some(MarketplacePreviewBuckets {
        category,
        principal,
        provider: marketplace_preview_provider(req.uri().path()).to_string(),
    })
}

/// Rate-limit credentialed marketplace sandbox previews (NAN-2062).
///
/// One bucket distinguishes an interactive user from each delegated API key;
/// a second bucket is shared by provider slug. Together they prevent one
/// principal from consuming another's allowance and bound each provider's
/// external API quota across all callers.
pub async fn marketplace_preview_rate_limit_middleware(
    State(state): State<RateLimitState>,
    req: Request,
    next: Next,
) -> Response<Body> {
    let Some(buckets) = marketplace_preview_buckets(&req) else {
        return next.run(req).await;
    };
    let result = match state
        .check(
            buckets.category,
            &buckets.principal,
            state.config.marketplace_preview_window_seconds,
            state.config.marketplace_preview_principal_max_requests,
        )
        .await
    {
        Ok(()) => {
            state
                .check(
                    "marketplace_preview_provider",
                    &buckets.provider,
                    state.config.marketplace_preview_window_seconds,
                    state.config.marketplace_preview_provider_max_requests,
                )
                .await
        }
        Err(retry_after) => Err(retry_after),
    };

    match result {
        Ok(_) => next.run(req).await,
        Err(retry_after) => {
            tracing::warn!(
                principal = %buckets.principal,
                provider = %buckets.provider,
                "Marketplace preview rate limit exceeded"
            );
            let error = RateLimitError {
                error: "Too many marketplace preview requests. Please try again later."
                    .to_string(),
                retry_after_seconds: retry_after,
            };
            let body = serde_json::to_string(&error)
                .unwrap_or_else(|_| r#"{"error":"Too many requests"}"#.to_string());

            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Content-Type", "application/json")
                .header("Retry-After", retry_after.to_string())
                .body(Body::from(body))
                .unwrap()
        }
    }
}

/// Middleware for rate limiting upload requests
/// SECURITY: Prevents DoS attacks via repeated large file uploads
pub async fn upload_rate_limit_middleware(
    State(state): State<RateLimitState>,
    req: Request,
    next: Next,
) -> Response<Body> {
    let ip = extract_client_ip(&req);

    match state
        .check(
            "upload_ip",
            &ip,
            state.config.upload_window_seconds,
            state.config.upload_max_requests,
        )
        .await
    {
        Ok(_) => next.run(req).await,
        Err(retry_after) => {
            tracing::warn!(ip = %ip, "Upload rate limit exceeded");

            let error = RateLimitError {
                error: "Too many upload requests. Please try again later.".to_string(),
                retry_after_seconds: retry_after,
            };

            let body = serde_json::to_string(&error)
                .unwrap_or_else(|_| r#"{"error":"Too many requests"}"#.to_string());

            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Content-Type", "application/json")
                .header("Retry-After", retry_after.to_string())
                .body(Body::from(body))
                .unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::auth::api_key::ApiKeyInfo;
    use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
    use nanosiem_core::auth::TokenClaims;
    use uuid::Uuid;

    fn session(permissions: &[&str]) -> crate::middleware::AuthContext {
        crate::middleware::AuthContext::from_jwt(TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: Vec::new(),
            permissions: permissions.iter().map(ToString::to_string).collect(),
            exp: chrono::Utc::now().timestamp() + 60,
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        })
    }

    fn api_key(permissions: &[&str]) -> crate::middleware::AuthContext {
        crate::middleware::AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "marketplace-preview".to_string(),
            permissions: permissions.iter().map(ToString::to_string).collect(),
            user_id: Some(Uuid::now_v7()),
        })
    }

    fn preview_request(auth: crate::middleware::AuthContext) -> Request {
        let mut request = Request::builder()
            .uri("/api/marketplace/catalog/virustotal/preview")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(auth);
        request
    }

    #[test]
    fn test_default_config_values() {
        let config = RateLimitConfig::default();
        // Per-IP caps sized for NAT (NAN-592). Per-email caps stay tight —
        // they're the real per-account brute-force defence.
        assert_eq!(config.login_max_requests, 100);
        assert_eq!(config.login_window_seconds, 300);
        assert_eq!(config.login_email_max_requests, 10);
        assert_eq!(config.login_email_window_seconds, 600);
        assert_eq!(config.password_reset_max_requests, 50);
        assert_eq!(config.password_reset_window_seconds, 3600);
        assert_eq!(config.password_reset_email_max_requests, 5);
        assert_eq!(config.password_reset_email_window_seconds, 3600);
        assert_eq!(config.mfa_setup_max_requests, 60);
        assert_eq!(config.mfa_setup_window_seconds, 300);
        assert_eq!(config.upload_max_requests, 30);
        assert_eq!(config.upload_window_seconds, 60);
        assert_eq!(config.dry_resolve_max_requests, 30);
        assert_eq!(config.dry_resolve_window_seconds, 60);
        assert_eq!(config.detection_code_probe_max_requests, 6);
        assert_eq!(config.detection_code_probe_window_seconds, 60);
        assert_eq!(config.marketplace_preview_principal_max_requests, 6);
        assert_eq!(config.marketplace_preview_provider_max_requests, 30);
        assert_eq!(config.marketplace_preview_window_seconds, 60);
    }

    #[test]
    fn test_extract_client_ip_fallback() {
        let req = Request::builder().body(Body::empty()).unwrap();
        let ip = extract_client_ip(&req);
        assert_eq!(ip, "unknown");
    }

    #[test]
    fn test_rate_limit_error_serialization() {
        let error = RateLimitError {
            error: "Too many requests".to_string(),
            retry_after_seconds: 300,
        };
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("300"));
        assert!(json.contains("Too many requests"));
    }

    #[test]
    fn marketplace_preview_bucket_extracts_provider_slug() {
        assert_eq!(
            marketplace_preview_provider("/api/marketplace/catalog/virustotal/preview"),
            "virustotal"
        );
        assert_eq!(
            marketplace_preview_provider("/api/marketplace/catalog/threatfox/preview/"),
            "threatfox"
        );
        assert_eq!(marketplace_preview_provider("/preview"), "unknown");
    }

    #[test]
    fn denied_jwt_and_api_key_callers_are_excluded_from_preview_accounting() {
        let missing_auth = Request::builder()
            .uri("/api/marketplace/catalog/virustotal/preview")
            .body(Body::empty())
            .unwrap();
        assert!(marketplace_preview_buckets(&missing_auth).is_none());

        for auth in [
            session(&[]),
            session(&[permissions::ENRICHMENTS_VIEW]),
            session(&[permissions::SEARCH_VIEW]),
            api_key(&[]),
            api_key(&[permissions::ENRICHMENTS_VIEW]),
            api_key(&[permissions::SEARCH_VIEW]),
        ] {
            assert!(marketplace_preview_buckets(&preview_request(auth)).is_none());
        }
    }

    #[test]
    fn configured_jwt_and_api_key_callers_receive_isolated_preview_buckets() {
        let session_auth = session(&[permissions::ENRICHMENTS_CONFIGURE]);
        let session_id = session_auth.user_id().to_string();
        let session_buckets =
            marketplace_preview_buckets(&preview_request(session_auth)).unwrap();
        assert_eq!(session_buckets.category, "marketplace_preview_user");
        assert_eq!(session_buckets.principal, session_id);
        assert_eq!(session_buckets.provider, "virustotal");

        let api_key_auth = api_key(&[permissions::ENRICHMENTS_CONFIGURE]);
        let api_key_id = api_key_auth.api_key_id.unwrap().to_string();
        let api_key_buckets =
            marketplace_preview_buckets(&preview_request(api_key_auth)).unwrap();
        assert_eq!(api_key_buckets.category, "marketplace_preview_api_key");
        assert_eq!(api_key_buckets.principal, api_key_id);
        assert_eq!(api_key_buckets.provider, "virustotal");
    }
}
