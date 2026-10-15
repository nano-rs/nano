// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity provider sync implementations
//!
//! Each provider implements the SyncProvider trait for full and delta sync.
//! Providers that paginate should override `full_sync_paged` to yield pages
//! one at a time, keeping memory bounded for large directories.

pub mod entra;
pub mod google;
pub mod okta;
pub mod workday;

use super::types::{ConnectionTestResult, DeltaSyncResult};
use crate::inputlookup::{SsrfConfig, SsrfError, SsrfValidator};
use async_trait::async_trait;

/// Callback that receives each page of users during a paged sync.
/// Returns the count of users processed for progress tracking.
///
/// NAN-1151: pages are now the provider's RAW user objects
/// (`serde_json::Value`), not pre-mapped `UserRecordUpsert`s — the caller emits
/// them onto the `nano_enrich` lane where the repo-sourced per-source VRL does
/// the mapping. The hard-coded Rust mappers are gone.
pub type PageCallback<'a> = &'a (dyn Fn(
    Vec<serde_json::Value>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<u64, SyncError>> + Send + 'a>,
> + Send
         + Sync);

/// Trait for identity provider sync implementations.
///
/// NAN-1151: providers fetch and yield RAW provider user objects; mapping to
/// `user_registry` happens in VRL on the enrichment lane, not here.
#[async_trait]
pub trait SyncProvider: Send + Sync {
    /// Perform a full sync — fetch all users from the provider as raw JSON.
    /// Default implementation used as fallback for providers that don't support paged sync.
    async fn full_sync(
        &self,
        credentials: &serde_json::Value,
        config: &serde_json::Value,
    ) -> Result<Vec<serde_json::Value>, SyncError>;

    /// Perform a full sync, yielding pages to a callback as they arrive.
    /// Each page is dropped after the callback processes it, keeping memory bounded.
    /// Returns the total number of users synced.
    ///
    /// Default implementation falls back to `full_sync` and passes all results as one page.
    async fn full_sync_paged(
        &self,
        credentials: &serde_json::Value,
        config: &serde_json::Value,
        on_page: PageCallback<'_>,
    ) -> Result<u64, SyncError> {
        let users = self.full_sync(credentials, config).await?;
        let count = users.len() as u64;
        on_page(users).await?;
        Ok(count)
    }

    /// Perform a delta sync — fetch only changed users since the last sync
    /// Returns None if delta sync is not supported or the delta_link is invalid.
    async fn delta_sync(
        &self,
        credentials: &serde_json::Value,
        config: &serde_json::Value,
        delta_link: Option<&str>,
    ) -> Result<Option<DeltaSyncResult>, SyncError>;

    /// Test the connection to the provider
    async fn test_connection(
        &self,
        credentials: &serde_json::Value,
    ) -> Result<ConnectionTestResult, SyncError>;
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("Authentication failed: {0}")]
    AuthError(String),
    #[error("API error: {status} {message}")]
    ApiError { status: u16, message: String },
    #[error("Rate limited, retry after {retry_after_secs:?}s")]
    RateLimited { retry_after_secs: Option<u64> },
    #[error("Invalid credentials: {0}")]
    InvalidCredentials(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
}

// =============================================================================
// NAN-3483: bounded 429 retry inside a sync
// =============================================================================

/// How a sync rides out provider rate limits. One 429 used to fail the whole
/// sync and park the provider for the scheduler's 30-minute failure cooldown;
/// now the page request is retried after the wait the provider asks for, a
/// bounded number of times.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RateLimitPolicy {
    /// Retries per request after the first 429 (attempts = retries + 1).
    pub max_retries: u32,
    /// Longest wait honoured. A provider asking for more fails the sync now
    /// (with the wait in the error) rather than holding it open.
    pub max_wait: std::time::Duration,
    /// Wait when the 429 carries no usable Retry-After / reset header.
    pub default_wait: std::time::Duration,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            max_retries: 5,
            max_wait: std::time::Duration::from_secs(120),
            default_wait: std::time::Duration::from_secs(30),
        }
    }
}

/// Run `op`, retrying it while it returns [`SyncError::RateLimited`] under
/// `policy`. Any other result (success or another error) returns at once.
pub(crate) async fn retry_rate_limited<T, F, Fut>(
    policy: RateLimitPolicy,
    mut op: F,
) -> Result<T, SyncError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, SyncError>>,
{
    let mut retries = 0u32;
    loop {
        match op().await {
            Err(SyncError::RateLimited { retry_after_secs }) if retries < policy.max_retries => {
                let wait = retry_after_secs
                    .map(std::time::Duration::from_secs)
                    .unwrap_or(policy.default_wait);
                if wait > policy.max_wait {
                    return Err(SyncError::RateLimited { retry_after_secs });
                }
                // A reset already in the past (or "0") still waits a second so
                // the retry lands after the window rolls over.
                let wait = wait.max(std::time::Duration::from_secs(1));
                retries += 1;
                tracing::warn!(
                    wait_secs = wait.as_secs(),
                    retry = retries,
                    max_retries = policy.max_retries,
                    "Identity provider rate limited; retrying after its requested wait"
                );
                tokio::time::sleep(wait).await;
            }
            other => return other,
        }
    }
}

/// Seconds to wait from a 429's headers: `Retry-After` (delta-seconds) when
/// present, else Okta's `X-Rate-Limit-Reset` (epoch seconds) relative to
/// `now_epoch_secs`.
pub(crate) fn rate_limit_wait_secs(
    headers: &reqwest::header::HeaderMap,
    now_epoch_secs: u64,
) -> Option<u64> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
    };
    header("retry-after").or_else(|| {
        header("x-rate-limit-reset").map(|epoch| epoch.saturating_sub(now_epoch_secs))
    })
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    fn limited(secs: Option<u64>) -> SyncError {
        SyncError::RateLimited { retry_after_secs: secs }
    }

    #[tokio::test(start_paused = true)]
    async fn retries_after_the_requested_wait_then_succeeds() {
        let calls = AtomicU32::new(0);
        let started = tokio::time::Instant::now();
        let out = retry_rate_limited(RateLimitPolicy::default(), || async {
            match calls.fetch_add(1, Ordering::SeqCst) {
                0 => Err(limited(Some(3))),
                1 => Err(limited(Some(7))),
                _ => Ok("page"),
            }
        })
        .await
        .unwrap();
        assert_eq!(out, "page");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        // Slept exactly what the provider asked for, in order.
        assert_eq!(started.elapsed(), Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn gives_up_after_max_retries() {
        let calls = AtomicU32::new(0);
        let policy = RateLimitPolicy { max_retries: 2, ..Default::default() };
        let err = retry_rate_limited(policy, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(limited(Some(1)))
        })
        .await
        .unwrap_err();
        assert!(matches!(err, SyncError::RateLimited { retry_after_secs: Some(1) }));
        assert_eq!(calls.load(Ordering::SeqCst), 3, "first attempt + 2 retries");
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_over_the_cap_fails_now() {
        let calls = AtomicU32::new(0);
        let started = tokio::time::Instant::now();
        let err = retry_rate_limited(RateLimitPolicy::default(), || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(limited(Some(3600)))
        })
        .await
        .unwrap_err();
        assert!(matches!(err, SyncError::RateLimited { retry_after_secs: Some(3600) }));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn no_header_uses_the_default_wait_and_zero_waits_a_second() {
        let calls = AtomicU32::new(0);
        let started = tokio::time::Instant::now();
        retry_rate_limited(RateLimitPolicy::default(), || async {
            match calls.fetch_add(1, Ordering::SeqCst) {
                0 => Err(limited(None)),
                1 => Err(limited(Some(0))),
                _ => Ok(()),
            }
        })
        .await
        .unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(30 + 1));
    }

    #[tokio::test(start_paused = true)]
    async fn other_errors_are_not_retried() {
        let calls = AtomicU32::new(0);
        let err = retry_rate_limited(RateLimitPolicy::default(), || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(SyncError::AuthError("E0000011".into()))
        })
        .await
        .unwrap_err();
        assert!(matches!(err, SyncError::AuthError(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn wait_prefers_retry_after_then_okta_reset() {
        use reqwest::header::{HeaderMap, HeaderValue};
        let mut h = HeaderMap::new();
        h.insert("x-rate-limit-reset", HeaderValue::from_static("1000060"));
        assert_eq!(rate_limit_wait_secs(&h, 1_000_000), Some(60));
        // Reset already passed: zero, not an underflow.
        assert_eq!(rate_limit_wait_secs(&h, 2_000_000), Some(0));
        h.insert("retry-after", HeaderValue::from_static("5"));
        assert_eq!(rate_limit_wait_secs(&h, 1_000_000), Some(5));
        assert_eq!(rate_limit_wait_secs(&HeaderMap::new(), 1_000_000), None);
        let mut bad = HeaderMap::new();
        bad.insert("retry-after", HeaderValue::from_static("Wed, 21 Oct 2026 07:28:00 GMT"));
        assert_eq!(rate_limit_wait_secs(&bad, 1_000_000), None);
    }
}

// =============================================================================
// NAN-1196: SSRF guard for outbound identity-provider requests
// =============================================================================
//
// Provider request URLs are built from admin-supplied credential fields
// (Okta `domain`, Workday `report_url`, …). Before we deliver the bound secret
// (SSWS token / basic auth / signed JWT) we validate the destination so an
// admin can't point a provider at internal services or cloud metadata
// (169.254.169.254) and exfiltrate the credential. This is a best-effort guard
// (resolve-then-check); it does not fully close DNS-rebinding TOCTOU — a
// connect-time IP re-check via a custom connector would. The accompanying
// `restricted_redirect_policy` blocks the common redirect-to-IP-literal bypass.

/// Validate an outbound provider URL AND build a `reqwest` client PINNED to the
/// validated IP before we deliver credentials to it.
///
/// Requires `https`, rejects the non-public TLDs provider sync never targets
/// (`.localhost` / `.local` / `.internal`), and rejects any host (literal or
/// resolved) in a blocked range — all via the shared DNS-aware `SsrfValidator`
/// (NAN-1369), so identity sync uses exactly the same SSRF rules as every other
/// outbound path. NAN-2018: it then PINS the client to the exact validated
/// addresses via `resolve_to_addrs`, closing the DNS-rebinding TOCTOU the old
/// validate-then-connect flow left open — a rebind can no longer redirect the
/// bound secret (SSWS token / basic auth / signed JWT) to an internal target.
/// Redirects use the shared restricted policy. Returns the pinned client and the
/// parsed URL to dial. `timeout` is per-provider (Workday RaaS needs a long one).
pub(crate) async fn guarded_client(
    raw_url: &str,
    timeout: std::time::Duration,
) -> Result<(reqwest::Client, url::Url), SyncError> {
    let validator = SsrfValidator::new(SsrfConfig {
        allow_http: false, // credential delivery is https-only
        blocked_domains: vec![
            "localhost".to_string(),
            "local".to_string(),
            "internal".to_string(),
        ],
        ..Default::default()
    });

    validator
        .build_pinned_client(
            raw_url,
            reqwest::Client::builder()
                .timeout(timeout)
                .redirect(restricted_redirect_policy()),
        )
        .await
        .map_err(|e| match e {
            SsrfError::DnsResolutionFailed(host, msg) => {
                SyncError::NetworkError(format!("DNS resolution failed for {host:?}: {msg}"))
            }
            other => {
                SyncError::InvalidCredentials(format!("outbound URL {raw_url:?} rejected: {other}"))
            }
        })
}

// Identity-sync HTTP clients use the shared SSRF redirect policy (NAN-1369),
// re-exported here so the per-provider `super::restricted_redirect_policy()`
// call sites keep resolving.
pub(crate) use crate::inputlookup::restricted_redirect_policy;

#[cfg(test)]
mod ssrf_tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn blocks_metadata_and_internal_ranges() {
        let v = SsrfValidator::default_secure();
        for ip in [
            "169.254.169.254", // AWS/GCP/Azure metadata (link-local)
            "100.100.100.100", // Alibaba metadata (CGNAT)
            "127.0.0.1",
            "10.1.2.3",
            "172.16.5.4",
            "192.168.1.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1", // IPv4-mapped private
        ] {
            assert!(
                v.validate_ip_address(ip.parse::<IpAddr>().unwrap())
                    .is_err(),
                "{ip} should be blocked"
            );
        }
    }

    #[test]
    fn allows_public_addresses() {
        let v = SsrfValidator::default_secure();
        for ip in ["8.8.8.8", "1.1.1.1", "140.82.112.3", "2606:4700:4700::1111"] {
            assert!(
                v.validate_ip_address(ip.parse::<IpAddr>().unwrap()).is_ok(),
                "{ip} should be allowed"
            );
        }
    }

    #[tokio::test]
    async fn guard_rejects_scheme_and_literal_metadata() {
        let t = std::time::Duration::from_secs(30);
        assert!(guarded_client("http://example.com/", t).await.is_err());
        assert!(
            guarded_client("https://169.254.169.254/latest/meta-data/", t)
                .await
                .is_err()
        );
        assert!(guarded_client("https://10.0.0.5/api/v1/users", t)
            .await
            .is_err());
        assert!(guarded_client("https://localhost/x", t).await.is_err());
    }
}
