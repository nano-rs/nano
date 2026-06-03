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

/// True if `ip` is in a range we must never let provider sync reach
/// (loopback / private / link-local / ULA / unspecified / multicast / CGNAT /
/// cloud-metadata).
pub(crate) fn is_blocked_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local() // 169.254/16 — incl. 169.254.169.254 metadata
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                // carrier-grade NAT 100.64.0.0/10 (incl. 100.100.100.100 Alibaba metadata)
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // unique-local fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped (::ffff:a.b.c.d) — re-check the embedded v4
                || v6
                    .to_ipv4_mapped()
                    .map(|m| is_blocked_ip(&std::net::IpAddr::V4(m)))
                    .unwrap_or(false)
        }
    }
}

/// Validate an outbound provider URL before sending credentials to it.
/// Requires `https`, rejects obviously-internal hostnames, and rejects any host
/// (literal or resolved) that lands in a blocked range.
pub(crate) async fn guard_outbound_url(raw_url: &str) -> Result<(), SyncError> {
    let url = url::Url::parse(raw_url)
        .map_err(|e| SyncError::InvalidCredentials(format!("invalid URL {raw_url:?}: {e}")))?;

    if url.scheme() != "https" {
        return Err(SyncError::InvalidCredentials(format!(
            "outbound URL must use https, got scheme {:?}",
            url.scheme()
        )));
    }

    let host = url.host_str().ok_or_else(|| {
        SyncError::InvalidCredentials("outbound URL has no host".to_string())
    })?;

    let host_l = host.to_ascii_lowercase();
    if host_l == "localhost"
        || host_l.ends_with(".localhost")
        || host_l.ends_with(".local")
        || host_l.ends_with(".internal")
    {
        return Err(SyncError::InvalidCredentials(format!(
            "outbound host {host:?} is not allowed"
        )));
    }

    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<std::net::IpAddr> = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| {
                SyncError::NetworkError(format!("DNS resolution failed for {host:?}: {e}"))
            })?
            .map(|sa| sa.ip())
            .collect(),
    };

    if addrs.is_empty() {
        return Err(SyncError::NetworkError(format!(
            "host {host:?} did not resolve"
        )));
    }
    for ip in &addrs {
        if is_blocked_ip(ip) {
            return Err(SyncError::InvalidCredentials(format!(
                "outbound host {host:?} resolves to a disallowed address ({ip})"
            )));
        }
    }
    Ok(())
}

/// Redirect policy for identity-sync HTTP clients: follow at most a few hops,
/// and refuse to follow a redirect to a non-https target or to a private/
/// metadata IP literal — the common SSRF-via-redirect bypass of the pre-request
/// `guard_outbound_url` check. (Hostname redirects are still followed; they are
/// not re-resolved here, the documented residual.)
pub(crate) fn restricted_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 4 {
            return attempt.stop();
        }
        let url = attempt.url();
        if url.scheme() != "https" {
            return attempt.error("SSRF guard: refusing redirect to non-https target");
        }
        if let Some(host) = url.host_str() {
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                if is_blocked_ip(&ip) {
                    return attempt
                        .error("SSRF guard: refusing redirect to disallowed IP literal");
                }
            }
        }
        attempt.follow()
    })
}

#[cfg(test)]
mod ssrf_tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn blocks_metadata_and_internal_ranges() {
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
                is_blocked_ip(&ip.parse::<IpAddr>().unwrap()),
                "{ip} should be blocked"
            );
        }
    }

    #[test]
    fn allows_public_addresses() {
        for ip in ["8.8.8.8", "1.1.1.1", "140.82.112.3", "2606:4700:4700::1111"] {
            assert!(
                !is_blocked_ip(&ip.parse::<IpAddr>().unwrap()),
                "{ip} should be allowed"
            );
        }
    }

    #[tokio::test]
    async fn guard_rejects_scheme_and_literal_metadata() {
        assert!(guard_outbound_url("http://example.com/").await.is_err());
        assert!(guard_outbound_url("https://169.254.169.254/latest/meta-data/")
            .await
            .is_err());
        assert!(guard_outbound_url("https://10.0.0.5/api/v1/users")
            .await
            .is_err());
        assert!(guard_outbound_url("https://localhost/x").await.is_err());
    }
}
