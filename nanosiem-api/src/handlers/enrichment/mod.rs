// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment API handlers
//!
//! Split into focused submodules by domain:
//! - `types` — request/response types
//! - `sources` — source listing, enable/disable, stats, auto-sync
//! - `ipinfo` — IPinfo configure, sync, IP lookup
//! - `threatfox` — ThreatFox configure, sync, IOC lookup, IOC stats
//! - `tor` — TOR exit nodes configure, sync
//! - `agent` — agent enrichment lookup (Deno providers)

// Agent enrichment lookup uses agent_enrichment + custom_enrichment::sandbox,
// both of which moved to nanosiem-enterprise in Phase 3.3 (NAN-744).
#[cfg(feature = "enterprise")]
mod agent;
mod ipinfo;
mod sources;
mod threatfox;
mod tor;
mod types;

#[cfg(feature = "enterprise")]
pub use agent::*;
pub use ipinfo::*;
pub use sources::*;
pub use threatfox::*;
pub use tor::*;
pub use types::*;

use chrono::{DateTime, Utc};
use nanosiem_core::enrichment::EnrichmentService;
use nanosiem_core::inputlookup::{SsrfConfig, SsrfValidator};

use crate::error::ApiError;
use crate::handlers::AuditExt;

// =============================================================================
// SHARED HELPERS
// =============================================================================

/// Validate that a URL is safe to fetch (not targeting internal resources).
///
/// Delegates to the shared DNS-aware `SsrfValidator` (same one used by
/// inputlookup, OIDC discovery, marketplace, and the scheduler), which
/// resolves the hostname and rejects any answer in loopback, RFC1918,
/// link-local, IPv6 ULA, or the cloud-metadata ranges. A bare hostname
/// check is not enough: an attacker-controlled name like `localtest.me`
/// resolves to 127.0.0.1 and previously bypassed the static allowlist.
///
/// Plain `http://` is allowed so existing IPinfo Lite configs keep working;
/// the IP-range checks apply equally to http and https.
pub(crate) async fn validate_external_url(url_str: &str) -> Result<(), ApiError> {
    let validator = SsrfValidator::new(SsrfConfig {
        allow_http: true,
        ..Default::default()
    });

    validator
        .validate_with_dns(url_str)
        .await
        .map(|_| ())
        .map_err(|e| ApiError::ValidationError(e.to_string()))
}

/// Sanitize config by masking sensitive fields
pub(crate) fn sanitize_config(mut config: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = config.as_object_mut() {
        // Mask API key if present
        if let Some(api_key) = obj.get("api_key") {
            if let Some(key_str) = api_key.as_str() {
                if !key_str.is_empty() {
                    obj.insert("api_key".to_string(), serde_json::json!("••••••••"));
                }
            }
        }
    }
    config
}

/// Stale timeout for in_progress syncs (minutes)
/// Matches the scheduler's stale_sync_timeout_minutes
const STALE_SYNC_TIMEOUT_MINUTES: i64 = 60;

/// Check if a sync is currently in progress for a source
/// Returns (is_in_progress, updated_at)
pub(crate) async fn is_sync_in_progress(
    enrichment: &EnrichmentService,
    source_id: &str,
) -> Result<(bool, Option<DateTime<Utc>>), ApiError> {
    let sources = enrichment
        .list_sources()
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to list sources: {}", e)))?;

    let source = sources
        .into_iter()
        .find(|s| s.id == source_id)
        .ok_or_else(|| ApiError::NotFound(format!("Source not found: {}", source_id)))?;

    if source.last_sync_status.as_deref() == Some("in_progress") {
        let minutes_since_update = (Utc::now() - source.updated_at).num_minutes();
        // Only consider it "in progress" if within stale timeout
        if minutes_since_update < STALE_SYNC_TIMEOUT_MINUTES {
            return Ok((true, Some(source.updated_at)));
        }
        // If stale, it's not really in progress - scheduler will reset it
    }

    Ok((false, None))
}

// =============================================================================
// OPENAPI DOCUMENTATION
// =============================================================================

/// OpenAPI documentation for enrichment endpoints
pub struct EnrichmentApiDoc;

impl utoipa::OpenApi for EnrichmentApiDoc {
    fn openapi() -> utoipa::openapi::OpenApi {
        use utoipa::OpenApi;

        #[derive(OpenApi)]
        #[openapi(
            paths(
                list_enrichment_sources,
                configure_ipinfo,
                sync_ipinfo,
                enable_enrichment_source,
                disable_enrichment_source,
                get_auto_sync_config,
                configure_auto_sync,
                get_enrichment_stats,
                lookup_ip,
                configure_threatfox,
                sync_threatfox,
                lookup_ioc,
                get_ioc_stats,
                configure_tor_exit_nodes,
                sync_tor_exit_nodes,
            ),
            components(schemas(
                EnrichmentSourcesResponse,
                EnrichmentSourceInfo,
                ConfigureEnrichmentRequest,
                SyncResponse,
                AsyncSyncResponse,
                EnrichmentStatsResponse,
                IpLookupResponse,
                AutoSyncConfigRequest,
                AutoSyncConfigResponse,
                ConfigureThreatFoxRequest,
                IocLookupResponse,
                IocStatsResponse,
                ConfigureTorRequest,
            ))
        )]
        struct ApiDoc;

        ApiDoc::openapi()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NAN-696: regression coverage for the IPinfo SSRF gap. The previous
    // string-based hostname allowlist let `localtest.me` (and any
    // attacker-controlled hostname pointing at 127.0.0.1 / RFC1918 /
    // 169.254/16) through; switching to `SsrfValidator::validate_with_dns`
    // closes that. These tests exercise the literal-IP path so they don't
    // depend on outbound DNS in CI.

    #[tokio::test]
    async fn loopback_ipv4_literal_rejected() {
        let err = validate_external_url("http://127.0.0.1/ipinfo.csv.gz")
            .await
            .expect_err("loopback must be blocked");
        assert!(matches!(err, ApiError::ValidationError(_)));
    }

    #[tokio::test]
    async fn loopback_ipv6_literal_rejected() {
        assert!(validate_external_url("http://[::1]/").await.is_err());
    }

    #[tokio::test]
    async fn rfc1918_literal_rejected() {
        for url in [
            "http://10.0.0.1/",
            "http://172.20.5.5/",
            "http://192.168.1.1/",
        ] {
            assert!(
                validate_external_url(url).await.is_err(),
                "{url} should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn aws_metadata_endpoint_rejected() {
        assert!(validate_external_url("http://169.254.169.254/latest/meta-data/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn link_local_literal_rejected() {
        assert!(validate_external_url("http://169.254.42.1/").await.is_err());
    }

    #[tokio::test]
    async fn non_http_scheme_rejected() {
        assert!(validate_external_url("file:///etc/passwd").await.is_err());
        assert!(validate_external_url("gopher://evil.example.com/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn invalid_url_rejected() {
        assert!(validate_external_url("not a url").await.is_err());
    }

    #[tokio::test]
    async fn cloud_metadata_hostname_rejected() {
        assert!(
            validate_external_url("http://metadata.google.internal/computeMetadata/v1/")
                .await
                .is_err()
        );
    }

    // Requires outbound DNS that resolves `localtest.me` to 127.0.0.1
    // (true on the public internet; not guaranteed in sandboxed CI). This
    // is the exact attack from the Caido session — gated #[ignore] so it's
    // available for manual verification without making CI flaky on offline
    // build hosts.
    #[tokio::test]
    #[ignore = "requires outbound DNS for localtest.me"]
    async fn hostname_resolving_to_loopback_rejected() {
        let result = validate_external_url("http://localtest.me/ipinfo.csv.gz").await;
        assert!(
            matches!(result, Err(ApiError::ValidationError(_))),
            "expected ValidationError, got {result:?}"
        );
    }
}
