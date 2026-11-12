// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment API handlers
//!
//! Split into focused submodules by domain:
//! - `types` — request/response types
//! - `sources` — source listing, enable/disable, stats
//! - `lookup` — IP lookup against the ingest-time IP dictionary
//! - `agent` — generic agent enrichment lookup runtime (sandboxed-code providers)
//! - `platform_feeds` — nano's signed platform feed bundle (IPinfo Lite,
//!   ThreatFox, Tor exit list): status, check now, offline import (NAN-4948).
//!   IPinfo Lite comes only from this bundle: NAN-4959 removed main's native
//!   bring-your-own IPinfo configure / sync endpoints and download job.
//!
//! NAN-1111 sunset the per-provider ThreatFox and TOR Exit Nodes
//! handlers (and the dead `/api/enrichment/ioc/{lookup,stats}` endpoints
//! that lived in `threatfox.rs`) — both providers now run via the
//! marketplace + nano-rs/nano-enrichments. Their legacy deep-link
//! routes redirect to the marketplace from `App.tsx`'s
//! `LegacyEnrichmentRoute`.

// Agent enrichment lookup uses agent_enrichment + custom_enrichment::sandbox,
// both of which moved to nanosiem-enterprise in Phase 3.3 (NAN-744).
#[cfg(feature = "enterprise")]
mod agent;
mod lookup;
mod platform_feeds;
mod sources;
mod types;

#[cfg(feature = "enterprise")]
pub use agent::*;
pub use lookup::*;
pub use platform_feeds::*;
pub use sources::*;
pub use types::*;

use crate::handlers::AuditExt;

// =============================================================================
// SHARED HELPERS
// =============================================================================

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
                enable_enrichment_source,
                disable_enrichment_source,
                get_enrichment_stats,
                lookup_ip,
                get_platform_feeds,
                check_platform_feeds,
                import_platform_feeds,
            ),
            components(schemas(
                EnrichmentSourcesResponse,
                EnrichmentSourceInfo,
                EnrichmentStatsResponse,
                IpLookupResponse,
                PlatformFeedsStatus,
                PlatformFeedStatus,
                PlatformFeedState,
                PlatformFeedOutcome,
                PlatformFeedInstallResponse,
                PlatformFeedCheckAccepted,
            ))
        )]
        struct ApiDoc;

        ApiDoc::openapi()
    }
}
