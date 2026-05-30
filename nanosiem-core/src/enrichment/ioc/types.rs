// SPDX-License-Identifier: AGPL-3.0-or-later

//! IOC lookup response type.
//!
//! Post-NAN-1112 the module only carries the lookup response — the
//! legacy engine types (`IocEnrichment`, `ParsedIoc`, `IocStats`,
//! `IocType`, `ThreatFoxResponse`, `ThreatFoxIoc`) were deleted along
//! with the engine itself. See `project_iocs_canonical_storage_is_clickhouse`
//! for the architectural rationale: canonical IOC storage is CH
//! (`custom_enrichment_results`), not PG.

use serde::{Deserialize, Serialize};

/// IOC lookup result, one row per (source, key) pair.
///
/// Returned by [`super::lookup_ioc_all_sources`] which queries the CH
/// `custom_enrichment_results` table directly (mirroring the filter
/// used by `custom_ioc_enrichment_dict`). The field shape is preserved
/// from the previous PG-backed lookup so the prevalence/discovery
/// "threat_intel" panel keeps working without UI changes.
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct IocLookupResult {
    pub found: bool,
    pub source_id: Option<String>,
    pub ioc_type: Option<String>,
    pub threat_type: Option<String>,
    pub malware: Option<String>,
    pub confidence_level: Option<i32>,
    /// NAN-1112 semantic shift: under the legacy PG engine this was
    /// the upstream feed's "first_seen_utc" timestamp (e.g. when
    /// abuse.ch first observed the IOC). Post-migration it's
    /// `min(fetched_at)` from the CH path — i.e. when WE first
    /// fetched the IOC into the Deno marketplace store. For freshly-
    /// imported feeds these are minutes apart; for IOCs the upstream
    /// has tracked for years the new value is much more recent. The
    /// field is only surfaced inside the threat_intel panel's opaque
    /// `details` blob, not directly rendered, so the regression isn't
    /// user-visible today. Honest naming would be `first_fetched_at`
    /// — keeping the original name to preserve the response contract.
    pub first_seen_at: Option<String>,
    /// See [`Self::first_seen_at`] for the same semantic note —
    /// `max(fetched_at)` in the CH path, not upstream's last-seen.
    pub last_seen_at: Option<String>,
    pub tags: Vec<String>,
}
