// SPDX-License-Identifier: AGPL-3.0-or-later

//! IOC lookup against the canonical ClickHouse store.
//!
//! Post-NAN-1112 this module is a single read-side helper —
//! [`lookup_ioc_all_sources`] queries `nanosiem.custom_enrichment_results`
//! (the same table the `custom_ioc_enrichment_dict` ingest-time
//! enrichment is built from) and returns one [`IocLookupResult`] per
//! `(source, key)` pair. The only caller is the prevalence/discovery
//! artifact-detail "threat_intel" panel.
//!
//! The legacy PG-backed `IocRepository` + `sync_threatfox` /
//! `sync_tor_exit_nodes` engine + `ioc_enrichments` table were deleted
//! in NAN-1112. See `project_iocs_canonical_storage_is_clickhouse` for
//! the architectural rationale ("just go direct to CH").

mod types;

pub use types::IocLookupResult;

use clickhouse::Row;
use serde::Deserialize as SerdeDeserialize;
use thiserror::Error;
use tracing::instrument;

/// Row shape for the CH `custom_enrichment_results` aggregation. The
/// `clickhouse` crate requires a `Row`-deriving named struct for column
/// mapping — tuples don't implement `Row`.
#[derive(Debug, Row, SerdeDeserialize)]
struct CustomEnrichmentIocRow {
    enrichment_name: String,
    key_type: String,
    threat_type: String,
    malware: String,
    confidence: u8,
    first_seen: i64,
    last_seen: i64,
    tags: Vec<String>,
}

/// Errors that can occur during a CH-backed IOC lookup.
#[derive(Debug, Error)]
pub enum IocLookupError {
    #[error("ClickHouse error: {0}")]
    Clickhouse(#[from] clickhouse::error::Error),
}

/// Look an artifact up across every Deno IOC enrichment whose rows are
/// currently in `nanosiem.custom_enrichment_results` with `is_ioc=1`
/// and not yet expired. Returns one row per `(enrichment, key_type,
/// threat_type, malware, confidence)` combination, ordered by
/// confidence descending so the prevalence/discovery panel shows the
/// strongest verdicts first.
///
/// Post-NAN-1112 replacement for the PG-backed
/// `IocRepository::lookup_ioc_all_sources` — same return shape and
/// ordering semantics so the caller doesn't change. See the NAN-1112
/// ticket for the field-mapping analysis.
#[instrument(skip(ch))]
pub async fn lookup_ioc_all_sources(
    ch: &clickhouse::Client,
    value: &str,
) -> Result<Vec<IocLookupResult>, IocLookupError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }

    // Mirrors the `is_ioc = 1 AND expires_at > now()` filter the
    // `custom_ioc_enrichment_dict` definition uses (init.sql:265-298).
    // Reading the underlying table (not the dict) so we can group per
    // enrichment_name and recover first_seen/last_seen via min/max of
    // fetched_at, which the dict aggregates away.
    //
    // No `enabled` filter on the source. The legacy PG path joined
    // `enrichment_sources` and excluded disabled sources, but the
    // marketplace path doesn't carry that signal into
    // `custom_enrichment_results` — once data is written it stays
    // until TTL expiry (30 days) regardless of whether the
    // corresponding enrichment is currently enabled. That matches the
    // panel's "what do we know about this artifact" intent: a
    // recently-disabled feed's historical verdicts should still be
    // visible. If a future product decision wants the disable to
    // suppress immediately, join against `marketplace_catalog` /
    // `custom_enrichments` on `enrichment_id` and filter on
    // `enabled = true`.
    let rows: Vec<CustomEnrichmentIocRow> = ch
        .query(
            "SELECT
                 enrichment_name,
                 key_type,
                 threat_type,
                 malware,
                 confidence,
                 toUnixTimestamp(min(fetched_at)) AS first_seen,
                 toUnixTimestamp(max(fetched_at)) AS last_seen,
                 arrayDistinct(arrayFlatten(groupArray(tags))) AS tags
             FROM nanosiem.custom_enrichment_results
             WHERE key_value = ?
               AND is_ioc = 1
               AND expires_at > now()
             GROUP BY enrichment_name, key_type, threat_type, malware, confidence
             ORDER BY confidence DESC, enrichment_name",
        )
        .bind(value)
        .fetch_all()
        .await?;

    let empty_to_none = |s: String| if s.is_empty() { None } else { Some(s) };
    let unix_to_rfc3339 = |ts: i64| -> Option<String> {
        if ts <= 0 {
            return None;
        }
        chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0).map(|d| d.to_rfc3339())
    };

    Ok(rows
        .into_iter()
        .map(|row| IocLookupResult {
            found: true,
            source_id: empty_to_none(row.enrichment_name),
            ioc_type: empty_to_none(row.key_type),
            threat_type: empty_to_none(row.threat_type),
            malware: empty_to_none(row.malware),
            confidence_level: Some(row.confidence as i32),
            first_seen_at: unix_to_rfc3339(row.first_seen),
            last_seen_at: unix_to_rfc3339(row.last_seen),
            tags: row.tags,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_value_returns_no_rows() {
        // Smoke: empty value short-circuits before touching CH so the
        // call is safe to invoke without a configured client. The
        // CH-backed path itself is exercised by integration tests
        // against a live cluster (out of scope for unit tests).
        let ch = clickhouse::Client::default();
        let result = lookup_ioc_all_sources(&ch, "").await.unwrap();
        assert!(result.is_empty());
    }
}
