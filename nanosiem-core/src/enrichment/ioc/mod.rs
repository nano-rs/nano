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

use crate::db::dual_pool::{on_cluster_clause, TableNames};
use clickhouse::Row;
use serde::Deserialize as SerdeDeserialize;
use thiserror::Error;
use tracing::instrument;

/// Reserved namespace stem of code-free IOC list rows (enterprise
/// `ioc_lists`). Each publication writes under its own storage namespace
/// `ioc_list/<version>` ([`ioc_list_namespace`]); custom enrichments may not
/// use any namespace starting with `ioc_list`.
pub const IOC_LIST_NAMESPACE: &str = "ioc_list";

/// Bare name of the IOC list publication commit-marker table (migration 182).
pub const IOC_LIST_COMMITS_TABLE: &str = "ioc_list_commits";

/// Storage namespace of one IOC list publication. Putting the version in the
/// ReplacingMergeTree key means rows of different publications never collapse
/// into each other: an uncommitted (failed) publication can never physically
/// replace the committed one on insert or merge.
/// Canonical form of a URL indicator for ingest-time IOC matching (NAN-4982).
///
/// Trimmed of spaces; when it has a `scheme://`, only the scheme and host are
/// ASCII-lowercased. Userinfo, port, path, query and fragment keep their case
/// and bytes (they can be case-sensitive, so `User@host/Dropper/A` and
/// `user@host/dropper/a` are distinct indicators). Without `://` the trimmed
/// value is returned unchanged.
///
/// Byte-for-byte twin of `url_canon_sql` in scripts/gen-ocsf-ddl.py, which the
/// OCSF ingest view applies to event URLs and migration 188's dictionary
/// sources apply to `url` keys: a URL key only matches when both sides agree.
pub fn canonical_url(value: &str) -> String {
    let t = value.trim_matches(' ');
    let Some(at) = t.find("://") else {
        return t.to_string();
    };
    let (scheme, rest) = (&t[..at + 3], &t[at + 3..]);
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let userinfo_end = authority.rfind('@').map_or(0, |i| i + 1);
    let host_port = &authority[userinfo_end..];
    let host_end = if host_port.starts_with('[') {
        host_port
            .find(']')
            .map_or_else(
                || host_port.find(':').unwrap_or(host_port.len()),
                |i| i + 1,
            )
    } else {
        host_port.find(':').unwrap_or(host_port.len())
    };
    format!(
        "{}{}{}{}{}",
        scheme.to_ascii_lowercase(),
        &authority[..userinfo_end],
        host_port[..host_end].to_ascii_lowercase(),
        &host_port[host_end..],
        &rest[end..]
    )
}

pub fn ioc_list_namespace(version: u32) -> String {
    format!("{IOC_LIST_NAMESPACE}/{version}")
}

/// SQL predicate: the row is NOT an IOC list row.
pub fn not_ioc_list_row() -> String {
    format!("NOT startsWith(namespace, '{IOC_LIST_NAMESPACE}/')")
}

/// Row-level visibility predicate for `custom_enrichment_results`
/// (NAN-4902 lane G, migration 182): an IOC list row exists for readers only
/// if it belongs to its list's ACTIVE publication — the highest committed
/// version per list in `ioc_list_commits`. A publication that failed
/// part-way never becomes visible; a superseded one disappears the moment the
/// next commits (a removed indicator needs no tombstone); a delete commits an
/// empty withdrawal. Every reader applies it BEFORE the per-key collapse.
/// `GLOBAL IN` keeps it valid when the outer read is a `_distributed`
/// wrapper. `commits_table` is the fully-qualified (cluster-routed) table.
///
/// NAN-4948: the same predicate also hides platform feed bundle rows
/// (`platform_feed/<feed>/<sequence>` namespaces) that are not their feed's
/// active, committed generation (migration 184), so every reader that already
/// applies IOC-list visibility gets platform-feed visibility with no change.
/// The platform commits table is derived from `commits_table` (same database,
/// same `_distributed` routing). NAN-4959: legacy marketplace IOC rows (a
/// retired Deno ThreatFox / Tor install, an air-gap IOC import) stop being
/// visible once the bundle has committed a ThreatFox / Tor generation
/// (`ioc_visible_predicate`, CH migration 187).
pub fn committed_rows_predicate(commits_table: &str) -> String {
    let platform_commits = commits_table.replace(
        IOC_LIST_COMMITS_TABLE,
        crate::platform_enrichment::state::PLATFORM_FEED_COMMITS_TABLE,
    );
    format!(
        "(({} OR version GLOBAL IN (SELECT max(version) FROM {commits_table} GROUP BY list_id)) AND {})",
        not_ioc_list_row(),
        crate::platform_enrichment::state::ioc_visible_predicate(&platform_commits)
    )
}

/// The commits table matching a fully-qualified `custom_enrichment_results`
/// reference (local or `_distributed`), for callers that only hold the table
/// string.
pub fn commits_table_for(results_table: &str) -> String {
    results_table.replace("custom_enrichment_results", IOC_LIST_COMMITS_TABLE)
}

/// Row shape for the CH `custom_enrichment_results` aggregation. The
/// `clickhouse` crate requires a `Row`-deriving named struct for column
/// mapping — tuples don't implement `Row`. Its RowBinary schema validation is
/// strict on integer width: `toUnixTimestamp` yields UInt32, so the SQL casts
/// to Int64 for the `i64` fields (without the cast every lookup failed with a
/// SchemaMismatch, found by the NAN-4902 lane G real-ClickHouse suite).
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
    // Reads via the `_distributed` wrapper on clusters (custom_enrichment_results
    // is in DISTRIBUTED_TABLES — a per-shard table with an additive wrapper); on
    // single-node `.read()` returns the local name, so the emitted table
    // reference is byte-identical. Routing through the wrapper is required so the
    // read covers ALL shards, not the one this connection landed on.
    //
    // Latest version per storage key FIRST (NAN-4902 lane G): each
    // `(namespace, enrichment_name, key_type, key_value)` collapses to its
    // newest row by `argMax(…, (version, fetched_at))`, and only then are
    // liveness and the verdict read. Without it a republished IOC list that
    // changed a verdict (risk 25 → 90, a new threat type) returned BOTH the
    // obsolete and the current verdict — on different shards ReplacingMergeTree
    // merges never repair it. first_seen / last_seen stay historical:
    // min/max of fetched_at over every committed version of the key.
    //
    // Only the active publication of an IOC list is visible (uncommitted and
    // superseded ones are not): see `committed_rows_predicate`.
    let names = TableNames::new(!on_cluster_clause().is_empty());
    let table = names.read("custom_enrichment_results");
    let visible = committed_rows_predicate(&names.read(IOC_LIST_COMMITS_TABLE));
    let rows: Vec<CustomEnrichmentIocRow> = ch
        .query(&format!(
            "SELECT
                 enrichment_name,
                 key_type,
                 live_threat_type AS threat_type,
                 live_malware AS malware,
                 live_confidence AS confidence,
                 first_seen,
                 last_seen,
                 live_tags AS tags
             FROM (
                 SELECT
                     enrichment_name,
                     key_type,
                     argMax(threat_type, (version, fetched_at)) AS live_threat_type,
                     argMax(malware, (version, fetched_at)) AS live_malware,
                     argMax(confidence, (version, fetched_at)) AS live_confidence,
                     arrayDistinct(argMax(tags, (version, fetched_at))) AS live_tags,
                     argMax(is_ioc, (version, fetched_at)) AS live_is_ioc,
                     argMax(expires_at, (version, fetched_at)) AS live_expires_at,
                     toInt64(toUnixTimestamp(min(fetched_at))) AS first_seen,
                     toInt64(toUnixTimestamp(max(fetched_at))) AS last_seen
                 FROM {table}
                 WHERE key_value = ? AND {visible}
                 GROUP BY namespace, enrichment_name, key_type
             )
             WHERE live_is_ioc = 1 AND live_expires_at > now()
             ORDER BY confidence DESC, enrichment_name",
        ))
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
    const URL_CANON_VECTORS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/ocsf_url_canonicalization.tsv"
    ));

    #[test]
    fn canonical_url_matches_shared_rust_and_sql_vectors() {
        use super::canonical_url as c;
        for (line_no, line) in URL_CANON_VECTORS.lines().enumerate() {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 3, "vector line {}: {line:?}", line_no + 1);
            assert_eq!(c(fields[1]), fields[2], "vector {}", fields[0]);
        }
        assert_ne!(
            c("https://User@bad.example/Dropper/A"),
            c("https://user@bad.example/Dropper/A")
        );
        assert_ne!(
            c("https://bad.example/Dropper/A"),
            c("https://bad.example/dropper/a")
        );
        assert_eq!(c(c("HTTP://A.B/X").as_str()), "http://a.b/X", "idempotent");
    }

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
