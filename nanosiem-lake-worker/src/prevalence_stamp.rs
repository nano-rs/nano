// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ingest-time prevalence stamping for the lake path (NAN-2361).
//!
//! UDM and OCSF-on-ClickHouse both stamp prevalence onto every row at INSERT
//! time via MATERIALIZED columns (`prevalence_file_hash`, `prevalence_dest_ip`).
//! The lake path stamped nothing, so expanding an OCSF row showed every OCSF
//! field and no prevalence. This restores that parity.
//!
//! **Semantics are as-of-ingest** — how rare an artifact was *when the event
//! happened*. That is the triage question ("was this novel at the time?") and it
//! is stable: two analysts reading the same row a week apart see the same number.
//! The query-time as-of-now path (`| prevalence`, `/v1/prevalence/lookup`) is a
//! separate concern and is unchanged.
//!
//! **Placement follows the IOC precedent exactly**: entries append to the
//! canonical OCSF `enrichments[]` array rather than adding flat top-level
//! columns. That is OCSF-legal on a strict-canonical 1.9 lake, requires no
//! schema change at all, and avoids the dotted-unmapped-key failure mode that
//! wedges *all* lake publication behind a poison batch.
//!
//! **Fail-open is a hard requirement.** The stamp is an enrichment, never a gate:
//! a row that lands without prevalence is recoverable, a row that never lands is
//! gone. Every error path here degrades to "publish without the stamp", and the
//! stamper is only ever constructed when a snapshot is actually assigned.
//!
//! **No cross-container call.** Bronze mounts the runtime volume and reads the
//! immutable SlateDB checkpoint directly. Introducing a publisher -> query-worker
//! request here would rebuild the dependency edge that caused the activation /
//! publisher deadlock (65% availability, publisher silent while blocked).

use std::collections::BTreeMap;
use std::sync::Arc;

use rayon::prelude::*;
use serde_json::{json, Map, Value};

use crate::config::LoadedPrevalenceSnapshotConfig;
use crate::enrichment::{prevalence_artifact_candidates, string_at, value_at, IngestEnrichmentMetrics};
use crate::prevalence::{ip_is_private, PrevalenceCacheBudget, PrevalenceResult, PrevalenceService};

/// NAN-2710: `IngestEnrichmentMetrics::prevalence_state` values.
pub const PREVALENCE_STATE_STAMPED: &str = "stamped";
/// A hand-off (or enrichment config) is configured but no prevalence snapshot
/// is installed yet -- the normal state before a tenant's first generation
/// publishes. Rows are left without a prevalence entry, which every reader
/// resolves to the N/A sentinel (65535); a guessed value would be worse than
/// none, because "absent from the baseline" reads as "brand new and rare".
pub const PREVALENCE_STATE_PENDING: &str = "pending";
pub const PREVALENCE_STATE_FAILED: &str = "failed";

/// Record a batch that could not be stamped because no snapshot is installed:
/// count the artifacts that WOULD have been looked up (so an operator can see
/// the gap per shard) and mark the batch pending. Never decorates a row.
pub fn record_pending_batch(events: &[&mut Value], metrics: &mut IngestEnrichmentMetrics) {
    let candidates = events
        .par_iter()
        .map(|event| {
            event
                .as_object()
                .map(|object| stampable_artifacts(object).len() as u64)
                .unwrap_or(0)
        })
        .sum::<u64>();
    metrics.prevalence_candidates = metrics.prevalence_candidates.saturating_add(candidates);
    metrics.prevalence_state = Some(PREVALENCE_STATE_PENDING.to_string());
}

/// The lookup API bounds a single request; batches larger than this are chunked
/// rather than truncated, because a silently dropped artifact reads as "brand
/// new and therefore rare" and would fabricate a signal.
const MAX_LOOKUP_CHUNK: usize = 10_000;

/// Upper bound on distinct artifacts stamped for one publication batch. Bronze
/// batches are small (hundreds of rows), so this is a runaway guard, not a
/// working limit. Exceeding it degrades to "no stamp" rather than a partial
/// stamp, for the same reason `MAX_LOOKUP_CHUNK` chunks instead of truncating.
const MAX_BATCH_ARTIFACTS: usize = 200_000;

/// The enrichment `name` and `provider` written into `enrichments[]`. Stable
/// strings: dashboards and saved searches match on them.
const ENRICHMENT_NAME: &str = "prevalence";
const ENRICHMENT_PROVIDER: &str = "nano";
const ENRICHMENT_TYPE: &str = "reputation";

/// Scalar `prevalence_*` columns, mirroring the ClickHouse UDM/OCSF profile
/// exactly so every existing UI surface works against the lake unchanged.
///
/// `enrichments[]` carries the rich, OCSF-canonical detail; these carry the
/// FILTERABLE scalar. The whole prevalence UI contract is built on them —
/// `prevalence-sentinels.ts` renders any `prevalence_*` field by name, the
/// rarity slider emits `| where prevalence_min <= N`, and the rarity chart reads
/// the distribution. Without these the lake shows prevalence but cannot filter
/// or chart it.
///
/// Sentinels are the ClickHouse ones and must not drift:
///   * `65535` — field N/A: the entity is absent on this row, or it is a
///     private/link-local IP the pipeline deliberately does not track.
///   * `9999`  — "common": the artifact is on so many hosts the count is capped.
///   * `1..9998` — a real host count, rendered as-is.
///
/// Note the scale difference this bridges: the lake caps its host set at
/// `HOST_CAP` (65) and reports `saturated`, whereas ClickHouse caps at 1000.
/// A saturated lake artifact is therefore mapped to `9999` ("common") rather
/// than to its literal count of 65, because "more hosts than we bothered to
/// count" is what `9999` means on every surface that reads it.
const PREVALENCE_NA: u64 = 65_535;
const PREVALENCE_COMMON: u64 = 9_999;

/// UNWIRED pending a decision — see below.
///
/// ClickHouse stamps `prevalence_file_hash` / `_dest_ip` / `_min` etc. as
/// top-level UInt16 columns, and the prevalence UI is built on them:
/// `prevalence-sentinels.ts` renders any `prevalence_*` field by name, and the
/// rarity slider emits `| where prevalence_min <= N`.
///
/// Those columns are NOT legal on the lake. Staging-tail admission runs
/// `validate_ocsf_event` against the pinned OCSF 1.9 contract, which rejects
/// any attribute not defined for the class:
///
/// ```text
///     OCSF 1.9 validation rejected outbox event: prevalence_dest_domain:
///       attribute "prevalence_dest_domain" is not defined for this class/profile
/// ```
///
/// It fails CLOSED — the batch stays durable and ingest stalls rather than
/// writing an invalid event — so this is a hard gate. The sanctioned homes are
/// `enrichments[]` (what this module writes) and the free-form `unmapped`
/// object.
///
/// This logic is retained, tested, and verified against the ClickHouse
/// expressions so that whichever path is chosen — resolving `prevalence_min` in
/// the query layer over `enrichments[]`, or relocating the scalars under
/// `unmapped` — does not have to be rebuilt. Tracked on NAN-2361.
#[allow(dead_code)]
/// The artifacts that feed each scalar column, mirroring the ClickHouse OCSF
/// expressions in `init.sql` / migration 154 exactly:
///
/// ```text
/// prevalence_file_hash    <- file.hashes.sha256
/// prevalence_process_hash <- process.file.hashes.sha256
/// prevalence_dest_domain  <- dst_endpoint.hostname, else query.hostname,
///                            NOT an IPv4 literal
/// prevalence_dest_ip      <- dst_endpoint.ip, NOT private/link-local
/// ```
///
/// Deliberately narrower than `artifact_candidates`: the columns must agree with
/// ClickHouse so a saved search, rule, or dashboard means the same thing on both
/// backends. `enrichments[]` still receives the full candidate set, so the extra
/// artifacts (source IPs, MD5s, URL hostnames) are visible — just not scalarised.
pub(crate) fn column_artifacts(event: &Map<String, Value>) -> Vec<(&'static str, String)> {
    let mut artifacts = Vec::new();
    if let Some(hash) = sha256_at(event, "file.hashes") {
        artifacts.push(("prevalence_file_hash", hash));
    }
    if let Some(hash) = sha256_at(event, "process.file.hashes") {
        artifacts.push(("prevalence_process_hash", hash));
    }
    // `dst_endpoint.hostname` is the canonical destination and is mirrored into
    // http_request.url.hostname where both apply (measured: 60/60 agreement, 0
    // rows carrying only the HTTP form). DNS Activity is the exception — a
    // resolver query names its target in `query.hostname` with no destination
    // host — so it is a fallback, not an additional artifact: taking both would
    // double-count the same domain on any event that carries both.
    //
    // ClickHouse excludes hostnames that are really IPv4 literals, so an address
    // sitting in a hostname field is not counted as a domain.
    if let Some(host) = ["dst_endpoint.hostname", "query.hostname"]
        .into_iter()
        .find_map(|path| string_at(event, path))
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty() && !is_ipv4_literal(value))
    {
        artifacts.push(("prevalence_dest_domain", host));
    }
    if let Some(ip) = string_at(event, "dst_endpoint.ip")
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty() && !ip_is_private(value))
    {
        artifacts.push(("prevalence_dest_ip", ip));
    }
    artifacts
}

/// The SHA-256 entry of an OCSF `hashes` array, matching ClickHouse's
/// `file.hashes.sha256` promotion. Falls back to identifying it by width when
/// the algorithm is unlabelled, since a 64-hex digest in a hashes array is a
/// SHA-256 by construction.
#[allow(dead_code)]
fn sha256_at(event: &Map<String, Value>, path: &str) -> Option<String> {
    let hashes = value_at(event, path)?.as_array()?;
    hashes.iter().filter_map(Value::as_object).find_map(|hash| {
        let value = hash.get("value").and_then(Value::as_str)?.trim().to_ascii_lowercase();
        let labelled_sha256 = hash
            .get("algorithm")
            .and_then(Value::as_str)
            .is_some_and(|algorithm| algorithm.eq_ignore_ascii_case("sha-256")
                || algorithm.eq_ignore_ascii_case("sha256"));
        let looks_like_sha256 =
            value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
        (labelled_sha256 || looks_like_sha256).then_some(value)
    })
}

#[allow(dead_code)]
fn is_ipv4_literal(value: &str) -> bool {
    let mut parts = 0;
    for part in value.split('.') {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        parts += 1;
    }
    parts == 4
}

/// Collapse a lookup outcome to the scalar the UI contract expects.
#[allow(dead_code)]
pub(crate) fn scalar_for(result: Option<&PrevalenceResult>) -> u64 {
    match result {
        // Saturated means "on more hosts than the window counts" -> common.
        Some(result) if result.host_count_saturated => PREVALENCE_COMMON,
        Some(result) => result.host_count.clamp(1, 9_998),
        // A miss is a brand-new artifact, which is the RAREST thing there is.
        // ClickHouse migration 153 made exactly this change (default 9999 -> 1)
        // because defaulting an unseen artifact to "common" hid new malware.
        None => 1,
    }
}

/// Reads the immutable prevalence checkpoint assigned to this tenant and stamps
/// admitted rows before publication.
pub struct PrevalenceStamper {
    service: Arc<PrevalenceService>,
    snapshot_id: String,
    window: String,
}

impl std::fmt::Debug for PrevalenceStamper {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrevalenceStamper")
            .field("snapshot_id", &self.snapshot_id)
            .field("window", &self.window)
            .finish()
    }
}

impl PrevalenceStamper {
    /// Bind to the immutable snapshot serving `window`. Returns `None` when no
    /// snapshot is assigned — the fail-open path, and the normal state of a
    /// deployment that has not built its first prevalence derivative yet.
    pub fn for_window(service: Arc<PrevalenceService>, window: &str) -> Option<Self> {
        let snapshot_id = service.snapshot_id_for_window(window)?.to_string();
        Some(Self {
            service,
            snapshot_id,
            window: window.to_string(),
        })
    }

    /// Bind to the longest baseline this tenant actually has assigned.
    ///
    /// Rarity is a statement about a baseline, and a longer baseline makes
    /// "never seen before" mean more: an artifact absent from 30 days is a
    /// stronger signal than one absent from the last hour, which merely says it
    /// is not currently chatty. Deriving the window from the assignment instead
    /// of a flag also means a deployment that only builds short windows still
    /// stamps, rather than silently stamping nothing because a configured
    /// window does not exist.
    pub fn longest_window(service: Arc<PrevalenceService>) -> Option<Self> {
        for window in ["30d", "7d", "24h", "1h"] {
            if let Some(stamper) = Self::for_window(service.clone(), window) {
                return Some(stamper);
            }
        }
        None
    }

    /// Open the tenant-pinned snapshots with the tenant's own entity HMAC key
    /// and bind the longest window. `Ok(None)` when the assignment carries no
    /// usable window (the caller keeps publishing, pending).
    pub async fn from_assignment(
        snapshots: BTreeMap<String, LoadedPrevalenceSnapshotConfig>,
        hmac_key: &std::path::Path,
        cache: PrevalenceCacheBudget,
    ) -> anyhow::Result<Option<Self>> {
        use anyhow::Context;
        let secret = std::fs::read(hmac_key).context("read prevalence HMAC key")?;
        let secret = secret
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        if secret.len() < 32 {
            anyhow::bail!("prevalence HMAC key must contain at least 32 bytes");
        }
        let service = PrevalenceService::load_with_cache(snapshots, secret, cache)
            .await
            .context("open immutable prevalence checkpoint for ingest stamping")?
            .map(Arc::new);
        Ok(service.and_then(Self::longest_window))
    }

    pub fn window(&self) -> &str {
        &self.window
    }

    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    /// Stamp every event in the batch. One batched lookup per chunk of distinct
    /// artifacts — never one per event, and never one per row-artifact pair.
    ///
    /// Errors are returned so the caller can log them, but the caller MUST treat
    /// them as non-fatal; see the module note on fail-open.
    pub async fn stamp_batch(
        &self,
        events: &mut [&mut Value],
        metrics: &mut IngestEnrichmentMetrics,
    ) -> anyhow::Result<()> {
        let total_start = std::time::Instant::now();
        let candidate_start = std::time::Instant::now();
        // Per-event candidate lists, computed once. Private and link-local
        // addresses are dropped here rather than looked up: the prevalence
        // source only holds public artifacts, so a lookup would miss and the
        // miss would be indistinguishable from "brand new", permanently
        // stamping every RFC1918 address as rare. ClickHouse solves the same
        // problem with an explicit exclusion regex (migration 151); std's
        // classification is that exact set and additionally covers the full
        // 172.16/12 that the original `startsWith` form missed.
        // Candidate extraction is independent per event and was a serial CPU
        // pass over the whole admitted batch. At the 2026-08-23 10k-EPS gate,
        // prevalence sat outside every publisher phase timer and contributed
        // tens of seconds to a ~210k-row cycle while the host had idle cores.
        // Keep ordering deterministic while allowing the CPU-bound per-row
        // traversal to consume the publisher's available Rayon pool.
        let per_event = events
            .par_iter()
            .map(|event| {
                event
                    .as_object()
                    .map(stampable_artifacts)
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        let candidate_us = candidate_start.elapsed().as_micros() as u64;
        let mut distinct = BTreeMap::<String, Option<PrevalenceResult>>::new();
        for candidates in &per_event {
            for (_, artifact) in candidates {
                distinct.entry(artifact.clone()).or_insert(None);
            }
        }

        metrics.prevalence_candidates = metrics
            .prevalence_candidates
            .saturating_add(per_event.iter().map(Vec::len).sum::<usize>() as u64);

        if distinct.is_empty() {
            tracing::info!(
                events = events.len(),
                distinct_artifacts = 0,
                candidate_us,
                lookup_us = 0,
                decorate_us = 0,
                total_us = total_start.elapsed().as_micros() as u64,
                "prevalence stamp phase timings"
            );
            return Ok(());
        }
        if distinct.len() > MAX_BATCH_ARTIFACTS {
            anyhow::bail!(
                "prevalence stamp batch has {} distinct artifacts, above the {MAX_BATCH_ARTIFACTS} guard",
                distinct.len()
            );
        }

        let keys = distinct.keys().cloned().collect::<Vec<_>>();
        let lookup_start = std::time::Instant::now();
        for chunk in keys.chunks(MAX_LOOKUP_CHUNK) {
            let found = self
                .service
                .lookup(&self.snapshot_id, &self.window, chunk, &[])
                .await?;
            for result in found {
                if let Some(slot) = distinct.get_mut(&result.artifact) {
                    *slot = Some(result);
                }
            }
        }
        let lookup_us = lookup_start.elapsed().as_micros() as u64;

        metrics.prevalence_hits = metrics.prevalence_hits.saturating_add(
            distinct
                .values()
                .filter(|value| value.is_some())
                .count() as u64,
        );

        // Construct each immutable enrichment shape once per distinct
        // artifact. The old loop rebuilt the same nested JSON object for every
        // repeated occurrence, even when a batch contained hundreds of
        // thousands of rows but only a small template-sized artifact set.
        let entries = distinct
            .iter()
            .map(|(artifact, result)| {
                let entry = match result {
                    Some(result) => observed_entry(result),
                    // A miss is a POSITIVE finding, not missing data: the
                    // artifact was not seen anywhere in the prevalence window,
                    // so it is brand new and therefore maximally interesting.
                    // ClickHouse encodes the same decision by defaulting the
                    // stamp to 1 rather than to a "common" sentinel (migration
                    // 153). Omitting the entry would make "never seen before"
                    // indistinguishable from "not enriched".
                    None => new_artifact_entry(artifact),
                };
                (artifact.clone(), entry)
            })
            .collect::<BTreeMap<_, _>>();
        let decorate_start = std::time::Instant::now();
        let attached = decorate_prevalence(events, per_event, &entries);
        let decorate_us = decorate_start.elapsed().as_micros() as u64;
        metrics.prevalence_attached = metrics.prevalence_attached.saturating_add(attached);
        tracing::info!(
            events = events.len(),
            distinct_artifacts = entries.len(),
            candidate_us,
            lookup_us,
            decorate_us,
            total_us = total_start.elapsed().as_micros() as u64,
            "prevalence stamp phase timings"
        );
        Ok(())
    }
}

fn decorate_prevalence(
    events: &mut [&mut Value],
    per_event: Vec<Vec<(String, String)>>,
    entries: &BTreeMap<String, Value>,
) -> u64 {
    debug_assert_eq!(events.len(), per_event.len());
    events
        .par_iter_mut()
        .zip(per_event.into_par_iter())
        .map(|(event, paths)| {
            if paths.is_empty() {
                return 0_u64;
            }
            let Some(object) = event.as_object_mut() else {
                return 0;
            };
            // NOT wired: writing scalar top-level fields is rejected by the
            // pinned OCSF 1.9 contract. See the note on `column_artifacts`.
            paths
                .into_iter()
                .filter(|(_, artifact)| {
                    entries
                        .get(artifact)
                        .is_some_and(|entry| append_enrichment(object, entry.clone()))
                })
                .count() as u64
        })
        .sum()
}

/// Resolve each artifact class on a row to its scalar value.
///
/// Several artifacts can map to one column (a row can carry more than one
/// hash); the RAREST wins, matching `prevalence_min`'s `least()` semantics —
/// a row containing one never-before-seen hash is interesting even if its
/// other hashes are ubiquitous.
#[allow(dead_code)]
fn scalar_columns(
    artifacts: &[(&'static str, String)],
    resolved: &BTreeMap<String, Option<PrevalenceResult>>,
) -> BTreeMap<&'static str, u64> {
    let mut columns = BTreeMap::<&'static str, u64>::new();
    for (column, artifact) in artifacts {
        let scalar = scalar_for(resolved.get(artifact).and_then(Option::as_ref));
        let slot = columns.entry(*column).or_insert(scalar);
        *slot = (*slot).min(scalar);
    }
    columns
}

/// Write the four artifact-class columns plus `prevalence_min`.
///
/// `prevalence_min` is `least()` over the artifact classes THAT RESOLVED, so an
/// absent entity cannot drag a row's minimum to 65535 and hide a genuinely rare
/// artifact from the rarity slider. A row with no tracked artifact at all stays
/// N/A.
///
/// ClickHouse implements this as `least()` over four branches where an ABSENT
/// field contributes 9999 rather than 65535 — "so an absent field never drags
/// the min down" (init.sql). Taking the minimum over only the classes that
/// resolved is equivalent for every row that has at least one, and the
/// all-absent row falls back to the same 9999 rather than to N/A. The
/// per-class columns still report 65535 for an absent class, exactly as
/// ClickHouse does.
#[allow(dead_code)]
fn apply_scalar_columns(event: &mut Map<String, Value>, columns: &BTreeMap<&'static str, u64>) {
    for column in [
        "prevalence_file_hash",
        "prevalence_process_hash",
        "prevalence_dest_ip",
        "prevalence_dest_domain",
    ] {
        let value = columns.get(column).copied().unwrap_or(PREVALENCE_NA);
        event.insert(column.to_string(), Value::from(value));
    }
    let minimum = columns.values().copied().min().unwrap_or(PREVALENCE_COMMON);
    event.insert("prevalence_min".to_string(), Value::from(minimum));
}

/// Artifacts worth a prevalence lookup, as `(ocsf_path, value)`.
///
/// The path is retained because the scalar columns are per-artifact-class:
/// a hash and a destination IP on the same row stamp different columns.
pub(crate) fn stampable_artifacts(event: &Map<String, Value>) -> Vec<(String, String)> {
    let mut artifacts = prevalence_artifact_candidates(event)
        .into_iter()
        .filter(|(_, value)| !ip_is_private(value))
        .collect::<Vec<_>>();
    artifacts.sort();
    artifacts.dedup();
    artifacts
}

pub(crate) fn observed_entry(result: &PrevalenceResult) -> Value {
    json!({
        "name": ENRICHMENT_NAME,
        "value": result.artifact,
        "type": ENRICHMENT_TYPE,
        "provider": ENRICHMENT_PROVIDER,
        "short_desc": if result.is_rare { "rare artifact" } else { "observed artifact" },
        "data": {
            "artifact_type": result.artifact_type,
            "host_count": result.host_count,
            "host_count_saturated": result.host_count_saturated,
            "total_occurrences": result.total_occurrences,
            "first_seen": result.first_seen,
            "last_seen": result.last_seen,
            "is_rare": result.is_rare,
            "is_new": false,
            "prevalence_score": result.prevalence_score,
            "as_of": "ingest",
        }
    })
}

pub(crate) fn new_artifact_entry(artifact: &str) -> Value {
    json!({
        "name": ENRICHMENT_NAME,
        "value": artifact,
        "type": ENRICHMENT_TYPE,
        "provider": ENRICHMENT_PROVIDER,
        "short_desc": "new artifact",
        "data": {
            "host_count": 1,
            "host_count_saturated": false,
            "is_rare": true,
            "is_new": true,
            "as_of": "ingest",
        }
    })
}

/// Append to the canonical OCSF `enrichments[]`, skipping exact duplicates so a
/// replayed or re-enriched batch stays byte-identical. Mirrors `enrich_iocs`.
///
/// Deliberately infallible: this runs AFTER every lookup has resolved, so the
/// only way it can decline is an event whose `enrichments` is not an array —
/// which admission already rejects. Returning `bool` rather than `Result` keeps
/// the batch all-or-nothing: a lookup failure stamps nothing, and no failure
/// mode can leave a half-stamped batch whose digest is not reproducible.
fn append_enrichment(event: &mut Map<String, Value>, entry: Value) -> bool {
    let Some(enrichments) = event
        .entry("enrichments")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
    else {
        return false;
    };
    if enrichments.iter().any(|existing| existing == &entry) {
        return false;
    }
    enrichments.push(entry);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(value: Value) -> Map<String, Value> {
        value.as_object().expect("event object").clone()
    }

    /// ClickHouse migration 151 exists because the original private-IP exclusion
    /// used `startsWith(dest_ip,'172.16.')` and therefore covered only 172.16/16
    /// rather than the full 172.16.0.0/12. Docker's default bridge networks live
    /// at 172.17-172.31, so every containerised address fell through to a lookup,
    /// missed, and was permanently stamped as a brand-new (rare) artifact.
    ///
    /// This asserts the boundary directly rather than trusting the classifier.
    #[test]
    fn private_ranges_are_never_stamped_including_the_docker_bridge_block() {
        for private in [
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.17.0.2",  // Docker default bridge — the 151 regression
            "172.20.10.7",
            "172.31.255.254",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254", // link-local (cloud metadata)
        ] {
            let candidates = stampable_artifacts(&event(json!({
                "src_endpoint": {"ip": private},
            })));
            assert!(
                candidates.is_empty(),
                "{private} must be excluded from prevalence lookup"
            );
        }
    }

    /// The complement of the test above: addresses immediately outside the
    /// private blocks must still be stamped. A classifier that excluded too much
    /// would silently stop stamping public traffic, which no test of the
    /// exclusion set alone would catch.
    #[test]
    fn public_addresses_adjacent_to_private_blocks_are_still_stamped() {
        for public in [
            "9.255.255.255",
            "11.0.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "192.167.255.255",
            "192.169.0.1",
            "8.8.8.8",
        ] {
            let candidates = stampable_artifacts(&event(json!({
                "src_endpoint": {"ip": public},
            })));
            assert_eq!(
                candidates,
                vec![("src_endpoint.ip".to_string(), public.to_string())],
                "{public} is public and must be stamped"
            );
        }
    }

    /// ClickHouse migration 153 changed the not-found default from 9999 to 1:
    /// an artifact nobody has ever seen is RARE, not common. Encoding the miss
    /// as an explicit entry (rather than omitting it) is what keeps "never seen
    /// before" distinguishable from "not enriched".
    #[test]
    fn an_unseen_artifact_is_stamped_rare_and_new_not_omitted() {
        let entry = new_artifact_entry("8.8.8.8");
        let data = entry.get("data").expect("data");
        assert_eq!(data.get("host_count"), Some(&json!(1)));
        assert_eq!(data.get("is_rare"), Some(&json!(true)));
        assert_eq!(data.get("is_new"), Some(&json!(true)));
        assert_eq!(data.get("as_of"), Some(&json!("ingest")));
    }

    /// The stamp records how rare the artifact was AT INGEST. If this ever
    /// silently became as-of-query, two analysts reading the same row a week
    /// apart would see different numbers for the same event.
    #[test]
    fn every_stamp_declares_as_of_ingest() {
        let observed = observed_entry(&PrevalenceResult {
            artifact: "8.8.8.8".to_string(),
            artifact_type: "ip".to_string(),
            host_count: 42,
            host_count_saturated: false,
            total_occurrences: 99,
            first_seen: "2026-08-01T00:00:00Z".to_string(),
            last_seen: "2026-08-19T00:00:00Z".to_string(),
            is_rare: false,
            prevalence_score: 7,
        });
        assert_eq!(
            observed.pointer("/data/as_of"),
            Some(&json!("ingest")),
            "observed stamps must declare their as-of semantics"
        );
        assert_eq!(observed.pointer("/data/host_count"), Some(&json!(42)));
        assert_eq!(observed.pointer("/data/is_new"), Some(&json!(false)));
        assert_eq!(
            new_artifact_entry("8.8.8.8").pointer("/data/as_of"),
            Some(&json!("ingest"))
        );
    }

    /// Bronze re-prepares a pending batch on retry. If stamping appended a
    /// second identical entry each time, a retried batch would carry duplicated
    /// prevalence and drift from the first attempt.
    #[test]
    fn restamping_the_same_event_is_idempotent() {
        let mut target = event(json!({"src_endpoint": {"ip": "8.8.8.8"}}));
        let entry = new_artifact_entry("8.8.8.8");
        assert!(append_enrichment(&mut target, entry.clone()));
        assert!(!append_enrichment(&mut target, entry.clone()));
        assert!(!append_enrichment(&mut target, entry));
        let enrichments = target
            .get("enrichments")
            .and_then(Value::as_array)
            .expect("enrichments array");
        assert_eq!(enrichments.len(), 1);
    }

    #[test]
    fn batch_decoration_reuses_entries_and_preserves_event_order() {
        let mut left = json!({"src_endpoint": {"ip": "8.8.8.8"}});
        let mut right = json!({"dst_endpoint": {"hostname": "evil.example"}});
        let mut events = vec![&mut left, &mut right];
        let per_event = vec![
            vec![("src_endpoint.ip".to_string(), "8.8.8.8".to_string())],
            vec![
                ("first".to_string(), "evil.example".to_string()),
                ("second".to_string(), "evil.example".to_string()),
            ],
        ];
        let entries = BTreeMap::from([
            ("8.8.8.8".to_string(), new_artifact_entry("8.8.8.8")),
            (
                "evil.example".to_string(),
                new_artifact_entry("evil.example"),
            ),
        ]);

        assert_eq!(decorate_prevalence(&mut events, per_event, &entries), 2);
        assert_eq!(
            left.pointer("/enrichments/0/value"),
            Some(&json!("8.8.8.8"))
        );
        assert_eq!(
            right.pointer("/enrichments/0/value"),
            Some(&json!("evil.example"))
        );
        assert_eq!(
            right["enrichments"].as_array().map(Vec::len),
            Some(1),
            "the same artifact on two OCSF paths remains one enrichment"
        );
    }

    /// Prevalence must coexist with IOC enrichment rather than replacing it:
    /// both append to the same canonical OCSF array.
    #[test]
    fn stamping_preserves_existing_ioc_enrichments() {
        let existing = json!({"name": "abuse.ch", "value": "8.8.8.8", "type": "threat_intelligence"});
        let mut target = event(json!({
            "src_endpoint": {"ip": "8.8.8.8"},
            "enrichments": [existing.clone()],
        }));
        assert!(append_enrichment(&mut target, new_artifact_entry("8.8.8.8")));
        let enrichments = target
            .get("enrichments")
            .and_then(Value::as_array)
            .expect("enrichments array");
        assert_eq!(enrichments.len(), 2);
        assert_eq!(enrichments[0], existing, "existing IOC enrichment must survive");
    }

    /// Hashes and hostnames are prevalence artifacts too, not just IPs — and the
    /// private-IP filter must not accidentally drop them.
    #[test]
    fn hashes_and_hostnames_are_stamped() {
        let candidates = stampable_artifacts(&event(json!({
            "file": {"hashes": [{"value": "a".repeat(64)}]},
            "url": {"hostname": "evil.example.com"},
            "src_endpoint": {"ip": "192.168.1.5"},
        })));
        let values = candidates
            .iter()
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>();
        assert!(values.contains(&"a".repeat(64).as_str()));
        assert!(values.contains(&"evil.example.com"));
        assert!(
            !values.contains(&"192.168.1.5"),
            "the private address must still be filtered out"
        );
    }

    fn result_with(host_count: u64, saturated: bool) -> PrevalenceResult {
        PrevalenceResult {
            artifact: "x".to_string(),
            artifact_type: "hash".to_string(),
            host_count,
            host_count_saturated: saturated,
            total_occurrences: 1,
            first_seen: "2026-08-01T00:00:00Z".to_string(),
            last_seen: "2026-08-19T00:00:00Z".to_string(),
            is_rare: host_count < 5,
            prevalence_score: 1,
        }
    }

    /// The sentinel contract the entire prevalence UI is built on. If any of
    /// these drift, `prevalence-sentinels.ts` mislabels every row: a real count
    /// renders as "N/A", or an unseen artifact renders as "common".
    #[test]
    fn scalar_sentinels_match_the_clickhouse_contract() {
        // Unseen -> rarest. This is ClickHouse migration 153's whole point.
        assert_eq!(scalar_for(None), 1);
        // Saturated -> "common", NOT its literal capped count of 65.
        assert_eq!(scalar_for(Some(&result_with(65, true))), PREVALENCE_COMMON);
        // Ordinary counts pass through untouched and stay inside 1..=9998, so
        // they can never be mistaken for either sentinel.
        for count in [1_u64, 2, 7, 64, 65] {
            let scalar = scalar_for(Some(&result_with(count, false)));
            assert_eq!(scalar, count);
            assert_ne!(scalar, PREVALENCE_NA);
            assert_ne!(scalar, PREVALENCE_COMMON);
        }
    }

    /// The scalar columns must read the SAME source fields ClickHouse does, or a
    /// saved search means different things on the two backends.
    #[test]
    fn column_sources_match_the_clickhouse_ocsf_expressions() {
        let artifacts = column_artifacts(&event(json!({
            "file": {"hashes": [{"algorithm": "SHA-256", "value": "a".repeat(64)}]},
            "process": {"file": {"hashes": [{"value": "b".repeat(64)}]}},
            "dst_endpoint": {"ip": "8.8.8.8", "hostname": "evil.example.com"},
            "src_endpoint": {"ip": "1.2.3.4"},
        })));
        assert_eq!(
            artifacts,
            vec![
                ("prevalence_file_hash", "a".repeat(64)),
                ("prevalence_process_hash", "b".repeat(64)),
                ("prevalence_dest_domain", "evil.example.com".to_string()),
                ("prevalence_dest_ip", "8.8.8.8".to_string()),
            ],
            "src_endpoint.ip has no ClickHouse column and must not scalarise"
        );
    }

    /// ClickHouse excludes hostnames that are really IPv4 literals from domain
    /// prevalence.
    #[test]
    fn ipv4_literals_in_a_hostname_field_are_not_domain_artifacts() {
        assert!(
            column_artifacts(&event(json!({"dst_endpoint": {"hostname": "203.0.113.9"}})))
                .is_empty(),
            "an IPv4 literal in hostname is not a domain artifact"
        );
        assert_eq!(
            column_artifacts(&event(
                json!({"dst_endpoint": {"hostname": "203.0.113.9.example.com"}})
            ))
            .len(),
            1,
            "a real domain is still an artifact"
        );
    }

    /// A DNS query names its target in `query.hostname` and carries no
    /// destination host, so domain prevalence must fall back to it — otherwise
    /// the one event class where domain rarity matters most stamps N/A.
    #[test]
    fn dns_queries_stamp_domain_prevalence_from_query_hostname() {
        let artifacts = column_artifacts(&event(json!({
            "query": {"hostname": "malware.example.com"},
        })));
        assert_eq!(
            artifacts,
            vec![("prevalence_dest_domain", "malware.example.com".to_string())]
        );
    }

    /// The fallback must not double-count: an event carrying both names one
    /// domain, and `dst_endpoint.hostname` wins because it is the canonical
    /// destination ClickHouse reads.
    #[test]
    fn dst_endpoint_hostname_wins_over_query_hostname() {
        let artifacts = column_artifacts(&event(json!({
            "dst_endpoint": {"hostname": "canonical.example.com"},
            "query": {"hostname": "other.example.com"},
        })));
        assert_eq!(
            artifacts,
            vec![("prevalence_dest_domain", "canonical.example.com".to_string())],
            "one domain artifact per row, not two"
        );
    }

    /// Only SHA-256 feeds the hash columns, matching `file.hashes.sha256`.
    #[test]
    fn md5_only_hashes_do_not_feed_the_sha256_columns() {
        assert!(
            column_artifacts(&event(json!({
                "file": {"hashes": [{"algorithm": "MD5", "value": "c".repeat(32)}]},
            })))
            .is_empty(),
            "MD5 is not the sha256 column source"
        );
    }

    /// An absent entity must stamp N/A, and N/A must never win `prevalence_min`
    /// — otherwise a row carrying one rare hash and no IP would report 65535
    /// and the rarity slider would skip it entirely.
    ///
    /// Drives the REAL `scalar_columns` / `apply_scalar_columns` rather than a
    /// copy of their logic, so a change to either is actually caught.
    #[test]
    fn absent_entities_stamp_na_without_poisoning_prevalence_min() {
        let mut event = json!({"file": {"hashes": [{"value": "b".repeat(64)}]}});
        let artifacts = column_artifacts(event.as_object().expect("object"));
        // Nothing resolved => every artifact is a miss.
        let resolved = BTreeMap::<String, Option<PrevalenceResult>>::new();
        let columns = scalar_columns(&artifacts, &resolved);
        apply_scalar_columns(event.as_object_mut().expect("object"), &columns);

        assert_eq!(event.get("prevalence_file_hash"), Some(&json!(1)));
        assert_eq!(event.get("prevalence_dest_ip"), Some(&json!(PREVALENCE_NA)));
        assert_eq!(
            event.get("prevalence_min"),
            Some(&json!(1)),
            "the rare hash must win prevalence_min, not the absent IP's N/A"
        );
    }

    /// A row with no tracked artifact must never collapse to a real-looking
    /// count. ClickHouse yields least(9999,9999,9999,9999) = 9999 here, because
    /// every absent branch contributes 9999 — NOT 65535, and NOT a real count.
    #[test]
    fn a_row_with_no_tracked_artifact_matches_clickhouses_9999() {
        let mut event = json!({"src_endpoint": {"ip": "8.8.8.8"}});
        let artifacts = column_artifacts(event.as_object().expect("object"));
        let columns = scalar_columns(&artifacts, &BTreeMap::new());
        apply_scalar_columns(event.as_object_mut().expect("object"), &columns);
        assert_eq!(
            event.get("prevalence_min"),
            Some(&json!(PREVALENCE_COMMON)),
            "an all-absent row matches ClickHouse's least() of four 9999 branches"
        );
        // The per-class columns still report N/A, exactly as ClickHouse does.
        assert_eq!(event.get("prevalence_dest_ip"), Some(&json!(PREVALENCE_NA)));
    }

    /// The rarest artifact wins a shared column.
    #[test]
    fn the_rarest_artifact_wins_a_shared_column() {
        let artifacts = vec![
            ("prevalence_file_hash", "aa".to_string()),
            ("prevalence_file_hash", "bb".to_string()),
        ];
        let mut resolved = BTreeMap::new();
        resolved.insert("aa".to_string(), Some(result_with(40, false)));
        resolved.insert("bb".to_string(), Some(result_with(2, false)));
        let columns = scalar_columns(&artifacts, &resolved);
        assert_eq!(columns.get("prevalence_file_hash"), Some(&2));
    }
}
