// SPDX-License-Identifier: AGPL-3.0-or-later

//! Old-hour token-index reindex (NAN-3077).
//!
//! The keyword index (v2 blocks, v3 per-minute token counts) is written by
//! every new part once the cell turns `ingest_keyword_index` on, but a sealed
//! hour that is already one `h` part is never merged again (day merges are
//! off, NAN-2886), so every hour written before the flag keeps its v1 index
//! for the whole retention. Keyword searches and their histograms over those
//! hours scan every row (measured on a lean test tenant: the same 8 h keyword
//! histogram 0.70 s over v3 hours, 5.70 s over pre-v3 hours; the k6 7 d
//! windows are mostly pre-v3 hours today).
//!
//! The fix reuses the sealed-hour merge: an hour that is exactly one sorted
//! `h` part whose token index is not the writer's current format is merged
//! again (one input, same hour, same level), which rebuilds its data files,
//! indexes and partials with the current writer, under the same hour-scoped
//! writer authority, memory rules and supersession as any hour seal. It runs
//! only when nothing else is due, never while catching up, one hour at a
//! time, newest hours first (the ones searches read most), spaced out, and
//! failed hours skipped until restart. Coverage is checked for every signed
//! token file and memoized per part.

use std::collections::BTreeSet;

use crate::parts::levels::{Level, MergePolicy};
use crate::parts::part_log::PartRef;
use crate::parts::HOUR_US;

/// NAN-3077: the old-hour reindex runs only when this is `1`. Its probe
/// (index version) and part download run in a background task and a merge
/// is planned only for a part already local, so the ingest tick never waits
/// on R2 for it; it ships off until enabled per cell after a watched run.
pub const ENABLE_ENV: &str = "NANO_LAKE_REINDEX_OLD_HOURS";

/// Whether the old-hour reindex runs (see [`ENABLE_ENV`]).
pub fn enabled() -> bool {
    enabled_from(std::env::var(ENABLE_ENV).ok().as_deref())
}

fn enabled_from(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.trim() == "1")
}

/// Coverage rewrites use the normal compaction/signing/supersession path.
pub const SIDECAR_ENABLE_ENV: &str = "NANO_LAKE_SIDECAR_BACKFILL";

pub fn sidecar_enabled() -> bool {
    enabled_from(std::env::var(SIDECAR_ENABLE_ENV).ok().as_deref())
        && super::writer::uid_sidecar_write_enabled(std::env::var("NANO_LAKE_UID_SIDECAR_WRITE").ok().as_deref())
}

pub fn keyword_enabled() -> bool {
    enabled() && crate::parts::token_counts::enabled() && crate::parts::block_index::enabled()
}

/// Signed artifact coverage, per data file. Null bloom entries remain valid
/// conservative evidence; a file without the UID column cannot gain a UID bloom.
pub fn sidecars_are_current(record: &crate::parts::provenance::ProvenanceRecord, entities: bool) -> bool {
    !record.files.data.is_empty() && record.files.data.iter().all(|data|
        data.uid_blooms.is_some() && (!entities || data.entity_blooms.is_some()))
}

/// Durable operator request. The tenant is bound by the authenticated router,
/// assignment and work directory, never supplied by the request body.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CountBackfill {
    pub start_ms: i64,
    pub end_ms: i64,
}
impl CountBackfill {
    pub fn validate(&self, now_ms: i64) -> anyhow::Result<()> {
        anyhow::ensure!(self.start_ms >= 0 && self.start_ms < self.end_ms
            && self.end_ms <= now_ms && self.end_ms - self.start_ms <= 31 * 86_400_000,
            "count backfill requires a past window of at most 31 days");
        Ok(())
    }
    pub fn contains(&self, part: &PartRef) -> bool {
        part.max_time_us >= self.start_ms.saturating_mul(1000)
            && part.min_time_us < self.end_ms.saturating_mul(1000)
    }
}

/// An untrusted footer is only a scheduling hint: readers still authenticate
/// count chunks against the signed manifest before accepting a count.
pub fn v2_hint(footer: &[u8]) -> anyhow::Result<bool> {
    let metadata = parquet::file::metadata::ParquetMetaDataReader::decode_metadata(footer)?;
    Ok(metadata.file_metadata().key_value_metadata().is_some_and(|items| items.iter().any(|item|
        item.key == crate::parts::entity_counts::V2_COVERAGE_PATH
            && item.value.as_deref().and_then(|value| value.parse::<u8>().ok())
                .is_some_and(|mask| mask > 0 && mask < 16))))
}

/// Largest entity-ranges footer whose v2 count hint is read remotely. The
/// backfill probe and the query reader share it: a probe stricter than the
/// reader (it was 4 MiB vs 8 MiB) calls a part uncovered that search reads
/// as covered, and re-rewriting it cannot change that (NAN-3795).
pub const COUNT_HINT_FOOTER_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Minimum spacing between two reindex merge starts.
pub const REINDEX_SPACING_MS: i64 = 30_000;

/// NAN-3772: consecutive failed probes/rewrites of one hour before it is
/// skipped until restart or a new window (one R2 blip must not strand it).
pub const MAX_COVERAGE_ATTEMPTS: u32 = 6;

/// Backoff after the `failures`-th consecutive failure: 1, 2, 4, 8, 16 min,
/// capped at 30 min.
pub fn coverage_retry_backoff_ms(failures: u32) -> i64 {
    (60_000_i64 << failures.saturating_sub(1).min(5)).min(30 * 60_000)
}

/// Sealed hours that are exactly one sorted `h` part, newest first, minus
/// `done` (failed hours skipped until restart): the reindex candidates.
pub fn candidates(live: &[PartRef], now_ms: i64, policy: &MergePolicy, done: &BTreeSet<i32>) -> Vec<PartRef> {
    let mut by_hour: std::collections::BTreeMap<i32, Vec<&PartRef>> = std::collections::BTreeMap::new();
    for part in live.iter().filter(|part| part.level.is_hourly()) {
        by_hour.entry(part.event_hour).or_default().push(part);
    }
    let mut out = by_hour
        .into_iter()
        .filter(|(hour, parts)| {
            let hour_end_ms = (i64::from(*hour) + 1) * (HOUR_US / 1_000);
            now_ms >= hour_end_ms + policy.hour_seal_ms
                && !done.contains(hour)
                && parts.len() == 1
                && parts[0].level == Level::Hour
                && parts[0].sorted
        })
        .map(|(_, parts)| parts[0].clone())
        .collect::<Vec<_>>();
    out.sort_by_key(|part| std::cmp::Reverse(part.event_hour));
    out
}

/// Coverage must hold for every signed group, including its exact row total.
/// A v4 group is also current for a v3-only writer (no downgrade rewrite).
pub fn groups_are_current(groups: &[crate::parts::sidecar::TokenGroup], rows: u64, expected_groups: u32, trigrams: bool) -> bool {
    groups.len() == expected_groups as usize
        && groups.iter().map(|group| u128::from(group.rows)).sum::<u128>() == u128::from(rows)
        && groups.iter().all(|group| group.counts.is_some() && (!trigrams || group.trigrams.is_some()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::format::PartId;

    fn part(level: Level, hour: i32, created_ms: i64) -> PartRef {
        PartRef {
            part_id: PartId::new(created_ms).unwrap(),
            level,
            event_hour: hour,
            event_day: None,
            rows: 10,
            min_time_us: i64::from(hour) * HOUR_US,
            max_time_us: i64::from(hour) * HOUR_US + 1,
            schema_fingerprint: String::new(),
            provenance_sha256: String::new(),
            merkle_root: String::new(),
            sorted: true,
            data_bytes: 1,
            row_groups: 1,
            data_files: 1,
        }
    }

    #[test]
    fn count_window_is_bounded_and_uses_event_overlap() {
        let now = 1_800_000_000_000;
        let window = CountBackfill { start_ms: now - 7 * 86_400_000, end_ms: now };
        window.validate(now).unwrap();
        let mut input = part(Level::Hour, 1, now);
        input.min_time_us = (window.start_ms - 1000) * 1000;
        input.max_time_us = window.start_ms * 1000;
        assert!(window.contains(&input));
        input.min_time_us = now * 1000;
        input.max_time_us = (now + 1) * 1000;
        assert!(!window.contains(&input));
        for invalid in [CountBackfill { start_ms: now, end_ms: now },
            CountBackfill { start_ms: 0, end_ms: now },
            CountBackfill { start_ms: now - 1, end_ms: now + 1 }] {
            assert!(invalid.validate(now).is_err());
        }
    }

    #[test]
    fn only_settled_single_hour_parts_newest_first() {
        let policy = MergePolicy::default();
        let hour = 497_000;
        let now_ms = (i64::from(hour) + 10) * (HOUR_US / 1_000);
        let live = vec![
            part(Level::Hour, hour, 1_790_000_000_001),
            part(Level::Hour, hour + 1, 1_790_000_000_002),
            // An hour still merging (h + late L0): the ordinary seal rewrites it.
            part(Level::Hour, hour + 2, 1_790_000_000_003),
            part(Level::L0, hour + 2, 1_790_000_000_004),
            // Unsealed hour.
            part(Level::Hour, hour + 10, 1_790_000_000_005),
        ];
        let mut unsorted = part(Level::Hour, hour + 3, 1_790_000_000_006);
        unsorted.sorted = false;
        let mut all = live.clone();
        all.push(unsorted);
        let hours = |done: &BTreeSet<i32>| candidates(&all, now_ms, &policy, done).iter().map(|p| p.event_hour).collect::<Vec<_>>();
        assert_eq!(hours(&BTreeSet::new()), vec![hour + 1, hour]);
        assert_eq!(hours(&BTreeSet::from([hour + 1])), vec![hour], "an hour is reindexed at most once per process");
    }

    #[test]
    fn sidecar_coverage_requires_every_signed_data_file() {
        use crate::parts::provenance::{tests::sample_record, FileDigest};
        let mut record = sample_record();
        let digest = FileDigest { name: "uids-00000.json".into(), bytes: 2, sha256: "0".repeat(64) };
        assert!(!sidecars_are_current(&record, false));
        record.files.data[0].uid_blooms = Some(digest.clone());
        assert!(sidecars_are_current(&record, false));
        assert!(!sidecars_are_current(&record, true));
        record.files.data[0].entity_blooms = Some(digest);
        assert!(sidecars_are_current(&record, true));
        let mut missing = record.files.data[0].clone();
        missing.uid_blooms = None;
        record.files.data.push(missing);
        assert!(!sidecars_are_current(&record, true));
        record.files.data.clear();
        assert!(!sidecars_are_current(&record, false));
    }

    #[test]
    fn reindex_is_off_unless_explicitly_enabled() {
        assert!(!enabled_from(None));
        assert!(!enabled_from(Some("")));
        assert!(!enabled_from(Some("true")));
        assert!(!enabled_from(Some("0")));
        assert!(enabled_from(Some("1")));
    }

    #[test]
    fn coverage_requires_counts_and_every_signed_group() {
        use crate::parts::sidecar::TokenGroupBuilder;
        let group = |v4| {
            let mut builder = if v4 { TokenGroupBuilder::with_trigrams(4) } else { TokenGroupBuilder::with_blocks_and_counts(4) };
            builder.add_row_at(0);
            builder.add_text("PowerShell");
            builder.add_body("PowerShell");
            builder.finish().unwrap()
        };
        let v3 = vec![group(false)];
        let v4 = vec![group(true)];
        assert!(groups_are_current(&v3, 1, 1, false));
        assert!(!groups_are_current(&v3, 1, 1, true));
        assert!(groups_are_current(&v4, 1, 1, true));
        assert!(groups_are_current(&v4, 1, 1, false));
        assert!(!groups_are_current(&v4, 2, 1, true));
        assert!(!groups_are_current(&v4, 1, 2, true));
        assert!(!groups_are_current(&[TokenGroupBuilder::new().finish().unwrap()], 0, 1, false));
    }
}
