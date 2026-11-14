// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prevalence coverage state: ready / warming / partial / stale.
//!
//! A prevalence lookup that finds nothing used to render `host_count 0`, which
//! reads as "boring" when it may only mean "prevalence has not covered this
//! window yet". This module says which it is, PER ARTIFACT KIND (hash, domain,
//! IP each have their own aggregate table, enabled and backfilled
//! independently), from cheap ClickHouse metadata:
//!
//! * `covered_since[kind]`: the oldest `time_bucket` in that kind's
//!   `*_prevalence_agg` table (partitioned by `toYYYYMM(time_bucket)`, so
//!   `min()` is answered by the implicit min-max projection). An empty table
//!   is `None`: nothing about that kind is known;
//! * `ingest_since` / `ingest_head`: the oldest / newest event in `logs`
//!   (same metadata path). `ingest_since` separates a young install (warming)
//!   from an older install with a prevalence gap (partial);
//! * `refreshed_at`: the oldest last successful run of the
//!   `*_prevalence_final_refresh` refreshable views (`system.view_refreshes`),
//!   which feed the rare / new lists and the prevalence dictionaries.
//!
//! Source-restricted viewers read the source-attributed tables (ClickHouse
//! 170), which were never backfilled. Their coverage comes from those tables
//! under the same source predicate ([`ScopedCoverage`]); a kind with no
//! attributed row before the window start is `partial` for them, and the
//! response never carries timestamps derived from other sources
//! (`covered_since` and `ingest_head` are omitted).
//!
//! Classification is pure and unit-tested; the probes live in
//! `PrevalenceRepository::coverage_probe` / `scoped_coverage_before`.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::types::{ArtifactType, PrevalenceData};

/// How often the `*_prevalence_final_refresh` views run by default (ClickHouse
/// 160). A planned-volume tier lengthens it (NAN-5345: 30 min at ~1 TB/day,
/// 60 at >=10 TB/day); the probe reads the live cadence into
/// [`CoverageProbe::refresh_interval`], and this is the floor and fallback.
pub const FINAL_REFRESH_INTERVAL: Duration = Duration::minutes(10);

/// The longest live `*_prevalence_final_refresh` cadence in the connection's
/// database, in seconds (0 when unknown). ClickHouse normalizes the unit (`EVERY 60 MINUTE` reads back as
/// `EVERY 1 HOUR`), so every unit is converted.
pub const PREVALENCE_REFRESH_SECONDS_SQL: &str = "SELECT toUInt32(max(multiIf(\
    unit = 'SECOND', n, unit = 'MINUTE', n * 60, unit = 'HOUR', n * 3600, \
    unit = 'DAY', n * 86400, unit = 'WEEK', n * 604800, 0))) \
    FROM (SELECT toUInt32OrZero(extract(create_table_query, 'REFRESH EVERY (\\d+) [A-Z]+')) AS n, \
                 extract(create_table_query, 'REFRESH EVERY \\d+ ([A-Z]+)') AS unit \
          FROM system.tables \
          WHERE database = currentDatabase() \
            AND name IN ('hash_prevalence_final_refresh', 'domain_prevalence_final_refresh', \
                         'ip_prevalence_final_refresh'))";

/// `time_bucket` is hourly (`toStartOfHour`): coverage that starts within one
/// bucket of the window start covers the window.
pub const BUCKET_SLACK: Duration = Duration::hours(1);

/// Coverage of one prevalence read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PrevalenceCoverageState {
    /// The window is fully covered and the snapshot is current: a miss means
    /// "not seen".
    Ready,
    /// Prevalence covers only part of the window (tracking enabled later, or
    /// source attribution started inside the window): a miss is unknown.
    Partial,
    /// The refreshed snapshot (rare / new lists, dictionaries) lags ingest by
    /// more than two refresh intervals.
    Stale,
    /// Prevalence started inside the window on a young install (or has no
    /// data for this kind yet): a miss is unknown, not rare.
    Warming,
}

/// The artifact kinds with their own prevalence tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ArtifactKind {
    Hash,
    Domain,
    Ip,
}

impl ArtifactKind {
    pub const ALL: [ArtifactKind; 3] = [ArtifactKind::Hash, ArtifactKind::Domain, ArtifactKind::Ip];

    pub fn of(artifact_type: ArtifactType) -> Self {
        if artifact_type.is_hash() {
            ArtifactKind::Hash
        } else if artifact_type.is_ip() {
            ArtifactKind::Ip
        } else {
            ArtifactKind::Domain
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// `product_state` on prevalence responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PrevalenceProductState {
    /// Most important condition: warming > stale > partial > ready.
    pub state: PrevalenceCoverageState,
    /// Prevalence does not cover the window yet (young install / no data).
    pub warming: bool,
    /// The refreshed snapshot lags ingest.
    pub stale: bool,
    /// Prevalence covers only part of the window.
    pub partial: bool,
    /// Oldest prevalence bucket of the covered kinds (`None`: no data yet, or
    /// withheld from a source-restricted viewer).
    pub covered_since: Option<DateTime<Utc>>,
    /// Last successful snapshot refresh (`None` for live reads or unknown).
    pub refreshed_at: Option<DateTime<Utc>>,
    /// Newest ingested event, capped at now (`None` for a source-restricted
    /// viewer: it would reveal activity in sources they cannot see).
    pub ingest_head: Option<DateTime<Utc>>,
    /// Start of the window this state describes.
    pub window_start: DateTime<Utc>,
    /// Seconds until a retry can change the answer (warming / stale only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u64>,
    /// Snapshot age in seconds (`now - refreshed_at`), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_s: Option<u64>,
}

impl PrevalenceProductState {
    /// A miss in this state is "not seen" (true) or unknown (false).
    pub fn miss_is_definitive(&self) -> bool {
        !self.warming && !self.partial
    }

    fn from_flags(
        warming: bool,
        stale: bool,
        partial: bool,
        base: PrevalenceProductState,
    ) -> PrevalenceProductState {
        let state = if warming {
            PrevalenceCoverageState::Warming
        } else if stale {
            PrevalenceCoverageState::Stale
        } else if partial {
            PrevalenceCoverageState::Partial
        } else {
            PrevalenceCoverageState::Ready
        };
        // `base.retry_after_s` carries the live refresh interval from classify.
        let retry_after_s = (warming || stale)
            .then(|| base.retry_after_s.unwrap_or(FINAL_REFRESH_INTERVAL.num_seconds() as u64));
        PrevalenceProductState { state, warming, stale, partial, retry_after_s, ..base }
    }
}

/// Raw metadata read by `PrevalenceRepository::coverage_probe`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoverageProbe {
    /// Oldest `time_bucket` per kind (`[hash, domain, ip]`); `None` = no rows.
    pub covered_since: [Option<DateTime<Utc>>; 3],
    /// Oldest event in `logs`.
    pub ingest_since: Option<DateTime<Utc>>,
    /// Newest event in `logs`.
    pub ingest_head: Option<DateTime<Utc>>,
    /// Oldest last successful `*_prevalence_final_refresh` run.
    pub refreshed_at: Option<DateTime<Utc>>,
    /// Longest live `*_prevalence_final_refresh` cadence (`None`: unknown).
    pub refresh_interval: Option<Duration>,
}

impl CoverageProbe {
    /// The cadence staleness is judged against: the live one, never below the
    /// shipped default.
    pub fn effective_refresh_interval(&self) -> Duration {
        self.refresh_interval
            .filter(|interval| *interval > FINAL_REFRESH_INTERVAL)
            .unwrap_or(FINAL_REFRESH_INTERVAL)
    }
}

impl CoverageProbe {
    pub fn covered_since(&self, kind: ArtifactKind) -> Option<DateTime<Utc>> {
        self.covered_since[kind.index()]
    }

    pub fn set_covered_since(&mut self, kind: ArtifactKind, since: Option<DateTime<Utc>>) {
        self.covered_since[kind.index()] = since;
    }
}

/// For a source-restricted viewer: whether that viewer's attributed rows of
/// each kind reach back to the window start (`None` = unknown, probe failed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScopedCoverage {
    pub covered_before: [Option<bool>; 3],
}

impl ScopedCoverage {
    pub fn set(&mut self, kind: ArtifactKind, covered: Option<bool>) {
        self.covered_before[kind.index()] = covered;
    }
}

/// Which snapshot a read uses: the live `*_prevalence_agg` tables (single /
/// bulk / scatter lookups: never stale) or the refreshed `*_prevalence_final`
/// tables (rare / new lists, explorer, dictionaries).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoverageSource {
    Live,
    Refreshed,
}

/// Classify one kind for the window starting at `window_start`.
pub fn classify(
    probe: &CoverageProbe,
    kind: ArtifactKind,
    source: CoverageSource,
    window_start: DateTime<Utc>,
    now: DateTime<Utc>,
) -> PrevalenceProductState {
    let ingest_head = probe.ingest_head.map(|head| head.min(now));
    let refreshed_at = match source {
        CoverageSource::Live => None,
        CoverageSource::Refreshed => probe.refreshed_at,
    };
    let covered_since = probe.covered_since(kind);

    let (warming, partial) = match covered_since {
        // No rows of this kind at all: nothing has been aggregated yet.
        None => (true, false),
        Some(since) if since > window_start + BUCKET_SLACK => {
            // Prevalence starts inside the window. If events are about as old
            // as prevalence (or there are none), the install is young: warming.
            // Older events mean a prevalence gap: partial.
            let young = probe.ingest_since.is_none_or(|first| first >= since - BUCKET_SLACK);
            (young, !young)
        }
        Some(_) => (false, false),
    };

    let interval = probe.effective_refresh_interval();
    let stale = match (refreshed_at, ingest_head) {
        (Some(refreshed), Some(head)) => head - refreshed > interval * 2,
        _ => false,
    };

    PrevalenceProductState::from_flags(
        warming,
        stale,
        partial,
        PrevalenceProductState {
            state: PrevalenceCoverageState::Ready,
            warming,
            stale,
            partial,
            covered_since,
            refreshed_at,
            ingest_head,
            window_start,
            retry_after_s: Some(interval.num_seconds() as u64),
            age_s: refreshed_at.map(|refreshed| (now - refreshed).num_seconds().max(0) as u64),
        },
    )
}

/// Narrow an unrestricted kind state to a source-restricted viewer: the
/// attributed rows must reach the window start themselves, otherwise a miss is
/// unknown (`partial`; warming stays warming). Timestamps derived from other
/// sources are withheld.
pub fn restrict(global: PrevalenceProductState, covered_before: Option<bool>) -> PrevalenceProductState {
    let partial = global.partial || (!global.warming && covered_before != Some(true));
    let base = PrevalenceProductState { covered_since: None, ingest_head: None, ..global.clone() };
    PrevalenceProductState::from_flags(global.warming, global.stale, partial, base)
}

/// Coverage of one read, per artifact kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageReport {
    by_kind: [PrevalenceProductState; 3],
}

impl CoverageReport {
    pub fn new(hash: PrevalenceProductState, domain: PrevalenceProductState, ip: PrevalenceProductState) -> Self {
        Self { by_kind: [hash, domain, ip] }
    }

    pub fn kind(&self, kind: ArtifactKind) -> &PrevalenceProductState {
        &self.by_kind[kind.index()]
    }

    /// Turn a miss into "unknown" with ITS kind's coverage (a covered hash
    /// table never vouches for an empty domain table).
    pub fn apply(&self, data: &mut PrevalenceData) {
        data.apply_coverage(self.kind(ArtifactKind::of(data.artifact_type)));
    }

    /// One response-level state over `kinds`, conservatively: the worst state,
    /// every flag that any kind raises, and the LATEST coverage start (`None`
    /// when any kind has none).
    pub fn combined(&self, kinds: &[ArtifactKind]) -> PrevalenceProductState {
        let kinds: Vec<ArtifactKind> = if kinds.is_empty() { ArtifactKind::ALL.to_vec() } else { kinds.to_vec() };
        let states: Vec<&PrevalenceProductState> = kinds.iter().map(|k| self.kind(*k)).collect();
        let first = states[0].clone();
        let warming = states.iter().any(|s| s.warming);
        let stale = states.iter().any(|s| s.stale);
        let partial = states.iter().any(|s| s.partial);
        let covered_since = states
            .iter()
            .map(|s| s.covered_since)
            .collect::<Option<Vec<_>>>()
            .and_then(|all| all.into_iter().max());
        let base = PrevalenceProductState {
            covered_since,
            age_s: states.iter().filter_map(|s| s.age_s).max(),
            retry_after_s: states.iter().filter_map(|s| s.retry_after_s).max(),
            ..first
        };
        PrevalenceProductState::from_flags(warming, stale, partial, base)
    }
}

#[cfg(test)]
#[path = "coverage_tests.rs"]
mod tests;
