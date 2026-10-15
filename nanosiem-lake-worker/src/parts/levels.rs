// SPDX-License-Identifier: AGPL-3.0-or-later

//! Merge levels, triggers and supersession (contract section 6).
//!
//! The planner here is pure: it takes the live set and a clock and returns
//! the merges that are due. The merge itself streams (see
//! `crate::parts_ingest::merge`), and the result commits as one `merge`
//! log entry that supersedes every input.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::part_log::PartRef;
use super::{event_day_of, DAY_US, HOUR_US};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Level {
    #[serde(rename = "l0")]
    L0,
    #[serde(rename = "m")]
    Minute,
    #[serde(rename = "h")]
    Hour,
    #[serde(rename = "d")]
    Day,
}

impl Level {
    pub fn code(self) -> &'static str {
        match self {
            Self::L0 => "l0",
            Self::Minute => "m",
            Self::Hour => "h",
            Self::Day => "d",
        }
    }

    /// True when a part of this level spans one event hour.
    pub fn is_hourly(self) -> bool {
        !matches!(self, Self::Day)
    }
}

/// Tunables of the merge policy. Defaults are the contract values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergePolicy {
    /// Merge an hour's L0 parts into an M part once it holds this many.
    pub minute_min_l0_parts: usize,
    /// ...or once its oldest L0 part is this old (arrival ms).
    pub minute_max_l0_age_ms: i64,
    /// An hour is sealed this long after it ends.
    pub hour_seal_ms: i64,
    /// A day is sealed this long after it ends.
    pub day_seal_ms: i64,
    /// Superseded part data is deleted after this grace.
    pub supersede_grace_ms: i64,
    /// Unlogged part files are deleted after this age (>= 49 h).
    pub orphan_age_ms: i64,
    /// Interim cap on one merged part's total bytes (NAN-2884): until every
    /// `lake_part` PUT carries `x-amz-checksum-sha256`, the owner re-hashes
    /// cell parts within a 2 GiB budget per sign call. A merge whose inputs'
    /// estimated output exceeds it is not planned: the day stays as hour
    /// parts (or the hour as minute parts). `None` removes the cap.
    pub max_part_bytes: Option<u64>,
    /// Plan `d` parts. Off by default (interim, NAN-2886): control's writer
    /// authority is hour-scoped (legal holds and retention are per hour) and
    /// refuses a day part whose rows extend past its first hour, so `h` is
    /// the top level for every tenant until multi-hour authority lands.
    pub day_merges: bool,
    /// A sealed hour with unmerged (L0/M) parts is (re)merged into `h` only
    /// once its NEWEST unmerged part is at least this old (arrival ms)...
    /// A catch-up that feeds late L0s into already-sealed hours would
    /// otherwise rewrite the whole hour once per L0 (the lab-tenant wedge).
    #[serde(default = "default_sealed_remerge_debounce_ms")]
    pub sealed_remerge_debounce_ms: i64,
    /// ...or once its OLDEST unmerged part is this old: bounds how long late
    /// L0/M parts pile up beside the hour's `h` part.
    #[serde(default = "default_sealed_remerge_max_defer_ms")]
    pub sealed_remerge_max_defer_ms: i64,
}

fn default_sealed_remerge_debounce_ms() -> i64 {
    5 * 60_000
}

fn default_sealed_remerge_max_defer_ms() -> i64 {
    30 * 60_000
}

/// The interim per-part size cap (owner re-hash budget per sign call).
pub const INTERIM_MAX_PART_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Estimated bytes of a merged part: its inputs' data plus 35% for token
/// indexes and partials (measured on real tenant1 hour parts: 22%; small
/// parts up to 32%).
pub fn estimated_part_bytes(inputs: &[PartRef]) -> u64 {
    let data: u64 = inputs.iter().map(|p| p.data_bytes).sum();
    data.saturating_add(data.saturating_mul(35) / 100)
}

impl Default for MergePolicy {
    fn default() -> Self {
        Self {
            minute_min_l0_parts: 12,
            minute_max_l0_age_ms: 60_000,
            hour_seal_ms: 10 * 60_000,
            day_seal_ms: 2 * 3_600_000,
            supersede_grace_ms: 3_600_000,
            // NAN-2879 policy: the 48 h id memory + 1 h (contract 6.4).
            orphan_age_ms: 49 * 3_600_000,
            max_part_bytes: Some(INTERIM_MAX_PART_BYTES),
            day_merges: false,
            sealed_remerge_debounce_ms: default_sealed_remerge_debounce_ms(),
            sealed_remerge_max_defer_ms: default_sealed_remerge_max_defer_ms(),
        }
    }
}

/// When ingest cuts an L0 part: at most `max_age_ms` after the first
/// buffered row arrived, sooner (down to `min_age_ms`) once the rate fills
/// `target_rows`. `max_age_ms` is the ingest share of arrival→searchable at
/// low rates, where it dominates (NAN-2984): the rest is the Vector sink
/// batch timeout (5 s), the 1 s edge pull and the sign/PUT/log append.
///
/// Part-count cost: L0 parts/hour = 3,600 s / the interval (360 at the 10 s
/// default, 120 at the old 30 s cap). The merge policy (M at
/// `minute_min_l0_parts` L0s or `minute_max_l0_age_ms`, H at seal) bounds
/// what queries see to ≈ 1 M part per minute of the open hour plus a few
/// L0s, independent of this interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlushPolicy {
    /// Floor: never cut L0 parts faster than this, whatever the rate.
    pub min_age_ms: i64,
    /// Cap: a buffered row waits at most this long for its part.
    pub max_age_ms: i64,
    /// Rows a part should hold; sets the interval between the two bounds.
    pub target_rows: u64,
}

/// Default L0 age cap (NAN-2984; was 30 s): arrival→searchable ≤ ~20 s at
/// any rate instead of ~45 s below 100 eps.
pub const DEFAULT_FLUSH_MAX_AGE_MS: i64 = 10_000;
/// Default L0 age floor.
pub const DEFAULT_FLUSH_MIN_AGE_MS: i64 = 5_000;
/// Default rows per L0 part.
pub const DEFAULT_FLUSH_TARGET_ROWS: u64 = 3_000;
/// Bounds a configured policy must stay inside: at least 1 s between parts
/// (owner-sign QPS, PUTs), and never more than the 2-minute visibility
/// ceiling. Defined once, with the cell config check (`IngestFlush`).
pub const FLUSH_AGE_FLOOR_MS: i64 = nanosiem_lake_cell::contract::IngestFlush::AGE_FLOOR_MS as i64;
pub const FLUSH_AGE_CEILING_MS: i64 = nanosiem_lake_cell::contract::IngestFlush::AGE_CEILING_MS as i64;

impl Default for FlushPolicy {
    fn default() -> Self {
        Self { min_age_ms: DEFAULT_FLUSH_MIN_AGE_MS, max_age_ms: DEFAULT_FLUSH_MAX_AGE_MS, target_rows: DEFAULT_FLUSH_TARGET_ROWS }
    }
}

impl FlushPolicy {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (FLUSH_AGE_FLOOR_MS..=FLUSH_AGE_CEILING_MS).contains(&self.min_age_ms)
                && (FLUSH_AGE_FLOOR_MS..=FLUSH_AGE_CEILING_MS).contains(&self.max_age_ms),
            "ingest flush ages must be within {FLUSH_AGE_FLOOR_MS}..={FLUSH_AGE_CEILING_MS} ms"
        );
        anyhow::ensure!(self.min_age_ms <= self.max_age_ms, "ingest flush min_age_ms exceeds max_age_ms");
        anyhow::ensure!(self.target_rows > 0 && self.target_rows <= FLUSH_MAX_ROWS as u64, "ingest flush target_rows must be 1..={FLUSH_MAX_ROWS}");
        Ok(())
    }

    /// Flush interval for L0 parts: `clamp(min, max, target_rows / eps)`.
    /// An unknown or zero rate (idle, first batch) gets the cap.
    pub fn interval_ms(&self, events_per_second: f64) -> i64 {
        let (min, max) = (self.min_age_ms as f64, self.max_age_ms.max(self.min_age_ms) as f64);
        if !events_per_second.is_finite() || events_per_second <= 0.0 {
            return max as i64;
        }
        ((self.target_rows as f64 / events_per_second) * 1_000.0).clamp(min, max) as i64
    }
}

/// Flush interval under the default [`FlushPolicy`].
pub fn flush_interval_ms(events_per_second: f64) -> i64 {
    FlushPolicy::default().interval_ms(events_per_second)
}

/// A flush also fires at this many buffered rows.
pub const FLUSH_MAX_ROWS: usize = nanosiem_lake_cell::contract::IngestFlush::MAX_TARGET_ROWS as usize;

/// Maximum L0 inputs per minute job (72k rows at the default 300-eps flush).
pub const MAX_MINUTE_MERGE_INPUTS: usize = 24;

/// One merge the planner decided is due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedMerge {
    pub output_level: Level,
    /// Event hour of the output (first hour of the day for a day part).
    pub event_hour: i32,
    pub inputs: Vec<PartRef>,
}

/// Plan every due merge over the live set at `now_ms` (wall clock, which is
/// also the arrival clock that stamps part ids).
///
/// Rules (contract 6.1–6.2):
/// - M: an hour with ≥ `minute_min_l0_parts` L0 parts, or whose oldest L0
///   is older than `minute_max_l0_age_ms`, and ≥ 2 L0 parts; all L0 of the
///   hour merge.
/// - H: a sealed hour with any L0/M part, or with more than one H part; all
///   of the hour's L0/M/H parts merge, once the L0/M parts have settled
///   (newest older than `sealed_remerge_debounce_ms`, or oldest older than
///   `sealed_remerge_max_defer_ms`); until then its L0s merge into M.
/// - D: a sealed day whose every non-empty hour is exactly one H part (no
///   L0/M), plus at most one prior D; all merge. Empty hours are fine.
///   Late data for a day that already has a D part produces H parts that
///   re-merge into a new D.
///
/// Parts with `sorted == false` (adopted) are never merge inputs.
///
/// This is [`plan_merges_with`] with the history lane open (inline merges,
/// or a background scheduler that is not catching up).
pub fn plan_merges(live: &[PartRef], now_ms: i64, policy: &MergePolicy) -> Vec<PlannedMerge> {
    plan_merges_with(live, now_ms, policy, true)
}

/// True when a sealed hour's unmerged (L0/M) parts are `quiet`: the newest
/// was created at least `sealed_remerge_debounce_ms` ago, so the hour no
/// longer receives writes (a backfilled hour once ingest moved past it).
fn unmerged_quiet<'a>(parts: impl Iterator<Item = &'a PartRef>, now_ms: i64, policy: &MergePolicy) -> bool {
    let mut newest = None;
    for part in parts.filter(|p| matches!(p.level, Level::L0 | Level::Minute)) {
        newest = newest.max(Some(part.part_id.created_unix_ms()));
    }
    newest.is_some_and(|newest| now_ms - newest >= policy.sealed_remerge_debounce_ms)
}

/// [`plan_merges`] for a scheduler whose hour lane may be closed.
///
/// NAN-3187: with `history_open`, a sealed, quiet hour (see
/// [`unmerged_quiet`]) merges its L0 and M parts straight into its `h` part,
/// whatever its L0 count, instead of first rewriting the L0s into M parts
/// (rows were rewritten twice, L0→M→H, after a 14 h backlog). An hour over
/// `max_part_bytes` is chunked into cap-sized `h` parts directly (each row
/// rewritten once; those parts are final and not re-planned). With the lane
/// closed (the background scheduler defers hour merges while ingest catches
/// up) the L0s of a large hour still
/// consolidate into M as before, so they do not pile up while no `h` merge can
/// start. Hours still receiving writes, and unsealed hours, are unchanged.
pub fn plan_merges_with(live: &[PartRef], now_ms: i64, policy: &MergePolicy, history_open: bool) -> Vec<PlannedMerge> {
    // Bound one minute job to 72k rows at 300 eps / 10-second L0s.
    // 24 inputs per minute sustain 1,200 eps, four times arrival.
    let split = |merges: Vec<PlannedMerge>| merges.into_iter().flat_map(|merge| {
        if merge.output_level == Level::Minute {
            merge.inputs.chunks(MAX_MINUTE_MERGE_INPUTS).filter(|c| c.len() >= 2).map(|c| PlannedMerge {
                output_level: Level::Minute, event_hour: merge.event_hour, inputs: c.to_vec(),
            }).collect::<Vec<_>>()
        } else { vec![merge] }
    }).collect::<Vec<_>>();
    let Some(cap) = policy.max_part_bytes else { return split(plan_merges_uncapped(live, now_ms, policy, history_open)) };
    let fits = |inputs: &[PartRef]| estimated_part_bytes(inputs) <= cap;
    let mut out = Vec::new();
    for merge in plan_merges_uncapped(live, now_ms, policy, history_open) {
        if fits(&merge.inputs) {
            out.push(merge);
            continue;
        }
        // Over the cap. A day stays as hour parts. An hour (or a minute
        // merge) still consolidates its L0 parts: into minute parts of
        // time-ordered chunks under the cap, so L0s never pile up. A quiet
        // sealed hour with the hour lane open (NAN-3187) consolidates its
        // L0 and M parts into cap-sized hour parts instead: one rewrite.
        if merge.output_level == Level::Day {
            continue;
        }
        let direct = history_open && merge.output_level == Level::Hour && unmerged_quiet(merge.inputs.iter(), now_ms, policy);
        let (output_level, chunked) = if direct {
            (Level::Hour, &[Level::L0, Level::Minute][..])
        } else {
            (Level::Minute, &[Level::L0][..])
        };
        let mut l0 = merge.inputs.iter().filter(|p| chunked.contains(&p.level)).cloned().collect::<Vec<_>>();
        l0.sort_by_key(|p| (p.min_time_us, p.max_time_us));
        let mut chunk: Vec<PartRef> = Vec::new();
        for part in l0 {
            chunk.push(part);
            if !fits(&chunk) {
                let last = chunk.pop().expect("pushed");
                if chunk.len() >= 2 {
                    out.push(PlannedMerge { output_level, event_hour: merge.event_hour, inputs: std::mem::take(&mut chunk) });
                } else {
                    chunk.clear();
                }
                chunk.push(last);
            }
        }
        if chunk.len() >= 2 {
            out.push(PlannedMerge { output_level, event_hour: merge.event_hour, inputs: chunk });
        }
    }
    split(out)
}

fn plan_merges_uncapped(live: &[PartRef], now_ms: i64, policy: &MergePolicy, history_open: bool) -> Vec<PlannedMerge> {
    let mut by_hour: BTreeMap<i32, Vec<&PartRef>> = BTreeMap::new();
    let mut days: BTreeMap<i32, Vec<&PartRef>> = BTreeMap::new();
    for part in live.iter().filter(|part| part.sorted) {
        match part.level {
            Level::Day => days.entry(part.event_day.unwrap_or_else(|| event_day_of(i64::from(part.event_hour) * HOUR_US))).or_default().push(part),
            _ => by_hour.entry(part.event_hour).or_default().push(part),
        }
    }
    let mut planned = Vec::new();
    for (hour, parts) in &by_hour {
        let hour_end_ms = (i64::from(*hour) + 1) * (HOUR_US / 1_000);
        let sealed = now_ms >= hour_end_ms + policy.hour_seal_ms;
        let unmerged = parts.iter().filter(|p| p.level != Level::Hour).count();
        let hour_parts = parts.iter().filter(|p| p.level == Level::Hour).count();
        // A sealed hour still receiving late parts (catch-up) waits until
        // they go quiet (or the defer cap), so the hour is rewritten once
        // per batch, not once per L0. Meanwhile its L0s still merge into M
        // below; every part stays live and queryable.
        let settled = || {
            let created = parts.iter().filter(|p| p.level != Level::Hour).map(|p| p.part_id.created_unix_ms());
            let (newest, oldest) = created.fold((i64::MIN, i64::MAX), |(n, o), c| (n.max(c), o.min(c)));
            unmerged == 0
                || now_ms - newest >= policy.sealed_remerge_debounce_ms
                || now_ms - oldest >= policy.sealed_remerge_max_defer_ms
        };
        // A large sealed L0 backlog consolidates into M before H (NAN-3077)
        // unless the hour is quiet and an `h` merge can start (NAN-3187):
        // then its L0s go straight into the `h` part.
        let direct = history_open && sealed && unmerged_quiet(parts.iter().copied(), now_ms, policy);
        if sealed && (unmerged > 0 || hour_parts > 1) && settled()
            && (direct || parts.iter().filter(|p| p.level == Level::L0).count() < policy.minute_min_l0_parts) {
            planned.push(PlannedMerge {
                output_level: Level::Hour,
                event_hour: *hour,
                inputs: parts.iter().map(|p| (*p).clone()).collect(),
            });
            continue;
        }
        let l0 = parts.iter().filter(|p| p.level == Level::L0).collect::<Vec<_>>();
        if l0.len() >= 2 {
            let oldest = l0.iter().map(|p| p.part_id.created_unix_ms()).min().unwrap_or(now_ms);
            if l0.len() >= policy.minute_min_l0_parts || now_ms - oldest >= policy.minute_max_l0_age_ms {
                planned.push(PlannedMerge {
                    output_level: Level::Minute,
                    event_hour: *hour,
                    inputs: l0.iter().map(|p| (**p).clone()).collect(),
                });
            }
        }
    }
    if !policy.day_merges {
        return planned;
    }
    // Day merges: hours grouped by day.
    let mut hours_by_day: BTreeMap<i32, Vec<(&i32, &Vec<&PartRef>)>> = BTreeMap::new();
    for (hour, parts) in &by_hour {
        hours_by_day.entry(event_day_of(i64::from(*hour) * HOUR_US)).or_default().push((hour, parts));
    }
    let mut day_keys = hours_by_day.keys().copied().collect::<Vec<_>>();
    day_keys.extend(days.keys().copied());
    day_keys.sort_unstable();
    day_keys.dedup();
    for day in day_keys {
        let day_end_ms = (i64::from(day) + 1) * (DAY_US / 1_000);
        if now_ms < day_end_ms + policy.day_seal_ms {
            continue;
        }
        let hours = hours_by_day.get(&day).map(Vec::as_slice).unwrap_or(&[]);
        let prior_days = days.get(&day).map(Vec::as_slice).unwrap_or(&[]);
        let all_hour_parts = hours.iter().all(|(_, parts)| parts.len() == 1 && parts[0].level == Level::Hour);
        if !all_hour_parts || (hours.is_empty() && prior_days.len() <= 1) {
            continue;
        }
        let mut inputs = prior_days.iter().map(|p| (*p).clone()).collect::<Vec<_>>();
        inputs.extend(hours.iter().flat_map(|(_, parts)| parts.iter().map(|p| (*p).clone())));
        planned.push(PlannedMerge {
            output_level: Level::Day,
            event_hour: day * 24,
            inputs,
        });
    }
    planned
}

/// NAN-3701: how long the most overdue live L0 part has waited past the
/// moment `policy` makes it a merge input, in ms (0 when none is overdue).
///
/// Raw L0 age is not a compaction-stall signal. A LONE L0 in its hour (a
/// low-rate tenant between flushes, or a straggler that lands after the
/// hour's last minute merge) is never a minute-merge input (that needs two
/// L0s): it waits for the hour to seal and settle, so a healthy one routinely
/// reaches `hour_seal_ms` (10 min) of age. On 2026-10-12 that paged
/// `oldest_unmerged_l0_age` every hour at about xx:06 on cell-us-1 and, on
/// tenant-a, at 924 s (a straggler created 19:00:24Z waited for the 19:10 seal,
/// then for its 1.25M-row hour merge, committed 19:18:16Z).
///
/// Due times, per event hour (the same rules as [`plan_merges_with`]):
/// - two or more L0s: the second-oldest L0's arrival or the oldest's plus
///   `minute_max_l0_age_ms`, whichever is later (sooner at
///   `minute_min_l0_parts`);
/// - a lone L0: the hour merge, once the hour is sealed and its unmerged
///   (L0/M) parts settled: max(hour end + `hour_seal_ms`, min(newest + the
///   debounce, oldest + the max defer)).
///
/// The value includes merge execution and lane queueing (a due L0 is
/// overdue until its merge commits), so a hung, failing or quarantined merge
/// keeps it growing.
///
/// An UNSORTED L0 is never a merge input (`merge.rs` refuses it), so it would
/// stay forever. The part log refuses one today: `add` carries only sorted
/// L0s, and `adopt` only unsorted h/d parts. But it must not hide if that
/// ever changes, so it is due `hour_seal_ms` after its arrival (there is no
/// sort or adopt window for L0) and counts overdue from there. Unsorted h/d
/// (adopted) parts are final and not L0, so they are not counted.
pub fn l0_merge_overdue_ms<'a>(live: impl IntoIterator<Item = &'a PartRef>, now_ms: i64, policy: &MergePolicy) -> i64 {
    let mut by_hour: BTreeMap<i32, Vec<&PartRef>> = BTreeMap::new();
    let mut worst = 0i64;
    for part in live {
        if part.level == Level::L0 && !part.sorted {
            let due = part.part_id.created_unix_ms().saturating_add(policy.hour_seal_ms);
            worst = worst.max(now_ms.saturating_sub(due));
        } else if part.sorted && part.level.is_hourly() {
            by_hour.entry(part.event_hour).or_default().push(part);
        }
    }
    for (hour, parts) in &by_hour {
        let mut l0 = parts.iter().filter(|p| p.level == Level::L0).map(|p| p.part_id.created_unix_ms()).collect::<Vec<_>>();
        if l0.is_empty() {
            continue;
        }
        l0.sort_unstable();
        let due = if l0.len() >= 2 {
            let by_age = l0[0].saturating_add(policy.minute_max_l0_age_ms);
            let by_count = l0.get(policy.minute_min_l0_parts.max(2) - 1).copied().unwrap_or(i64::MAX);
            l0[1].max(by_age.min(by_count))
        } else {
            let hour_end_ms = (i64::from(*hour) + 1) * (HOUR_US / 1_000);
            let (newest, oldest) = parts.iter().filter(|p| matches!(p.level, Level::L0 | Level::Minute))
                .map(|p| p.part_id.created_unix_ms())
                .fold((i64::MIN, i64::MAX), |(n, o), c| (n.max(c), o.min(c)));
            let settled = newest.saturating_add(policy.sealed_remerge_debounce_ms)
                .min(oldest.saturating_add(policy.sealed_remerge_max_defer_ms));
            hour_end_ms.saturating_add(policy.hour_seal_ms).max(settled)
        };
        worst = worst.max(now_ms.saturating_sub(due));
    }
    worst
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::format::PartId;

    fn part(level: Level, hour: i32, created_ms: i64) -> PartRef {
        let id = PartId::parse(&format!("{created_ms:013}-{:016x}", (hour as u64) * 1000 + created_ms as u64 % 1000 + level as u64)).unwrap();
        PartRef {
            part_id: id,
            level,
            event_hour: hour,
            event_day: (level == Level::Day).then(|| hour / 24),
            rows: 10,
            min_time_us: i64::from(hour) * HOUR_US,
            max_time_us: i64::from(hour) * HOUR_US + 1,
            schema_fingerprint: "0".repeat(64),
            provenance_sha256: "0".repeat(64),
            merkle_root: "0".repeat(64),
            sorted: true,
            data_bytes: 1,
            row_groups: 1,
            data_files: 1,
        }
    }

    const H: i32 = 497_314; // an hour; hour 10 of its day
    fn hour_ms(h: i32) -> i64 {
        i64::from(h) * 3_600_000
    }

    #[test]
    fn flush_interval_is_clamped() {
        // NAN-2984 defaults: 10 s cap at low rates (was 30 s), 5 s floor.
        assert_eq!(flush_interval_ms(300.0), 10_000);
        assert_eq!(flush_interval_ms(20.0), 10_000);
        assert_eq!(flush_interval_ms(1.0), 10_000);
        assert_eq!(flush_interval_ms(450.0), 6_666);
        assert_eq!(flush_interval_ms(10_000.0), 5_000);
        assert_eq!(flush_interval_ms(0.0), 10_000);
        assert_eq!(flush_interval_ms(f64::NAN), 10_000);
    }

    #[test]
    fn flush_policy_is_configurable_and_validated() {
        let legacy = FlushPolicy { min_age_ms: 5_000, max_age_ms: 30_000, target_rows: 3_000 };
        legacy.validate().unwrap();
        assert_eq!(legacy.interval_ms(20.0), 30_000);
        assert_eq!(legacy.interval_ms(300.0), 10_000);
        let fast = FlushPolicy { min_age_ms: 2_000, max_age_ms: 5_000, target_rows: 1_000 };
        fast.validate().unwrap();
        assert_eq!(fast.interval_ms(20.0), 5_000);
        assert_eq!(fast.interval_ms(1_000.0), 2_000);
        FlushPolicy::default().validate().unwrap();
        for bad in [
            FlushPolicy { min_age_ms: 500, ..FlushPolicy::default() },
            FlushPolicy { max_age_ms: 180_000, ..FlushPolicy::default() },
            FlushPolicy { min_age_ms: 20_000, max_age_ms: 10_000, target_rows: 3_000 },
            FlushPolicy { target_rows: 0, ..FlushPolicy::default() },
            FlushPolicy { target_rows: FLUSH_MAX_ROWS as u64 + 1, ..FlushPolicy::default() },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    /// Worst-case arrival→searchable budget at the defaults stays well
    /// under the 60 s p95 target at 20 and 300 eps: sink batch timeout (5 s)
    /// + edge pull tick (1 s) + L0 age + sign/PUT/log append (allow 5 s).
    #[test]
    fn default_visibility_budget_is_under_target() {
        for eps in [0.0, 1.0, 20.0, 300.0, 1_200.0] {
            let worst_ms = 5_000 + 1_000 + flush_interval_ms(eps) + 5_000;
            assert!(worst_ms <= 25_000, "eps {eps}: {worst_ms} ms");
        }
    }

    #[test]
    fn minute_merge_after_age_or_count() {
        let now = hour_ms(H) + 10 * 60_000;
        let live = vec![part(Level::L0, H, now - 70_000), part(Level::L0, H, now - 10_000)];
        let planned = plan_merges(&live, now, &MergePolicy::default());
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].output_level, Level::Minute);
        // Young parts, few of them: nothing yet.
        let live = vec![part(Level::L0, H, now - 5_000), part(Level::L0, H, now - 1_000)];
        assert!(plan_merges(&live, now, &MergePolicy::default()).is_empty());
    }

    #[test]
    fn sealed_hour_merges_everything_into_one_hour_part() {
        let now = hour_ms(H + 1) + 11 * 60_000;
        let live = vec![part(Level::Minute, H, now - 3_000_000), part(Level::L0, H, now - 1_000)];
        let planned = plan_merges(&live, now, &MergePolicy::default());
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].output_level, Level::Hour);
        assert_eq!(planned[0].inputs.len(), 2);
        // A single H part is final.
        assert!(plan_merges(&[part(Level::Hour, H, 1)], now, &MergePolicy::default()).is_empty());
    }

    #[test]
    fn late_data_remerges_the_hour() {
        let now = hour_ms(H + 5);
        let policy = MergePolicy::default();
        // Fresh late data waits for the debounce (it may be a catch-up)...
        let live = vec![part(Level::Hour, H, 1), part(Level::L0, H, now - 1_000)];
        assert!(plan_merges(&live, now, &policy).is_empty(), "a fresh late L0 does not rewrite the hour");
        // ...then the hour re-merges once.
        let live = vec![part(Level::Hour, H, 1), part(Level::L0, H, now - policy.sealed_remerge_debounce_ms)];
        let planned = plan_merges(&live, now, &policy);
        assert_eq!(planned[0].output_level, Level::Hour);
        assert_eq!(planned[0].inputs.len(), 2);
    }

    #[test]
    fn sealed_hour_under_steady_late_data_defers_but_is_bounded() {
        let now = hour_ms(H + 5);
        let policy = MergePolicy::default();
        // L0s keep arriving (newest always fresh), but the oldest crossed the cap.
        let live = vec![
            part(Level::Hour, H, 1),
            part(Level::L0, H, now - policy.sealed_remerge_max_defer_ms),
            part(Level::L0, H, now - 1_000),
        ];
        let planned = plan_merges(&live, now, &policy);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].output_level, Level::Hour);
        // Below the cap, the deferred hour still consolidates its L0s into M.
        let live = vec![part(Level::Hour, H, 1), part(Level::L0, H, now - 70_000), part(Level::L0, H, now - 1_000)];
        let planned = plan_merges(&live, now, &policy);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].output_level, Level::Minute);
        assert_eq!(planned[0].inputs.len(), 2);
    }

    /// The lean test tenant's wedge (2026-09-29): ingest resumed ~1.6 h behind, so
    /// every 10 s L0 landed in an already-sealed hour and each one planned a
    /// rewrite of that whole hour. Simulates the catch-up tick by tick (one
    /// L0 of `catch_up`x the live rate per 10 s tick, merges applied as
    /// planned, at most 2 per tick) and counts rows rewritten into `h` parts.
    fn catch_up_hour_rewrite_rows(policy: &MergePolicy) -> (u64, u64, usize) {
        const TICK_MS: i64 = 10_000;
        const EPS: i64 = 300;
        let catch_up = 5; // event time advances 5x faster than the wall clock
        let start = hour_ms(H + 3);
        let mut event_ms = start - 96 * 60_000; // 1.6 h behind
        let mut live: Vec<PartRef> = Vec::new();
        let mut seq = 0_u64;
        let mut mk = |level: Level, hour: i32, created: i64, rows: u64| {
            seq += 1;
            let id = PartId::parse(&format!("{created:013}-{seq:016x}")).unwrap();
            PartRef {
                part_id: id,
                level,
                event_hour: hour,
                event_day: None,
                rows,
                min_time_us: i64::from(hour) * HOUR_US,
                max_time_us: i64::from(hour) * HOUR_US + HOUR_US - 1,
                schema_fingerprint: "0".repeat(64),
                provenance_sha256: "0".repeat(64),
                merkle_root: "0".repeat(64),
                sorted: true,
                data_bytes: rows * 150,
                row_groups: 1,
                data_files: 1,
            }
        };
        let (mut ingested, mut rewritten, mut h_merges) = (0_u64, 0_u64, 0_usize);
        let mut now = start;
        while event_ms < now - 60_000 {
            now += TICK_MS;
            let span = TICK_MS * catch_up;
            let rows = (EPS * span / 1_000) as u64;
            let hour = (event_ms / 3_600_000) as i32;
            live.push(mk(Level::L0, hour, now, rows));
            ingested += rows;
            event_ms += span;
            for merge in plan_merges(&live, now, policy).into_iter().take(2) {
                let rows = merge.inputs.iter().map(|p| p.rows).sum::<u64>();
                if merge.output_level == Level::Hour {
                    rewritten += rows;
                    h_merges += 1;
                }
                live.retain(|p| !merge.inputs.iter().any(|i| i.part_id == p.part_id));
                live.push(mk(merge.output_level, merge.event_hour, now, rows));
            }
        }
        (ingested, rewritten, h_merges)
    }

    #[test]
    fn catch_up_does_not_rewrite_sealed_hours_per_l0() {
        let old = MergePolicy { sealed_remerge_debounce_ms: 0, sealed_remerge_max_defer_ms: 0, ..MergePolicy::default() };
        let (ingested, old_rows, old_merges) = catch_up_hour_rewrite_rows(&old);
        let (same, new_rows, new_merges) = catch_up_hour_rewrite_rows(&MergePolicy::default());
        assert_eq!(ingested, same);
        // Before: an h rewrite of the growing hour for nearly every L0.
        assert!(old_merges >= 50, "old policy: {old_merges} h merges");
        assert!(old_rows > 10 * ingested, "old policy rewrote {old_rows} rows for {ingested} ingested");
        // After: each backlog hour is rewritten a bounded number of times,
        // so merge work per ingested row is small (measured: 1 h merge of
        // 0.66 M rows vs 101 merges rewriting 52 M rows for 2.1 M ingested).
        assert!(new_merges <= 8, "new policy: {new_merges} h merges");
        assert!(new_rows <= ingested, "new policy rewrote {new_rows} rows for {ingested} ingested");
        assert!(old_rows >= 10 * new_rows, "old {old_rows} vs new {new_rows}");
    }

    #[test]
    fn hour_is_the_top_level_by_default() {
        let day_start = H - 10;
        let now = hour_ms(day_start + 24) + 3 * 3_600_000;
        let live = (0..24).map(|i| part(Level::Hour, day_start + i, 1)).collect::<Vec<_>>();
        assert!(plan_merges(&live, now, &MergePolicy::default()).is_empty(), "no d parts by default (NAN-2886)");
        let small = MergePolicy { max_part_bytes: None, ..MergePolicy::default() };
        assert!(plan_merges(&live, now, &small).is_empty(), "20-eps tenants too");
    }

    #[test]
    fn day_merge_waits_for_every_hour_to_be_an_hour_part() {
        let day_start = H - 10;
        let now = hour_ms(day_start + 24) + 3 * 3_600_000;
        let mut live = (0..24).map(|i| part(Level::Hour, day_start + i, 1)).collect::<Vec<_>>();
        let days = MergePolicy { day_merges: true, ..MergePolicy::default() };
        let planned = plan_merges(&live, now, &days);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].output_level, Level::Day);
        assert_eq!(planned[0].event_hour, day_start);
        assert_eq!(planned[0].inputs.len(), 24);
        live.push(part(Level::L0, day_start + 3, now - 1_000));
        let planned = plan_merges(&live, now, &days);
        assert!(planned.iter().all(|m| m.output_level != Level::Day));
        // A lone day part is final.
        assert!(plan_merges(&[part(Level::Day, day_start, 1)], now, &days).is_empty());
    }

    #[test]
    fn adopted_unsorted_parts_are_never_inputs() {
        let now = hour_ms(H + 5);
        let mut adopted = part(Level::Hour, H, 1);
        adopted.sorted = false;
        let live = vec![adopted, part(Level::Hour, H, 2)];
        assert!(plan_merges(&live, now, &MergePolicy::default()).is_empty());
    }

    #[test]
    fn interim_cap_keeps_a_large_day_as_hour_parts() {
        let day_start = H - 10;
        let now = hour_ms(day_start + 24) + 3 * 3_600_000;
        let mut live = (0..24).map(|i| part(Level::Hour, day_start + i, 1)).collect::<Vec<_>>();
        // A 300-eps day: ~113 MB per hour part, ~3.7 GB in total.
        live.iter_mut().for_each(|p| p.data_bytes = 160_000_000);
        let policy = MergePolicy { day_merges: true, ..MergePolicy::default() };
        assert!(plan_merges(&live, now, &policy).is_empty(), "the day would exceed 2 GiB");
        let uncapped = MergePolicy { max_part_bytes: None, ..policy };
        assert_eq!(plan_merges(&live, now, &uncapped).len(), 1);
        // An over-cap sealed hour still consolidates its L0s into minute parts.
        let hour_now = hour_ms(H + 1) + 11 * 60_000;
        let mut big_hour = (0..40).map(|i| part(Level::L0, H, 1_000 + i)).collect::<Vec<_>>();
        big_hour.iter_mut().for_each(|p| p.data_bytes = 200_000_000);
        let planned = plan_merges_with(&big_hour, hour_now, &policy, false);
        assert!(!planned.is_empty() && planned.iter().all(|m| m.output_level == Level::Minute));
        assert!(planned.iter().all(|m| estimated_part_bytes(&m.inputs) <= INTERIM_MAX_PART_BYTES));
        // With the hour lane open (NAN-3187) the quiet hour goes straight to
        // cap-sized hour parts.
        let planned = plan_merges(&big_hour, hour_now, &policy);
        assert!(!planned.is_empty() && planned.iter().all(|m| m.output_level == Level::Hour));
        assert!(planned.iter().all(|m| estimated_part_bytes(&m.inputs) <= INTERIM_MAX_PART_BYTES));
        // A 20-eps day fits and still merges.
        live.iter_mut().for_each(|p| p.data_bytes = 7_000_000);
        assert_eq!(plan_merges(&live, now, &policy).len(), 1);
    }

    /// `n` L0 parts of hour `hour`, the newest created at `newest_ms`, one
    /// 10 s flush apart (oldest first).
    fn l0s(hour: i32, n: i64, newest_ms: i64) -> Vec<PartRef> {
        (0..n).map(|i| part(Level::L0, hour, newest_ms - (n - 1 - i) * 10_000)).collect()
    }

    /// Apply `planned` to `live` the way a committed merge does.
    fn apply(live: &mut Vec<PartRef>, planned: &[PlannedMerge], now_ms: i64) {
        for (i, merge) in planned.iter().enumerate() {
            live.retain(|p| !merge.inputs.iter().any(|input| input.part_id == p.part_id));
            let mut output = part(merge.output_level, merge.event_hour, now_ms + i as i64);
            output.data_bytes = merge.inputs.iter().map(|p| p.data_bytes).sum();
            live.push(output);
        }
    }

    /// NAN-3187: a backfilled sealed hour with 30 L0 parts that ingest has
    /// moved past merges straight into one `h` part: no L0 → M rewrite first.
    #[test]
    fn quiet_sealed_hour_with_30_l0s_merges_directly_into_h() {
        let policy = MergePolicy::default();
        let now = hour_ms(H + 3);
        let live = l0s(H, 30, now - policy.sealed_remerge_debounce_ms);
        let planned = plan_merges(&live, now, &policy);
        assert_eq!(planned.len(), 1, "{planned:?}");
        assert_eq!(planned[0].output_level, Level::Hour);
        assert_eq!(planned[0].inputs.len(), 30);
        assert!(planned.iter().all(|m| m.output_level != Level::Minute), "no M step");
        // Existing M parts of the hour join the same merge.
        let mut with_m = live.clone();
        with_m.push(part(Level::Minute, H, now - 3_000_000));
        let planned = plan_merges(&with_m, now, &policy);
        assert_eq!((planned.len(), planned[0].output_level, planned[0].inputs.len()), (1, Level::Hour, 31));
        // While the background hour lane is closed (ingest catching up) the
        // L0s still consolidate into M so they do not pile up (NAN-3077).
        let planned = plan_merges_with(&live, now, &policy, false);
        assert!(!planned.is_empty() && planned.iter().all(|m| m.output_level == Level::Minute), "{planned:?}");
    }

    /// NAN-3187 keeps the old behavior for hours still receiving writes:
    /// unsealed hours, and sealed hours whose newest L0 is fresh.
    #[test]
    fn unsealed_and_still_written_hours_keep_l0_to_m() {
        let policy = MergePolicy::default();
        // Unsealed (the open hour): 30 L0s merge into M, identically whether
        // or not the hour lane is open.
        let now = hour_ms(H) + 30 * 60_000;
        let live = l0s(H, 30, now - 1_000);
        let open = plan_merges_with(&live, now, &policy, true);
        assert_eq!(open, plan_merges_with(&live, now, &policy, false));
        assert!(!open.is_empty() && open.iter().all(|m| m.output_level == Level::Minute));
        assert_eq!(open.iter().map(|m| m.inputs.len()).sum::<usize>(), 30);
        // Sealed but a catch-up is still writing into it (newest L0 fresh,
        // oldest past the defer cap): M, as before.
        let now = hour_ms(H + 3);
        let mut live = l0s(H, 29, now - 1_000);
        live.insert(0, part(Level::L0, H, now - policy.sealed_remerge_max_defer_ms));
        let open = plan_merges_with(&live, now, &policy, true);
        assert_eq!(open, plan_merges_with(&live, now, &policy, false));
        assert!(!open.is_empty() && open.iter().all(|m| m.output_level == Level::Minute), "{open:?}");
        // Few L0s in a sealed hour: H as before.
        let live = l0s(H, 3, now - policy.sealed_remerge_debounce_ms);
        assert_eq!(plan_merges_with(&live, now, &policy, true), plan_merges_with(&live, now, &policy, false));
    }

    /// An over-cap quiet hour becomes cap-sized `h` parts in one rewrite,
    /// and the result is final (nothing is re-planned).
    #[test]
    fn over_cap_quiet_hour_converges_in_one_rewrite() {
        let policy = MergePolicy::default();
        let now = hour_ms(H + 3);
        let mut live = l0s(H, 40, now - policy.sealed_remerge_debounce_ms);
        live.iter_mut().for_each(|p| p.data_bytes = 200_000_000);
        let planned = plan_merges(&live, now, &policy);
        assert!(planned.len() >= 2 && planned.iter().all(|m| m.output_level == Level::Hour), "{planned:?}");
        assert!(planned.iter().all(|m| estimated_part_bytes(&m.inputs) <= INTERIM_MAX_PART_BYTES));
        let merged = planned.iter().map(|m| m.inputs.len()).sum::<usize>();
        assert!(merged >= 39, "every L0 but at most a lone tail is merged: {merged}");
        apply(&mut live, &planned, now);
        assert!(plan_merges(&live, now + 60_000, &policy).is_empty(), "cap-sized h parts are final");
        assert!(live.len() <= planned.len() + 1);
    }

    /// Several backfilled hours each plan their own direct `h` merge, so the
    /// history lanes can run them side by side (`merge_lanes`).
    #[test]
    fn backlog_hours_each_plan_a_direct_hour_merge() {
        let policy = MergePolicy::default();
        let now = hour_ms(H + 6);
        let live = [l0s(H, 30, now - 600_000), l0s(H + 1, 30, now - 400_000)].concat();
        let planned = plan_merges(&live, now, &policy);
        assert_eq!(planned.iter().map(|m| (m.output_level, m.event_hour, m.inputs.len())).collect::<Vec<_>>(),
            vec![(Level::Hour, H, 30), (Level::Hour, H + 1, 30)]);
    }

    /// NAN-3701: a lone L0 is not overdue until its hour merge is due.
    #[test]
    fn l0_merge_overdue_waits_for_the_policy_deadline() {
        let policy = MergePolicy::default();
        let end = hour_ms(H + 1);
        // A straggler for hour H landing just after the hour's last minute merge (cell-us-1 xx:06, tenant-a 15:15 EDT).
        let straggler = vec![part(Level::Minute, H, end - 60_000), part(Level::L0, H, end + 24_000)];
        assert_eq!(l0_merge_overdue_ms(&straggler, end + 9 * 60_000, &policy), 0, "unsealed: nothing is due");
        assert_eq!(l0_merge_overdue_ms(&straggler, end + policy.hour_seal_ms + 30_000, &policy), 30_000);
        // tenant-a 2026-10-12: due at the 19:10 seal, hour merge committed 19:18:16 = 8 min 16 s overdue, raw age 924 s.
        let tenant_a = l0_merge_overdue_ms(&straggler, end + 18 * 60_000 + 16_000, &policy);
        assert_eq!(tenant_a, 8 * 60_000 + 16_000);
        // A low-rate tenant's only L0 of the hour, 40 min before the seal: raw age 25 min, not due.
        let quiet = vec![part(Level::L0, H, hour_ms(H) + 20 * 60_000)];
        assert_eq!(l0_merge_overdue_ms(&quiet, hour_ms(H) + 45 * 60_000, &policy), 0);
        // A late lone L0 for a long-sealed hour is due after the debounce.
        let late = vec![part(Level::Hour, H, 1), part(Level::L0, H, hour_ms(H + 5))];
        assert_eq!(l0_merge_overdue_ms(&late, hour_ms(H + 5) + policy.sealed_remerge_debounce_ms - 1, &policy), 0);
        assert_eq!(l0_merge_overdue_ms(&late, hour_ms(H + 5) + policy.sealed_remerge_debounce_ms + 7_000, &policy), 7_000);
    }

    /// NAN-3701: with two or more L0s the minute merge is due at once; a stall grows linearly.
    #[test]
    fn l0_merge_overdue_counts_from_the_minute_merge_deadline() {
        let policy = MergePolicy::default();
        let t = hour_ms(H) + 10 * 60_000;
        // One L0 per pull poll, 5 min apart (cell-us-1 overnight): due when the second lands.
        let polls = vec![part(Level::L0, H, t), part(Level::L0, H, t + 5 * 60_000)];
        assert_eq!(l0_merge_overdue_ms(&polls, t + 5 * 60_000 + 20_000, &policy), 20_000, "raw age 320 s, 20 s overdue");
        // Busy hour, merge loop stuck: overdue from oldest + minute_max_l0_age_ms.
        let busy = (0..6).map(|i| part(Level::L0, H, t + i * 10_000)).collect::<Vec<_>>();
        assert_eq!(l0_merge_overdue_ms(&busy, t + 20 * 60_000, &policy), 20 * 60_000 - policy.minute_max_l0_age_ms);
        // Twelve L0s are due at the twelfth's arrival, before the age bound.
        let burst = (0..12).map(|i| part(Level::L0, H, t + i * 1_000)).collect::<Vec<_>>();
        assert_eq!(l0_merge_overdue_ms(&burst, t + 31_000, &policy), 20_000);
        // Adopted (unsorted h/d) parts are final, not L0; no L0 at all is 0.
        let mut adopted = part(Level::Hour, H, t);
        adopted.sorted = false;
        assert_eq!(l0_merge_overdue_ms(&[adopted], t + 3_600_000, &policy), 0);
        assert_eq!(l0_merge_overdue_ms(&[part(Level::Minute, H, t)], t + 3_600_000, &policy), 0);
    }

    /// NAN-3701: an unsorted L0 can never merge (merge.rs refuses it). It must
    /// not hide: it is due `hour_seal_ms` after arrival, so one stuck for 2 h is
    /// 110 min overdue (past the 60 min page), even beside healthy sorted parts.
    #[test]
    fn l0_merge_overdue_counts_an_unsorted_l0_that_can_never_merge() {
        let policy = MergePolicy::default();
        let t = hour_ms(H) + 10 * 60_000;
        let mut stuck = part(Level::L0, H, t);
        stuck.sorted = false;
        assert!(plan_merges(std::slice::from_ref(&stuck), t + 7_200_000, &policy).is_empty(), "never a merge input");
        assert_eq!(l0_merge_overdue_ms(std::slice::from_ref(&stuck), t + policy.hour_seal_ms, &policy), 0);
        let live = vec![stuck, part(Level::Hour, H - 1, 1), part(Level::L0, H + 1, t + 7_190_000)];
        let overdue = l0_merge_overdue_ms(&live, t + 7_200_000, &policy);
        assert_eq!(overdue, 7_200_000 - policy.hour_seal_ms);
        assert!(overdue >= 60 * 60_000, "pages at the lake-cell l0_merge_overdue page threshold (60 min)");
    }

    /// NAN-3701: the deadline agrees with the planner: overdue => a planned merge takes the L0.
    #[test]
    fn l0_merge_overdue_matches_plan_merges() {
        let policy = MergePolicy::default();
        let end = hour_ms(H + 1);
        let t = hour_ms(H) + 10 * 60_000;
        let cases: Vec<Vec<PartRef>> = vec![
            vec![part(Level::Minute, H, end - 60_000), part(Level::L0, H, end + 24_000)],
            vec![part(Level::L0, H, hour_ms(H) + 20 * 60_000)],
            vec![part(Level::Hour, H, 1), part(Level::L0, H, hour_ms(H + 5))],
            vec![part(Level::L0, H, t), part(Level::L0, H, t + 5 * 60_000)],
            (0..12).map(|i| part(Level::L0, H, t + i * 1_000)).collect(),
        ];
        let takes_l0 = |live: &[PartRef], now| plan_merges(live, now, &policy).iter().any(|m| m.inputs.iter().any(|p| p.level == Level::L0));
        for (i, live) in cases.iter().enumerate() {
            // The first instant (1 s steps) the planner takes an L0 is exactly its due time:
            // not overdue there, overdue by the elapsed time after it.
            let mut now = live.iter().map(|p| p.part_id.created_unix_ms()).max().unwrap();
            while !takes_l0(live, now) {
                assert_eq!(l0_merge_overdue_ms(live, now, &policy), 0, "case {i}: overdue at {now} before any merge takes the L0");
                now += 1_000;
            }
            assert_eq!(l0_merge_overdue_ms(live, now, &policy), 0, "case {i}: due later than the planner at {now}");
            assert_eq!(l0_merge_overdue_ms(live, now + 1_000, &policy), 1_000, "case {i}: due earlier than the planner at {now}");
        }
    }
}
