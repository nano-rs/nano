// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4755: a merge that kills ingest[T] must not restart-loop it.
//!
//! FP cell-us-1, 2026-10-28: after a one-hour ingest stall, the ops tenant's
//! sealed-hour `h` merge of the stall hour (33 inputs, ~100k rows) pushed the
//! ingest role past its 3.4 GB `memory.max` 20-40 s after every start. The
//! kernel SIGKILLed the process, the supervisor restarted it, and the new
//! process planned the very same merge: the merge quarantine lives in memory
//! and only records an `Err`, so a kill left no trace. Six restarts in 15 min,
//! and the backlog behind them never drained.
//!
//! This ledger (`merge-attempts.json` in the work dir, rename + fsync, like
//! [`super::admission_attempts`]) records every merge right before it starts
//! and retains its failed/split decisions while that hour stays live. A
//! process that finds an entry still marked in flight knows the previous
//! one died during that merge, and:
//!
//! - **shrinks it**: the next attempt runs one shape step smaller (half the
//!   decode window, half the open readers / class runs; see
//!   [`super::merge::MergeShape`]), down to [`MAX_SHIFT`];
//! - **splits it** when it failed at the smallest shape: the hour then
//!   merges in time-ordered chunks of at most [`Entry::max_inputs`] input
//!   parts, each committed as its own `h` part (durable progress: a chunk
//!   that commits is never redone), halving the chunk per further failure,
//!   down to [`MIN_SPLIT_INPUTS`];
//! - **parks it** when even a minimum chunk failed at the smallest shape:
//!   the merge waits [`PARK_BASE_MS`] while ingest keeps admitting, then
//!   gets one more attempt; after [`MAX_MIN_FAILURES`] failures it is
//!   **left unmerged**: never
//!   started again (until the role's `memory.max` grows), its parts live
//!   and readable, counted in `merges_left_unmerged`. Every path ends in a
//!   bounded number of attempts: catch-up converges, or the hour stays as it
//!   is and ingest goes on. An unmerged hour costs query fan-out, never data.
//!
//! The in-process memory guard ([`super::merge_quota::MemoryPressure`]) ends
//! a merge with an error before the kernel kills the process; the scheduler
//! records that through [`MergeAttempts::shrink`] too, so a guarded merge
//! shrinks without a restart at all. A split merge keeps its entry after a
//! commit so that its finished chunks remain final across restarts.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

const FILE: &str = "merge-attempts.json";
/// Smallest shape: 1/8 of the decode window, 2 open readers (see
/// [`super::merge::MergeShape::for_shift`]).
pub const MAX_SHIFT: u8 = 3;
/// First park after a death at the smallest shape.
pub const PARK_BASE_MS: i64 = 15 * 60_000;
/// Longest park.
pub const PARK_MAX_MS: i64 = 4 * 3_600_000;
/// Fewest input parts a split chunk merges (a merge needs two).
pub const MIN_SPLIT_INPUTS: u32 = 2;
/// Failures of a minimum chunk at the smallest shape before it is left
/// unmerged (one parked retry).
pub const MAX_MIN_FAILURES: u32 = 2;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Shape step the next attempt runs at (0 = full size).
    pub shift: u8,
    /// Attempts that ended in a kill or a memory-guard abort.
    pub failures: u32,
    /// Minimum-shape failures so far (the first parks; the second stops).
    pub parks: u32,
    /// Wall-clock ms before which the merge does not start again.
    pub parked_until_ms: i64,
    /// Started by a process and not ended by it.
    pub in_flight: bool,
    /// Input parts of the attempt in flight (or the last one).
    #[serde(default)]
    pub begun_inputs: u32,
    /// Split: the hour merges in chunks of at most this many input parts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_inputs: Option<u32>,
    /// Left unmerged at this `memory.max` (bytes; 0 when unknown): not
    /// started again unless the limit grows past it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_unmerged_at_limit: Option<u64>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Stored {
    merges: BTreeMap<String, Entry>,
    /// Recovery spans two files. Keep the forgiveness request until the
    /// admission ledger has durably removed the old process's charges.
    #[serde(default)]
    forgive_admission: bool,
}

/// What [`MergeAttempts::shrink`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shrunk {
    /// The next attempt runs at this shape step.
    Shift(u8),
    /// Split: chunks of at most this many input parts from now on.
    Split(u32),
    /// Parked until this wall-clock ms.
    Parked(i64),
    /// Never started again (until `memory.max` grows); its parts stay live.
    LeftUnmerged,
}

/// The durable merge-attempt ledger in ingest[T]'s work dir.
#[derive(Debug)]
pub struct MergeAttempts {
    path: PathBuf,
    stored: Stored,
    /// An unreadable ledger must never be replaced with an empty one: it
    /// may hold permanent split/left-unmerged decisions. Admission can run,
    /// but compaction waits until a later open can read the ledger.
    readable: bool,
}

/// The ledger's identity of a merge: its level code and event hour (the
/// scheduler's quarantine key).
pub fn merge_id(level: &str, hour: i32) -> String {
    format!("{level}:{hour}")
}

impl MergeAttempts {
    /// Open (or start) the ledger at `now_ms`. Every entry a previous process
    /// left in flight is a merge it died during: it is shrunk (or parked)
    /// here, durably, before anything can start it again. An unreadable file
    /// defers compaction without interrupting admission or losing policy.
    pub fn open(work_dir: &Path, now_ms: i64) -> Self {
        let path = work_dir.join(FILE);
        let (stored, readable) = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(stored) => (stored, true),
                Err(error) => {
                    tracing::warn!(error = %error, "merge attempt ledger unreadable; compaction deferred");
                    (Stored::default(), false)
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (Stored::default(), true),
            Err(error) => {
                tracing::warn!(error = %error, "merge attempt ledger unreadable; compaction deferred");
                (Stored::default(), false)
            }
        };
        let mut ledger = Self { path, stored, readable };
        let died = ledger.stored.merges.iter().filter(|(_, entry)| entry.in_flight).map(|(id, _)| id.clone()).collect::<Vec<_>>();
        let limit = super::merge_quota::memory_limit();
        for id in &died {
            let outcome = ledger.apply_failure(id, now_ms, None, limit);
            tracing::warn!(merge = %id, outcome = ?outcome,
                "ingest restarted after dying during a merge; the merge runs smaller (or waits) instead of the same size again");
        }
        if !died.is_empty() {
            ledger.stored.forgive_admission = true;
            if let Err(error) = ledger.persist() {
                tracing::warn!(error = %format!("{error:#}"), "merge attempt ledger not persisted");
            }
        }
        ledger
    }

    /// Did the previous process die with a merge in flight? Its death cannot
    /// then be attributed to the object it was admitting (NAN-4755).
    pub fn died_during_merge(&self) -> bool {
        self.stored.forgive_admission
    }

    /// Call only after admission forgiveness has been durably written. A
    /// crash before this acknowledgement repeats an idempotent forgiveness.
    pub fn admission_forgiven(&mut self) -> Result<()> {
        self.stored.forgive_admission = false;
        self.persist()
    }

    /// The shape step the next attempt of `id` runs at.
    pub fn shift(&self, id: &str) -> u8 {
        self.stored.merges.get(id).map_or(0, |entry| entry.shift)
    }

    /// Wall-clock ms until which `id` waits, if it is parked at `now_ms`.
    pub fn parked_until(&self, id: &str, now_ms: i64) -> Option<i64> {
        self.stored.merges.get(id).map(|entry| entry.parked_until_ms).filter(|until| *until > now_ms)
    }

    /// Most input parts one merge of `id` may take (split), if capped.
    pub fn max_inputs(&self, id: &str) -> Option<usize> {
        self.stored.merges.get(id).and_then(|entry| entry.max_inputs).map(|n| n as usize)
    }

    /// Was `id` left unmerged (never started again at this limit)?
    pub fn left_unmerged(&self, id: &str) -> bool {
        self.stored.merges.get(id).is_some_and(|entry| entry.left_unmerged_at_limit.is_some())
    }

    /// Merges left unmerged (the `merges_left_unmerged` gauge).
    pub fn left_unmerged_count(&self) -> usize {
        self.stored.merges.values().filter(|entry| entry.left_unmerged_at_limit.is_some()).count()
    }

    /// The role's `memory.max` is now `limit`: a merge left unmerged at a
    /// smaller one gets its chance again (one more bounded ladder per
    /// growth: the chunk size and shape it reached are kept).
    pub fn rearm_if_limit_grew(&mut self, limit: Option<u64>) -> Result<usize> {
        let Some(limit) = limit else { return Ok(0) };
        let mut rearmed = 0;
        for entry in self.stored.merges.values_mut() {
            if entry.left_unmerged_at_limit.is_some_and(|at| at > 0 && limit > at) {
                entry.left_unmerged_at_limit = None;
                entry.parks = 0;
                entry.parked_until_ms = 0;
                rearmed += 1;
            }
        }
        if rearmed > 0 {
            self.persist()?;
        }
        Ok(rearmed)
    }

    /// Permanent decisions belong to live data. Once retention (or a day
    /// merge) removes the last part of that hour, forget its policy and
    /// gauge contribution. Never prune an attempt still running.
    pub fn retain_live_hours(&mut self, live: &BTreeSet<i32>) -> Result<()> {
        let before = self.stored.merges.len();
        self.stored.merges.retain(|id, entry| {
            if entry.in_flight { return true; }
            let Some((level, hour)) = id.split_once(':') else { return true; };
            let Ok(hour) = hour.parse::<i32>() else { return true; };
            if level == "d" {
                live.range(hour..=hour.saturating_add(23)).next().is_some()
            } else {
                live.contains(&hour)
            }
        });
        if self.stored.merges.len() != before { self.persist()?; }
        Ok(())
    }

    pub fn entry(&self, id: &str) -> Option<&Entry> {
        self.stored.merges.get(id)
    }

    /// Record proactive shape/split floors without inventing a failed or
    /// in-flight attempt. Committed chunks retain this cap across restarts.
    pub fn plan_at_least(&mut self, id: &str, shift: u8, max_inputs: Option<usize>) -> Result<()> {
        anyhow::ensure!(self.readable, "merge attempt ledger unreadable; compaction deferred");
        anyhow::ensure!(!self.left_unmerged(id), "merge left unmerged until memory.max grows");
        if self.entry(id).is_some_and(|entry| entry.in_flight) {
            return Ok(());
        }
        let previous = self.entry(id).cloned();
        let before = previous.clone().unwrap_or_default();
        let mut planned = before.clone();
        planned.shift = planned.shift.max(shift.min(MAX_SHIFT));
        if let Some(cap) = max_inputs {
            let cap = u32::try_from(cap).unwrap_or(u32::MAX).max(MIN_SPLIT_INPUTS);
            planned.max_inputs = Some(planned.max_inputs.map_or(cap, |old| old.min(cap)));
        }
        if planned != before {
            self.stored.merges.insert(id.to_owned(), planned);
            if let Err(error) = self.persist() {
                // A later planning pass must retry the write, rather than
                // treating an unrecorded in-memory choice as durable.
                match previous {
                    Some(entry) => { self.stored.merges.insert(id.to_owned(), entry); }
                    None => { self.stored.merges.remove(id); }
                }
                return Err(error);
            }
        }
        Ok(())
    }

    /// Record, durably, that `id` starts now with `inputs` input parts (0:
    /// a merge that cannot be split, a day merge); returns its shape step.
    pub fn begin(&mut self, id: &str, inputs: usize) -> Result<u8> {
        self.begin_at_least(id, inputs, 0)
    }

    /// Persist the selected starting shape before launching compute. Keep
    /// any smaller shape recovered from an earlier failed attempt, so a
    /// restart or a new estimate cannot undo the bounded retry ladder.
    pub fn begin_at_least(&mut self, id: &str, inputs: usize, shift: u8) -> Result<u8> {
        anyhow::ensure!(self.readable, "merge attempt ledger unreadable; compaction deferred");
        anyhow::ensure!(!self.left_unmerged(id), "merge left unmerged until memory.max grows");
        // Every live hour keeps its progress, including the steps before
        // splitting. Evicting even an idle, partially shrunk attempt can
        // restart its ladder forever on a large catch-up. The scheduler
        // prunes entries only after their hour has no live data.
        let entry = self.stored.merges.entry(id.to_string()).or_default();
        entry.shift = entry.shift.max(shift.min(MAX_SHIFT));
        entry.in_flight = true;
        entry.begun_inputs = u32::try_from(inputs).unwrap_or(u32::MAX);
        let shift = entry.shift;
        self.persist()?;
        Ok(shift)
    }

    /// `id` committed: forget it (its next merge starts at full size). A
    /// split hour keeps its chunk size and shape: the next chunk of the same
    /// hour must not start at full size and redo the climb (or re-merge the
    /// committed chunks into one part that does not fit).
    pub fn committed(&mut self, id: &str) -> Result<()> {
        match self.stored.merges.get_mut(id) {
            None => return Ok(()),
            Some(entry) if entry.max_inputs.is_some() => {
                entry.in_flight = false;
                entry.parks = 0;
                entry.parked_until_ms = 0;
            }
            Some(_) => {
                self.stored.merges.remove(id);
            }
        }
        self.persist()
    }

    /// `id` ended with an error that is not about memory: it is no longer in
    /// flight (the scheduler's quarantine backs it off); its shape stays.
    pub fn ended(&mut self, id: &str) -> Result<()> {
        let Some(entry) = self.stored.merges.get_mut(id) else { return Ok(()) };
        if entry.shift == 0 && entry.parks == 0 && entry.failures == 0 {
            self.stored.merges.remove(id);
        } else {
            entry.in_flight = false;
        }
        self.persist()
    }

    /// `id` ran out of memory (the guard ended it, or the process died
    /// during it) with `inputs` input parts (0: cannot be split): run it one
    /// shape step smaller; at the smallest, split it into half-size chunks;
    /// at a minimum chunk, park it, then leave it unmerged.
    pub fn shrink(&mut self, id: &str, now_ms: i64, inputs: usize) -> Result<Shrunk> {
        let outcome = self.apply_failure(id, now_ms, Some(inputs), super::merge_quota::memory_limit());
        self.persist()?;
        Ok(outcome)
    }

    fn apply_failure(&mut self, id: &str, now_ms: i64, inputs: Option<usize>, limit: Option<u64>) -> Shrunk {
        let entry = self.stored.merges.entry(id.to_string()).or_default();
        entry.in_flight = false;
        entry.failures = entry.failures.saturating_add(1);
        if entry.shift < MAX_SHIFT {
            entry.shift += 1;
            return Shrunk::Shift(entry.shift);
        }
        let inputs = inputs.map_or(entry.begun_inputs, |n| u32::try_from(n).unwrap_or(u32::MAX));
        if inputs > MIN_SPLIT_INPUTS {
            // Half the failed attempt's inputs (a chunk of a split hour is
            // already at most the cap): strictly smaller every time.
            let chunk = (inputs / 2).max(MIN_SPLIT_INPUTS);
            entry.max_inputs = Some(chunk);
            entry.parks = 0;
            entry.parked_until_ms = 0;
            return Shrunk::Split(chunk);
        }
        entry.parks = entry.parks.saturating_add(1);
        if entry.parks >= MAX_MIN_FAILURES {
            entry.left_unmerged_at_limit = Some(limit.unwrap_or(0));
            entry.parked_until_ms = 0;
            return Shrunk::LeftUnmerged;
        }
        let backoff = PARK_BASE_MS.saturating_mul(1_i64 << (entry.parks - 1).min(16)).min(PARK_MAX_MS);
        entry.parked_until_ms = now_ms.saturating_add(backoff);
        Shrunk::Parked(entry.parked_until_ms)
    }

    fn persist(&self) -> Result<()> {
        anyhow::ensure!(self.readable, "merge attempt ledger unreadable; compaction deferred");
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(&self.stored)?;
        {
            let mut file = std::fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path).with_context(|| format!("rename {}", self.path.display()))?;
        let dir = self.path.parent().context("merge ledger has no directory")?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;

    #[test]
    fn proactive_split_survives_reopen_and_commit_without_charging_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let id = merge_id("h", 7);
        let mut ledger = MergeAttempts::open(dir.path(), NOW);
        ledger.plan_at_least(&id, MAX_SHIFT, Some(13)).unwrap();
        drop(ledger);
        let mut ledger = MergeAttempts::open(dir.path(), NOW + 1);
        let entry = ledger.entry(&id).unwrap();
        assert_eq!((entry.shift, entry.max_inputs, entry.failures, entry.in_flight), (MAX_SHIFT, Some(13), 0, false));
        assert!(!ledger.died_during_merge());
        ledger.begin(&id, 13).unwrap();
        let running = ledger.entry(&id).cloned();
        ledger.plan_at_least(&id, MAX_SHIFT, Some(2)).unwrap();
        assert_eq!(ledger.entry(&id), running.as_ref(), "planning cannot rewrite an active attempt's recorded shape");
        ledger.committed(&id).unwrap();
        ledger.plan_at_least(&id, 0, Some(26)).unwrap();
        assert_eq!(ledger.max_inputs(&id), Some(13), "never expand a committed split");
        assert_eq!(ledger.shift(&id), MAX_SHIFT);
        ledger.plan_at_least(&id, MAX_SHIFT, Some(0)).unwrap();
        assert_eq!(ledger.max_inputs(&id), Some(2), "the minimum is two inputs");
    }

    #[test]
    fn a_killed_proactive_chunk_recovers_from_its_actual_fan_in() {
        let dir = tempfile::tempdir().unwrap();
        let id = merge_id("h", 7);
        let mut ledger = MergeAttempts::open(dir.path(), NOW);
        ledger.plan_at_least(&id, MAX_SHIFT, Some(13)).unwrap();
        ledger.begin(&id, 13).unwrap();
        drop(ledger); // SIGKILL before ending or committing the chunk.
        let mut ledger = MergeAttempts::open(dir.path(), NOW + 1);
        assert!(ledger.died_during_merge());
        let entry = ledger.entry(&id).unwrap();
        assert_eq!((entry.shift, entry.max_inputs, entry.failures, entry.in_flight),
            (MAX_SHIFT, Some(6), 1, false));
        ledger.admission_forgiven().unwrap();
        ledger.begin(&id, 6).unwrap();
        ledger.committed(&id).unwrap();
        drop(ledger);
        let reopened = MergeAttempts::open(dir.path(), NOW + 2);
        assert!(!reopened.died_during_merge());
        assert_eq!(reopened.max_inputs(&id), Some(6));
    }

    #[test]
    fn selected_shape_is_durable_and_recovery_shrinks_from_the_shape_that_ran() {
        let dir = tempfile::tempdir().unwrap();
        let id = merge_id("h", 7);
        let mut ledger = MergeAttempts::open(dir.path(), NOW);
        assert_eq!(ledger.begin_at_least(&id, 164, 2).unwrap(), 2);
        assert_eq!(ledger.entry(&id).unwrap().failures, 0, "planning is not a failed attempt");
        drop(ledger);
        let mut ledger = MergeAttempts::open(dir.path(), NOW + 1);
        assert_eq!(ledger.shift(&id), 3, "a killed shift-2 attempt recovers at shift 3");
        assert_eq!(ledger.begin_at_least(&id, 164, 0).unwrap(), 3, "never undo recovery");
        ledger.committed(&id).unwrap();
        assert!(ledger.entry(&id).is_none());
        assert_eq!(ledger.begin_at_least(&id, 164, u8::MAX).unwrap(), MAX_SHIFT);
    }

    /// The incident: every restart planned the same merge at the same size.
    /// Each death now shrinks it; a death at the smallest shape parks it
    /// with a doubling, capped backoff; a commit clears it.
    #[test]
    fn a_merge_that_kills_the_process_shrinks_then_parks_and_a_commit_clears_it() {
        let dir = tempfile::tempdir().unwrap();
        let id = merge_id("h", 498_105);
        let mut shifts = Vec::new();
        for _ in 0..=MAX_SHIFT {
            let mut ledger = MergeAttempts::open(dir.path(), NOW);
            shifts.push(ledger.begin(&id, 0).unwrap());
            // SIGKILL: nothing ends the entry.
        }
        assert_eq!(shifts, vec![0, 1, 2, 3], "one step smaller per death");
        let mut ledger = MergeAttempts::open(dir.path(), NOW);
        assert!(ledger.died_during_merge());
        ledger.admission_forgiven().unwrap();
        assert_eq!(ledger.parked_until(&id, NOW), Some(NOW + PARK_BASE_MS), "died at the smallest shape: parked");
        assert_eq!(ledger.parked_until(&id, NOW + PARK_BASE_MS), None, "then one more attempt");
        assert_eq!(ledger.shift(&id), MAX_SHIFT, "still at the smallest shape");
        drop(ledger);
        let mut ledger = MergeAttempts::open(dir.path(), NOW + PARK_BASE_MS);
        assert!(!ledger.died_during_merge(), "nothing was in flight");
        ledger.begin(&id, 0).unwrap();
        let mut ledger = MergeAttempts::open(dir.path(), NOW + PARK_BASE_MS);
        assert!(ledger.left_unmerged(&id), "a second minimum-shape failure is left unmerged");
        ledger.admission_forgiven().unwrap();
        drop(ledger);
        let mut ledger = MergeAttempts::open(dir.path(), NOW + 3 * PARK_BASE_MS);
        assert!(ledger.begin(&id, 0).is_err(), "a stopped merge cannot be launched through another planner");
        let id = merge_id("h", 498_106);
        ledger.begin(&id, 0).unwrap();
        ledger.committed(&id).unwrap();
        let ledger = MergeAttempts::open(dir.path(), NOW + 3 * PARK_BASE_MS);
        assert_eq!((ledger.shift(&id), ledger.entry(&id)), (0, None), "a commit clears the merge");
        assert!(!ledger.died_during_merge());
    }

    /// A guard abort shrinks in-process (no restart); an unrelated error
    /// ends the attempt without shrinking; parks are capped.
    #[test]
    fn guard_aborts_shrink_in_process_and_other_errors_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let id = merge_id("m", 7);
        let mut ledger = MergeAttempts::open(dir.path(), NOW);
        assert_eq!(ledger.begin(&id, 0).unwrap(), 0);
        ledger.ended(&id).unwrap();
        assert_eq!(ledger.entry(&id), None, "a plain failure at full size leaves nothing");
        assert_eq!(ledger.begin(&id, 0).unwrap(), 0);
        assert_eq!(ledger.shrink(&id, NOW, 0).unwrap(), Shrunk::Shift(1));
        assert_eq!(ledger.begin(&id, 0).unwrap(), 1);
        ledger.ended(&id).unwrap();
        assert_eq!(ledger.shift(&id), 1, "an unrelated error keeps the shape");
        let reopened = MergeAttempts::open(dir.path(), NOW);
        assert!(!reopened.died_during_merge(), "ended attempts are not deaths");
        assert_eq!(reopened.shift(&id), 1);
        let mut ledger = reopened;
        let outcomes = (0..40).map(|_| ledger.shrink(&id, NOW, 0).unwrap()).collect::<Vec<_>>();
        assert_eq!(&outcomes[..3], &[Shrunk::Shift(2), Shrunk::Shift(3), Shrunk::Parked(NOW + PARK_BASE_MS)],
            "an unsplittable merge parks at the smallest shape");
        assert!(outcomes[3..].iter().all(|outcome| *outcome == Shrunk::LeftUnmerged), "then it is left unmerged: no retry loop");
        assert!(ledger.left_unmerged(&id));
        assert_eq!(ledger.left_unmerged_count(), 1);
    }

    /// NAN-4755 convergence: past the smallest shape the hour splits into
    /// ever smaller chunks (each committed chunk is durable progress and
    /// keeps the split), then a minimum chunk fails twice and is left
    /// unmerged: a bounded number of attempts in every case, across
    /// restarts. A grown `memory.max` re-arms it once.
    #[test]
    fn past_the_smallest_shape_an_hour_splits_then_is_left_unmerged_in_bounded_attempts() {
        let dir = tempfile::tempdir().unwrap();
        let id = merge_id("h", 498_107);
        let mut ledger = MergeAttempts::open(dir.path(), NOW);
        let mut outcomes = Vec::new();
        let mut inputs = 33;
        for attempt in 0..64 {
            if ledger.left_unmerged(&id) { break; }
            ledger.begin(&id, inputs).unwrap();
            if attempt % 2 == 1 {
                // A SIGKILL instead of a guard stop: the reopen records it.
                ledger = MergeAttempts::open(dir.path(), NOW);
                outcomes.push(None);
            } else {
                outcomes.push(Some(ledger.shrink(&id, NOW, inputs).unwrap()));
            }
            inputs = ledger.max_inputs(&id).unwrap_or(inputs);
        }
        let entry = ledger.entry(&id).unwrap().clone();
        assert!(entry.left_unmerged_at_limit.is_some(), "{outcomes:?}");
        // 3 shape steps, 33 -> 16 -> 8 -> 4 -> 2 inputs, 2 failures.
        assert_eq!(entry.failures, 3 + 4 + 2, "{outcomes:?}");
        assert_eq!(entry.max_inputs, Some(MIN_SPLIT_INPUTS));
        let reopened = MergeAttempts::open(dir.path(), NOW + PARK_MAX_MS * 10);
        assert!(reopened.left_unmerged(&id), "durable across restarts: never started again");

        // A chunk that commits keeps the split (no climb back to full size).
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = MergeAttempts::open(dir.path(), NOW);
        for _ in 0..MAX_SHIFT { ledger.shrink(&id, NOW, 24).unwrap(); }
        assert_eq!(ledger.shrink(&id, NOW, 24).unwrap(), Shrunk::Split(12));
        ledger.begin(&id, 12).unwrap();
        ledger.committed(&id).unwrap();
        let ledger = MergeAttempts::open(dir.path(), NOW);
        assert_eq!((ledger.shift(&id), ledger.max_inputs(&id)), (MAX_SHIFT, Some(12)));
        assert!(!ledger.died_during_merge());

        // memory.max grew: one more bounded ladder from where it was.
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = MergeAttempts::open(dir.path(), NOW);
        ledger.stored.merges.insert(id.clone(), Entry { shift: MAX_SHIFT, max_inputs: Some(2), parks: 3,
            left_unmerged_at_limit: Some(1 << 30), ..Entry::default() });
        assert_eq!(ledger.rearm_if_limit_grew(Some(1 << 30)).unwrap(), 0, "same limit: stays left");
        assert_eq!(ledger.rearm_if_limit_grew(Some(2 << 30)).unwrap(), 1);
        assert!(!ledger.left_unmerged(&id));
        assert_eq!(ledger.max_inputs(&id), Some(2));
    }

    #[test]
    fn ledger_pressure_keeps_shrink_split_and_left_unmerged_policy_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = MergeAttempts::open(dir.path(), NOW);
        // Above the former 256-entry limit: no stage of the ladder may
        // be forgotten merely because other live hours are being merged.
        const HOURS: usize = 300;
        for hour in 0..HOURS as i32 {
            ledger.stored.merges.insert(merge_id("h", hour), Entry {
                shift: if hour % 3 == 0 { 2 } else { MAX_SHIFT },
                failures: 2,
                max_inputs: (hour % 3 != 0).then_some(2),
                left_unmerged_at_limit: (hour % 3 == 2).then_some(1 << 30),
                ..Entry::default()
            });
        }
        for hour in HOURS as i32..HOURS as i32 + 8 {
            let id = merge_id("h", hour);
            ledger.begin(&id, 12).unwrap();
            ledger.committed(&id).unwrap();
        }
        let mut reopened = MergeAttempts::open(dir.path(), NOW);
        assert_eq!(reopened.left_unmerged_count(), HOURS / 3);
        for hour in 0..HOURS as i32 {
            let id = merge_id("h", hour);
            assert_eq!(reopened.max_inputs(&id), (hour % 3 != 0).then_some(2));
            assert_eq!(reopened.shift(&id), if hour % 3 == 0 { 2 } else { MAX_SHIFT });
        }
        assert_eq!(reopened.rearm_if_limit_grew(Some(1 << 30)).unwrap(), 0);
        assert_eq!(reopened.rearm_if_limit_grew(Some(2 << 30)).unwrap(), HOURS / 3);
        assert_eq!(reopened.rearm_if_limit_grew(Some(2 << 30)).unwrap(), 0);
        reopened.retain_live_hours(&BTreeSet::from([1])).unwrap();
        let reopened = MergeAttempts::open(dir.path(), NOW);
        assert_eq!(reopened.stored.merges.len(), 1, "only live hours retain their policy");
        assert_eq!(reopened.max_inputs(&merge_id("h", 1)), Some(2));
    }

    #[test]
    fn an_unreadable_ledger_is_preserved_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE);
        let broken = b"{unreadable";
        std::fs::write(&path, broken).unwrap();
        let mut ledger = MergeAttempts::open(dir.path(), NOW);
        assert!(ledger.begin(&merge_id("h", 1), 2).is_err());
        assert_eq!(std::fs::read(path).unwrap(), broken);
    }
}
