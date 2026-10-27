// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4319: a source object that kills ingest[T] (an OOM SIGKILL, an
//! abort) must not wedge the tenant.
//!
//! An error return is already bounded (the object is refused whole and
//! quarantined). A crash is not: the process dies before any refusal, the
//! supervisor restarts it, the edge log hands the same segment out again and
//! it dies again, forever, with every later segment queued behind it (a
//! 50k-row landing segment OOM-killed a 1.2 GB ingest role every 60 s).
//!
//! So ingest[T] records, durably and right BEFORE it admits, every object it
//! admits (`admission-attempts.json` in its work dir, written with rename +
//! fsync; an object left pending is never counted). An entry is dropped once
//! the object is no longer pending (its flush committed and the source
//! acknowledged it). An entry a new process finds at open therefore means a
//! process died with the object admitted and unacknowledged (a suspect):
//!
//! - while any pending object carries such an entry, admission takes one
//!   object at a time from idle (the oldest pending first, so ranges stay
//!   contiguous) and flushes it a tick later, admitting nothing else until
//!   it commits, so the next crash names the culprit;
//! - an object admitted ALONE [`MAX_ADMISSION_CRASHES`] times without being
//!   acknowledged is refused whole (`admission_invalid`, detail
//!   `admission_crashed`), quarantined for an operator replay (NAN-3643),
//!   and acknowledged: the edge log moves past it.
//!
//! NAN-4542: a crash with several objects in flight names none of them: it
//! makes each a suspect (entry, count unchanged) and only admissions of one
//! object from idle are counted. Before, a batch crash charged every object
//! in it, isolation let later suspects join the same flush (4 per flush in
//! the `kill -9` test), and three unrelated restarts refused healthy objects
//! as poison (their rows quarantined, out of the live set).
//!
//! A deploy or node restart that interrupts an admitted object counts once
//! at most; the entry is dropped as soon as that object commits.
//!
//! NAN-4553 (review of NAN-4542):
//!
//! - **Bisection.** Recovery no longer admits every suspect alone (up to
//!   ~512 single-object flushes after one crash with a full buffer). It
//!   admits, from idle, a group of the oldest suspects and flushes it a tick
//!   later: half the suspects left by a crash in normal mode, half the
//!   group a crash interrupted during recovery (its size is written with
//!   the group's admission). A group that commits clears all its
//!   members; one that crashes is halved, so N suspects with one culprit
//!   take ~log2(N) flushes (and crashes) to name it. Only a group of one is
//!   charged.
//! - **Recorded before the fetch.** The first object of an admission from
//!   idle is recorded before its source GET, digest and footer read, so an
//!   object that kills ingest there is charged like one that kills it in
//!   decode (before, it looped forever at count 0).
//! - **Coded exits the object cannot cause are not crashes.** A charge is
//!   undone ([`AdmissionAttempts::uncharge_this_process`]) when ingest exits
//!   on a coded path that is never the object's: fencing, a double consume,
//!   a 401/403 store refusal (credentials), an epoch change, credentials,
//!   enrichment or catalog custody giving up, the writer lease lost, a clean
//!   end. Coded exits the object CAN cause keep it, exactly like a crash:
//!   the 30-minute tick retry window and a 4xx store refusal other than
//!   401/403 (400 BadDigest / InvalidArgument on a part it produced). An
//!   object that fails every tick without crashing is therefore refused
//!   after [`MAX_ADMISSION_CRASHES`] such exits (bounded time, quarantined),
//!   never retried forever at charge 0 (review P1, see
//!   [`super::ingest::exit_keeps_charges`]). A store outage longer than the
//!   window during recovery costs a charge; three are needed to refuse, and
//!   the result is a durable quarantine, not loss. Abnormal ends keep it
//!   too: a SIGKILL (OOM, node), an abort, a panic, a stall-watchdog respawn.
//!
//! What the ledger cannot tell apart cheaply: an OOM kill caused by the
//! object in flight and one caused by other memory in the same process (a
//! merge, the prevalence catch-up, the edge prefetch) at the same moment.
//! The kernel's kill carries no attribution, and the supervisor sees only
//! `cgroup_oom_kill` on the role leaf, which is exactly what a real poison
//! object produces too. Recording the phase (admit / buffered / flush)
//! would cost an fsync per phase and still not separate a merge OOM during
//! the admit phase. What bounds the harm instead: (1) an alone admission is
//! held to the working budget (NAN-4553 row slices), so an object can no
//! longer blow the role limit by itself; (2) an isolated object is exposed
//! for one admit + one flush (a tick, plus R2/owner round trips), not the
//! flush age; (3) refusal needs [`MAX_ADMISSION_CRASHES`] such deaths; and
//! (4) a refused object is quarantined for an operator replay, never lost.
//!
//! NAN-4336: the same ledger isolates an object whose part the writer owner
//! refuses permanently (HTTP 422 `writer_reservation_refused`: control's
//! reserve guard said no, and replaying the same request reaches the same
//! verdict). A flush cannot drop such rows in place (its edge range is issued,
//! its rows are in the dedup window), so ingest exits and restarts like after
//! a crash: every object of the refused flush is a suspect and is admitted
//! and flushed alone. A flush of ONE object refused that way names it
//! ([`AdmissionAttempts::mark_reserve_refused`]); the next process refuses it
//! whole (detail [`RESERVE_REFUSED`]), quarantines it and acknowledges it, so
//! later objects flow instead of retrying it until wall-clock time catches up.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Admissions of one object alone (nothing else admitted and unacknowledged)
/// that ended with the process gone before the object was acknowledged,
/// before it is refused whole.
pub const MAX_ADMISSION_CRASHES: u32 = 3;
/// Value-free detail of the refusal (the reject entry's reason stays
/// `admission_invalid`, which every log reader already accepts).
pub const ADMISSION_CRASHED: &str = "admission_crashed";
/// Most entries kept (pending objects of one ingest are bounded far below).
const MAX_ENTRIES: usize = 4_096;
const FILE: &str = "admission-attempts.json";
/// NAN-4336: value-free detail of an object refused because the writer owner
/// refused its part's reservation permanently (reject reason stays
/// `admission_invalid`).
pub const RESERVE_REFUSED: &str = "reserve_refused";

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Stored {
    /// `key \n version` → admissions alone started without an
    /// acknowledgement (NAN-4542: 0 for an object only ever admitted beside
    /// others: a suspect, not yet charged).
    attempts: BTreeMap<String, u32>,
    /// NAN-4336: objects whose single-object flush the owner refused
    /// permanently; refused whole at the next admission. Absent in a ledger
    /// written before NAN-4336.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    reserve_refused: std::collections::BTreeSet<String>,
    /// NAN-4553: size of the recovery group last admitted (suspects only),
    /// until no suspect is left. A process that finds it halves it. Absent
    /// in a ledger written before NAN-4553 (and outside recovery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    isolate: Option<u32>,
}

/// The durable admission-attempt ledger in ingest[T]'s work dir.
#[derive(Debug)]
pub struct AdmissionAttempts {
    path: PathBuf,
    stored: Stored,
    /// Entries a previous process left (it died with them admitted and
    /// unacknowledged), as read at open, until this process admits them.
    /// Only these are suspects: an object this process admitted (or
    /// deferred) is never one, however long it stays pending.
    suspects: BTreeMap<String, u32>,
    /// NAN-4542: suspects this process has re-admitted (alone), until they
    /// leave the pending set. Admission keeps every other object out of
    /// their flush until it commits, so the next crash counts against the
    /// one object in flight and never against the healthy ones beside it.
    isolating: std::collections::BTreeSet<String>,
    /// NAN-4553: objects this process charged (an admission alone), so a
    /// coded exit can undo the charge.
    charged: std::collections::BTreeSet<String>,
    /// NAN-4553: suspects admitted together during recovery (bisection).
    group_limit: usize,
}

/// The ledger's identity of a source object.
pub fn object_id(key: &str, version: &str) -> String {
    format!("{key}\n{version}")
}

impl AdmissionAttempts {
    /// Open (or start) the ledger. An unreadable file is started over: losing
    /// the counts only delays a refusal, it never refuses good data.
    pub fn open(work_dir: &Path) -> Self {
        let path = work_dir.join(FILE);
        let stored = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|error| {
                tracing::warn!(error = %error, "admission attempt ledger unreadable; starting over");
                Stored::default()
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Stored::default(),
            Err(error) => {
                tracing::warn!(error = %error, "admission attempt ledger unreadable; starting over");
                Stored::default()
            }
        };
        let suspects = stored.attempts.clone();
        let group_limit = match stored.isolate {
            Some(group) => (group as usize).div_ceil(2),
            None => suspects.len().div_ceil(2),
        }
        .max(1);
        Self { path, stored, suspects, isolating: Default::default(), charged: Default::default(), group_limit }
    }

    /// NAN-4553: how many suspects recovery admits together (from idle, in
    /// one flush): half of what the crash interrupted, 1 at the end.
    pub fn group_limit(&self) -> usize {
        self.group_limit
    }

    /// Admissions of `id` that ended with a process gone before its
    /// acknowledgement, when a previous process left it and this one has
    /// not admitted it yet; `None` when it is not a suspect.
    pub fn suspect(&self, id: &str) -> Option<u32> {
        self.suspects.get(id).copied()
    }

    /// NAN-4336: the owner refused this object's own flush permanently.
    pub fn reserve_refused(&self, id: &str) -> bool {
        self.stored.reserve_refused.contains(id)
    }

    /// NAN-4336: record, durably, that the owner refused the flush of this
    /// one object permanently. Only an object this ledger counts (admitted,
    /// unacknowledged) is marked.
    pub fn mark_reserve_refused(&mut self, id: &str) -> Result<()> {
        if self.stored.attempts.contains_key(id) && self.stored.reserve_refused.insert(id.to_string()) {
            self.persist()?;
        }
        Ok(())
    }

    /// Any suspect left by a process that died mid-admission.
    pub fn has_suspects(&self) -> bool {
        !self.suspects.is_empty()
    }

    /// NAN-4542: a suspect this process re-admitted that is still pending
    /// (its flush has not committed and been acknowledged yet).
    pub fn isolating(&self, id: &str) -> bool {
        self.isolating.contains(id)
    }

    /// NAN-4542: any re-admitted suspect still pending.
    pub fn has_isolating(&self) -> bool {
        !self.isolating.is_empty()
    }

    /// No entry at all (nothing admitted and unacknowledged).
    pub fn is_empty(&self) -> bool {
        self.stored.attempts.is_empty()
    }

    /// Drop entries of objects no longer pending (acknowledged). Persists
    /// only when something changed.
    pub fn retain_pending<'a>(&mut self, pending: impl IntoIterator<Item = &'a str>) -> Result<()> {
        if self.stored.attempts.is_empty() {
            return Ok(());
        }
        let pending = pending.into_iter().collect::<std::collections::BTreeSet<_>>();
        let before = self.stored.attempts.len();
        self.stored.attempts.retain(|id, _| pending.contains(id.as_str()));
        self.suspects.retain(|id, _| pending.contains(id.as_str()));
        self.isolating.retain(|id| pending.contains(id.as_str()));
        self.stored.reserve_refused.retain(|id| pending.contains(id.as_str()));
        self.charged.retain(|id| pending.contains(id.as_str()));
        let recovered = self.clear_recovered();
        if self.stored.attempts.len() != before || recovered {
            self.persist()?;
        }
        Ok(())
    }

    /// NAN-4553: recovery is over (no suspect left, none re-admitted and
    /// pending): drop the group size so the next crash starts over.
    fn clear_recovered(&mut self) -> bool {
        self.suspects.is_empty() && self.isolating.is_empty() && self.stored.isolate.take().is_some()
    }

    /// Record one admission of each object, durably, right before it starts
    /// (objects actually admitted only: never one left pending). NAN-4542:
    /// only an admission `alone` (one object, nothing else admitted and
    /// unacknowledged) is counted; others only make the object a suspect.
    pub fn begin<'a>(&mut self, ids: impl IntoIterator<Item = &'a str>, alone: bool) -> Result<()> {
        let ids = ids.into_iter().collect::<Vec<_>>();
        let group = ids.len();
        self.begin_group(ids, alone, group)
    }

    /// [`Self::begin`] for objects of an admission of `group` objects (the
    /// first object of an admission is recorded on its own, before its
    /// fetch: NAN-4553).
    pub fn begin_group<'a>(&mut self, ids: impl IntoIterator<Item = &'a str>, alone: bool, group: usize) -> Result<()> {
        for id in ids {
            if self.suspects.remove(id).is_some() {
                self.isolating.insert(id.to_string());
                self.stored.isolate = Some(u32::try_from(group.max(1)).unwrap_or(u32::MAX));
            }
            if self.stored.attempts.len() >= MAX_ENTRIES && !self.stored.attempts.contains_key(id) {
                // Never expected: the oldest entry goes (its object is the
                // least likely still pending).
                let oldest = self.stored.attempts.keys().next().cloned();
                if let Some(oldest) = oldest {
                    self.stored.attempts.remove(&oldest);
                    self.stored.reserve_refused.remove(&oldest);
                }
            }
            let attempts = self.stored.attempts.entry(id.to_string()).or_default();
            // One process death counts once: an object this process already
            // charged (recorded before a fetch that then failed and was
            // retried) is not charged again.
            if alone && self.charged.insert(id.to_string()) {
                *attempts += 1;
            }
        }
        self.persist()
    }

    /// NAN-4553: charge an object already recorded by this process (it was
    /// recorded before its fetch as part of a larger admission, and turned
    /// out to be admitted alone).
    pub fn charge(&mut self, id: &str) -> Result<()> {
        if self.charged.contains(id) {
            return Ok(());
        }
        let Some(attempts) = self.stored.attempts.get_mut(id) else { return Ok(()) };
        *attempts += 1;
        self.charged.insert(id.to_string());
        self.persist()
    }

    /// NAN-4553: charge a suspect without admitting it (its refusal reads
    /// the object too, and may die there). Once per process; it stays a
    /// suspect, so a failed refusal is retried.
    pub fn charge_suspect(&mut self, id: &str) -> Result<()> {
        if !self.suspects.contains_key(id) || !self.charged.insert(id.to_string()) {
            return Ok(());
        }
        *self.stored.attempts.entry(id.to_string()).or_default() += 1;
        self.persist()
    }

    /// NAN-4553: this process is exiting on a coded path (a handled fatal
    /// error, not a crash): undo the charges it made, so only abnormal ends
    /// count against the object in flight. The objects stay suspects (they
    /// are still admitted and unacknowledged). Returns how many were undone.
    pub fn uncharge_this_process(&mut self) -> Result<usize> {
        let mut undone = 0;
        for id in std::mem::take(&mut self.charged) {
            if let Some(attempts) = self.stored.attempts.get_mut(&id).filter(|attempts| **attempts > 0) {
                *attempts -= 1;
                undone += 1;
            }
        }
        if undone > 0 {
            self.persist()?;
        }
        Ok(undone)
    }

    /// Forget an object (refused whole).
    pub fn forget(&mut self, id: &str) -> Result<()> {
        self.suspects.remove(id);
        self.isolating.remove(id);
        self.charged.remove(id);
        // NAN-4553: the culprit of the group the bisection narrowed is named;
        // the suspects left are most likely healthy: try them together again
        // (a second culprit among them is bisected the same way).
        self.group_limit = self.suspects.len().max(1);
        let marked = self.stored.reserve_refused.remove(id);
        let recovered = self.clear_recovered();
        if self.stored.attempts.remove(id).is_some() || marked || recovered {
            self.persist()?;
        }
        Ok(())
    }

    fn persist(&self) -> Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(&self.stored)?;
        {
            let mut file = std::fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path).with_context(|| format!("rename {}", self.path.display()))?;
        if let Some(dir) = self.path.parent() {
            if let Ok(dir) = std::fs::File::open(dir) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_survive_a_reopen_and_drop_once_acknowledged() {
        let dir = tempfile::tempdir().unwrap();
        let a = object_id("bronze-v2/a", "edge-log-v1:17");
        let b = object_id("bronze-v2/b", "edge-log-v1:18");
        let mut ledger = AdmissionAttempts::open(dir.path());
        assert!(ledger.is_empty() && !ledger.has_suspects());
        ledger.begin([a.as_str(), b.as_str()], false).unwrap();
        // Still pending in the same process: never a suspect.
        assert_eq!(ledger.suspect(&a), None);
        // A crash: the next process reads what the last one began. Two
        // objects were in flight: both are suspects, neither is charged
        // (NAN-4542).
        let mut ledger = AdmissionAttempts::open(dir.path());
        assert_eq!((ledger.suspect(&a), ledger.suspect(&b)), (Some(0), Some(0)));
        ledger.begin([a.as_str()], true).unwrap();
        assert_eq!(ledger.suspect(&a), None, "admitted by this process");
        let mut ledger = AdmissionAttempts::open(dir.path());
        assert_eq!(ledger.suspect(&a), Some(1), "a crash with it alone in flight is charged");
        ledger.begin([a.as_str()], true).unwrap();
        let mut ledger = AdmissionAttempts::open(dir.path());
        assert_eq!(ledger.suspect(&a), Some(2));
        // b was acknowledged: no longer pending.
        ledger.retain_pending([a.as_str()]).unwrap();
        assert_eq!(ledger.suspect(&b), None);
        let ledger = AdmissionAttempts::open(dir.path());
        assert_eq!((ledger.suspect(&a), ledger.suspect(&b)), (Some(2), None));
    }

    /// NAN-4542: a suspect re-admitted by this process stays isolated until
    /// it leaves the pending set (or is refused); an object this process
    /// admits fresh never is.
    #[test]
    fn a_readmitted_suspect_stays_isolated_until_acknowledged() {
        let dir = tempfile::tempdir().unwrap();
        let a = object_id("bronze-v2/a", "edge-log-v1:30");
        let b = object_id("bronze-v2/b", "edge-log-v1:31");
        let c = object_id("bronze-v2/c", "edge-log-v1:32");
        AdmissionAttempts::open(dir.path()).begin([a.as_str(), b.as_str()], false).unwrap();
        let mut ledger = AdmissionAttempts::open(dir.path());
        assert!(!ledger.has_isolating(), "nothing re-admitted yet");
        ledger.begin([a.as_str(), c.as_str()], false).unwrap();
        assert!(ledger.isolating(&a));
        assert!(!ledger.isolating(&b), "a suspect not re-admitted yet");
        assert!(!ledger.isolating(&c), "a fresh admission of this process");
        ledger.retain_pending([a.as_str(), b.as_str(), c.as_str()]).unwrap();
        assert!(ledger.isolating(&a), "still pending: still isolated");
        ledger.retain_pending([b.as_str(), c.as_str()]).unwrap();
        assert!(!ledger.has_isolating(), "acknowledged: no longer isolated");
        ledger.begin([b.as_str()], true).unwrap();
        ledger.forget(&b).unwrap();
        assert!(!ledger.has_isolating(), "refused whole: no longer isolated");
    }

    #[test]
    fn a_reserve_refusal_mark_survives_a_reopen_and_reads_older_ledgers() {
        let dir = tempfile::tempdir().unwrap();
        let a = object_id("bronze-v2/a", "edge-log-v1:22");
        let mut ledger = AdmissionAttempts::open(dir.path());
        ledger.mark_reserve_refused(&a).unwrap();
        assert!(!ledger.reserve_refused(&a), "never admitted: not marked");
        ledger.begin([a.as_str()], true).unwrap();
        ledger.mark_reserve_refused(&a).unwrap();
        let mut ledger = AdmissionAttempts::open(dir.path());
        assert!(ledger.reserve_refused(&a));
        assert_eq!(ledger.suspect(&a), Some(1));
        ledger.forget(&a).unwrap();
        assert!(!AdmissionAttempts::open(dir.path()).reserve_refused(&a));
        // A ledger written before NAN-4336 has no `reserve_refused` key.
        std::fs::write(dir.path().join(FILE), br#"{"attempts":{"k\n1":2}}"#).unwrap();
        let ledger = AdmissionAttempts::open(dir.path());
        assert_eq!(ledger.suspect("k\n1"), Some(2));
        assert!(!ledger.reserve_refused("k\n1"));
    }

    /// NAN-4553: recovery halves the group a crash interrupted; only a group
    /// of one is charged; the size is dropped once recovery is over.
    #[test]
    fn recovery_bisects_suspects_and_charges_only_singletons() {
        let dir = tempfile::tempdir().unwrap();
        let ids = (0..8).map(|i| object_id(&format!("bronze-v2/{i}"), "1")).collect::<Vec<_>>();
        let refs = || ids.iter().map(String::as_str);
        // Normal mode: 8 objects in flight, a crash.
        AdmissionAttempts::open(dir.path()).begin(refs(), false).unwrap();
        let mut ledger = AdmissionAttempts::open(dir.path());
        assert_eq!(ledger.group_limit(), 4, "half the suspects");
        // Recovery admits the oldest 4 together; a crash.
        ledger.begin(refs().take(4), false).unwrap();
        let mut ledger = AdmissionAttempts::open(dir.path());
        assert_eq!(ledger.group_limit(), 2, "half the interrupted group");
        ledger.begin(refs().take(2), false).unwrap();
        let mut ledger = AdmissionAttempts::open(dir.path());
        assert_eq!(ledger.group_limit(), 1);
        ledger.begin(refs().take(1), true).unwrap();
        let mut ledger = AdmissionAttempts::open(dir.path());
        assert_eq!(ledger.group_limit(), 1, "a crash of a singleton stays at one");
        assert_eq!(refs().map(|id| ledger.suspect(id).unwrap()).collect::<Vec<_>>(), [1, 0, 0, 0, 0, 0, 0, 0],
            "only the singleton was charged");
        // Everything commits: recovery over, the size is gone.
        ledger.begin(refs(), false).unwrap();
        ledger.retain_pending([]).unwrap();
        let ledger = AdmissionAttempts::open(dir.path());
        assert!(ledger.is_empty());
        assert_eq!(ledger.stored.isolate, None);
    }

    /// NAN-4553: a coded exit undoes this process's charges (the object
    /// stays a suspect); a crash keeps them; a later charge is not undone
    /// twice.
    #[test]
    fn a_coded_exit_undoes_the_charge_and_a_crash_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let a = object_id("bronze-v2/a", "1");
        let b = object_id("bronze-v2/b", "1");
        let mut ledger = AdmissionAttempts::open(dir.path());
        ledger.begin([a.as_str()], true).unwrap();
        ledger.begin_group([b.as_str()], false, 2).unwrap();
        ledger.charge(&b).unwrap();
        ledger.charge(&b).unwrap();
        assert_eq!(ledger.uncharge_this_process().unwrap(), 2);
        let mut ledger = AdmissionAttempts::open(dir.path());
        assert_eq!((ledger.suspect(&a), ledger.suspect(&b)), (Some(0), Some(0)), "coded exit: suspects, not charged");
        ledger.begin([a.as_str()], true).unwrap();
        // A crash (no uncharge): the charge stays.
        let mut ledger = AdmissionAttempts::open(dir.path());
        assert_eq!(ledger.suspect(&a), Some(1));
        assert_eq!(ledger.uncharge_this_process().unwrap(), 0, "nothing charged by this process");
        assert_eq!(AdmissionAttempts::open(dir.path()).suspect(&a), Some(1), "an earlier process's charge is kept");
    }

    #[test]
    fn an_unreadable_ledger_starts_over() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), b"{not json").unwrap();
        let ledger = AdmissionAttempts::open(dir.path());
        assert!(ledger.is_empty() && !ledger.has_suspects());
    }
}
