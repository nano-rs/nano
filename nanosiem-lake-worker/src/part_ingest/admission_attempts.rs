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
//!   object at a time (the oldest pending first, so ranges stay
//!   contiguous), so the next crash names the culprit;
//! - an object admitted [`MAX_ADMISSION_CRASHES`] times without being
//!   acknowledged is refused whole (`admission_invalid`, detail
//!   `admission_crashed`), quarantined for an operator replay (NAN-3643),
//!   and acknowledged: the edge log moves past it.
//!
//! A deploy or node restart that interrupts an admitted object counts once;
//! the entry is dropped as soon as that object commits.
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

/// Admissions of one object that ended with the process gone before the
/// object was acknowledged, before it is refused whole.
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
    /// `key \n version` → admissions started without an acknowledgement.
    attempts: BTreeMap<String, u32>,
    /// NAN-4336: objects whose single-object flush the owner refused
    /// permanently; refused whole at the next admission. Absent in a ledger
    /// written before NAN-4336.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    reserve_refused: std::collections::BTreeSet<String>,
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
        Self { path, stored, suspects }
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
        self.stored.reserve_refused.retain(|id| pending.contains(id.as_str()));
        if self.stored.attempts.len() != before {
            self.persist()?;
        }
        Ok(())
    }

    /// Count one admission of each object, durably, right before it starts
    /// (objects actually admitted only: never one left pending).
    pub fn begin<'a>(&mut self, ids: impl IntoIterator<Item = &'a str>) -> Result<()> {
        for id in ids {
            self.suspects.remove(id);
            if self.stored.attempts.len() >= MAX_ENTRIES && !self.stored.attempts.contains_key(id) {
                // Never expected: the oldest entry goes (its object is the
                // least likely still pending).
                let oldest = self.stored.attempts.keys().next().cloned();
                if let Some(oldest) = oldest {
                    self.stored.attempts.remove(&oldest);
                    self.stored.reserve_refused.remove(&oldest);
                }
            }
            *self.stored.attempts.entry(id.to_string()).or_default() += 1;
        }
        self.persist()
    }

    /// Forget an object (refused whole).
    pub fn forget(&mut self, id: &str) -> Result<()> {
        self.suspects.remove(id);
        let marked = self.stored.reserve_refused.remove(id);
        if self.stored.attempts.remove(id).is_some() || marked {
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
        ledger.begin([a.as_str(), b.as_str()]).unwrap();
        // Still pending in the same process: never a suspect.
        assert_eq!(ledger.suspect(&a), None);
        // A crash: the next process reads what the last one began.
        let mut ledger = AdmissionAttempts::open(dir.path());
        assert_eq!((ledger.suspect(&a), ledger.suspect(&b)), (Some(1), Some(1)));
        ledger.begin([a.as_str()]).unwrap();
        assert_eq!(ledger.suspect(&a), None, "admitted by this process");
        let mut ledger = AdmissionAttempts::open(dir.path());
        assert_eq!(ledger.suspect(&a), Some(2));
        // b was acknowledged: no longer pending.
        ledger.retain_pending([a.as_str()]).unwrap();
        assert_eq!(ledger.suspect(&b), None);
        let ledger = AdmissionAttempts::open(dir.path());
        assert_eq!((ledger.suspect(&a), ledger.suspect(&b)), (Some(2), None));
    }

    #[test]
    fn a_reserve_refusal_mark_survives_a_reopen_and_reads_older_ledgers() {
        let dir = tempfile::tempdir().unwrap();
        let a = object_id("bronze-v2/a", "edge-log-v1:22");
        let mut ledger = AdmissionAttempts::open(dir.path());
        ledger.mark_reserve_refused(&a).unwrap();
        assert!(!ledger.reserve_refused(&a), "never admitted: not marked");
        ledger.begin([a.as_str()]).unwrap();
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

    #[test]
    fn an_unreadable_ledger_starts_over() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE), b"{not json").unwrap();
        let ledger = AdmissionAttempts::open(dir.path());
        assert!(ledger.is_empty() && !ledger.has_suspects());
    }
}
