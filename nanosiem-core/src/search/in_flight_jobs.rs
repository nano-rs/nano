// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3920: the durable search jobs this process started recently, so the
//! NAN-3883 attach check looks at a caller's few candidate jobs instead of
//! listing every job the caller ever ran (235 jobs cost ~2 s on every search).
//!
//! A hint, never an authority: every candidate is re-read through the
//! tenant-pinned job view and matched by `settled_reuse` before anyone
//! attaches. A job started by another replica, or before a restart, is simply
//! not attached to; the search runs, as it did before NAN-3883.
use std::{
    collections::VecDeque,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A durable search runs for minutes; attaching to anything older is moot.
const TTL: Duration = Duration::from_secs(2 * 60 * 60);
/// Bounded memory: the oldest entries go first.
const CAPACITY: usize = 4096;
/// The attach check reads at most this many candidates.
pub(crate) const MAX_CANDIDATES: usize = 8;

#[derive(Debug, Clone)]
struct Entry {
    job_id: String,
    user_id: Uuid,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    at: Instant,
}

#[derive(Debug, Default)]
pub(crate) struct InFlightJobs {
    entries: Mutex<VecDeque<Entry>>,
}

impl InFlightJobs {
    pub(crate) fn global() -> &'static Self {
        static JOBS: OnceLock<InFlightJobs> = OnceLock::new();
        JOBS.get_or_init(Self::default)
    }

    pub(crate) fn record(&self, job_id: &str, user_id: Uuid, start: DateTime<Utc>, end: DateTime<Utc>) {
        self.record_at(job_id, user_id, start, end, Instant::now());
    }

    fn record_at(&self, job_id: &str, user_id: Uuid, start: DateTime<Utc>, end: DateTime<Utc>, at: Instant) {
        let Ok(mut entries) = self.entries.lock() else { return };
        entries.retain(|entry| entry.job_id != job_id);
        if entries.len() >= CAPACITY {
            entries.pop_front();
        }
        entries.push_back(Entry { job_id: job_id.to_string(), user_id, start, end, at });
    }

    /// The newest jobs this caller started over exactly this window.
    pub(crate) fn candidates(&self, user_id: Uuid, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<String> {
        self.candidates_at(user_id, start, end, Instant::now())
    }

    fn candidates_at(&self, user_id: Uuid, start: DateTime<Utc>, end: DateTime<Utc>, now: Instant) -> Vec<String> {
        let Ok(mut entries) = self.entries.lock() else { return Vec::new() };
        entries.retain(|entry| now.saturating_duration_since(entry.at) < TTL);
        entries
            .iter()
            .rev()
            .filter(|entry| entry.user_id == user_id && entry.start == start && entry.end == end)
            .take(MAX_CANDIDATES)
            .map(|entry| entry.job_id.clone())
            .collect()
    }

    /// A candidate that is no longer queued or running (or no longer exists).
    pub(crate) fn forget(&self, job_id: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|entry| entry.job_id != job_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn window(hour: u32) -> (DateTime<Utc>, DateTime<Utc>) {
        (Utc.with_ymd_and_hms(2026, 10, 15, hour, 0, 0).unwrap(), Utc.with_ymd_and_hms(2026, 10, 15, hour + 1, 0, 0).unwrap())
    }

    #[test]
    fn candidates_are_the_callers_newest_jobs_over_the_same_window() {
        let jobs = InFlightJobs::default();
        let (alice, bob) = (Uuid::new_v4(), Uuid::new_v4());
        let (start, end) = window(1);
        let (other_start, other_end) = window(2);
        let now = Instant::now();
        jobs.record_at("a1", alice, start, end, now);
        jobs.record_at("b1", bob, start, end, now);
        jobs.record_at("a2", alice, other_start, other_end, now);
        jobs.record_at("a3", alice, start, end, now);
        assert_eq!(jobs.candidates_at(alice, start, end, now), vec!["a3", "a1"]);
        assert_eq!(jobs.candidates_at(bob, start, end, now), vec!["b1"]);
        jobs.forget("a3");
        assert_eq!(jobs.candidates_at(alice, start, end, now), vec!["a1"]);
    }

    #[test]
    fn candidates_expire_and_are_capped() {
        let jobs = InFlightJobs::default();
        let user = Uuid::new_v4();
        let (start, end) = window(3);
        let then = Instant::now();
        jobs.record_at("old", user, start, end, then);
        assert!(jobs.candidates_at(user, start, end, then + TTL).is_empty());
        for index in 0..20 {
            jobs.record_at(&format!("j{index}"), user, start, end, then);
        }
        let found = jobs.candidates_at(user, start, end, then);
        assert_eq!(found.len(), MAX_CANDIDATES);
        assert_eq!(found[0], "j19");
    }

    #[test]
    fn memory_is_bounded() {
        let jobs = InFlightJobs::default();
        let (start, end) = window(4);
        let now = Instant::now();
        for index in 0..CAPACITY + 10 {
            jobs.record_at(&format!("j{index}"), Uuid::new_v4(), start, end, now);
        }
        assert_eq!(jobs.entries.lock().unwrap().len(), CAPACITY);
    }
}
