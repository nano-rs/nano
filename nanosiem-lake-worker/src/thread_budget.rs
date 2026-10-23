// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4174: a process-wide CPU thread budget for chDB statements.
//!
//! query[T]'s role quota is a few cores (`budget::query_threads`, 1..8 from
//! the role CPU limit). Before this, every interactive statement was capped
//! at a fixed 4 threads (`part_query::lanes::INTERACTIVE_MAX_THREADS`) and
//! nothing looked across statements: a lone user's 7 d scan used 4 of ~6.5
//! cores, while two users (each with a histogram companion) ran up to four
//! statements of 4 threads (+4 parsing threads each) and the cgroup throttled
//! them 14-47 s per minute. Durable jobs on the read-write lane ran at the
//! planner's full thread count beside them.
//!
//! Here every statement on a budgeted executor (query[T]'s small, large and
//! read-write lanes; not the one-row point lane) takes a [`ThreadGrant`] when
//! its lane starts it, and its `max_threads` / `max_parsing_threads` are
//! lowered to the grant ([`ThreadGrant::apply`]); the grant is returned when
//! the statement ends. chDB fixes a statement's threads at start, so the
//! budget shapes each new statement by what is running then:
//!
//! - **Interactive** (a request's rows/aggregate statement): an equal share
//!   of the pool among the interactive statements running, itself included:
//!   alone, the whole pool; beside one other, half; beside two, a third.
//!   Background statements do not count against it.
//! - **Companion** (a `-hist` histogram/rollup companion): the interactive
//!   share, at most [`COMPANION_MAX_THREADS`]; companions do not shrink a
//!   primary's share (they are short and only add to its request).
//! - **Background** (anything outside an interactive request: durable search
//!   and view jobs such as bare-`*` and retro hunts, partial builds, prewarm;
//!   or a request id marked `detect-`): one thread while any interactive or
//!   companion statement runs; otherwise what other background statements
//!   leave, at most half the pool, so a job that started on an idle process
//!   still leaves room for the next interactive statement.
//!
//! A grant only ever lowers a statement's own setting, so a statement that
//! asked for fewer threads (a bounded reader, the degraded rung, a payload
//! page) keeps its value, and no statement's rows change.
//!
//! OS-level priority (chDB's `os_thread_priority`) is deliberately not used:
//! raising a pooled thread's nice value cannot be undone without
//! CAP_SYS_NICE, so the next interactive statement on that thread would run
//! niced too.

use std::sync::{Arc, Mutex};

/// A companion statement's most threads.
pub const COMPANION_MAX_THREADS: u64 = 2;
/// Request-id prefix that marks a statement as background work (a scheduled
/// detection sent to query[T]).
pub const BACKGROUND_REQUEST_PREFIX: &str = "detect-";

/// Who a statement serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Priority {
    Interactive,
    Companion,
    Background,
}

impl Priority {
    /// The class of a statement submitted from the current task: inside an
    /// interactive request (`query_timing::measure`) by its request id,
    /// otherwise background.
    pub fn current() -> Self {
        match crate::query_timing::current() {
            Some(phases) => Self::of_request(&phases.lock().unwrap_or_else(|e| e.into_inner()).request_id),
            None => Self::Background,
        }
    }

    /// The class of a statement of the interactive request `request_id`.
    pub fn of_request(request_id: &str) -> Self {
        if request_id.starts_with(BACKGROUND_REQUEST_PREFIX) {
            Self::Background
        } else if request_id.contains("-hist") {
            Self::Companion
        } else {
            Self::Interactive
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Companion => "companion",
            Self::Background => "background",
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Running {
    interactive: u64,
    companion: u64,
    background: u64,
    background_threads: u64,
}

/// The process's thread pool (see the module docs).
#[derive(Debug)]
pub struct ThreadBudget {
    total: u64,
    running: Mutex<Running>,
}

impl ThreadBudget {
    /// A pool of `total` threads (at least one): the role's CPU quota in
    /// whole cores, `budget::query_threads`.
    pub fn new(total: u64) -> Arc<Self> {
        Arc::new(Self { total: total.max(1), running: Mutex::default() })
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    /// Threads granted to a `priority` statement starting now; held until
    /// the grant is dropped.
    pub fn grant(self: &Arc<Self>, priority: Priority) -> ThreadGrant {
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let threads = threads_for(self.total, &running, priority);
        match priority {
            Priority::Interactive => running.interactive += 1,
            Priority::Companion => running.companion += 1,
            Priority::Background => {
                running.background += 1;
                running.background_threads += threads;
            }
        }
        ThreadGrant { budget: self.clone(), priority, threads }
    }

    /// Statements holding a grant: (interactive, companion, background).
    pub fn running(&self) -> (u64, u64, u64) {
        let running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        (running.interactive, running.companion, running.background)
    }

    fn release(&self, priority: Priority, threads: u64) {
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        match priority {
            Priority::Interactive => running.interactive = running.interactive.saturating_sub(1),
            Priority::Companion => running.companion = running.companion.saturating_sub(1),
            Priority::Background => {
                running.background = running.background.saturating_sub(1);
                running.background_threads = running.background_threads.saturating_sub(threads);
            }
        }
    }
}

fn threads_for(total: u64, running: &Running, priority: Priority) -> u64 {
    let share = (total / (running.interactive + 1)).max(1);
    match priority {
        Priority::Interactive => share,
        Priority::Companion => share.min(COMPANION_MAX_THREADS),
        Priority::Background if running.interactive + running.companion > 0 => 1,
        Priority::Background => total.saturating_sub(running.background_threads).min(total / 2).max(1),
    }
}

/// One statement's threads, returned to the pool on drop.
#[derive(Debug)]
pub struct ThreadGrant {
    budget: Arc<ThreadBudget>,
    priority: Priority,
    threads: u64,
}

impl ThreadGrant {
    pub fn threads(&self) -> u64 {
        self.threads
    }

    pub fn priority(&self) -> Priority {
        self.priority
    }

    /// `sql` with `max_threads` (and `max_parsing_threads`, chDB's Parquet
    /// decode pool, which defaults to every host core) at most the grant. A
    /// statement that names no `max_threads` is left alone (typed and
    /// maintenance statements without a settings clause).
    pub fn apply(&self, sql: &str) -> String {
        use crate::part_query::lanes::{lower_setting, setting};
        if setting(sql, "max_threads").is_none() {
            return sql.to_string();
        }
        let sql = lower_setting(sql, "max_threads", self.threads);
        lower_setting(&sql, "max_parsing_threads", self.threads)
    }
}

impl Drop for ThreadGrant {
    fn drop(&mut self) {
        self.budget.release(self.priority, self.threads);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lone_interactive_statement_gets_the_whole_pool() {
        let budget = ThreadBudget::new(6);
        assert_eq!(budget.grant(Priority::Interactive).threads(), 6);
        // Released on drop: the next lone statement gets it all again.
        assert_eq!(budget.grant(Priority::Interactive).threads(), 6);
        assert_eq!(budget.running(), (0, 0, 0));
        assert_eq!(ThreadBudget::new(0).grant(Priority::Interactive).threads(), 1);
    }

    #[test]
    fn concurrent_interactive_statements_share_the_pool() {
        let budget = ThreadBudget::new(6);
        let first = budget.grant(Priority::Interactive);
        let second = budget.grant(Priority::Interactive);
        let third = budget.grant(Priority::Interactive);
        assert_eq!((first.threads(), second.threads(), third.threads()), (6, 3, 2));
        drop(first);
        // Two running: a newcomer gets a third.
        assert_eq!(budget.grant(Priority::Interactive).threads(), 2);
        drop((second, third));
        assert_eq!(budget.grant(Priority::Interactive).threads(), 6);
        // Never below one thread, however many run.
        let many = (0..10).map(|_| budget.grant(Priority::Interactive)).collect::<Vec<_>>();
        assert!(many.iter().all(|grant| grant.threads() >= 1));
        assert_eq!(budget.grant(Priority::Interactive).threads(), 1);
    }

    /// Two users, each issuing a statement while the other's runs: every
    /// statement after the first gets half the pool, so the steady state
    /// fills the pool instead of oversubscribing it 2x.
    #[test]
    fn two_users_alternating_settle_on_half_each() {
        let budget = ThreadBudget::new(6);
        let mut a = budget.grant(Priority::Interactive);
        let mut b = budget.grant(Priority::Interactive);
        for _ in 0..4 {
            drop(a);
            a = budget.grant(Priority::Interactive);
            assert_eq!(a.threads() + b.threads(), 6, "a={} b={}", a.threads(), b.threads());
            drop(b);
            b = budget.grant(Priority::Interactive);
            assert_eq!(a.threads() + b.threads(), 6);
        }
    }

    #[test]
    fn companions_take_at_most_two_and_never_shrink_a_primary() {
        let budget = ThreadBudget::new(6);
        let companion = budget.grant(Priority::Companion);
        assert_eq!(companion.threads(), COMPANION_MAX_THREADS);
        assert_eq!(budget.grant(Priority::Interactive).threads(), 6, "a primary beside its own companion");
        let primary = budget.grant(Priority::Interactive);
        let _others = (0..5).map(|_| budget.grant(Priority::Interactive)).collect::<Vec<_>>();
        assert_eq!(budget.grant(Priority::Companion).threads(), 1);
        drop(primary);
        assert_eq!(ThreadBudget::new(1).grant(Priority::Companion).threads(), 1);
    }

    #[test]
    fn background_yields_to_interactive() {
        let budget = ThreadBudget::new(6);
        // Idle process: a job gets half the pool, a second job what is left.
        let job = budget.grant(Priority::Background);
        assert_eq!(job.threads(), 3);
        let job2 = budget.grant(Priority::Background);
        assert_eq!(job2.threads(), 3);
        assert_eq!(budget.grant(Priority::Background).threads(), 1, "pool used up by jobs");
        // A running job never shrinks an interactive statement's share.
        let user = budget.grant(Priority::Interactive);
        assert_eq!(user.threads(), 6);
        // While anything interactive runs, a new job gets one thread.
        assert_eq!(budget.grant(Priority::Background).threads(), 1);
        drop(user);
        let companion = budget.grant(Priority::Companion);
        assert_eq!(budget.grant(Priority::Background).threads(), 1);
        drop((companion, job, job2));
        assert_eq!(budget.grant(Priority::Background).threads(), 3);
        assert_eq!(budget.running(), (0, 0, 0));
        assert_eq!(ThreadBudget::new(1).grant(Priority::Background).threads(), 1);
    }

    #[test]
    fn priority_of_request_ids() {
        assert_eq!(Priority::of_request("0192-abc"), Priority::Interactive);
        assert_eq!(Priority::of_request("0192-abc-hist"), Priority::Companion);
        assert_eq!(Priority::of_request("0192-abc-stats-1"), Priority::Interactive);
        assert_eq!(Priority::of_request("detect-0192"), Priority::Background);
        // Outside any request: background.
        assert_eq!(Priority::current(), Priority::Background);
    }

    #[tokio::test]
    async fn priority_inside_a_request_is_its_class() {
        let class = crate::query_timing::measure("req-1-hist", async { Ok::<_, ()>(Priority::current()) }).await.unwrap();
        assert_eq!(class, Priority::Companion);
        let class = crate::query_timing::measure("req-1", async { Ok::<_, ()>(Priority::current()) }).await.unwrap();
        assert_eq!(class, Priority::Interactive);
    }

    #[test]
    fn apply_only_lowers_and_bounds_the_parsing_pool() {
        let budget = ThreadBudget::new(6);
        let user = budget.grant(Priority::Interactive);
        let other = budget.grant(Priority::Interactive);
        assert_eq!(other.threads(), 3);
        assert_eq!(other.apply("SELECT 1 SETTINGS max_threads=6, max_execution_time=55"),
            "SELECT 1 SETTINGS max_threads=3, max_execution_time=55, max_parsing_threads=3");
        assert_eq!(other.apply("SELECT 1 SETTINGS max_threads=6, max_parsing_threads=6"),
            "SELECT 1 SETTINGS max_threads=3, max_parsing_threads=3");
        // A bounded reader keeps its own two threads.
        assert_eq!(user.apply("SELECT 1 SETTINGS max_threads=2, max_parsing_threads=2"),
            "SELECT 1 SETTINGS max_threads=2, max_parsing_threads=2");
        // No max_threads: nothing is added.
        assert_eq!(user.apply("SELECT 1"), "SELECT 1");
        assert_eq!(user.apply("SELECT 'max_threads=9' SETTINGS use_query_cache=0"), "SELECT 'max_threads=9' SETTINGS use_query_cache=0");
    }
}

#[cfg(test)]
#[path = "thread_budget_native_tests.rs"]
mod native;
