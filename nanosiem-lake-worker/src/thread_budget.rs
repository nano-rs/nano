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
//! - **Agent** (NAN-4738: a request id marked `agent-`, an agent-class
//!   search from nano-search, NAN-4703): the lowest class. One thread while
//!   any interactive, companion or background statement runs; otherwise what
//!   other agent statements leave of a quarter of the pool. Agent statements
//!   never count against the interactive share, so an analyst beside any
//!   number of running agent statements still gets the whole pool (the
//!   16-agent NAN-4689 burst cut an analyst hunt to one thread and 2.2 s to
//!   20.4 s when agents were classed interactive).
//!
//! - **One request, one share** (NAN-4751): the interactive share counts
//!   requests, not statements. A request's own slices (`-stats-`, `-dc-`,
//!   `-sliced-stats-`, `-rows-`, ... of one id, [`request_root`]) count once
//!   against other requests, and split their request's share among
//!   themselves, so analyst B beside analyst A's two concurrent slices gets
//!   half the pool, not a third. Agent and background statements are
//!   unchanged (they never count against the interactive share).
//!
//! - **Floor of two, bounded total** (NAN-4772): the equal share is never
//!   below [`INTERACTIVE_MIN_THREADS`] (a pool of one keeps one). At five
//!   or more concurrent requests it fell to one thread: in the Mythos
//!   1.0.12 bakeoff 349 of 619 statements ran on one thread (median 258 ms
//!   vs 93 ms at six), and the eight slowest hunts (1.5-2.2 s) were all
//!   one-thread aggregates. Grants are fixed at start, so shares alone
//!   oversubscribed the pool (6+3+2+2+2 = 15 threads on 6). The threads
//!   held by running interactive statements are now bounded by the pool
//!   plus [`INTERACTIVE_SLACK_THREADS`]: a new statement takes its share,
//!   lowered to the room left (so only later statements shrink, down to
//!   one thread), and with no room left it waits on its lane until a
//!   running interactive statement ends. Two of slack: a second analyst
//!   never waits behind a lone whole-pool scan, it starts on the floor at
//!   once (6 + 2 on a 6-thread pool); a third waits for the first to end
//!   instead of oversubscribing the cores it would share anyway. Agent,
//!   background and companion grants are outside the bound and unchanged
//!   (one thread each beside an analyst; a companion at most two, at most
//!   `slots - 1` of them), so agents still yield to every analyst.
//!
//! A grant only ever lowers a statement's own setting, so a statement that
//! asked for fewer threads (a bounded reader, the degraded rung, a payload
//! page) keeps its value, and no statement's rows change.
//!
//! OS-level priority (chDB's `os_thread_priority`) is deliberately not used:
//! raising a pooled thread's nice value cannot be undone without
//! CAP_SYS_NICE, so the next interactive statement on that thread would run
//! niced too.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};

/// A companion statement's most threads.
pub const COMPANION_MAX_THREADS: u64 = 2;
/// NAN-4772: an interactive statement's equal share is never below this
/// (on a pool of at least that many; see the module docs).
pub const INTERACTIVE_MIN_THREADS: u64 = 2;
/// NAN-4772: running interactive statements hold at most the pool plus
/// this many threads (one floor: see the module docs).
pub const INTERACTIVE_SLACK_THREADS: u64 = INTERACTIVE_MIN_THREADS;
/// Request-id prefix that marks a statement as background work (a scheduled
/// detection sent to query[T]).
pub const BACKGROUND_REQUEST_PREFIX: &str = "detect-";
/// Request-id prefix that marks a statement as agent work (an agent-class
/// search, NAN-4738). Must match nano-search's
/// `search::service::background_request::AGENT_REQUEST_PREFIX`.
pub const AGENT_REQUEST_PREFIX: &str = "agent-";
/// The share of the pool all agent statements together take on an
/// otherwise idle process: a quarter (at least one thread each).
const AGENT_POOL_DIVISOR: u64 = 4;
/// NAN-4751: the request-id suffixes nano-search gives one request's own
/// statements (`core_search`: the `-stats-{path}` / `-sliced-stats-{path}`
/// / `-dc-{path}` / `-rows-{path}` slices, `-metric-{i}`, the `-count-*`
/// unions and rollups, `-field-union-*`, `-lateral-seed`, the `-hist`
/// companion). A UUID id never contains one (its groups are 4+ hex digits).
const REQUEST_SIBLING_MARKERS: &[&str] = &[
    "-hist", "-stats-", "-sliced-stats-", "-dc-", "-rows-", "-metric-", "-count-", "-field-union-", "-lateral-",
];

/// NAN-4751: the request a statement's id belongs to: the id up to its
/// first sibling marker ([`REQUEST_SIBLING_MARKERS`]), else the whole id.
/// Only threads depend on it: a caller that names unrelated ids alike only
/// shares one request's slot between them.
pub fn request_root(request_id: &str) -> &str {
    REQUEST_SIBLING_MARKERS
        .iter()
        .filter_map(|marker| request_id.find(marker))
        .min()
        .map_or(request_id, |end| &request_id[..end])
}

/// Who a statement serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Priority {
    Interactive,
    Companion,
    Background,
    /// NAN-4738: below everything else (see the module docs).
    Agent,
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
        } else if request_id.starts_with(AGENT_REQUEST_PREFIX) {
            // Before the companion check: an agent's `-hist` stays agent.
            Self::Agent
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
            Self::Agent => "agent",
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Running {
    interactive: u64,
    /// NAN-4772: threads held by running interactive statements.
    interactive_threads: u64,
    /// NAN-4751: running interactive statements per request
    /// ([`request_root`]); a grant without a request is its own.
    interactive_requests: HashMap<String, u64>,
    companion: u64,
    background: u64,
    background_threads: u64,
    agent: u64,
    agent_threads: u64,
}

/// The process's thread pool (see the module docs).
#[derive(Debug)]
pub struct ThreadBudget {
    total: u64,
    running: Mutex<Running>,
    /// NAN-4772: signalled when an interactive grant is returned.
    released: Condvar,
}

impl ThreadBudget {
    /// A pool of `total` threads (at least one): the role's CPU quota in
    /// whole cores, `budget::query_threads`.
    pub fn new(total: u64) -> Arc<Self> {
        Arc::new(Self { total: total.max(1), running: Mutex::default(), released: Condvar::new() })
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    /// Threads granted to a `priority` statement starting now that belongs
    /// to no other running statement's request; held until the grant is
    /// dropped. An interactive statement may wait (blocking the calling
    /// lane thread) until a running one ends (NAN-4772).
    pub fn grant(self: &Arc<Self>, priority: Priority) -> ThreadGrant {
        self.grant_for(priority, None)
    }

    /// [`Self::grant`] for a statement of request `request_id` (NAN-4751:
    /// an interactive statement shares its request's slot with the
    /// request's other running statements, see the module docs).
    pub fn grant_for_request(self: &Arc<Self>, priority: Priority, request_id: &str) -> ThreadGrant {
        self.grant_for(priority, Some(request_root(request_id).to_string()))
    }

    /// [`Self::grant`] without waiting: `None` when an interactive
    /// statement would have to wait for room.
    pub fn try_grant(self: &Arc<Self>, priority: Priority) -> Option<ThreadGrant> {
        let running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        self.take(running, priority, None).ok()
    }

    /// [`Self::grant_for_request`] without waiting (see [`Self::try_grant`]).
    pub fn try_grant_for_request(self: &Arc<Self>, priority: Priority, request_id: &str) -> Option<ThreadGrant> {
        let running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        self.take(running, priority, Some(request_root(request_id).to_string())).ok()
    }

    /// Threads held by running interactive statements (NAN-4772: at most
    /// the pool plus [`INTERACTIVE_SLACK_THREADS`]).
    pub fn interactive_threads(&self) -> u64 {
        self.running.lock().unwrap_or_else(|e| e.into_inner()).interactive_threads
    }

    fn grant_for(self: &Arc<Self>, priority: Priority, mut request: Option<String>) -> ThreadGrant {
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            match self.take(running, priority, request) {
                Ok(grant) => return grant,
                Err((guard, back)) => {
                    // No room: a running interactive statement returns some.
                    running = self.released.wait(guard).unwrap_or_else(|e| e.into_inner());
                    request = back;
                }
            }
        }
    }

    /// Take a grant under the lock, or hand the lock (and request) back
    /// when an interactive statement has no room.
    #[allow(clippy::type_complexity)]
    fn take<'a>(
        self: &Arc<Self>,
        mut running: std::sync::MutexGuard<'a, Running>,
        priority: Priority,
        request: Option<String>,
    ) -> Result<ThreadGrant, (std::sync::MutexGuard<'a, Running>, Option<String>)> {
        let Some(threads) = threads_for(self.total, &running, priority, request.as_deref()) else {
            return Err((running, request));
        };
        let request = (priority == Priority::Interactive).then_some(request).flatten();
        match priority {
            Priority::Interactive => {
                running.interactive += 1;
                running.interactive_threads += threads;
                if let Some(request) = request.as_ref() {
                    *running.interactive_requests.entry(request.clone()).or_default() += 1;
                }
            }
            Priority::Companion => running.companion += 1,
            Priority::Background => {
                running.background += 1;
                running.background_threads += threads;
            }
            Priority::Agent => {
                running.agent += 1;
                running.agent_threads += threads;
            }
        }
        Ok(ThreadGrant { budget: self.clone(), priority, threads, request })
    }

    /// Statements holding a grant: (interactive, companion, background).
    pub fn running(&self) -> (u64, u64, u64) {
        let running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        (running.interactive, running.companion, running.background)
    }

    /// Agent statements holding a grant.
    pub fn running_agents(&self) -> u64 {
        self.running.lock().unwrap_or_else(|e| e.into_inner()).agent
    }

    fn release(&self, priority: Priority, threads: u64, request: Option<&str>) {
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        match priority {
            Priority::Interactive => {
                running.interactive = running.interactive.saturating_sub(1);
                running.interactive_threads = running.interactive_threads.saturating_sub(threads);
                self.released.notify_all();
                if let Some(request) = request {
                    if let Some(count) = running.interactive_requests.get_mut(request) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            running.interactive_requests.remove(request);
                        }
                    }
                }
            }
            Priority::Companion => running.companion = running.companion.saturating_sub(1),
            Priority::Background => {
                running.background = running.background.saturating_sub(1);
                running.background_threads = running.background_threads.saturating_sub(threads);
            }
            Priority::Agent => {
                running.agent = running.agent.saturating_sub(1);
                running.agent_threads = running.agent_threads.saturating_sub(threads);
            }
        }
    }
}

/// `None`: an interactive statement with no room under the bound (it waits).
fn threads_for(total: u64, running: &Running, priority: Priority, request: Option<&str>) -> Option<u64> {
    let share = (total / (running.interactive + 1)).max(1);
    Some(match priority {
        Priority::Interactive => {
            // NAN-4751: other requests count once each, however many
            // statements they run; this request's running statements split
            // its share. Without a request id every statement is its own
            // request (the NAN-4174 share above).
            let siblings = request.and_then(|request| running.interactive_requests.get(request)).copied().unwrap_or(0);
            let keyed = running.interactive_requests.values().sum::<u64>();
            let unkeyed = running.interactive.saturating_sub(keyed);
            let other_requests = running.interactive_requests.len() as u64 - u64::from(siblings > 0) + unkeyed;
            // NAN-4772: never below the floor (a one-core role keeps one),
            // then within the room the running statements leave.
            let share = (total / (other_requests + 1) / (siblings + 1)).max(INTERACTIVE_MIN_THREADS.min(total));
            let room = (total + INTERACTIVE_SLACK_THREADS).saturating_sub(running.interactive_threads);
            if room == 0 {
                return None;
            }
            share.min(room)
        }
        Priority::Companion => share.min(COMPANION_MAX_THREADS),
        Priority::Background if running.interactive + running.companion > 0 => 1,
        Priority::Background => total.saturating_sub(running.background_threads).min(total / 2).max(1),
        Priority::Agent if running.interactive + running.companion + running.background > 0 => 1,
        Priority::Agent => (total / AGENT_POOL_DIVISOR).saturating_sub(running.agent_threads).max(1),
    })
}

/// One statement's threads, returned to the pool on drop.
#[derive(Debug)]
pub struct ThreadGrant {
    budget: Arc<ThreadBudget>,
    priority: Priority,
    threads: u64,
    /// An interactive statement's request ([`request_root`]).
    request: Option<String>,
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
        self.budget.release(self.priority, self.threads, self.request.as_deref());
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
        // NAN-4772: a newcomer's half share is lowered to the slack left.
        let second = budget.grant(Priority::Interactive);
        assert_eq!((first.threads(), second.threads()), (6, INTERACTIVE_SLACK_THREADS));
        assert!(budget.try_grant(Priority::Interactive).is_none(), "a third waits for room");
        drop(first);
        // One running: a newcomer gets half, the next a third.
        let third = budget.grant(Priority::Interactive);
        assert_eq!(third.threads(), 3);
        assert_eq!(budget.grant(Priority::Interactive).threads(), 2);
        drop((second, third));
        assert_eq!(budget.grant(Priority::Interactive).threads(), 6);
        // However many arrive, the running total stays within the bound and
        // every admitted statement has at least one thread.
        let many = std::iter::from_fn(|| budget.try_grant(Priority::Interactive)).take(64).collect::<Vec<_>>();
        assert!(many.iter().all(|grant| grant.threads() >= 1));
        assert_eq!(many.iter().map(ThreadGrant::threads).sum::<u64>(), 6 + INTERACTIVE_SLACK_THREADS);
        assert_eq!(budget.interactive_threads(), 6 + INTERACTIVE_SLACK_THREADS);
        drop(many);
        assert_eq!(budget.interactive_threads(), 0);
    }

    /// NAN-4772: the Mythos 1.0.12 bakeoff shape. On a six-thread role,
    /// five concurrent analyst requests used to start on 6+3+2+1+1 threads
    /// (and on 6+3+2+2+2 = 15 with the floor alone). Shares stay at least
    /// the floor; the running total is bounded by the pool plus the slack:
    /// only later statements shrink (down to one), and with no room left a
    /// statement waits. A pool smaller than the floor keeps its own size,
    /// and agent, background and companion grants are unchanged.
    #[test]
    fn interactive_grants_keep_the_floor_within_a_bounded_total() {
        let budget = ThreadBudget::new(6);
        let bound = 6 + INTERACTIVE_SLACK_THREADS;
        let first = budget.grant_for_request(Priority::Interactive, "req-0");
        let second = budget.grant_for_request(Priority::Interactive, "req-1");
        assert_eq!((first.threads(), second.threads()), (6, 2), "the second starts on the floor at once");
        assert!(budget.try_grant_for_request(Priority::Interactive, "req-2").is_none(), "the third waits for room");
        drop(first);
        let third = budget.grant_for_request(Priority::Interactive, "req-2");
        let fourth = budget.grant_for_request(Priority::Interactive, "req-3");
        let fifth = budget.grant_for_request(Priority::Interactive, "req-4");
        assert_eq!((third.threads(), fourth.threads(), fifth.threads()), (3, 2, 1), "a later share shrinks to the room left");
        assert_eq!(budget.interactive_threads(), bound);
        assert!(budget.try_grant_for_request(Priority::Interactive, "req-0-stats-0").is_none(), "a slice waits too");
        // Lower classes keep their single thread beside analysts.
        assert_eq!(budget.grant(Priority::Agent).threads(), 1);
        assert_eq!(budget.grant(Priority::Background).threads(), 1);
        assert_eq!(budget.grant(Priority::Companion).threads(), 1);
        drop((second, third, fourth, fifth));
        assert_eq!(budget.interactive_threads(), 0);
        assert_eq!(ThreadBudget::new(1).grant(Priority::Interactive).threads(), 1, "a one-core role is not oversubscribed");
        let two = ThreadBudget::new(2);
        let first = two.grant(Priority::Interactive);
        assert_eq!((first.threads(), two.grant(Priority::Interactive).threads()), (2, 2));
    }

    /// NAN-4772: a statement with no room waits on its lane thread and
    /// starts as soon as a running interactive statement ends.
    #[test]
    fn a_statement_without_room_waits_for_a_release() {
        let budget = ThreadBudget::new(6);
        let first = budget.grant_for_request(Priority::Interactive, "a");
        let second = budget.grant_for_request(Priority::Interactive, "b");
        let waiter = {
            let budget = budget.clone();
            std::thread::spawn(move || budget.grant_for_request(Priority::Interactive, "c").threads())
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!waiter.is_finished(), "no room: it waits");
        drop(first);
        assert_eq!(waiter.join().unwrap(), 3, "half the pool beside b, once a ended");
        drop(second);
        assert_eq!(budget.interactive_threads(), 0);
    }

    /// Two users, each issuing a statement while the other's runs: every
    /// statement after the first gets half the pool, so the steady state
    /// fills the pool instead of oversubscribing it 2x.
    #[test]
    fn two_users_alternating_settle_on_half_each() {
        let budget = ThreadBudget::new(6);
        let mut a = budget.grant(Priority::Interactive);
        let mut b = budget.grant(Priority::Interactive);
        // NAN-4772: b started on the slack beside a lone a; one rotation
        // settles them.
        drop(a);
        a = budget.grant(Priority::Interactive);
        drop(b);
        b = budget.grant(Priority::Interactive);
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
        let others = std::iter::from_fn(|| budget.try_grant(Priority::Interactive)).take(8).collect::<Vec<_>>();
        assert_eq!(budget.grant(Priority::Companion).threads(), (6 / (1 + others.len() as u64 + 1)).clamp(1, COMPANION_MAX_THREADS));
        assert_eq!(budget.interactive_threads(), 6 + INTERACTIVE_SLACK_THREADS, "companions take nothing from the interactive bound");
        drop((primary, others));
        assert_eq!(ThreadBudget::new(1).grant(Priority::Companion).threads(), 1);
    }

    #[test]
    fn request_roots_strip_the_sibling_suffixes() {
        let id = "0192d2a0-0000-7000-8000-000000000000";
        for suffix in ["", "-hist", "-stats-0", "-stats-0lr", "-sliced-stats-0l", "-dc-x", "-dc-0r", "-rows-0", "-metric-3",
            "-count-rollup", "-count-union-source", "-field-union-overlap", "-lateral-seed"] {
            assert_eq!(request_root(&format!("{id}{suffix}")), id, "{suffix}");
        }
        assert_eq!(request_root(&format!("agent-{id}-dc-0l")), format!("agent-{id}"));
        assert_eq!(request_root("abc"), "abc");
        // The earliest marker wins.
        assert_eq!(request_root("a-dc-x-stats-1"), "a");
    }

    /// NAN-4751: a request's concurrent slices count once against other
    /// requests and split their own request's share.
    #[test]
    fn one_requests_slices_share_one_slot() {
        // The share alone (the NAN-4772 room is checked separately): on 12
        // threads with A running two slices and B one, a new request C is
        // one of three requests (12 / 3 = 4; a third when every statement
        // counted, 12 / 4 = 3); A's third slice splits A's half three ways;
        // B's second slice splits B's half.
        let running = Running {
            interactive: 3,
            interactive_requests: [("a".to_string(), 2), ("b".to_string(), 1)].into_iter().collect(),
            ..Running::default()
        };
        let share = |request: &str| threads_for(12, &running, Priority::Interactive, Some(request));
        assert_eq!(share("c"), Some(4));
        assert_eq!(share("a"), Some(2));
        assert_eq!(share("b"), Some(3));
        // Statements without a request id each count as their own request.
        let unkeyed = Running { interactive: 4, ..running.clone() };
        assert_eq!(threads_for(12, &unkeyed, Priority::Interactive, Some("c")), Some(3));

        // Grants: siblings are counted and released per request.
        let budget = ThreadBudget::new(8);
        let a_left = budget.grant_for_request(Priority::Interactive, "a-dc-0l");
        assert_eq!(a_left.threads(), 8, "alone: the whole pool");
        let a_right = budget.grant_for_request(Priority::Interactive, "a-dc-0r");
        assert_eq!(a_right.threads(), INTERACTIVE_SLACK_THREADS, "a sibling's half, within the room");
        assert_eq!(budget.running(), (2, 0, 0));
        assert_eq!(budget.running.lock().unwrap().interactive_requests.get("a"), Some(&2));
        drop((a_left, a_right));
        let b = budget.grant_for_request(Priority::Interactive, "b");
        assert_eq!(b.threads(), 8, "A's slot is released");
        let anonymous = budget.grant(Priority::Interactive);
        assert_eq!(anonymous.threads(), INTERACTIVE_SLACK_THREADS);
        drop((b, anonymous));
        assert_eq!(budget.running(), (0, 0, 0));
        assert_eq!(budget.interactive_threads(), 0);
        assert!(budget.running.lock().unwrap().interactive_requests.is_empty(), "no request is leaked");
    }

    /// NAN-4751 keeps NAN-4738: agent statements (any id) still take the
    /// lowest grant, never count against an analyst, and the analyst's
    /// share ignores them; a request's companion stays capped.
    #[test]
    fn request_shares_leave_agents_and_companions_as_they_were() {
        let budget = ThreadBudget::new(8);
        let agents = (0..16)
            .map(|n| budget.grant_for_request(Priority::Agent, &format!("agent-{n}-dc-0l")))
            .collect::<Vec<_>>();
        assert_eq!(agents[0].threads(), 2);
        assert!(agents[1..].iter().all(|grant| grant.threads() == 1));
        let analyst = budget.grant_for_request(Priority::Interactive, "u-stats-0");
        assert_eq!(analyst.threads(), 8, "agents never shrink an analyst");
        assert_eq!(budget.grant_for_request(Priority::Agent, "agent-x").threads(), 1);
        assert_eq!(budget.grant_for_request(Priority::Companion, "u-hist").threads(), COMPANION_MAX_THREADS);
        // Its sibling: 8 / 2 = 4, within the slack left (NAN-4772).
        assert_eq!(budget.grant_for_request(Priority::Interactive, "u-stats-1").threads(), INTERACTIVE_SLACK_THREADS);
        drop(analyst);
        drop(agents);
        assert_eq!(budget.running_agents(), 0);
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
    fn agents_never_shrink_an_analyst_and_yield_to_everything() {
        // NAN-4738: the NAN-4689 soak cell (8 threads) during a 16-agent burst.
        let budget = ThreadBudget::new(8);
        let first_agent = budget.grant(Priority::Agent);
        assert_eq!(first_agent.threads(), 2, "alone: a quarter of the pool");
        let second_agent = budget.grant(Priority::Agent);
        assert_eq!(second_agent.threads(), 1, "agents share their quarter");
        let mut agents = (0..14).map(|_| budget.grant(Priority::Agent)).collect::<Vec<_>>();
        assert_eq!(budget.running_agents(), 16);
        assert_eq!(budget.running(), (0, 0, 0), "agents are not interactive");
        let analyst = budget.grant(Priority::Interactive);
        assert_eq!(analyst.threads(), 8, "an analyst beside 16 agent statements keeps the whole pool");
        assert_eq!(budget.grant(Priority::Agent).threads(), 1, "one thread while an analyst runs");
        assert_eq!(budget.grant(Priority::Companion).threads(), COMPANION_MAX_THREADS);
        drop(analyst);
        let detection = budget.grant(Priority::Background);
        assert_eq!(detection.threads(), 4, "detections do not yield to agents");
        assert_eq!(budget.grant(Priority::Agent).threads(), 1, "agents yield to detections");
        drop(detection);
        drop((first_agent, second_agent));
        agents.clear();
        assert_eq!(budget.running_agents(), 0);
        assert_eq!(budget.grant(Priority::Agent).threads(), 2, "threads are returned");
        assert_eq!(ThreadBudget::new(1).grant(Priority::Agent).threads(), 1);
    }

    #[test]
    fn priority_of_request_ids() {
        assert_eq!(Priority::of_request("0192-abc"), Priority::Interactive);
        assert_eq!(Priority::of_request("0192-abc-hist"), Priority::Companion);
        assert_eq!(Priority::of_request("0192-abc-stats-1"), Priority::Interactive);
        assert_eq!(Priority::of_request("detect-0192"), Priority::Background);
        assert_eq!(Priority::of_request("agent-0192"), Priority::Agent);
        assert_eq!(Priority::of_request("agent-0192-hist"), Priority::Agent);
        assert_eq!(Priority::of_request("agent-0192-stats-0"), Priority::Agent);
        assert_eq!(Priority::of_request("0192-agent-x"), Priority::Interactive);
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
        assert_eq!(other.threads(), 2);
        assert_eq!(other.apply("SELECT 1 SETTINGS max_threads=6, max_execution_time=55"),
            "SELECT 1 SETTINGS max_threads=2, max_execution_time=55, max_parsing_threads=2");
        assert_eq!(other.apply("SELECT 1 SETTINGS max_threads=6, max_parsing_threads=6"),
            "SELECT 1 SETTINGS max_threads=2, max_parsing_threads=2");
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
