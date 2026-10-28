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
//! A grant only ever lowers a statement's own setting, so a statement that
//! asked for fewer threads (a bounded reader, the degraded rung, a payload
//! page) keeps its value, and no statement's rows change.
//!
//! OS-level priority (chDB's `os_thread_priority`) is deliberately not used:
//! raising a pooled thread's nice value cannot be undone without
//! CAP_SYS_NICE, so the next interactive statement on that thread would run
//! niced too.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A companion statement's most threads.
pub const COMPANION_MAX_THREADS: u64 = 2;
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

    /// Threads granted to a `priority` statement starting now that belongs
    /// to no other running statement's request; held until the grant is
    /// dropped.
    pub fn grant(self: &Arc<Self>, priority: Priority) -> ThreadGrant {
        self.grant_for(priority, None)
    }

    /// [`Self::grant`] for a statement of request `request_id` (NAN-4751:
    /// an interactive statement shares its request's slot with the
    /// request's other running statements, see the module docs).
    pub fn grant_for_request(self: &Arc<Self>, priority: Priority, request_id: &str) -> ThreadGrant {
        self.grant_for(priority, Some(request_root(request_id).to_string()))
    }

    fn grant_for(self: &Arc<Self>, priority: Priority, request: Option<String>) -> ThreadGrant {
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let threads = threads_for(self.total, &running, priority, request.as_deref());
        let request = (priority == Priority::Interactive).then_some(request).flatten();
        match priority {
            Priority::Interactive => {
                running.interactive += 1;
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
        ThreadGrant { budget: self.clone(), priority, threads, request }
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

fn threads_for(total: u64, running: &Running, priority: Priority, request: Option<&str>) -> u64 {
    let share = (total / (running.interactive + 1)).max(1);
    match priority {
        Priority::Interactive => {
            // NAN-4751: other requests count once each, however many
            // statements they run; this request's running statements split
            // its share. Without a request id every statement is its own
            // request (the NAN-4174 share above).
            let siblings = request.and_then(|request| running.interactive_requests.get(request)).copied().unwrap_or(0);
            let keyed = running.interactive_requests.values().sum::<u64>();
            let unkeyed = running.interactive.saturating_sub(keyed);
            let other_requests = running.interactive_requests.len() as u64 - u64::from(siblings > 0) + unkeyed;
            (total / (other_requests + 1) / (siblings + 1)).max(1)
        }
        Priority::Companion => share.min(COMPANION_MAX_THREADS),
        Priority::Background if running.interactive + running.companion > 0 => 1,
        Priority::Background => total.saturating_sub(running.background_threads).min(total / 2).max(1),
        Priority::Agent if running.interactive + running.companion + running.background > 0 => 1,
        Priority::Agent => (total / AGENT_POOL_DIVISOR).saturating_sub(running.agent_threads).max(1),
    }
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
        let budget = ThreadBudget::new(8);
        let a_left = budget.grant_for_request(Priority::Interactive, "a-dc-0l");
        assert_eq!(a_left.threads(), 8, "alone: the whole pool");
        let a_right = budget.grant_for_request(Priority::Interactive, "a-dc-0r");
        assert_eq!(a_right.threads(), 4, "a sibling splits its request's share");
        // Analyst B beside A's two slices: one other request, half the pool
        // (it was a third when every statement counted).
        let b = budget.grant_for_request(Priority::Interactive, "b");
        assert_eq!(b.threads(), 4);
        assert_eq!(budget.running(), (3, 0, 0));
        // A third slice of A beside B: half the pool, split three ways.
        assert_eq!(budget.grant_for_request(Priority::Interactive, "a-dc-0ll").threads(), 1);
        drop((a_left, a_right));
        assert_eq!(budget.grant_for_request(Priority::Interactive, "a-stats-0").threads(), 4, "A's slot is released");
        drop(b);
        assert_eq!(budget.grant_for_request(Priority::Interactive, "c").threads(), 8);
        // Statements without a request id each count as their own request.
        let anonymous = budget.grant(Priority::Interactive);
        assert_eq!(budget.grant_for_request(Priority::Interactive, "d").threads(), 4);
        assert_eq!(budget.grant(Priority::Interactive).threads(), 4);
        drop(anonymous);
        assert_eq!(budget.running(), (0, 0, 0));
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
        assert_eq!(budget.grant_for_request(Priority::Interactive, "u-stats-1").threads(), 4);
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
