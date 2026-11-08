// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4664: in-flight sharing of identical searches.
//!
//! A fleet of agents hunting at once sends the same search many times over
//! (16 bakeoff agents ran the same 10 hunts). Identical searches that are
//! already running share ONE run: the first request leads (it takes the
//! admission slot and executes), every identical request that arrives while
//! it runs follows and receives a clone of the leader's result. Followers
//! never take an admission slot.
//!
//! This is not a cache: the result is computed now, for this moment, so it
//! applies even to `use_cache: false` and to `x-nano-cache-bypass` refreshes.
//! A finished run is forgotten at once; the next identical request leads a
//! fresh run.
//!
//! **Identity** is [`crate::cache::SearchResultCache::inflight_key_for`]: the
//! caller's effective source and artifact deny sets (RBAC scope), its
//! authority fingerprint (admission priority), the normalized query,
//! `use_cache`, the exact time bounds, limit, offset, every result-shaping
//! flag and the dataset. [`share_eligible`] keeps out anything a follower
//! must not inherit from another caller's run.
//!
//! **Leader loss.** If the leader is cancelled (its client left, it escalated
//! to a durable job, a `DELETE` killed it) or fails for a reason of its own
//! (admission, a dependency blip), no follower fails with it: one follower
//! becomes the new leader and runs the search, the rest follow that one. A
//! failure the query itself determines (parse, budget, timeout) is handed to
//! every follower at once instead of being re-run one follower at a time.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

use metrics::counter;
use tokio::sync::watch;

/// How a request's result was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// This request ran the search.
    Leader,
    /// This request received an identical concurrent run's result.
    Follower,
}

/// What a finished leader publishes to its followers: its result, or a
/// failure the query itself determines (see [`InFlight::run`]).
type Published<V, E> = Option<Result<V, E>>;
type Runs<V, E> = Mutex<HashMap<String, watch::Receiver<Published<V, E>>>>;

/// Registry of runs in flight, keyed by search identity. Entries live only
/// while their leader runs, so its size is bounded by concurrent requests;
/// a follower holds one channel receiver, never a slot in a list.
pub(crate) struct InFlight<V, E> {
    runs: Runs<V, E>,
}

impl<V, E> Default for InFlight<V, E> {
    fn default() -> Self {
        Self { runs: Mutex::new(HashMap::new()) }
    }
}

/// Removes the leader's entry when its run ends or its future is dropped
/// (cancel, escalation, panic). Declared after the sender, so it drops
/// first: woken followers never find the dead entry.
struct LeaderGuard<'a, V, E> {
    runs: &'a Runs<V, E>,
    key: &'a str,
    mine: watch::Receiver<Published<V, E>>,
}

impl<V, E> Drop for LeaderGuard<'_, V, E> {
    fn drop(&mut self) {
        let mut runs = self.runs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if runs.get(self.key).is_some_and(|current| current.same_channel(&self.mine)) {
            runs.remove(self.key);
        }
    }
}

impl<V: Clone, E> InFlight<V, E> {
    /// Number of runs in flight (tests).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.runs.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len()
    }

    /// Run `lead()` as this key's leader, or follow the identical run in
    /// flight. `shared_failure` copies a leader's error that the QUERY
    /// determines (it would fail the same way for every follower: a parse or
    /// SQL error, a resource budget, a timeout); followers receive that copy
    /// instead of re-running the search one after another. Any other failure
    /// (an admission refusal, a cancel, a dependency blip) and a cancelled
    /// leader hand the run to ONE follower, which calls `lead` again.
    pub(crate) async fn run<F, Fut>(&self, key: &str, mut lead: F, shared_failure: fn(&E) -> Option<E>) -> (Result<V, E>, Role)
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        loop {
            let follow = {
                let mut runs = self.runs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                match runs.get(key) {
                    Some(running) => Ok(running.clone()),
                    None => {
                        let (tx, rx) = watch::channel(None);
                        runs.insert(key.to_owned(), rx.clone());
                        Err((tx, rx))
                    }
                }
            };
            match follow {
                Ok(mut running) => {
                    loop {
                        let published = match &*running.borrow_and_update() {
                            Some(Ok(value)) => Some(Ok(value.clone())),
                            Some(Err(error)) => shared_failure(error).map(Err),
                            None => None,
                        };
                        if let Some(result) = published {
                            counter!("nanosiem_search_inflight_total", "role" => "follower").increment(1);
                            return (result, Role::Follower);
                        }
                        if running.changed().await.is_err() {
                            break;
                        }
                    }
                    // The leader ended without a shareable outcome (cancelled
                    // or a caller-specific failure): take over.
                    counter!("nanosiem_search_inflight_takeovers_total").increment(1);
                }
                Err((tx, mine)) => {
                    let guard = LeaderGuard { runs: &self.runs, key, mine };
                    counter!("nanosiem_search_inflight_total", "role" => "leader").increment(1);
                    let result = lead().await;
                    let published = match &result {
                        Ok(value) => Some(Ok(value.clone())),
                        Err(error) => shared_failure(error).map(Err),
                    };
                    if published.is_some() {
                        let _ = tx.send(published);
                    }
                    drop(guard);
                    return (result, Role::Leader);
                }
            }
        }
    }
}

/// A leader's failure that every identical follower would also hit, copied
/// for them (NAN-4664). Caller- or moment-specific failures (admission, a
/// cancel, a database error) return `None`: a follower takes the run over
/// instead.
pub(crate) fn query_determined_failure(error: &nanosiem_core::SearchError) -> Option<nanosiem_core::SearchError> {
    use nanosiem_core::SearchError as E;
    Some(match error {
        E::ParseError(message) => E::ParseError(message.clone()),
        E::StructuredParseError { message, position, line, column, token, expected, suggestions, formatted } => E::StructuredParseError {
            message: message.clone(), position: *position, line: *line, column: *column, token: token.clone(),
            expected: expected.clone(), suggestions: suggestions.clone(), formatted: formatted.clone(),
        },
        E::FieldNotFound { field, suggestions, message } => E::FieldNotFound { field: field.clone(), suggestions: suggestions.clone(), message: message.clone() },
        E::SqlGenError(message) => E::SqlGenError(message.clone()),
        E::SqlValidationError(message) => E::SqlValidationError(message.clone()),
        E::InvalidTimeRange => E::InvalidTimeRange,
        E::Timeout(ms) => E::Timeout(*ms),
        E::ResponseTooLarge(size, limit) => E::ResponseTooLarge(*size, *limit),
        _ => return None,
    })
}

/// Whether a search may share an identical in-flight run (NAN-4664). Only
/// when nothing about the run depends on who asked beyond the identity key:
///
/// - not a query that reads state outside the event data or is billed per
///   member: lookups, IOC feeds, `| ai`;
/// - not a query naming a source the caller cannot see: that attempt is
///   audited from the caller's own run (NAN-3222), so it always leads.
pub(crate) fn share_eligible(query: &str, deny_set: &std::collections::BTreeSet<String>) -> bool {
    if crate::cache::reads_state_outside_the_events(query) {
        return false;
    }
    // NAN-4928 review P2: relative `earliest=`/`latest=` resolve against each
    // request's own clock at execution, so the request bounds in the key do
    // not describe the window; such a query never shares a run.
    if nanosiem_core::query::has_outer_time_modifiers(query) {
        return false;
    }
    !names_denied_source(query, deny_set)
}

/// Whether `query` explicitly names a source the caller cannot see (or does
/// not parse). Such a request must reach the source gate itself so its
/// attempt is audited (NAN-3222): it never follows a shared run, and never
/// takes a cache or settled-reuse fast path (NAN-4928 review P2).
pub(crate) fn names_denied_source(query: &str, deny_set: &std::collections::BTreeSet<String>) -> bool {
    if deny_set.is_empty() {
        return false;
    }
    match nanosiem_core::query::parse_query(query) {
        Ok(parsed) => !nanosiem_core::search::denied_source_audit::denied_sources_named(&parsed, deny_set).is_empty(),
        Err(_) => true,
    }
}

/// The process-wide registry the search handler shares runs through.
pub(crate) fn searches() -> &'static InFlight<nanosiem_core::SearchResponse, nanosiem_core::SearchError> {
    static SEARCHES: std::sync::OnceLock<InFlight<nanosiem_core::SearchResponse, nanosiem_core::SearchError>> = std::sync::OnceLock::new();
    SEARCHES.get_or_init(InFlight::default)
}

#[cfg(test)]
#[path = "inflight_tests.rs"]
mod tests;
