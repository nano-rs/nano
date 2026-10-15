// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query tracking for cancellation support
//!
//! This module provides a thread-safe registry for tracking active queries,
//! enabling query cancellation by request ID.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

/// Information about an active query
#[derive(Debug, Clone)]
pub struct QueryInfo {
    /// ClickHouse query_id for KILL QUERY
    pub query_id: String,
    /// NAN-2100: the CREDENTIAL that started this request_id, for cancel authz.
    ///
    /// MUST be the api-key id for api-key auth and the user id for an
    /// interactive session — never the key's human OWNER. Storing the owner
    /// collapses "Fred's browser session", "Fred's key A" and "Fred's
    /// zero-permission key B" into one identity, letting the weakest of them
    /// `KILL QUERY` the others' live investigations.
    ///
    /// The two `AuthContext` types disagree on what `claims.sub` means for an
    /// api key (`nanosiem-search` stores the key id, `nanosiem-api-lib` the
    /// owner), so callers must resolve it through their context's explicit
    /// credential accessor rather than reading `claims.sub` directly.
    pub owner_principal_id: Option<Uuid>,
    /// When the query started
    pub started_at: Instant,
}

/// Thread-safe registry for tracking active queries
///
/// Maps client-provided request_id -> ClickHouse query_id
/// Used to enable query cancellation via the API
#[derive(Debug, Clone, Default)]
pub struct QueryTracker {
    active: Arc<DashMap<String, QueryInfo>>,
    /// NAN-3883: `DELETE /api/search/{id}` for an id this instance is not
    /// running yet, keyed by request id: the principal that asked and when.
    /// The UI cancels a superseded run's request id the moment it starts the
    /// next one, often before that run's `POST` has been admitted (the browser
    /// abort itself never reaches search through the edge). Without this the
    /// cancel found nothing (`{"cancelled":false}`) and the superseded search
    /// ran to completion or escalation beside the current one.
    cancel_requests: Arc<DashMap<String, (Uuid, Instant)>>,
    /// NAN-3883: one signal per interactive request a handler is serving, so
    /// a cancel that lands before the query reached the engine (admission,
    /// planning, cache lookup) still stops it. The token tells one
    /// registration from a later one under the same id.
    cancel_signals: Arc<DashMap<String, (Uuid, tokio::sync::watch::Sender<bool>)>>,
}

/// NAN-3883: how long a cancel for a not-yet-arrived request id is kept.
/// The cancel and the request it targets leave the browser together.
pub const CANCEL_REQUEST_TTL: std::time::Duration = std::time::Duration::from_secs(120);

/// NAN-3883: an interactive request's cancel signal; unregisters on drop.
#[derive(Debug)]
pub struct CancelSignal {
    registry: Arc<DashMap<String, (Uuid, tokio::sync::watch::Sender<bool>)>>,
    request_id: String,
    token: Uuid,
    receiver: tokio::sync::watch::Receiver<bool>,
}

impl CancelSignal {
    /// Resolves once the request is cancelled; pending forever otherwise.
    pub async fn cancelled(&mut self) {
        if self.receiver.wait_for(|cancelled| *cancelled).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

impl Drop for CancelSignal {
    fn drop(&mut self) {
        let token = self.token;
        self.registry.remove_if(&self.request_id, |_, (registered, _)| *registered == token);
    }
}

impl QueryTracker {
    /// Create a new query tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new query
    ///
    /// # Arguments
    /// * `request_id` - Client-provided request ID
    /// * `query_id` - ClickHouse query_id to use for cancellation
    pub fn register(&self, request_id: String, query_id: String) {
        let existing_owner = self
            .active
            .get(&request_id)
            .and_then(|r| r.value().owner_principal_id);
        self.active.insert(
            request_id,
            QueryInfo {
                query_id,
                owner_principal_id: existing_owner,
                started_at: Instant::now(),
            },
        );
    }

    /// Reserve a request_id with the CREDENTIAL that started it, before
    /// execution begins. This lets cancellation enforce ownership even before a
    /// query_id is assigned. See [`QueryInfo::owner_principal_id`] for what
    /// `owner_principal_id` must be.
    ///
    /// Returns `true` when the caller owns the id afterwards — it was free, or
    /// it was already held by the SAME principal (companion queries reuse the
    /// main request id). Returns `false` on a conflict with a DIFFERENT
    /// principal; the caller must then refuse the request.
    ///
    /// NAN-2100: this used to be an unconditional `or_insert_with`, which kept
    /// the FIRST reserver's identity and still reported success. A second
    /// credential's query then ran under an id owned by the first, so the first
    /// could `KILL QUERY` it. The shared Redis registry already rejected that
    /// collision (`SET NX`); single-instance deployments — and any request that
    /// fell back to local ownership after a Redis error — had no such check.
    #[must_use]
    pub fn reserve_request(&self, request_id: String, owner_principal_id: Uuid) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.active.entry(request_id) {
            Entry::Occupied(existing) => {
                existing.get().owner_principal_id == Some(owner_principal_id)
            }
            Entry::Vacant(slot) => {
                slot.insert(QueryInfo {
                    query_id: String::new(),
                    owner_principal_id: Some(owner_principal_id),
                    started_at: Instant::now(),
                });
                true
            }
        }
    }

    /// NAN-3883: register `request_id`'s cancel signal for the handler that
    /// serves it. `None` when a cancel for it already arrived from
    /// `principal` (the caller answers QUERY_CANCELLED without running it).
    pub fn cancel_signal(&self, request_id: &str, principal: Uuid) -> Option<CancelSignal> {
        if self.take_cancel_request(request_id, principal) {
            return None;
        }
        let (sender, receiver) = tokio::sync::watch::channel(false);
        let token = Uuid::new_v4();
        self.cancel_signals.insert(request_id.to_string(), (token, sender));
        Some(CancelSignal {
            registry: Arc::clone(&self.cancel_signals),
            request_id: request_id.to_string(),
            token,
            receiver,
        })
    }

    /// NAN-3883: cancel `request_id` on behalf of `principal` (already
    /// authorized as its owner, or the id is unknown everywhere). Signals a
    /// handler serving it and returns `true`; otherwise remembers the cancel
    /// for [`CANCEL_REQUEST_TTL`] so the request is refused if it arrives
    /// later, and returns `false`.
    pub fn request_cancel(&self, request_id: &str, principal: Uuid) -> bool {
        if let Some(entry) = self.cancel_signals.get(request_id) {
            let _ = entry.value().1.send(true);
            return true;
        }
        self.cancel_requests
            .retain(|_, (_, at)| at.elapsed() <= CANCEL_REQUEST_TTL);
        self.cancel_requests
            .insert(request_id.to_string(), (principal, Instant::now()));
        false
    }

    /// NAN-3883: consume a remembered cancel of `request_id` by `principal`.
    /// Another principal's cancel never stops this principal's request.
    fn take_cancel_request(&self, request_id: &str, principal: Uuid) -> bool {
        self.cancel_requests
            .remove_if(request_id, |_, (owner, at)| {
                *owner == principal && at.elapsed() <= CANCEL_REQUEST_TTL
            })
            .is_some()
    }

    /// Unregister a query (call when query completes)
    ///
    /// Returns the QueryInfo if it was registered
    pub fn unregister(&self, request_id: &str) -> Option<QueryInfo> {
        self.active.remove(request_id).map(|(_, info)| info)
    }

    /// Get query info by request ID
    pub fn get(&self, request_id: &str) -> Option<QueryInfo> {
        self.active.get(request_id).map(|r| r.value().clone())
    }

    /// Get count of active queries
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// List all active queries (for debugging/monitoring)
    pub fn list_active(&self) -> Vec<(String, QueryInfo)> {
        self.active
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect()
    }

    /// Remove stale entries older than `max_age`.
    ///
    /// Queries that fail to call `unregister()` (e.g., due to error paths or panics)
    /// leave orphaned entries in the tracker. This method cleans them up.
    pub fn cleanup_stale(&self, max_age: std::time::Duration) -> usize {
        let mut removed = 0;
        // Check and remove under the same shard write lock. A collected list
        // of IDs could otherwise delete a newly registered replacement after
        // the original stale entry was observed.
        self.active.retain(|_, info| {
            if info.started_at.elapsed() > max_age {
                removed += 1;
                false
            } else {
                true
            }
        });
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_removes_only_current_stale_entries_and_reports_actual_removals() {
        let tracker = QueryTracker::new();
        let owner = Uuid::now_v7();
        assert!(tracker.reserve_request("stale".into(), owner));
        tracker.active.get_mut("stale").unwrap().started_at =
            Instant::now() - std::time::Duration::from_secs(7200);
        assert!(tracker.reserve_request("replaced".into(), owner));
        tracker.active.get_mut("replaced").unwrap().started_at =
            Instant::now() - std::time::Duration::from_secs(7200);
        tracker.register("replaced".into(), "current-query".into());
        assert_eq!(tracker.cleanup_stale(std::time::Duration::from_secs(3600)), 1);
        assert!(tracker.get("stale").is_none());
        let fresh = tracker.get("replaced").unwrap();
        assert_eq!(fresh.query_id, "current-query");
        assert_eq!(fresh.owner_principal_id, Some(owner));
        assert_eq!(tracker.cleanup_stale(std::time::Duration::from_secs(3600)), 0);
    }

    #[test]
    fn test_query_tracker_register_unregister() {
        let tracker = QueryTracker::new();

        tracker.register("req-123".to_string(), "ch-456".to_string());
        assert_eq!(tracker.active_count(), 1);

        let info = tracker.get("req-123").unwrap();
        assert_eq!(info.query_id, "ch-456");
        assert_eq!(info.owner_principal_id, None);

        let removed = tracker.unregister("req-123").unwrap();
        assert_eq!(removed.query_id, "ch-456");
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_query_tracker_missing_query() {
        let tracker = QueryTracker::new();
        assert!(tracker.get("nonexistent").is_none());
        assert!(tracker.unregister("nonexistent").is_none());
    }

    #[test]
    fn test_query_tracker_cleanup_stale() {
        let tracker = QueryTracker::new();

        // Register a query
        tracker.register("req-old".to_string(), "ch-old".to_string());
        assert_eq!(tracker.active_count(), 1);

        // Cleanup with a zero max_age should remove it immediately
        let removed = tracker.cleanup_stale(std::time::Duration::from_secs(0));
        assert_eq!(removed, 1);
        assert_eq!(tracker.active_count(), 0);

        // Register another and cleanup with a large max_age should keep it
        tracker.register("req-new".to_string(), "ch-new".to_string());
        let removed = tracker.cleanup_stale(std::time::Duration::from_secs(3600));
        assert_eq!(removed, 0);
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn test_reserve_owner_persists_after_register() {
        let tracker = QueryTracker::new();
        let user_id = Uuid::now_v7();

        assert!(tracker.reserve_request("req-1".to_string(), user_id));
        tracker.register("req-1".to_string(), "ch-1".to_string());

        let info = tracker.get("req-1").unwrap();
        assert_eq!(info.query_id, "ch-1");
        assert_eq!(info.owner_principal_id, Some(user_id));
    }

    /// NAN-2100: reserving an id already held by a DIFFERENT credential must be
    /// refused. The old `or_insert_with` kept the first reserver and reported
    /// success, so the second credential's query ran under an id the first one
    /// could `KILL QUERY`. Companion queries from the SAME credential must
    /// still succeed — they deliberately reuse the main request id.
    #[test]
    fn reserve_request_rejects_a_different_principal() {
        let tracker = QueryTracker::new();
        let key_a = Uuid::now_v7();
        let key_b = Uuid::now_v7();

        assert!(tracker.reserve_request("req-1".to_string(), key_a));
        // Same credential re-reserving (companion query) — allowed.
        assert!(tracker.reserve_request("req-1".to_string(), key_a));
        // Different credential — refused, and ownership does NOT change.
        assert!(!tracker.reserve_request("req-1".to_string(), key_b));
        assert_eq!(
            tracker.get("req-1").unwrap().owner_principal_id,
            Some(key_a)
        );

        // An id registered by the engine with no reserved owner is not
        // claimable either — fail closed rather than let a late caller adopt it.
        tracker.register("req-2".to_string(), "ch-2".to_string());
        assert!(!tracker.reserve_request("req-2".to_string(), key_b));
    }

    /// NAN-3883: the UI cancels a superseded run as it starts the next one;
    /// the cancel may land before that run's request is admitted.
    #[test]
    fn a_cancel_before_the_request_arrives_refuses_it_for_that_principal_only() {
        let tracker = QueryTracker::new();
        let owner = Uuid::now_v7();
        let other = Uuid::now_v7();
        assert!(!tracker.request_cancel("t:req-early", owner), "nothing was running yet");
        // Another principal reusing the id is unaffected.
        assert!(tracker.cancel_signal("t:req-early", other).is_some());
        // The owner's late request is refused, once.
        assert!(tracker.cancel_signal("t:req-early", owner).is_none());
        assert!(tracker.cancel_signal("t:req-early", owner).is_some());
    }

    #[tokio::test]
    async fn a_cancel_while_the_handler_serves_the_request_signals_it() {
        let tracker = QueryTracker::new();
        let owner = Uuid::now_v7();
        let mut signal = tracker.cancel_signal("t:req-live", owner).unwrap();
        assert!(tracker.request_cancel("t:req-live", owner));
        tokio::time::timeout(std::time::Duration::from_secs(1), signal.cancelled())
            .await
            .expect("the serving handler sees the cancel");
        drop(signal);
        // Unregistered on drop: a later cancel is remembered instead.
        assert!(!tracker.request_cancel("t:req-live", owner));
    }

    #[tokio::test]
    async fn an_uncancelled_signal_stays_pending_and_a_stale_drop_keeps_the_new_registration() {
        let tracker = QueryTracker::new();
        let owner = Uuid::now_v7();
        let mut first = tracker.cancel_signal("t:req", owner).unwrap();
        assert!(tokio::time::timeout(std::time::Duration::from_millis(20), first.cancelled()).await.is_err());
        let mut second = tracker.cancel_signal("t:req", owner).unwrap();
        drop(first);
        assert!(tracker.request_cancel("t:req", owner), "the live registration survived the stale drop");
        tokio::time::timeout(std::time::Duration::from_secs(1), second.cancelled()).await.unwrap();
    }
}
