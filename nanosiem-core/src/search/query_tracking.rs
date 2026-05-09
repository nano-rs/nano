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
    /// Authenticated user that started this request_id (for cancel authz)
    pub owner_user_id: Option<Uuid>,
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
}

impl QueryTracker {
    /// Create a new query tracker
    pub fn new() -> Self {
        Self {
            active: Arc::new(DashMap::new()),
        }
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
            .and_then(|r| r.value().owner_user_id);
        self.active.insert(
            request_id,
            QueryInfo {
                query_id,
                owner_user_id: existing_owner,
                started_at: Instant::now(),
            },
        );
    }

    /// Reserve a request_id with its authenticated owner before execution starts.
    /// This lets cancellation enforce ownership even before query_id is assigned.
    pub fn reserve_request(&self, request_id: String, owner_user_id: Uuid) {
        self.active.entry(request_id).or_insert_with(|| QueryInfo {
            query_id: String::new(),
            owner_user_id: Some(owner_user_id),
            started_at: Instant::now(),
        });
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
        let stale_ids: Vec<String> = self
            .active
            .iter()
            .filter(|r| r.value().started_at.elapsed() > max_age)
            .map(|r| r.key().clone())
            .collect();
        let count = stale_ids.len();
        for id in stale_ids {
            self.active.remove(&id);
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_tracker_register_unregister() {
        let tracker = QueryTracker::new();

        tracker.register("req-123".to_string(), "ch-456".to_string());
        assert_eq!(tracker.active_count(), 1);

        let info = tracker.get("req-123").unwrap();
        assert_eq!(info.query_id, "ch-456");
        assert_eq!(info.owner_user_id, None);

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

        tracker.reserve_request("req-1".to_string(), user_id);
        tracker.register("req-1".to_string(), "ch-1".to_string());

        let info = tracker.get("req-1").unwrap();
        assert_eq!(info.query_id, "ch-1");
        assert_eq!(info.owner_user_id, Some(user_id));
    }
}
