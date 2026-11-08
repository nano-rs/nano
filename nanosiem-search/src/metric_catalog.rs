// SPDX-License-Identifier: AGPL-3.0-or-later
//! In-process, single-flight cache for the metric catalog (NAN-4098).
//!
//! The Metrics explorer loads the catalog on every visit, and several panels
//! (plus the monitor dialog) ask for it at once. Each entry is reused for
//! [`CATALOG_TTL`]; concurrent misses for one key share a single ClickHouse
//! scan instead of each running it. A failed refresh serves the last good
//! entry (stale-but-serving) rather than failing the dropdown. Process-local:
//! the shared Dragonfly result cache still fronts it across replicas.
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long one catalog entry is served before a refresh.
pub const CATALOG_TTL: Duration = Duration::from_secs(60);
/// Bound on distinct keys (service filter × window) kept in memory.
const MAX_KEYS: usize = 256;

struct Entry<T> {
    fetched_at: Instant,
    value: T,
}

pub struct SingleFlightCache<T> {
    ttl: Duration,
    entries: Mutex<HashMap<String, Entry<T>>>,
    flights: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl<T: Clone> SingleFlightCache<T> {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
            flights: Mutex::new(HashMap::new()),
        }
    }

    fn fresh(&self, key: &str) -> Option<T> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .get(key)
            .filter(|entry| entry.fetched_at.elapsed() < self.ttl)
            .map(|entry| entry.value.clone())
    }

    fn stale(&self, key: &str) -> Option<T> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.get(key).map(|entry| entry.value.clone())
    }

    fn store(&self, key: &str, value: T) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= MAX_KEYS && !entries.contains_key(key) {
            // Keys are user-chosen (service filter): drop the oldest entry.
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.fetched_at)
                .map(|(key, _)| key.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            key.to_owned(),
            Entry {
                fetched_at: Instant::now(),
                value,
            },
        );
    }

    fn flight(&self, key: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut flights = self.flights.lock().unwrap_or_else(|e| e.into_inner());
        if flights.len() >= MAX_KEYS && !flights.contains_key(key) {
            // Only idle locks (no waiter or holder besides the map) are dropped.
            flights.retain(|_, lock| Arc::strong_count(lock) > 1);
        }
        flights.entry(key.to_owned()).or_default().clone()
    }

    /// Serve `key` from the cache, or run `load` once for all concurrent
    /// callers. `bypass` skips the fresh entry (an explicit refresh) but
    /// still joins an in-flight load. Returns `(value, from_cache)`.
    pub async fn get_or_load<E, F, Fut>(
        &self,
        key: &str,
        bypass: bool,
        load: F,
    ) -> Result<(T, bool), E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        if !bypass {
            if let Some(value) = self.fresh(key) {
                return Ok((value, true));
            }
        }
        let flight = self.flight(key);
        let started = Instant::now();
        let _guard = flight.lock().await;
        // Another caller refreshed while we waited: reuse its result.
        {
            let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = entries.get(key) {
                if entry.fetched_at >= started || (!bypass && entry.fetched_at.elapsed() < self.ttl) {
                    return Ok((entry.value.clone(), true));
                }
            }
        }
        match load().await {
            Ok(value) => {
                self.store(key, value.clone());
                Ok((value, false))
            }
            Err(error) => match self.stale(key) {
                Some(value) => {
                    tracing::warn!(key, "metric catalog refresh failed; serving the last good catalog");
                    Ok((value, true))
                }
                None => Err(error),
            },
        }
    }
}

#[cfg(test)]
#[path = "metric_catalog_tests.rs"]
mod tests;
