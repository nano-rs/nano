// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3094: short-TTL, single-flight registry for lean product-view work.
//!
//! The Asset page used to fire four typed endpoints in parallel, and three of
//! them (dossier, artifact summary, artifact occurrences) each re-ran the same
//! identity discovery plus a 50k-row host scan against query[T]: six scans per
//! page load, which is what exhausted the cell's interactive lanes. The views
//! now share ONE snapshot per `(tenant, scope, view identity, window)`:
//!
//! - **single-flight**: every caller for the same key gets the same handle, so
//!   the work behind it runs once however many panels ask for it;
//! - **short TTL**: a handle is reused for [`LAKE_VIEW_CACHE_TTL`], so a
//!   reload, a panel's poll or a second analyst on the same window reads it
//!   without another lake call;
//! - **failures are never cached**: the owner calls [`lake_view_forget`] when
//!   its work fails, so the next request starts over.
//!
//! The registry is process-wide (tenant views are cloned per request) and the
//! tenant id is part of every key, so one tenant can never read another
//! tenant's snapshot. The caller's effective source scope is part of the key
//! too: two callers with different deny-sets never share a snapshot.

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// How long a handle is served after it was created.
pub(crate) const LAKE_VIEW_CACHE_TTL: Duration = Duration::from_secs(120);
/// Most handles held at once (all tenants). The oldest is evicted first.
const LAKE_VIEW_CACHE_CAPACITY: usize = 256;

struct Slot {
    created: Instant,
    /// A pinned slot (work still in progress) never expires; its TTL starts
    /// when it is unpinned.
    pinned: bool,
    value: Arc<dyn Any + Send + Sync>,
}

fn slots() -> &'static Mutex<HashMap<String, Slot>> {
    static SLOTS: OnceLock<Mutex<HashMap<String, Slot>>> = OnceLock::new();
    SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Build a cache key from its identity parts. Parts are length-prefixed so no
/// two different part lists can collide by concatenation.
pub(crate) fn lake_view_cache_key(parts: &[&str]) -> String {
    let mut key = String::new();
    for part in parts {
        key.push_str(&part.len().to_string());
        key.push(':');
        key.push_str(part);
        key.push('|');
    }
    key
}

/// The live handle for `key`, or a new one from `create` (second value
/// `true`). `replace_if` lets the caller refuse a live handle (an explicit
/// refresh refuses a finished one) so a fresh handle replaces it.
pub(crate) fn lake_view_handle<T, F>(
    key: &str,
    replace_if: impl FnOnce(&T) -> bool,
    create: F,
) -> (Arc<T>, bool)
where
    T: Send + Sync + 'static,
    F: FnOnce() -> T,
{
    let mut slots = slots()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    slots.retain(|_, slot| slot.pinned || now.duration_since(slot.created) < LAKE_VIEW_CACHE_TTL);
    if let Some(existing) = slots
        .get(key)
        .and_then(|slot| slot.value.clone().downcast::<T>().ok())
    {
        if !replace_if(&existing) {
            return (existing, false);
        }
    }
    if !slots.contains_key(key) && slots.len() >= LAKE_VIEW_CACHE_CAPACITY {
        if let Some(oldest) = slots
            .iter()
            .filter(|(_, slot)| !slot.pinned)
            .min_by_key(|(_, slot)| slot.created)
            .map(|(key, _)| key.clone())
        {
            slots.remove(&oldest);
        }
    }
    let value = Arc::new(create());
    slots.insert(
        key.to_string(),
        Slot {
            created: now,
            pinned: false,
            value: value.clone() as Arc<dyn Any + Send + Sync>,
        },
    );
    (value, true)
}

/// The live handle for `key`, if any, without creating one (NAN-3262).
pub(crate) fn lake_view_peek<T: Send + Sync + 'static>(key: &str) -> Option<Arc<T>> {
    let slots = slots()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let slot = slots.get(key)?;
    if !slot.pinned && slot.created.elapsed() >= LAKE_VIEW_CACHE_TTL {
        return None;
    }
    slot.value.clone().downcast::<T>().ok()
}

/// Pin `key` while `handle`'s work runs (it cannot expire), or unpin it and
/// start its TTL now. No-op when `key` maps to another handle.
pub(crate) fn lake_view_pin<T: Send + Sync + 'static>(key: &str, handle: &Arc<T>, pinned: bool) {
    let mut slots = slots()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(slot) = slots.get_mut(key) {
        let same = slot
            .value
            .clone()
            .downcast::<T>()
            .is_ok_and(|value| Arc::ptr_eq(&value, handle));
        if same {
            slot.pinned = pinned;
            if !pinned {
                slot.created = Instant::now();
            }
        }
    }
}

/// Drop `key` only while it still maps to `handle` (a newer handle that
/// replaced it is left alone).
pub(crate) fn lake_view_forget<T: Send + Sync + 'static>(key: &str, handle: &Arc<T>) {
    let mut slots = slots()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let same = slots.get(key).is_some_and(|slot| {
        slot.value
            .clone()
            .downcast::<T>()
            .is_ok_and(|value| Arc::ptr_eq(&value, handle))
    });
    if same {
        slots.remove(key);
    }
}

/// Compute `key` once for every concurrent caller and serve the value for
/// [`LAKE_VIEW_CACHE_TTL`]. `fresh` (an explicit refresh) skips a finished
/// value but still joins a computation in flight. Errors are not cached.
pub(crate) async fn lake_view_once<T, Fut>(
    key: &str,
    fresh: bool,
    compute: impl FnOnce() -> Fut,
) -> Result<T, crate::search::SearchError>
where
    T: Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<T, crate::search::SearchError>>,
{
    let (cell, _) = lake_view_handle(
        key,
        |cell: &tokio::sync::OnceCell<T>| fresh && cell.initialized(),
        tokio::sync::OnceCell::new,
    );
    match cell.get_or_try_init(compute).await {
        Ok(value) => Ok(value.clone()),
        Err(error) => {
            lake_view_forget(key, &cell);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_handle_per_key_until_replaced_or_forgotten() {
        let key = lake_view_cache_key(&["test-handle", &uuid::Uuid::new_v4().to_string()]);
        let (first, created) = lake_view_handle(&key, |_: &u64| false, || 1_u64);
        assert!(created);
        let (again, created) = lake_view_handle(&key, |_: &u64| false, || 2_u64);
        assert!(!created);
        assert!(Arc::ptr_eq(&first, &again));
        let (replaced, created) = lake_view_handle(&key, |_: &u64| true, || 3_u64);
        assert!(created);
        assert_eq!(*replaced, 3);
        // Forgetting the stale handle leaves the replacement in place.
        lake_view_forget(&key, &first);
        let (still, created) = lake_view_handle(&key, |_: &u64| false, || 4_u64);
        assert!(!created);
        assert_eq!(*still, 3);
        lake_view_forget(&key, &still);
        let (fresh, created) = lake_view_handle(&key, |_: &u64| false, || 5_u64);
        assert!(created);
        assert_eq!(*fresh, 5);
    }

    #[tokio::test]
    async fn once_is_single_flight_and_never_caches_errors() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let key = lake_view_cache_key(&["test-once", &uuid::Uuid::new_v4().to_string()]);
        let failed = lake_view_once::<u64, _>(&key, false, || async {
            Err(crate::search::SearchError::ResourceExhausted(
                "busy".to_string(),
            ))
        })
        .await;
        assert!(failed.is_err());
        let runs = Arc::new(AtomicUsize::new(0));
        let call = || {
            let runs = runs.clone();
            let key = key.clone();
            async move {
                lake_view_once::<u64, _>(&key, false, || async move {
                    runs.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Ok(7)
                })
                .await
            }
        };
        let (a, b) = tokio::join!(call(), call());
        assert_eq!((a.unwrap(), b.unwrap()), (7, 7));
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        let fresh = lake_view_once::<u64, _>(&key, true, || async { Ok(9) }).await;
        assert_eq!(fresh.unwrap(), 9);
    }

    #[test]
    fn keys_are_length_prefixed() {
        assert_ne!(
            lake_view_cache_key(&["ab", "c"]),
            lake_view_cache_key(&["a", "bc"])
        );
    }
}
