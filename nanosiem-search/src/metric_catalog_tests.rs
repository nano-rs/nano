// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn concurrent_misses_share_one_load_and_reuse_it() {
    let cache = Arc::new(SingleFlightCache::<u32>::new(Duration::from_secs(60)));
    let loads = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let cache = cache.clone();
        let loads = loads.clone();
        tasks.push(tokio::spawn(async move {
            cache
                .get_or_load("k", false, || async {
                    loads.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok::<_, ()>(7)
                })
                .await
                .unwrap()
                .0
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), 7);
    }
    assert_eq!(loads.load(Ordering::SeqCst), 1, "one scan for eight concurrent misses");
    let (value, cached) = cache
        .get_or_load("k", false, || async { Ok::<_, ()>(9) })
        .await
        .unwrap();
    assert_eq!((value, cached), (7, true));
}

#[tokio::test]
async fn expiry_bypass_and_stale_on_error() {
    let cache = SingleFlightCache::<u32>::new(Duration::from_millis(20));
    assert_eq!(cache.get_or_load("k", false, || async { Ok::<_, ()>(1) }).await.unwrap(), (1, false));
    // bypass refreshes even while fresh
    assert_eq!(cache.get_or_load("k", true, || async { Ok::<_, ()>(2) }).await.unwrap(), (2, false));
    tokio::time::sleep(Duration::from_millis(30)).await;
    // expired + failing refresh: last good value, flagged cached
    assert_eq!(cache.get_or_load("k", false, || async { Err::<u32, _>("down") }).await.unwrap(), (2, true));
    // no prior value: the error surfaces
    assert_eq!(cache.get_or_load("other", false, || async { Err::<u32, _>("down") }).await, Err("down"));
}

#[tokio::test]
async fn key_count_is_bounded() {
    let cache = SingleFlightCache::<usize>::new(Duration::from_secs(60));
    for i in 0..(MAX_KEYS + 10) {
        let key = format!("svc-{i}");
        cache.get_or_load(&key, false, || async move { Ok::<_, ()>(i) }).await.unwrap();
    }
    assert!(cache.entries.lock().unwrap().len() <= MAX_KEYS);
    assert!(cache.flights.lock().unwrap().len() <= MAX_KEYS);
}
