// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5296: the ingest-stall probe against a live ClickHouse.
//!
//! Ignored by default. `scripts/e2e/lanes/ingest-workload-deadlock.sh` runs it
//! twice on a throwaway server: once while two async-insert flushes are
//! deadlocked on migration 189's `ingest` CPU cap (`NAN5296_EXPECT=stalled`),
//! and once after migration 198 under the same load (`NAN5296_EXPECT=calm`).

use chrono::{Duration, Utc};
use nanosiem_core::ingest_stall::{probe, StallAlert, StallTracker, SLOT_SATURATION_ALERT};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

#[tokio::test]
#[ignore = "needs a live ClickHouse; run by scripts/e2e/lanes/ingest-workload-deadlock.sh"]
async fn live_stall_probe_matches_the_server_state() {
    let client = nanosiem_core::db::clickhouse_transport::client()
        .with_url(env("NAN5296_CH_URL"))
        .with_user(env("NAN5296_CH_USER"))
        .with_password(env("NAN5296_CH_PASSWORD"));
    let sample = probe(&client).await.expect("stall probe query");
    eprintln!("NAN-5296 live stall probe: {sample:?}");

    let mut tracker = StallTracker::default();
    let start = Utc::now();
    tracker.observe(&sample, start);
    let later = start + Duration::seconds(SLOT_SATURATION_ALERT.as_secs() as i64);
    let alert = tracker.observe(&sample, later);

    match env("NAN5296_EXPECT").as_str() {
        "stalled" => {
            assert!(
                sample.ingest_slots_full_with_queue,
                "the deadlocked ingest semaphore must read full with waiters: {sample:?}"
            );
            assert!(
                sample.longest_async_flush_seconds >= 30,
                "the deadlocked flush must be visible in system.processes: {sample:?}"
            );
            assert!(
                matches!(alert, StallAlert::Firing(_)),
                "a minute of saturation must fire the watchdog alert: {alert:?}"
            );
        }
        "calm" => {
            assert!(!sample.ingest_slots_full_with_queue, "{sample:?}");
            assert_eq!(sample.stuck_async_flushes, 0, "{sample:?}");
            assert_eq!(alert, StallAlert::Calm);
        }
        other => panic!("NAN5296_EXPECT must be stalled or calm, got {other:?}"),
    }
}
