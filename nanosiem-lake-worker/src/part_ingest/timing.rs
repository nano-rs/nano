// SPDX-License-Identifier: AGPL-3.0-or-later
//! Process-local, value-free elapsed times. No tenant labels, I/O or global state.
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc, Mutex,
    },
    time::Instant,
};

// The final bucket is open-ended; null avoids an imprecise u64::MAX in JSON clients.
const BUCKET_US: [Option<u64>; 8] = [
    Some(1_000),
    Some(10_000),
    Some(50_000),
    Some(100_000),
    Some(500_000),
    Some(1_000_000),
    Some(5_000_000),
    None,
];

#[derive(Default)]
struct Elapsed {
    active: AtomicU64,
    finished: AtomicU64,
    total_us: AtomicU64,
    max_us: AtomicU64,
    last_us: AtomicU64,
    buckets: [AtomicU64; 8],
}

/// Labels are compile-time operation/stage names, never request data.
#[derive(Clone, Default)]
pub(super) struct Timings(Arc<Mutex<BTreeMap<&'static str, Arc<Elapsed>>>>);

impl Timings {
    pub(super) fn start(&self, label: &'static str) -> ElapsedGuard {
        let elapsed = self
            .0
            .lock()
            .expect("ingest timings")
            .entry(label)
            .or_default()
            .clone();
        elapsed.active.fetch_add(1, Relaxed);
        ElapsedGuard {
            elapsed,
            started: Instant::now(),
        }
    }

    pub(super) fn snapshot(&self) -> Value {
        let values = self.0.lock().expect("ingest timings");
        Value::Object(values.iter().map(|(name, e)| ((*name).into(), json!({
            "in_flight": e.active.load(Relaxed), "finished_total": e.finished.load(Relaxed),
            "elapsed_us_total": e.total_us.load(Relaxed), "max_us": e.max_us.load(Relaxed), "last_us": e.last_us.load(Relaxed),
            "bucket_upper_us": BUCKET_US, "bucket_counts": e.buckets.iter().map(|b| b.load(Relaxed)).collect::<Vec<_>>()
        }))).collect())
    }
}

/// Drop records every terminated scope, including errors and cancellation.
/// In-flight elapsed time is not added to the histogram until termination.
pub(super) struct ElapsedGuard {
    elapsed: Arc<Elapsed>,
    started: Instant,
}
impl Drop for ElapsedGuard {
    fn drop(&mut self) {
        let us = u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let e = &self.elapsed;
        e.total_us.fetch_add(us, Relaxed);
        e.max_us.fetch_max(us, Relaxed);
        e.last_us.store(us, Relaxed);
        e.buckets[BUCKET_US
            .iter()
            .position(|bound| bound.is_none_or(|bound| us <= bound))
            .unwrap()]
        .fetch_add(1, Relaxed);
        e.finished.fetch_add(1, Relaxed);
        e.active.fetch_sub(1, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ingest_stage_timing_cancellation_closes_only_its_own_scope() {
        let timings = Timings::default();
        let peer = Timings::default();
        let (ready, wait) = tokio::sync::oneshot::channel();
        let observed = timings.clone();
        let task = tokio::spawn(async move {
            let _scope = observed.start("authorize");
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        wait.await.unwrap();
        assert_eq!(timings.snapshot()["authorize"]["in_flight"], 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let snapshot = timings.snapshot();
        assert_eq!(snapshot["authorize"]["in_flight"], 0);
        assert_eq!(snapshot["authorize"]["finished_total"], 1);
        assert_eq!(
            snapshot["authorize"]["bucket_counts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_u64().unwrap())
                .sum::<u64>(),
            1
        );
        assert_eq!(peer.snapshot(), json!({}));
    }
}
