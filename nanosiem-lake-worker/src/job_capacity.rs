// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MEMORY_UNIT: u64 = 1024 * 1024;

pub fn container_memory_budget(limit: u64) -> u64 {
    (limit / 5 * 4) / MEMORY_UNIT * MEMORY_UNIT
}

/// Reservations include idle warm engines as well as executing attempts.
pub struct JobMemoryBudget(Arc<Semaphore>);

impl JobMemoryBudget {
    pub fn new(bytes: u64) -> Self {
        Self(Arc::new(Semaphore::new((bytes / MEMORY_UNIT) as usize)))
    }

    pub async fn reserve(&self, bytes: u64) -> OwnedSemaphorePermit {
        self.0
            .clone()
            .acquire_many_owned(bytes.div_ceil(MEMORY_UNIT) as u32)
            .await
            .expect("job memory budget is never closed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn two_medium_jobs_overlap_but_large_waits_for_both() {
        let budget = JobMemoryBudget::new(32 << 30);
        let first = budget.reserve(16 << 30).await;
        let second = tokio::time::timeout(Duration::from_millis(100), budget.reserve(16 << 30))
            .await
            .expect("second medium must not serialize behind first");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), budget.reserve(16 << 30))
                .await
                .is_err()
        );
        drop(first);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), budget.reserve(32 << 30))
                .await
                .is_err()
        );
        drop(second);
        let _large = tokio::time::timeout(Duration::from_millis(100), budget.reserve(32 << 30))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_container_capped_large_job_can_reserve_the_entire_budget() {
        let bytes = container_memory_budget(8 << 30);
        assert!(bytes < 8 << 30);
        let budget = JobMemoryBudget::new(bytes);
        let _large = tokio::time::timeout(Duration::from_millis(100), budget.reserve(bytes))
            .await
            .expect("fractional MiB cgroup headroom must not strand Large jobs");
    }

    #[tokio::test]
    async fn fractional_memory_reservations_round_up() {
        let budget = JobMemoryBudget::new(MEMORY_UNIT * 2);
        let _first = budget.reserve(MEMORY_UNIT + 1).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), budget.reserve(1))
                .await
                .is_err()
        );
    }
}

#[derive(Default)]
pub struct JobPhaseTimings {
    pub claim_ms: Option<u64>,
    pub hydrate_verify_ms: Option<u64>,
    pub execute_ms: Option<u64>,
    pub upload_ms: Option<u64>,
    pub complete_ms: Option<u64>,
}

impl JobPhaseTimings {
    pub fn log(&self, job_id: &str) {
        tracing::info!(
            job_id,
            claim_ms = self.claim_ms,
            hydrate_verify_ms = self.hydrate_verify_ms,
            execute_ms = self.execute_ms,
            upload_ms = self.upload_ms,
            complete_ms = self.complete_ms,
            "durable job phase timings"
        );
    }
}

#[cfg(test)]
mod timing_tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn structured_events_expose_all_phase_timings() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let capture = Capture(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(move || capture.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            JobPhaseTimings {
                claim_ms: Some(1),
                hydrate_verify_ms: Some(2),
                execute_ms: Some(3),
                upload_ms: Some(4),
                complete_ms: Some(5),
            }
            .log("test-job");
        });
        let event: serde_json::Value = serde_json::from_slice(&bytes.lock().unwrap()).unwrap();
        for (field, duration) in [
            ("claim_ms", 1),
            ("hydrate_verify_ms", 2),
            ("execute_ms", 3),
            ("upload_ms", 4),
            ("complete_ms", 5),
        ] {
            assert_eq!(event["fields"][field], duration);
        }
    }
}
