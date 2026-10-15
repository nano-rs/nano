// SPDX-License-Identifier: AGPL-3.0-or-later
//! Request-local accounting. Spawned background work deliberately inherits no counters.
use std::{future::Future, sync::{Arc, atomic::{AtomicI64, AtomicU64, Ordering}}, time::Instant};

#[derive(Clone, Copy)]
pub enum Phase { Auth, Scope, Authority, Ledger, Upstream, Audit }

#[derive(Default)]
pub struct RequestTiming {
    micros: [AtomicI64; 6],
    db_roundtrips: AtomicU64,
    lake_result_cache_hits: AtomicU64,
    admission: std::sync::atomic::AtomicU8,
}

/// How an authenticated request was admitted (NAN-3231). Logged on
/// "Request completed" so `auth_ms` / `db_roundtrips` can be split by path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Admission {
    /// Public route, dedicated profile, or refused before admission ran.
    None = 0,
    /// Answered from the admission cache (one guard statement).
    Warm = 1,
    /// Cold admission through the one-snapshot definers.
    Cold = 2,
    /// Cold admission through the legacy multi-statement path.
    ColdLegacy = 3,
}

impl Admission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Warm => "warm",
            Self::Cold => "cold",
            Self::ColdLegacy => "cold_legacy",
        }
    }
}

/// Record the admission path of the current request (no-op outside a request).
pub fn record_admission(kind: Admission) {
    let _ = TIMING.try_with(|timing| timing.admission.store(kind as u8, Ordering::Relaxed));
}

tokio::task_local! {
    static TIMING: Arc<RequestTiming>;
    static PHASE: Phase;
}

impl RequestTiming {
    pub async fn scope<F: Future>(self: Arc<Self>, future: F) -> F::Output {
        TIMING.scope(self, future).await
    }

    pub fn milliseconds(&self, phase: Phase) -> f64 {
        self.micros[phase as usize].load(Ordering::Relaxed).max(0) as f64 / 1000.0
    }

    pub fn db_roundtrips(&self) -> u64 { self.db_roundtrips.load(Ordering::Relaxed) }

    pub fn admission(&self) -> Admission {
        match self.admission.load(Ordering::Relaxed) {
            1 => Admission::Warm,
            2 => Admission::Cold,
            3 => Admission::ColdLegacy,
            _ => Admission::None,
        }
    }

    /// Numeric durations only: safe on public health and failed requests too.
    /// `total` is wall time until response headers, not response-body streaming.
    pub fn server_timing(&self, total_ms: f64) -> String {
        format!(
            "total;dur={total_ms:.3}, auth;dur={:.3}, scope;dur={:.3}, authority;dur={:.3}, ledger;dur={:.3}, upstream;dur={:.3}, audit;dur={:.3}",
            self.milliseconds(Phase::Auth), self.milliseconds(Phase::Scope),
            self.milliseconds(Phase::Authority), self.milliseconds(Phase::Ledger),
            self.milliseconds(Phase::Upstream), self.milliseconds(Phase::Audit),
        )
    }
}

/// A lean cell answered this request's rows from its exact result cache.
pub fn record_lake_result_cache_hit() {
    let _ = TIMING.try_with(|timing| timing.lake_result_cache_hits.fetch_add(1, Ordering::Relaxed));
}

/// Whether this request's rows came from a lean cell's result cache (drives
/// `x-nano-cache`, since those tenants have no serving generation for the
/// search result cache to key on).
pub fn lake_result_cache_hit() -> bool {
    TIMING.try_with(|timing| timing.lake_result_cache_hits.load(Ordering::Relaxed) > 0).unwrap_or(false)
}

/// Nested phases are exclusive: time spent resolving scope is subtracted from auth.
pub async fn timed<F: Future>(phase: Phase, future: F) -> F::Output {
    let Ok(timing) = TIMING.try_with(Arc::clone) else { return future.await; };
    let parent = PHASE.try_with(|value| *value).ok();
    let _elapsed = PhaseElapsed { timing, phase, parent, start: Instant::now() };
    PHASE.scope(phase, future).await

}

struct PhaseElapsed { timing: Arc<RequestTiming>, phase: Phase, parent: Option<Phase>, start: Instant }
impl Drop for PhaseElapsed {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_micros().min(i64::MAX as u128) as i64;
        self.timing.micros[self.phase as usize].fetch_add(elapsed, Ordering::Relaxed);
        if let Some(parent) = self.parent {
            self.timing.micros[parent as usize].fetch_sub(elapsed, Ordering::Relaxed);
        }
    }
}

/// Count actual SQL executions, including failed attempts and transaction commands.
/// Pool checkout and Redis commands are not PostgreSQL round trips.
pub trait RequestDb: Future + Sized {
    fn request_db(self) -> impl Future<Output = Self::Output> + Send
    where Self: Send {
        async move {
            let _ = TIMING.try_with(|timing| timing.db_roundtrips.fetch_add(1, Ordering::Relaxed));
            self.await
        }
    }
}
impl<F: Future> RequestDb for F {}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn counts_failed_attempts_but_excludes_detached_work() {
        let timing = Arc::new(RequestTiming::default());
        timing.clone().scope(timed(Phase::Auth, async {
            let _: Result<(), ()> = async { Err(()) }.request_db().await;
            timed(Phase::Scope, async { tokio::time::sleep(std::time::Duration::from_millis(2)).await; }).await;
            tokio::spawn(async { async {}.request_db().await }).await.unwrap();
        })).await;
        assert_eq!(timing.db_roundtrips(), 1);
        assert!(timing.milliseconds(Phase::Scope) >= 2.0);
    }
}

pub fn timed_sync<T>(phase: Phase, operation: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let output = operation();
    let elapsed = start.elapsed().as_micros().min(i64::MAX as u128) as i64;
    let _ = TIMING.try_with(|timing| {
        timing.micros[phase as usize].fetch_add(elapsed, Ordering::Relaxed);
        if let Ok(parent) = PHASE.try_with(|value| *value) {
            timing.micros[parent as usize].fetch_sub(elapsed, Ordering::Relaxed);
        }
    });
    output
}
