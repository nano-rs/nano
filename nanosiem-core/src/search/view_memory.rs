// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3282: memory budgets for product-view assembly.
//!
//! The Asset / Cloud / tree / prevalence views read ClickHouse answers into
//! the search process and decode them to `serde_json::Value`. A single
//! busy-host view (or a UI polling the same view while earlier answers are
//! still in flight) must never be able to OOM the process.
//!
//! Two bounds, both charged as ClickHouse response bytes are *received*
//! (before they are decoded):
//!
//! 1. **Per request** — a [`ViewMemoryLedger`] accumulates every byte read on
//!    behalf of one view request. Past its budget the read stops with
//!    [`SearchError::ViewTooLarge`] (HTTP 413, "narrow the window").
//! 2. **Process wide** — every ledger reserves its bytes from one shared
//!    [`Semaphore`] whose permits are MiB. Concurrent views therefore cannot
//!    hold more than the global budget at once; a request that cannot reserve
//!    within the wait window fails with [`SearchError::ViewMemoryBusy`]
//!    (HTTP 503, retryable). Reservations are released when the ledger drops,
//!    i.e. when the request (or the background snapshot build) finishes.
//!
//! The ledger is carried as a task-local, so the ClickHouse executor accounts
//! every response read inside a scoped view without each call site threading
//! it through. Reads outside a scope (ordinary searches, jobs) are unaffected.
//!
//! Wire bytes are charged times [`DECODE_AMPLIFICATION`]: the raw body and its
//! decoded `serde_json::Value` tree are resident together, and a JSON row
//! decodes to a few times its wire size.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use super::SearchError;

pub const MIB: u64 = 1024 * 1024;

/// Resident bytes charged per wire byte (raw body + decoded value tree).
pub const DECODE_AMPLIFICATION: u64 = 3;

/// Share of the container memory limit all in-flight views may hold.
const GLOBAL_SHARE_PERCENT: u64 = 40;
/// Global budget when no cgroup limit is readable (dev hosts, unlimited pods).
const FALLBACK_GLOBAL_BYTES: u64 = 384 * MIB;
/// One request may hold at most this share of the global budget, so a few
/// views can always proceed side by side.
const REQUEST_SHARE_DIVISOR: u64 = 3;
/// Neither budget goes below this (tiny limits or overrides stay usable).
const MIN_BUDGET_BYTES: u64 = 16 * MIB;
/// How long a view waits for global headroom before a retryable 503.
const DEFAULT_WAIT: Duration = Duration::from_secs(5);
/// Charge the ledger at most once per this many wire bytes while streaming.
/// Executor reads charge the ledger at most once per this many wire bytes.
pub const CHARGE_STEP_BYTES: u64 = 256 * 1024;

pub const ENV_GLOBAL_MIB: &str = "NANO_SEARCH_VIEW_MEMORY_MIB";
pub const ENV_REQUEST_MIB: &str = "NANO_SEARCH_VIEW_REQUEST_MIB";
pub const ENV_WAIT_MS: &str = "NANO_SEARCH_VIEW_MEMORY_WAIT_MS";

const CGROUP_V2_MEMORY_MAX: &str = "/sys/fs/cgroup/memory.max";
const CGROUP_V1_MEMORY_LIMIT: &str = "/sys/fs/cgroup/memory/memory.limit_in_bytes";

/// Parse a cgroup memory limit file (`memory.max` on v2,
/// `memory.limit_in_bytes` on v1). `max`, empty, garbage and the v1
/// "unlimited" sentinel (a page-aligned value near `i64::MAX`) are `None`.
pub fn parse_cgroup_memory_limit(contents: &str) -> Option<u64> {
    let value = contents.trim();
    if value.is_empty() || value == "max" {
        return None;
    }
    let bytes = value.parse::<u64>().ok()?;
    // v1 reports "no limit" as 0x7FFFFFFFFFFFF000; anything past 1 PiB is
    // not a real container limit.
    (bytes > 0 && bytes < (1 << 50)).then_some(bytes)
}

fn read_cgroup_memory_limit() -> Option<u64> {
    [CGROUP_V2_MEMORY_MAX, CGROUP_V1_MEMORY_LIMIT]
        .into_iter()
        .find_map(|path| std::fs::read_to_string(path).ok().and_then(|text| parse_cgroup_memory_limit(&text)))
}

/// The derived budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewMemoryConfig {
    /// All in-flight views together.
    pub global_bytes: u64,
    /// One view request (never more than `global_bytes`).
    pub request_bytes: u64,
    /// Longest wait for global headroom.
    pub wait: Duration,
}

impl ViewMemoryConfig {
    /// Derive the budgets: overrides win; otherwise the global budget is
    /// [`GLOBAL_SHARE_PERCENT`] of the container limit (or a conservative
    /// constant) and one request gets a third of it.
    pub fn derive(
        cgroup_limit_bytes: Option<u64>,
        global_override_mib: Option<u64>,
        request_override_mib: Option<u64>,
        wait_override_ms: Option<u64>,
    ) -> Self {
        let global_bytes = global_override_mib
            .map(|mib| mib.saturating_mul(MIB))
            .or_else(|| cgroup_limit_bytes.map(|limit| limit / 100 * GLOBAL_SHARE_PERCENT))
            .unwrap_or(FALLBACK_GLOBAL_BYTES)
            .max(MIN_BUDGET_BYTES);
        let request_bytes = request_override_mib
            .map(|mib| mib.saturating_mul(MIB))
            .unwrap_or(global_bytes / REQUEST_SHARE_DIVISOR)
            .max(MIN_BUDGET_BYTES)
            .min(global_bytes);
        let wait = wait_override_ms.map(Duration::from_millis).unwrap_or(DEFAULT_WAIT);
        Self { global_bytes, request_bytes, wait }
    }

    /// From the process environment and the container's cgroup limit.
    pub fn from_environment() -> Self {
        let env_u64 = |name: &str| {
            std::env::var(name)
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .filter(|value| *value > 0)
        };
        Self::derive(
            read_cgroup_memory_limit(),
            env_u64(ENV_GLOBAL_MIB),
            env_u64(ENV_REQUEST_MIB),
            env_u64(ENV_WAIT_MS),
        )
    }
}

/// The process-wide budget every view ledger reserves from.
#[derive(Debug)]
pub struct ViewMemoryBudget {
    config: ViewMemoryConfig,
    semaphore: Arc<Semaphore>,
    total_mib: u32,
}

static GLOBAL: OnceLock<Arc<ViewMemoryBudget>> = OnceLock::new();

impl ViewMemoryBudget {
    pub fn new(config: ViewMemoryConfig) -> Arc<Self> {
        let total_mib = u32::try_from(config.global_bytes / MIB)
            .unwrap_or(u32::MAX)
            .clamp(1, Semaphore::MAX_PERMITS as u32);
        Arc::new(Self { config, semaphore: Arc::new(Semaphore::new(total_mib as usize)), total_mib })
    }

    /// The process budget, derived once from the environment.
    pub fn global() -> &'static Arc<Self> {
        GLOBAL.get_or_init(|| {
            let budget = Self::new(ViewMemoryConfig::from_environment());
            tracing::info!(
                global_mib = budget.config.global_bytes / MIB,
                request_mib = budget.config.request_bytes / MIB,
                wait_ms = budget.config.wait.as_millis() as u64,
                "product-view memory budget configured"
            );
            budget
        })
    }

    pub fn config(&self) -> ViewMemoryConfig {
        self.config
    }

    /// MiB currently free for new reservations.
    pub fn available_mib(&self) -> u32 {
        self.semaphore.available_permits() as u32
    }

    pub fn total_mib(&self) -> u32 {
        self.total_mib
    }

    /// A fresh per-request ledger for `view`.
    pub fn ledger(self: &Arc<Self>, view: &str) -> Arc<ViewMemoryLedger> {
        Arc::new(ViewMemoryLedger {
            budget: self.clone(),
            view: view.to_string(),
            charged: AtomicU64::new(0),
            reservation: Mutex::new(Reservation::default()),
        })
    }
}

#[derive(Debug, Default)]
struct Reservation {
    mib: u32,
    permit: Option<OwnedSemaphorePermit>,
}

/// Bytes read on behalf of one view request, reserved from the global budget.
/// Dropping it releases the reservation.
#[derive(Debug)]
pub struct ViewMemoryLedger {
    budget: Arc<ViewMemoryBudget>,
    view: String,
    charged: AtomicU64,
    reservation: Mutex<Reservation>,
}

impl ViewMemoryLedger {
    pub fn view(&self) -> &str {
        &self.view
    }

    /// Resident bytes charged so far.
    pub fn charged_bytes(&self) -> u64 {
        self.charged.load(Ordering::Relaxed)
    }

    /// MiB reserved from the global budget.
    pub async fn reserved_mib(&self) -> u32 {
        self.reservation.lock().await.mib
    }

    /// Charge `bytes` of resident memory: refuse past the request budget,
    /// then reserve the covering MiB from the global budget, waiting at most
    /// the configured window for headroom.
    pub async fn charge(&self, bytes: u64) -> Result<(), SearchError> {
        let config = self.budget.config;
        let mut reservation = self.reservation.lock().await;
        let needed = self.charged.load(Ordering::Relaxed).saturating_add(bytes);
        if needed > config.request_bytes {
            tracing::warn!(
                view = %self.view,
                needed_bytes = needed,
                budget_bytes = config.request_bytes,
                "product view refused: over its per-request memory budget"
            );
            return Err(SearchError::ViewTooLarge {
                view: self.view.clone(),
                needed_bytes: needed,
                budget_bytes: config.request_bytes,
            });
        }
        let needed_mib = u32::try_from(needed.div_ceil(MIB)).unwrap_or(u32::MAX);
        if needed_mib > reservation.mib {
            let extra = needed_mib - reservation.mib;
            let started = std::time::Instant::now();
            let acquired = tokio::time::timeout(
                config.wait,
                self.budget.semaphore.clone().acquire_many_owned(extra),
            )
            .await;
            let permit = match acquired {
                Ok(Ok(permit)) => permit,
                Ok(Err(_closed)) => {
                    return Err(SearchError::ViewMemoryBusy {
                        view: self.view.clone(),
                        waited_ms: 0,
                    })
                }
                Err(_elapsed) => {
                    let waited_ms = started.elapsed().as_millis() as u64;
                    tracing::warn!(
                        view = %self.view,
                        wanted_mib = extra,
                        held_mib = reservation.mib,
                        available_mib = self.budget.available_mib(),
                        waited_ms,
                        "product view refused: process-wide view memory budget is busy"
                    );
                    return Err(SearchError::ViewMemoryBusy { view: self.view.clone(), waited_ms });
                }
            };
            match reservation.permit.as_mut() {
                Some(held) => held.merge(permit),
                None => reservation.permit = Some(permit),
            }
            reservation.mib = needed_mib;
        }
        self.charged.store(needed, Ordering::Relaxed);
        Ok(())
    }
}

tokio::task_local! {
    static LEDGER: Arc<ViewMemoryLedger>;
}

/// Run `future` with `ledger` accounting every ClickHouse response it reads.
pub async fn scope<F: Future>(ledger: Arc<ViewMemoryLedger>, future: F) -> F::Output {
    LEDGER.scope(ledger, future).await
}

/// Run `future` under a fresh ledger from the process budget.
pub async fn scoped<F: Future>(view: &str, future: F) -> F::Output {
    scope(ViewMemoryBudget::global().ledger(view), future).await
}

/// Like [`scoped`], but an enclosing view keeps its own ledger (its budget
/// already covers this work; a nested ledger would double-reserve).
pub async fn scoped_if_absent<F: Future>(view: &str, future: F) -> F::Output {
    match current() {
        Some(_) => future.await,
        None => scoped(view, future).await,
    }
}

/// The ledger of the current view, if any.
pub fn current() -> Option<Arc<ViewMemoryLedger>> {
    LEDGER.try_with(Arc::clone).ok()
}

/// Charge `wire_bytes` of a ClickHouse response (amplified for its decoded
/// form) to the current view; a no-op outside a view scope.
///
/// Boxed (type-erased): this sits deep inside every executor read, and
/// callers such as meloD tool futures are already near rustc's layout query
/// depth limit.
pub fn charge_wire_bytes(wire_bytes: u64) -> BoxFuture<'static, Result<(), SearchError>> {
    Box::pin(async move {
        match current() {
            Some(ledger) => ledger.charge(wire_bytes.saturating_mul(DECODE_AMPLIFICATION)).await,
            None => Ok(()),
        }
    })
}

#[cfg(test)]
#[path = "view_memory_tests.rs"]
mod tests;
