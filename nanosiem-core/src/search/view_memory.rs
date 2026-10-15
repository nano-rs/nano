// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3282: memory budgets for product-view assembly.
//!
//! The Asset / Cloud / tree / prevalence views read lake responses into the
//! search process and decode them to `serde_json::Value`. One shared search
//! pod serves every tenant, so a single busy-host view (or a UI polling the
//! same view every two seconds while earlier answers are still in flight) must
//! never be able to OOM the process.
//!
//! Two bounds, both charged as lake response bodies are *received* (before
//! they are decoded):
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
//! The ledger is carried as a task-local, so the lake client accounts every
//! response read inside a scoped view without each call site threading it
//! through. Reads outside a scope (ordinary searches, jobs) are unaffected.
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
const CHARGE_STEP_BYTES: u64 = 256 * 1024;

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
                    return Err(SearchError::ServiceUnavailable(
                        "product-view memory budget is closed".to_string(),
                    ))
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

/// Run `future` with `ledger` accounting every lake response it reads.
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

/// Charge `wire_bytes` of a lake response (amplified for its decoded form)
/// to the current view; a no-op outside a view scope.
///
/// Boxed (type-erased) like [`read_body`]: these sit deep inside every lake
/// read, and callers such as meloD tool futures are already near rustc's
/// layout query depth limit.
pub fn charge_wire_bytes(wire_bytes: u64) -> BoxFuture<'static, Result<(), SearchError>> {
    Box::pin(async move {
        match current() {
            Some(ledger) => ledger.charge(wire_bytes.saturating_mul(DECODE_AMPLIFICATION)).await,
            None => Ok(()),
        }
    })
}

/// Read a response body, charging it to the current view as it arrives so an
/// oversized answer is refused before it is fully buffered or decoded.
/// Outside a view scope this is `response.bytes()`.
pub fn read_body<'a>(
    response: reqwest::Response,
    map_error: impl Fn(reqwest::Error) -> SearchError + Send + Sync + 'a,
) -> BoxFuture<'a, Result<bytes::Bytes, SearchError>> {
    Box::pin(async move {
        let Some(ledger) = current() else {
            return response.bytes().await.map_err(map_error);
        };
        read_body_charged(response, &ledger, map_error).await
    })
}

async fn read_body_charged(
    mut response: reqwest::Response,
    ledger: &ViewMemoryLedger,
    map_error: impl Fn(reqwest::Error) -> SearchError,
) -> Result<bytes::Bytes, SearchError> {
    // A declared length is charged up front: an oversized answer is refused
    // without reading it.
    if let Some(length) = response.content_length() {
        ledger.charge(length.saturating_mul(DECODE_AMPLIFICATION)).await?;
        return response.bytes().await.map_err(map_error);
    }
    let mut body = bytes::BytesMut::new();
    let mut pending = 0u64;
    while let Some(chunk) = response.chunk().await.map_err(&map_error)? {
        pending += chunk.len() as u64;
        body.extend_from_slice(&chunk);
        if pending >= CHARGE_STEP_BYTES {
            ledger.charge(pending.saturating_mul(DECODE_AMPLIFICATION)).await?;
            pending = 0;
        }
    }
    if pending > 0 {
        ledger.charge(pending.saturating_mul(DECODE_AMPLIFICATION)).await?;
    }
    Ok(body.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(global_mib: u64, request_mib: u64, wait_ms: u64) -> Arc<ViewMemoryBudget> {
        ViewMemoryBudget::new(ViewMemoryConfig::derive(
            None,
            Some(global_mib),
            Some(request_mib),
            Some(wait_ms),
        ))
    }

    #[test]
    fn cgroup_limits_parse_v1_and_v2_shapes() {
        assert_eq!(parse_cgroup_memory_limit("1073741824\n"), Some(1 << 30));
        assert_eq!(parse_cgroup_memory_limit("max\n"), None);
        assert_eq!(parse_cgroup_memory_limit(""), None);
        assert_eq!(parse_cgroup_memory_limit("0"), None);
        assert_eq!(parse_cgroup_memory_limit("garbage"), None);
        // cgroup v1 "unlimited".
        assert_eq!(parse_cgroup_memory_limit("9223372036854771712"), None);
    }

    #[test]
    fn budgets_derive_from_the_container_limit() {
        // The incident pod: a 1 GiB limit → ~40% for views, a third per request.
        let config = ViewMemoryConfig::derive(Some(1 << 30), None, None, None);
        assert_eq!(config.global_bytes, (1u64 << 30) / 100 * 40);
        assert_eq!(config.request_bytes, config.global_bytes / 3);
        assert_eq!(config.wait, DEFAULT_WAIT);

        // No readable limit → the conservative constant.
        let config = ViewMemoryConfig::derive(None, None, None, None);
        assert_eq!(config.global_bytes, FALLBACK_GLOBAL_BYTES);

        // Overrides win; a request never exceeds the global budget; floors hold.
        let config = ViewMemoryConfig::derive(Some(1 << 30), Some(100), Some(500), Some(250));
        assert_eq!(config.global_bytes, 100 * MIB);
        assert_eq!(config.request_bytes, 100 * MIB);
        assert_eq!(config.wait, Duration::from_millis(250));
        let config = ViewMemoryConfig::derive(Some(MIB), None, None, None);
        assert_eq!(config.global_bytes, MIN_BUDGET_BYTES);
        assert_eq!(config.request_bytes, MIN_BUDGET_BYTES);
    }

    #[tokio::test]
    async fn a_request_over_its_budget_is_a_typed_view_too_large() {
        let budget = budget(64, 16, 100);
        let ledger = budget.ledger("asset-dossier");
        ledger.charge(10 * MIB).await.expect("within budget");
        let error = ledger.charge(7 * MIB).await.expect_err("over the per-request budget");
        match error {
            SearchError::ViewTooLarge { view, needed_bytes, budget_bytes } => {
                assert_eq!(view, "asset-dossier");
                assert_eq!(needed_bytes, 17 * MIB);
                assert_eq!(budget_bytes, 16 * MIB);
            }
            other => panic!("expected ViewTooLarge, got {other:?}"),
        }
        // The refused charge is not recorded and nothing leaks.
        assert_eq!(ledger.charged_bytes(), 10 * MIB);
        drop(ledger);
        assert_eq!(budget.available_mib(), 64);
    }

    #[tokio::test]
    async fn concurrent_requests_are_bounded_by_the_global_budget() {
        let budget = budget(32, 16, 50);
        let first = budget.ledger("asset-events");
        let second = budget.ledger("asset-events");
        first.charge(16 * MIB).await.expect("first fits");
        second.charge(16 * MIB).await.expect("second fits");
        assert_eq!(budget.available_mib(), 0);

        // A third request cannot reserve while both hold their bytes.
        let third = budget.ledger("asset-artifacts");
        let error = third.charge(MIB).await.expect_err("global budget exhausted");
        assert!(matches!(error, SearchError::ViewMemoryBusy { .. }), "got {error:?}");
        assert_eq!(third.charged_bytes(), 0);

        // Finishing one request releases its reservation for the next.
        drop(first);
        assert_eq!(budget.available_mib(), 16);
        third.charge(MIB).await.expect("headroom after release");
        assert_eq!(third.reserved_mib().await, 1);
    }

    #[tokio::test]
    async fn a_waiter_proceeds_when_headroom_frees_within_the_window() {
        let budget = budget(16, 16, 2_000);
        let holder = budget.ledger("cloud-dossier");
        holder.charge(16 * MIB).await.unwrap();
        let waiter = budget.ledger("cloud-dossier");
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(holder);
        });
        waiter.charge(4 * MIB).await.expect("acquires once the holder finishes");
        release.await.unwrap();
        assert_eq!(budget.available_mib(), 12);
    }

    #[tokio::test]
    async fn reservations_grow_in_whole_mib_and_charges_outside_a_scope_are_free() {
        let budget = budget(64, 32, 50);
        let ledger = budget.ledger("tree-page");
        ledger.charge(100).await.unwrap();
        ledger.charge(100).await.unwrap();
        assert_eq!(ledger.reserved_mib().await, 1);
        ledger.charge(MIB).await.unwrap();
        assert_eq!(ledger.reserved_mib().await, 2);
        assert_eq!(budget.available_mib(), 62);

        // No scope → no accounting, never an error.
        assert!(current().is_none());
        charge_wire_bytes(u64::MAX / 4).await.expect("unscoped reads are not budgeted");

        // Inside a scope the amplified wire bytes land on the ledger.
        let scoped_ledger = budget.ledger("asset-dossier");
        scope(scoped_ledger.clone(), async {
            charge_wire_bytes(MIB).await.unwrap();
            let error = charge_wire_bytes(10 * MIB).await.expect_err("amplified over 32 MiB");
            assert!(matches!(error, SearchError::ViewTooLarge { .. }));
        })
        .await;
        assert_eq!(scoped_ledger.charged_bytes(), DECODE_AMPLIFICATION * MIB);
    }

    #[tokio::test]
    async fn scoped_if_absent_keeps_an_enclosing_ledger_and_scopes_bare_work() {
        let budget = budget(64, 32, 50);
        let outer = budget.ledger("asset-dossier");
        scope(outer.clone(), async {
            scoped_if_absent("detection rule", async {
                assert_eq!(current().expect("still scoped").view(), "asset-dossier");
                charge_wire_bytes(MIB).await.unwrap();
            })
            .await;
        })
        .await;
        assert_eq!(outer.charged_bytes(), DECODE_AMPLIFICATION * MIB);

        // Bare work (a scheduled detection rule) gets its own ledger.
        assert!(current().is_none());
        let view = scoped_if_absent("detection rule", async {
            current().map(|ledger| ledger.view().to_string())
        })
        .await;
        assert_eq!(view.as_deref(), Some("detection rule"));
    }
}
