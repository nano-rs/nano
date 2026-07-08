// SPDX-License-Identifier: AGPL-3.0-or-later

//! Synthetic-check runner (NAN-1538).
//!
//! A leader-only, panic-safe background arm that probes enabled synthetic
//! checks on their configured interval. Each tick it loads the enabled
//! definitions from PostgreSQL ([`SyntheticCheckRepository::list_enabled`]),
//! and for every check whose `interval_secs` has elapsed since its last
//! recorded result it executes one HTTP GET (reqwest, per-check timeout) and
//! writes a row into `nanosiem.synthetic_check_results` (migration 142).
//!
//! Concurrency (O47): due checks are probed concurrently with a bounded number
//! of simultaneous probes, so one slow / black-holed target (up to
//! `MAX_TIMEOUT_SECS`) can't delay every other check. An in-flight guard keeps a
//! still-running probe from being re-scheduled on the next tick.
//!
//! Failure isolation (NAN-1102): a panic anywhere in a jobs scheduler aborts
//! ALL schedulers. Synthetic probes hit arbitrary remote URLs, so per-check
//! work must NEVER panic the loop. Every probe is fallible-by-result (a failed
//! request becomes a `success=0` row, not an error that bubbles up); each probe
//! runs in its own task so a panic is isolated to that task (surfaces as a
//! `JoinError` the tick logs) and never `?`-propagates out. The outer tick loop
//! runs forever.
//!
//! Alerting (O18/O19): the PG alert spine is written *independently of* the
//! ClickHouse result row — the spine stays reachable even when ClickHouse is
//! down, which is exactly the outage a synthetic check exists to catch. Failure
//! alerts honor a durable re-arm window (one alert per window while a check
//! stays down, not one per probe), and a one-shot recovery notification fires on
//! the failing→healthy edge. Both re-arm and recovery are decided from the
//! persisted `alerts` table, so they survive a restart / leader failover.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use chrono::Utc;
use clickhouse::Client as ClickHouseClient;
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::synthetic_check_repository::{
    SyntheticCheck, SyntheticCheckRepository, SyntheticCheckRepositoryError,
};
use crate::db::repository::{AlertInsert, AlertRepository};
use crate::inputlookup::SsrfValidator;
use crate::models::Severity;
use crate::webhooks::WebhookService;

/// How often the runner wakes to look for due checks. The minimum check
/// interval is 30s (enforced at create/update), so a 15s tick guarantees a due
/// check is picked up within half its minimum interval.
const TICK_SECS: u64 = 15;

/// Hard ceiling on a single probe's request timeout regardless of the check's
/// configured `timeout_secs`, so one slow target can't stall the runner.
const MAX_TIMEOUT_SECS: u64 = 120;

/// Max probes running simultaneously within one tick (O47). Checks are probed
/// concurrently so a slow / black-holed target can't delay the rest; this caps
/// the fan-out (each probe still runs its own SSRF validation + per-request
/// timeout). Check cardinality is tier-capped, so this bound is generous.
const MAX_CONCURRENT_PROBES: usize = 16;

/// Default re-arm window (seconds) for synthetic failure/recovery alerts (O19):
/// while a check stays down, at most one failure alert per this window (not one
/// per probe). Overridable via `SYNTHETIC_REARM_SECS`; defaults to 1h. Mirrors
/// the SLO evaluator's durable cadence gate (NAN-1563).
const DEFAULT_REARM_SECS: u64 = 3600;

/// The synthetic-check runner. Cheap to clone (wraps the connection-pooling
/// `reqwest::Client` and the two DB handles).
#[derive(Clone)]
pub struct SyntheticRunner {
    repo: SyntheticCheckRepository,
    ch_client: ClickHouseClient,
    /// Whether the ClickHouse deployment is clustered (NAN-1721 O1). When true,
    /// the `due_for` READ routes to `synthetic_check_results_distributed` so it
    /// sees results from every shard; the result INSERT stays on the LOCAL table
    /// (the Distributed engine does not accept inserts here). Detected once from
    /// the pool's `TableNames` at wiring time.
    is_clustered: bool,
    /// NAN-1541: the unified alert spine. A check that probes to a status other
    /// than its `expected_status` (or errors out) raises one alert per failing
    /// probe through here with `kind = synthetic`.
    alert_repo: AlertRepository,
    /// NAN-1546: fires the raised synthetic alert to webhooks subscribed to the
    /// observability stream. `None` when no webhook service is wired (e.g. tests).
    webhook_service: Option<WebhookService>,
    /// O47: check ids with a probe currently in flight. Because `due_for`
    /// measures from the last *completed* result, a slow (black-holed) probe
    /// would otherwise be re-scheduled on every tick while it's still running;
    /// this guard drops the duplicate. Shared across the concurrent probe tasks.
    in_flight: Arc<Mutex<HashSet<Uuid>>>,
}

impl SyntheticRunner {
    /// Build a runner from the PG pool (definitions) and the ClickHouse client
    /// (results). The HTTP client carries no default timeout — each probe sets
    /// its own per-request timeout from the check's `timeout_secs`. `is_clustered`
    /// (from the pool's `TableNames`) routes the `due_for` READ to the
    /// `_distributed` wrapper on a cluster (NAN-1721 O1); the INSERT stays local.
    pub fn new(pool: PgPool, ch_client: ClickHouseClient, is_clustered: bool) -> Self {
        Self {
            repo: SyntheticCheckRepository::new(pool.clone()),
            ch_client,
            is_clustered,
            alert_repo: AlertRepository::new(pool),
            webhook_service: None,
            in_flight: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Wire the webhook service so failing-probe alerts (kind = synthetic) fire
    /// webhooks subscribed to the observability stream (NAN-1546).
    pub fn with_webhook_service(mut self, webhook_service: WebhookService) -> Self {
        self.webhook_service = Some(webhook_service);
        self
    }

    /// Spawn the runner loop. Returns the task handle for graceful shutdown.
    pub fn start(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(StdDuration::from_secs(TICK_SECS));
            // Skip the immediate first tick so startup is quiet.
            interval.tick().await;
            info!(tick_secs = TICK_SECS, "Synthetic-check runner started");
            loop {
                interval.tick().await;
                self.run_tick().await;
            }
        })
    }

    /// One scheduler tick: probe every enabled check that is due, concurrently
    /// (O47). Errors from the PG listing are logged and the tick is skipped (the
    /// loop continues); each check's probe runs in its own task so one slow
    /// target can't delay the rest, and a panic is isolated to that task —
    /// surfacing here as a `JoinError` we log, never aborting the tick or the
    /// scheduler (NAN-1102).
    async fn run_tick(&self) {
        let checks = match self.repo.list_enabled().await {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "Synthetic runner: failed to list enabled checks");
                return;
            }
        };
        if checks.is_empty() {
            return;
        }

        // Bound how many probes run at once so a burst of checks can't spawn an
        // unbounded fan-out of concurrent requests.
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES));
        let mut probes: JoinSet<()> = JoinSet::new();

        for check in checks {
            let runner = self.clone();
            let semaphore = semaphore.clone();
            probes.spawn(async move {
                // Bound simultaneous probes.
                let _permit = match semaphore.acquire_owned().await {
                    Ok(p) => p,
                    // Semaphore closed only on shutdown; nothing to do.
                    Err(_) => return,
                };

                // Per-check isolation (NAN-1102): due_for / probe_and_record
                // return Result and are logged here, never `?`-propagated.
                let due = match runner.due_for(&check).await {
                    Ok(due) => due,
                    Err(e) => {
                        warn!(check = %check.id, error = %e, "Synthetic runner: due-check query failed; skipping");
                        return;
                    }
                };
                if !due {
                    return;
                }

                // O47: skip if a probe for this check is still running from an
                // earlier tick. `due_for` measures from the last *completed*
                // result, so without this a slow probe would pile up concurrent
                // duplicates every tick. The guard frees the slot on drop —
                // including early return / panic.
                let _in_flight = match runner.try_claim(check.id) {
                    Some(guard) => guard,
                    None => {
                        debug!(check = %check.id, "Synthetic runner: probe already in flight; skipping");
                        return;
                    }
                };

                if let Err(e) = runner.probe_and_record(&check).await {
                    warn!(check = %check.id, error = %e, "Synthetic runner: probe/record failed");
                }
            });
        }

        // Drain all probe tasks. A panic inside a probe is isolated to its task
        // and surfaces as a JoinError here — logged, never aborting the scheduler.
        while let Some(res) = probes.join_next().await {
            if let Err(e) = res {
                error!(error = %e, "Synthetic runner: probe task panicked (isolated)");
            }
        }
    }

    /// Try to mark `id` as having an in-flight probe (O47). Returns a guard that
    /// frees the slot on drop, or `None` when a probe for this check is already
    /// running. A poisoned lock is recovered (we only ever mutate a `HashSet`,
    /// so the data stays consistent) rather than panicking (NAN-1102).
    fn try_claim(&self, id: Uuid) -> Option<InFlightGuard> {
        let mut set = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        if set.contains(&id) {
            return None;
        }
        set.insert(id);
        Some(InFlightGuard {
            set: self.in_flight.clone(),
            id,
        })
    }

    /// Whether `check` is due: no prior result, or the newest result is older
    /// than `interval_secs`. One bounded `max(timestamp)` read per check.
    async fn due_for(&self, check: &SyntheticCheck) -> Result<bool, clickhouse::error::Error> {
        let check_id = check.id.to_string();
        // Read routes to the `_distributed` wrapper on a cluster so the last-run
        // time reflects EVERY shard's results, not just the connected one
        // (NAN-1721 O1); local otherwise. The result INSERT in `probe_and_record`
        // must stay on the LOCAL table (the Distributed engine rejects inserts).
        let table = if self.is_clustered {
            "nanosiem.synthetic_check_results_distributed"
        } else {
            "nanosiem.synthetic_check_results"
        };
        // Parameterized via the official client's `?` binding — injection-safe.
        // (`table` is not user input: a compile-time literal chosen by cluster
        // state, so splicing it into the query text carries no injection risk.)
        let sql =
            format!("SELECT toInt64(max(timestamp) * 1000) FROM {table} WHERE check_id = ?");
        let last_ms: i64 = self
            .ch_client
            .query(&sql)
            .bind(&check_id)
            .fetch_optional::<i64>()
            .await?
            .unwrap_or(0);

        if last_ms == 0 {
            return Ok(true);
        }
        let now_ms = Utc::now().timestamp_millis();
        let elapsed_secs = (now_ms - last_ms).max(0) / 1000;
        Ok(elapsed_secs >= check.interval_secs as i64)
    }

    /// Build a reqwest client whose connection is pinned to the validated,
    /// resolved IP(s) of `target_url` — the SSRF guard for synthetic probes
    /// (the runner fetches user-supplied URLs server-side on the leader).
    ///
    /// Mirrors the enrichment downloader: `validate_with_dns` rejects bad
    /// schemes and blocked IP literals; then we resolve the host, re-validate
    /// every resolved IP, and pin reqwest to exactly those addrs so DNS can't
    /// be rebound to an internal IP after validation. Redirects are disabled so
    /// there is no second, unvalidated hop. Returns the rejection reason on
    /// block (the caller records it as the probe failure). Secure by default:
    /// private/link-local/loopback/metadata ranges are blocked.
    async fn ssrf_checked_client(target_url: &str) -> Result<reqwest::Client, String> {
        // Shared validate-then-pin guard (NAN-1617): pre-flight validation +
        // re-resolve + per-address re-validation, returning the addrs to pin.
        let (url, addrs) = SsrfValidator::http_allowed_validator()
            .validate_and_resolve(target_url)
            .await
            .map_err(|e| format!("blocked by SSRF guard: {e}"))?;

        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("nano-synthetic-monitor");

        // IP-literal hosts return an empty Vec (reqwest dials the literal,
        // already validated). DNS-name hosts: pin reqwest to the pre-validated
        // addrs so DNS can't be rebound to an internal IP after validation.
        if !addrs.is_empty() {
            let host = url.host_str().ok_or_else(|| "URL missing host".to_string())?;
            builder = builder.resolve_to_addrs(host, &addrs);
        }

        builder
            .build()
            .map_err(|e| format!("HTTP client build failed: {e}"))
    }

    /// Execute one HTTP GET for `check` and write the result row. A failed
    /// request (DNS / connect / timeout / non-2xx) is NOT an error — it is
    /// recorded as a `success=0` row. The only `Err` returned here is a
    /// ClickHouse write failure (so the tick can log it and move on).
    async fn probe_and_record(
        &self,
        check: &SyntheticCheck,
    ) -> Result<(), clickhouse::error::Error> {
        let timeout = StdDuration::from_secs((check.timeout_secs.max(1) as u64).min(MAX_TIMEOUT_SECS));

        // SSRF guard (defense-in-depth): validate + DNS-resolve the target and
        // pin the connection to the validated IP(s), so a check can never be
        // used to reach internal / link-local / cloud-metadata addresses, and
        // can't be DNS-rebound between validation and connect. A blocked target
        // is recorded as a failed probe (status 0) — it is never fetched.
        //
        // O48: `latency_ms` times ONLY the network round-trip (`send`), NOT the
        // SSRF validation + DNS resolution above (which would inflate latency and
        // vary with resolver speed), and is `0` for a blocked / never-sent probe.
        let (status_code, error, latency_ms) =
            match Self::ssrf_checked_client(&check.target_url).await {
                Err(reason) => {
                    let mut msg = reason;
                    msg.truncate(500);
                    // Blocked before any request left the box — no round-trip to time.
                    (0u16, msg, 0.0_f64)
                }
                Ok(client) => {
                    let started = std::time::Instant::now();
                    let sent = client.get(&check.target_url).timeout(timeout).send().await;
                    let latency_ms = started.elapsed().as_secs_f64() * 1000.0;
                    match sent {
                        Ok(resp) => (resp.status().as_u16(), String::new(), latency_ms),
                        Err(e) => {
                            // No HTTP status observed (DNS/connect/timeout). status_code=0.
                            // The elapsed send() time is still meaningful latency
                            // (e.g. a timeout at the configured deadline).
                            let mut msg = e.to_string();
                            msg.truncate(500);
                            (0u16, msg, latency_ms)
                        }
                    }
                }
            };

        let success = if status_code as i32 == check.expected_status {
            1u8
        } else {
            0u8
        };
        let now_ms = Utc::now().timestamp_millis();

        debug!(
            check = %check.id,
            status = status_code,
            success,
            latency_ms,
            "Synthetic probe complete"
        );

        // O49: a probe started this tick may finish after its check was deleted
        // (the tick worked off a `list_enabled` snapshot). Re-check existence
        // before writing a result or raising any alert so a just-deleted check
        // can't emit an orphaned result / a late alert. `NotFound` == deleted →
        // discard this probe silently. A transient PG error is NOT a delete: fail
        // open and proceed rather than drop a real probe result.
        match self.repo.get(check.id).await {
            Ok(_) => {}
            Err(SyntheticCheckRepositoryError::NotFound(_)) => {
                debug!(check = %check.id, "Synthetic check deleted mid-probe; discarding result");
                return Ok(());
            }
            Err(e) => {
                warn!(check = %check.id, error = %e, "Synthetic runner: existence re-check failed; proceeding");
            }
        }

        // O18: raise the failure/recovery notification through the PG alert spine
        // FIRST, independent of the ClickHouse result write below. The spine (PG)
        // stays reachable even when ClickHouse is down — the very outage a
        // synthetic check exists to catch — so the CH insert's success must not
        // gate whether the alert fires. O19: failure alerts honor a durable
        // re-arm window (one per window, not one per probe — NAN-1541's
        // one-alert-per-probe storm is gone), and a one-shot recovery
        // notification fires on the failing→healthy edge. A PG raise failure is
        // logged inside these helpers, never propagated (NAN-1102).
        if success == 0 {
            self.maybe_raise_failure_alert(check, status_code, &error).await;
        } else {
            self.maybe_raise_recovery(check).await;
        }

        // Record the probe result in ClickHouse. DateTime64(3) <- millis (the
        // column's CODEC is Delta,ZSTD; the official client serializes the bound
        // i64 into the 3-precision column). A write failure is returned so the
        // tick logs it; the alert above already fired independently (O18).
        self.ch_client
            .query(
                "INSERT INTO nanosiem.synthetic_check_results \
                 (check_id, timestamp, success, latency_ms, status_code, error) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(check.id.to_string())
            .bind(now_ms)
            .bind(success)
            .bind(latency_ms)
            .bind(status_code)
            .bind(&error)
            .execute()
            .await?;

        Ok(())
    }

    /// Failure-alert gate (O19). Consults the durable re-arm authority — the
    /// persisted `alerts` table via
    /// [`AlertRepository::latest_alert_at_for_source`] keyed on the bare check id
    /// — and raises at most one `kind:"synthetic"` alert per re-arm window while a
    /// check stays down, instead of one per probe. Because the authority is the
    /// persisted table, the gate survives a jobs restart / leader failover. On a
    /// lookup error we skip raising this tick rather than risk an alert storm
    /// without the guard; the ClickHouse result row still records the failure.
    async fn maybe_raise_failure_alert(
        &self,
        check: &SyntheticCheck,
        status_code: u16,
        error: &str,
    ) {
        let source_id = check.id.to_string();
        let rearm_secs = rearm_window_secs();

        match self
            .alert_repo
            .latest_alert_at_for_source("synthetic", &source_id)
            .await
        {
            Ok(Some(last)) => {
                let elapsed = (Utc::now() - last).num_seconds();
                // Within the window (or a future timestamp from clock skew) →
                // still armed; suppress. Time-based, so a momentary recovery
                // between ticks does not reset the window (mirrors the SLO
                // evaluator's re-arm philosophy).
                if elapsed < 0 || (elapsed as u64) < rearm_secs {
                    debug!(check = %check.id, "Synthetic failure within re-arm window; alert suppressed");
                    return;
                }
            }
            // No prior failure alert for this check — raise.
            Ok(None) => {}
            Err(e) => {
                warn!(check = %check.id, error = %e, "Synthetic runner: re-arm lookup failed; skipping alert");
                return;
            }
        }

        self.raise_failure_alert(check, status_code, error).await;
    }

    /// Recovery-notification gate (O19). On a *successful* probe, fire exactly
    /// one recovery notification per failing→healthy edge. Fully durable
    /// (restart / failover-safe): compare the most recent failure alert (keyed on
    /// the bare check id) against the most recent recovery alert (keyed on the
    /// `:recovered` source) — a recovery is due only when the last failure is
    /// newer than the last recovery. Keying recovery on a distinct source id
    /// keeps recovery rows out of the failure re-arm lookup above, so a
    /// recover→re-fail flap can't suppress the next real failure. A lookup error
    /// skips (no notification) rather than risk a duplicate.
    async fn maybe_raise_recovery(&self, check: &SyntheticCheck) {
        let failure_source = check.id.to_string();
        let recovery_source = recovery_source_id(check);

        let last_failure = match self
            .alert_repo
            .latest_alert_at_for_source("synthetic", &failure_source)
            .await
        {
            Ok(Some(t)) => t,
            // Never failed (no failure alert) → nothing to recover from.
            Ok(None) => return,
            Err(e) => {
                warn!(check = %check.id, error = %e, "Synthetic runner: recovery lookup failed; skipping");
                return;
            }
        };

        let last_recovery = match self
            .alert_repo
            .latest_alert_at_for_source("synthetic", &recovery_source)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!(check = %check.id, error = %e, "Synthetic runner: recovery lookup failed; skipping");
                return;
            }
        };

        // Already recovered since the last failure alert → don't re-fire.
        if let Some(recovered_at) = last_recovery {
            if recovered_at >= last_failure {
                return;
            }
        }

        self.raise_recovery_alert(check).await;
    }

    /// Build and insert a `kind = synthetic` alert for a failing probe. Errors
    /// are logged, never returned — keeping the probe path panic/error-safe.
    async fn raise_failure_alert(&self, check: &SyntheticCheck, status_code: u16, error: &str) {
        // High severity when the target is hard-down (no HTTP response at all),
        // medium for a wrong-but-present status code.
        let severity = if status_code == 0 {
            Severity::High
        } else {
            Severity::Medium
        };

        let payload = serde_json::json!([{
            "check_id": check.id.to_string(),
            "check_name": check.name,
            "target_url": check.target_url,
            "expected_status": check.expected_status,
            "observed_status": status_code,
            "error": error,
            "evaluated_at": Utc::now().to_rfc3339(),
        }]);

        match self
            .alert_repo
            .create_alert(AlertInsert {
                kind: "synthetic",
                rule_id: None,
                source_id: Some(check.id.to_string()),
                severity: &severity,
                matched_events: &payload,
                event_hash: None,
                // A13 (NAN-1752): synthetic checks have no detection match count.
                match_count: None,
            })
            .await
        {
            Ok(alert) => {
                info!(
                    check = %check.id,
                    expected = check.expected_status,
                    observed = status_code,
                    "Synthetic check failed — alert raised"
                );

                // NAN-1546: forward to webhooks on the observability stream.
                // The probe target is the entity; the check name is the human
                // label. Fire-and-forget (spawns internally) — never blocks the
                // runner tick.
                if let Some(ref webhooks) = self.webhook_service {
                    webhooks
                        .fire_alert(
                            alert.id,
                            "synthetic",
                            None,
                            &check.name,
                            &format!("{:?}", severity).to_lowercase(),
                            Some(check.target_url.clone()),
                            &payload,
                            alert.created_at,
                        )
                        .await;
                }
            }
            Err(e) => {
                warn!(
                    check = %check.id,
                    error = %e,
                    "Synthetic runner: failed to raise failure alert"
                );
            }
        }
    }

    /// Build and insert a `kind = synthetic` *recovery* alert (a probe now
    /// succeeds after a failing streak) and forward it to observability webhooks
    /// (O19). Low severity — an informational edge event. Keyed on the
    /// `:recovered` source id so it never pollutes the failure re-arm lookup; the
    /// payload's `check_id` still carries the real id for the FE. Errors are
    /// logged, never returned — keeping the probe path panic/error-safe.
    async fn raise_recovery_alert(&self, check: &SyntheticCheck) {
        let severity = Severity::Low;

        let payload = serde_json::json!([{
            "check_id": check.id.to_string(),
            "check_name": check.name,
            "target_url": check.target_url,
            "expected_status": check.expected_status,
            "status": "recovered",
            "evaluated_at": Utc::now().to_rfc3339(),
        }]);

        match self
            .alert_repo
            .create_alert(AlertInsert {
                kind: "synthetic",
                rule_id: None,
                source_id: Some(recovery_source_id(check)),
                severity: &severity,
                matched_events: &payload,
                event_hash: None,
                // A13 (NAN-1752): synthetic checks have no detection match count.
                match_count: None,
            })
            .await
        {
            Ok(alert) => {
                info!(check = %check.id, "Synthetic check recovered — recovery alert raised");

                // NAN-1546: forward to webhooks on the observability stream, same
                // as the failure path. Fire-and-forget — never blocks the tick.
                if let Some(ref webhooks) = self.webhook_service {
                    webhooks
                        .fire_alert(
                            alert.id,
                            "synthetic",
                            None,
                            &check.name,
                            &format!("{:?}", severity).to_lowercase(),
                            Some(check.target_url.clone()),
                            &payload,
                            alert.created_at,
                        )
                        .await;
                }
            }
            Err(e) => {
                warn!(
                    check = %check.id,
                    error = %e,
                    "Synthetic runner: failed to raise recovery alert"
                );
            }
        }
    }
}

/// RAII guard that removes a check id from the in-flight set on drop, so a probe
/// that returns early or panics still releases its slot (O47).
struct InFlightGuard {
    set: Arc<Mutex<HashSet<Uuid>>>,
    id: Uuid,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        // Recover from a poisoned lock (we only ever mutate the set, so its data
        // stays consistent) rather than panic on drop.
        let mut set = self.set.lock().unwrap_or_else(|e| e.into_inner());
        set.remove(&self.id);
    }
}

/// Re-arm window (seconds) for synthetic failure/recovery alerts (O19).
/// Overridable via `SYNTHETIC_REARM_SECS`; falls back to [`DEFAULT_REARM_SECS`]
/// (1h) for an unset / unparsable / non-positive value.
fn rearm_window_secs() -> u64 {
    std::env::var("SYNTHETIC_REARM_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(DEFAULT_REARM_SECS)
}

/// Alert-spine `source_id` for the *recovery* edge of a synthetic check. Kept
/// distinct from the failure source id (the bare check id) so recovery rows
/// never pollute the failure re-arm lookup; both carry `kind = "synthetic"` and
/// surface in the Observability alerts view, and the payload's `check_id` carries
/// the real id for the FE either way (O19).
fn recovery_source_id(check: &SyntheticCheck) -> String {
    format!("{}:recovered", check.id)
}
