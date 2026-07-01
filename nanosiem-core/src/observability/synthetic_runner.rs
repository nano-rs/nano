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
//! Failure isolation (NAN-1102): a panic anywhere in a jobs scheduler aborts
//! ALL schedulers. Synthetic probes hit arbitrary remote URLs, so per-check
//! work must NEVER panic the loop. Every probe is fallible-by-result (a failed
//! request becomes a `success=0` row, not an error that bubbles up) and the
//! tick body never `?`-propagates a single check's failure — it logs and
//! continues. The outer tick loop runs forever.

use std::time::Duration as StdDuration;

use chrono::Utc;
use clickhouse::Client as ClickHouseClient;
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};


use super::synthetic_check_repository::{SyntheticCheck, SyntheticCheckRepository};
use crate::db::repository::{AlertInsert, AlertRepository};
use crate::inputlookup::SsrfValidator;
use crate::models::Severity;

/// How often the runner wakes to look for due checks. The minimum check
/// interval is 30s (enforced at create/update), so a 15s tick guarantees a due
/// check is picked up within half its minimum interval.
const TICK_SECS: u64 = 15;

/// Hard ceiling on a single probe's request timeout regardless of the check's
/// configured `timeout_secs`, so one slow target can't stall the runner.
const MAX_TIMEOUT_SECS: u64 = 120;

/// The synthetic-check runner. Cheap to clone (wraps the connection-pooling
/// `reqwest::Client` and the two DB handles).
#[derive(Clone)]
pub struct SyntheticRunner {
    repo: SyntheticCheckRepository,
    ch_client: ClickHouseClient,
    /// NAN-1541: the unified alert spine. A check that probes to a status other
    /// than its `expected_status` (or errors out) raises one alert per failing
    /// probe through here with `kind = synthetic`.
    alert_repo: AlertRepository,
}

impl SyntheticRunner {
    /// Build a runner from the PG pool (definitions) and the ClickHouse client
    /// (results). The HTTP client carries no default timeout — each probe sets
    /// its own per-request timeout from the check's `timeout_secs`.
    pub fn new(pool: PgPool, ch_client: ClickHouseClient) -> Self {
        Self {
            repo: SyntheticCheckRepository::new(pool.clone()),
            ch_client,
            alert_repo: AlertRepository::new(pool),
        }
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

    /// One scheduler tick: probe every enabled check that is due. Errors from
    /// the PG listing are logged and the tick is skipped (the loop continues);
    /// per-check probe work is fully isolated below.
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

        for check in checks {
            // Per-check isolation: a single bad check (network error, slow
            // target, malformed URL) must never abort the tick or the
            // scheduler (NAN-1102). due_for() / probe_and_record() are written
            // to return Result, never panic; we log and continue regardless.
            let due = match self.due_for(&check).await {
                Ok(due) => due,
                Err(e) => {
                    warn!(check = %check.id, error = %e, "Synthetic runner: due-check query failed; skipping");
                    continue;
                }
            };
            if !due {
                continue;
            }
            if let Err(e) = self.probe_and_record(&check).await {
                warn!(check = %check.id, error = %e, "Synthetic runner: probe/record failed");
            }
        }
    }

    /// Whether `check` is due: no prior result, or the newest result is older
    /// than `interval_secs`. One bounded `max(timestamp)` read per check.
    async fn due_for(&self, check: &SyntheticCheck) -> Result<bool, clickhouse::error::Error> {
        let check_id = check.id.to_string();
        // Parameterized via the official client's `?` binding — injection-safe.
        let last_ms: i64 = self
            .ch_client
            .query(
                "SELECT toInt64(max(timestamp) * 1000) \
                 FROM nanosiem.synthetic_check_results \
                 WHERE check_id = ?",
            )
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
        let started = std::time::Instant::now();

        // SSRF guard (defense-in-depth): validate + DNS-resolve the target and
        // pin the connection to the validated IP(s), so a check can never be
        // used to reach internal / link-local / cloud-metadata addresses, and
        // can't be DNS-rebound between validation and connect. A blocked target
        // is recorded as a failed probe (status 0) — it is never fetched.
        let (status_code, error) = match Self::ssrf_checked_client(&check.target_url).await {
            Err(reason) => {
                let mut msg = reason;
                msg.truncate(500);
                (0u16, msg)
            }
            Ok(client) => match client.get(&check.target_url).timeout(timeout).send().await {
                Ok(resp) => (resp.status().as_u16(), String::new()),
                Err(e) => {
                    // No HTTP status observed (DNS/connect/timeout). status_code=0.
                    let mut msg = e.to_string();
                    msg.truncate(500);
                    (0u16, msg)
                }
            },
        };

        let latency_ms = started.elapsed().as_secs_f64() * 1000.0;
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

        // DateTime64(3) <- millis (the column's CODEC is Delta,ZSTD; the
        // official client serializes the bound i64 into the 3-precision column).
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

        // NAN-1541: on FAILURE (observed status != expected, or a request
        // error with status_code=0), raise an alert through the unified spine
        // with `kind = synthetic`. Per-check isolation: a PG raise failure is
        // logged here and never propagated, so it can't abort the result-row
        // write nor the tick (NAN-1102). No event-hash dedup — the check's own
        // interval (>= 30s) bounds the alert volume; one alert per failing
        // probe is the simple, predictable behavior.
        if success == 0 {
            self.raise_failure_alert(check, status_code, &error).await;
        }

        Ok(())
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

        if let Err(e) = self
            .alert_repo
            .create_alert(AlertInsert {
                kind: "synthetic",
                rule_id: None,
                source_id: Some(check.id.to_string()),
                severity: &severity,
                matched_events: &payload,
                event_hash: None,
            })
            .await
        {
            warn!(
                check = %check.id,
                error = %e,
                "Synthetic runner: failed to raise failure alert"
            );
        } else {
            info!(
                check = %check.id,
                expected = check.expected_status,
                observed = status_code,
                "Synthetic check failed — alert raised"
            );
        }
    }
}
