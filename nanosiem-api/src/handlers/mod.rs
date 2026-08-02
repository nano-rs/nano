// SPDX-License-Identifier: AGPL-3.0-or-later

//! API request handlers

use crate::state::AppState;
use nanosiem_core::audit::{AuditEmitter, AuditEvent};
use nanosiem_core::auth::UserRepository;

// Canonical home for `AuditExt` is now `nanosiem-api-lib` (NAN-752 follow-up
// to NAN-751's OIDC lift, which had to use a fully-qualified-call workaround
// because the trait was defined here). Re-exported at the original path so
// existing handler imports (`use crate::handlers::AuditExt;`) keep resolving
// without churn, and the impl on `AppState` below stays in this crate (the
// only place that knows what an `AppState` is).
pub use nanosiem_api_lib::AuditExt;

// Agent enrichment handlers — lifted to nanosiem-enterprise in NAN-752
// (Phase 2 of the open-core split). Re-exported here so route registrations
// (`handlers::agent_enrichment::list_providers`, etc.) continue to resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::agent_enrichment;
pub mod alerts;
pub mod api_keys;
pub mod audit;
// Air-gapped deployment import handlers (NAN-1201) — enterprise only.
#[cfg(feature = "enterprise")]
pub mod airgap;
pub mod auth;
pub mod capabilities;
// Cases + queues + queue-routing-rules + case-grouping settings handlers —
// lifted to nanosiem-enterprise in NAN-752 (Phase 2 of the open-core split).
// Re-exported here so route registrations (`handlers::cases::list_cases`,
// etc.) continue to resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::cases;
pub mod credentials;
// Custom enrichment handlers — lifted to nanosiem-enterprise in NAN-752 (Phase
// 2 of the open-core split). Re-exported here so route registrations
// (`handlers::custom_enrichment::list_custom_enrichments`, etc.) continue to
// resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::custom_enrichment;
pub mod artifacts;
pub mod dashboards;
pub mod demo;
pub mod detection_code_targets;
pub mod detections;
pub mod enrichment;
// Entity context handler — lifted to nanosiem-enterprise in NAN-752 (Phase
// 2 of the open-core split). Re-exported here so route registrations
// (`handlers::entity_context::get_entity_context`, etc.) continue to resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::entity_context;
pub mod feedback;
pub mod fields;
pub mod folder_settings;
pub mod gdpr;
// NAN-2121: the privilege-grant validator lives in nanosiem-api-lib so the
// enterprise crate (OIDC group-mapping handler) can enforce the same invariant.
// Re-exported here so in-crate call sites keep using `crate::handlers::grant_authz`.
pub use nanosiem_api_lib::grant_authz;
pub mod groups;
pub mod health;
// NAN-2238 Active Hunter: hunt definitions, runners, sweeps, leads, triage.
pub mod hunts;
pub mod identity;
// Incidents handlers — lifted to nanosiem-enterprise in NAN-752 (Phase 2 of
// the open-core split). Incidents group multiple cases for SOC investigations
// and ship with cases.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::incidents;
// Integration collectors (NAN-2189) — enterprise only, like the sandbox
// runtime they drive.
#[cfg(feature = "enterprise")]
pub mod integrations;
pub mod ip_allowlist;
#[cfg(feature = "enterprise")]
pub mod license;
pub mod log_sources;
pub mod lookup;
pub mod marketplace;
// meloD AI handlers — lifted to nanosiem-enterprise in NAN-752 (Phase 2 of
// the open-core split). Re-exported here so route registrations
// (`handlers::melod_chat`, `handlers::melod::get_ai_failures`, etc.) continue
// to resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::melod;
pub mod mfa;
pub mod mitre;
// Notebooks handlers — lifted to nanosiem-enterprise in NAN-752 (Phase 2 of
// the open-core split). Re-exported here so route registrations
// (`handlers::notebooks::list_notebooks`, etc.) continue to resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::notebooks;
pub mod notifications;
pub mod observability_metric_monitors;
// Observability ↔ Security convergence cross-link (NAN-1542) — ENTERPRISE only
// (NAN-1544). Open builds omit the route + spec path entirely.
#[cfg(feature = "enterprise")]
pub mod observability_service_signals;
pub mod observability_slos;
pub mod observability_synthetics;
// OIDC handlers — lifted to nanosiem-enterprise in NAN-751 (Phase 2 of the
// open-core split). Re-exported here so route registrations
// (`handlers::oidc::list_providers`, etc.) continue to resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::oidc;
pub mod onboarding;
pub mod parser_repositories;
pub mod playbook_repositories;
pub mod playbooks;
pub mod prevalence;
pub mod query_library;
pub mod recent_activity;
pub mod reports;
/// Composite target-resource capability policy shared by every
/// content-repository import/sync/fixup/remove path (NAN-2029).
pub mod repository_target_authz;
// Risk analytics handlers — lifted to nanosiem-enterprise in NAN-752 (Phase
// 2 of the open-core split). Re-exported here so route registrations
// (`handlers::risk::get_risky_entities`, etc.) continue to resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::risk;
pub mod roles;
pub mod rule_repositories;
pub mod search;
pub mod search_history;
pub mod sessions;
pub mod settings;
pub mod setup;
pub mod siem_health;
pub mod siem_health_suppressions;
pub mod system_health_events;
pub mod source_configs;
pub mod source_scopes;
pub mod system;
pub mod tuning;
pub mod upload;
pub mod users;

pub use alerts::*;
pub use api_keys::*;
pub use audit::*;
pub use auth::*;
pub use capabilities::*;
pub use credentials::*;
pub use dashboards::*;
pub use detections::*;
pub use enrichment::*;
pub use feedback::*;
pub use fields::*;
pub use groups::*;
pub use health::*;
pub use lookup::*;
#[cfg(feature = "enterprise")]
pub use melod::*;
#[cfg(feature = "enterprise")]
pub use notebooks::*;
pub use notifications::*;
// `oidc` re-exported above as a module via `pub use nanosiem_enterprise::...`;
// nothing additional needed here.
pub use prevalence::*;
pub use query_library::*;
pub use recent_activity::*;
// NOTE: `reports` is intentionally NOT glob-re-exported — its `list_reports` /
// `get_report` would collide with `siem_health`'s same-named handlers. Route
// bindings reference these as `handlers::reports::*` (NAN-1793).
// `risk` re-exported above as a module via `pub use nanosiem_enterprise::...`;
// route bindings reference items as `handlers::risk::*` so a wildcard
// re-export here is unnecessary.
pub use roles::*;
pub use search::*;
pub use search_history::*;
pub use sessions::*;
pub use settings::*;
pub use setup::*;
pub use siem_health::*;
pub use system::*;
pub use tuning::*;
pub use upload::*;
pub use users::*;

/// Bounded per-insert timeout for the durable (synchronous) audit path. A CH
/// blip must never hang the audit task indefinitely; on timeout we log + bump
/// the failure metric (see [`record_audit_emit_failure`]).
const DURABLE_AUDIT_EMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);

/// Concurrency cap for in-flight durable (synchronous) audit inserts (NAN-1625).
///
/// Belt-and-suspenders alongside the non-floodable classifier set and the
/// per-insert timeout: even a burst of *legitimate* durable security events
/// can never exhaust the ClickHouse connection pool or stall other work,
/// because at most this many synchronous inserts run at once. When the cap is
/// reached we do NOT queue/block — we fall back to the (also-bounded)
/// async-insert path (and record the degradation via the failure metric).
static DURABLE_AUDIT_INSERTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(12);

/// Bounded per-insert timeout for the async-insert (fire-and-forget) audit
/// path. Async-insert acks on receipt so this is normally fast, but a slow or
/// unresponsive ClickHouse must never hold an audit task indefinitely.
const ASYNC_AUDIT_EMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Total-concurrency bound for the async-insert (fire-and-forget) audit path
/// (NAN-1625). Covers BOTH routine events AND the durable-path saturation
/// fallback, so — combined with [`DURABLE_AUDIT_INSERTS`] — the audit
/// subsystem as a whole can NEVER exhaust the ClickHouse connection pool or
/// pile up unbounded tasks under any burst or CH slowdown. At most this many
/// async-insert audit writes are ever in flight. On saturation of this bound we
/// **drop** the event (log full event + metric) rather than block/queue:
/// accepting audit loss under extreme pressure is strictly better than choking
/// the platform, and the drop is loud, metered, and log-recoverable. Larger
/// than the durable cap because these writes ack on receipt (cheap) rather than
/// blocking on flush.
static ROUTINE_AUDIT_INSERTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(64);

/// Best-effort actor-name enrichment: fill `actor_name` from `actor_id` via a
/// single PostgreSQL lookup. Intentionally called only *after* a concurrency
/// permit is held (or skipped entirely on the drop path), so the PG lookups are
/// bounded by the same caps as the CH inserts — a burst can't pile up unbounded
/// user-repo queries or pressure the PG pool. On lookup failure we keep the
/// event as-is (it still carries `actor_id`, so it stays recoverable).
async fn resolve_actor_name(mut event: AuditEvent, user_repo: &UserRepository) -> AuditEvent {
    if event.actor_id.is_some() && event.actor_name.is_none() {
        if let Some(actor_id) = event.actor_id {
            if let Ok(user) = user_repo.get_user_by_id(actor_id).await {
                event.actor_name = Some(user.name);
            }
        }
    }
    event
}

/// Run the async-insert (fire-and-forget) audit write under the total
/// concurrency bound ([`ROUTINE_AUDIT_INSERTS`]) + a bounded timeout
/// ([`ASYNC_AUDIT_EMIT_TIMEOUT`]). Used by BOTH routine events and the
/// durable-path saturation fallback.
///
/// Takes ownership of `event` because actor-name enrichment (a PG lookup) is
/// performed here — but only *after* acquiring the concurrency permit, so it is
/// bounded. On saturation of the concurrency bound the event is **dropped**
/// (never blocked/queued, and NOT enriched — no PG work on the drop path) so
/// the audit subsystem cannot exhaust the CH (or PG) pool; the drop is recorded
/// via [`record_audit_emit_failure`] (full event + metric).
///
/// `critical` distinguishes a routine event (`false`) from a durable event that
/// fell back after the durable cap saturated (`true`) — it only affects log
/// level + the metric label, never behavior.
async fn emit_async_bounded(
    emitter: &AuditEmitter,
    user_repo: &UserRepository,
    event: AuditEvent,
    critical: bool,
) {
    match ROUTINE_AUDIT_INSERTS.try_acquire() {
        Ok(_permit) => {
            let event = resolve_actor_name(event, user_repo).await;
            match tokio::time::timeout(ASYNC_AUDIT_EMIT_TIMEOUT, emitter.emit(&event)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    record_audit_emit_failure(&event, &e.to_string(), critical, "insert_error")
                }
                Err(_) => record_audit_emit_failure(
                    &event,
                    "async audit insert timed out",
                    critical,
                    "timeout",
                ),
            }
            // `_permit` released here.
        }
        Err(_) => {
            // Total audit-insert concurrency exhausted — DROP rather than pile
            // up tasks / exhaust the CH pool. Loud + full-event-logged so the
            // dropped event is recoverable from application logs. (No PG
            // enrichment here — `actor_id` in the logged event suffices.)
            record_audit_emit_failure(
                &event,
                "audit-insert concurrency bound saturated — event dropped",
                critical,
                "async_saturated",
            );
        }
    }
}

/// Surface an audit-emit failure loudly + observably instead of swallowing it.
///
/// This is the core of the NAN-1625 "durable-in-normal-case, observable-on-
/// failure, NOT availability-coupled" tradeoff: we never propagate the error
/// back into the user's request (the mutation already committed, and auth must
/// not be coupled to ClickHouse availability). Instead we (a) log the FULL
/// event at `error!`/`warn!` so it is reconstructable from application logs and
/// (b) increment `nanosiem_audit_emit_failures_total`, turning silent loss
/// into a loud, log-recoverable, alertable failure.
///
/// `reason` (`insert_error` / `timeout` / `durable_saturated` /
/// `async_saturated`) is carried as a metric label so every emission of this
/// counter shares the same label key set (`action` / `critical` / `reason`)
/// and failure/degrade modes are alertable independently. Every call — whether
/// a hard failure (insert error / timeout), a drop (concurrency-bound
/// saturation) or a durability degrade — logs the FULL event so it is always
/// recoverable from application logs, never merely counted.
fn record_audit_emit_failure(event: &AuditEvent, error: &str, critical: bool, reason: &'static str) {
    let event_json = serde_json::to_string(event).unwrap_or_else(|_| "<unserializable>".to_string());
    if critical {
        tracing::error!(
            source = %event.source,
            action = %event.action,
            error = %error,
            reason = %reason,
            event = %event_json,
            "Security-critical audit event not durably persisted — full event logged for recovery",
        );
    } else {
        tracing::warn!(
            source = %event.source,
            action = %event.action,
            error = %error,
            reason = %reason,
            event = %event_json,
            "Audit event emit failed — full event logged for recovery",
        );
    }
    ::metrics::counter!(
        "nanosiem_audit_emit_failures_total",
        "action" => event.action.clone(),
        "critical" => if critical { "true" } else { "false" },
        "reason" => reason,
    )
    .increment(1);
}

impl AuditExt for AppState {
    /// Hybrid audit emission (NAN-1625).
    ///
    /// After NAN-1622 ClickHouse is the *sole* audit store, so fire-and-forget
    /// `tokio::spawn` + `warn!` can silently drop events on a crash or CH blip.
    /// We now differentiate by criticality:
    ///
    /// - **Security-critical, non-floodable** events (see
    ///   [`nanosiem_core::audit::is_security_critical`]) are emitted **durably** via
    ///   `emit_durable` (synchronous `async_insert=0` + `wait_end_of_query=1`),
    ///   so the write genuinely lands rather than merely being received.
    /// - **Routine / high-volume / attacker-floodable** events keep the cheap
    ///   async-insert fire-and-forget path (awaiting a sync insert on floodable
    ///   events would amplify a flood into a self-inflicted DoS).
    ///
    /// Both CH-insert paths are concurrency-bounded + timed out, so the audit
    /// subsystem can never exhaust the ClickHouse (or PostgreSQL) connection
    /// pool under any burst or CH slowdown: the durable path is capped at
    /// [`DURABLE_AUDIT_INSERTS`] (+ a 4s timeout), and the async-insert path
    /// (routine events *and* the durable-saturation fallback) at
    /// [`ROUTINE_AUDIT_INSERTS`] (+ a 5s timeout); actor-name PG enrichment runs
    /// only behind those permits. A process-global backstop inside `AuditEmitter`
    /// bounds *every* audit insert (including direct, non-dispatch callers) as a
    /// final ceiling. On saturation of any bound we never block/queue — the
    /// durable path degrades to the bounded async path, and the async path
    /// drops-with-log-and-metric. Excess audits are dropped (loudly, recoverably),
    /// never allowed to choke the platform.
    ///
    /// The trait contract stays **non-blocking** — the durable insert runs in a
    /// spawned task, not on the request thread. Blocking the HTTP response
    /// would require making this trait `async` and threading `.await` through
    /// ~270 call sites, where a single missed `.await` would *silently drop*
    /// an audit event (a strictly worse failure than the one we're fixing).
    ///
    /// Honest residual: this spawns one task per audit call *before* the permit
    /// checks, so a burst of N events briefly creates N tasks. Those tasks are
    /// cheap — each either acquires a permit and does one bounded insert, or
    /// drops-and-exits immediately (no unbounded I/O, no permit queueing) — so
    /// this is NOT a pool/auth-availability risk, but it is not literally
    /// "bounded task count." The full admission-control fix — a shared bounded
    /// work-queue / local WAL that *enqueues* events instead of per-event
    /// spawning (also closing the process-crash-before-flush window) — is the
    /// acknowledged follow-up.
    ///
    /// Failure handling is availability-decoupled: on timeout/insert-error we
    /// never fail the (already-committed) mutation — a CH outage must not block
    /// login/MFA/api-key ops. We log the full event + bump a metric instead.
    fn emit_audit(&self, event: AuditEvent) {
        let emitter = self.audit_emitter.clone();
        let user_repo = self.user_repo.clone();
        tokio::spawn(async move {
            // NOTE: actor-name enrichment (a PG lookup) is deliberately deferred
            // to *after* a concurrency permit is acquired (durable arm below /
            // `emit_async_bounded`), and skipped on the drop path, so neither
            // the ClickHouse nor the PostgreSQL pool can be exhausted by a burst
            // of audit events.
            if nanosiem_core::audit::is_security_critical(&event.action) {
                // DURABLE path: cap concurrency first so a burst can't exhaust
                // the CH pool. `try_acquire` never blocks — on saturation we
                // fall back to the (also-bounded) async-insert path.
                match DURABLE_AUDIT_INSERTS.try_acquire() {
                    Ok(_permit) => {
                        let event = resolve_actor_name(event, &user_repo).await;
                        match tokio::time::timeout(
                            DURABLE_AUDIT_EMIT_TIMEOUT,
                            emitter.emit_durable(&event),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                record_audit_emit_failure(
                                    &event,
                                    &e.to_string(),
                                    true,
                                    "insert_error",
                                )
                            }
                            Err(_) => record_audit_emit_failure(
                                &event,
                                "durable audit insert timed out",
                                true,
                                "timeout",
                            ),
                        }
                        // `_permit` released here.
                    }
                    Err(_) => {
                        // Durable cap saturated — record the degrade (full event
                        // + metric, so a dropped durability guarantee is
                        // log-recoverable) and fall back to the *bounded*
                        // async-insert path. The fallback shares the total
                        // concurrency bound + timeout, so it can never exhaust
                        // the CH pool either. (If it also drops/fails it records
                        // its own reason via `emit_async_bounded`.) Logged
                        // un-enriched to avoid an unbounded PG lookup here; the
                        // fallback enriches only if it acquires a permit.
                        record_audit_emit_failure(
                            &event,
                            "durable audit concurrency bound saturated — degraded to async-insert",
                            true,
                            "durable_saturated",
                        );
                        emit_async_bounded(&emitter, &user_repo, event, true).await;
                    }
                }
            } else {
                // ROUTINE fire-and-forget path: async-insert under the total
                // concurrency bound + timeout. On saturation the event is
                // dropped-with-log-and-metric rather than piling up tasks, so
                // routine audit volume can never choke the CH pool.
                emit_async_bounded(&emitter, &user_repo, event, false).await;
            }
        });
    }
}
