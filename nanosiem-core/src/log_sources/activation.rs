// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5132 (PR 5): two-phase activation of a routed log source.
//!
//! Adding a source used to be one reload that built its parser chain AND
//! routed traffic to it. On a role-split install each ingest host installs the
//! generation on its own; a host that refused it kept the old routing while
//! the others ran the new one (a split config) until the rollback generation
//! reached everyone.
//!
//! Now the change goes out in two generations:
//!
//! * **A, stage:** the source renders *parked* (`activation_parked`, see
//!   `VectorConfigManager::generate_source_config`): its chain and fan-in slots
//!   exist on every host, but its entry reads the never-matching slot filter
//!   and `source_router` has no route for it. Routing is identical to before,
//!   so a host that refuses A changes nothing an event sees. The deploy waits
//!   until EVERY ingest host acknowledged A (local install: the correlated
//!   activation marker plus the health poll).
//! * **B, activate:** the hold is released and the router route is added. B
//!   only changes the router and the chain's entry, which A already proved
//!   builds on every host.
//!
//! A removal runs the same two steps in reverse: A unroutes and parks the
//! chain, B drops it. A failure in either step withdraws the change: the
//! hold is released, the source goes back to its previous enabled state, and
//! the previous configuration is restored (local) or republished (role split).
//!
//! The hold is a PostgreSQL row, not process state: every app host renders and
//! publishes from the database, so all of them render A while it is held.

use std::time::Duration;

use sqlx::PgPool;
use uuid::Uuid;

/// Turns two-phase activation off (`off`, `false`, `0`). On by default
/// wherever it can be verified (see [`available`]).
pub const TWO_PHASE_ENV: &str = "NANO_VECTOR_TWO_PHASE_ACTIVATION";

/// A hold older than this belongs to a deploy whose process died: two phases
/// each wait at most the delivery acknowledgement (180 s) plus the render.
pub const STALE_HOLD_AFTER: Duration = Duration::from_secs(30 * 60);

/// Why a source is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldPurpose {
    Deploy,
    Undeploy,
}

impl HoldPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Deploy => "deploy",
            Self::Undeploy => "undeploy",
        }
    }
}

/// Whether this install can run a two-phase activation: the parked filter
/// exists only with stable fan-in slots, and phase A must be verifiable: by
/// the ingest hosts' acknowledgement (generation delivery) or by the local
/// Vector's activation marker. A pull install without generation delivery
/// has nothing to wait for.
pub fn available() -> bool {
    let pull_only = crate::parsers::vector_config_local_reload_disabled()
        && !crate::parsers::vector_config_remote_delivery::generation_delivery_configured();
    available_with(
        crate::parsers::vector_config_fanin_slots_enabled(),
        pull_only,
        std::env::var(TWO_PHASE_ENV).ok().as_deref(),
    )
}

/// Pure form of [`available`].
pub fn available_with(slots: bool, pull_only: bool, setting: Option<&str>) -> bool {
    let off = setting
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "off" | "false" | "0"))
        .unwrap_or(false);
    slots && !pull_only && !off
}

/// Whether a source of this kind and transport goes through two phases: log
/// sources fed by `source_router` (HTTP, Vector-native and unknown labels).
/// HEC, OTLP and pull sources read their own lanes and keep one phase.
pub fn eligible(kind: &str, source_type: &str) -> bool {
    kind != "enrichment" && crate::parsers::vector_config_is_router_fed(source_type)
}

/// Role split: whether phase A may proceed, from the delivery the phase-A
/// reload left ([`crate::parsers::vector_config_remote_delivery::take_delivery`]).
/// Only a full acknowledgement passes. A reload that went "live" can still be
/// `Pending` (some host still installing, NAN-5279), and nothing reported at
/// all means no evidence; both withdraw, because the whole point of phase A is
/// that EVERY host built the parked chain before routing changes anywhere.
/// `Err` carries the delivery note for the withdrawal message.
pub fn staged_on_every_host(
    staged: Option<(String, crate::parsers::vector_config_remote_delivery::GenerationDelivery)>,
) -> Result<(), String> {
    use crate::parsers::vector_config_remote_delivery::DeliveryState;
    match staged {
        Some((_, delivery)) if delivery.state == DeliveryState::Acknowledged => Ok(()),
        Some((note, _)) => Err(note),
        None => Err("no ingest host reported it".to_string()),
    }
}

/// Render `log_source_id` parked until [`release`].
pub async fn hold(pool: &PgPool, log_source_id: Uuid, purpose: HoldPurpose) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO log_source_activation_holds (log_source_id, purpose) VALUES ($1, $2) \
         ON CONFLICT (log_source_id) DO UPDATE SET purpose = EXCLUDED.purpose, created_at = now()",
    )
    .bind(log_source_id)
    .bind(purpose.as_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// Render `log_source_id` normally again. Idempotent.
pub async fn release(pool: &PgPool, log_source_id: Uuid) -> Result<bool, sqlx::Error> {
    let done = sqlx::query("DELETE FROM log_source_activation_holds WHERE log_source_id = $1")
        .bind(log_source_id)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}

/// Release holds left by a deploy whose process died (older than
/// [`STALE_HOLD_AFTER`]). Returns how many were released.
pub async fn release_stale(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let done = sqlx::query(
        "DELETE FROM log_source_activation_holds \
         WHERE created_at < now() - make_interval(secs => $1)",
    )
    .bind(STALE_HOLD_AFTER.as_secs_f64())
    .execute(pool)
    .await?;
    if done.rows_affected() > 0 {
        tracing::warn!(
            released = done.rows_affected(),
            "released log-source activation holds left by an interrupted deploy; those sources render live again"
        );
    }
    Ok(done.rows_affected())
}

#[cfg(test)]
#[path = "activation_tests.rs"]
mod tests;
