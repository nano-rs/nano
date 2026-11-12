// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rolling generation installs across ingest hosts (NAN-5285, v2.0.13 retest F3).
//!
//! Every ingest host's config consumer polls the same API, so a published
//! generation used to be installed by every host within one poll interval of
//! each other. A Vector reload that rebuilds the fan-ins stalls that host's
//! ingest for 10–15 s, and with every host reloading at once the load balancer
//! had no healthy target: 503s and timeouts on HEC, HTTP and OTLP.
//!
//! A consumer now takes this lease before installing, and the lease tells it
//! whether to drain first. Draining means withdrawing readiness so the load
//! balancers' `/healthz` checks take the host out of rotation, then installing,
//! rejoining, and releasing the lease. The next host installs only after
//! that. The upgrade already rolls ingest hosts one at a time through the LB
//! hooks; this is the same stagger for the config path, using the health check
//! instead of the hooks (the consumer runs in a container without them).
//!
//! The drain is granted only when another ingest host is ready to take the
//! traffic. A lone ingest host, or one whose peers are down, installs in place
//! as before: a short stall beats refusing every event.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// The one lease every ingest consumer competes for.
pub const LEASE_SCOPE: &str = "ingest";
/// Bounds on the lease a consumer may ask for. The consumer asks for its ack
/// wait plus the drain and rejoin windows; the bound keeps a bad request from
/// blocking every other host for long.
pub const MIN_LEASE_TTL_SECS: u64 = 30;
pub const MAX_LEASE_TTL_SECS: u64 = 600;
/// Per-relay readiness probe budget when deciding whether to drain.
const READY_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// What a consumer that asked for the lease gets back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LeaseOutcome {
    /// Install now. `drain`: withdraw readiness and wait for the load balancer
    /// before reloading, because another ingest host is ready to take the
    /// traffic.
    Granted { drain: bool, ttl_secs: u64 },
    /// Another host is installing. Keep serving the installed generation and
    /// ask again on the next poll.
    Busy {
        holder: String,
        generation: i64,
        expires_in_secs: i64,
    },
}

/// Why a lease request was refused before it reached the database.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LeaseRequestError {
    #[error("holder must be 1-128 characters of [A-Za-z0-9._:-]")]
    InvalidHolder,
    #[error("generation must be positive")]
    InvalidGeneration,
}

/// A holder is the consumer's host identity (the Compose host id, the k8s pod
/// name). It is stored and echoed to the other hosts, so keep it plain.
pub fn validate_holder(holder: &str) -> Result<(), LeaseRequestError> {
    let ok = !holder.is_empty()
        && holder.len() <= 128
        && holder
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    if ok { Ok(()) } else { Err(LeaseRequestError::InvalidHolder) }
}

/// The TTL actually granted for a requested one.
pub fn clamp_ttl(requested_secs: Option<u64>) -> u64 {
    requested_secs
        .unwrap_or(MAX_LEASE_TTL_SECS / 2)
        .clamp(MIN_LEASE_TTL_SECS, MAX_LEASE_TTL_SECS)
}

/// Drain only when the cluster has more than one ingest host and at least two
/// of them answer ready: the requester itself and one that takes its traffic.
pub fn should_drain(ingest_hosts: usize, ready_hosts: usize) -> bool {
    ingest_hosts > 1 && ready_hosts >= 2
}

/// Take (or renew) the lease for `holder`. Granted when nobody holds it, the
/// holder already holds it (a renewal, or a retry after a lost response), or
/// the previous holder's lease expired. One statement, so two consumers asking
/// at the same moment cannot both win.
pub async fn acquire(
    pool: &PgPool,
    holder: &str,
    generation: i64,
    ttl_secs: u64,
) -> Result<Option<(String, i64, i64)>, sqlx::Error> {
    let granted: Option<(String,)> = sqlx::query_as(
        "INSERT INTO vector_config_install_leases \
             (scope, holder, generation, acquired_at, expires_at) \
         VALUES ($1, $2, $3, now(), now() + make_interval(secs => $4)) \
         ON CONFLICT (scope) DO UPDATE SET \
             holder = EXCLUDED.holder, generation = EXCLUDED.generation, \
             acquired_at = now(), expires_at = EXCLUDED.expires_at \
         WHERE vector_config_install_leases.holder = EXCLUDED.holder \
            OR vector_config_install_leases.expires_at < now() \
         RETURNING holder",
    )
    .bind(LEASE_SCOPE)
    .bind(holder)
    .bind(generation)
    .bind(ttl_secs as f64)
    .fetch_optional(pool)
    .await?;
    if granted.is_some() {
        return Ok(None);
    }
    // Busy: report who holds it. The row can vanish between the two
    // statements (released); that reads as busy for one more poll, harmless.
    let current: Option<(String, i64, i64)> = sqlx::query_as(
        "SELECT holder, generation, \
                GREATEST(0, CEIL(EXTRACT(EPOCH FROM (expires_at - now()))))::BIGINT \
         FROM vector_config_install_leases WHERE scope = $1",
    )
    .bind(LEASE_SCOPE)
    .fetch_optional(pool)
    .await?;
    Ok(Some(current.unwrap_or_else(|| (String::new(), 0, 0))))
}

/// Release the lease if `holder` holds it. Returns whether a row was removed.
pub async fn release(pool: &PgPool, holder: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM vector_config_install_leases WHERE scope = $1 AND holder = $2",
    )
    .bind(LEASE_SCOPE)
    .bind(holder)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// How many ingest hosts' readiness relays answer `/healthz` with 200 now.
pub async fn ready_hosts(urls: &[String]) -> usize {
    let client = reqwest::Client::new();
    let probes = urls.iter().map(|url| {
        let client = &client;
        async move {
            client
                .get(format!("{url}/healthz"))
                .timeout(READY_PROBE_TIMEOUT)
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
        }
    });
    futures::future::join_all(probes)
        .await
        .into_iter()
        .filter(|ready| *ready)
        .count()
}

/// The full lease decision: take the lease, and on success decide the drain
/// from the configured ingest hosts' live readiness.
pub async fn request(
    pool: &PgPool,
    holder: &str,
    generation: i64,
    requested_ttl_secs: Option<u64>,
) -> Result<LeaseOutcome, LeaseError> {
    validate_holder(holder).map_err(LeaseError::Request)?;
    if generation <= 0 {
        return Err(LeaseError::Request(LeaseRequestError::InvalidGeneration));
    }
    let ttl_secs = clamp_ttl(requested_ttl_secs);
    match acquire(pool, holder, generation, ttl_secs).await? {
        None => {
            let urls = super::relay_urls();
            let drain = should_drain(urls.len(), ready_hosts(&urls).await);
            tracing::info!(
                holder,
                generation,
                drain,
                ingest_hosts = urls.len(),
                "Vector config install lease granted"
            );
            Ok(LeaseOutcome::Granted { drain, ttl_secs })
        }
        Some((current, current_generation, expires_in_secs)) => Ok(LeaseOutcome::Busy {
            holder: current,
            generation: current_generation,
            expires_in_secs,
        }),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error(transparent)]
    Request(LeaseRequestError),
    #[error("install lease store: {0}")]
    Database(#[from] sqlx::Error),
}

#[cfg(test)]
#[path = "install_lease_tests.rs"]
mod tests;
