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
//!
//! NAN-5874: only a Vector that keeps acknowledged events across a re-pointing
//! reload installs. Vector up to `0.61.0-nano.13` dropped, as delivered, every
//! event an unchanged input took in while a reload that re-pointed it built
//! (v2.0.35 puts `<parser>_source_tz` in front of every `_parse`, so the
//! upgrade's first generation is such a reload). A consumer reports the
//! release its Vector runs (`vector_release`, from Vector's `build_info`
//! gauge); a consumer that does not (one from before v2.0.35, beside a
//! nano.13 Vector) or a Vector older than [`MIN_VECTOR_RELEASE`] is told to
//! wait ([`VECTOR_UPGRADE_HOLDER`]) and keeps serving its installed
//! generation until the rollout replaces its pod. An API from before v2.0.35
//! would still grant such a consumer the lease during a rolling upgrade, and
//! it serves the new generation from the same database, so the lease moved to
//! a new scope ([`LEASE_SCOPE`]) and this API holds the old one
//! ([`fence_legacy_scope`]): an old API then answers every request "busy".
//!
//! NAN-5810: the floor is now `0.62.0-nano.2`. Vector 0.62 parses a config
//! before it interpolates env vars, so nano renders numeric placeholders
//! quoted (`max_bytes = "${VECTOR_BATCH_MAX_BYTES:-52428800}"`), and a 0.61
//! Vector cannot load that (`unknown variant`): a 0.62-format generation would
//! take its whole config down. HEC record preservation (nanosiem#10462) also
//! needs the `splunk_hec` event_kind marker first shipped in 0.62.0-nano.2. A
//! 0.61 host (nano.14 / nano.15 included) or a 0.62.0-nano.1 one is therefore
//! told to wait like a nano.13 one and keeps serving its installed generation
//! until its pod or host is replaced with the new image.
//!
//! The same rolling-upgrade race as NAN-5874 applies: a v2.0.35 API replica
//! still running beside this one grants `ingest-v2` with its own, lower floor
//! (0.61.0-nano.14), and serves this version's generations from the same
//! database. So the lease moved again, to `ingest-v3` on
//! `/install-lease/v3`, and this API fences every superseded scope
//! ([`FENCED_LEGACY_SCOPES`]: `ingest` and `ingest-v2`). A floor bump that
//! changes what a Vector can load adds the next scope here the same way.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// The one lease every ingest consumer competes for (`ingest` before
/// v2.0.35, `ingest-v2` in v2.0.35; NAN-5810 review P1-1: `ingest-v3` from
/// v2.0.36).
pub const LEASE_SCOPE: &str = "ingest-v3";
/// The scope APIs before v2.0.35 grant (on `/install-lease`).
pub const LEGACY_LEASE_SCOPE: &str = "ingest";
/// The scope v2.0.35 APIs grant (on `/install-lease/v2`).
pub const LEASE_V2_SCOPE: &str = "ingest-v2";
/// Every scope an older API grants. This API holds all of them (see
/// [`fence_legacy_scope`]) so no older API grants a consumer an install of a
/// generation this version rendered.
pub const FENCED_LEGACY_SCOPES: &[&str] = &[LEGACY_LEASE_SCOPE, LEASE_V2_SCOPE];
/// The holder of the fenced scopes; an old API reports it as the host that is
/// installing.
pub const LEGACY_FENCE_HOLDER: &str = "nano-2.0.36-upgrade";
/// How long the fence outlives the last API that refreshed it. Every v2.0.36+
/// API refreshes it on each publication reconcile tick (5 s by default) and
/// on every lease request, so it holds while any such API runs. After a
/// rollback to an older version the old APIs grant their scope again within
/// this long (well inside the consumer's and the Compose healthcheck's
/// budgets).
pub const LEGACY_FENCE_TTL_SECS: u64 = 60;
/// The first Vector release that can install this API's generations, as
/// (major, minor, patch, nano): one that loads quoted numeric placeholders
/// (Vector 0.62, NAN-5810), carries the `splunk_hec` event_kind marker HEC
/// record preservation needs (nanosiem#10462, first in 0.62.0-nano.2), and
/// keeps acknowledged events across a re-pointing reload (nano-rs/vector
/// NAN-5874, first in 0.61.0-nano.14).
pub const MIN_VECTOR_RELEASE: (u32, u32, u32, u32) = (0, 62, 0, 2);
/// The holder named in a busy answer to a consumer whose Vector must be
/// upgraded first (a consumer from before v2.0.35 logs it as the installing
/// host).
pub const VECTOR_UPGRADE_HOLDER: &str = "vector-0.62.0-nano.2-required";
/// The holder named in a busy answer on a superseded path (`/install-lease`
/// or `/install-lease/v2`) to a consumer that reports its Vector release: it
/// takes the lease on `/install-lease/v3`.
pub const LEASE_V3_HOLDER: &str = "install-lease-v3-required";
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
///
/// Only `/install-lease/v3` releases: this version grants on no other path, and
/// the fenced scopes' rows belong to [`LEGACY_FENCE_HOLDER`].
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

/// The `X.Y.Z-nano.N` release in a Vector `build_info` revision label (the fork
/// image sets `nano 0.62.0-nano.2 <sha>`); `None` when the label names none.
pub fn parse_vector_release(label: &str) -> Option<(u32, u32, u32, u32)> {
    label.split_whitespace().find_map(|word| {
        let (version, nano) = word.split_once("-nano.")?;
        let mut parts = version.split('.').map(|p| p.parse::<u32>().ok());
        let (major, minor, patch) = (parts.next()??, parts.next()??, parts.next()??);
        if parts.next().is_some() {
            return None;
        }
        let nano = nano.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()?;
        Some((major, minor, patch, nano))
    })
}

/// NAN-5891 (review r3): the explicit opt-in that lets a Vector build with no
/// `-nano.` release (an upstream or custom build) install this release's
/// generations. Off by default: such a build does not mark HEC event kinds
/// (`%splunk_hec.event_kind`, nano-rs/vector NAN-5891), and the shipped
/// `hec_normalize` needs that marker. SIEM Health reports it when set.
pub const ALLOW_CUSTOM_VECTOR_ENV: &str = "NANO_ALLOW_CUSTOM_VECTOR";

/// Whether [`ALLOW_CUSTOM_VECTOR_ENV`] is set to `true`.
pub fn custom_vector_allowed() -> bool {
    std::env::var(ALLOW_CUSTOM_VECTOR_ENV).is_ok_and(|v| v.trim().eq_ignore_ascii_case("true"))
}

/// Whether a consumer whose Vector reports `reported` may install. Unreported
/// (a consumer from before v2.0.35, or Vector's metrics not up yet) or an
/// older fork release waits. A label with no parsable `-nano.` release (an
/// upstream or custom build) FAILS CLOSED unless [`ALLOW_CUSTOM_VECTOR_ENV`]
/// is set (NAN-5891 review r3).
pub fn vector_release_allows_install(reported: Option<&str>) -> bool {
    vector_release_allows_install_with(reported, custom_vector_allowed())
}

/// [`vector_release_allows_install`] with the opt-in passed in (testable
/// without the process environment).
pub fn vector_release_allows_install_with(reported: Option<&str>, allow_custom: bool) -> bool {
    match reported.map(str::trim) {
        None | Some("") => false,
        Some(label) => match parse_vector_release(label) {
            Some(release) => release >= MIN_VECTOR_RELEASE,
            None => allow_custom,
        },
    }
}

/// Why `reported` is refused, for the log line (see [`request`]).
fn refusal_reason(reported: Option<&str>) -> &'static str {
    match reported.map(str::trim) {
        Some(label) if !label.is_empty() && parse_vector_release(label).is_none() => {
            "vector-0.62.0-nano.2-required: custom or upstream Vector builds aren't supported \
             (this release's HEC config needs the nano Vector build's event-kind marker); run \
             the pinned nano Vector image, or set NANO_ALLOW_CUSTOM_VECTOR=true on nano-api to \
             accept the risk"
        }
        _ => {
            "vector-0.62.0-nano.2-required: this ingest host's Vector predates 0.62.0-nano.2 \
             and cannot load this release's config (or would drop acknowledged events on the \
             reload); it keeps its installed generation until its pod runs the new image"
        }
    }
}

/// Hold every scope an older API grants ([`FENCED_LEGACY_SCOPES`]), so none
/// of them lets a consumer install while this version's generations are
/// published (see the module docs). One statement for all of them.
/// Unconditional: a consumer that held one is mid-install of a generation it
/// already downloaded and finishes; its release then removes nothing.
pub async fn fence_legacy_scope(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO vector_config_install_leases \
             (scope, holder, generation, acquired_at, expires_at) \
         SELECT fenced.scope, $2, 0, now(), now() + make_interval(secs => $3) \
         FROM unnest($1::text[]) AS fenced(scope) \
         ON CONFLICT (scope) DO UPDATE SET \
             holder = EXCLUDED.holder, generation = 0, \
             acquired_at = now(), expires_at = EXCLUDED.expires_at",
    )
    .bind(FENCED_LEGACY_SCOPES)
    .bind(LEGACY_FENCE_HOLDER)
    .bind(LEGACY_FENCE_TTL_SECS as f64)
    .execute(pool)
    .await?;
    Ok(())
}

/// A superseded path on this version never grants, and refreshes the fence. A
/// consumer whose Vector could install this version's generations (0.62.0-nano.2
/// or later) is sent to `/install-lease/v3` ([`LEASE_V3_HOLDER`]). Any other
/// (a v2.0.35 consumer beside a 0.61 Vector, one that reports no release yet,
/// or one from before v2.0.35) is told the actionable reason: its Vector must
/// be upgraded first ([`VECTOR_UPGRADE_HOLDER`], NAN-5810 review r2: a v2.0.35
/// consumer logs that holder as "must be 0.62.0-nano.2 or later", while it
/// does not know `install-lease-v3-required`).
///
/// A custom or upstream build is sent to v3 only when [`ALLOW_CUSTOM_VECTOR_ENV`]
/// is set, the same rule [`request`] applies, so it is never redirected to a
/// path that would refuse it (NAN-5891).
async fn refuse_on_superseded_path(
    pool: &PgPool,
    holder: &str,
    generation: i64,
    vector_release: Option<&str>,
) -> Result<LeaseOutcome, LeaseError> {
    refuse_on_superseded_path_with(pool, holder, generation, vector_release, custom_vector_allowed()).await
}

/// [`refuse_on_superseded_path`] with the custom-build opt-in passed in
/// (testable without the process environment).
async fn refuse_on_superseded_path_with(
    pool: &PgPool,
    holder: &str,
    generation: i64,
    vector_release: Option<&str>,
    allow_custom: bool,
) -> Result<LeaseOutcome, LeaseError> {
    validate_holder(holder).map_err(LeaseError::Request)?;
    if generation <= 0 {
        return Err(LeaseError::Request(LeaseRequestError::InvalidGeneration));
    }
    fence_legacy_scope(pool).await?;
    let holder_named = if vector_release_allows_install_with(vector_release, allow_custom) {
        LEASE_V3_HOLDER
    } else {
        VECTOR_UPGRADE_HOLDER
    };
    Ok(LeaseOutcome::Busy {
        holder: holder_named.to_string(),
        generation,
        expires_in_secs: 0,
    })
}

/// The legacy path (`/install-lease`) on a v2.0.35+ API never grants (NAN-5874 review): a grant
/// there would be a lease the consumer files as a legacy one and releases on the legacy path,
/// where an older replica answers 204 without releasing it.
pub async fn request_on_legacy_path(
    pool: &PgPool,
    holder: &str,
    generation: i64,
    vector_release: Option<&str>,
) -> Result<LeaseOutcome, LeaseError> {
    refuse_on_superseded_path(pool, holder, generation, vector_release).await
}

/// The v2.0.35 path (`/install-lease/v2`) on a v2.0.36+ API never grants (NAN-5810 review P1-1):
/// a v2.0.35 consumer's Vector is 0.61, which cannot load this version's generations, and a
/// v2.0.36 consumer that reached it retries on `/install-lease/v3`.
pub async fn request_on_v2_path(
    pool: &PgPool,
    holder: &str,
    generation: i64,
    vector_release: Option<&str>,
) -> Result<LeaseOutcome, LeaseError> {
    refuse_on_superseded_path(pool, holder, generation, vector_release).await
}

/// The full lease decision: refuse a Vector that cannot load this release's
/// generation or loses events on a re-pointing reload, take the lease, and on success decide the drain from
/// the configured ingest hosts' live readiness.
pub async fn request(
    pool: &PgPool,
    holder: &str,
    generation: i64,
    requested_ttl_secs: Option<u64>,
    vector_release: Option<&str>,
) -> Result<LeaseOutcome, LeaseError> {
    validate_holder(holder).map_err(LeaseError::Request)?;
    if generation <= 0 {
        return Err(LeaseError::Request(LeaseRequestError::InvalidGeneration));
    }
    fence_legacy_scope(pool).await?;
    let custom = vector_release
        .map(str::trim)
        .is_some_and(|label| !label.is_empty() && parse_vector_release(label).is_none());
    if custom && custom_vector_allowed() {
        tracing::warn!(
            holder,
            generation,
            vector_release = vector_release.unwrap_or(""),
            "Vector config install ALLOWED for a custom or upstream Vector build because \
             NANO_ALLOW_CUSTOM_VECTOR=true: it does not mark HEC event kinds, so HEC object \
             events take the legacy handling and HEC string events whose text is compact JSON \
             are handled as object events"
        );
    }
    if !vector_release_allows_install(vector_release) {
        tracing::warn!(
            holder,
            generation,
            vector_release = vector_release.unwrap_or("not reported"),
            "Vector config install refused: {}",
            refusal_reason(vector_release)
        );
        return Ok(LeaseOutcome::Busy {
            holder: VECTOR_UPGRADE_HOLDER.to_string(),
            generation,
            expires_in_secs: 0,
        });
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
