// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5395: whether a newly issued ingest token is already live on ingest.
//!
//! HEC and HTTP ingest authenticate against Vector's hashed tokens file
//! (`valid_tokens_file`, re-read at most every 2 s). OTLP does not: the edge's
//! `auth_request` asks nano-api, which reads PostgreSQL, so a new token works
//! there at once. That is why a fresh token could pass OTLP while HEC still
//! answered 401.
//!
//! What the issue / rotate call can honestly say depends on the delivery:
//! * `shared_volume` (single-host Compose): nano-api writes the file Vector
//!   reads before the call gets here. After one re-read interval Vector has
//!   seen it, so the call waits that long (bounded) and reports `ready`.
//! * `http` (Helm, role-split Compose): every ingest host's config consumer
//!   pulls the file every 2 s and installs it; nano-api has no evidence of
//!   when each host installed it. The call does not wait and never reports
//!   `ready`: it returns the bound a sender should retry a 401 within.
//!   (Install acknowledgements from the consumers, against a registry of the
//!   expected ingest hosts, would be needed to report `ready` here.)
//! * `none`: tokens are not delivered; never ready.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::TokenDelivery;

/// Seconds the create / rotate call may wait for ingest (`0` = do not wait).
pub const READY_WAIT_ENV: &str = "NANO_INGEST_TOKEN_READY_WAIT_SECS";
pub const DEFAULT_READY_WAIT: Duration = Duration::from_secs(8);
pub const MAX_READY_WAIT: Duration = Duration::from_secs(30);
/// Retry hint for a sender when the token is not confirmed live: the
/// consumer's pull interval (2 s) plus Vector's re-read interval (2 s) plus a
/// margin.
pub const NOT_READY_RETRY_AFTER_SECS: u64 = 5;

/// Whether a just-issued token is accepted on HEC and HTTP ingest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct IngestReadiness {
    /// `true` only when nano-api itself wrote the tokens file Vector reads
    /// (`shared_volume`) and one Vector re-read interval has passed since: the
    /// file lists the token and Vector has had the chance to load it. Never
    /// `true` for `http` delivery, where nano-api cannot see when each ingest
    /// host installed it. When `false`, retry a HEC/HTTP 401 for up to
    /// `retry_after_secs`. OTLP accepts a new token at once either way.
    pub ready: bool,
    /// How the token reaches ingest: `http`, `shared_volume` or `none`.
    pub delivery: TokenDelivery,
    /// How long the call waited, in milliseconds.
    pub waited_ms: u64,
    /// Set when `ready` is false: seconds within which a 401 should be retried.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
}

/// The configured wait: [`DEFAULT_READY_WAIT`] when unset or unparsable,
/// clamped to [`MAX_READY_WAIT`].
pub fn ready_wait_from(value: Option<&str>) -> Duration {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        None => DEFAULT_READY_WAIT,
        Some(v) => v
            .parse::<u64>()
            .map(|secs| Duration::from_secs(secs).min(MAX_READY_WAIT))
            .unwrap_or(DEFAULT_READY_WAIT),
    }
}

/// Reports, within `budget`, whether the token is live on ingest.
///
/// `settle` is Vector's file re-read interval plus a margin. Only
/// `shared_volume` waits (exactly `settle`, and only when it fits in
/// `budget`); the wait holds no lock or database connection and sits under a
/// hard deadline, so the call never takes longer than `budget`.
pub async fn wait_for_ingest(
    delivery: TokenDelivery,
    budget: Duration,
    settle: Duration,
) -> IngestReadiness {
    let started = tokio::time::Instant::now();
    let finish = |ready: bool| IngestReadiness {
        ready,
        delivery,
        waited_ms: started.elapsed().as_millis() as u64,
        retry_after_secs: (!ready).then_some(NOT_READY_RETRY_AFTER_SECS),
    };
    match delivery {
        TokenDelivery::SharedVolume if settle <= budget => {
            let deadline = started + budget;
            match tokio::time::timeout_at(deadline, tokio::time::sleep(settle)).await {
                Ok(()) => finish(true),
                Err(_) => finish(false),
            }
        }
        TokenDelivery::SharedVolume | TokenDelivery::Http | TokenDelivery::None => finish(false),
    }
}

#[cfg(test)]
#[path = "readiness_tests.rs"]
mod tests;
