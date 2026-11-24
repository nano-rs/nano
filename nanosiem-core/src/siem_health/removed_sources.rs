// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deleted log sources in SIEM Health (NAN-5760).
//!
//! The report's per-source lists come from ClickHouse `source_type` values,
//! and a deleted source's events stay in `logs`. Without this, a deleted
//! source read as "silent" (data in the prior 24h, none since) for up to 48h
//! after the delete, and lowered the ingestion score.
//!
//! Setting a `source_type` aside HIDES it from alerting, so every condition
//! below must hold (NAN-5760 review P1: a create-then-delete of a draft must
//! not be able to blind health to a live stream):
//!
//! 1. A tombstone exists (`log_source_tombstones`, migration 398). The trigger
//!    only writes one for a source that had a live claim: deployed (now or
//!    ever) or bound to an ingest token. A draft never deployed and never
//!    token-bound leaves none.
//! 2. The tombstone is inside the 48h health window ([`TOMBSTONE_WINDOW_HOURS`]).
//! 3. The key is the source's exact route key (its literal match values, or
//!    its safe name; never a pattern), a valid route-key identifier, and not a
//!    platform or reserved lane.
//! 4. No live log source and no routing rule claims the key.
//! 5. ClickHouse shows events for the key from BEFORE the delete (the source
//!    actually produced it) and none after the delete plus [`LATE_ARRIVAL_GRACE_SECS`].
//!    A key that keeps receiving events after the delete is live again and is
//!    reported as a normal active (or later silent) source.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use clickhouse::Client as ClickHouseClient;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::reserved_source_types::{classify, Reservation};
use crate::log_sources::connect::validate_route_key;
use crate::log_sources::health_series::route_keys_for;

/// Tombstones older than this cannot touch a report (its windows are 48h);
/// two hours of slack for clock skew between PostgreSQL and ClickHouse.
pub const TOMBSTONE_WINDOW_HOURS: i64 = 50;

/// Events stamped up to this long after a delete are in-flight buffers, not a
/// sender that is still writing.
pub const LATE_ARRIVAL_GRACE_SECS: i64 = 300;

/// The deleted source a removed route key belonged to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedSource {
    pub log_source_name: String,
    pub deleted_at: DateTime<Utc>,
}

/// Route keys (lowercase `source_type` values) of deleted log sources that no
/// live source claims.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemovedSourceKeys {
    keys: BTreeMap<String, RemovedSource>,
}

/// One tombstone row: a deleted source's identity.
#[derive(Debug, Clone)]
pub struct Tombstone {
    pub name: String,
    pub match_values: Option<Vec<String>>,
    pub deleted_at: DateTime<Utc>,
}

/// Oldest and newest event timestamp (unix seconds) for a key in the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvidence {
    pub first_event: i64,
    pub last_event: i64,
}

/// A key a tombstone may never set aside: reserved/platform lanes and
/// anything that is not a literal route-key identifier.
pub fn never_set_aside(key: &str) -> bool {
    if validate_route_key(key).is_err() {
        return true;
    }
    if classify(key) != Reservation::None {
        return true;
    }
    let platform = crate::auth::reserved_source_types::PLATFORM_LANES
        .iter()
        .chain(crate::auth::reserved_source_types::WARN_ONLY_PREFIXES)
        .any(|prefix| key.starts_with(prefix));
    platform
        || matches!(
            key,
            "parse_failure" | "reserved_spoof" | "unknown" | "generic" | "unclaimed"
        )
}

/// The exact route keys a tombstone could set aside.
pub fn tombstone_keys(tombstone: &Tombstone) -> Vec<String> {
    route_keys_for(tombstone.match_values.as_deref(), &tombstone.name)
        .into_iter()
        .filter(|key| !never_set_aside(key))
        .collect()
}

impl RemovedSourceKeys {
    /// Pure: tombstoned keys minus every key a live source or routing rule
    /// claims. When two tombstones name one key, the most recent delete wins.
    /// The result is a CANDIDATE set; [`Self::retain_evidenced`] must run
    /// before anything is set aside.
    pub fn from_parts<'a>(
        tombstones: impl IntoIterator<Item = &'a Tombstone>,
        live: impl IntoIterator<Item = (Option<&'a [String]>, &'a str)>,
        routed: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let mut claimed: BTreeSet<String> = live
            .into_iter()
            .flat_map(|(values, name)| route_keys_for(values, name))
            .collect();
        claimed.extend(routed.into_iter().map(|key| key.trim().to_lowercase()));
        let mut keys: BTreeMap<String, RemovedSource> = BTreeMap::new();
        for tombstone in tombstones {
            for key in tombstone_keys(tombstone) {
                if claimed.contains(&key) {
                    continue;
                }
                let newer = keys
                    .get(&key)
                    .is_none_or(|existing| existing.deleted_at < tombstone.deleted_at);
                if newer {
                    keys.insert(
                        key,
                        RemovedSource {
                            log_source_name: tombstone.name.clone(),
                            deleted_at: tombstone.deleted_at,
                        },
                    );
                }
            }
        }
        Self { keys }
    }

    /// Pure: keep only keys the deleted source demonstrably produced (events
    /// at or before the delete) and that are not receiving events any more
    /// (none later than the delete plus the late-arrival grace). A key with
    /// no events in the window has nothing to set aside and is dropped.
    pub fn retain_evidenced(&mut self, evidence: &HashMap<String, KeyEvidence>) {
        self.keys.retain(|key, source| {
            let Some(seen) = evidence.get(key) else {
                return false;
            };
            let deleted = source.deleted_at.timestamp();
            seen.first_event <= deleted && seen.last_event <= deleted + LATE_ARRIVAL_GRACE_SECS
        });
    }

    /// Candidates from PostgreSQL (tombstones in the window, minus live and
    /// routed claims). See [`Self::load`] for the full, evidenced set.
    pub async fn load_candidates(pool: &PgPool) -> Result<Self, sqlx::Error> {
        let tombstones: Vec<(String, Option<Vec<String>>, DateTime<Utc>)> = sqlx::query_as(
            "SELECT name, match_values, deleted_at FROM log_source_tombstones \
             WHERE deleted_at > now() - make_interval(hours => $1::int)",
        )
        .bind(TOMBSTONE_WINDOW_HOURS as i32)
        .fetch_all(pool)
        .await?;
        if tombstones.is_empty() {
            return Ok(Self::default());
        }
        let live: Vec<(String, Option<Vec<String>>)> =
            sqlx::query_as("SELECT name, match_values FROM log_sources")
                .fetch_all(pool)
                .await?;
        let routed: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT r.target_source_type FROM routing_rules r \
             JOIN source_configurations c ON c.id = r.source_configuration_id \
             WHERE c.enabled",
        )
        .fetch_all(pool)
        .await?;
        let tombstones: Vec<Tombstone> = tombstones
            .into_iter()
            .map(|(name, match_values, deleted_at)| Tombstone { name, match_values, deleted_at })
            .collect();
        Ok(Self::from_parts(
            &tombstones,
            live.iter().map(|(name, values)| (values.as_deref(), name.as_str())),
            routed.iter().map(String::as_str),
        ))
    }

    /// The removed keys: [`Self::load_candidates`] confirmed against the
    /// events in `logs_table` ([`Self::retain_evidenced`]).
    pub async fn load(
        pool: &PgPool,
        ch: &ClickHouseClient,
        logs_table: &str,
    ) -> Result<Self, String> {
        let mut keys = Self::load_candidates(pool).await.map_err(|e| e.to_string())?;
        if keys.is_empty() {
            return Ok(keys);
        }
        let sql = evidence_sql(logs_table, keys.keys.keys().map(String::as_str));
        let rows: Vec<(String, i64, i64)> =
            ch.query(&sql).fetch_all().await.map_err(|e| e.to_string())?;
        let evidence = rows
            .into_iter()
            .map(|(key, first_event, last_event)| (key, KeyEvidence { first_event, last_event }))
            .collect();
        keys.retain_evidenced(&evidence);
        Ok(keys)
    }

    /// [`Self::load`], degrading to "nothing removed" when it fails: a failed
    /// read must never hide a source, only leave the pre-NAN-5760 behavior.
    pub async fn load_or_empty(pool: &PgPool, ch: &ClickHouseClient, logs_table: &str) -> Self {
        match Self::load(pool, ch, logs_table).await {
            Ok(keys) => keys,
            Err(error) => {
                tracing::warn!(%error, "could not read deleted log sources for SIEM health");
                Self::default()
            }
        }
    }

    /// The deleted source `source_type` belonged to, when it is removed.
    pub fn get(&self, source_type: &str) -> Option<&RemovedSource> {
        let key = source_type.trim().to_lowercase();
        self.keys.get(&key)
    }

    pub fn contains(&self, source_type: &str) -> bool {
        self.get(source_type).is_some()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }
}

/// Oldest and newest event per candidate key over the 48h window. Keys passed
/// [`validate_route_key`] (a conservative identifier alphabet), and are quoted
/// defensively anyway.
pub fn evidence_sql<'a>(logs_table: &str, keys: impl Iterator<Item = &'a str>) -> String {
    let list = keys
        .map(|key| format!("'{}'", key.replace('\\', "\\\\").replace('\'', "\\'")))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "SELECT source_type, toInt64(toUnixTimestamp(min(timestamp))), \
         toInt64(toUnixTimestamp(max(timestamp))) \
         FROM {logs_table} \
         WHERE timestamp >= now() - INTERVAL 48 HOUR AND source_type IN ({list}) \
         GROUP BY source_type"
    )
}

/// The route keys each deleted source's tombstone may set aside, for the
/// `LOG_SOURCE_DELETED` audit event. A source with no entry left no
/// tombstone (it never had a live claim).
pub async fn tombstoned_route_keys(
    pool: &PgPool,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, Vec<String>>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(Uuid, String, Option<Vec<String>>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT log_source_id, name, match_values, deleted_at FROM log_source_tombstones \
         WHERE log_source_id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, match_values, deleted_at)| {
            (id, tombstone_keys(&Tombstone { name, match_values, deleted_at }))
        })
        .collect())
}

#[cfg(test)]
#[path = "removed_sources_tests.rs"]
mod tests;
