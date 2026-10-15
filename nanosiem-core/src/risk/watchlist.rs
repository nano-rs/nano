// SPDX-License-Identifier: AGPL-3.0-or-later

//! Risk watchlists (NAN-3228): named, weighted groups of risk entities.
//!
//! # Scoring model
//!
//! A watchlist carries a weight `w` in `[0, 1]`. Its members' accumulated
//! (decayed) risk is amplified at READ time:
//!
//! ```text
//! effective = round_half_even(base x (1 + w))
//! ```
//!
//! * `w = 0` tracks only; `w = 1` doubles the score.
//! * Paused lists (`enabled = false`) apply nothing.
//! * **Stacking:** an entity on several enabled lists takes the MAXIMUM weight
//!   of those lists — weights never compound, so adding an entity to a second
//!   list can only raise it to that list's weight, never multiply twice.
//!
//! The weight is applied where the entity-grain score is computed (the lake
//! worker's risk aggregate and the ClickHouse builders in
//! [`super::clickhouse_sql`]), so ordering, `min_score` floors, overview bands,
//! the notable count and the `dataset=risk` rule thresholds all see the
//! effective score, while the base score stays available next to it. Nothing
//! in the findings ledger is rewritten: pausing or deleting a list takes
//! effect on the next read, and the weight applies retroactively to the whole
//! 7-day decay window.
//!
//! Members match risk entities by their normalized VALUE (trimmed,
//! lowercased) — the same value-keyed matching the clear boundaries use. The
//! member's `entity_type` is the analyst's classification (display and
//! filtering); the risk grain infers its own type from the value.
//!
//! Source visibility: the weight multiplies the score the CALLER may see (the
//! grain is computed after the per-source deny filter), so a restricted
//! viewer never learns a hidden source's contribution through a watchlist.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// At most this many watchlists per tenant.
pub const MAX_WATCHLISTS_PER_TENANT: i64 = 50;
/// At most this many members on one watchlist.
pub const MAX_MEMBERS_PER_WATCHLIST: i64 = 500;
/// At most this many member rows across all of a tenant's watchlists. Bounds
/// the weight map every risk read carries to the lake worker.
pub const MAX_MEMBERS_PER_TENANT: i64 = 2000;
/// At most this many entities in one add / remove request.
pub const MAX_MEMBERS_PER_REQUEST: usize = 500;
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_DESCRIPTION_LEN: usize = 200;
pub const MAX_NOTE_LEN: usize = 500;
pub const MAX_ENTITY_VALUE_LEN: usize = 1024;

/// Analyst classification of a watchlist member.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum WatchEntityType {
    User,
    Host,
    Ip,
    Hash,
}

impl WatchEntityType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Host => "host",
            Self::Ip => "ip",
            Self::Hash => "hash",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "host" => Some(Self::Host),
            "ip" => Some(Self::Ip),
            "hash" => Some(Self::Hash),
            _ => None,
        }
    }
}

/// Detect a member's type from its value (the design's rules, mirrored by the
/// web client): IPv4 / IPv4 CIDR / IPv6 → `ip`; 32 / 40 / 64 hex characters →
/// `hash`; contains `.` and no `@` → `host`; anything else → `user`.
pub fn detect_entity_type(value: &str) -> WatchEntityType {
    let value = value.trim();
    if is_ipv4_or_cidr(value) || value.parse::<std::net::Ipv6Addr>().is_ok() {
        return WatchEntityType::Ip;
    }
    if matches!(value.len(), 32 | 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return WatchEntityType::Hash;
    }
    if value.contains('.') && !value.contains('@') {
        return WatchEntityType::Host;
    }
    WatchEntityType::User
}

fn is_ipv4_or_cidr(value: &str) -> bool {
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    address.parse::<std::net::Ipv4Addr>().is_ok()
        && prefix.is_none_or(|p| p.parse::<u8>().is_ok_and(|bits| bits <= 32))
}

/// Why a watchlist input was refused (mapped to 400 by both API modes).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct WatchlistValidationError(pub String);

fn invalid(message: impl Into<String>) -> WatchlistValidationError {
    WatchlistValidationError(message.into())
}

/// Names are snake_case: lowercase letters, digits and `_`, starting with a
/// letter or digit, at most 64 characters.
pub fn validate_name(name: &str) -> Result<String, WatchlistValidationError> {
    let name = name.trim();
    let mut chars = name.chars();
    let valid_first = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    if !valid_first
        || name.len() > MAX_NAME_LEN
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(invalid(
            "name must be snake_case: 1-64 lowercase letters, digits or '_', starting with a letter or digit",
        ));
    }
    Ok(name.to_string())
}

pub fn validate_description(description: &str) -> Result<String, WatchlistValidationError> {
    let description = description.trim();
    if description.chars().count() > MAX_DESCRIPTION_LEN
        || description.chars().any(char::is_control)
    {
        return Err(invalid(
            "description must be at most 200 characters without control characters",
        ));
    }
    Ok(description.to_string())
}

pub fn validate_note(note: &str) -> Result<String, WatchlistValidationError> {
    let note = note.trim();
    if note.chars().count() > MAX_NOTE_LEN || note.chars().any(char::is_control) {
        return Err(invalid(
            "reason must be at most 500 characters without control characters",
        ));
    }
    Ok(note.to_string())
}

/// A weight in hundredths (`0..=100`), the stored `NUMERIC(3, 2)` precision.
pub fn validate_weight(weight: f64) -> Result<u8, WatchlistValidationError> {
    if !weight.is_finite() || !(0.0..=1.0).contains(&weight) {
        return Err(invalid("weight must be between 0 and 1"));
    }
    Ok((weight * 100.0).round() as u8)
}

/// Normalize a member value: trimmed, lowercased (the risk grain is matched
/// case-insensitively by value). CIDR ranges are refused: scoring matches
/// exact entity values, so a range would silently never apply.
pub fn normalize_entity_value(value: &str) -> Result<String, WatchlistValidationError> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_ENTITY_VALUE_LEN {
        return Err(invalid("entity value must be 1-1024 characters"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid("entity value must not contain control characters"));
    }
    if is_ipv4_or_cidr(value) && value.contains('/') {
        return Err(invalid(format!(
            "{value}: CIDR ranges cannot be scored yet; add the individual addresses"
        )));
    }
    Ok(value.to_lowercase())
}

/// Effective score for a base score and a weight (`0..=1`), rounded half to
/// even exactly like ClickHouse `round()` on a Float64.
pub fn effective_score(base: i64, weight: f64) -> i64 {
    if weight <= 0.0 {
        return base;
    }
    (base as f64 * (1.0 + weight)).round_ties_even() as i64
}

/// The per-entity weight map for one tenant: normalized entity value →
/// MAX weight (hundredths) across that entity's ENABLED lists with a
/// positive weight. Empty means no amplification anywhere.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RiskWatchWeights {
    by_entity: BTreeMap<String, u8>,
}

impl RiskWatchWeights {
    /// Build from `(normalized value, weight hundredths)` rows, keeping the
    /// maximum per value (the stacking rule) and dropping zero weights.
    pub fn from_rows(rows: impl IntoIterator<Item = (String, u8)>) -> Self {
        let mut by_entity: BTreeMap<String, u8> = BTreeMap::new();
        for (entity, centi) in rows {
            let centi = centi.min(100);
            if centi == 0 || entity.is_empty() {
                continue;
            }
            let slot = by_entity.entry(entity.trim().to_lowercase()).or_insert(0);
            *slot = (*slot).max(centi);
        }
        Self { by_entity }
    }

    pub fn is_empty(&self) -> bool {
        self.by_entity.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_entity.len()
    }

    /// The weight for an entity value (`0.0` when not watched).
    pub fn weight(&self, entity: &str) -> f64 {
        self.by_entity
            .get(&entity.trim().to_lowercase())
            .map_or(0.0, |centi| f64::from(*centi) / 100.0)
    }

    /// The map the lake worker receives (`watch_weights`).
    pub fn lake_map(&self) -> BTreeMap<String, f64> {
        self.by_entity
            .iter()
            .map(|(entity, centi)| (entity.clone(), f64::from(*centi) / 100.0))
            .collect()
    }

    /// Parallel `(entities, weights)` arrays for the ClickHouse
    /// `arrayElement(weights, indexOf(entities, lower(entity)))` lookup, with
    /// a trailing `('', 0.0)` sentinel so both arrays are never empty (an
    /// empty array literal would type as `Array(Nothing)`).
    pub fn parallel_arrays(&self) -> (Vec<String>, Vec<f64>) {
        let mut entities = Vec::with_capacity(self.by_entity.len() + 1);
        let mut weights = Vec::with_capacity(self.by_entity.len() + 1);
        for (entity, centi) in &self.by_entity {
            entities.push(entity.clone());
            weights.push(f64::from(*centi) / 100.0);
        }
        entities.push(String::new());
        weights.push(0.0);
        (entities, weights)
    }
}

/// The tenant the dedicated (single-tenant) deployment binds watchlist rows to.
pub const DEDICATED_TENANT_ID: Uuid = crate::reports::COMPATIBILITY_TENANT_ID;

/// Read a tenant's weight map: members of ENABLED lists with a positive
/// weight, MAX weight per normalized value. Bounded by
/// [`MAX_MEMBERS_PER_TENANT`]. On hosted-shared `executor` is the signed
/// tenant transaction (RLS-scoped); dedicated passes its pool.
pub async fn read_watch_weights<'e, E>(
    executor: E,
    tenant_id: Uuid,
) -> Result<RiskWatchWeights, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows: Vec<(String, i32)> = sqlx::query_as(
        r#"
        SELECT member.entity_value, MAX(round(list.weight * 100))::int4 AS centi
        FROM risk_watchlist_members member
        JOIN risk_watchlists list
          ON list.tenant_id = member.tenant_id AND list.id = member.watchlist_id
        WHERE member.tenant_id = $1 AND list.tenant_id = $1
          AND list.enabled AND list.weight > 0
        GROUP BY member.entity_value
        LIMIT $2
        "#,
    )
    .bind(tenant_id)
    .bind(MAX_MEMBERS_PER_TENANT)
    .fetch_all(executor)
    .await?;
    Ok(RiskWatchWeights::from_rows(rows.into_iter().map(
        |(entity, centi)| (entity, centi.clamp(0, 100) as u8),
    )))
}

// ---------------------------------------------------------------------------
// Callers without `risk:watchlists` (NAN-3232)
// ---------------------------------------------------------------------------
//
// Watchlist membership is its own grant. A caller without it still gets the
// EFFECTIVE (weighted) score everywhere — the weight is tenant scoring policy
// — but nothing that says an entity is watched: no base score, no applied
// weight, and per-rule contributions presented on the effective scale so
// they do not visibly fall short of the headline score.

/// `true` when `permissions` include `risk:watchlists`.
pub fn may_view_watchlists<S: AsRef<str>>(permissions: &[S]) -> bool {
    permissions
        .iter()
        .any(|p| p.as_ref() == crate::auth::permissions::RISK_WATCHLISTS)
}

impl super::types::EntityRiskSummary {
    /// Drop the watch fields (`base_risk_score`, `watch_weight`); the
    /// effective `risk_score` stays.
    pub fn hide_watch(&mut self) {
        self.base_risk_score = None;
        self.watch_weight = None;
    }
}

impl super::types::TimeWindowedRiskScore {
    /// Drop the watch fields (`base_decayed_score_*`, `watch_weight`); the
    /// effective `decayed_score_*` stay.
    pub fn hide_watch(&mut self) {
        self.base_decayed_score_24h = None;
        self.base_decayed_score_7d = None;
        self.watch_weight = None;
    }
}

/// Present per-rule decayed contributions on the effective scale (each
/// `round_half_even(c x (1 + w))`), so their sum tracks the weighted headline
/// score instead of the base. A no-op without a positive weight.
pub fn scale_contributions_to_effective(
    contributions: &mut [super::types::EntityRuleContribution],
    weight: Option<f64>,
) {
    let Some(weight) = weight.filter(|w| w.is_finite() && *w > 0.0) else {
        return;
    };
    for contribution in contributions {
        contribution.decayed_contribution_24h =
            effective_score(contribution.decayed_contribution_24h, weight);
        contribution.decayed_contribution_7d =
            effective_score(contribution.decayed_contribution_7d, weight);
    }
}

/// The entity-context shape (risk badge + per-rule breakdown) for a caller
/// without `risk:watchlists`: contributions scaled by the badge's applied
/// weight, then the badge's watch fields dropped.
pub fn hide_watch_in_entity_context(
    risk: &mut Option<super::types::EntityRiskSummary>,
    contributions: &mut [super::types::EntityRuleContribution],
) {
    let weight = risk.as_ref().and_then(|summary| summary.watch_weight);
    scale_contributions_to_effective(contributions, weight);
    if let Some(summary) = risk {
        summary.hide_watch();
    }
}

/// `true` when `error` means the watchlist tables do not exist yet (open-core
/// schema or a database the migration has not reached): scoring then simply
/// applies no weights.
pub fn is_missing_watchlist_schema(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|db| db.code())
        .is_some_and(|code| code == "42P01")
}

#[cfg(test)]
#[path = "watchlist_tests.rs"]
mod watchlist_tests;
