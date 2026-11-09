// SPDX-License-Identifier: AGPL-3.0-or-later

//! Connect-first onboarding on the ClickHouse product (NAN-4912 phase 2,
//! ported from main's NAN-4847 without the hosted plumbing).
//!
//! A log source is connected before it is parsed: the Add data flow creates a
//! draft source, issues an ingest token bound to it (NAN-4907), and events sent
//! with that token are routed on the source's route key. Until the source's
//! parser is published no router lane claims that key, so the events take the
//! router's `generic` catch-all and land in `logs` unparsed, searchable as
//! `source_type=<route key>`. That makes "receiving, not parsed" a first-class
//! state, derived here from the per-source rollup.
//!
//! Three read models come out of one rollup scan ([`SourceActivityReader`]):
//! * [`LogSourceConnectStatus`]: per-source state for the list, detail and
//!   Connect step;
//! * [`UnassignedSource`]: route keys that arrive but no log source claims
//!   (typically senders multiplexing over the legacy install token, or the
//!   unauthenticated OTLP / Vector-native lanes);
//! * the unbound tokens (their source was deleted), listed by the caller.
//!
//! [`convert_unassigned`] turns an unassigned key into a draft source whose
//! route key is that key, so the sender keeps working unchanged (no token is
//! issued, rotated or rebound). When an unbound token is named, it is bound to
//! the new source: same token value, so again nothing changes for the sender.

use std::collections::{BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use clickhouse::Client as ClickHouseClient;
use sqlx::PgPool;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::types::{LogSource, NewLogSource};
use super::{LogSourceService, LogSourceServiceError};
use crate::auth::ScopeSet;
use crate::ingest_tokens::{
    is_push_capable, route_key, IngestToken, IngestTokenService, IngestTokenServiceError,
};
use crate::search::service::source_scope_sql_predicate;

/// The window every connect read model covers.
pub const ACTIVITY_WINDOW_HOURS: i64 = 24;
/// Most distinct route keys one activity scan returns (busiest first).
const ACTIVITY_ROW_LIMIT: usize = 1000;
/// Longest route key a conversion accepts.
pub const MAX_ROUTE_KEY_LEN: usize = 100;

/// Route keys the platform itself assigns. They describe a failure or an
/// unlabelled event, not a sender, so they are never offered for conversion.
const SYSTEM_ROUTE_KEYS: &[&str] = &["unknown", "parse_failure", "", "*"];

/// One route key's ingest over [`ACTIVITY_WINDOW_HOURS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SourceActivity {
    /// The `source_type` value the events carry (lowercased by the rollup).
    pub route_key: String,
    pub events_24h: u64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
}

/// Where a log source stands on the way from "created" to "parsed".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectState {
    /// A published source switched off: its parser no longer runs.
    Disabled,
    /// Not published, and nothing has arrived for its route key yet.
    AwaitingData,
    /// Events arrive but no parser is published: they land unparsed in `logs`,
    /// searchable as `source_type=<route key>`.
    ReceivingUnparsed,
    /// Published and receiving.
    Receiving,
    /// Published, but nothing arrived in the window.
    NoRecentData,
}

/// Per-source connect state, as the list, detail and Connect step show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LogSourceConnectStatus {
    #[serde(with = "crate::typeid::log_source")]
    #[schema(value_type = String)]
    pub source_id: Uuid,
    /// The `source_type` this source's events carry.
    pub route_key: String,
    pub state: ConnectState,
    pub deployed: bool,
    pub lifecycle_status: String,
    /// Whether a token can be bound to this source (push transports only).
    pub push_capable: bool,
    pub events_24h: u64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    /// Active ingest tokens bound to this source.
    pub active_tokens: u32,
    /// Most recent use of any of those tokens (sampled from Vector, approximate).
    pub token_last_used_at: Option<DateTime<Utc>>,
}

/// A route key that arrives but no log source claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UnassignedSource {
    pub route_key: String,
    pub events_24h: u64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    /// Whether the key can become a source's route key as is
    /// ([`validate_route_key`]). A key that cannot is still shown, so an
    /// operator sees the traffic, but must be fixed at the sender.
    pub convertible: bool,
}

/// Every route key a log source claims: its match values (the router routes
/// on each of them), else its safe name. Lowercased, like the rollup key.
pub fn claimed_route_keys(sources: &[LogSource]) -> BTreeSet<String> {
    let mut claimed = BTreeSet::new();
    for source in sources {
        match source.match_values.as_deref() {
            Some(values) if !values.is_empty() => {
                claimed.extend(values.iter().map(|v| v.trim().to_lowercase()));
            }
            _ => {
                claimed.insert(crate::vector_naming::safe_name(&source.name));
            }
        }
    }
    claimed
}

/// The route key a source's events carry: exactly the token binding's key
/// ([`route_key`]), so the state shown and the routing never disagree.
pub fn source_route_key(source: &LogSource) -> String {
    route_key(source.match_values.as_deref(), &source.name)
}

/// Whether `key` may become a log source's route key. The key is rendered
/// into generated Vector configuration (router conditions and the tokens
/// file), and an unassigned key comes straight from a sender's header, so
/// only a conservative identifier alphabet is accepted: lowercase ASCII
/// letters, digits, `_`, `-` and `.`, starting with a letter or digit.
pub fn validate_route_key(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > MAX_ROUTE_KEY_LEN {
        return Err(format!("A source key must be 1 to {MAX_ROUTE_KEY_LEN} characters"));
    }
    let mut chars = key.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest_ok = chars.all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '.')
    });
    if !first_ok || !rest_ok {
        return Err(
            "A source key may contain only lowercase letters, digits, '_', '-' and '.', \
             and must start with a letter or digit"
                .into(),
        );
    }
    if is_system_route_key(key) {
        return Err(format!("{key:?} is assigned by the platform and cannot name a source"));
    }
    Ok(())
}

fn is_system_route_key(key: &str) -> bool {
    SYSTEM_ROUTE_KEYS.contains(&key)
        || key.starts_with("nano_enrich")
        || crate::auth::scope::is_reserved_source_type(key)
        // NAN-5032: `audit` / `findings` (and the rewrite marker) are written by
        // nano itself; they never name a sender's source.
        || crate::auth::reserved_source_types::classify(key)
            == crate::auth::reserved_source_types::Reservation::Enforced
        || key == crate::auth::reserved_source_types::SPOOF_MARKER
}

/// Derives a source's state from what it is and what arrived for it.
///
/// `enabled` only matters once a parser is published: a draft is created
/// disabled (deploy enables it), yet its tokens already route events, which
/// land unparsed. A published source switched off no longer parses.
pub fn connect_state(enabled: bool, deployed: bool, events_24h: u64) -> ConnectState {
    match (deployed, enabled, events_24h > 0) {
        (false, _, false) => ConnectState::AwaitingData,
        (false, _, true) => ConnectState::ReceivingUnparsed,
        (true, false, _) => ConnectState::Disabled,
        (true, true, true) => ConnectState::Receiving,
        (true, true, false) => ConnectState::NoRecentData,
    }
}

/// Per-source statuses from the sources, the activity scan and the tokens.
/// Enrichment sources (no log route) are skipped.
pub fn connect_statuses(
    sources: &[LogSource],
    activity: &[SourceActivity],
    tokens: &[IngestToken],
) -> Vec<LogSourceConnectStatus> {
    let by_key: HashMap<&str, &SourceActivity> =
        activity.iter().map(|a| (a.route_key.as_str(), a)).collect();
    sources
        .iter()
        .filter(|source| source.kind != "enrichment")
        .map(|source| {
            let key = source_route_key(source);
            let seen = by_key.get(key.to_lowercase().as_str()).copied();
            let bound: Vec<&IngestToken> = tokens
                .iter()
                .filter(|t| t.state == "active" && t.source_id == Some(source.id))
                .collect();
            let events_24h = seen.map_or(0, |a| a.events_24h);
            LogSourceConnectStatus {
                source_id: source.id,
                state: connect_state(source.enabled, source.deployed, events_24h),
                deployed: source.deployed,
                lifecycle_status: source.lifecycle_status.clone(),
                push_capable: is_push_capable(&source.source_type),
                events_24h,
                first_seen: seen.and_then(|a| a.first_seen),
                last_seen: seen.and_then(|a| a.last_seen),
                active_tokens: bound.len() as u32,
                token_last_used_at: bound.iter().filter_map(|t| t.last_used_at).max(),
                route_key: key,
            }
        })
        .collect()
}

/// Route keys in the activity scan that no source claims, busiest first.
/// Platform-assigned keys (`unknown`, `parse_failure`, the enrichment lane)
/// are left out.
pub fn unassigned_sources(
    sources: &[LogSource],
    activity: &[SourceActivity],
) -> Vec<UnassignedSource> {
    let claimed = claimed_route_keys(sources);
    let mut out: Vec<UnassignedSource> = activity
        .iter()
        .filter(|a| a.events_24h > 0)
        .filter(|a| !claimed.contains(&a.route_key) && !is_system_route_key(&a.route_key))
        .map(|a| UnassignedSource {
            route_key: a.route_key.clone(),
            events_24h: a.events_24h,
            first_seen: a.first_seen,
            last_seen: a.last_seen,
            convertible: validate_route_key(&a.route_key).is_ok(),
        })
        .collect();
    out.sort_by(|a, b| b.events_24h.cmp(&a.events_24h).then(a.route_key.cmp(&b.route_key)));
    out
}

/// Reads per-route-key ingest from the profile-aware `logs_per_source_5m_v2`
/// rollup (7-day TTL): one aggregate scan, no raw-table read.
#[derive(Clone)]
pub struct SourceActivityReader {
    ch: ClickHouseClient,
    table_names: crate::db::TableNames,
}

/// The rollup scan. The caller's deny set is applied on the raw scope key,
/// exactly as the ingestion-history reads do (NAN-2059), so a denied source
/// never appears, not even as an unassigned key.
///
/// `keys = None` is the unassigned inventory: every key, busiest first, capped
/// at [`ACTIVITY_ROW_LIMIT`]. `keys = Some(..)` reads exactly those (known)
/// route keys with no cap, so a quiet source among many noisy unassigned keys
/// still reads as receiving (codex P2-4).
pub fn activity_sql(
    rollup_table: &str,
    profile: &str,
    hours: i64,
    scope: &ScopeSet,
    keys: Option<&[String]>,
) -> String {
    let (key_sql, limit_sql) = match keys {
        Some(keys) => {
            let list = keys
                .iter()
                .map(|k| format!("'{}'", crate::sql_hygiene::escape_sql_string(k.trim().to_lowercase())))
                .collect::<Vec<_>>()
                .join(", ");
            (format!(" AND source_type IN ({list})"), String::new())
        }
        None => (String::new(), format!(" LIMIT {ACTIVITY_ROW_LIMIT}")),
    };
    let scope_sql = if scope.is_restricted() {
        let predicate = source_scope_sql_predicate("scope_source_type", scope.deny_set())
            .expect("a restricted ScopeSet always renders a predicate");
        format!(" AND scope_source_type_complete = 1 AND {predicate}")
    } else {
        String::new()
    };
    format!(
        "SELECT source_type AS route_key, sum(events) AS events, \
                toUnixTimestamp64Milli(min(first_event_at)) AS first_ms, \
                toUnixTimestamp64Milli(max(last_event_at)) AS last_ms \
         FROM {rollup_table} \
         WHERE bucket_start >= now() - INTERVAL {hours} HOUR \
           AND schema_profile = '{profile}'{scope_sql}{key_sql} \
         GROUP BY route_key \
         ORDER BY events DESC{limit_sql}",
        profile = crate::sql_hygiene::escape_sql_string(profile),
    )
}

/// Parses the scan's `JSONEachRow` output (UInt64 arrives quoted).
pub fn parse_activity_rows(body: &str) -> Vec<SourceActivity> {
    fn num(json: &serde_json::Value, key: &str) -> Option<i64> {
        json.get(key).and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_u64().map(|u| u as i64))
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
    }
    fn at(ms: Option<i64>) -> Option<DateTime<Utc>> {
        ms.filter(|ms| *ms > 0).and_then(DateTime::from_timestamp_millis)
    }
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|json| {
            Some(SourceActivity {
                route_key: json.get("route_key")?.as_str()?.to_string(),
                events_24h: num(&json, "events").unwrap_or(0).max(0) as u64,
                first_seen: at(num(&json, "first_ms")),
                last_seen: at(num(&json, "last_ms")),
            })
        })
        .collect()
}

impl SourceActivityReader {
    pub fn new(ch: ClickHouseClient, table_names: crate::db::TableNames) -> Self {
        Self { ch, table_names }
    }

    /// Ingest per route key over the last `hours` (capped at the rollup's
    /// 7-day retention), visible to `scope`.
    pub async fn activity(
        &self,
        hours: i64,
        scope: &ScopeSet,
    ) -> Result<Vec<SourceActivity>, String> {
        self.read(hours, scope, None).await
    }

    /// Ingest for exactly `keys` (known sources' route keys), uncapped. Empty
    /// `keys` reads nothing.
    pub async fn activity_for(
        &self,
        keys: &[String],
        hours: i64,
        scope: &ScopeSet,
    ) -> Result<Vec<SourceActivity>, String> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        self.read(hours, scope, Some(keys)).await
    }

    async fn read(
        &self,
        hours: i64,
        scope: &ScopeSet,
        keys: Option<&[String]>,
    ) -> Result<Vec<SourceActivity>, String> {
        let hours = hours.clamp(1, 7 * 24);
        let sql = activity_sql(
            &self.table_names.read("logs_per_source_5m_v2"),
            crate::schema::active_log_telemetry_profile(),
            hours,
            scope,
            keys,
        );
        let mut cursor = self
            .ch
            .query(&sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| e.to_string())?;
        let mut body = Vec::new();
        while let Some(chunk) = cursor.next().await.map_err(|e| e.to_string())? {
            body.extend_from_slice(&chunk);
        }
        let body = String::from_utf8(body).map_err(|e| e.to_string())?;
        Ok(parse_activity_rows(&body))
    }
}

/// `POST /api/log-sources/unassigned/convert`.
#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConvertUnassignedRequest {
    /// The unassigned key; it becomes the new source's route key unchanged.
    pub route_key: String,
    /// Display name (defaults to the key).
    #[serde(default)]
    pub name: Option<String>,
    /// An unbound ingest token to bind to the new source. Same value: the
    /// sender keeps its configuration.
    #[serde(default)]
    pub credential_id: Option<Uuid>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
}

/// The converted source, and the token bound to it when one was named.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ConvertUnassignedResponse {
    pub log_source: LogSource,
    pub bound_token: Option<IngestToken>,
    /// The token is bound but Vector's tokens file update failed; the
    /// background reconcile retries it within 30 s.
    pub publication_pending: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    #[error("{0}")]
    InvalidKey(String),
    /// Another log source already routes on this key.
    #[error("log source {0:?} already receives source key {1:?}")]
    AlreadyClaimed(String, String),
    /// The named token is not unbound (active or revoked) or does not exist.
    #[error("{0}")]
    Token(#[from] IngestTokenServiceError),
    #[error("{0}")]
    TokenNotUnbound(String),
    #[error(transparent)]
    Source(#[from] LogSourceServiceError),
    #[error("conversion lock: {0}")]
    Database(#[from] sqlx::Error),
}

/// Converts an unassigned route key into a draft log source, binding an
/// unbound token when one is named. No token value changes, so every sender
/// keeps working: legacy-multiplex senders keep declaring the same type, and a
/// bound token now routes on the key it already carried.
///
/// The token is checked before the source is created, so the common refusals
/// leave nothing behind; if the bind itself then fails (a race), the draft is
/// deleted again.
pub async fn convert_unassigned(
    pool: &PgPool,
    sources: &LogSourceService,
    tokens: &IngestTokenService,
    request: ConvertUnassignedRequest,
    actor: Option<Uuid>,
) -> Result<ConvertUnassignedResponse, ConvertError> {
    let key = request.route_key.trim().to_string();
    validate_route_key(&key).map_err(ConvertError::InvalidKey)?;

    // Check-then-create across API replicas (codex P1-2): a PostgreSQL
    // transaction-scoped advisory lock on the normalized key is held for the
    // claim check, the draft insert and the token bind, so two concurrent
    // conversions of one key (on any replica) cannot both pass the check. The
    // loser waits, then sees the winner's claim and binds nothing. The lock
    // transaction itself writes nothing; ending it releases the lock.
    let mut lock = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2))")
        .bind(CONVERT_LOCK_CLASS)
        .bind(&key)
        .execute(&mut *lock)
        .await?;
    let result = convert_locked(sources, tokens, key, request, actor).await;
    if let Err(error) = lock.rollback().await {
        tracing::warn!(%error, "releasing the conversion lock failed; it is released when the connection closes");
    }
    result
}

/// Advisory-lock class for route-key conversions (first `int4` of the pair).
const CONVERT_LOCK_CLASS: i32 = 0x4e34_9120;

async fn convert_locked(
    sources: &LogSourceService,
    tokens: &IngestTokenService,
    key: String,
    request: ConvertUnassignedRequest,
    actor: Option<Uuid>,
) -> Result<ConvertUnassignedResponse, ConvertError> {
    let existing = sources.list(None).await?;
    if let Some(owner) = existing.iter().find(|s| claimed_route_keys(std::slice::from_ref(*s)).contains(&key)) {
        return Err(ConvertError::AlreadyClaimed(owner.name.clone(), key));
    }

    if let Some(id) = request.credential_id {
        let token = tokens.get(id).await?.ok_or(IngestTokenServiceError::NotFound)?;
        if token.state != "unbound" {
            return Err(ConvertError::TokenNotUnbound(format!(
                "Ingest token {:?} is {}; only an unbound token can be assigned",
                token.name, token.state
            )));
        }
        tokens.ensure_delivery()?;
    }

    let name = request
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .unwrap_or(&key)
        .to_string();
    let log_source = sources
        .create(NewLogSource {
            name,
            description: None,
            namespace: "default".into(),
            timezone: "UTC".into(),
            source_type: "routed".into(),
            parser_vrl: String::new(),
            output_fields: None,
            dispatch_source_config_id: None,
            category: request.category.filter(|v| !v.trim().is_empty()),
            vendor: request.vendor.filter(|v| !v.trim().is_empty()),
            product: request.product.filter(|v| !v.trim().is_empty()),
            icon: None,
            color: None,
            match_field: None,
            match_pattern: None,
            match_values: Some(vec![key.clone()]),
            sampling_ratio: None,
            sampling_exclude_condition: None,
            lifecycle_status: Some("draft".into()),
        })
        .await?;

    let Some(credential_id) = request.credential_id else {
        return Ok(ConvertUnassignedResponse {
            log_source,
            bound_token: None,
            publication_pending: false,
        });
    };
    match tokens.bind(credential_id, log_source.id, actor).await {
        Ok(token) => Ok(ConvertUnassignedResponse {
            log_source,
            bound_token: Some(token),
            publication_pending: false,
        }),
        // Bound in the database; only the file write failed. The reconcile
        // republishes it, so the conversion stands.
        Err(IngestTokenServiceError::Publish { .. }) => Ok(ConvertUnassignedResponse {
            bound_token: tokens.get(credential_id).await.ok().flatten(),
            log_source,
            publication_pending: true,
        }),
        Err(error) => {
            if let Err(cleanup) = sources.delete(log_source.id).await {
                tracing::warn!(%cleanup, source_id = %log_source.id, "could not remove the draft source of a failed conversion");
            }
            Err(error.into())
        }
    }
}
