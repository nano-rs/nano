// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audit Query Service
//!
//! Queries audit events from ClickHouse (source_type='audit') instead of PostgreSQL.
//! This provides access to the full audit trail including events emitted via emit_audit().

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::db::DualPool;

/// Errors from audit query operations
#[derive(Debug, Error)]
pub enum AuditQueryError {
    #[error("ClickHouse query error: {0}")]
    QueryError(String),
    #[error("ClickHouse not available")]
    NotAvailable,
}

/// Query parameters for audit log search
#[derive(Debug, Clone, Default)]
pub struct ClickHouseAuditQuery {
    /// Filter by actor ID (from metadata)
    pub actor_id: Option<Uuid>,
    /// Filter by action
    pub action: Option<String>,
    /// Filter by source subsystem
    pub source: Option<String>,
    /// Filter by resource type (from metadata)
    pub resource_type: Option<String>,
    /// Filter by time range start
    pub start_time: Option<DateTime<Utc>>,
    /// Filter by time range end
    pub end_time: Option<DateTime<Utc>>,
    /// Filter by success/failure status
    pub success: Option<bool>,
    /// Case-insensitive free-text match over the whole event: message, action,
    /// actor, source IP and the metadata JSON (resource, API key, details).
    /// NAN-5308: the audit page's search box filters server-side through this,
    /// so it covers every matching row, not only the loaded page.
    pub search: Option<String>,
    /// Result limit
    pub limit: Option<i64>,
    /// Result offset
    pub offset: Option<i64>,
}

/// A single audit log entry from ClickHouse
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickHouseAuditEntry {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub user: Option<String>,
    pub action: Option<String>,
    pub source: Option<String>,
    pub src_ip: Option<String>,
    pub user_agent: Option<String>,
    pub status: Option<String>,
    pub message: String,
    pub metadata: serde_json::Value,
    /// Extracted from metadata for convenience
    pub actor_id: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub resource_name: Option<String>,
    /// API key ID if the action was authenticated via an API key
    pub api_key_id: Option<String>,
    /// API key display name if the action was authenticated via an API key
    pub api_key_name: Option<String>,
}

/// Row returned from ClickHouse
#[derive(Debug, clickhouse::Row, Deserialize)]
struct AuditRow {
    id: String,
    timestamp_str: String,
    #[serde(rename = "user_val")]
    user_val: String,
    action: String,
    source: String,
    src_ip: String,
    user_agent: String,
    status: String,
    message: String,
    metadata: String,
}

/// Row for count query
#[derive(Debug, clickhouse::Row, Deserialize)]
struct CountRow {
    count: u64,
}

/// Row for distinct values
#[derive(Debug, clickhouse::Row, Deserialize)]
struct StringRow {
    value: String,
}

/// Row for the per-API-key daily usage aggregation. `day` is a UTC calendar
/// date rendered as `YYYY-MM-DD` (via `toString(toDate(...))`) so it round-trips
/// cleanly into `chrono::NaiveDate` without depending on the ClickHouse client's
/// `Date` codec.
#[derive(Debug, clickhouse::Row, Deserialize)]
struct DailyUsageRow {
    day: String,
    count: u64,
}

/// Resolved time range and filter flags for building WHERE clauses
struct ResolvedFilters {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    /// Filter conditions (each a bound template), ANDed after the audit scope.
    conditions: Vec<&'static str>,
    has_action: bool,
    has_source: bool,
    has_actor: bool,
    has_resource_type: bool,
    has_status: bool,
    status_filter: Option<&'static str>,
    search: Option<String>,
}

/// Longest free-text needle accepted for audit search.
pub const AUDIT_SEARCH_MAX_CHARS: usize = 256;

/// Normalize a free-text audit search: trimmed, empty → `None`, capped at
/// [`AUDIT_SEARCH_MAX_CHARS`] characters.
pub fn normalize_audit_search(raw: Option<&str>) -> Option<String> {
    // NUL can never match stored text, and PostgreSQL rejects it outright
    // (the degraded path would answer 503).
    let cleaned: String = raw?.chars().filter(|c| *c != '\0').collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(AUDIT_SEARCH_MAX_CHARS).collect())
}

/// ClickHouse predicate for [`ClickHouseAuditQuery::search`]. A substring
/// position check (not LIKE), so `%` / `_` in the needle are literal. The
/// needle is always a bound parameter.
///
/// The metadata JSON is searched with its object KEYS stripped
/// (`"actor_id":`, `"resource_name":`, …): every audit row carries the same
/// keys, so matching them made `q=actor`, `q=key`, `q=_` return every row.
/// The pattern has no `?` (the clickhouse client reads `?` as a placeholder).
pub(crate) const AUDIT_SEARCH_CONDITION: &str = concat!(
    "positionCaseInsensitiveUTF8(concat(message, ' ', action, ' ', `user`, ' ', src_ip, ' ', ",
    r#"replaceRegexpAll(metadata, '"([^"\\\\]|\\\\.)*"\\s*:', ' ')), ?) > 0"#,
);

/// Build shared WHERE clause and resolved time range from a query
fn resolve_filters(query: &ClickHouseAuditQuery) -> ResolvedFilters {
    let start_time = query
        .start_time
        .unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let end_time = query.end_time.unwrap_or_else(|| Utc::now());
    let status_filter = query.success.map(|s| if s { "success" } else { "failure" });

    let mut conditions = Vec::new();
    let has_action = query.action.is_some();
    let has_source = query.source.is_some();
    let has_actor = query.actor_id.is_some();
    let has_resource_type = query.resource_type.is_some();
    let has_status = status_filter.is_some();

    if has_action {
        conditions.push("action = ?");
    }
    if has_source {
        conditions.push("source = ?");
    }
    if has_actor {
        conditions.push("JSONExtractString(metadata, 'actor_id') = ?");
    }
    if has_resource_type {
        conditions.push("JSONExtractString(metadata, 'resource_type') = ?");
    }
    if has_status {
        conditions.push("status = ?");
    }
    let search = normalize_audit_search(query.search.as_deref());
    if search.is_some() {
        conditions.push(AUDIT_SEARCH_CONDITION);
    }

    ResolvedFilters {
        start: start_time,
        end: end_time,
        conditions,
        has_action,
        has_source,
        has_actor,
        has_resource_type,
        has_status,
        status_filter,
        search,
    }
}

/// Bind filter parameters to a ClickHouse query cursor
fn bind_filters<'a>(
    mut q: clickhouse::query::Query,
    query: &ClickHouseAuditQuery,
    filters: &ResolvedFilters,
) -> clickhouse::query::Query {
    if filters.has_action {
        q = q.bind(query.action.as_deref().unwrap_or(""));
    }
    if filters.has_source {
        q = q.bind(query.source.as_deref().unwrap_or(""));
    }
    if filters.has_actor {
        q = q.bind(query.actor_id.map(|id| id.to_string()).unwrap_or_default());
    }
    if filters.has_resource_type {
        q = q.bind(query.resource_type.as_deref().unwrap_or(""));
    }
    if filters.has_status {
        q = q.bind(filters.status_filter.unwrap_or(""));
    }
    if let Some(search) = &filters.search {
        q = q.bind(search.as_str());
    }
    q
}

fn row_to_entry(row: AuditRow) -> ClickHouseAuditEntry {
    let metadata: serde_json::Value =
        serde_json::from_str(&row.metadata).unwrap_or(serde_json::Value::Null);

    let timestamp =
        chrono::NaiveDateTime::parse_from_str(&row.timestamp_str, "%Y-%m-%d %H:%M:%S%.f")
            .map(|ndt| ndt.and_utc())
            .unwrap_or_default();

    ClickHouseAuditEntry {
        event_id: row.id,
        timestamp,
        // Prefer the display-case actor name preserved in metadata: the `user`
        // column is lowercased at write time (LOWERCASE_NORMALIZED_FIELDS
        // contract, NAN-1432) so the search-bar raw-equality fast path finds
        // audit rows. `actor_name` is present on both pre- and post-fix rows;
        // the column is the fallback for rows without it.
        user: metadata
            .get("actor_name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .or_else(|| {
                if row.user_val.is_empty() {
                    None
                } else {
                    Some(row.user_val)
                }
            }),
        action: if row.action.is_empty() {
            None
        } else {
            Some(row.action)
        },
        source: if row.source.is_empty() {
            None
        } else {
            Some(row.source)
        },
        src_ip: if row.src_ip.is_empty() {
            None
        } else {
            Some(row.src_ip)
        },
        user_agent: if row.user_agent.is_empty() {
            None
        } else {
            Some(row.user_agent)
        },
        status: if row.status.is_empty() {
            None
        } else {
            Some(row.status)
        },
        message: row.message,
        actor_id: metadata
            .get("actor_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        resource_type: metadata
            .get("resource_type")
            .and_then(|v| v.as_str())
            .map(String::from),
        resource_id: metadata
            .get("resource_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        resource_name: metadata
            .get("resource_name")
            .and_then(|v| v.as_str())
            .map(String::from),
        api_key_id: metadata
            .get("api_key_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        api_key_name: metadata
            .get("api_key_name")
            .and_then(|v| v.as_str())
            .map(String::from),
        metadata,
    }
}

/// Where the audit trail lives for the active schema profile (NAN-5346).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuditStore {
    /// UDM: `source_type = 'audit'` rows in `logs`.
    Udm,
    /// OCSF: the API Activity (6003) rows the emitter writes to `ocsf_logs`
    /// with `source_type = 'audit'`, unioned with the UDM rows in `logs` and
    /// deduplicated by audit event id (see [`plan_sources`]).
    Ocsf,
}

/// The audit columns every reader uses, projected from an OCSF audit row.
/// `metadata` is the `unmapped` object, which carries the same keys as the
/// UDM row's metadata JSON (`AuditEvent::to_ocsf_event`). `status` comes from
/// `status_id` (1 = Success) so it reads `success` / `failure` like UDM, and
/// no alias refers to a column of its own name.
const OCSF_AUDIT_PROJECTION: &str = "id, timestamp, \
     `actor.user.name` AS `user`, `api.operation` AS action, `api.service.name` AS source, \
     `src_endpoint.ip` AS src_ip, `http_request.user_agent` AS user_agent, \
     if(status_id = 1, 'success', 'failure') AS status, message, toString(unmapped) AS metadata";

/// The same columns read from a UDM `logs` audit row, for the union with
/// [`OCSF_AUDIT_PROJECTION`].
const UDM_AUDIT_COLUMNS: &str =
    "id, timestamp, `user`, action, source, src_ip, user_agent, status, message, metadata";

/// The upper time bound of one read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UpperBound {
    /// `timestamp <= ?`
    Inclusive(DateTime<Utc>),
    /// No upper bound (the `since` readers).
    Open,
}

/// One time-bounded read of audit rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuditSegment {
    pub(crate) store: AuditStore,
    pub(crate) table: String,
    pub(crate) start: DateTime<Utc>,
    pub(crate) end: UpperBound,
    /// UDM segment only: the OCSF table whose copies this read skips
    /// ([`AUDIT_DEDUP_KEY_UDM`] against [`AUDIT_DEDUP_KEYS_OCSF`]).
    pub(crate) skip_copies_in: Option<String>,
    /// OCSF segment only (NAN-5356): the `logs` table holding the UDM
    /// originals of legacy case copies, which this read hides
    /// ([`LEGACY_CASE_ORIGINAL_LOOKBACK_SECS`]).
    pub(crate) legacy_originals_in: Option<String>,
}

/// NAN-5346: the dedupe key of a UDM audit row. Rows written since NAN-5346
/// (and case rows since NAN-5356) carry the audit `event_id` in their
/// metadata, which is the OCSF copy's row `id`. Older rows fall back to (event
/// time in milliseconds, message): the OCSF copy's timestamp is derived from
/// `event.time`, the same `occurred_at` in milliseconds, and both copies carry
/// the same message. Legacy case rows ([`UDM_LEGACY_CASE`]) match neither and
/// are not deduplicated here: the UDM row is canonical for them.
const AUDIT_DEDUP_KEY_UDM: &str = "if(JSONExtractString(metadata, 'event_id') != '', \
     JSONExtractString(metadata, 'event_id'), \
     concat(toString(toUnixTimestamp64Milli(timestamp)), '|', message))";

/// Both keys an OCSF audit row can match: its `id` (the event id) and the
/// fallback key of a pre-NAN-5346 UDM row.
const AUDIT_DEDUP_KEYS_OCSF: &str =
    "arrayJoin([toString(id), concat(toString(toUnixTimestamp64Milli(timestamp)), '|', message)])";

/// NAN-5356: a legacy (pre-fix) row of the case lifecycle writer
/// (`cases::audit::CaseAuditEvent`) in `logs`: source `case`, no `event_id`,
/// and the case metadata shape. Platform audit events with source `case`
/// (the case handlers' `AuditEvent`s) carry `resource_type` in their metadata
/// and keep the (ms, message) key, which pairs them already.
///
/// Before NAN-5356 the case writer saved this UDM row first and then, only if
/// that insert succeeded, a separate OCSF copy (new id, ~80 ms later, another
/// message). No key links the two, so the UDM row is CANONICAL: every legacy
/// UDM case row is shown, and its OCSF copy ([`OCSF_LEGACY_CASE`]) is hidden.
/// Nothing is paired, so a failed mirror write can never hide or swap an
/// event.
const UDM_LEGACY_CASE: &str = "source = 'case' AND JSONExtractString(metadata, 'event_id') = '' \
     AND NOT JSONHas(metadata, 'resource_type') AND JSONHas(metadata, 'case_title')";

/// NAN-5356: a legacy OCSF copy of a case lifecycle event. Its
/// `unmapped.details` is the writer's UDM metadata (`case_title`,
/// `alert_count`, `entity_count`, ...), which carries `event_id` since the fix.
///
/// Read through the JSON subcolumns, not `toString(unmapped)`: serializing
/// the object per path made the predicate ~30x slower.
const OCSF_LEGACY_CASE: &str = "`api.service.name` = 'case' \
     AND unmapped.details.event_id IS NULL \
     AND unmapped.details.case_title IS NOT NULL \
     AND unmapped.details.alert_count IS NOT NULL \
     AND unmapped.details.entity_count IS NOT NULL";

/// NAN-5356: how far before a legacy OCSF case copy its UDM original can be.
/// The writer stamped the copy right after the original's insert returned
/// (~80 ms in practice); five minutes covers a slow insert with a wide margin.
///
/// A legacy copy is hidden when a legacy UDM case row with the same case
/// fingerprint ([`CASE_FINGERPRINT_KEYS`]) is within this lookback before it.
/// It is shown only as an ORPHAN, whose original is gone: `logs` and
/// `ocsf_logs` share the retention setting (NAN-5346), but TTL deletes happen
/// at merge time per table, the cold-storage warm TTL covers `logs` only, and
/// the disk-pressure evictor drops partitions per table, so near the
/// retention edge `logs` can lose a row before `ocsf_logs`. Then the copy is
/// the only record of the event and is shown rather than nothing.
///
/// Known edge: at the very start of a query window an original just before
/// the window hides its copy just inside it, so the event is not listed in
/// that window; widening the window shows it.
const LEGACY_CASE_ORIGINAL_LOOKBACK_SECS: i64 = 300;

/// The case-event fields (keys of the UDM `metadata` JSON and of the OCSF
/// copy's `unmapped.details`) in the case fingerprint, after the case id,
/// action, case status and severity. Strings only: both stores render them
/// identically, and a JSON `null` reads as `''` on both.
const CASE_FINGERPRINT_KEYS: [&str; 10] = [
    "case_title",
    "actor_id",
    "alert_id",
    "previous_status",
    "disposition",
    "assigned_to",
    "entity_type",
    "entity_value",
    "related_case_id",
    "notes",
];

/// `cityHash64(<case id>, <action>, <status>, <severity>, <detail fields>)`.
/// One argument per field, so no separator can make two tuples collide.
fn case_fingerprint(case_id: &str, action: &str, status: &str, severity: &str, field: impl Fn(&str) -> String) -> String {
    let mut args = vec![case_id.to_string(), action.to_string(), status.to_string(), severity.to_string()];
    args.extend(CASE_FINGERPRINT_KEYS.iter().map(|k| field(k)));
    format!("cityHash64({})", args.join(", "))
}

/// The UDM side of the case fingerprint (`session_id` holds the case id).
fn case_fingerprint_udm() -> String {
    case_fingerprint("session_id", "action", "status", "severity", |k| {
        format!("JSONExtractString(metadata, '{k}')")
    })
}

/// The OCSF side, over the `unmapped` JSON subcolumns. A path the copy does
/// not carry (a JSON `null` is not stored) reads as `''`, like
/// `JSONExtractString` on the UDM side. A string the JSON type inferred as a
/// date renders back as the same text; one it would re-render differently
/// (an ISO timestamp in `notes`) only fails to match, which shows the copy
/// (a duplicate), never hides an event.
fn case_fingerprint_ocsf() -> String {
    case_fingerprint(
        &ocsf_unmapped_string("resource_id"),
        "`api.operation`",
        &ocsf_unmapped_string("details.status"),
        &ocsf_unmapped_string("details.severity"),
        |k| ocsf_unmapped_string(&format!("details.{k}")),
    )
}

/// `unmapped.<path>` as a String, `''` when absent.
fn ocsf_unmapped_string(path: &str) -> String {
    format!("ifNull(CAST(unmapped.{path}, 'Nullable(String)'), '')")
}

/// The lookback bucket of a row: `intDiv(<unix seconds>, lookback)`.
fn lookback_bucket() -> String {
    format!("intDiv(toUnixTimestamp(timestamp), {LEGACY_CASE_ORIGINAL_LOOKBACK_SECS})")
}

/// The key of a legacy OCSF case copy: fingerprint and lookback bucket.
/// The reader computes it only for legacy case copies (`''` otherwise, which
/// no original offers), so the JSON work is skipped on every other row.
fn legacy_copy_key() -> String {
    format!("concat(toString({}), '|', toString({}))", case_fingerprint_ocsf(), lookback_bucket())
}

/// The keys a legacy UDM case original offers: its fingerprint with its own
/// lookback bucket and the next one. A copy at most one lookback after its
/// original is in one of the two, so it matches.
fn legacy_original_keys() -> String {
    let fp = case_fingerprint_udm();
    let b = lookback_bucket();
    format!("arrayJoin([concat(toString({fp}), '|', toString({b})), concat(toString({fp}), '|', toString({b} + 1))])")
}

impl AuditSegment {
    fn time(&self) -> &'static str {
        match self.end {
            UpperBound::Inclusive(_) => "timestamp >= ? AND timestamp <= ?",
            UpperBound::Open => "timestamp >= ?",
        }
    }

    fn time_binds(&self) -> Vec<String> {
        self.binds_from(self.start)
    }

    fn binds_from(&self, start: DateTime<Utc>) -> Vec<String> {
        let mut binds = vec![crate::sql_hygiene::format_ch_bound_micros(&start)];
        if let UpperBound::Inclusive(t) = &self.end {
            binds.push(crate::sql_hygiene::format_ch_bound_micros(t));
        }
        binds
    }

    /// Binds in SQL order: the window, then the window of the subquery: the
    /// same window for the UDM copy-skipping read, the window widened by the
    /// lookback for the OCSF legacy-original read.
    fn binds(&self) -> Vec<String> {
        let mut binds = self.time_binds();
        if self.skip_copies_in.is_some() {
            binds.extend(self.time_binds());
        }
        if self.legacy_originals_in.is_some() {
            let lookback = chrono::Duration::seconds(LEGACY_CASE_ORIGINAL_LOOKBACK_SECS);
            binds.extend(self.binds_from(self.start - lookback));
        }
        binds
    }

    /// The scope of this read: window, audit rows and, in the OCSF union,
    /// the dedupe. One WHERE.
    ///
    /// * UDM: not an event whose OCSF copy is in the same window, except a
    ///   legacy case row, which is always kept (it is canonical).
    /// * OCSF: not a legacy case copy whose UDM original exists.
    fn predicate(&self) -> String {
        let mut predicate = format!("{} AND source_type = 'audit'", self.time());
        if let Some(ocsf) = &self.skip_copies_in {
            predicate.push_str(&format!(
                " AND (({UDM_LEGACY_CASE}) OR {AUDIT_DEDUP_KEY_UDM} GLOBAL NOT IN \
                 (SELECT {AUDIT_DEDUP_KEYS_OCSF} FROM {ocsf} WHERE {} AND source_type = 'audit'))",
                self.time()
            ));
        }
        if let Some(logs) = &self.legacy_originals_in {
            predicate.push_str(&format!(
                " AND if({OCSF_LEGACY_CASE}, {}, '') GLOBAL NOT IN \
                 (SELECT {} FROM {logs} WHERE {} AND source_type = 'audit' AND {UDM_LEGACY_CASE})",
                legacy_copy_key(),
                legacy_original_keys(),
                self.time()
            ));
        }
        predicate
    }

    /// `SELECT <audit columns> FROM <table> WHERE <predicate>`.
    fn select(&self) -> String {
        let columns = match self.store {
            AuditStore::Udm => UDM_AUDIT_COLUMNS,
            AuditStore::Ocsf => OCSF_AUDIT_PROJECTION,
        };
        format!("SELECT {columns} FROM {} WHERE {}", self.table, self.predicate())
    }
}

/// The reads a query over `[start, end]` (`end = None`: open) needs.
///
/// UDM: `logs` only. OCSF: `ocsf_logs` and `logs` over the same window. The
/// emitter still writes both copies (the UDM write stops in a later release,
/// once no N-1 reader reads only `logs`), and earlier OCSF copies were best
/// effort, so neither table alone is complete. A `logs` row is skipped when
/// its event's OCSF copy is in the window ([`AUDIT_DEDUP_KEY_UDM`]), so each
/// event appears once and an event whose OCSF copy failed still appears. No
/// copy, backfill or cutover.
pub(crate) fn plan_sources(
    store: AuditStore,
    logs_table: &str,
    ocsf_table: &str,
    start: DateTime<Utc>,
    end: Option<DateTime<Utc>>,
) -> Vec<AuditSegment> {
    let end = end.map_or(UpperBound::Open, UpperBound::Inclusive);
    let udm = |skip_copies_in| AuditSegment {
        store: AuditStore::Udm,
        table: logs_table.to_string(),
        start,
        end: end.clone(),
        skip_copies_in,
        legacy_originals_in: None,
    };
    match store {
        AuditStore::Udm => vec![udm(None)],
        AuditStore::Ocsf => vec![
            AuditSegment {
                store: AuditStore::Ocsf,
                table: ocsf_table.to_string(),
                start,
                end: end.clone(),
                skip_copies_in: None,
                legacy_originals_in: Some(logs_table.to_string()),
            },
            udm(Some(ocsf_table.to_string())),
        ],
    }
}

/// `FROM … WHERE …` over `segments`, then `conditions` (the filters, applied
/// to the audit column names). Returns the SQL and the time binds, which come
/// first, in order; the filter binds follow.
///
/// One UDM segment (the UDM profile): one WHERE carrying the time bounds, the
/// audit scope and the filters, the pre-OCSF reader minus its PREWHERE
/// (CLAUDE.md, NAN-1412). Otherwise each segment is a subquery projecting the
/// audit columns (`UNION ALL` when there are two) and the filters apply to
/// that, so every filter and the free-text search read the same names.
pub(crate) fn audit_from(segments: &[AuditSegment], conditions: &[&str]) -> (String, Vec<String>) {
    let binds: Vec<String> = segments.iter().flat_map(AuditSegment::binds).collect();
    if let [only] = segments {
        if only.store == AuditStore::Udm {
            let mut sql = format!("FROM {} WHERE {}", only.table, only.predicate());
            for c in conditions {
                sql.push_str(" AND ");
                sql.push_str(c);
            }
            return (sql, binds);
        }
    }
    let union = segments.iter().map(AuditSegment::select).collect::<Vec<_>>().join(" UNION ALL ");
    let mut sql = format!("FROM ({union})");
    if !conditions.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&conditions.join(" AND "));
    }
    (sql, binds)
}

/// The audit page / export / lookup-history row query. Binds: the time binds,
/// the filters, limit, offset.
pub(crate) fn rows_sql(segments: &[AuditSegment], conditions: &[&str]) -> (String, Vec<String>) {
    let (from, binds) = audit_from(segments, conditions);
    (
        format!(
            "SELECT toString(id) as id, toString(timestamp) as timestamp_str, `user` as user_val, action, source, src_ip, user_agent, status, message, metadata \
             {from} \
             ORDER BY timestamp DESC \
             LIMIT ? OFFSET ?"
        ),
        binds,
    )
}

/// The total for [`rows_sql`]. Binds: the time binds, the filters.
pub(crate) fn count_sql(segments: &[AuditSegment], conditions: &[&str]) -> (String, Vec<String>) {
    let (from, binds) = audit_from(segments, conditions);
    (format!("SELECT count() as count {from}"), binds)
}

/// Distinct non-empty `action` or `source` values (the filter dropdowns).
/// Binds: the time binds.
pub(crate) fn distinct_sql(segments: &[AuditSegment], column: AuditColumn) -> (String, Vec<String>) {
    let column = column.name();
    let non_empty = format!("{column} != ''");
    let (from, binds) = audit_from(segments, &[non_empty.as_str()]);
    (format!("SELECT DISTINCT {column} as value {from} ORDER BY value"), binds)
}

/// Per-day call volume of one API key. Binds: the time binds, the key id.
pub(crate) fn api_key_daily_usage_sql(segments: &[AuditSegment]) -> (String, Vec<String>) {
    let (from, binds) = audit_from(segments, &["JSONExtractString(metadata, 'api_key_id') = ?"]);
    (
        format!(
            "SELECT toString(toDate(timestamp, 'UTC')) AS day, count() AS count \
             {from} \
             GROUP BY day \
             ORDER BY day"
        ),
        binds,
    )
}

/// An audit column with a distinct-values reader.
#[derive(Debug, Clone, Copy)]
pub(crate) enum AuditColumn {
    Action,
    Source,
}

impl AuditColumn {
    fn name(self) -> &'static str {
        match self {
            Self::Action => "action",
            Self::Source => "source",
        }
    }
}

/// Service for querying audit events from ClickHouse
#[derive(Clone)]
pub struct AuditQueryService {
    dual_pool: DualPool,
    store: AuditStore,
}

impl AuditQueryService {
    /// Create a new audit query service for the active schema profile.
    pub fn new(dual_pool: DualPool) -> Self {
        let ocsf = crate::schema::active_profile_from_env()
            .map(|p| p.id() == crate::schema::SchemaId::Ocsf)
            // Same fallback as `AuditEmitter::new`, so reader and writer agree.
            .unwrap_or(false);
        let store = if ocsf { AuditStore::Ocsf } else { AuditStore::Udm };
        Self { dual_pool, store }
    }

    /// The reads for `[start, end]` (`end = None`: open) in this profile.
    fn sources(&self, start: DateTime<Utc>, end: Option<DateTime<Utc>>) -> Vec<AuditSegment> {
        plan_sources(
            self.store,
            self.dual_pool.logs_table(),
            &self.dual_pool.table_names().read("ocsf_logs"),
            start,
            end,
        )
    }

    /// Query audit logs from ClickHouse
    pub async fn query(
        &self,
        query: &ClickHouseAuditQuery,
    ) -> Result<Vec<ClickHouseAuditEntry>, AuditQueryError> {
        let client = self.dual_pool.clickhouse();
        let limit = query.limit.unwrap_or(50).min(1000);
        let offset = query.offset.unwrap_or(0);
        let filters = resolve_filters(query);

        let segments = self.sources(filters.start, Some(filters.end));
        let (sql, time_binds) = rows_sql(&segments, &filters.conditions);

        let mut q = client.query(&sql);
        for b in &time_binds {
            q = q.bind(b.as_str());
        }
        q = bind_filters(q, query, &filters);
        q = q.bind(limit as u64);
        q = q.bind(offset as u64);

        let rows: Vec<AuditRow> = q
            .fetch_all()
            .await
            .map_err(|e| AuditQueryError::QueryError(e.to_string()))?;

        Ok(rows.into_iter().map(row_to_entry).collect())
    }

    /// Count audit logs matching query
    pub async fn count(&self, query: &ClickHouseAuditQuery) -> Result<u64, AuditQueryError> {
        let client = self.dual_pool.clickhouse();
        let filters = resolve_filters(query);

        let segments = self.sources(filters.start, Some(filters.end));
        let (sql, time_binds) = count_sql(&segments, &filters.conditions);

        let mut q = client.query(&sql);
        for b in &time_binds {
            q = q.bind(b.as_str());
        }
        q = bind_filters(q, query, &filters);

        let row: CountRow = q
            .fetch_one()
            .await
            .map_err(|e| AuditQueryError::QueryError(e.to_string()))?;

        Ok(row.count)
    }

    /// Get distinct action values from audit events
    pub async fn get_distinct_actions(&self) -> Result<Vec<String>, AuditQueryError> {
        self.distinct(AuditColumn::Action).await
    }

    /// Get distinct source values from audit events
    pub async fn get_distinct_sources(&self) -> Result<Vec<String>, AuditQueryError> {
        self.distinct(AuditColumn::Source).await
    }

    /// Distinct non-empty values of an audit column over the last 90 days.
    async fn distinct(&self, column: AuditColumn) -> Result<Vec<String>, AuditQueryError> {
        let client = self.dual_pool.clickhouse();
        let since = Utc::now() - chrono::Duration::days(90);

        let segments = self.sources(since, None);
        let (sql, time_binds) = distinct_sql(&segments, column);
        let mut q = client.query(&sql);
        for b in &time_binds {
            q = q.bind(b.as_str());
        }
        let rows: Vec<StringRow> = q
            .fetch_all()
            .await
            .map_err(|e| AuditQueryError::QueryError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.value).collect())
    }

    /// Count audited actions attributed to an API key, bucketed by UTC calendar
    /// day, for the window starting at `start` (inclusive).
    ///
    /// Reads the ClickHouse audit store (`source_type='audit'`) where the
    /// event's `metadata.api_key_id` matches the key — i.e. every action
    /// performed *via* that delegated credential (the key as the calling
    /// actor). Both handler mutations and authorization denials populate
    /// `metadata.api_key_id` (the `AuditEvent::api_key` builder), so this is the
    /// system-of-record source for per-key call volume.
    ///
    /// NAN-1622 migrated this off the retired PostgreSQL `audit_logs` table.
    /// This matches the documented "actor's api_key_id" intent: the PG column
    /// overloaded actor-credential and target-key meanings (lifecycle writers
    /// stored the *managed* key there), whereas the ClickHouse view is
    /// actor-only and additionally captures every mutation the key performed
    /// (those only ever emitted to ClickHouse). Admin lifecycle actions taken on
    /// a key carry the key in `metadata.resource_id`, not here.
    ///
    /// Returns only days with activity (sparse) ordered oldest-first; callers
    /// densify into a continuous zero-filled series.
    pub async fn api_key_daily_usage(
        &self,
        api_key_id: Uuid,
        start: DateTime<Utc>,
    ) -> Result<Vec<(chrono::NaiveDate, i64)>, AuditQueryError> {
        let client = self.dual_pool.clickhouse();

        // Bucket on the UTC calendar day explicitly so day boundaries match the
        // handler's UTC densification regardless of the column's timezone.
        let segments = self.sources(start, None);
        let (sql, time_binds) = api_key_daily_usage_sql(&segments);

        let mut q = client.query(&sql);
        for b in &time_binds {
            q = q.bind(b.as_str());
        }
        let rows: Vec<DailyUsageRow> = q
            .bind(api_key_id.to_string())
            .fetch_all()
            .await
            .map_err(|e| AuditQueryError::QueryError(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                chrono::NaiveDate::parse_from_str(&r.day, "%Y-%m-%d")
                    .map(|day| (day, r.count as i64))
                    .map_err(|e| {
                        AuditQueryError::QueryError(format!("invalid day bucket '{}': {e}", r.day))
                    })
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "query_search_tests.rs"]
mod search_tests;

#[cfg(test)]
#[path = "query_store_tests.rs"]
mod store_tests;

#[cfg(test)]
#[path = "query_case_dedupe_live_tests.rs"]
mod case_dedupe_live_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn row(user_val: &str, metadata: &str) -> AuditRow {
        AuditRow {
            id: "evt-1".to_string(),
            timestamp_str: "2026-06-12 12:00:00.000000".to_string(),
            user_val: user_val.to_string(),
            action: "rule_created".to_string(),
            source: "detection".to_string(),
            src_ip: "10.0.0.1".to_string(),
            user_agent: String::new(),
            status: "success".to_string(),
            message: "[detection] rule_created by Dan Lussier".to_string(),
            metadata: metadata.to_string(),
        }
    }

    /// NAN-1432: the `user` column is lowercased at write time so the
    /// search-bar raw-equality fast path finds audit rows; the audit page must
    /// keep rendering the display-case name, which lives in metadata.
    #[test]
    fn entry_user_prefers_display_case_actor_name_from_metadata() {
        let entry = row_to_entry(row("dan lussier", r#"{"actor_name":"Dan Lussier"}"#));
        assert_eq!(entry.user.as_deref(), Some("Dan Lussier"));
    }

    /// Rows without a metadata actor_name (system/API-key events, or legacy
    /// metadata shapes) fall back to the `user` column verbatim.
    #[test]
    fn entry_user_falls_back_to_column_without_actor_name() {
        let entry = row_to_entry(row("dan lussier", "{}"));
        assert_eq!(entry.user.as_deref(), Some("dan lussier"));

        let entry = row_to_entry(row("dan lussier", r#"{"actor_name":null}"#));
        assert_eq!(entry.user.as_deref(), Some("dan lussier"));

        let entry = row_to_entry(row("", "{}"));
        assert_eq!(entry.user, None);
    }
}
