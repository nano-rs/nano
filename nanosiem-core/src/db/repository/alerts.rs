// SPDX-License-Identifier: AGPL-3.0-or-later

//! Alert repository for CRUD operations

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::BTreeSet;
use thiserror::Error;
use uuid::Uuid;

use crate::models::{
    AcknowledgeAlert, Alert, AlertStatus, CloseAlert, Disposition, NewAlert, Severity,
};

#[derive(Error, Debug)]
pub enum AlertRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Alert not found: {0}")]
    NotFound(Uuid),
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),
    #[error("Duplicate alert: rule_id={0}, event_hash={1}")]
    DuplicateAlert(Uuid, String),
}

/// Repository for alert operations
#[derive(Clone)]
pub struct AlertRepository {
    pool: PgPool,
}

/// Compute a hash of matched events for deduplication.
///
/// Strips `_nano_*` timing metadata fields before hashing so that detection
/// timing injection doesn't break dedup (each execution injects a new
/// `_nano_detected_at`).
///
/// NAN-1711 / audit D16: for **enriched aggregate rows** — objects carrying the
/// system-injected `_first_seen` AND `_last_seen` pair (detection query
/// enrichment stamps these on stats/chart/timechart/top/rare output; genuine
/// raw events never have them) — the fields that drift under a sliding lookback
/// on otherwise-static data are also stripped: `_first_seen` (the trailing edge
/// creeps up as old events age out) and the aggregate `count`/`percent`.
/// `_last_seen` is deliberately KEPT: it is the entity's newest-activity
/// watermark, stable on static data but advancing on genuinely new events, so a
/// per-event-alert-mode aggregate rule stops re-alerting every cycle *without*
/// suppressing real new activity — mirroring the `entity + _last_seen` identity
/// the grouped finding dedup uses (D14). Raw events (no injected pair) hash
/// exactly as before, including any legitimate `count` field they carry.
///
/// This hash is also the `detection_matches (rule_id, event_hash)` ON-CONFLICT
/// key, so static aggregate windows now store ONE match row per window instead
/// of one per cycle — the intended dedup behavior, matching the alert dedup.
pub fn compute_event_hash(matched_events: &serde_json::Value) -> String {
    let mut hasher = Sha256::new();
    let clean = strip_volatile_fields(matched_events);
    let json_str = serde_json::to_string(&clean).unwrap_or_default();
    hasher.update(json_str.as_bytes());
    hex::encode(hasher.finalize())
}

/// Recursively strip `_nano_*` prefixed keys from JSON values; on enriched
/// aggregate rows (both `_first_seen` and `_last_seen` present) additionally
/// strip the drifting window fields (`_first_seen`, `count`, `percent`) while
/// keeping the `_last_seen` watermark. See [`compute_event_hash`].
fn strip_volatile_fields(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(strip_volatile_fields).collect())
        }
        serde_json::Value::Object(map) => {
            let is_enriched_aggregate =
                map.contains_key("_first_seen") && map.contains_key("_last_seen");
            let clean: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .filter(|(k, _)| {
                    if k.starts_with("_nano_") {
                        return false;
                    }
                    if is_enriched_aggregate
                        && matches!(k.as_str(), "_first_seen" | "count" | "percent")
                    {
                        return false;
                    }
                    true
                })
                .map(|(k, v)| (k.clone(), strip_volatile_fields(v)))
                .collect();
            serde_json::Value::Object(clean)
        }
        other => other.clone(),
    }
}

/// NAN-1800: derive the DISTINCT normalized `source_type` values carried by an
/// alert's matched events, for the `alerts.source_types` stamp (migration 246).
///
/// Two forms are read from each event object:
/// * `source_type` — the raw per-event column (raw / grouped-raw detection
///   rules, real-time signal alerts, vendor pass-through).
/// * `_nano_source_types` — an array the detection engine stamps onto
///   AGGREGATE rows (stats/timechart/top/rare collapse the raw stream, so the
///   rows carry no per-event `source_type`; execution annotates them with the
///   window's distinct source types). The `_nano_` prefix keeps it out of every
///   dedup hash (`compute_event_hash` strips `_nano_*`).
///
/// Values are trimmed + lowercased (OCSF source_type is NOT ingest-lowercased)
/// and returned sorted-unique. An empty result (producer events carry no
/// source_type — observability / risk-notable alerts) stamps `'{}'`, which the
/// read-side filter treats as visible-to-everyone (back-compat).
pub fn distinct_source_types(matched_events: &serde_json::Value) -> Vec<String> {
    fn insert_normalized(raw: &str, set: &mut BTreeSet<String>) {
        let norm = raw.trim().to_lowercase();
        if !norm.is_empty() {
            set.insert(norm);
        }
    }
    let mut set: BTreeSet<String> = BTreeSet::new();
    if let Some(events) = matched_events.as_array() {
        for event in events {
            // NAN-2155 (codex round 3): the PER-EVENT `source_type` is
            // ingest-controlled, so a sender could name their source after the
            // unresolved-provenance sentinel and have their own detections
            // hidden from every restricted analyst. Only the engine's
            // `_nano_source_types` annotation below may carry it.
            if let Some(st) = event
                .get("source_type")
                .and_then(|v| v.as_str())
                .filter(|st| !crate::auth::is_reserved_source_type(st))
            {
                insert_normalized(st, &mut set);
            }
            if let Some(arr) = event.get("_nano_source_types").and_then(|v| v.as_array()) {
                for v in arr {
                    if let Some(st) = v.as_str() {
                        insert_normalized(st, &mut set);
                    }
                }
            }
        }
    }
    set.into_iter().collect()
}

/// NAN-1800: build the read-side per-source scope filter fragment.
///
/// Returns `("", None)` for an EMPTY deny set so the emitted SQL is
/// byte-identical to the pre-scoping query (back-compat; system callers pass
/// `ScopeSet::unrestricted().deny_set()`). For a restricted viewer it returns
/// the `AND ($N::text[] = '{}' OR NOT (<col> && $N::text[]))` clause plus the
/// normalized (trimmed + lowercased) deny values to bind at `$N`. A row is
/// visible iff NONE of its stamped source_types is denied; rows stamped `'{}'`
/// (pre-feature / non-source-derived) never overlap and stay visible.
///
/// NAN-2155: for a RESTRICTED caller the bound values additionally carry
/// [`UNRESOLVED_SOURCE_SENTINEL`](crate::auth::UNRESOLVED_SOURCE_SENTINEL), the
/// marker the detection engine stamps when it could not determine an aggregate
/// window's source provenance. `'{}'` still means "known to have no source" and
/// stays visible; "we could not tell" is now a DIFFERENT, hidden-from-restricted
/// value instead of being conflated with it. Unrestricted callers are unaffected
/// — no clause is emitted at all, so the SQL is byte-identical.
fn scope_clause(deny: &BTreeSet<String>, column: &str, param: usize) -> (String, Option<Vec<String>>) {
    let denied = crate::auth::deny_bind_values(deny);
    if denied.is_empty() {
        (String::new(), None)
    } else {
        (
            format!(
                " AND (${p}::text[] = '{{}}' OR NOT ({col} && ${p}::text[]))",
                p = param,
                col = column
            ),
            Some(denied),
        )
    }
}

/// NAN-1541: a single alert produced by the spine, parameterized over its
/// `kind` discriminator. This is the unified raise contract: detection and the
/// three observability evaluators all build one of these and route through
/// [`AlertRepository::create_alert`].
///
/// - `kind` is one of `detection`, `metric_monitor`, `slo`, `synthetic`,
///   `risk_notable` (enforced by the migration-212 CHECK, extended by 237).
/// - `rule_id` is `Some` only for detection alerts; observability rows leave it
///   `None` (the FK is nullable).
/// - `source_id` carries the producer's identifier as text — the rule UUID for
///   detections, the monitor/check typeid for observability alerts, the
///   `<entity_type>:<entity>` pair for risk notables (NAN-1792).
/// - `event_hash` drives dedup. `Some` uses `ON CONFLICT (rule_id, event_hash)
///   DO NOTHING`; `None` skips the dedup conflict path entirely.
pub struct AlertInsert<'a> {
    pub kind: &'a str,
    pub rule_id: Option<Uuid>,
    pub source_id: Option<String>,
    pub severity: &'a Severity,
    pub matched_events: &'a serde_json::Value,
    pub event_hash: Option<String>,
    /// A13 (NAN-1752): the TRUE match count to persist in
    /// `alerts.matched_event_count`. `None` leaves the column NULL and the read
    /// side falls back to `jsonb_array_length(matched_events)` (the stored
    /// sample size). Detection producers set the real count; observability
    /// producers pass `None`.
    pub match_count: Option<i64>,
}

/// NAN-1541: normalize an optional kinds filter into the `Option<Vec<String>>`
/// the queries bind. An absent filter OR an empty slice both mean "all kinds"
/// (bound as SQL NULL so the `$N::text[] IS NULL OR ...` guard short-circuits).
fn normalize_kinds(kinds: Option<&[String]>) -> Option<Vec<String>> {
    match kinds {
        Some(k) if !k.is_empty() => Some(k.to_vec()),
        _ => None,
    }
}

/// A5 (NAN-1747): default safety lag (seconds) applied to the SOAR stream
/// cursor. See [`AlertRepository::list_after`] for the rationale.
const DEFAULT_ALERT_STREAM_SAFETY_LAG_SECS: i64 = 5;

/// A5 (NAN-1747): read the configured stream safety lag from the environment
/// (`NANOSIEM_ALERT_STREAM_SAFETY_LAG_SECS`), falling back to
/// [`DEFAULT_ALERT_STREAM_SAFETY_LAG_SECS`]. Non-numeric or negative values are
/// ignored (fall back to the default) so a bad env value can't make the stream
/// return future/unbounded rows.
fn stream_safety_lag_secs() -> i64 {
    std::env::var("NANOSIEM_ALERT_STREAM_SAFETY_LAG_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .unwrap_or(DEFAULT_ALERT_STREAM_SAFETY_LAG_SECS)
}

/// A5 (NAN-1747): pure helper — the newest `created_at` a stream page may
/// return, given `now` and a non-negative `lag_secs`. Negative lags clamp to 0.
fn apply_safety_lag(now: DateTime<Utc>, lag_secs: i64) -> DateTime<Utc> {
    now - chrono::Duration::seconds(lag_secs.max(0))
}

/// Map raw `(status_text, count)` rows into `(AlertStatus, count)`, dropping any
/// unrecognized status. Shared by the count-by-status queries.
fn map_status_counts(results: Vec<(String, i64)>) -> Vec<(AlertStatus, i64)> {
    results
        .into_iter()
        .filter_map(|(status, count)| {
            let status = match status.as_str() {
                "new" => Some(AlertStatus::New),
                "acknowledged" => Some(AlertStatus::Acknowledged),
                "closed" => Some(AlertStatus::Closed),
                _ => None,
            };
            status.map(|s| (s, count))
        })
        .collect()
}

impl AlertRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// NAN-1541: the ONE unified create. Every alert producer — detection and
    /// each observability evaluator — funnels through here with its own `kind`
    /// + `source_id`. Detection behavior is preserved exactly: `create` /
    /// `create_without_dedup` are thin wrappers that set `kind = "detection"`
    /// and `source_id = rule_id`.
    ///
    /// When `event_hash` is `Some`, the insert is dedup-guarded via
    /// `ON CONFLICT (rule_id, event_hash) DO NOTHING` (returns `DuplicateAlert`
    /// on conflict). When `None`, a plain insert is issued (no dedup).
    pub async fn create_alert(
        &self,
        insert: AlertInsert<'_>,
    ) -> Result<Alert, AlertRepositoryError> {
        // A8 (NAN-1747): the dedup unique index is `(rule_id, event_hash)`.
        // Postgres treats NULLs as DISTINCT, so a row with `rule_id = NULL` can
        // NEVER win the `ON CONFLICT (rule_id, event_hash)` race — the dedup is
        // a silent no-op for any producer that leaves `rule_id` unset. Every
        // current observability producer passes `event_hash: None` (no dedup
        // expected), so nothing relies on it today. A future producer that
        // passes `Some(event_hash)` with `rule_id: None` would silently get
        // duplicate rows instead of the dedup it asked for; fail loudly in debug
        // so that combination is caught at the source rather than in prod.
        debug_assert!(
            !(insert.event_hash.is_some() && insert.rule_id.is_none()),
            "create_alert: Some(event_hash) with rule_id=None can never dedup \
             (PG treats NULLs as distinct on the (rule_id, event_hash) unique \
             index); a producer that needs dedup must supply a rule_id, or use a \
             NULL-aware constraint"
        );
        // A13 (NAN-1752): persist the TRUE match count into the INT4
        // `matched_event_count` column. Match counts are bounded well within i32
        // (DEFAULT_RESULT_LIMIT caps at 1M), so a saturating cast is only a
        // theoretical guard. `None` → NULL, and the read side falls back to
        // `jsonb_array_length(matched_events)`.
        let match_count_col: Option<i32> = insert
            .match_count
            .map(|c| i32::try_from(c).unwrap_or(i32::MAX));
        // NAN-1800: stamp the alert with the distinct normalized source_type
        // values of its matched events, derived HERE so every producer (all six
        // AlertInsert construction sites) gets it without changes. The read
        // side enforces per-source RBAC via array overlap on this column.
        let source_types = distinct_source_types(insert.matched_events);
        match insert.event_hash {
            Some(event_hash) => {
                // Atomic insert with conflict detection - no race condition window
                let result = sqlx::query_as::<_, Alert>(
                    r#"
                    INSERT INTO alerts (rule_id, severity, matched_events, event_hash, kind, source_id, matched_event_count, source_types)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (rule_id, event_hash) WHERE event_hash IS NOT NULL DO NOTHING
                    RETURNING *
                    "#,
                )
                .bind(insert.rule_id)
                .bind(insert.severity)
                .bind(insert.matched_events)
                .bind(&event_hash)
                .bind(insert.kind)
                .bind(&insert.source_id)
                .bind(match_count_col)
                .bind(&source_types)
                .fetch_optional(&self.pool)
                .await?;

                match result {
                    Some(alert) => Ok(alert),
                    None => Err(AlertRepositoryError::DuplicateAlert(
                        // rule_id is NULL for observability alerts; surface nil
                        // in the (rare) dedup-conflict error rather than panic.
                        insert.rule_id.unwrap_or_else(Uuid::nil),
                        event_hash,
                    )),
                }
            }
            None => {
                let result = sqlx::query_as::<_, Alert>(
                    r#"
                    INSERT INTO alerts (rule_id, severity, matched_events, kind, source_id, matched_event_count, source_types)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    RETURNING *
                    "#,
                )
                .bind(insert.rule_id)
                .bind(insert.severity)
                .bind(insert.matched_events)
                .bind(insert.kind)
                .bind(&insert.source_id)
                .bind(match_count_col)
                .bind(&source_types)
                .fetch_one(&self.pool)
                .await?;

                Ok(result)
            }
        }
    }

    /// Create a new detection alert with deduplication
    /// If event_hash is provided and an alert with the same rule_id + event_hash exists,
    /// returns DuplicateAlert error instead of creating a duplicate
    ///
    /// Uses INSERT ON CONFLICT to atomically handle deduplication (race-condition safe).
    /// Thin wrapper over [`create_alert`] with `kind = "detection"`.
    pub async fn create(&self, alert: &NewAlert) -> Result<Alert, AlertRepositoryError> {
        // Compute event hash if not provided
        let event_hash = alert
            .event_hash
            .clone()
            .unwrap_or_else(|| compute_event_hash(&alert.matched_events));

        self.create_alert(AlertInsert {
            kind: "detection",
            rule_id: Some(alert.rule_id),
            source_id: Some(alert.rule_id.to_string()),
            severity: &alert.severity,
            matched_events: &alert.matched_events,
            event_hash: Some(event_hash),
            match_count: alert.match_count,
        })
        .await
    }

    /// Create a new detection alert without deduplication check (for backwards compatibility).
    /// Thin wrapper over [`create_alert`] with `kind = "detection"`.
    pub async fn create_without_dedup(
        &self,
        alert: &NewAlert,
    ) -> Result<Alert, AlertRepositoryError> {
        self.create_alert(AlertInsert {
            kind: "detection",
            rule_id: Some(alert.rule_id),
            source_id: Some(alert.rule_id.to_string()),
            severity: &alert.severity,
            matched_events: &alert.matched_events,
            event_hash: None,
            match_count: alert.match_count,
        })
        .await
    }

    /// NAN-1563: durable re-arm authority for observability alerts.
    ///
    /// Returns the `created_at` of the most recent alert for `(kind, source_id)`,
    /// or `None` if no such alert exists. This is the durable backstop for
    /// time-based re-arm dedup on the `event_hash: None` insert path (SLO /
    /// metric-monitor alerts), which carry no per-event dedup hash. Because the
    /// answer comes from the persisted `alerts` table, it survives a
    /// jobs-process restart / leader failover — the new leader sees the prior
    /// leader's last alert and respects the re-arm window instead of re-firing.
    ///
    /// Parameterized; `source_id` is the producer's identifier text (the SLO id
    /// for `kind = "slo"`).
    pub async fn latest_alert_at_for_source(
        &self,
        kind: &str,
        source_id: &str,
    ) -> Result<Option<DateTime<Utc>>, AlertRepositoryError> {
        let created_at: Option<DateTime<Utc>> = sqlx::query_scalar(
            r#"
            SELECT created_at
            FROM alerts
            WHERE kind = $1 AND source_id = $2
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(kind)
        .bind(source_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(created_at)
    }

    /// Find an alert by ID (with rule name).
    ///
    /// NAN-1800: `deny` is the viewer's per-source deny set — an alert whose
    /// `source_types` overlap it is reported as `NotFound` (indistinguishable
    /// from nonexistent). System callers pass
    /// `ScopeSet::unrestricted().deny_set()` (empty = byte-identical SQL).
    pub async fn find_by_id(
        &self,
        id: Uuid,
        deny: &BTreeSet<String>,
    ) -> Result<Alert, AlertRepositoryError> {
        let (scope_sql, scope_bind) = scope_clause(deny, "a.source_types", 2);
        let sql = format!(
            r#"
            SELECT
                a.*,
                r.name as rule_name,
                -- A13 (NAN-1752): prefer the TRUE match count persisted in
                -- `matched_event_count` at insert; fall back to the stored SAMPLE
                -- size for legacy rows (NULL column). `matched_events` is capped
                -- at max_events_per_alert for grouped alerts, so the fallback
                -- under-reports a large match — the stored column does not.
                COALESCE(a.matched_event_count, jsonb_array_length(a.matched_events)) as matched_event_count,
                t.verdict_type as triage_verdict,
                t.confidence as triage_confidence,
                t.verdict as triage_verdict_details
            FROM alerts a
            LEFT JOIN detection_rules r ON a.rule_id = r.id
            LEFT JOIN (
                SELECT DISTINCT ON (alert_id) alert_id, verdict_type, confidence, verdict
                FROM alert_triage_results
                WHERE status = 'completed'
                ORDER BY alert_id, created_at DESC
            ) t ON t.alert_id = a.id
            WHERE a.id = $1{scope_sql}
            "#
        );
        let mut query = sqlx::query_as::<_, Alert>(&sql).bind(id);
        if let Some(denied) = &scope_bind {
            query = query.bind(denied);
        }
        let result = query
            .fetch_optional(&self.pool)
            .await?
            .ok_or(AlertRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// List alerts with optional filters (with rule names).
    ///
    /// NAN-1541: `kinds` filters by the spine discriminator. `None` (or an
    /// empty slice) returns ALL kinds; the SIEM Alerts view passes
    /// `["detection"]` and the Observability Alerts view passes the monitor
    /// kinds. Detection callers that don't pass `kinds` keep the prior
    /// behavior, but the API layer always scopes them to `["detection"]`.
    pub async fn list(
        &self,
        status: Option<AlertStatus>,
        severity: Option<Severity>,
        kinds: Option<&[String]>,
        limit: i64,
        offset: i64,
        deny: &BTreeSet<String>,
    ) -> Result<Vec<Alert>, AlertRepositoryError> {
        // Thin wrapper: no rule scoping.
        self.list_filtered(status, severity, None, kinds, limit, offset, deny)
            .await
    }

    /// A4/A6 (NAN-1747): unified filtered list. Adds an optional `rule_id`
    /// scope so `GET /api/alerts?rule_id=…` applies status/severity/kinds and
    /// paging (the old rule-scoped path hard-capped at 100 and dropped every
    /// other filter).
    ///
    /// A6: ordering is severity-rank → `created_at DESC` → `id DESC`. The `id`
    /// tiebreak makes a given `OFFSET` deterministic within a snapshot; without
    /// it, rows sharing a `created_at` could reorder between pages and drop /
    /// duplicate under concurrent inserts. (Deep-OFFSET paging is still
    /// snapshot-relative — a true fix is keyset pagination on
    /// `(severity_rank, created_at, id)` — but ordering is now stable.)
    pub async fn list_filtered(
        &self,
        status: Option<AlertStatus>,
        severity: Option<Severity>,
        rule_id: Option<Uuid>,
        kinds: Option<&[String]>,
        limit: i64,
        offset: i64,
        deny: &BTreeSet<String>,
    ) -> Result<Vec<Alert>, AlertRepositoryError> {
        let kinds_filter = normalize_kinds(kinds);
        let (scope_sql, scope_bind) = scope_clause(deny, "a.source_types", 7);
        let sql = format!(
            r#"
            SELECT
                a.*,
                r.name as rule_name,
                -- A13 (NAN-1752): prefer the TRUE match count persisted at insert
                -- in `matched_event_count`; fall back to the stored SAMPLE size
                -- (`jsonb_array_length`) for legacy rows whose column is NULL.
                -- `matched_events` is capped at max_events_per_alert for grouped
                -- alerts, so the fallback under-reports a large match.
                COALESCE(a.matched_event_count, jsonb_array_length(a.matched_events)) as matched_event_count,
                t.verdict_type as triage_verdict,
                t.confidence as triage_confidence,
                t.verdict as triage_verdict_details
            FROM alerts a
            LEFT JOIN detection_rules r ON a.rule_id = r.id
            LEFT JOIN (
                SELECT DISTINCT ON (alert_id) alert_id, verdict_type, confidence, verdict
                FROM alert_triage_results
                WHERE status = 'completed'
                ORDER BY alert_id, created_at DESC
            ) t ON t.alert_id = a.id
            WHERE ($1::text IS NULL OR a.status = $1)
              AND ($2::text IS NULL OR a.severity = $2)
              AND ($5::uuid IS NULL OR a.rule_id = $5)
              AND ($6::text[] IS NULL OR a.kind = ANY($6)){scope_sql}
            ORDER BY
                CASE a.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                a.created_at DESC,
                a.id DESC
            LIMIT $3 OFFSET $4
            "#
        );
        let mut query = sqlx::query_as::<_, Alert>(&sql)
            .bind(status.map(|s| format!("{:?}", s).to_lowercase()))
            .bind(severity.map(|s| format!("{:?}", s).to_lowercase()))
            .bind(limit)
            .bind(offset)
            .bind(rule_id)
            .bind(kinds_filter);
        if let Some(denied) = &scope_bind {
            query = query.bind(denied);
        }
        let results = query.fetch_all(&self.pool).await?;

        Ok(results)
    }

    /// List alerts by rule ID (with rule name)
    /// Limited to most recent 100 alerts to prevent memory issues
    pub async fn list_by_rule(
        &self,
        rule_id: Uuid,
        deny: &BTreeSet<String>,
    ) -> Result<Vec<Alert>, AlertRepositoryError> {
        let (scope_sql, scope_bind) = scope_clause(deny, "a.source_types", 2);
        let sql = format!(
            r#"
            SELECT
                a.*,
                r.name as rule_name,
                -- A13 (NAN-1752): true persisted count, falling back to the
                -- stored sample size for legacy NULL rows.
                COALESCE(a.matched_event_count, jsonb_array_length(a.matched_events)) as matched_event_count
            FROM alerts a
            LEFT JOIN detection_rules r ON a.rule_id = r.id
            WHERE a.rule_id = $1{scope_sql}
            ORDER BY a.created_at DESC
            LIMIT 100
            "#
        );
        let mut query = sqlx::query_as::<_, Alert>(&sql).bind(rule_id);
        if let Some(denied) = &scope_bind {
            query = query.bind(denied);
        }
        let results = query.fetch_all(&self.pool).await?;

        Ok(results)
    }

    /// List alerts by rule ID with custom limit
    pub async fn list_by_rule_limited(
        &self,
        rule_id: Uuid,
        limit: i64,
        deny: &BTreeSet<String>,
    ) -> Result<Vec<Alert>, AlertRepositoryError> {
        let (scope_sql, scope_bind) = scope_clause(deny, "a.source_types", 3);
        let sql = format!(
            r#"
            SELECT
                a.*,
                r.name as rule_name,
                -- A13 (NAN-1752): true persisted count, falling back to the
                -- stored sample size for legacy NULL rows.
                COALESCE(a.matched_event_count, jsonb_array_length(a.matched_events)) as matched_event_count
            FROM alerts a
            LEFT JOIN detection_rules r ON a.rule_id = r.id
            WHERE a.rule_id = $1{scope_sql}
            ORDER BY a.created_at DESC
            LIMIT $2
            "#
        );
        let mut query = sqlx::query_as::<_, Alert>(&sql).bind(rule_id).bind(limit);
        if let Some(denied) = &scope_bind {
            query = query.bind(denied);
        }
        let results = query.fetch_all(&self.pool).await?;

        Ok(results)
    }

    /// Acknowledge an alert
    ///
    /// Uses atomic status check in WHERE clause to prevent race conditions.
    /// NAN-1800: the viewer's `deny` set guards the UPDATE itself — a denied
    /// alert is never mutated, and the fallthrough `find_by_id` (same deny)
    /// reports it as `NotFound`.
    pub async fn acknowledge(
        &self,
        id: Uuid,
        ack: &AcknowledgeAlert,
        deny: &BTreeSet<String>,
    ) -> Result<Alert, AlertRepositoryError> {
        // Atomic state transition - status check in WHERE prevents race conditions
        let (scope_sql, scope_bind) = scope_clause(deny, "source_types", 4);
        let sql = format!(
            r#"
            UPDATE alerts SET
                status = 'acknowledged',
                acknowledged_by = $2,
                acknowledged_at = $3
            WHERE id = $1 AND status = 'new'{scope_sql}
            RETURNING *
            "#
        );
        let mut query = sqlx::query_as::<_, Alert>(&sql)
            .bind(id)
            .bind(&ack.acknowledged_by)
            .bind(Utc::now());
        if let Some(denied) = &scope_bind {
            query = query.bind(denied);
        }
        let result = query.fetch_optional(&self.pool).await?;

        match result {
            Some(alert) => Ok(alert),
            None => {
                // Check if alert exists (and is visible to this viewer) to
                // provide the appropriate error
                match self.find_by_id(id, deny).await {
                    Ok(alert) => Err(AlertRepositoryError::InvalidStateTransition(format!(
                        "Can only acknowledge alerts with 'new' status, current status is '{:?}'",
                        alert.status
                    ))),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Close an alert
    ///
    /// Uses atomic status check in WHERE clause to prevent race conditions
    pub async fn close(
        &self,
        id: Uuid,
        close: &CloseAlert,
        deny: &BTreeSet<String>,
    ) -> Result<Alert, AlertRepositoryError> {
        // Atomic state transition - status check in WHERE prevents race
        // conditions. NAN-1800: deny-scope guard on the UPDATE (see acknowledge).
        let (scope_sql, scope_bind) = scope_clause(deny, "source_types", 5);
        let sql = format!(
            r#"
            UPDATE alerts SET
                status = 'closed',
                disposition = $2,
                closed_by = $3,
                closed_at = $4
            WHERE id = $1 AND status != 'closed'{scope_sql}
            RETURNING *
            "#
        );
        let mut query = sqlx::query_as::<_, Alert>(&sql)
            .bind(id)
            .bind(&close.disposition)
            .bind(&close.closed_by)
            .bind(Utc::now());
        if let Some(denied) = &scope_bind {
            query = query.bind(denied);
        }
        let result = query.fetch_optional(&self.pool).await?;

        match result {
            Some(alert) => Ok(alert),
            None => {
                // Check if alert exists (and is visible to this viewer) to
                // provide the appropriate error
                match self.find_by_id(id, deny).await {
                    Ok(_) => Err(AlertRepositoryError::InvalidStateTransition(
                        "Alert is already closed".to_string(),
                    )),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Assign an alert to an analyst
    ///
    /// A9 (NAN-1747): use `fetch_optional` and map only the *no-row* case to
    /// `NotFound`. `fetch_one().map_err(|_| NotFound)` masked every transient DB
    /// error (connection drop, pool timeout) as a 404 for an alert that exists;
    /// real DB errors now propagate as `DatabaseError` (→ 500) via `?`.
    pub async fn assign(
        &self,
        id: Uuid,
        assignee: &str,
        deny: &BTreeSet<String>,
    ) -> Result<Alert, AlertRepositoryError> {
        // NAN-1800: deny-scope guard on the UPDATE — a denied alert reads as
        // NotFound and is never mutated.
        let (scope_sql, scope_bind) = scope_clause(deny, "source_types", 3);
        let sql = format!(
            r#"
            UPDATE alerts SET assigned_to = $2
            WHERE id = $1{scope_sql}
            RETURNING *
            "#
        );
        let mut query = sqlx::query_as::<_, Alert>(&sql).bind(id).bind(assignee);
        if let Some(denied) = &scope_bind {
            query = query.bind(denied);
        }
        let result = query
            .fetch_optional(&self.pool)
            .await?
            .ok_or(AlertRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// Bulk acknowledge alerts.
    ///
    /// NAN-1800: rows whose `source_types` overlap the viewer's `deny` set are
    /// silently excluded from the UPDATE (they don't count toward the returned
    /// affected total) — a restricted viewer cannot mutate alerts they can't see.
    pub async fn bulk_acknowledge(
        &self,
        ids: &[Uuid],
        acknowledged_by: &str,
        deny: &BTreeSet<String>,
    ) -> Result<usize, AlertRepositoryError> {
        let (scope_sql, scope_bind) = scope_clause(deny, "source_types", 4);
        let sql = format!(
            r#"
            UPDATE alerts SET
                status = 'acknowledged',
                acknowledged_by = $2,
                acknowledged_at = $3
            WHERE id = ANY($1) AND status = 'new'{scope_sql}
            "#
        );
        let mut query = sqlx::query(&sql)
            .bind(ids)
            .bind(acknowledged_by)
            .bind(Utc::now());
        if let Some(denied) = &scope_bind {
            query = query.bind(denied);
        }
        let result = query.execute(&self.pool).await?;

        Ok(result.rows_affected() as usize)
    }

    /// Bulk close alerts.
    ///
    /// NAN-1800: deny-scoped like [`bulk_acknowledge`].
    pub async fn bulk_close(
        &self,
        ids: &[Uuid],
        disposition: Disposition,
        closed_by: &str,
        deny: &BTreeSet<String>,
    ) -> Result<usize, AlertRepositoryError> {
        let (scope_sql, scope_bind) = scope_clause(deny, "source_types", 5);
        let sql = format!(
            r#"
            UPDATE alerts SET
                status = 'closed',
                disposition = $2,
                closed_by = $3,
                closed_at = $4
            WHERE id = ANY($1) AND status != 'closed'{scope_sql}
            "#
        );
        let mut query = sqlx::query(&sql)
            .bind(ids)
            .bind(&disposition)
            .bind(closed_by)
            .bind(Utc::now());
        if let Some(denied) = &scope_bind {
            query = query.bind(denied);
        }
        let result = query.execute(&self.pool).await?;

        Ok(result.rows_affected() as usize)
    }

    /// Count alerts by status.
    ///
    /// A12 (NAN-1747): the counts are now UNBOUNDED in time to match
    /// `list` / `GET /api/alerts` (which has no time window). Previously this
    /// silently applied a `created_at >= NOW() - 90 days` window, so the header
    /// counts and the list disagreed on any deployment older than 90 days. The
    /// query is a `GROUP BY status` aggregate over the metadata `alerts` table
    /// (not the ClickHouse log firehose), so a full scan here is acceptable.
    ///
    /// NAN-1541: `kinds` scopes the counts to the spine discriminator (`None`
    /// = all kinds).
    pub async fn count_by_status(
        &self,
        kinds: Option<&[String]>,
        deny: &BTreeSet<String>,
    ) -> Result<Vec<(AlertStatus, i64)>, AlertRepositoryError> {
        let kinds_filter = normalize_kinds(kinds);
        let (scope_sql, scope_bind) = scope_clause(deny, "source_types", 2);
        let sql = format!(
            r#"SELECT status, COUNT(*) FROM alerts
               WHERE ($1::text[] IS NULL OR kind = ANY($1)){scope_sql}
               GROUP BY status"#
        );
        let mut query = sqlx::query_as(&sql).bind(kinds_filter);
        if let Some(denied) = &scope_bind {
            query = query.bind(denied);
        }
        let results: Vec<(String, i64)> = query.fetch_all(&self.pool).await?;

        Ok(map_status_counts(results))
    }

    /// A12 (NAN-1747): count alerts by status, excluding alerts whose `rule_id`
    /// is in `exclude_rule_ids` (demo-isolation). Runs a single SQL aggregate
    /// so the demo counts path no longer materializes a 10k-row list in memory
    /// and then counts in Rust.
    ///
    /// NULL `rule_id` rows (observability alerts) are always kept — mirroring
    /// the handler filter `rule_id.map_or(true, |rid| !exclude.contains(&rid))`.
    pub async fn count_by_status_excluding_rules(
        &self,
        kinds: Option<&[String]>,
        exclude_rule_ids: &[Uuid],
        deny: &BTreeSet<String>,
    ) -> Result<Vec<(AlertStatus, i64)>, AlertRepositoryError> {
        let kinds_filter = normalize_kinds(kinds);
        let (scope_sql, scope_bind) = scope_clause(deny, "source_types", 3);
        let sql = format!(
            r#"SELECT status, COUNT(*) FROM alerts
               WHERE ($1::text[] IS NULL OR kind = ANY($1))
                 AND (rule_id IS NULL OR NOT (rule_id = ANY($2))){scope_sql}
               GROUP BY status"#
        );
        let mut query = sqlx::query_as(&sql).bind(kinds_filter).bind(exclude_rule_ids);
        if let Some(denied) = &scope_bind {
            query = query.bind(denied);
        }
        let results: Vec<(String, i64)> = query.fetch_all(&self.pool).await?;

        Ok(map_status_counts(results))
    }

    /// List alerts created after a specific timestamp and ID (for cursor-based
    /// streaming; e.g. the `/api/alerts/stream` SOAR poller).
    ///
    /// A5 (NAN-1747): the cursor advances on `created_at`, but `created_at`
    /// defaults to `now()` at INSERT — i.e. transaction-*start*, not commit.
    /// Two executions inserting concurrently can commit out of order: alert A
    /// (`created_at = T1`) may become visible AFTER alert B (`created_at = T2`,
    /// `T2 > T1`). A poller that reads between the two commits sees B, advances
    /// its cursor past `T2`, and then never returns A (`T1 < cursor`) — silent
    /// permanent loss to the very system the cursor stream exists to protect.
    ///
    /// Fix: only return rows whose `created_at` is older than a small safety
    /// lag (`NANOSIEM_ALERT_STREAM_SAFETY_LAG_SECS`, default 5s). By the time a
    /// row is eligible, any concurrently-started-but-later-committing row has
    /// had `lag` seconds to become visible, so the out-of-order window closes.
    /// Trade-off: newly created alerts appear to the stream `lag` seconds late
    /// (an acceptable price for not dropping alerts). This is not a monotonic
    /// commit sequence — under a lag-exceeding stall it can still race — but it
    /// removes the routine reorder-loss without a schema change.
    pub async fn list_after(
        &self,
        after_timestamp: DateTime<Utc>,
        after_id: Uuid,
        limit: i64,
        deny: &BTreeSet<String>,
    ) -> Result<Vec<Alert>, AlertRepositoryError> {
        let cutoff = apply_safety_lag(Utc::now(), stream_safety_lag_secs());
        let (scope_sql, scope_bind) = scope_clause(deny, "a.source_types", 5);
        let sql = format!(
            r#"
            SELECT
                a.*,
                r.name as rule_name,
                -- A13 (NAN-1752): prefer the persisted TRUE match count; fall back
                -- to the stored SAMPLE size for legacy NULL rows. See the note in
                -- `list_filtered`.
                COALESCE(a.matched_event_count, jsonb_array_length(a.matched_events)) as matched_event_count,
                t.verdict_type as triage_verdict,
                t.confidence as triage_confidence,
                t.verdict as triage_verdict_details
            FROM alerts a
            LEFT JOIN detection_rules r ON a.rule_id = r.id
            LEFT JOIN (
                SELECT DISTINCT ON (alert_id) alert_id, verdict_type, confidence, verdict
                FROM alert_triage_results
                WHERE status = 'completed'
                ORDER BY alert_id, created_at DESC
            ) t ON t.alert_id = a.id
            WHERE ((a.created_at > $1) OR (a.created_at = $1 AND a.id > $2))
              AND a.created_at <= $4{scope_sql}
            ORDER BY a.created_at ASC, a.id ASC
            LIMIT $3
            "#
        );
        let mut query = sqlx::query_as::<_, Alert>(&sql)
            .bind(after_timestamp)
            .bind(after_id)
            .bind(limit)
            .bind(cutoff);
        if let Some(denied) = &scope_bind {
            query = query.bind(denied);
        }
        let results = query.fetch_all(&self.pool).await?;

        Ok(results)
    }
}

// NAN-1747 pure-logic tests live in a dedicated sibling file (repo convention:
// tests in sibling files, not large inline modules).
#[cfg(test)]
#[path = "alerts_nan1747_tests.rs"]
mod alerts_nan1747_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_event_hash_strips_nano_fields() {
        let raw_events = serde_json::json!([{
            "src_ip": "10.1.3.212",
            "failures": 6
        }]);

        let enriched_events = serde_json::json!([{
            "src_ip": "10.1.3.212",
            "failures": 6,
            "_nano_detected_at": "2026-04-13T12:00:00+00:00"
        }]);

        assert_eq!(
            compute_event_hash(&raw_events),
            compute_event_hash(&enriched_events),
            "Hash should be stable regardless of _nano_* fields"
        );
    }

    #[test]
    fn test_compute_event_hash_differs_for_different_events() {
        let events_a = serde_json::json!([{"src_ip": "10.1.3.212"}]);
        let events_b = serde_json::json!([{"src_ip": "10.1.3.213"}]);

        assert_ne!(
            compute_event_hash(&events_a),
            compute_event_hash(&events_b),
        );
    }

    /// NAN-1711 / audit D16: an enriched AGGREGATE row (system-injected
    /// `_first_seen`/`_last_seen` pair) must hash stably while the drifting
    /// window fields move — `count`/`percent` change and `_first_seen` creeps
    /// upward on every sliding-lookback cycle over static data. Without the
    /// strip, a per-event-alert-mode aggregate rule minted one new alert per
    /// entity per cycle.
    #[test]
    fn aggregate_row_hash_ignores_drifting_count_percent_first_seen() {
        let cycle_1 = serde_json::json!([{
            "src_ip": "10.1.3.212",
            "count": 42,
            "percent": 3.14,
            "_first_seen": "2026-07-01 10:00:00",
            "_last_seen": "2026-07-01 11:00:00"
        }]);
        // Next cycle: trailing edge slid past old events — count down,
        // percent shifted, _first_seen crept up. Same newest activity.
        let cycle_2 = serde_json::json!([{
            "src_ip": "10.1.3.212",
            "count": 17,
            "percent": 9.81,
            "_first_seen": "2026-07-01 10:25:00",
            "_last_seen": "2026-07-01 11:00:00"
        }]);

        assert_eq!(
            compute_event_hash(&cycle_1),
            compute_event_hash(&cycle_2),
            "aggregate-row hash must ignore drifting count/percent/_first_seen"
        );
    }

    /// NAN-1711 / audit D16: `_last_seen` is the kept watermark — genuinely new
    /// activity for the SAME entity advances it and must re-hash (new alert),
    /// mirroring the `entity + _last_seen` finding-dedup identity (D14).
    #[test]
    fn aggregate_row_hash_still_changes_when_last_seen_advances() {
        let before = serde_json::json!([{
            "src_ip": "10.1.3.212",
            "count": 42,
            "_first_seen": "2026-07-01 10:00:00",
            "_last_seen": "2026-07-01 11:00:00"
        }]);
        let after_new_activity = serde_json::json!([{
            "src_ip": "10.1.3.212",
            "count": 43,
            "_first_seen": "2026-07-01 10:00:00",
            "_last_seen": "2026-07-01 11:30:00"
        }]);

        assert_ne!(
            compute_event_hash(&before),
            compute_event_hash(&after_new_activity),
            "an advanced _last_seen (new activity) must produce a new hash"
        );
    }

    /// NAN-1800: source_types stamping — raw events (per-event `source_type`)
    /// and aggregate rows (engine-stamped `_nano_source_types` array) both
    /// contribute; values are trimmed + lowercased + sorted-unique.
    #[test]
    fn distinct_source_types_reads_both_forms_normalized() {
        let events = serde_json::json!([
            {"source_type": "  Windows_Event_Log ", "message": "a"},
            {"source_type": "syslog", "message": "b"},
            {"count": 12, "_nano_source_types": ["Syslog", "aws_cloudtrail", " "]},
            {"count": 3, "_nano_source_types": ["insider_threat"]},
            {"message": "no source_type at all"}
        ]);
        assert_eq!(
            distinct_source_types(&events),
            vec![
                "aws_cloudtrail".to_string(),
                "insider_threat".to_string(),
                "syslog".to_string(),
                "windows_event_log".to_string(),
            ]
        );
    }

    /// NAN-1800: producers whose events carry no source_type (observability /
    /// risk-notable alerts, non-array payloads) stamp an empty array — the
    /// back-compat "visible to everyone" form.
    #[test]
    fn distinct_source_types_empty_for_non_source_events() {
        assert!(distinct_source_types(&serde_json::json!([{"value": 1.0}])).is_empty());
        assert!(distinct_source_types(&serde_json::json!({})).is_empty());
        assert!(distinct_source_types(&serde_json::json!(null)).is_empty());
    }

    /// NAN-1800: empty deny set emits NO clause and NO bind — byte-identical
    /// back-compat SQL for system callers.
    #[test]
    fn scope_clause_empty_deny_is_noop() {
        let (sql, bind) = scope_clause(&BTreeSet::new(), "a.source_types", 7);
        assert!(sql.is_empty());
        assert!(bind.is_none());
    }

    /// NAN-1800: a restricted deny set emits the overlap-rejection clause at
    /// the requested parameter index with normalized bind values.
    #[test]
    fn scope_clause_restricted_deny_emits_overlap_filter() {
        let deny: BTreeSet<String> =
            [" Audit ".to_string(), "Insider_Threat".to_string(), "".to_string()]
                .into_iter()
                .collect();
        let (sql, bind) = scope_clause(&deny, "a.source_types", 7);
        assert_eq!(
            sql,
            " AND ($7::text[] = '{}' OR NOT (a.source_types && $7::text[]))"
        );
        // NAN-2155: a restricted caller also denies the unresolved-provenance
        // sentinel, so an aggregate alert whose source could not be determined
        // is hidden from them instead of being conflated with the legitimately
        // sourceless `'{}'` rows.
        assert_eq!(
            bind,
            Some(vec![
                crate::auth::UNRESOLVED_SOURCE_SENTINEL.to_string(),
                "audit".to_string(),
                "insider_threat".to_string(),
            ])
        );
    }

    /// NAN-1711 / audit D16: the strip is GATED on the injected pair. A raw
    /// event's legitimate `count`/`percent` fields (no `_first_seen`/`_last_seen`)
    /// must keep busting the hash exactly as before.
    #[test]
    fn raw_event_hash_still_keyed_on_count_and_percent() {
        let a = serde_json::json!([{"src_ip": "10.1.3.212", "count": 1}]);
        let b = serde_json::json!([{"src_ip": "10.1.3.212", "count": 2}]);
        assert_ne!(
            compute_event_hash(&a),
            compute_event_hash(&b),
            "raw events (no injected bounds) must hash their count field"
        );

        // A row with only ONE of the pair is NOT an enriched aggregate — no strip.
        let only_first = serde_json::json!([{
            "src_ip": "10.1.3.212", "count": 1, "_first_seen": "2026-07-01 10:00:00"
        }]);
        let only_first_other_count = serde_json::json!([{
            "src_ip": "10.1.3.212", "count": 2, "_first_seen": "2026-07-01 10:00:00"
        }]);
        assert_ne!(
            compute_event_hash(&only_first),
            compute_event_hash(&only_first_other_count),
            "a lone _first_seen must not trigger the aggregate strip"
        );
    }
}
