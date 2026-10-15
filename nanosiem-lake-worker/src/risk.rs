// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed, tenant-pinned accumulated-risk queries over an immutable findings
//! ledger. Requests carry risk semantics only, never SQL or storage paths.

use crate::config::LoadedRiskSnapshotConfig;
use crate::executor::NativeExecutor;
use crate::planner::TenantQueryConfig;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

pub use nanosiem_core::risk::watchlist_suggest::RiskSuggestPattern;
use nanosiem_core::risk::watchlist_suggest::{SUGGEST_MAX_PATTERNS, SUGGEST_MAX_VALUES, SUGGEST_ROWS_PER_VALUE};

const DAY_US: i64 = 86_400_000_000;
const MAX_ENTITIES: usize = 1_000;
const MAX_CLEARS: usize = 10_000;
/// Watchlist weight map bound (NAN-3228: the API caps a tenant at 2000
/// member rows; this leaves headroom without admitting an unbounded map).
const MAX_WATCH_WEIGHTS: usize = 5_000;
/// Weighted score lookup: the entity's MAX enabled-watchlist weight, 0 when
/// unwatched (NAN-3228). Matched on the lowercased value.
const WATCH_WEIGHT: &str = "if(indexOf({watch_entities:Array(String)}, lower(entity)) = 0, 0.0, {watch_weights:Array(Float64)}[indexOf({watch_entities:Array(String)}, lower(entity))])";
const MAX_RESULT_ROWS: u64 = 10_000;
const GLOBAL_CLEAR_ENTITY: &str = "__nano_global_clear_boundary__";
// Keep the entity-specific boundary above Parquet predicate pushdown. chDB's
// Parquet V3 reader otherwise treats the parameterized indexOf/arrayElement
// expression as a physical input column and fails with NOT_FOUND_COLUMN_IN_BLOCK.
const REQUEST_CLEAR_BOUNDARY: &str = "if(indexOf({clear_entities:Array(String)}, materialize(entity)) = 0, 0, {clear_times:Array(Int64)}[indexOf({clear_entities:Array(String)}, materialize(entity))])";

#[derive(Debug, thiserror::Error)]
pub enum RiskError {
    #[error("risk request is invalid: {0}")]
    Invalid(String),
    #[error("risk snapshot changed after assignment")]
    SnapshotChanged,
    #[error("risk clear snapshot is older than the request fence")]
    ClearStateBehind,
    /// NAN-2361: carries the engine diagnostic instead of discarding it. The
    /// worker sanitizes it before it reaches a caller.
    #[error("risk query failed: {0}")]
    Query(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RiskRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub risk_operation: String,
    pub anchor_us: i64,
    pub decay: RiskDecay,
    #[serde(default)]
    pub clear_boundaries: BTreeMap<String, i64>,
    #[serde(default)]
    pub minimum_clear_revision: Option<i64>,
    #[serde(default, deserialize_with = "nanosiem_core::auth::source_visibility::deserialize_lake_deny_set")]
    pub deny_source_types: Vec<String>,
    /// Watchlist weights (NAN-3228): normalized entity value -> weight in
    /// `[0, 1]`. Scores are amplified as `base x (1 + weight)`.
    #[serde(default)]
    pub watch_weights: BTreeMap<String, f64>,
    #[serde(default)]
    pub window: Option<String>,
    #[serde(default)]
    pub entity_type_filter: Option<String>,
    #[serde(default)]
    pub min_score: Option<i64>,
    #[serde(default)]
    pub max_score: Option<i64>,
    #[serde(default)]
    pub min_score_24h: Option<i64>,
    #[serde(default)]
    pub min_score_7d: Option<i64>,
    #[serde(default)]
    pub limit: Option<u64>,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub entities: Vec<String>,
    #[serde(default)]
    pub lookback_days: Option<i64>,
    /// Watchlist suggestion patterns (NAN-3249, `risk_operation: "suggest"`
    /// only): exact / prefix / suffix matches on the lowercased entity, each
    /// tagged with the index of the typed value it belongs to.
    #[serde(default)]
    pub suggest_patterns: Vec<RiskSuggestPattern>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RiskDecay {
    pub decay_0_24h: f64,
    pub decay_1_3d: f64,
    pub decay_3_5d: f64,
    pub decay_5_7d: f64,
}

pub struct RiskService {
    snapshot_id: String,
    snapshot_version: String,
    source: PathBuf,
    bytes: u64,
    modified: std::time::SystemTime,
    clear_snapshot_version: Option<String>,
    clear_source: Option<PathBuf>,
    clear_bytes: u64,
    clear_modified: Option<std::time::SystemTime>,
    clear_published_revision: i64,
    global_clear_us: i64,
}

impl RiskService {
    pub fn new(config: LoadedRiskSnapshotConfig) -> Self {
        Self {
            snapshot_id: config.snapshot_id,
            snapshot_version: config.snapshot_version,
            source: config.source,
            bytes: config.bytes,
            modified: config.modified,
            clear_snapshot_version: config.clear_snapshot_version,
            clear_source: config.clear_source,
            clear_bytes: config.clear_bytes,
            clear_modified: config.clear_modified,
            clear_published_revision: config.clear_published_revision,
            global_clear_us: config.global_clear_us,
        }
    }

    pub fn snapshot_identity(&self) -> (&str, &str, Option<&str>, i64) {
        (
            &self.snapshot_id,
            &self.snapshot_version,
            self.clear_snapshot_version.as_deref(),
            self.clear_published_revision,
        )
    }

    pub async fn execute(
        &self,
        executor: &NativeExecutor,
        tenant: &TenantQueryConfig,
        request: &RiskRequest,
    ) -> Result<Value, RiskError> {
        if request.tenant_id != tenant.tenant_id {
            return Err(RiskError::Invalid("risk request tenant differs from the assigned reader".to_string()));
        }
        self.verify_snapshot()?;
        validate_request(request)?;
        self.verify_clear_fence(request)?;
        let mut params = common_params(self, request);
        let sql = match request.risk_operation.as_str() {
            "leaderboard" => leaderboard_sql(self, request, &mut params)?,
            "scores" => scores_sql(self, request, &mut params)?,
            "badge" => badge_sql(self, request, &mut params)?,
            "overview" => overview_sql(self, request)?,
            "entity_types" => entity_types_sql(self, request),
            "activity" => activity_sql(self, request, &mut params)?,
            "signals" => signals_sql(self, request, &mut params)?,
            "contributions" => contributions_sql(self, request, &mut params)?,
            "timeline" => timeline_sql(self, request, &mut params)?,
            "suggest" => suggest_sql(request, &mut params)?,
            _ => return Err(RiskError::Invalid("unsupported risk operation".to_string())),
        };
        if request.risk_operation == "suggest" && request.suggest_patterns.is_empty() {
            return Ok(self.envelope(tenant, Vec::new(), 0.0, 0, 0));
        }
        if request.entities.is_empty()
            && matches!(
                request.risk_operation.as_str(),
                "badge" | "activity" | "signals" | "contributions" | "timeline"
            )
        {
            return Ok(self.envelope(tenant, Vec::new(), 0.0, 0, 0));
        }
        // Risk reads a compact, immutable snapshot. Disable both Parquet
        // predicate pushdown and PREWHERE movement for this route because
        // chDB's V3 reader can otherwise push the parameterized clear-boundary
        // expression into the file reader as if it were a physical column.
        // The event/search path remains fully pushdown-enabled.
        let sql = format!(
            "{sql} SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
             max_memory_usage={}, use_query_cache=0, \
             input_format_parquet_filter_push_down=0, optimize_move_to_prewhere=0",
            tenant.threads,
            tenant.max_execution_seconds,
            tenant.max_query_bytes,
            tenant.max_memory_bytes,
        );
        let output = executor.execute_sql(sql, params).await.map_err(|error| {
            tracing::error!(
                error = %error,
                request_id = %request.request_id,
                risk_operation = %request.risk_operation,
                "native risk query failed"
            );
            RiskError::Query(error.to_string())
        })?;
        let rows = decode_rows(&output.data)?;
        Ok(self.envelope(
            tenant,
            rows,
            output.elapsed.as_secs_f64(),
            output.storage_rows_read,
            output.storage_bytes_read,
        ))
    }

    /// Build the trusted entity-grain source used by `dataset=risk` nPL.
    /// Storage coordinates stay in the assigned generation; the caller only
    /// supplies PostgreSQL-resolved decay, clear, and source-scope semantics.
    pub fn npl_source(
        &self,
        request: &RiskRequest,
    ) -> Result<(String, Vec<(String, String)>, u64), RiskError> {
        self.verify_snapshot()?;
        validate_request(request)?;
        self.verify_clear_fence(request)?;
        let params = common_params(self, request);
        let source = format!(
            "(SELECT entity, entity_type, decayed_score_24h AS score_24h, \
             decayed_score_7d AS score_7d, risk_score_24h AS raw_score_24h, \
             risk_score_7d AS raw_score_7d, signal_count_24h AS findings_24h, \
             signal_count_7d AS findings_7d, distinct_rules_24h, distinct_rules_7d, \
             distinct_tactics_24h, distinct_tactics_7d, \
             fromUnixTimestamp64Micro(last_signal_at) AS last_finding_at, \
             last_rule_name, last_severity FROM ({}))",
            aggregate_sql(self, request),
        );
        Ok((source, params, self.bytes.saturating_add(self.clear_bytes)))
    }

    fn verify_snapshot(&self) -> Result<(), RiskError> {
        let metadata = std::fs::metadata(&self.source).map_err(|_| RiskError::SnapshotChanged)?;
        if metadata.len() != self.bytes
            || metadata
                .modified()
                .map_err(|_| RiskError::SnapshotChanged)?
                != self.modified
        {
            return Err(RiskError::SnapshotChanged);
        }
        if let Some(clear_source) = self.clear_source.as_ref() {
            let clear_metadata =
                std::fs::metadata(clear_source).map_err(|_| RiskError::SnapshotChanged)?;
            if clear_metadata.len() != self.clear_bytes
                || Some(
                    clear_metadata
                        .modified()
                        .map_err(|_| RiskError::SnapshotChanged)?,
                ) != self.clear_modified
            {
                return Err(RiskError::SnapshotChanged);
            }
        }
        Ok(())
    }

    fn verify_clear_fence(&self, request: &RiskRequest) -> Result<(), RiskError> {
        if request
            .minimum_clear_revision
            .is_some_and(|minimum| self.clear_published_revision < minimum)
        {
            return Err(RiskError::ClearStateBehind);
        }
        Ok(())
    }

    pub(crate) fn envelope(
        &self,
        tenant: &TenantQueryConfig,
        rows: Vec<Value>,
        engine_seconds: f64,
        storage_rows: u64,
        storage_bytes: u64,
    ) -> Value {
        json!({
            "snapshot": {
                "tenant_id": tenant.tenant_id,
                "snapshot_id": self.snapshot_id,
                "snapshot_version": self.snapshot_version,
                "clear_snapshot_version": self.clear_snapshot_version,
                "clear_published_revision": self.clear_published_revision,
            },
            "budget": {
                "route": "risk",
                "candidate_objects": if self.clear_source.is_some() { 2 } else { 1 },
                "estimated_scan_bytes": self.bytes.saturating_add(self.clear_bytes),
                "max_query_bytes": tenant.max_query_bytes,
            },
            "result": {
                "result_rows": rows.len(),
                "rows": rows,
                "engine_seconds": engine_seconds,
                "storage_rows": storage_rows,
                "storage_bytes": storage_bytes,
            }
        })
    }
}

fn validate_request(request: &RiskRequest) -> Result<(), RiskError> {
    let decays = [
        request.decay.decay_0_24h,
        request.decay.decay_1_3d,
        request.decay.decay_3_5d,
        request.decay.decay_5_7d,
    ];
    if request.request_id.is_empty()
        || request.anchor_us <= 0
        || decays
            .iter()
            .any(|value| !value.is_finite() || !(0.0..=1.0).contains(value))
        || request.clear_boundaries.len() > MAX_CLEARS
        || request.watch_weights.len() > MAX_WATCH_WEIGHTS
        || request
            .watch_weights
            .values()
            .any(|weight| !weight.is_finite() || !(0.0..=1.0).contains(weight))
        || request
            .minimum_clear_revision
            .is_some_and(|value| value < 0)
        || request.entities.len() > MAX_ENTITIES
        || request.deny_source_types.len() > 1_024
        || request
            .limit
            .is_some_and(|value| value == 0 || value > MAX_RESULT_ROWS)
        || request.offset.is_some_and(|value| value > MAX_RESULT_ROWS)
        || request.max_score.is_some_and(|value| value < 0)
        || request
            .lookback_days
            .is_some_and(|value| !(1..=28).contains(&value))
    {
        return Err(RiskError::Invalid(
            "request exceeds a numeric or collection bound".to_string(),
        ));
    }
    if request
        .clear_boundaries
        .iter()
        .any(|(entity, boundary)| invalid_text(entity, 4_096) || *boundary <= 0)
        || request
            .entities
            .iter()
            .any(|entity| invalid_text(entity, 4_096))
        || request
            .watch_weights
            .keys()
            .any(|entity| invalid_text(entity, 4_096))
        || request
            .deny_source_types
            .iter()
            .any(|source| invalid_text(source, 512))
        || request
            .entity_type_filter
            .as_deref()
            .is_some_and(|value| invalid_text(value, 128))
    {
        return Err(RiskError::Invalid(
            "request contains an invalid text value".to_string(),
        ));
    }
    if request.suggest_patterns.len() > SUGGEST_MAX_PATTERNS
        || request
            .suggest_patterns
            .iter()
            .any(|pattern| usize::from(pattern.group) >= SUGGEST_MAX_VALUES || invalid_text(&pattern.text, 4_096))
        || (!request.suggest_patterns.is_empty() && request.risk_operation != "suggest")
    {
        return Err(RiskError::Invalid(
            "suggest patterns exceed a bound or are invalid".to_string(),
        ));
    }
    if request.risk_operation == "activity" && request.entities.len() > 100 {
        return Err(RiskError::Invalid(
            "activity accepts at most 100 entities".to_string(),
        ));
    }
    Ok(())
}

fn invalid_text(value: &str, max: usize) -> bool {
    value.is_empty() || value.len() > max || value.chars().any(char::is_control)
}

fn common_params(service: &RiskService, request: &RiskRequest) -> Vec<(String, String)> {
    let mut params = vec![
        (
            "risk_source".to_string(),
            service.source.to_string_lossy().into_owned(),
        ),
        ("anchor_us".to_string(), request.anchor_us.to_string()),
        ("c24".to_string(), (request.anchor_us - DAY_US).to_string()),
        (
            "c3".to_string(),
            (request.anchor_us - 3 * DAY_US).to_string(),
        ),
        (
            "c5".to_string(),
            (request.anchor_us - 5 * DAY_US).to_string(),
        ),
        (
            "c7".to_string(),
            (request.anchor_us - 7 * DAY_US).to_string(),
        ),
        ("decay0".to_string(), request.decay.decay_0_24h.to_string()),
        ("decay1".to_string(), request.decay.decay_1_3d.to_string()),
        ("decay3".to_string(), request.decay.decay_3_5d.to_string()),
        ("decay5".to_string(), request.decay.decay_5_7d.to_string()),
    ];
    if let Some(clear_source) = service.clear_source.as_ref() {
        params.push((
            "risk_clear_source".to_string(),
            clear_source.to_string_lossy().into_owned(),
        ));
    }
    params.push((
        "global_clear_us".to_string(),
        service
            .global_clear_us
            .max(
                request
                    .clear_boundaries
                    .get(GLOBAL_CLEAR_ENTITY)
                    .copied()
                    .unwrap_or(0),
            )
            .to_string(),
    ));
    let mut clears = request
        .clear_boundaries
        .iter()
        .filter(|(entity, _)| entity.as_str() != GLOBAL_CLEAR_ENTITY)
        .collect::<Vec<_>>();
    clears.sort_by(|left, right| left.0.cmp(right.0));
    params.push((
        "clear_entities".to_string(),
        string_array(clears.iter().map(|(entity, _)| entity.as_str())),
    ));
    params.push((
        "clear_times".to_string(),
        format!(
            "[{}]",
            clears
                .iter()
                .map(|(_, value)| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ),
    ));
    let denied = request
        .deny_source_types
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    params.push((
        "denied_sources".to_string(),
        string_array(denied.iter().map(String::as_str)),
    ));
    let watch = request
        .watch_weights
        .iter()
        .map(|(entity, weight)| (entity.trim().to_lowercase(), *weight))
        .collect::<BTreeMap<_, _>>();
    params.push((
        "watch_entities".to_string(),
        string_array(watch.keys().map(String::as_str)),
    ));
    params.push((
        "watch_weights".to_string(),
        format!(
            "[{}]",
            watch
                .values()
                .map(|weight| format!("{weight:?}"))
                .collect::<Vec<_>>()
                .join(",")
        ),
    ));
    params
}

fn risk_relation(service: &RiskService) -> String {
    if service.clear_source.is_some() {
        "file({risk_source:String}, Parquet) AS risk_findings LEFT ANY JOIN \
         file({risk_clear_source:String}, Parquet) AS risk_clears USING (entity)"
            .to_string()
    } else {
        "file({risk_source:String}, Parquet)".to_string()
    }
}

fn clear_boundary_filter(service: &RiskService) -> String {
    let published = if service.clear_source.is_some() {
        "ifNull(risk_clears.cleared_at_us, 0)"
    } else {
        "0"
    };
    format!(
        " AND timestamp_us > greatest({{global_clear_us:Int64}}, {published}, {REQUEST_CLEAR_BOUNDARY})"
    )
}

fn aggregate_sql(service: &RiskService, request: &RiskRequest) -> String {
    let relation = risk_relation(service);
    let clear = clear_boundary_filter(service);
    let scope = if request.deny_source_types.is_empty() {
        String::new()
    } else {
        " AND notEmpty(origin_source_types) AND NOT hasAny(arrayMap(origin -> lower(trimBoth(origin)), origin_source_types), {denied_sources:Array(String)})".to_string()
    };
    format!(
        "WITH signal_scores AS (\
           SELECT id, entity, multiIf(\
             stamped_entity_type = 'cloud_account', 'cloud_account', \
             match(entity, '^[0-9]{{1,3}}\\\\.[0-9]{{1,3}}\\\\.[0-9]{{1,3}}\\\\.[0-9]{{1,3}}$'), 'ip', \
             position(entity, '@') > 0, 'email', position(entity, '.') > 0, 'hostname', 'user'\
           ) AS entity_type, risk_score, timestamp_us, rule_id, mitre_tactics, rule_name, severity, \
           multiIf(timestamp_us >= {{c24:Int64}}, {{decay0:Float64}}, \
                   timestamp_us >= {{c3:Int64}}, {{decay1:Float64}}, \
                   timestamp_us >= {{c5:Int64}}, {{decay3:Float64}}, \
                   timestamp_us >= {{c7:Int64}}, {{decay5:Float64}}, 0.0) AS decay_factor \
           FROM {relation} \
           WHERE entity NOT IN ('', 'unknown') AND timestamp_us >= {{c7:Int64}} \
             AND timestamp_us < {{anchor_us:Int64}}{clear}{scope}\
         ) SELECT entity, entity_type, sumIf(risk_score, timestamp_us >= {{c24:Int64}}) AS risk_score_24h, \
           sum(risk_score) AS risk_score_7d, \
           toInt64(round(sumIf(risk_score * decay_factor, timestamp_us >= {{c24:Int64}}))) AS base_decayed_score_24h, \
           toInt64(round(sum(risk_score * decay_factor))) AS base_decayed_score_7d, \
           {WATCH_WEIGHT} AS watch_weight, \
           toInt64(round(base_decayed_score_24h * (1 + watch_weight))) AS decayed_score_24h, \
           toInt64(round(base_decayed_score_7d * (1 + watch_weight))) AS decayed_score_7d, \
           countIf(timestamp_us >= {{c24:Int64}}) AS signal_count_24h, count() AS signal_count_7d, \
           max(timestamp_us) AS last_signal_at, argMax(rule_name, tuple(timestamp_us, id)) AS last_rule_name, \
           argMax(severity, tuple(timestamp_us, id)) AS last_severity, \
           uniqExactIf(rule_id, timestamp_us >= {{c24:Int64}}) AS distinct_rules_24h, \
           uniqExact(rule_id) AS distinct_rules_7d, \
           length(arrayDistinct(arrayFlatten(groupArrayIf(mitre_tactics, timestamp_us >= {{c24:Int64}})))) AS distinct_tactics_24h, \
           length(arrayDistinct(arrayFlatten(groupArray(mitre_tactics)))) AS distinct_tactics_7d \
         FROM signal_scores GROUP BY entity, entity_type \
         ORDER BY decayed_score_24h DESC, decayed_score_7d DESC, entity"
    )
}

fn leaderboard_sql(
    service: &RiskService,
    request: &RiskRequest,
    params: &mut Vec<(String, String)>,
) -> Result<String, RiskError> {
    let window = request.window.as_deref().unwrap_or("24h");
    if !matches!(window, "24h" | "7d" | "all") {
        return Err(RiskError::Invalid(
            "leaderboard window is invalid".to_string(),
        ));
    }
    let (score, count) = if window == "24h" {
        ("decayed_score_24h", "signal_count_24h")
    } else {
        ("decayed_score_7d", "signal_count_7d")
    };
    params.push((
        "min_score".to_string(),
        request.min_score.unwrap_or(0).max(0).to_string(),
    ));
    params.push((
        "limit".to_string(),
        request.limit.unwrap_or(100).to_string(),
    ));
    params.push((
        "offset".to_string(),
        request.offset.unwrap_or(0).to_string(),
    ));
    let mut predicates = vec![
        format!("{score} >= {{min_score:Int64}}"),
        format!("{count} > 0"),
    ];
    if let Some(max_score) = request.max_score {
        params.push(("max_score".to_string(), max_score.max(0).to_string()));
        predicates.push(format!("{score} <= {{max_score:Int64}}"));
    }
    if let Some(entity_type) = &request.entity_type_filter {
        params.push(("entity_type".to_string(), entity_type.clone()));
        predicates.push("entity_type = {entity_type:String}".to_string());
    }
    // Watchlist member scores (NAN-3228): restrict to a set of normalized
    // member values, matched like the weight lookup.
    if !request.entities.is_empty() {
        params.push((
            "entities".to_string(),
            string_array(request.entities.iter().map(|entity| entity.as_str())),
        ));
        predicates.push("lower(entity) IN {entities:Array(String)}".to_string());
    }
    Ok(format!(
        "SELECT * FROM ({}) WHERE {} ORDER BY {score} DESC, {count} DESC, \
         entity_type ASC, entity ASC \
         LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}}",
        aggregate_sql(service, request),
        predicates.join(" AND ")
    ))
}

fn scores_sql(
    service: &RiskService,
    request: &RiskRequest,
    params: &mut Vec<(String, String)>,
) -> Result<String, RiskError> {
    params.push((
        "min_24h".to_string(),
        request.min_score_24h.unwrap_or(0).max(0).to_string(),
    ));
    params.push((
        "min_7d".to_string(),
        request.min_score_7d.unwrap_or(0).max(0).to_string(),
    ));
    params.push((
        "limit".to_string(),
        request.limit.unwrap_or(100).to_string(),
    ));
    Ok(format!(
        "SELECT * FROM ({}) WHERE decayed_score_24h >= {{min_24h:Int64}} \
         OR decayed_score_7d >= {{min_7d:Int64}} \
         ORDER BY decayed_score_24h DESC, decayed_score_7d DESC LIMIT {{limit:UInt64}}",
        aggregate_sql(service, request)
    ))
}

fn badge_sql(
    service: &RiskService,
    request: &RiskRequest,
    params: &mut Vec<(String, String)>,
) -> Result<String, RiskError> {
    params.push((
        "entities".to_string(),
        string_array(request.entities.iter().map(String::as_str)),
    ));
    Ok(format!(
        "SELECT * FROM ({}) WHERE entity IN {{entities:Array(String)}} \
         ORDER BY decayed_score_7d DESC LIMIT 1",
        aggregate_sql(service, request)
    ))
}

fn overview_sql(service: &RiskService, request: &RiskRequest) -> Result<String, RiskError> {
    let window = request.window.as_deref().unwrap_or("24h");
    if !matches!(window, "24h" | "7d" | "all") {
        return Err(RiskError::Invalid("overview window is invalid".to_string()));
    }
    let (score, count) = if window == "24h" {
        ("decayed_score_24h", "signal_count_24h")
    } else {
        ("decayed_score_7d", "signal_count_7d")
    };
    Ok(format!(
        "SELECT count() AS total_entities, countIf({score} > 70) AS critical_entities, \
         countIf({score} > 50 AND {score} <= 70) AS high_entities, \
         countIf({score} > 30 AND {score} <= 50) AS medium_entities, \
         countIf({score} > 0 AND {score} <= 30) AS low_entities, \
         toInt64(sum({count})) AS total_signals, if(count() > 0, avg({score}), 0.0) AS avg_risk_score \
         FROM ({}) WHERE {score} > 0",
        aggregate_sql(service, request)
    ))
}

fn entity_types_sql(service: &RiskService, request: &RiskRequest) -> String {
    format!(
        "SELECT entity_type, count() AS entity_count FROM ({}) \
         GROUP BY entity_type ORDER BY entity_count DESC, entity_type ASC",
        aggregate_sql(service, request)
    )
}

fn detail_filters(
    service: &RiskService,
    request: &RiskRequest,
    params: &mut Vec<(String, String)>,
) -> Result<String, RiskError> {
    let lookback = request
        .lookback_days
        .unwrap_or(if request.risk_operation == "activity" {
            28
        } else {
            7
        });
    if !(1..=28).contains(&lookback) {
        return Err(RiskError::Invalid("lookback is invalid".to_string()));
    }
    params.push((
        "entities".to_string(),
        string_array(request.entities.iter().map(String::as_str)),
    ));
    params.push((
        "cutoff_us".to_string(),
        (request.anchor_us - lookback * DAY_US).to_string(),
    ));
    let clear = clear_boundary_filter(service);
    let scope = if request.deny_source_types.is_empty() {
        ""
    } else {
        " AND notEmpty(origin_source_types) AND NOT hasAny(arrayMap(origin -> lower(trimBoth(origin)), origin_source_types), {denied_sources:Array(String)})"
    };
    Ok(format!(
        "entity IN {{entities:Array(String)}} AND timestamp_us >= {{cutoff_us:Int64}} \
         AND timestamp_us < {{anchor_us:Int64}}{clear}{scope}"
    ))
}

fn activity_sql(
    service: &RiskService,
    request: &RiskRequest,
    params: &mut Vec<(String, String)>,
) -> Result<String, RiskError> {
    let filters = detail_filters(service, request, params)?;
    let relation = risk_relation(service);
    Ok(format!(
        "SELECT entity, formatDateTime(fromUnixTimestamp64Micro(timestamp_us), '%Y-%m-%d', 'UTC') AS day, \
         count() AS cnt FROM {relation} WHERE {filters} \
         GROUP BY entity, day ORDER BY entity, day"
    ))
}

fn signals_sql(
    service: &RiskService,
    request: &RiskRequest,
    params: &mut Vec<(String, String)>,
) -> Result<String, RiskError> {
    let filters = detail_filters(service, request, params)?;
    let relation = risk_relation(service);
    let limit = request.limit.unwrap_or(100);
    if limit > 1_000 {
        return Err(RiskError::Invalid("signals limit exceeds 1000".to_string()));
    }
    params.push(("limit".to_string(), limit.to_string()));
    Ok(format!(
        "SELECT id, timestamp_us, rule_id, rule_name, severity, toInt32(risk_score) AS risk_score, \
         'detection_match' AS signal_type FROM {relation} \
         WHERE {filters} ORDER BY timestamp_us DESC, id DESC LIMIT {{limit:UInt64}}"
    ))
}

fn contributions_sql(
    service: &RiskService,
    request: &RiskRequest,
    params: &mut Vec<(String, String)>,
) -> Result<String, RiskError> {
    let filters = detail_filters(service, request, params)?;
    let relation = risk_relation(service);
    Ok(format!(
        "WITH signal_scores AS (SELECT id, timestamp_us, toInt32(risk_score) AS risk_score, rule_id, \
           rule_name, severity, multiIf(timestamp_us >= {{c24:Int64}}, {{decay0:Float64}}, \
           timestamp_us >= {{c3:Int64}}, {{decay1:Float64}}, timestamp_us >= {{c5:Int64}}, {{decay3:Float64}}, \
           timestamp_us >= {{c7:Int64}}, {{decay5:Float64}}, 0.0) AS decay_factor \
           FROM {relation} WHERE {filters}) \
         SELECT rule_id, argMax(rule_name, tuple(timestamp_us, id)) AS rule_name, \
           argMax(severity, tuple(timestamp_us, id)) AS severity, countIf(timestamp_us >= {{c24:Int64}}) AS fires_24h, \
           count() AS fires_7d, toInt64(round(sumIf(risk_score * decay_factor, timestamp_us >= {{c24:Int64}}))) \
           AS decayed_contribution_24h, toInt64(round(sum(risk_score * decay_factor))) AS decayed_contribution_7d, \
           max(timestamp_us) AS last_fire_at, argMax(risk_score, tuple(timestamp_us, id)) AS last_fire_score \
         FROM signal_scores GROUP BY rule_id ORDER BY decayed_contribution_7d DESC, rule_id LIMIT 50"
    ))
}

/// Hour-bucket × rule aggregates for the entity risk timeline (NAN-3225).
/// Bucket `h` holds `timestamp_us ∈ [anchor-(h+1)h, anchor-h·h)`; the API
/// folds them into an exact hourly decayed series
/// (`nanosiem_core::risk::timeline`). Same filters as `contributions`
/// (entity set, lookback, clear boundary, source scope), newest bucket
/// first so a capped read drops the oldest.
fn timeline_sql(
    service: &RiskService,
    request: &RiskRequest,
    params: &mut Vec<(String, String)>,
) -> Result<String, RiskError> {
    let filters = detail_filters(service, request, params)?;
    let relation = risk_relation(service);
    let limit = request.limit.unwrap_or(MAX_RESULT_ROWS);
    params.push(("limit".to_string(), limit.to_string()));
    Ok(format!(
        "SELECT toUInt32(intDiv({{anchor_us:Int64}} - 1 - timestamp_us, 3600000000)) AS hours_ago, rule_id, \
           argMax(rule_name, tuple(timestamp_us, id)) AS rule_name, \
           argMax(severity, tuple(timestamp_us, id)) AS severity, count() AS fires, \
           toInt64(sum(risk_score)) AS score_sum, max(timestamp_us) AS last_fire_us, \
           toInt32(argMax(risk_score, tuple(timestamp_us, id))) AS last_fire_score, \
           arrayDistinct(arrayFlatten(groupArray(mitre_tactics))) AS mitre_tactics \
         FROM {relation} WHERE {filters} \
         GROUP BY hours_ago, rule_id ORDER BY hours_ago ASC, rule_id ASC LIMIT {{limit:UInt64}}"
    ))
}

/// Watchlist entity suggestions (NAN-3249): distinct ledger entities over the
/// detail lookback (default 28 days) that match a suggest pattern on the
/// LOWERCASED entity, under the request's source scope; exact matches first,
/// then newest, at most `SUGGEST_ROWS_PER_VALUE` per typed value.
///
/// Patterns travel only as bound arrays and compare with `=` / `startsWith`
/// / `endsWith` — never LIKE — so `%`, `_` and quotes in a typed value are
/// literal. Clear boundaries are deliberately not applied: a cleared entity
/// is still an observed value that scores again on its next finding.
fn suggest_sql(request: &RiskRequest, params: &mut Vec<(String, String)>) -> Result<String, RiskError> {
    let lookback = request.lookback_days.unwrap_or(28);
    if !(1..=28).contains(&lookback) {
        return Err(RiskError::Invalid("lookback is invalid".to_string()));
    }
    params.push(("cutoff_us".to_string(), (request.anchor_us - lookback * DAY_US).to_string()));
    params.push((
        "suggest_texts".to_string(),
        string_array(request.suggest_patterns.iter().map(|pattern| pattern.text.as_str())),
    ));
    let ints = |values: Vec<u64>| {
        format!("[{}]", values.iter().map(u64::to_string).collect::<Vec<_>>().join(","))
    };
    params.push((
        "suggest_ops".to_string(),
        ints(request.suggest_patterns.iter().map(|pattern| u64::from(pattern.op.code())).collect()),
    ));
    params.push((
        "suggest_groups".to_string(),
        ints(request.suggest_patterns.iter().map(|pattern| u64::from(pattern.group)).collect()),
    ));
    params.push((
        "suggest_indexes".to_string(),
        ints((1..=request.suggest_patterns.len() as u64).collect()),
    ));
    params.push(("suggest_rows_per_value".to_string(), SUGGEST_ROWS_PER_VALUE.to_string()));
    let scope = if request.deny_source_types.is_empty() {
        ""
    } else {
        " AND notEmpty(origin_source_types) AND NOT hasAny(arrayMap(origin -> lower(trimBoth(origin)), origin_source_types), {denied_sources:Array(String)})"
    };
    Ok(format!(
        "SELECT toUInt16(pg) AS value_index, entity, any(observed_type) AS entity_type, \
           toInt64(max(seen_us)) AS last_seen_us, toUInt32(min(pi)) AS pattern_index \
         FROM (\
           SELECT entity, any(multiIf(\
             stamped_entity_type = 'cloud_account', 'cloud_account', \
             match(entity, '^[0-9]{{1,3}}\\\\.[0-9]{{1,3}}\\\\.[0-9]{{1,3}}\\\\.[0-9]{{1,3}}$'), 'ip', \
             position(entity, '@') > 0, 'email', position(entity, '.') > 0, 'hostname', 'user'\
           )) AS observed_type, max(timestamp_us) AS seen_us \
           FROM file({{risk_source:String}}, Parquet) \
           WHERE entity NOT IN ('', 'unknown') AND timestamp_us >= {{cutoff_us:Int64}} \
             AND timestamp_us < {{anchor_us:Int64}}{scope} \
             AND arrayExists((t, o) -> multiIf(o = 0, lower(entity) = t, o = 1, startsWith(lower(entity), t), \
                 endsWith(lower(entity), t)), {{suggest_texts:Array(String)}}, {{suggest_ops:Array(UInt8)}}) \
           GROUP BY entity\
         ) ARRAY JOIN {{suggest_texts:Array(String)}} AS pv, {{suggest_ops:Array(UInt8)}} AS pk, \
           {{suggest_groups:Array(UInt16)}} AS pg, {{suggest_indexes:Array(UInt32)}} AS pi \
         WHERE multiIf(pk = 0, lower(entity) = pv, pk = 1, startsWith(lower(entity), pv), endsWith(lower(entity), pv)) \
         GROUP BY value_index, entity \
         ORDER BY value_index ASC, min(pk) ASC, last_seen_us DESC, entity ASC \
         LIMIT {{suggest_rows_per_value:UInt64}} BY value_index"
    ))
}

fn string_array<'a>(values: impl Iterator<Item = &'a str>) -> String {
    let values = values
        .map(|value| format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'")))
        .collect::<Vec<_>>();
    format!("[{}]", values.join(","))
}

fn decode_rows(bytes: &[u8]) -> Result<Vec<Value>, RiskError> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_slice(line)
                .map_err(|error| RiskError::Query(format!("risk row is not valid JSON: {error}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_time_decay_boundaries_match_the_finding_reader() {
        let service = RiskService {
            source: PathBuf::from("/tmp/risk.parquet"),
            snapshot_id: "snapshot".into(),
            snapshot_version: "0".repeat(64),
            bytes: 1,
            modified: std::time::SystemTime::UNIX_EPOCH,
            clear_snapshot_version: None,
            clear_source: None,
            clear_bytes: 0,
            clear_modified: None,
            clear_published_revision: 0,
            global_clear_us: 0,
        };
        let request = RiskRequest {
            request_id: "boundary".into(),
            tenant_id: "tenant".into(),
            risk_operation: "leaderboard".into(),
            anchor_us: 8 * DAY_US,
            decay: RiskDecay {
                decay_0_24h: 1.0,
                decay_1_3d: 0.7,
                decay_3_5d: 0.4,
                decay_5_7d: 0.2,
            },
            clear_boundaries: BTreeMap::new(),
            watch_weights: Default::default(),
            minimum_clear_revision: None,
            deny_source_types: vec!["Denied_Source".into()],
            window: None,
            entity_type_filter: None,
            min_score: None,
            max_score: None,
            min_score_24h: None,
            min_score_7d: None,
            limit: None,
            offset: None,
            entities: Vec::new(),
            lookback_days: None,
            suggest_patterns: Vec::new(),
        };
        let params = common_params(&service, &request)
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        assert_eq!(params["c24"], (7 * DAY_US).to_string());
        assert_eq!(params["c3"], (5 * DAY_US).to_string());
        assert_eq!(params["c5"], (3 * DAY_US).to_string());
        assert_eq!(params["c7"], DAY_US.to_string());
        assert_eq!(params["denied_sources"], "['denied_source']");
        let sql = aggregate_sql(&service, &request);
        assert!(sql.contains("timestamp_us >= {c24:Int64}, {decay0:Float64}"));
        assert!(sql.contains("timestamp_us >= {c3:Int64}, {decay1:Float64}"));
        assert!(sql.contains("timestamp_us >= {c5:Int64}, {decay3:Float64}"));
        assert!(sql.contains("timestamp_us >= {c7:Int64}, {decay5:Float64}, 0.0"));
        assert!(sql.contains("timestamp_us < {anchor_us:Int64}"));
        assert!(sql.contains("notEmpty(origin_source_types)"));
        assert!(sql.contains("sum(risk_score) AS risk_score_7d"));
        // NAN-3228: the unweighted decayed sum is the base; the effective
        // (watch-weighted) decayed_score_7d is derived from it.
        assert!(sql.contains("toInt64(round(sum(risk_score * decay_factor))) AS base_decayed_score_7d"));
        assert!(sql.contains("toInt64(round(base_decayed_score_7d * (1 + watch_weight))) AS decayed_score_7d"));
    }

    #[test]
    fn string_arrays_escape_values_without_building_sql() {
        assert_eq!(
            string_array(["alpha", "o'hare"].into_iter()),
            "['alpha','o\\'hare']"
        );
    }

    #[test]
    fn invalid_decay_and_bounds_fail_closed() {
        let request = RiskRequest {
            request_id: "r".into(),
            tenant_id: "t".into(),
            risk_operation: "scores".into(),
            anchor_us: 1,
            decay: RiskDecay {
                decay_0_24h: 2.0,
                decay_1_3d: 0.7,
                decay_3_5d: 0.4,
                decay_5_7d: 0.2,
            },
            clear_boundaries: BTreeMap::new(),
            watch_weights: Default::default(),
            minimum_clear_revision: None,
            deny_source_types: Vec::new(),
            window: None,
            entity_type_filter: None,
            min_score: None,
            max_score: None,
            min_score_24h: None,
            min_score_7d: None,
            limit: None,
            offset: None,
            entities: Vec::new(),
            lookback_days: None,
            suggest_patterns: Vec::new(),
        };
        assert!(validate_request(&request).is_err());
    }

    #[test]
    fn leaderboard_applies_parameterized_score_band_before_pagination() {
        let service = RiskService {
            source: PathBuf::from("/tmp/risk.parquet"),
            snapshot_id: "snapshot".to_string(),
            snapshot_version: "0".repeat(64),
            bytes: 1,
            modified: std::time::SystemTime::UNIX_EPOCH,
            clear_snapshot_version: None,
            clear_source: None,
            clear_bytes: 0,
            clear_modified: None,
            clear_published_revision: 0,
            global_clear_us: 0,
        };
        let request = RiskRequest {
            request_id: "r".into(),
            tenant_id: "t".into(),
            risk_operation: "leaderboard".into(),
            anchor_us: DAY_US * 8,
            decay: RiskDecay {
                decay_0_24h: 1.0,
                decay_1_3d: 0.7,
                decay_3_5d: 0.4,
                decay_5_7d: 0.2,
            },
            clear_boundaries: BTreeMap::new(),
            watch_weights: Default::default(),
            minimum_clear_revision: None,
            deny_source_types: Vec::new(),
            window: Some("24h".into()),
            entity_type_filter: Some("ip".into()),
            min_score: Some(51),
            max_score: Some(70),
            min_score_24h: None,
            min_score_7d: None,
            limit: Some(101),
            offset: Some(200),
            entities: Vec::new(),
            lookback_days: None,
            suggest_patterns: Vec::new(),
        };
        let mut params = Vec::new();
        let sql = leaderboard_sql(&service, &request, &mut params).expect("leaderboard SQL");
        let params = params.into_iter().collect::<BTreeMap<_, _>>();
        assert!(sql.contains("decayed_score_24h <= {max_score:Int64}"));
        assert!(sql.contains("entity_type = {entity_type:String}"));
        assert!(sql.contains("entity_type ASC, entity ASC"));
        assert_eq!(params["min_score"], "51");
        assert_eq!(params["max_score"], "70");
        assert_eq!(params["limit"], "101");
        assert_eq!(params["offset"], "200");
    }

    #[test]
    fn global_clear_is_one_boundary_and_not_an_entity_array_member() {
        let mut request = RiskRequest {
            request_id: "r".into(),
            tenant_id: "t".into(),
            risk_operation: "scores".into(),
            anchor_us: 2,
            decay: RiskDecay {
                decay_0_24h: 1.0,
                decay_1_3d: 0.7,
                decay_3_5d: 0.4,
                decay_5_7d: 0.2,
            },
            clear_boundaries: BTreeMap::new(),
            watch_weights: Default::default(),
            minimum_clear_revision: None,
            deny_source_types: Vec::new(),
            window: None,
            entity_type_filter: None,
            min_score: None,
            max_score: None,
            min_score_24h: None,
            min_score_7d: None,
            limit: None,
            offset: None,
            entities: Vec::new(),
            lookback_days: None,
            suggest_patterns: Vec::new(),
        };
        request
            .clear_boundaries
            .insert(GLOBAL_CLEAR_ENTITY.to_string(), 123);
        request.clear_boundaries.insert("alice".to_string(), 456);
        let service = RiskService {
            source: PathBuf::from("/tmp/risk.parquet"),
            snapshot_id: "snapshot".to_string(),
            snapshot_version: "0".repeat(64),
            bytes: 1,
            modified: std::time::SystemTime::UNIX_EPOCH,
            clear_snapshot_version: None,
            clear_source: None,
            clear_bytes: 0,
            clear_modified: None,
            clear_published_revision: 0,
            global_clear_us: 0,
        };
        let params = common_params(&service, &request)
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            params.get("global_clear_us").map(String::as_str),
            Some("123")
        );
        assert_eq!(
            params.get("clear_entities").map(String::as_str),
            Some("['alice']")
        );
        assert!(aggregate_sql(&service, &request).contains("greatest({global_clear_us:Int64}"));
        assert!(aggregate_sql(&service, &request).contains("materialize(entity)"));
        assert!(
            detail_filters(&service, &request, &mut Vec::new())
                .unwrap()
                .contains("materialize(entity)")
        );
    }

    #[test]
    fn immutable_clear_sidecar_is_joined_and_revision_fenced() {
        let directory = tempfile::tempdir().expect("temporary risk state");
        let risk_source = directory.path().join("risk.parquet");
        let clear_source = directory.path().join("risk-clears.parquet");
        std::fs::write(&risk_source, b"risk").expect("risk source");
        std::fs::write(&clear_source, b"clear").expect("clear source");
        let risk_metadata = std::fs::metadata(&risk_source).expect("risk metadata");
        let clear_metadata = std::fs::metadata(&clear_source).expect("clear metadata");
        let service = RiskService {
            source: risk_source.clone(),
            snapshot_id: "snapshot".to_string(),
            snapshot_version: format!("sha256:{}", "0".repeat(64)),
            bytes: risk_metadata.len(),
            modified: risk_metadata.modified().expect("risk modified"),
            clear_snapshot_version: Some(format!("sha256:{}", "1".repeat(64))),
            clear_source: Some(clear_source.clone()),
            clear_bytes: clear_metadata.len(),
            clear_modified: Some(clear_metadata.modified().expect("clear modified")),
            clear_published_revision: 42,
            global_clear_us: 123,
        };
        let mut request = RiskRequest {
            request_id: "r".into(),
            tenant_id: "t".into(),
            risk_operation: "npl".into(),
            anchor_us: DAY_US * 8,
            decay: RiskDecay {
                decay_0_24h: 1.0,
                decay_1_3d: 0.7,
                decay_3_5d: 0.4,
                decay_5_7d: 0.2,
            },
            clear_boundaries: BTreeMap::new(),
            watch_weights: Default::default(),
            minimum_clear_revision: Some(42),
            deny_source_types: Vec::new(),
            window: None,
            entity_type_filter: None,
            min_score: None,
            max_score: None,
            min_score_24h: None,
            min_score_7d: None,
            limit: None,
            offset: None,
            entities: Vec::new(),
            lookback_days: None,
            suggest_patterns: Vec::new(),
        };
        request.clear_boundaries.insert("alice".to_string(), 456);
        let (source, params, bytes) = service.npl_source(&request).expect("fenced source");
        assert!(source.contains("LEFT ANY JOIN"));
        assert!(source.contains("risk_clears.cleared_at_us"));
        assert_eq!(bytes, risk_metadata.len() + clear_metadata.len());
        let params = params.into_iter().collect::<BTreeMap<_, _>>();
        assert_eq!(
            params["risk_clear_source"],
            clear_source.to_string_lossy().as_ref()
        );
        assert_eq!(params["global_clear_us"], "123");

        request.minimum_clear_revision = Some(43);
        assert!(matches!(
            service.npl_source(&request),
            Err(RiskError::ClearStateBehind)
        ));
    }

    /// The lean cell's `POST /v1/risk` extracts `Json<RiskRequest>` directly
    /// (part_query/server.rs `risk_route`), so the body the API sends must
    /// deserialize as-is. It is pinned byte-for-byte to what
    /// the enterprise crate `RiskLakeClient` posts to a lake cell; a
    /// `route` key would be rejected with axum's plain-text 422.
    #[test]
    fn lean_cell_body_from_the_api_deserializes_on_the_direct_risk_route() {
        let body = serde_json::json!({
            "request_id": "01a0e5a7-e4ab-7eb2-b0f5-cb6edbb29c09",
            "tenant_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "risk_operation": "leaderboard",
            "anchor_us": 1_790_000_000_000_000_i64,
            "decay": {"decay_0_24h": 1.0, "decay_1_3d": 0.7, "decay_3_5d": 0.4, "decay_5_7d": 0.2},
            "clear_boundaries": {},
            "deny_source_types": [],
            "entity_type_filter": "host",
            "limit": 50,
            "offset": 0
        });
        let request: RiskRequest = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(request.risk_operation, "leaderboard");
        assert_eq!(request.entity_type_filter.as_deref(), Some("host"));

        // The gen1 `/v1/query` discriminator is not part of this schema.
        let mut with_route = body;
        with_route["route"] = serde_json::json!("risk");
        let error = serde_json::from_value::<RiskRequest>(with_route).unwrap_err();
        assert!(error.to_string().contains("unknown field `route`"), "{error}");
    }

    /// NAN-3225: timeline buckets use the detail filters (entity set,
    /// lookback, clears) and, for a restricted caller, the same fail-closed
    /// origin predicate as every other risk read.
    #[test]
    fn timeline_buckets_are_detail_filtered_and_source_scoped() {
        let mut request: RiskRequest = serde_json::from_value(serde_json::json!({
            "request_id": "r", "tenant_id": "t", "risk_operation": "timeline",
            "anchor_us": 1_790_000_000_000_000_i64,
            "decay": {"decay_0_24h": 1.0, "decay_1_3d": 0.7, "decay_3_5d": 0.4, "decay_5_7d": 0.2},
            "entities": ["alice"], "lookback_days": 14, "limit": 10000
        }))
        .unwrap();
        let service = RiskService {
            source: PathBuf::from("/tmp/risk.parquet"),
            snapshot_id: "snapshot".to_string(),
            snapshot_version: "0".repeat(64),
            bytes: 1,
            modified: std::time::SystemTime::UNIX_EPOCH,
            clear_snapshot_version: None,
            clear_source: None,
            clear_bytes: 0,
            clear_modified: None,
            clear_published_revision: 0,
            global_clear_us: 0,
        };
        assert!(validate_request(&request).is_ok());
        let mut params = common_params(&service, &request);
        let open = timeline_sql(&service, &request, &mut params).unwrap();
        assert!(open.contains("intDiv({anchor_us:Int64} - 1 - timestamp_us, 3600000000)"));
        assert!(open.contains("entity IN {entities:Array(String)}"));
        assert!(open.contains("timestamp_us < {anchor_us:Int64}"));
        assert!(open.contains("GROUP BY hours_ago, rule_id ORDER BY hours_ago ASC"));
        assert!(!open.contains("denied_sources"));
        let params = params.into_iter().collect::<BTreeMap<_, _>>();
        assert_eq!(
            params.get("cutoff_us").map(String::as_str),
            Some((1_790_000_000_000_000_i64 - 14 * DAY_US).to_string().as_str())
        );
        assert_eq!(params.get("limit").map(String::as_str), Some("10000"));

        request.deny_source_types = vec!["apache_access".into()];
        let scoped = timeline_sql(&service, &request, &mut Vec::new()).unwrap();
        assert!(scoped.contains("notEmpty(origin_source_types) AND NOT hasAny("));
        assert!(scoped.contains("{denied_sources:Array(String)}"));

        request.lookback_days = Some(29);
        assert!(validate_request(&request).is_err(), "lookbacks stay bounded");
    }

    /// NAN-3249: the suggest operation is bounded (lookback, pattern count,
    /// per-value LIMIT BY), parameterized (typed values only travel as bound
    /// arrays, never LIKE), and source-scoped like every other risk read.
    #[test]
    fn suggest_is_bounded_parameterized_and_source_scoped() {
        use nanosiem_core::risk::watchlist_suggest::{plan, SuggestInput};
        let plan = plan(&[
            SuggestInput { value: "o'neil%_x".into(), entity_type: None },
            SuggestInput { value: "web01.corp.local".into(), entity_type: None },
        ])
        .unwrap();
        let mut request: RiskRequest = serde_json::from_value(serde_json::json!({
            "request_id": "r", "tenant_id": "t", "risk_operation": "suggest",
            "anchor_us": 1_790_000_000_000_000_i64,
            "decay": {"decay_0_24h": 1.0, "decay_1_3d": 0.7, "decay_3_5d": 0.4, "decay_5_7d": 0.2},
            "lookback_days": 28,
            "suggest_patterns": plan.patterns,
        }))
        .unwrap();
        assert!(validate_request(&request).is_ok());
        let mut params = Vec::new();
        let open = suggest_sql(&request, &mut params).unwrap();
        assert!(!open.to_uppercase().contains("LIKE"), "{open}");
        assert!(!open.contains("o'neil") && !open.contains("web01"), "values are bound: {open}");
        assert!(open.contains("LIMIT {suggest_rows_per_value:UInt64} BY value_index"));
        assert!(open.contains("timestamp_us >= {cutoff_us:Int64}") && open.contains("timestamp_us < {anchor_us:Int64}"));
        assert!(!open.contains("denied_sources"));
        let params = params.into_iter().collect::<BTreeMap<_, _>>();
        assert_eq!(
            params.get("cutoff_us").map(String::as_str),
            Some((1_790_000_000_000_000_i64 - 28 * DAY_US).to_string().as_str())
        );
        assert!(params["suggest_texts"].starts_with("['o\\'neil%_x',"), "{}", params["suggest_texts"]);
        assert_eq!(params["suggest_rows_per_value"], SUGGEST_ROWS_PER_VALUE.to_string());
        let n = plan.patterns.len();
        assert_eq!(params["suggest_indexes"], format!("[{}]", (1..=n).map(|i| i.to_string()).collect::<Vec<_>>().join(",")));

        request.deny_source_types = vec!["apache_access".into()];
        let scoped = suggest_sql(&request, &mut Vec::new()).unwrap();
        assert!(scoped.contains("notEmpty(origin_source_types) AND NOT hasAny("));
        assert!(scoped.contains("{denied_sources:Array(String)}"));

        let mut bad = request.clone();
        bad.lookback_days = Some(29);
        assert!(validate_request(&bad).is_err(), "lookbacks stay bounded");
        let mut bad = request.clone();
        bad.suggest_patterns = vec![plan.patterns[0].clone(); SUGGEST_MAX_PATTERNS + 1];
        assert!(validate_request(&bad).is_err(), "pattern count is bounded");
        let mut bad = request.clone();
        bad.suggest_patterns[0].group = SUGGEST_MAX_VALUES as u16;
        assert!(validate_request(&bad).is_err(), "group index is bounded");
        let mut bad = request.clone();
        bad.suggest_patterns[0].text = String::new();
        assert!(validate_request(&bad).is_err(), "empty pattern refused");
        let mut bad = request.clone();
        bad.risk_operation = "leaderboard".into();
        assert!(validate_request(&bad).is_err(), "patterns only ride the suggest op");
    }
}
