// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cloud overview — single aggregate endpoint that populates the redesigned
//! `| cloud` landing view (NAN-394).
//!
//! The landing view renders an org-wide posture dashboard: header with posture
//! score, accounts grid, top risky principals, cross-account timeline, anomaly
//! feed, service health, and top sensitive changes. This module fans the
//! required ClickHouse queries (and a risk-score fan-out against Postgres)
//! and assembles a single JSON response consumed by the frontend.
//!
//! Broken subqueries are logged at `error` level with a `subquery` tag so the
//! UI's empty-state fallbacks don't mask real failures in log dashboards —
//! same rule we learned porting NAN-393.

use super::SearchService;
use crate::extensions::CloudRiskProvider;
use crate::query::TimeRange;
use crate::risk::{EntityRiskSummary, RiskFilter, RiskTimeWindow};
use crate::search::SearchError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

// ============================================================================
// Response types — mirror nanosiem-web/src/lib/api/types.ts CloudOverview*
// ============================================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudOverview {
    pub header: CloudOverviewHeader,
    pub accounts: Vec<CloudOverviewAccount>,
    pub risky_principals: Vec<CloudOverviewPrincipal>,
    pub timeline: CloudOverviewTimeline,
    pub anomalies: Vec<CloudOverviewAnomaly>,
    pub service_health: Vec<CloudOverviewServiceHealth>,
    pub changes: Vec<CloudOverviewChange>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudOverviewProviderBreakdown {
    pub id: String,
    pub label: String,
    pub events: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudOverviewOpenAlerts {
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudOverviewHeader {
    pub org: String,
    pub org_id: String,
    pub window_label: String,
    pub accounts: u64,
    pub principals: u64,
    pub regions: u64,
    pub providers: Vec<CloudOverviewProviderBreakdown>,
    pub events_total: u64,
    pub events_failed: u64,
    pub events_denied: u64,
    pub open_alerts: CloudOverviewOpenAlerts,
    pub posture_score: u32,
    pub posture_delta: i32,
    pub posture_reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudOverviewAccount {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub events: u64,
    pub risk: u32,
    pub band: String,
    pub delta: i32,
    pub alerts: u64,
    pub principals: u64,
    pub regions: u64,
    pub top_principal: Option<String>,
    pub top_principal_risk: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudOverviewPrincipal {
    pub id: String,
    #[serde(rename = "type")]
    pub principal_type: String,
    pub account: String,
    pub risk: u32,
    pub band: String,
    pub delta: i32,
    pub events_24h: u64,
    pub reasons: Vec<String>,
    pub last_seen: Option<String>,
    pub sparkline: Vec<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudOverviewTimelineLane {
    pub id: String,
    pub label: String,
    pub accent: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudOverviewTimelineMarker {
    pub at: u32,
    pub label: String,
    pub severity: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudOverviewTimeline {
    pub label: String,
    pub buckets: u32,
    pub lanes: Vec<CloudOverviewTimelineLane>,
    /// Sparse `[bucket_index, lane_id, weight]` triples.
    pub points: Vec<serde_json::Value>,
    pub markers: Vec<CloudOverviewTimelineMarker>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudOverviewAnomaly {
    pub id: String,
    pub at: String,
    pub severity: String,
    pub kind: String,
    pub title: String,
    pub detail: String,
    pub principal: Option<String>,
    pub account: Option<String>,
    pub service: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudOverviewServiceHealth {
    pub id: String,
    pub label: String,
    pub events: u64,
    pub errors: u64,
    pub error_rate: f64,
    pub delta: f64,
    pub accent: String,
    pub status: String,
    pub top_error: Option<String>,
    pub trend: Vec<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudOverviewChange {
    pub at: String,
    pub kind: String,
    pub severity: String,
    pub account: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: Option<String>,
}

// ============================================================================
// Constants
// ============================================================================

/// Buckets shown in the cross-account timeline. Matches the mockup (48 buckets
/// across a 24h window = 30min buckets). For shorter windows the bucket width
/// is computed from the window span so we always produce 48 buckets total.
const TIMELINE_BUCKETS: u32 = 48;

/// Buckets shown in per-service trend sparklines.
const SERVICE_TREND_BUCKETS: u32 = 12;

/// Number of principals returned in the risky-principals list.
const TOP_PRINCIPALS_LIMIT: usize = 8;

/// Number of accounts returned in the accounts grid.
const TOP_ACCOUNTS_LIMIT: usize = 12;

/// Services returned in the service-health panel.
const TOP_SERVICES_LIMIT: usize = 10;

/// Sensitive changes returned in the Top Changes panel.
const TOP_CHANGES_LIMIT: usize = 10;

/// Anomalies returned in the feed.
const ANOMALIES_LIMIT: usize = 20;

fn band_for_score(score: u32) -> &'static str {
    if score >= 80 {
        "critical"
    } else if score >= 60 {
        "high"
    } else if score >= 35 {
        "medium"
    } else {
        "low"
    }
}

fn service_accent(service: &str) -> &'static str {
    match service {
        "iam" => "oklch(65% 0.19 30)",
        "sts" => "oklch(68% 0.14 30)",
        "secretsmanager" | "secrets" => "oklch(62% 0.18 0)",
        "s3" => "oklch(66% 0.16 170)",
        "kms" => "oklch(68% 0.13 290)",
        "ec2" => "oklch(66% 0.13 240)",
        "ecs" => "oklch(64% 0.13 220)",
        "lambda" => "oklch(66% 0.15 30)",
        "cloudformation" | "cfn" => "oklch(62% 0.12 280)",
        "rds" => "oklch(64% 0.13 260)",
        "signin" => "oklch(60% 0.10 90)",
        _ => "oklch(65% 0.05 250)",
    }
}

fn lane_accent(idx: usize) -> &'static str {
    // Palette matches the mockup's per-account lane accents. Indices beyond the
    // palette wrap so we never produce a blank lane.
    const PALETTE: [&str; 6] = [
        "oklch(68% 0.18 28)",
        "oklch(70% 0.15 50)",
        "oklch(68% 0.14 170)",
        "oklch(68% 0.14 240)",
        "oklch(65% 0.16 0)",
        "oklch(68% 0.12 290)",
    ];
    PALETTE[idx % PALETTE.len()]
}

fn window_label(time_range: &TimeRange) -> String {
    let span_secs = (time_range.end - time_range.start).num_seconds().max(0);
    if span_secs <= 3_600 {
        "last 1h".into()
    } else if span_secs <= 6 * 3_600 {
        format!("last {}h", span_secs / 3_600)
    } else if span_secs <= 26 * 3_600 {
        "last 24h".into()
    } else if span_secs <= 7 * 24 * 3_600 {
        format!("last {}d", (span_secs / 86_400).max(1))
    } else {
        format!("last {}d", (span_secs / 86_400).max(1))
    }
}

// ============================================================================
// Public entry
// ============================================================================

impl SearchService {
    pub async fn query_cloud_overview(
        &self,
        provider_filter: Option<&str>,
        account_filter: Option<&str>,
        time_range: &TimeRange,
    ) -> Result<CloudOverview, SearchError> {
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok(CloudOverview::default()),
        };

        let start_str = time_range
            .start
            .format("%Y-%m-%d %H:%M:%S%.6f")
            .to_string();
        let end_str = time_range
            .end
            .format("%Y-%m-%d %H:%M:%S%.6f")
            .to_string();

        let span_secs = (time_range.end - time_range.start).num_seconds().max(60);
        let timeline_bucket_secs = (span_secs as u64 / TIMELINE_BUCKETS as u64).max(1);
        let timeline_unix_start = time_range.start.timestamp() as u64;
        let trend_bucket_secs = (span_secs as u64 / SERVICE_TREND_BUCKETS as u64).max(1);

        // Active schema profile (NAN-1241). Every physical column referenced in
        // the raw SQL below is resolved through the profile so the queries run
        // against the right table + columns under both UDM (byte-equivalent to
        // the previous hardcodes, modulo the seam's uniform reserved-word
        // quoting) and OCSF (promoted dotted columns). Fields the active schema
        // does not map (`udm_column_sql` → None) are SKIPPED — we never emit a
        // dead `ext.` reference (that 500s on OCSF) nor the bare literal name.
        let profile = self.active_profile.as_ref();
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(profile));
        let signals_table = self.table_names.read("signals");

        // Resolve the cloud-context columns once. `cloud_provider` /
        // `cloud_account_id` gate both the filter clauses and the scope
        // predicates; the rest feed individual sub-queries. All map under both
        // shipped schemas today, but we honour skip-on-None throughout so a
        // future schema that drops a concept degrades gracefully instead of
        // referencing an unknown column.
        let cloud_provider_col = profile.udm_column_sql("cloud_provider");
        let cloud_service_col = profile.udm_column_sql("cloud_service");
        let cloud_account_id_col = profile.udm_column_sql("cloud_account_id");
        let cloud_region_col = profile.udm_column_sql("cloud_region");
        let user_col = Self::cloud_principal_col(profile);
        let status_col = profile.udm_column_sql("status");
        let http_status_col = profile.udm_column_sql("http_status_code");
        let action_col = profile.udm_column_sql("action");
        let change_type_col = profile.udm_column_sql("change_type");
        let resource_name_col = profile.udm_column_sql("resource_name");
        let resource_type_col = profile.udm_column_sql("resource_type");

        // The provider/account filters can only apply when the schema actually
        // has the gating column; otherwise drop the clause (and its bind).
        let provider_filter_active = provider_filter
            .filter(|p| !p.is_empty())
            .is_some()
            && cloud_provider_col.is_some();
        let account_filter_active = account_filter
            .filter(|a| !a.is_empty())
            .is_some()
            && cloud_account_id_col.is_some();
        let provider_clause = match (&cloud_provider_col, provider_filter_active) {
            (Some(col), true) => format!(" AND lower({col}) = lower(?)"),
            _ => String::new(),
        };
        let account_clause = match (&cloud_account_id_col, account_filter_active) {
            (Some(col), true) => format!(" AND {col} = ?"),
            _ => String::new(),
        };
        let extra_bind = |q: clickhouse::query::Query| -> clickhouse::query::Query {
            let mut q = q;
            if provider_filter_active {
                if let Some(p) = provider_filter.filter(|p| !p.is_empty()) {
                    q = q.bind(p.to_string());
                }
            }
            if account_filter_active {
                if let Some(a) = account_filter.filter(|a| !a.is_empty()) {
                    q = q.bind(a.to_string());
                }
            }
            q
        };

        // --- 1. Header / totals ---------------------------------------------
        // Scope = "any log row with cloud context populated". Parsers set
        // cloud_provider up-front (e.g. aws_cloudtrail sets "aws" at the top
        // of the VRL), but other sources only set cloud_service or
        // cloud_account_id, so we OR across all three. Errors are split into
        // action-level (status) and transport-level (http_status_code) —
        // everything else is a 200/success.
        // Cloud-scope predicate: "any row with cloud context populated". OR
        // across whichever of provider/service/account the schema maps; if none
        // map there is no cloud context to scope on and we omit the predicate.
        let cloud_scope_predicate = {
            let terms: Vec<String> = [&cloud_provider_col, &cloud_service_col, &cloud_account_id_col]
                .into_iter()
                .filter_map(|c| c.as_ref().map(|col| format!("{col} != ''")))
                .collect();
            if terms.is_empty() {
                String::new()
            } else {
                format!("AND ({})", terms.join(" OR "))
            }
        };

        // Header aggregate fragments — each axis is skipped when its column is
        // unmapped so we never reference an unknown column. NAN-1248: `status_cmp`
        // is the raw column under UDM (byte-identical) and `lower(status)` under
        // OCSF (matches the capitalized OCSF caption 'Failure'/'Success'). OCSF
        // has no 'error'/'denied' status caption, so those terms never match —
        // the http_response.code fallback below covers the denied axis.
        let events_failed_expr = match &status_col {
            Some(_) => {
                let s = Self::status_cmp_col(self.active_profile.as_ref());
                format!("countIf({s} = 'failure' OR {s} = 'error' OR {s} = 'denied')")
            }
            None => "toUInt64(0)".to_string(),
        };
        let events_denied_expr = {
            let mut terms: Vec<String> = Vec::new();
            if status_col.is_some() {
                let s = Self::status_cmp_col(self.active_profile.as_ref());
                terms.push(format!("{s} = 'denied'"));
            }
            if let Some(col) = &http_status_col {
                terms.push(format!("{col} = 403"));
            }
            if terms.is_empty() {
                "toUInt64(0)".to_string()
            } else {
                format!("countIf({})", terms.join(" OR "))
            }
        };
        let accounts_expr = match &cloud_account_id_col {
            Some(col) => format!("uniqIf({col}, {col} != '')"),
            None => "toUInt64(0)".to_string(),
        };
        let principals_expr = match &user_col {
            Some(col) => format!("uniqIf({col}, {col} != '')"),
            None => "toUInt64(0)".to_string(),
        };
        let regions_expr = match &cloud_region_col {
            Some(col) => format!("uniqIf({col}, {col} != '')"),
            None => "toUInt64(0)".to_string(),
        };
        let header_sql = format!(
            r#"SELECT
                count() AS events_total,
                {events_failed_expr} AS events_failed,
                {events_denied_expr} AS events_denied,
                {accounts_expr} AS accounts,
                {principals_expr} AS principals,
                {regions_expr} AS regions
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              {cloud_scope_predicate}
              {provider_clause}
              {account_clause}"#,
        );
        // Provider breakdown — only meaningful when the schema maps
        // `cloud_provider`. When unmapped we hand the executor a no-result query
        // shape (empty string column) so downstream parsing yields zero rows.
        let provider_sql = match &cloud_provider_col {
            Some(col) => format!(
                r#"SELECT lower({col}) AS provider, count() AS cnt
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND {col} != ''
              {provider_clause}
              {account_clause}
            GROUP BY provider
            ORDER BY cnt DESC
            LIMIT 5"#,
            ),
            None => format!(
                r#"SELECT '' AS provider, count() AS cnt
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              {provider_clause}
              {account_clause}
            GROUP BY provider
            LIMIT 0"#,
            ),
        };

        // --- 2. Accounts grid -----------------------------------------------
        // Two-stage aggregate: the inner query collapses (account, provider,
        // region, user) quadruples so we can (a) count principals/regions
        // exactly, and (b) pick the highest-volume principal via argMaxIf.
        // Accounts grid is keyed on `cloud_account_id`; without it there is no
        // account dimension to aggregate, so emit a zero-row query shape.
        // Provider / region / principal axes degrade to '' / 0 when unmapped
        // (build_accounts supplies the same defaults those JSON keys imply).
        let accounts_sql = match &cloud_account_id_col {
            Some(acct) => {
                // Inner: collapse to (account, provider, region, principal)
                // quadruples under STABLE ALIASES, then the outer aggregates over
                // those aliases. Re-referencing the raw expressions in the outer
                // scope is the NAN-1306 bug: under OCSF the principal is a
                // class-split `if("actor.user.name" != '', …, "user.name")`
                // expression and provider/region are dotted columns — none of
                // which the subquery exposes by their underlying names, so the
                // outer `uniqIf(<expr>, …)` threw `Code 47 UNKNOWN_IDENTIFIER`
                // (swallowed → empty accounts facet). Aliasing keeps both UDM
                // (bare columns) and OCSF (expressions) correct. Unmapped axes
                // degrade to '' (build_accounts implies the same defaults).
                let provider_inner = cloud_provider_col.as_deref().unwrap_or("''");
                let region_inner = cloud_region_col.as_deref().unwrap_or("''");
                let principal_inner = user_col.as_deref().unwrap_or("''");
                format!(
                    r#"SELECT
                account_id,
                lower(provider_raw) AS provider,
                sum(cnt) AS events,
                uniqIf(principal_v, principal_v != '') AS principals,
                uniqIf(region_v, region_v != '') AS regions,
                argMaxIf(principal_v, cnt, principal_v != '') AS top_principal
            FROM (
                SELECT {acct} AS account_id,
                       {provider_inner} AS provider_raw,
                       {region_inner} AS region_v,
                       {principal_inner} AS principal_v,
                       count() AS cnt
                FROM {logs_table}
                PREWHERE timestamp BETWEEN ? AND ?
                  AND {acct} != ''
                  {provider_clause}
                  {account_clause}
                GROUP BY account_id, provider_raw, region_v, principal_v
            )
            GROUP BY account_id, provider
            ORDER BY events DESC
            LIMIT {TOP_ACCOUNTS_LIMIT}"#,
                )
            }
            None => format!(
                r#"SELECT '' AS account_id, '' AS provider, count() AS events,
                toUInt64(0) AS principals, toUInt64(0) AS regions, '' AS top_principal
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              {provider_clause}
              {account_clause}
            GROUP BY account_id, provider
            LIMIT 0"#,
            ),
        };

        // --- 3. Top principals by event volume ------------------------------
        // Top principals are keyed on `user`; without it there is no principal
        // axis, so emit a zero-row shape. The cloud-context gate stays on
        // `cloud_provider` (UDM-byte-identical); if that column is unmapped the
        // gate is simply dropped rather than substituting a different axis.
        let principal_provider_gate = cloud_provider_col
            .as_ref()
            .map(|col| format!("AND {col} != ''"))
            .unwrap_or_default();
        let principals_sql = match &user_col {
            Some(user) => {
                let account_outer = match &cloud_account_id_col {
                    Some(col) => format!("{col} AS account_id"),
                    None => "'' AS account_id".to_string(),
                };
                let group_account = cloud_account_id_col
                    .as_ref()
                    .map(|col| format!(", {col}"))
                    .unwrap_or_default();
                format!(
                    r#"SELECT
                {user} AS principal,
                {account_outer},
                count() AS events,
                toString(max(timestamp)) AS last_seen
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND {user} != ''
              {principal_provider_gate}
              {provider_clause}
              {account_clause}
            GROUP BY principal{group_account}
            ORDER BY events DESC
            LIMIT {TOP_PRINCIPALS_LIMIT}"#,
                )
            }
            None => format!(
                r#"SELECT '' AS principal, '' AS account_id, count() AS events,
                '' AS last_seen
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              {provider_clause}
              {account_clause}
            GROUP BY principal, account_id
            LIMIT 0"#,
            ),
        };

        // --- 4. Cross-account timeline --------------------------------------
        // `toUnixTimestamp` always returns seconds regardless of DateTime64
        // precision — `toUInt64(DateTime64(6))` returns microseconds, which
        // silently blows up bucket math when precision differs.
        // Cross-account timeline is keyed on `cloud_account_id`; without it there
        // are no lanes to plot, so emit a zero-row shape.
        let timeline_sql = match &cloud_account_id_col {
            Some(acct) => format!(
                r#"SELECT
                {acct} AS account_id,
                toUInt32(intDiv(toUnixTimestamp(timestamp) - {timeline_unix_start}, {timeline_bucket_secs})) AS bucket,
                count() AS events
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND {acct} != ''
              {provider_clause}
              {account_clause}
            GROUP BY account_id, bucket
            HAVING bucket < {TIMELINE_BUCKETS}
            ORDER BY events DESC"#,
            ),
            None => format!(
                r#"SELECT '' AS account_id, toUInt32(0) AS bucket, count() AS events
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              {provider_clause}
              {account_clause}
            GROUP BY account_id, bucket
            LIMIT 0"#,
            ),
        };

        // --- 5. Service health ----------------------------------------------
        // Error rows are anything that looks like a failure at the action or
        // transport layer: non-success `status` or any HTTP 4xx/5xx.
        // Service health/trend are keyed on `cloud_service`; without it there are
        // no services to report, so emit zero-row shapes. The error count ORs
        // whichever of http_status_code / status the schema maps; `top_error`
        // needs `status`. Value literals stay UDM-exact.
        // TODO(OCSF): `status` value codes ('failure'/'denied'/'success') differ
        // from OCSF status_id enum strings; column mapped, values best-effort.
        let errors_expr = {
            let mut terms: Vec<String> = Vec::new();
            if let Some(col) = &http_status_col {
                terms.push(format!("{col} >= 400"));
            }
            if status_col.is_some() {
                // NAN-1248: status_cmp = raw col under UDM (byte-identical),
                // lower(status) under OCSF (matches 'Failure'); 'denied' has no
                // OCSF caption so the http >= 400 term above carries it.
                let s = Self::status_cmp_col(self.active_profile.as_ref());
                terms.push(format!("{s} = 'failure'"));
                terms.push(format!("{s} = 'denied'"));
            }
            if terms.is_empty() {
                "toUInt64(0)".to_string()
            } else {
                format!("countIf({})", terms.join(" OR "))
            }
        };
        let top_error_expr = match &status_col {
            // `col` is the raw display value (keep the OCSF caption verbatim);
            // `s` is the value-comparison form (lower() under OCSF). (NAN-1248)
            Some(col) => {
                let s = Self::status_cmp_col(self.active_profile.as_ref());
                format!("argMaxIf({col}, 1, {s} != '' AND {s} != 'success')")
            }
            None => "''".to_string(),
        };
        let service_health_sql = match &cloud_service_col {
            Some(svc) => format!(
                r#"SELECT
                lower({svc}) AS service,
                count() AS events,
                {errors_expr} AS errors,
                {top_error_expr} AS top_error
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND {svc} != ''
              {provider_clause}
              {account_clause}
            GROUP BY service
            ORDER BY events DESC
            LIMIT {TOP_SERVICES_LIMIT}"#,
            ),
            None => format!(
                r#"SELECT '' AS service, count() AS events, toUInt64(0) AS errors, '' AS top_error
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              {provider_clause}
              {account_clause}
            GROUP BY service
            LIMIT 0"#,
            ),
        };

        let service_trend_sql = match &cloud_service_col {
            Some(svc) => format!(
                r#"SELECT
                lower({svc}) AS service,
                toUInt32(intDiv(toUnixTimestamp(timestamp) - {timeline_unix_start}, {trend_bucket_secs})) AS bucket,
                count() AS events
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND {svc} != ''
              {provider_clause}
              {account_clause}
            GROUP BY service, bucket
            HAVING bucket < {SERVICE_TREND_BUCKETS}"#,
            ),
            None => format!(
                r#"SELECT '' AS service, toUInt32(0) AS bucket, count() AS events
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              {provider_clause}
              {account_clause}
            GROUP BY service, bucket
            LIMIT 0"#,
            ),
        };

        // --- 6. Top sensitive changes ---------------------------------------
        // Top sensitive changes need both `change_type` (the `kind` axis, which
        // build_changes treats as required) and `cloud_service` (scope). Without
        // either there is nothing to surface, so emit a zero-row shape. The
        // remaining axes (account/actor/action/target/target_type) degrade to ''
        // when unmapped — build_changes already tolerates missing JSON keys.
        // OCSF: `change_type` resolves to `activity_id` (UInt32 enum), NOT None,
        // so skip-on-None does not catch it. Comparing that int column to the
        // string IN-list ('permission_change'/'create'/'delete'/'update') is a
        // CH Code 53 that `fetch_rows` swallows into an empty panel — not a
        // silent under-match. The branch below therefore gates the IN-filter on
        // the UDM discriminator (`change_type == "change_type"`) and drops it
        // under OCSF; see the inline note there. The `kind` axis projection is
        // safe under both schemas (it's a value column, not a predicate).
        let changes_sql = match (&change_type_col, &cloud_service_col) {
            (Some(_change_type), Some(svc)) => {
                // Cluster B (NAN-1241): `change_type` is the literal UDM string
                // column under UDM but resolves to `activity_id` (UInt32 enum)
                // under OCSF. The string IN-filter below is only valid against
                // the UDM column — comparing the OCSF int column to string
                // literals is a CH Code 53 that `fetch_rows` swallows into an
                // empty panel. Gate the predicate on the UDM discriminator
                // (same one `change_type_equals` uses in cloud.rs): emit it ONLY
                // when the column resolves to the literal `change_type`,
                // otherwise drop the term entirely (no bind values are attached
                // to this fragment, so placeholder counts stay aligned). The
                // `{change_type} AS kind` projection stays either way — UNION-ALL
                // coerces the OCSF int value column to String fine.
                // TODO(OCSF/NAN-1248): value-vocabulary — under OCSF this filter
                // is dropped, so the panel is unfiltered by change kind until an
                // activity_id decode layer maps the OCSF generic activity enum.
                // NAN-1248: decode UDM change_type literals → OCSF activity_id
                // codes (create=1/update=3/delete=4; permission_change has no OCSF
                // code and is dropped under OCSF). UDM emits the verbatim string
                // IN-list (byte-identical); OCSF emits `activity_id IN (1, 3, 4)`.
                let change_kind_filter = format!(
                    "\n              AND {}",
                    Self::change_type_in(
                        self.active_profile.as_ref(),
                        &["permission_change", "create", "delete", "update"],
                    )
                );
                let account_outer = match &cloud_account_id_col {
                    Some(col) => format!("{col} AS account_id"),
                    None => "'' AS account_id".to_string(),
                };
                let actor_outer = match &user_col {
                    Some(col) => format!("{col} AS actor"),
                    None => "'' AS actor".to_string(),
                };
                let action_outer = match &action_col {
                    Some(col) => format!("{col} AS action"),
                    None => "'' AS action".to_string(),
                };
                let target_outer = match &resource_name_col {
                    Some(col) => format!("{col} AS target"),
                    None => "'' AS target".to_string(),
                };
                let target_type_outer = match &resource_type_col {
                    Some(col) => format!("{col} AS target_type"),
                    None => "'' AS target_type".to_string(),
                };
                // The post-aggregate filter requires at least one resource axis
                // to be present; drop it entirely when neither maps.
                let resource_filter = {
                    let mut terms: Vec<String> = Vec::new();
                    if let Some(col) = &resource_type_col {
                        terms.push(format!("{col} != ''"));
                    }
                    if let Some(col) = &resource_name_col {
                        terms.push(format!("{col} != ''"));
                    }
                    if terms.is_empty() {
                        String::new()
                    } else {
                        format!("WHERE {}", terms.join(" OR "))
                    }
                };
                // Project the DECODED change_type label (string) — under OCSF the
                // raw `activity_id` is a JSON *number*, which build_changes' as_str()
                // reads as empty and drops the row. change_type_label_expr yields
                // 'create'/'update'/'delete' (OCSF) / bare `change_type` (UDM,
                // byte-identical). (NAN-1248)
                let change_kind_label = Self::change_type_label_expr(self.active_profile.as_ref());
                format!(
                    r#"SELECT
                toString(timestamp) AS ts,
                lower({svc}) AS service,
                {change_kind_label} AS kind,
                {account_outer},
                {actor_outer},
                {action_outer},
                {target_outer},
                {target_type_outer}
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?{change_kind_filter}
              AND {svc} != ''
              {provider_clause}
              {account_clause}
            {resource_filter}
            ORDER BY timestamp DESC
            LIMIT {TOP_CHANGES_LIMIT}"#,
                )
            }
            _ => format!(
                r#"SELECT toString(timestamp) AS ts, '' AS service, '' AS kind,
                '' AS account_id, '' AS actor, '' AS action, '' AS target, '' AS target_type
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              {provider_clause}
              {account_clause}
            ORDER BY timestamp DESC
            LIMIT 0"#,
            ),
        };

        // --- 7. Anomaly feed (from signals) ---------------------------------
        // Inner-join to logs so we only surface signals whose matched event has
        // cloud context — otherwise every proxy / endpoint signal leaks into
        // the cloud view (caught during NAN-394 preview: squid_proxy signals
        // were polluting the feed).
        // Anomaly feed joins signals → logs and only keeps signals whose matched
        // event has cloud context. The cloud columns are read off the `l` alias,
        // so prefix the profile-resolved column with `l.`. account_id/service
        // degrade to '' when unmapped (build_anomalies tolerates empty keys);
        // the cloud-context WHERE ORs whichever of service/provider/account map.
        let anomaly_account_outer = match &cloud_account_id_col {
            Some(col) => format!("l.{col} AS account_id"),
            None => "'' AS account_id".to_string(),
        };
        let anomaly_service_outer = match &cloud_service_col {
            Some(col) => format!("lower(l.{col}) AS service"),
            None => "'' AS service".to_string(),
        };
        let anomaly_cloud_filter = {
            let terms: Vec<String> =
                [&cloud_service_col, &cloud_provider_col, &cloud_account_id_col]
                    .into_iter()
                    .filter_map(|c| c.as_ref().map(|col| format!("l.{col} != ''")))
                    .collect();
            if terms.is_empty() {
                // No cloud context to gate on — keep the feed empty rather than
                // surfacing every (non-cloud) signal.
                "WHERE 0".to_string()
            } else {
                format!("WHERE {}", terms.join(" OR "))
            }
        };
        let anomalies_sql = format!(
            r#"SELECT
                toString(s.id) AS id,
                toString(s.timestamp) AS ts,
                s.severity AS severity,
                s.rule_name AS rule_name,
                s.risk_entity AS principal,
                {anomaly_account_outer},
                {anomaly_service_outer},
                s.metadata AS metadata
            FROM {signals_table} AS s
            INNER JOIN {logs_table} AS l ON l.id = s.matched_log_id
            PREWHERE s.timestamp BETWEEN ? AND ?
            {anomaly_cloud_filter}
            ORDER BY s.timestamp DESC
            LIMIT {ANOMALIES_LIMIT}"#,
        );

        // --- Kick off queries in parallel -----------------------------------
        // Every subquery uses the same `fetch_rows` JSONEachRow path — the
        // typed `fetch_one::<Row>()` binary format is finicky about
        // LowCardinality/Nullable columns and fails silently, which we hit on
        // first preview: the header returned zeros while the other sections
        // populated cleanly. JSONEachRow sidesteps that.
        let header_fut = fetch_rows(
            extra_bind(
                clickhouse
                    .query(&header_sql)
                    .bind(start_str.clone())
                    .bind(end_str.clone()),
            ),
            "cloud_overview.header",
        );
        let provider_fut = fetch_rows(
            extra_bind(
                clickhouse
                    .query(&provider_sql)
                    .bind(start_str.clone())
                    .bind(end_str.clone()),
            ),
            "cloud_overview.providers",
        );
        let accounts_fut = fetch_rows(
            extra_bind(
                clickhouse
                    .query(&accounts_sql)
                    .bind(start_str.clone())
                    .bind(end_str.clone()),
            ),
            "cloud_overview.accounts",
        );
        let principals_fut = fetch_rows(
            extra_bind(
                clickhouse
                    .query(&principals_sql)
                    .bind(start_str.clone())
                    .bind(end_str.clone()),
            ),
            "cloud_overview.principals",
        );
        let timeline_fut = fetch_rows(
            extra_bind(
                clickhouse
                    .query(&timeline_sql)
                    .bind(start_str.clone())
                    .bind(end_str.clone()),
            ),
            "cloud_overview.timeline",
        );
        let service_health_fut = fetch_rows(
            extra_bind(
                clickhouse
                    .query(&service_health_sql)
                    .bind(start_str.clone())
                    .bind(end_str.clone()),
            ),
            "cloud_overview.service_health",
        );
        let service_trend_fut = fetch_rows(
            extra_bind(
                clickhouse
                    .query(&service_trend_sql)
                    .bind(start_str.clone())
                    .bind(end_str.clone()),
            ),
            "cloud_overview.service_trend",
        );
        let changes_fut = fetch_rows(
            extra_bind(
                clickhouse
                    .query(&changes_sql)
                    .bind(start_str.clone())
                    .bind(end_str.clone()),
            ),
            "cloud_overview.changes",
        );
        let anomalies_fut = fetch_rows(
            clickhouse
                .query(&anomalies_sql)
                .bind(start_str.clone())
                .bind(end_str.clone()),
            "cloud_overview.anomalies",
        );

        let (
            header_rows,
            provider_rows,
            account_rows,
            principal_rows,
            timeline_rows,
            service_health_rows,
            service_trend_rows,
            changes_rows,
            anomaly_rows,
        ) = tokio::join!(
            header_fut,
            provider_fut,
            accounts_fut,
            principals_fut,
            timeline_fut,
            service_health_fut,
            service_trend_fut,
            changes_fut,
            anomalies_fut,
        );

        // --- Risk fan-out (post-query, Postgres) ----------------------------
        // Pick the risk rollup window closest to the user's search span so
        // posture/band matches what they see below. The risk service only
        // supports three discrete windows (Last24Hours, Last7Days, All), so
        // anything over a week falls back to `All` — cumulative risk.
        let risk_provider = self.cloud_risk.as_ref();
        let risk_window = if span_secs <= 26 * 3_600 {
            RiskTimeWindow::Last24Hours
        } else if span_secs <= 7 * 24 * 3_600 {
            RiskTimeWindow::Last7Days
        } else {
            RiskTimeWindow::All
        };

        // --- Assemble ------------------------------------------------------
        let header_rows_len = header_rows.len();
        let header_row = header_rows
            .into_iter()
            .next()
            .map(|row| HeaderRow {
                events_total: row.get("events_total").and_then(|v| v.as_u64()).unwrap_or(0),
                events_failed: row
                    .get("events_failed")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                events_denied: row
                    .get("events_denied")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                accounts: row.get("accounts").and_then(|v| v.as_u64()).unwrap_or(0),
                principals: row.get("principals").and_then(|v| v.as_u64()).unwrap_or(0),
                regions: row.get("regions").and_then(|v| v.as_u64()).unwrap_or(0),
            })
            .unwrap_or_default();
        tracing::info!(
            events_total = header_row.events_total,
            accounts = header_row.accounts,
            principals = header_row.principals,
            header_rows_len,
            account_rows_len = account_rows.len(),
            principal_rows_len = principal_rows.len(),
            service_health_rows_len = service_health_rows.len(),
            anomaly_rows_len = anomaly_rows.len(),
            timeline_rows_len = timeline_rows.len(),
            changes_rows_len = changes_rows.len(),
            "Cloud overview assembled",
        );

        let providers: Vec<CloudOverviewProviderBreakdown> = provider_rows
            .iter()
            .filter_map(|row| {
                let id = row.get("provider")?.as_str()?.to_string();
                let events = row.get("cnt")?.as_u64()?;
                Some(CloudOverviewProviderBreakdown {
                    label: match id.as_str() {
                        "aws" => "AWS".into(),
                        "gcp" => "GCP".into(),
                        "azure" => "Azure".into(),
                        other => other.to_uppercase(),
                    },
                    id,
                    events,
                })
            })
            .collect();

        let accounts = build_accounts(&account_rows, risk_provider, risk_window).await;
        let top_account_label = accounts
            .first()
            .map(|a| a.name.clone())
            .filter(|n| !n.is_empty());
        let posture_score = accounts
            .iter()
            .take(5)
            .map(|a| a.risk)
            .max()
            .unwrap_or(0);
        let posture_reason = top_account_label
            .as_ref()
            .map(|name| format!("driven by {name}"));

        let risky_principals = build_risky_principals(
            &principal_rows,
            risk_provider,
            time_range,
            SERVICE_TREND_BUCKETS,
        )
        .await;

        let timeline = build_timeline(
            &timeline_rows,
            &accounts,
            TIMELINE_BUCKETS,
            &window_label(time_range),
        );

        let service_health =
            build_service_health(&service_health_rows, &service_trend_rows, SERVICE_TREND_BUCKETS);

        let anomalies = build_anomalies(&anomaly_rows);

        let changes = build_changes(&changes_rows, &accounts);

        let open_alerts = count_open_alerts(&anomalies);

        let header = CloudOverviewHeader {
            org: "nanosiem".into(),
            org_id: "".into(),
            window_label: window_label(time_range),
            accounts: header_row.accounts,
            principals: header_row.principals,
            regions: header_row.regions,
            providers,
            events_total: header_row.events_total,
            events_failed: header_row.events_failed,
            events_denied: header_row.events_denied,
            open_alerts,
            posture_score,
            posture_delta: 0,
            posture_reason,
        };

        Ok(CloudOverview {
            header,
            accounts,
            risky_principals,
            timeline,
            anomalies,
            service_health,
            changes,
        })
    }
}

// ============================================================================
// Header row (used only for typed fetch_one — simpler than JSON parsing)
// ============================================================================

#[derive(Debug, Default)]
struct HeaderRow {
    events_total: u64,
    events_failed: u64,
    events_denied: u64,
    accounts: u64,
    principals: u64,
    regions: u64,
}

// ============================================================================
// Subquery helper
// ============================================================================

async fn fetch_rows(
    query: clickhouse::query::Query,
    subquery: &'static str,
) -> Vec<serde_json::Value> {
    let mut cursor = match query.fetch_bytes("JSONEachRow") {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(subquery, error = %e, "Cloud overview subquery failed to start");
            return Vec::new();
        }
    };
    let mut bytes = Vec::new();
    loop {
        match cursor.next().await {
            Ok(Some(chunk)) => bytes.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(e) => {
                tracing::error!(subquery, error = %e, "Cloud overview subquery stream error");
                return Vec::new();
            }
        }
    }
    let text = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(subquery, error = %e, "Cloud overview subquery non-utf8 bytes");
            return Vec::new();
        }
    };
    text.lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect()
}

// ============================================================================
// Builders
// ============================================================================

async fn build_accounts(
    rows: &[serde_json::Value],
    risk_provider: &dyn CloudRiskProvider,
    risk_window: RiskTimeWindow,
) -> Vec<CloudOverviewAccount> {
    // First pass: extract account rows
    let mut accounts: Vec<CloudOverviewAccount> = rows
        .iter()
        .filter_map(|row| {
            let id = row.get("account_id")?.as_str()?.to_string();
            if id.is_empty() {
                return None;
            }
            let provider = row
                .get("provider")
                .and_then(|v| v.as_str())
                .unwrap_or("aws")
                .to_string();
            let events = row.get("events").and_then(|v| v.as_u64()).unwrap_or(0);
            let principals = row.get("principals").and_then(|v| v.as_u64()).unwrap_or(0);
            let regions = row.get("regions").and_then(|v| v.as_u64()).unwrap_or(0);
            let top_principal = row
                .get("top_principal")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            Some(CloudOverviewAccount {
                id: id.clone(),
                name: id.clone(),
                provider,
                events,
                risk: 0,
                band: "low".into(),
                delta: 0,
                alerts: 0,
                principals,
                regions,
                top_principal,
                top_principal_risk: 0,
            })
        })
        .collect();

    // Fan out to entity_risk_scores — one per account id. The store keys risk
    // by `cloud_account_id` for account-scoped findings.
    let ids: Vec<String> = accounts.iter().map(|a| a.id.clone()).collect();
    if ids.is_empty() {
        return accounts;
    }
    let risk_rows = risk_provider
        .risky_entities(
            risk_window,
            &RiskFilter {
                entity_type: Some("cloud_account".to_string()),
                min_score: None,
                risk_level: None,
                limit: Some(200),
                offset: None,
            },
        )
        .await;
    if let Ok(rows) = risk_rows {
        let by_id: HashMap<String, &EntityRiskSummary> =
            rows.iter().map(|r| (r.entity.clone(), r)).collect();
        for acc in accounts.iter_mut() {
            if let Some(r) = by_id.get(&acc.id) {
                acc.risk = r.risk_score.max(0) as u32;
            }
        }
    }

    // Also fan out by top principal (best-effort — an account with no direct
    // risk entry but whose top principal is risky still deserves elevated risk).
    for acc in accounts.iter_mut() {
        if acc.risk == 0 {
            if let Some(ref p) = acc.top_principal {
                if let Ok(Some(r)) = risk_provider.risk_for_entities(&[p.clone()]).await {
                    acc.top_principal_risk = r.risk_score.max(0) as u32;
                    acc.risk = (r.risk_score.max(0) as u32).min(100);
                }
            }
        }
    }

    for acc in accounts.iter_mut() {
        acc.band = band_for_score(acc.risk).into();
    }

    accounts
}

async fn build_risky_principals(
    rows: &[serde_json::Value],
    risk_provider: &dyn CloudRiskProvider,
    time_range: &TimeRange,
    sparkline_buckets: u32,
) -> Vec<CloudOverviewPrincipal> {
    let mut principals: Vec<CloudOverviewPrincipal> = rows
        .iter()
        .filter_map(|row| {
            let id = row.get("principal")?.as_str()?.to_string();
            if id.is_empty() {
                return None;
            }
            let account = row
                .get("account_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let events = row.get("events").and_then(|v| v.as_u64()).unwrap_or(0);
            let last_seen = row
                .get("last_seen")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            Some(CloudOverviewPrincipal {
                id,
                principal_type: "iam_user".into(),
                account,
                risk: 0,
                band: "low".into(),
                delta: 0,
                events_24h: events,
                reasons: Vec::new(),
                last_seen,
                sparkline: vec![0u64; sparkline_buckets as usize],
            })
        })
        .collect();

    // Fan risk out per principal. `get_risk_for_entities` picks the highest
    // score across the alias list, so we pass each principal's id in its own
    // call — mirrors the asset dossier pattern from NAN-393.
    for p in principals.iter_mut() {
        if let Ok(Some(r)) = risk_provider
            .risk_for_entities(&[p.id.clone()])
            .await
        {
            p.risk = (r.risk_score.max(0) as u32).min(100);
            p.band = band_for_score(p.risk).into();
            if let Some(rule) = r.last_rule_name.clone() {
                p.reasons.push(rule);
            }
        } else {
            p.band = "low".into();
        }
    }

    // Re-sort by risk descending after we've attached scores
    principals.sort_by(|a, b| b.risk.cmp(&a.risk).then(b.events_24h.cmp(&a.events_24h)));

    // Sparkline derivation is a follow-up — leave zeros for now; the frontend
    // renders a flat line cleanly. Backend can stitch per-principal histogram
    // via the existing histogram helper once we've sized the extra query cost.
    let _ = time_range;

    principals
}

fn build_timeline(
    rows: &[serde_json::Value],
    accounts: &[CloudOverviewAccount],
    buckets: u32,
    label: &str,
) -> CloudOverviewTimeline {
    let lanes: Vec<CloudOverviewTimelineLane> = accounts
        .iter()
        .take(6)
        .enumerate()
        .map(|(i, a)| CloudOverviewTimelineLane {
            id: a.id.clone(),
            label: a.name.clone(),
            accent: lane_accent(i).into(),
        })
        .collect();
    let lane_ids: std::collections::HashSet<String> =
        lanes.iter().map(|l| l.id.clone()).collect();

    // Normalize bucket weights to {1, 2, 3} per lane so the heatmap reads
    // consistently regardless of absolute event volume.
    let mut per_lane_max: BTreeMap<String, u64> = BTreeMap::new();
    for row in rows {
        let lane_id = row
            .get("account_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if lane_id.is_empty() || !lane_ids.contains(lane_id) {
            continue;
        }
        let events = row.get("events").and_then(|v| v.as_u64()).unwrap_or(0);
        per_lane_max
            .entry(lane_id.to_string())
            .and_modify(|m| {
                if events > *m {
                    *m = events
                }
            })
            .or_insert(events);
    }

    let points: Vec<serde_json::Value> = rows
        .iter()
        .filter_map(|row| {
            let lane_id = row.get("account_id")?.as_str()?.to_string();
            if !lane_ids.contains(&lane_id) {
                return None;
            }
            let bucket = row.get("bucket")?.as_u64()? as u32;
            if bucket >= buckets {
                return None;
            }
            let events = row.get("events").and_then(|v| v.as_u64()).unwrap_or(0);
            let max = per_lane_max.get(&lane_id).copied().unwrap_or(1).max(1);
            let weight = if events == 0 {
                0
            } else if events * 3 <= max {
                1
            } else if events * 3 <= 2 * max {
                2
            } else {
                3
            };
            if weight == 0 {
                return None;
            }
            Some(serde_json::json!([bucket, lane_id, weight]))
        })
        .collect();

    CloudOverviewTimeline {
        label: format!("Accounts · {label}"),
        buckets,
        lanes,
        points,
        markers: Vec::new(),
    }
}

fn build_service_health(
    rows: &[serde_json::Value],
    trend_rows: &[serde_json::Value],
    trend_buckets: u32,
) -> Vec<CloudOverviewServiceHealth> {
    // Index trend rows by service
    let mut trends: HashMap<String, Vec<u64>> = HashMap::new();
    for row in trend_rows {
        let service = row
            .get("service")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if service.is_empty() {
            continue;
        }
        let bucket = row.get("bucket").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        if bucket >= trend_buckets as usize {
            continue;
        }
        let events = row.get("events").and_then(|v| v.as_u64()).unwrap_or(0);
        let arr = trends
            .entry(service)
            .or_insert_with(|| vec![0u64; trend_buckets as usize]);
        arr[bucket] = events;
    }

    rows.iter()
        .filter_map(|row| {
            let id = row.get("service")?.as_str()?.to_string();
            if id.is_empty() {
                return None;
            }
            let events = row.get("events").and_then(|v| v.as_u64()).unwrap_or(0);
            let errors = row.get("errors").and_then(|v| v.as_u64()).unwrap_or(0);
            let error_rate = if events > 0 {
                (errors as f64) / (events as f64)
            } else {
                0.0
            };
            let status = if error_rate >= 0.05 {
                "bad"
            } else if error_rate >= 0.01 {
                "warn"
            } else {
                "ok"
            };
            let top_error = row
                .get("top_error")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let trend = trends.remove(&id).unwrap_or_else(|| vec![0u64; trend_buckets as usize]);
            Some(CloudOverviewServiceHealth {
                label: id.to_uppercase(),
                accent: service_accent(&id).into(),
                id,
                events,
                errors,
                error_rate,
                delta: 0.0,
                status: status.into(),
                top_error,
                trend,
            })
        })
        .collect()
}

fn build_anomalies(rows: &[serde_json::Value]) -> Vec<CloudOverviewAnomaly> {
    rows.iter()
        .filter_map(|row| {
            let id = row
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                return None;
            }
            let severity = row
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("medium")
                .to_lowercase();
            let severity = match severity.as_str() {
                "critical" | "high" | "medium" | "low" => severity,
                _ => "medium".into(),
            };
            let title = row
                .get("rule_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            // `signals.metadata` is a JSON string that defaults to `'{}'` for
            // rules that don't emit structured context. Extract a human-
            // readable description when one is present; otherwise leave the
            // detail empty so the frontend skips that row rather than
            // rendering a literal `{}`.
            let detail = row
                .get("metadata")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty() && *s != "{}")
                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
                .and_then(|meta| {
                    for key in ["description", "detail", "message", "summary", "reason"] {
                        if let Some(v) = meta.get(key).and_then(|v| v.as_str()) {
                            if !v.is_empty() {
                                return Some(v.to_string());
                            }
                        }
                    }
                    None
                })
                .unwrap_or_default();
            let at_raw = row
                .get("ts")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let at = format_hhmm(at_raw);
            let principal = row
                .get("principal")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let account = row
                .get("account_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let service = row
                .get("service")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            // Kind defaults to the service name when available — rough but
            // useful as a category label until rules emit typed `kind` in
            // metadata. Falls back to "detection" for non-cloud signals, which
            // we shouldn't see after the WHERE filter above.
            let kind = service.clone().unwrap_or_else(|| "detection".into());
            Some(CloudOverviewAnomaly {
                id,
                at,
                severity,
                kind,
                title,
                detail,
                principal,
                account,
                service,
            })
        })
        .collect()
}

fn build_changes(
    rows: &[serde_json::Value],
    accounts: &[CloudOverviewAccount],
) -> Vec<CloudOverviewChange> {
    let account_name: HashMap<String, String> =
        accounts.iter().map(|a| (a.id.clone(), a.name.clone())).collect();
    rows.iter()
        .filter_map(|row| {
            let ts = row.get("ts").and_then(|v| v.as_str()).unwrap_or("");
            let at = format_hhmm(ts);
            let kind = row
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if kind.is_empty() {
                return None;
            }
            let account_id = row
                .get("account_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let account_display = account_name
                .get(&account_id)
                .cloned()
                .unwrap_or_else(|| account_id.clone());
            let actor = row
                .get("actor")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let action = row
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let target = row
                .get("target")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .or_else(|| {
                    row.get("target_type")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_default();
            let severity = match kind.as_str() {
                "permission_change" | "create" | "delete" => "critical",
                _ => "medium",
            };
            let detail = row
                .get("target_type")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            Some(CloudOverviewChange {
                at,
                kind,
                severity: severity.into(),
                account: account_display,
                actor,
                action,
                target,
                detail,
            })
        })
        .collect()
}

fn count_open_alerts(anomalies: &[CloudOverviewAnomaly]) -> CloudOverviewOpenAlerts {
    let mut out = CloudOverviewOpenAlerts::default();
    for a in anomalies {
        match a.severity.as_str() {
            "critical" => out.critical += 1,
            "high" => out.high += 1,
            "medium" => out.medium += 1,
            _ => {}
        }
    }
    out
}

fn format_hhmm(ts: &str) -> String {
    // ClickHouse emits "2026-04-20 17:59:35.000000". We want "HH:MM".
    if ts.len() >= 16 {
        ts[11..16].to_string()
    } else {
        ts.to_string()
    }
}
