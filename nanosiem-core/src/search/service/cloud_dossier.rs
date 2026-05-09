// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cloud principal dossier — single aggregate for `| cloud principal=X` (NAN-395).
//!
//! Structurally analogous to `asset_dossier`: identity + facets + assume-role
//! chain + timeline lanes + regions + auth posture + top actions + top
//! resources + error rate + event stream, all in one round-trip against
//! ClickHouse. Risk score comes from the Postgres risk service.
//!
//! Learning re-used from NAN-394: every subquery goes through the shared
//! `fetch_rows` JSONEachRow helper. The typed `fetch_one::<Row>()` binary
//! format silently fails on multi-column LowCardinality SELECTs.

use super::SearchService;
use crate::query::TimeRange;
use crate::risk::{EntityRiskSummary, RiskTimeWindow};
use crate::search::SearchError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

// ============================================================================
// Request-side facet filters — mirror the chip toggles on the dossier UI.
// Empty vectors mean "no filter"; populated ones are AND'd into every
// subquery's PREWHERE so all sections narrow in lockstep. Not part of the
// response — serde/utoipa derives are not required.
// ============================================================================

#[derive(Debug, Default, Clone)]
pub struct CloudDossierFacetFilters {
    pub services: Vec<String>,
    pub regions: Vec<String>,
    pub accounts: Vec<String>,
    pub resource_types: Vec<String>,
    pub change_types: Vec<String>,
}

impl CloudDossierFacetFilters {
    fn is_empty(&self) -> bool {
        self.services.is_empty()
            && self.regions.is_empty()
            && self.accounts.is_empty()
            && self.resource_types.is_empty()
            && self.change_types.is_empty()
    }
}

/// Build an `AND (...)` clause + bind values from the facet filters. Returns
/// `("", vec![])` when every filter is empty so callers can inline it safely.
fn build_facet_clause(filters: &CloudDossierFacetFilters) -> (String, Vec<String>) {
    if filters.is_empty() {
        return (String::new(), Vec::new());
    }
    let mut clauses = Vec::new();
    let mut binds = Vec::new();

    let mut push = |column: &str, values: &[String], lower: bool| {
        if values.is_empty() {
            return;
        }
        let placeholders = vec!["?"; values.len()].join(",");
        if lower {
            clauses.push(format!("lower({column}) IN ({placeholders})"));
            for v in values {
                binds.push(v.to_lowercase());
            }
        } else {
            clauses.push(format!("{column} IN ({placeholders})"));
            for v in values {
                binds.push(v.clone());
            }
        }
    };

    push("cloud_service", &filters.services, true);
    push("cloud_region", &filters.regions, false);
    push("cloud_account_id", &filters.accounts, false);
    push("resource_type", &filters.resource_types, false);
    push("change_type", &filters.change_types, false);

    if clauses.is_empty() {
        return (String::new(), Vec::new());
    }
    (format!(" AND ({})", clauses.join(" AND ")), binds)
}

// ============================================================================
// Response types — mirror nanosiem-web/src/lib/api/types.ts CloudDossier*
// ============================================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossier {
    pub identity: CloudDossierIdentity,
    pub risk: CloudDossierRisk,
    pub facets: CloudDossierFacets,
    pub assume_chain: CloudDossierAssumeChain,
    pub timeline: CloudDossierTimeline,
    pub regions: Vec<CloudDossierRegion>,
    pub top_actions: Vec<CloudDossierActionRow>,
    pub top_resources: Vec<CloudDossierResource>,
    pub auth_posture: CloudDossierAuthPosture,
    pub error_rate: CloudDossierErrorRate,
    pub stream: Vec<CloudDossierStreamEvent>,
    pub window_label: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierUserAgent {
    pub ua: String,
    pub kind: String,
    pub count: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierIp {
    pub ip: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub event_count: u64,
    pub geo: Option<String>,
    pub asn: Option<String>,
    pub anomaly: Option<String>,
    pub risk: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierIdentity {
    pub id: String,
    pub principal_type: String,
    pub arn: Option<String>,
    pub account: Option<String>,
    pub account_name: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub created_by: Option<String>,
    pub key_age_days: Option<u32>,
    pub mfa: Option<bool>,
    pub mfa_policy_required: bool,
    pub console: bool,
    pub api_only: bool,
    pub assumed_roles: Vec<String>,
    pub groups: Vec<String>,
    pub tags: Vec<String>,
    pub user_agents: Vec<CloudDossierUserAgent>,
    pub ips: Vec<CloudDossierIp>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierRiskFactor {
    pub w: u32,
    pub label: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierRisk {
    pub score: u32,
    pub band: String,
    pub delta: i32,
    pub factors: Vec<CloudDossierRiskFactor>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierFacetItem {
    pub name: String,
    pub count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub anomaly: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierFacets {
    pub provider: Vec<CloudDossierFacetItem>,
    pub service: Vec<CloudDossierFacetItem>,
    pub region: Vec<CloudDossierFacetItem>,
    pub account: Vec<CloudDossierFacetItem>,
    pub resource_type: Vec<CloudDossierFacetItem>,
    pub change_type: Vec<CloudDossierFacetItem>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierAssumeHop {
    pub at: String,
    pub session_name: String,
    pub via: String,
    pub to_label: String,
    pub to_account: Option<String>,
    pub permissions: Vec<String>,
    pub calls: u64,
    pub note: Option<String>,
    pub sensitive: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierKeyAction {
    pub at: String,
    pub role: String,
    pub action: String,
    pub target: String,
    pub severity: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierAssumeChain {
    pub origin_label: String,
    pub origin_account: Option<String>,
    pub origin_ip: Option<String>,
    pub origin_first_at: Option<String>,
    pub origin_note: Option<String>,
    pub hops: Vec<CloudDossierAssumeHop>,
    pub key_actions: Vec<CloudDossierKeyAction>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierTimelineLane {
    pub id: String,
    pub label: String,
    pub accent: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierTimelineMarker {
    pub at: u32,
    pub label: String,
    pub severity: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierTimeline {
    pub label: String,
    pub buckets: u32,
    pub lanes: Vec<CloudDossierTimelineLane>,
    pub points: Vec<serde_json::Value>,
    pub markers: Vec<CloudDossierTimelineMarker>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierRegion {
    pub id: String,
    pub label: Option<String>,
    pub count: u64,
    pub anomaly: Option<String>,
    pub new_for_principal: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierActionRow {
    pub name: String,
    pub count: u64,
    pub errors: u64,
    pub service: String,
    pub principal: Option<String>,
    pub sensitive: bool,
    pub anomaly: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierResource {
    pub arn: String,
    pub r#type: String,
    pub account: String,
    pub changes: u64,
    pub last_at: String,
    pub severity: String,
    pub spark: Vec<u64>,
    pub touched: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierPosturePrincipal {
    pub name: String,
    pub mfa: Option<bool>,
    pub privileged: bool,
    pub key_age_days: Option<u32>,
    pub last_call: Option<String>,
    pub privileged_calls: u64,
    pub anomaly: bool,
    pub is_role: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierAuthPosture {
    pub total_principals: u64,
    pub with_mfa: u64,
    pub without_mfa: u64,
    pub privileged_without_mfa: u64,
    pub privileged_calls_without_mfa: u64,
    pub console_logins: u64,
    pub console_logins_without_mfa: u64,
    pub api_key_only_principals: u64,
    pub oldest_key_days: u32,
    pub principals: Vec<CloudDossierPosturePrincipal>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierErrorCode {
    pub code: String,
    pub count: u64,
    pub pct: f64,
    pub severity: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierErrorRate {
    pub events_total: u64,
    pub events_allowed: u64,
    pub events_failed: u64,
    pub events_denied: u64,
    pub top_errors: Vec<CloudDossierErrorCode>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierStreamEvent {
    pub id: String,
    pub ts: String,
    pub r#type: String,
    pub event_name: String,
    pub service: String,
    pub user: String,
    pub account: String,
    pub region: String,
    pub source_ip: String,
    pub resource: String,
    pub error_code: Option<String>,
    pub summary: serde_json::Value,
    pub detail: serde_json::Value,
    pub interesting: bool,
}

// ============================================================================
// Constants
// ============================================================================

/// Timeline bucket count — matches the mockup (45 buckets ≈ 5-min slots across
/// a typical 3h75m incident window). For longer search spans we keep the
/// bucket count constant and let each bucket cover a wider slice.
const TIMELINE_BUCKETS: u32 = 45;

/// How many distinct service lanes to render in the timeline. The
/// mockup shows 5 — matches the primary cloud services involved in an
/// investigation (STS, IAM, Secrets, S3, "everything else"). We pick the top
/// 5 services for the principal at query time.
const TIMELINE_LANES: usize = 5;

const TOP_ACTIONS_LIMIT: usize = 16;
const TOP_RESOURCES_LIMIT: usize = 8;
const STREAM_LIMIT: usize = 200;
const ERROR_CODES_LIMIT: usize = 5;
const POSTURE_PRINCIPALS_LIMIT: usize = 12;

/// Actions we consider "sensitive" — shown with a chip in the UI. List is
/// conservative and expands on demand.
const SENSITIVE_ACTIONS: &[&str] = &[
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:CreateUser",
    "iam:PutRolePolicy",
    "iam:UpdateAccessKey",
    "iam:DeleteUser",
    "sts:AssumeRole",
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue",
    "kms:ScheduleKeyDeletion",
    "kms:Decrypt",
    "s3:PutBucketPolicy",
    "s3:DeleteBucket",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:TerminateInstances",
    "cloudformation:UpdateStack",
    "cloudformation:DeleteStack",
];

fn is_sensitive(action: &str) -> bool {
    SENSITIVE_ACTIONS
        .iter()
        .any(|a| a.eq_ignore_ascii_case(action))
}

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

fn lane_accent(service: &str) -> String {
    service_accent(service).to_string()
}

fn window_label(time_range: &TimeRange) -> String {
    let span_secs = (time_range.end - time_range.start).num_seconds().max(0);
    if span_secs <= 3_600 {
        "last 1h".into()
    } else if span_secs <= 6 * 3_600 {
        format!("last {}h", span_secs / 3_600)
    } else if span_secs <= 26 * 3_600 {
        "last 24h".into()
    } else {
        format!("last {}d", (span_secs / 86_400).max(1))
    }
}

fn format_hhmm(ts: &str) -> String {
    if ts.len() >= 16 {
        ts[11..16].to_string()
    } else {
        ts.to_string()
    }
}

// Classify a CloudTrail event into AUTH / READ / WRITE / PERM so the stream
// can colour-code it. Mirrors the cloudTypeMeta map in cloud-stream.jsx.
fn classify_event_type(service: &str, action: &str, change_type: &str) -> &'static str {
    let action_l = action.to_ascii_lowercase();
    if service == "sts"
        || service == "signin"
        || action_l.starts_with("assumerole")
        || action_l.starts_with("consolelogin")
        || action_l.starts_with("getcalleridentity")
    {
        return "AUTH";
    }
    if change_type == "permission_change"
        || action_l.contains("attach")
        || action_l.contains("putpolicy")
        || action_l.contains("createaccesskey")
        || action_l.contains("putrolepolicy")
    {
        return "PERM";
    }
    if change_type == "create" || change_type == "delete" || change_type == "update" {
        return "WRITE";
    }
    if action_l.starts_with("get")
        || action_l.starts_with("list")
        || action_l.starts_with("describe")
        || action_l.starts_with("head")
    {
        return "READ";
    }
    "WRITE"
}

fn classify_ua(ua: &str) -> &'static str {
    let u = ua.to_ascii_lowercase();
    if u.contains("terraform") {
        "terraform"
    } else if u.contains("aws-cli") || u.contains("aws_cli") {
        "cli"
    } else if u.contains("boto") || u.contains("aws-sdk") || u.contains("aws_sdk") {
        "sdk"
    } else if u.contains("console.amazonaws") || u.contains("signin.aws") {
        "console"
    } else if u.contains("mozilla") || u.contains("chrome") || u.contains("safari") {
        "browser"
    } else {
        "other"
    }
}

// ============================================================================
// Public entry
// ============================================================================

impl SearchService {
    pub async fn query_cloud_dossier(
        &self,
        principal: &str,
        account_filter: Option<&str>,
        provider_filter: Option<&str>,
        facet_filters: &CloudDossierFacetFilters,
        time_range: &TimeRange,
    ) -> Result<CloudDossier, SearchError> {
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok(CloudDossier::default()),
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

        let logs_table = self.table_names.read("logs");

        // `principal_clause` is always present (it's required) — we match on
        // the `user` UDM column, which all cloud parsers populate with the
        // IAM user or role session id. Some sources also set src_user; fall
        // back via an OR for robustness.
        let principal_bind = principal.to_string();
        let provider_clause = provider_filter
            .filter(|p| !p.is_empty())
            .map(|_| " AND lower(cloud_provider) = lower(?)")
            .unwrap_or("");
        let account_clause = account_filter
            .filter(|a| !a.is_empty())
            .map(|_| " AND cloud_account_id = ?")
            .unwrap_or("");
        let (facet_clause, facet_binds) = build_facet_clause(facet_filters);

        // Bind order must match the rendered SQL placeholder order, which
        // comes out of `{provider_clause}{facet_clause}\n{account_clause}`:
        //   provider, facet_binds..., account.
        let extra_bind = |q: clickhouse::query::Query| -> clickhouse::query::Query {
            let mut q = q;
            if let Some(p) = provider_filter.filter(|p| !p.is_empty()) {
                q = q.bind(p.to_string());
            }
            for v in &facet_binds {
                q = q.bind(v.clone());
            }
            if let Some(a) = account_filter.filter(|a| !a.is_empty()) {
                q = q.bind(a.to_string());
            }
            q
        };

        // Every query binds: start, end, principal, [provider], [account]
        // in that order. Identity clause matches either exact `user` or the
        // trailing component of a `role/session` compound user string.
        let identity_match = "(user = ? OR splitByChar('/', user)[1] = ?)";

        // --- 1. Identity query ---------------------------------------------
        let identity_sql = format!(
            r#"SELECT
                count() AS events_total,
                argMaxIf(cloud_account_id, timestamp, cloud_account_id != '') AS account,
                argMaxIf(user, timestamp, user != '') AS last_user,
                toString(min(timestamp)) AS first_seen,
                toString(max(timestamp)) AS last_seen,
                groupUniqArrayIf(cloud_region, cloud_region != '') AS regions,
                groupUniqArrayIf(src_ip, src_ip != '') AS ips,
                countIf(mfa_used = 1) AS mfa_on,
                countIf(mfa_used = 0 AND user != '') AS mfa_off,
                countIf(lower(cloud_service) = 'signin') AS console_logins
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND {identity_match}
              {provider_clause}{facet_clause}
              {account_clause}"#,
        );

        // --- 2. User-agent breakdown ---------------------------------------
        let ua_sql = format!(
            r#"SELECT http_user_agent AS ua, count() AS cnt
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND {identity_match}
              AND http_user_agent != ''
              {provider_clause}{facet_clause}
              {account_clause}
            GROUP BY ua
            ORDER BY cnt DESC
            LIMIT 8"#,
        );

        // --- 3. IP breakdown -----------------------------------------------
        let ip_sql = format!(
            r#"SELECT
                src_ip AS ip,
                count() AS cnt,
                toString(min(timestamp)) AS first_at,
                toString(max(timestamp)) AS last_at,
                anyIf(enriched_src_country, enriched_src_country != '') AS country,
                anyIf(enriched_src_as_name, enriched_src_as_name != '') AS asn
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND {identity_match}
              AND src_ip != ''
              {provider_clause}{facet_clause}
              {account_clause}
            GROUP BY ip
            ORDER BY cnt DESC
            LIMIT 8"#,
        );

        // --- 4. Facets (6 dims UNION ALL) ----------------------------------
        let facets_sql = format!(
            r#"SELECT * FROM (
                SELECT 'provider' AS dim, lower(cloud_provider) AS value, count() AS cnt FROM {logs_table}
                PREWHERE timestamp BETWEEN ? AND ? AND {identity_match} AND cloud_provider != ''
                  {provider_clause}{facet_clause} {account_clause}
                GROUP BY value ORDER BY cnt DESC LIMIT 5
            ) UNION ALL (
                SELECT 'service' AS dim, lower(cloud_service) AS value, count() AS cnt FROM {logs_table}
                PREWHERE timestamp BETWEEN ? AND ? AND {identity_match} AND cloud_service != ''
                  {provider_clause}{facet_clause} {account_clause}
                GROUP BY value ORDER BY cnt DESC LIMIT 12
            ) UNION ALL (
                SELECT 'region' AS dim, cloud_region AS value, count() AS cnt FROM {logs_table}
                PREWHERE timestamp BETWEEN ? AND ? AND {identity_match} AND cloud_region != ''
                  {provider_clause}{facet_clause} {account_clause}
                GROUP BY value ORDER BY cnt DESC LIMIT 12
            ) UNION ALL (
                SELECT 'account' AS dim, cloud_account_id AS value, count() AS cnt FROM {logs_table}
                PREWHERE timestamp BETWEEN ? AND ? AND {identity_match} AND cloud_account_id != ''
                  {provider_clause}{facet_clause} {account_clause}
                GROUP BY value ORDER BY cnt DESC LIMIT 6
            ) UNION ALL (
                SELECT 'resource_type' AS dim, resource_type AS value, count() AS cnt FROM {logs_table}
                PREWHERE timestamp BETWEEN ? AND ? AND {identity_match} AND resource_type != ''
                  {provider_clause}{facet_clause} {account_clause}
                GROUP BY value ORDER BY cnt DESC LIMIT 12
            ) UNION ALL (
                SELECT 'change_type' AS dim, change_type AS value, count() AS cnt FROM {logs_table}
                PREWHERE timestamp BETWEEN ? AND ? AND {identity_match} AND change_type != ''
                  {provider_clause}{facet_clause} {account_clause}
                GROUP BY value ORDER BY cnt DESC LIMIT 8
            )"#,
        );

        // --- 5. AssumeRole chain --------------------------------------------
        // Rows where the principal is the one CALLING AssumeRole. We return
        // one row per distinct target role / session to let the frontend
        // assemble the hop chain. The role that was ASSUMED next becomes a
        // row here itself (its `user` is "<role>/<session>" which our
        // `splitByChar('/', user)[1] = principal` pattern catches).
        let chain_sql = format!(
            r#"SELECT
                toString(min(timestamp)) AS first_at,
                resource_name AS to_label,
                cloud_account_id AS to_account,
                count() AS calls,
                anyIf(src_ip, src_ip != '') AS ip
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND lower(cloud_service) = 'sts'
              AND lower(action) = 'assumerole'
              AND {identity_match}
              {provider_clause}{facet_clause}
              {account_clause}
            GROUP BY to_label, to_account
            HAVING to_label != ''
            ORDER BY first_at ASC
            LIMIT 4"#,
        );

        // --- 6. Key actions along the chain --------------------------------
        // Sensitive writes the principal performed (directly or via an
        // assumed role session). Severity is derived server-side from the
        // action name.
        let key_actions_sql = format!(
            r#"SELECT
                toString(min(timestamp)) AS at,
                splitByChar('/', user)[1] AS role,
                action AS action,
                anyIf(resource_name, resource_name != '') AS target,
                lower(cloud_service) AS service,
                change_type AS change_type,
                count() AS cnt
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND {identity_match}
              AND (
                action IN ('CreateAccessKey','AttachUserPolicy','CreateUser','PutRolePolicy','UpdateAccessKey',
                           'DeleteUser','PutBucketPolicy','DeleteBucket','AuthorizeSecurityGroupIngress',
                           'GetSecretValue','PutSecretValue','ScheduleKeyDeletion','TerminateInstances',
                           'UpdateStack','DeleteStack')
                OR change_type = 'permission_change'
              )
              {provider_clause}{facet_clause}
              {account_clause}
            GROUP BY role, action, service, change_type
            ORDER BY at DESC
            LIMIT 12"#,
        );

        // --- 7. Timeline lanes ----------------------------------------------
        let timeline_sql = format!(
            r#"SELECT
                lower(cloud_service) AS service,
                toUInt32(intDiv(toUnixTimestamp(timestamp) - {timeline_unix_start}, {timeline_bucket_secs})) AS bucket,
                count() AS events
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND {identity_match}
              AND cloud_service != ''
              {provider_clause}{facet_clause}
              {account_clause}
            GROUP BY service, bucket
            HAVING bucket < {TIMELINE_BUCKETS}"#,
        );

        // --- 8. Top actions -------------------------------------------------
        let actions_sql = format!(
            r#"SELECT
                action AS name,
                lower(cloud_service) AS service,
                splitByChar('/', user)[1] AS principal_role,
                count() AS cnt,
                countIf(status = 'failure' OR status = 'error' OR http_status_code >= 400) AS errs
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND {identity_match}
              AND action != ''
              {provider_clause}{facet_clause}
              {account_clause}
            GROUP BY name, service, principal_role
            ORDER BY cnt DESC
            LIMIT {TOP_ACTIONS_LIMIT}"#,
        );

        // --- 9. Top resources -----------------------------------------------
        let resources_sql = format!(
            r#"SELECT
                coalesce(nullIf(resource_id, ''), resource_name) AS arn,
                any(resource_type) AS resource_type,
                any(cloud_account_id) AS account,
                count() AS changes,
                toString(max(timestamp)) AS last_at,
                arraySlice(groupUniqArrayIf(action, action != ''), 1, 6) AS touched
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND {identity_match}
              AND (resource_id != '' OR resource_name != '')
              {provider_clause}{facet_clause}
              {account_clause}
            GROUP BY arn
            ORDER BY changes DESC
            LIMIT {TOP_RESOURCES_LIMIT}"#,
        );

        // --- 10. Error rate -------------------------------------------------
        let error_rate_sql = format!(
            r#"SELECT
                count() AS total,
                countIf(status = 'failure' OR status = 'error') AS failed,
                countIf(status = 'denied' OR http_status_code = 403) AS denied
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND {identity_match}
              {provider_clause}{facet_clause}
              {account_clause}"#,
        );

        let error_codes_sql = format!(
            r#"SELECT status AS code, count() AS cnt
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND {identity_match}
              AND status != '' AND status != 'success'
              {provider_clause}{facet_clause}
              {account_clause}
            GROUP BY code
            ORDER BY cnt DESC
            LIMIT {ERROR_CODES_LIMIT}"#,
        );

        // --- 11. Auth posture (account-scoped; lists all principals in the
        //     principal's primary account so the dossier shows fleet context)
        let posture_sql = format!(
            r#"SELECT
                user AS name,
                maxIf(mfa_used, user != '') > 0 AS has_mfa,
                anyIf(mfa_used, mfa_used = 0) AS seen_without_mfa,
                count() AS calls,
                countIf(change_type = 'permission_change' OR action IN
                    ('CreateAccessKey','AttachUserPolicy','PutRolePolicy','PutBucketPolicy')) AS priv_calls,
                toString(max(timestamp)) AS last_call,
                startsWith(user, 'arn:aws:sts::') OR positionCaseInsensitive(user, 'Role') > 0 AS is_role
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND user != ''
              {provider_clause}{facet_clause}
              {account_clause}
            GROUP BY name
            ORDER BY calls DESC
            LIMIT {POSTURE_PRINCIPALS_LIMIT}"#,
        );

        // --- 12. Event stream ------------------------------------------------
        let stream_sql = format!(
            r#"SELECT
                toString(id) AS id,
                toString(timestamp) AS ts,
                action AS event_name,
                lower(cloud_service) AS service,
                user AS user,
                cloud_account_id AS account,
                cloud_region AS region,
                src_ip AS source_ip,
                coalesce(nullIf(resource_name, ''), resource_id) AS resource,
                status AS status,
                http_status_code AS http_status_code,
                change_type AS change_type,
                message AS message
            FROM {logs_table}
            PREWHERE timestamp BETWEEN ? AND ?
              AND {identity_match}
              {provider_clause}{facet_clause}
              {account_clause}
            ORDER BY timestamp DESC
            LIMIT {STREAM_LIMIT}"#,
        );

        // --- Kick off all 12 queries in parallel ----------------------------
        let bind_principal_query = |sql: &str| -> clickhouse::query::Query {
            extra_bind(
                clickhouse
                    .query(sql)
                    .bind(start_str.clone())
                    .bind(end_str.clone())
                    .bind(principal_bind.clone())
                    .bind(principal_bind.clone()),
            )
        };

        // Facets SQL binds (start, end, principal, principal, [provider],
        // [facet_binds], [account]) × 6 dims. Order mirrors the clause order
        // in facets_sql: {provider_clause}{facet_clause} then {account_clause}.
        let bind_facets_query = || -> clickhouse::query::Query {
            let mut q = clickhouse.query(&facets_sql);
            for _ in 0..6 {
                q = q.bind(start_str.clone()).bind(end_str.clone());
                q = q.bind(principal_bind.clone()).bind(principal_bind.clone());
                if let Some(p) = provider_filter.filter(|p| !p.is_empty()) {
                    q = q.bind(p.to_string());
                }
                for v in &facet_binds {
                    q = q.bind(v.clone());
                }
                if let Some(a) = account_filter.filter(|a| !a.is_empty()) {
                    q = q.bind(a.to_string());
                }
            }
            q
        };

        // Auth posture doesn't take the principal binding (it's account-wide)
        let bind_posture_query = || -> clickhouse::query::Query {
            extra_bind(
                clickhouse
                    .query(&posture_sql)
                    .bind(start_str.clone())
                    .bind(end_str.clone()),
            )
        };

        let identity_fut = fetch_rows(bind_principal_query(&identity_sql), "cloud_dossier.identity");
        let ua_fut = fetch_rows(bind_principal_query(&ua_sql), "cloud_dossier.user_agents");
        let ip_fut = fetch_rows(bind_principal_query(&ip_sql), "cloud_dossier.ips");
        let facets_fut = fetch_rows(bind_facets_query(), "cloud_dossier.facets");
        let chain_fut = fetch_rows(bind_principal_query(&chain_sql), "cloud_dossier.chain");
        let key_actions_fut =
            fetch_rows(bind_principal_query(&key_actions_sql), "cloud_dossier.key_actions");
        let timeline_fut = fetch_rows(bind_principal_query(&timeline_sql), "cloud_dossier.timeline");
        let actions_fut = fetch_rows(bind_principal_query(&actions_sql), "cloud_dossier.actions");
        let resources_fut =
            fetch_rows(bind_principal_query(&resources_sql), "cloud_dossier.resources");
        let error_rate_fut =
            fetch_rows(bind_principal_query(&error_rate_sql), "cloud_dossier.error_rate");
        let error_codes_fut = fetch_rows(
            bind_principal_query(&error_codes_sql),
            "cloud_dossier.error_codes",
        );
        let posture_fut = fetch_rows(bind_posture_query(), "cloud_dossier.posture");
        let stream_fut = fetch_rows(bind_principal_query(&stream_sql), "cloud_dossier.stream");

        let (
            identity_rows,
            ua_rows,
            ip_rows,
            facet_rows,
            chain_rows,
            key_action_rows,
            timeline_rows,
            action_rows,
            resource_rows,
            error_rate_rows,
            error_code_rows,
            posture_rows,
            stream_rows,
        ) = tokio::join!(
            identity_fut,
            ua_fut,
            ip_fut,
            facets_fut,
            chain_fut,
            key_actions_fut,
            timeline_fut,
            actions_fut,
            resources_fut,
            error_rate_fut,
            error_codes_fut,
            posture_fut,
            stream_fut,
        );

        // --- Risk (Postgres fan-out) ----------------------------------------
        let risk_window = if span_secs <= 26 * 3_600 {
            RiskTimeWindow::Last24Hours
        } else if span_secs <= 7 * 24 * 3_600 {
            RiskTimeWindow::Last7Days
        } else {
            RiskTimeWindow::All
        };
        let risk_summary = self
            .cloud_risk
            .risk_for_entities(&[principal.to_string()])
            .await
            .ok()
            .flatten();
        let _ = risk_window; // reserved for a future windowed top-N lookup

        // --- Assemble -------------------------------------------------------
        let identity = build_identity(
            principal,
            &identity_rows,
            &ua_rows,
            &ip_rows,
            &chain_rows,
            &posture_rows,
        );
        let risk = build_risk(&risk_summary, principal);
        let facets = build_facets(&facet_rows);
        let assume_chain = build_assume_chain(principal, &chain_rows, &key_action_rows, &identity);
        let timeline = build_timeline(
            &timeline_rows,
            TIMELINE_BUCKETS,
            &window_label(time_range),
            &key_action_rows,
            timeline_unix_start,
            timeline_bucket_secs,
        );
        let regions = build_regions(&facets.region, &ip_rows);
        let top_actions = build_top_actions(&action_rows);
        let top_resources = build_top_resources(&resource_rows);
        let auth_posture = build_auth_posture(&posture_rows, principal);
        let error_rate = build_error_rate(&error_rate_rows, &error_code_rows);
        let stream = build_stream(&stream_rows);

        Ok(CloudDossier {
            identity,
            risk,
            facets,
            assume_chain,
            timeline,
            regions,
            top_actions,
            top_resources,
            auth_posture,
            error_rate,
            stream,
            window_label: window_label(time_range),
        })
    }
}

// ============================================================================
// JSONEachRow fetch helper (same pattern as cloud_overview.rs)
// ============================================================================

async fn fetch_rows(
    query: clickhouse::query::Query,
    subquery: &'static str,
) -> Vec<serde_json::Value> {
    let mut cursor = match query.fetch_bytes("JSONEachRow") {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(subquery, error = %e, "Cloud dossier subquery failed to start");
            return Vec::new();
        }
    };
    let mut bytes = Vec::new();
    loop {
        match cursor.next().await {
            Ok(Some(chunk)) => bytes.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(e) => {
                tracing::error!(subquery, error = %e, "Cloud dossier subquery stream error");
                return Vec::new();
            }
        }
    }
    let text = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(subquery, error = %e, "Cloud dossier subquery non-utf8 bytes");
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

fn build_identity(
    principal: &str,
    identity_rows: &[serde_json::Value],
    ua_rows: &[serde_json::Value],
    ip_rows: &[serde_json::Value],
    chain_rows: &[serde_json::Value],
    posture_rows: &[serde_json::Value],
) -> CloudDossierIdentity {
    let head = identity_rows.first();
    let account = head
        .and_then(|r| r.get("account"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let first_seen = head
        .and_then(|r| r.get("first_seen"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && !s.starts_with("1970"))
        .map(|s| s.to_string());
    let last_seen = head
        .and_then(|r| r.get("last_seen"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && !s.starts_with("1970"))
        .map(|s| s.to_string());
    let mfa_on = head
        .and_then(|r| r.get("mfa_on"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let mfa_off = head
        .and_then(|r| r.get("mfa_off"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let console_logins = head
        .and_then(|r| r.get("console_logins"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let user_agents: Vec<CloudDossierUserAgent> = ua_rows
        .iter()
        .filter_map(|row| {
            let ua = row.get("ua")?.as_str()?.to_string();
            let count = row.get("cnt").and_then(|v| v.as_u64()).unwrap_or(0);
            Some(CloudDossierUserAgent {
                kind: classify_ua(&ua).into(),
                ua,
                count,
            })
        })
        .collect();

    let ips: Vec<CloudDossierIp> = ip_rows
        .iter()
        .filter_map(|row| {
            let ip = row.get("ip")?.as_str()?.to_string();
            if ip.is_empty() {
                return None;
            }
            let count = row.get("cnt").and_then(|v| v.as_u64()).unwrap_or(0);
            let country = row
                .get("country")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let asn = row
                .get("asn")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            Some(CloudDossierIp {
                ip,
                first_seen: row
                    .get("first_at")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty() && !s.starts_with("1970"))
                    .map(|s| s.to_string()),
                last_seen: row
                    .get("last_at")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty() && !s.starts_with("1970"))
                    .map(|s| s.to_string()),
                event_count: count,
                geo: country,
                asn,
                anomaly: None,
                risk: None,
            })
        })
        .collect();

    let assumed_roles: Vec<String> = chain_rows
        .iter()
        .filter_map(|row| {
            let label = row.get("to_label").and_then(|v| v.as_str()).unwrap_or("");
            if label.is_empty() {
                None
            } else {
                Some(label.to_string())
            }
        })
        .collect();

    let is_role = principal.to_ascii_lowercase().contains("role")
        || principal.starts_with("arn:aws:sts::");

    // MFA tri-state: None for roles (N/A), Some(true) if we've ever seen an
    // MFA-yes call, Some(false) otherwise.
    let mfa = if is_role {
        None
    } else if mfa_on > 0 {
        Some(true)
    } else if mfa_off > 0 {
        Some(false)
    } else {
        None
    };

    // Look up the principal's entry in the posture table to mirror the
    // `role` flag + `is_role` heuristic there.
    let posture_hit = posture_rows.iter().find(|row| {
        row.get("name")
            .and_then(|v| v.as_str())
            .map(|s| s == principal)
            .unwrap_or(false)
    });
    let is_role = posture_hit
        .and_then(|row| row.get("is_role").and_then(|v| v.as_bool()))
        .unwrap_or(is_role);

    CloudDossierIdentity {
        id: principal.to_string(),
        principal_type: if is_role { "role".into() } else { "iam_user".into() },
        arn: None, // ARN backfill is a follow-up — would require parsing message / user_identity JSON
        account: account.clone(),
        account_name: None,
        first_seen,
        last_seen,
        created_by: None,
        key_age_days: None,
        mfa,
        mfa_policy_required: false,
        console: console_logins > 0,
        api_only: console_logins == 0,
        assumed_roles,
        groups: Vec::new(),
        tags: Vec::new(),
        user_agents,
        ips,
    }
}

fn build_risk(summary: &Option<EntityRiskSummary>, _principal: &str) -> CloudDossierRisk {
    match summary {
        Some(r) => {
            let score = r.risk_score.max(0) as u32;
            CloudDossierRisk {
                score: score.min(100),
                band: band_for_score(score).into(),
                delta: 0,
                factors: r
                    .last_rule_name
                    .clone()
                    .map(|rn| CloudDossierRiskFactor {
                        w: score.min(100),
                        label: rn,
                        detail: r
                            .last_severity
                            .clone()
                            .unwrap_or_else(|| "recent detection".into()),
                    })
                    .into_iter()
                    .collect(),
            }
        }
        None => CloudDossierRisk {
            score: 0,
            band: "low".into(),
            delta: 0,
            factors: Vec::new(),
        },
    }
}

fn build_facets(rows: &[serde_json::Value]) -> CloudDossierFacets {
    let mut out = CloudDossierFacets::default();
    for row in rows {
        let dim = row.get("dim").and_then(|v| v.as_str()).unwrap_or("");
        let value = row
            .get("value")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if value.is_empty() {
            continue;
        }
        let count = row.get("cnt").and_then(|v| v.as_u64()).unwrap_or(0);
        let item = CloudDossierFacetItem {
            name: value,
            count,
            label: None,
            anomaly: false,
        };
        match dim {
            "provider" => out.provider.push(item),
            "service" => out.service.push(item),
            "region" => out.region.push(item),
            "account" => out.account.push(item),
            "resource_type" => out.resource_type.push(item),
            "change_type" => out.change_type.push(item),
            _ => {}
        }
    }
    out
}

fn build_assume_chain(
    principal: &str,
    chain_rows: &[serde_json::Value],
    key_action_rows: &[serde_json::Value],
    identity: &CloudDossierIdentity,
) -> CloudDossierAssumeChain {
    let origin_ip = identity.ips.first().map(|ip| ip.ip.clone());
    let hops: Vec<CloudDossierAssumeHop> = chain_rows
        .iter()
        .filter_map(|row| {
            let to_label = row.get("to_label")?.as_str()?.to_string();
            if to_label.is_empty() {
                return None;
            }
            let at = row
                .get("first_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let calls = row.get("calls").and_then(|v| v.as_u64()).unwrap_or(0);
            let to_account = row
                .get("to_account")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            Some(CloudDossierAssumeHop {
                at: format_hhmm(&at),
                session_name: String::new(), // session name parsing from message is a follow-up
                via: "sts:AssumeRole".into(),
                to_label: to_label.clone(),
                to_account,
                permissions: Vec::new(),
                calls,
                note: None,
                sensitive: is_sensitive_role(&to_label),
            })
        })
        .collect();

    let key_actions: Vec<CloudDossierKeyAction> = key_action_rows
        .iter()
        .filter_map(|row| {
            let action = row.get("action")?.as_str()?.to_string();
            if action.is_empty() {
                return None;
            }
            let role = row
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let target = row
                .get("target")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let at_raw = row
                .get("at")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let severity = classify_action_severity(&action);
            Some(CloudDossierKeyAction {
                at: format_hhmm(at_raw),
                role,
                action,
                target,
                severity: severity.into(),
                detail: None,
            })
        })
        .collect();

    CloudDossierAssumeChain {
        origin_label: principal.to_string(),
        origin_account: identity.account.clone(),
        origin_ip,
        origin_first_at: identity.first_seen.clone(),
        origin_note: if identity.mfa == Some(false) {
            Some("No MFA on the originating principal.".into())
        } else {
            None
        },
        hops,
        key_actions,
    }
}

fn is_sensitive_role(label: &str) -> bool {
    let l = label.to_ascii_lowercase();
    l.contains("admin") || l.contains("billing") || l.contains("poweruser") || l.contains("devops")
}

fn classify_action_severity(action: &str) -> &'static str {
    let a = action.to_ascii_lowercase();
    if a.contains("createaccesskey")
        || a.contains("attachuserpolicy")
        || a.contains("putrolepolicy")
        || a.contains("deletebucket")
        || a.contains("schedulekeydeletion")
    {
        "critical"
    } else if a.contains("putbucketpolicy")
        || a.contains("authorizesecuritygroup")
        || a.contains("getsecretvalue")
        || a.contains("updatestack")
    {
        "high"
    } else {
        "medium"
    }
}

fn build_timeline(
    rows: &[serde_json::Value],
    buckets: u32,
    window: &str,
    key_action_rows: &[serde_json::Value],
    unix_start: u64,
    bucket_secs: u64,
) -> CloudDossierTimeline {
    // Compute top N services by total events and use them as lanes.
    let mut service_totals: HashMap<String, u64> = HashMap::new();
    for row in rows {
        let service = row
            .get("service")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let events = row.get("events").and_then(|v| v.as_u64()).unwrap_or(0);
        *service_totals.entry(service).or_default() += events;
    }
    let mut by_total: Vec<(String, u64)> = service_totals.into_iter().collect();
    by_total.sort_by(|a, b| b.1.cmp(&a.1));
    let lane_services: Vec<String> = by_total
        .into_iter()
        .take(TIMELINE_LANES)
        .map(|(s, _)| s)
        .filter(|s| !s.is_empty())
        .collect();
    let lane_set: std::collections::HashSet<&String> = lane_services.iter().collect();

    let lanes: Vec<CloudDossierTimelineLane> = lane_services
        .iter()
        .map(|svc| CloudDossierTimelineLane {
            id: svc.clone(),
            label: svc.to_uppercase(),
            accent: lane_accent(svc),
        })
        .collect();

    // Per-lane max for weight normalization (1..3)
    let mut per_lane_max: BTreeMap<String, u64> = BTreeMap::new();
    for row in rows {
        let service = row.get("service").and_then(|v| v.as_str()).unwrap_or("");
        if service.is_empty() || !lane_set.contains(&service.to_string()) {
            continue;
        }
        let events = row.get("events").and_then(|v| v.as_u64()).unwrap_or(0);
        per_lane_max
            .entry(service.to_string())
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
            let service = row.get("service")?.as_str()?.to_string();
            if !lane_set.contains(&service) {
                return None;
            }
            let bucket = row.get("bucket")?.as_u64()? as u32;
            if bucket >= buckets {
                return None;
            }
            let events = row.get("events").and_then(|v| v.as_u64()).unwrap_or(0);
            let max = per_lane_max.get(&service).copied().unwrap_or(1).max(1);
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
                None
            } else {
                Some(serde_json::json!([bucket, service, weight]))
            }
        })
        .collect();

    // Markers come from key actions — map each action's HH:MM back to a bucket.
    let markers: Vec<CloudDossierTimelineMarker> = key_action_rows
        .iter()
        .take(4)
        .filter_map(|row| {
            let at = row.get("at").and_then(|v| v.as_str()).unwrap_or("");
            let ts = chrono::DateTime::parse_from_str(
                &format!("{at} +0000"),
                "%Y-%m-%d %H:%M:%S%.f %z",
            )
            .ok()
            .map(|dt| dt.timestamp() as u64)
            .or_else(|| {
                chrono::DateTime::parse_from_str(&format!("{at} +0000"), "%Y-%m-%d %H:%M:%S %z")
                    .ok()
                    .map(|dt| dt.timestamp() as u64)
            })?;
            let bucket = if ts > unix_start {
                ((ts - unix_start) / bucket_secs) as u32
            } else {
                0
            };
            if bucket >= buckets {
                return None;
            }
            let action = row.get("action").and_then(|v| v.as_str()).unwrap_or("");
            Some(CloudDossierTimelineMarker {
                at: bucket,
                label: action.to_string(),
                severity: classify_action_severity(action).into(),
            })
        })
        .collect();

    CloudDossierTimeline {
        label: format!("Service lanes · {window}"),
        buckets,
        lanes,
        points,
        markers,
    }
}

fn build_regions(
    region_facet: &[CloudDossierFacetItem],
    _ip_rows: &[serde_json::Value],
) -> Vec<CloudDossierRegion> {
    region_facet
        .iter()
        .map(|item| CloudDossierRegion {
            id: item.name.clone(),
            label: None,
            count: item.count,
            anomaly: None,
            new_for_principal: false,
        })
        .collect()
}

fn build_top_actions(rows: &[serde_json::Value]) -> Vec<CloudDossierActionRow> {
    rows.iter()
        .filter_map(|row| {
            let name = row.get("name")?.as_str()?.to_string();
            if name.is_empty() {
                return None;
            }
            let service = row
                .get("service")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let count = row.get("cnt").and_then(|v| v.as_u64()).unwrap_or(0);
            let errors = row.get("errs").and_then(|v| v.as_u64()).unwrap_or(0);
            let principal = row
                .get("principal_role")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());
            let fq_action = format!("{service}:{name}");
            let sensitive = is_sensitive(&fq_action) || is_sensitive(&name);
            Some(CloudDossierActionRow {
                name,
                count,
                errors,
                service,
                principal,
                sensitive,
                anomaly: false,
            })
        })
        .collect()
}

fn build_top_resources(rows: &[serde_json::Value]) -> Vec<CloudDossierResource> {
    rows.iter()
        .filter_map(|row| {
            let arn = row.get("arn")?.as_str()?.to_string();
            if arn.is_empty() {
                return None;
            }
            let resource_type = row
                .get("resource_type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let account = row
                .get("account")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let changes = row.get("changes").and_then(|v| v.as_u64()).unwrap_or(0);
            let last_at = row
                .get("last_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let touched: Vec<String> = row
                .get("touched")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            // Severity is rough: more changes + sensitive resource type → higher.
            let severity = if resource_type.to_ascii_lowercase().contains("iam") && changes >= 5 {
                "critical"
            } else if changes >= 50 {
                "high"
            } else if changes >= 5 {
                "medium"
            } else {
                "low"
            };
            Some(CloudDossierResource {
                arn,
                r#type: resource_type,
                account,
                changes,
                last_at: format_hhmm(&last_at),
                severity: severity.into(),
                spark: Vec::new(), // sparkline derivation is a follow-up
                touched,
            })
        })
        .collect()
}

fn build_auth_posture(rows: &[serde_json::Value], principal: &str) -> CloudDossierAuthPosture {
    let principals: Vec<CloudDossierPosturePrincipal> = rows
        .iter()
        .filter_map(|row| {
            let name = row.get("name")?.as_str()?.to_string();
            if name.is_empty() {
                return None;
            }
            let has_mfa = row
                .get("has_mfa")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let seen_without = row
                .get("seen_without_mfa")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                > 0;
            let is_role = row
                .get("is_role")
                .and_then(|v| v.as_bool())
                .unwrap_or_else(|| {
                    name.to_ascii_lowercase().contains("role")
                        || name.starts_with("arn:aws:sts::")
                });
            let mfa = if is_role {
                None
            } else if has_mfa {
                Some(true)
            } else if seen_without {
                Some(false)
            } else {
                None
            };
            let last_call = row
                .get("last_call")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty() && !s.starts_with("1970"))
                .map(|s| format_hhmm(s));
            let priv_calls = row
                .get("priv_calls")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let anomaly = name == principal;
            Some(CloudDossierPosturePrincipal {
                name,
                mfa,
                privileged: priv_calls > 0,
                key_age_days: None,
                last_call,
                privileged_calls: priv_calls,
                anomaly,
                is_role,
            })
        })
        .collect();

    let total = principals.len() as u64;
    let with_mfa = principals
        .iter()
        .filter(|p| p.mfa == Some(true))
        .count() as u64;
    let without_mfa = principals
        .iter()
        .filter(|p| p.mfa == Some(false))
        .count() as u64;
    let privileged_without_mfa = principals
        .iter()
        .filter(|p| p.privileged && p.mfa == Some(false))
        .count() as u64;
    let priv_calls_no_mfa: u64 = principals
        .iter()
        .filter(|p| p.mfa == Some(false))
        .map(|p| p.privileged_calls)
        .sum();

    CloudDossierAuthPosture {
        total_principals: total,
        with_mfa,
        without_mfa,
        privileged_without_mfa,
        privileged_calls_without_mfa: priv_calls_no_mfa,
        console_logins: 0,
        console_logins_without_mfa: 0,
        api_key_only_principals: without_mfa,
        oldest_key_days: 0,
        principals,
    }
}

fn build_error_rate(
    rate_rows: &[serde_json::Value],
    code_rows: &[serde_json::Value],
) -> CloudDossierErrorRate {
    let head = rate_rows.first();
    let total = head
        .and_then(|r| r.get("total"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let failed = head
        .and_then(|r| r.get("failed"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let denied = head
        .and_then(|r| r.get("denied"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let allowed = total.saturating_sub(failed);

    let top_errors: Vec<CloudDossierErrorCode> = code_rows
        .iter()
        .filter_map(|row| {
            let code = row.get("code")?.as_str()?.to_string();
            if code.is_empty() || code == "success" {
                return None;
            }
            let count = row.get("cnt").and_then(|v| v.as_u64()).unwrap_or(0);
            let pct = if total > 0 {
                count as f64 / total as f64
            } else {
                0.0
            };
            let severity = if code.to_ascii_lowercase().contains("accessdenied")
                || code.to_ascii_lowercase().contains("unauthorized")
            {
                "critical"
            } else if code.to_ascii_lowercase().contains("throttl") {
                "medium"
            } else {
                "high"
            };
            Some(CloudDossierErrorCode {
                code,
                count,
                pct,
                severity: severity.into(),
            })
        })
        .collect();

    CloudDossierErrorRate {
        events_total: total,
        events_allowed: allowed,
        events_failed: failed,
        events_denied: denied,
        top_errors,
    }
}

fn build_stream(rows: &[serde_json::Value]) -> Vec<CloudDossierStreamEvent> {
    rows.iter()
        .filter_map(|row| {
            let id = row.get("id")?.as_str()?.to_string();
            let ts = row
                .get("ts")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let event_name = row
                .get("event_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let service = row
                .get("service")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let user = row
                .get("user")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let account = row
                .get("account")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let region = row
                .get("region")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let source_ip = row
                .get("source_ip")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let resource = row
                .get("resource")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let status = row
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let http_status = row
                .get("http_status_code")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let change_type = row
                .get("change_type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let error_code = if status.is_empty()
                || status == "success"
                || (http_status > 0 && http_status < 400)
            {
                None
            } else {
                Some(status.clone())
            };
            let ev_type = classify_event_type(&service, &event_name, &change_type);
            let interesting = ev_type == "AUTH"
                || ev_type == "PERM"
                || is_sensitive(&format!("{service}:{event_name}"))
                || error_code.is_some();

            // Compact summary for the one-line row. Keep to ≤ 4 fields so
            // the stream row doesn't overflow.
            let mut summary = serde_json::Map::new();
            if !user.is_empty() {
                summary.insert("user".into(), serde_json::Value::String(user.clone()));
            }
            if !resource.is_empty() {
                summary.insert(
                    "resource".into(),
                    serde_json::Value::String(resource.clone()),
                );
            }
            if !region.is_empty() {
                summary.insert("region".into(), serde_json::Value::String(region.clone()));
            }
            if let Some(ref e) = error_code {
                summary.insert("error".into(), serde_json::Value::String(e.clone()));
            }

            let mut detail = serde_json::Map::new();
            detail.insert("eventTime".into(), serde_json::Value::String(ts.clone()));
            detail.insert(
                "eventName".into(),
                serde_json::Value::String(event_name.clone()),
            );
            detail.insert(
                "sourceIPAddress".into(),
                serde_json::Value::String(source_ip.clone()),
            );
            detail.insert(
                "awsRegion".into(),
                serde_json::Value::String(region.clone()),
            );
            if !status.is_empty() {
                detail.insert("status".into(), serde_json::Value::String(status.clone()));
            }
            if http_status > 0 {
                detail.insert(
                    "httpStatusCode".into(),
                    serde_json::Value::Number(http_status.into()),
                );
            }
            if !change_type.is_empty() {
                detail.insert(
                    "changeType".into(),
                    serde_json::Value::String(change_type.clone()),
                );
            }

            Some(CloudDossierStreamEvent {
                id,
                ts: format_hhmm(&ts),
                r#type: ev_type.into(),
                event_name,
                service,
                user,
                account,
                region,
                source_ip,
                resource,
                error_code,
                summary: serde_json::Value::Object(summary),
                detail: serde_json::Value::Object(detail),
                interesting,
            })
        })
        .collect()
}
