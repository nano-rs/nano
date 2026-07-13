// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection statistics, trigger, and matches

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, RULE_TRIGGERED};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use uuid::Uuid;

use super::types::*;
use super::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{
    error::{ApiError, ErrorResponse},
    state::AppState,
};

/// NAN-1808: compose the caller's EFFECTIVE per-source deny scope for
/// detection-match reads — the per-source RBAC deny set (NAN-1799) unioned
/// with the `audit` source unless the caller holds `audit:view`. Mirrors
/// `handlers::alerts::effective_viewer_scope`. Returns `None` for an
/// unrestricted caller so the emitted SQL stays byte-identical to the
/// pre-scoping query; otherwise the normalized (trimmed + lowercased) deny
/// values to bind against `detection_matches.source_types`.
fn effective_viewer_deny(auth: &AuthContext) -> Option<Vec<String>> {
    let mut deny = auth.denied_sources.deny_set().clone();
    if !auth.has_permission(permissions::AUDIT_VIEW) {
        deny.insert("audit".to_string());
    }
    let deny: Vec<String> = deny
        .iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if deny.is_empty() {
        None
    } else {
        Some(deny)
    }
}

/// Manually trigger a detection rule to run now
#[utoipa::path(
    post,
    path = "/api/rules/{id}/trigger",
    tag = "detections",
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Rule triggered successfully", body = inline(Object)),
        (status = 403, description = "Missing permission: detections:promote", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
        (status = 500, description = "Scheduler not running or failed to trigger", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn trigger_detection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_PROMOTE)?;

    let rule = state.detection_service.get_rule(*id).await?;

    // Calculate lookback window
    let end = chrono::Utc::now();
    let lookback_minutes = rule.lookback_minutes.map(|m| m as i64).unwrap_or(15);
    let start = end - chrono::Duration::minutes(lookback_minutes);
    let time_range = nanosiem_core::search::TimeRangeInput::new(start, end);

    state
        .detection_service
        .execute_rule(&rule, Some(time_range))
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to trigger rule: {}", e)))?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, RULE_TRIGGERED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_rule", Some(*id), Some(rule.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({"triggered": true, "rule_id": *id})))
}

/// Get daily stats for all detection rules (for sparkline charts)
#[utoipa::path(
    get,
    path = "/api/rules/stats",
    tag = "detections",
    params(StatsQuery),
    responses(
        (status = 200, description = "Daily stats for all rules", body = inline(Object)),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_detection_stats(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<StatsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    let days = params.days.unwrap_or(28);
    let stats = state.detection_service.get_all_daily_stats(days).await?;

    // Convert to JSON-friendly format
    let result: std::collections::HashMap<String, Vec<serde_json::Value>> = stats
        .into_iter()
        .map(|(rule_id, daily_stats)| {
            let stats_json: Vec<serde_json::Value> = daily_stats
                .into_iter()
                .map(|s| {
                    serde_json::json!({
                        "date": s.date.to_string(),
                        "match_count": s.match_count,
                        "alert_count": s.alert_count,
                    })
                })
                .collect();
            (nanosiem_core::typeid::encode("rule", &rule_id), stats_json)
        })
        .collect();

    Ok(Json(serde_json::json!(result)))
}

/// Get today's detection firing counts per rule
///
/// Returns the number of detection_matches rows recorded today (UTC) for each rule.
/// One row per Grouped-mode firing, one row per event for PerEvent rules — this
/// matches what the rule-detail "Today · hour by hour" strip shows, rather than
/// the summed underlying event count tracked in detection_daily_stats (NAN-812).
#[utoipa::path(
    get,
    path = "/api/rules/today-counts",
    tag = "detections",
    responses(
        (status = 200, description = "Today's firing counts per rule", body = inline(HashMap<String, i64>)),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_today_counts(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<std::collections::HashMap<String, i64>>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    use chrono::{NaiveTime, Utc};

    let today_start = Utc::now()
        .date_naive()
        .and_time(NaiveTime::MIN)
        .and_utc();

    let rows = sqlx::query_as::<_, (uuid::Uuid, i64)>(
        r#"
        SELECT rule_id, COUNT(*)::bigint AS firings
        FROM detection_matches
        WHERE detected_at >= $1
        GROUP BY rule_id
        "#,
    )
    .bind(today_start)
    .fetch_all(&state.pool)
    .await?;

    let mut counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();

    for (rule_id, firings) in rows {
        counts.insert(nanosiem_core::typeid::encode("rule", &rule_id), firings);
    }

    Ok(Json(counts))
}

/// Get actual detection matches for a rule
///
/// Returns matches that were stored when the rule was actively running,
/// NOT results from re-running the query against historical data.
///
/// This shows what ACTUALLY matched when the rule was live/alerting.
/// Works for all rule modes (live, alerting) since matches are stored separately.
#[utoipa::path(
    get,
    path = "/api/rules/{id}/matches",
    tag = "detections",
    params(
        ("id" = String, Path, description = "Detection rule ID"),
        DetectionMatchesQuery
    ),
    responses(
        (status = 200, description = "Detection matches with pagination", body = DetectionMatchesResponse),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_detection_matches(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Query(query): Query<DetectionMatchesQuery>,
) -> Result<Json<DetectionMatchesResponse>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    // NAN-1808: per-source RBAC — detection_matches stores the full matched
    // events, a sibling surface to alerts NOT covered by alerts.source_types.
    // A restricted viewer must not read matches derived from a denied source.
    // A row is visible iff NONE of its stamped source_types is denied; rows
    // stamped '{}' (pre-feature / non-source-derived) never overlap and stay
    // visible. `None` (unrestricted) keeps the SQL byte-identical.
    let deny_vec = effective_viewer_deny(&auth);

    // Build the base query from detection_matches table.
    // LEFT JOIN match_reviews so the UI can show a "reviewed" chip without an
    // extra round-trip per row (NAN-494).
    let mut sql = String::from(
        r#"
        SELECT
            dm.id,
            dm.detected_at,
            dm.severity,
            'open' as status,
            dm.matched_events,
            mr.reviewed_at
        FROM detection_matches dm
        LEFT JOIN match_reviews mr ON mr.match_id = dm.id
        WHERE dm.rule_id = $1
        "#,
    );

    let mut param_count = 1;

    // Add time filters if provided
    if query.start_time.is_some() {
        param_count += 1;
        sql.push_str(&format!(" AND dm.detected_at >= ${}", param_count));
    }

    if query.end_time.is_some() {
        param_count += 1;
        sql.push_str(&format!(" AND dm.detected_at <= ${}", param_count));
    }

    if deny_vec.is_some() {
        param_count += 1;
        sql.push_str(&format!(
            " AND (${p}::text[] = '{{}}' OR NOT (dm.source_types && ${p}::text[]))",
            p = param_count
        ));
    }

    // Order by most recent first
    sql.push_str(" ORDER BY dm.detected_at DESC");

    // Add pagination
    param_count += 1;
    sql.push_str(&format!(" LIMIT ${}", param_count));
    param_count += 1;
    sql.push_str(&format!(" OFFSET ${}", param_count));

    // Build the query
    let mut query_builder = sqlx::query_as::<
        _,
        (
            Uuid,
            chrono::DateTime<chrono::Utc>,
            String,
            String,
            serde_json::Value,
            Option<chrono::DateTime<chrono::Utc>>,
        ),
    >(&sql)
    .bind(*id);

    if let Some(start) = query.start_time {
        query_builder = query_builder.bind(start);
    }

    if let Some(end) = query.end_time {
        query_builder = query_builder.bind(end);
    }

    if let Some(deny) = &deny_vec {
        query_builder = query_builder.bind(deny);
    }

    query_builder = query_builder.bind(query.limit).bind(query.offset);

    // Execute the query
    let rows = query_builder.fetch_all(&state.pool).await?;

    // Get total count
    let mut count_sql = String::from("SELECT COUNT(*) FROM detection_matches WHERE rule_id = $1");

    let mut count_param = 1;
    if query.start_time.is_some() {
        count_param += 1;
        count_sql.push_str(&format!(" AND detected_at >= ${}", count_param));
    }

    if query.end_time.is_some() {
        count_param += 1;
        count_sql.push_str(&format!(" AND detected_at <= ${}", count_param));
    }

    // NAN-1808: total must count the same scope-filtered rows the page shows —
    // an unfiltered count would leak the existence of denied-source matches.
    if deny_vec.is_some() {
        count_param += 1;
        count_sql.push_str(&format!(
            " AND (${p}::text[] = '{{}}' OR NOT (source_types && ${p}::text[]))",
            p = count_param
        ));
    }

    let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql).bind(*id);

    if let Some(start) = query.start_time {
        count_query = count_query.bind(start);
    }

    if let Some(end) = query.end_time {
        count_query = count_query.bind(end);
    }

    if let Some(deny) = &deny_vec {
        count_query = count_query.bind(deny);
    }

    let total = count_query.fetch_one(&state.pool).await?;

    // Convert rows to response format
    let matches: Vec<DetectionMatch> = rows
        .into_iter()
        .map(
            |(match_id, detected_at, severity, status, matched_events, reviewed_at)| {
                let mut events = if let serde_json::Value::Array(arr) = matched_events {
                    arr
                } else {
                    vec![]
                };

                // NAN-830: inject the canonical `_match_*` envelope on each
                // event so the frontend doesn't have to guess at user-defined
                // rule output shapes. Stored data stays untouched —
                // normalization runs on every serialize, so heuristic
                // improvements are immediate without a migration.
                // NAN-831: normalizer lives in nanosiem-core so the
                // test-rule analysis path can call it too.
                for event in &mut events {
                    nanosiem_core::detection::normalize_match_event(event);
                }

                DetectionMatch {
                    id: match_id,
                    detected_at,
                    severity,
                    status,
                    event_count: events.len() as i32,
                    events,
                    reviewed: Some(reviewed_at.is_some()),
                    reviewed_at,
                }
            },
        )
        .collect();

    Ok(Json(DetectionMatchesResponse { total, matches }))
}
