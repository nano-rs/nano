// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source Configuration management endpoint handlers
//!
//! Implements:
//! - GET /api/source-configurations - List all source configurations
//! - POST /api/source-configurations - Create a new source configuration
//! - GET /api/source-configurations/:id - Get a source configuration by ID
//! - PUT /api/source-configurations/:id - Update a source configuration
//! - DELETE /api/source-configurations/:id - Delete a source configuration
//! - POST /api/source-configurations/:id/toggle - Toggle enabled status
//! - POST /api/source-configurations/:id/deploy - Deploy to Vector
//! - POST /api/source-configurations/:id/undeploy - Undeploy from Vector
//! - GET /api/source-configurations/:id/deployments - Get deployment history
//! - GET /api/source-configurations/:id/rules - List routing rules
//! - POST /api/source-configurations/:id/rules - Create a routing rule
//! - PUT /api/source-configurations/:id/rules/:rule_id - Update a routing rule
//! - DELETE /api/source-configurations/:id/rules/:rule_id - Delete a routing rule
//! - POST /api/source-configurations/:id/rules/reorder - Reorder routing rules

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, ROUTING_RULE_CREATED, ROUTING_RULE_DELETED,
    ROUTING_RULE_REORDERED, ROUTING_RULE_UPDATED, SOURCE_CONFIG_CREATED, SOURCE_CONFIG_DELETED,
    SOURCE_CONFIG_DEPLOYED, SOURCE_CONFIG_DEPLOY_ALL, SOURCE_CONFIG_TOGGLED,
    SOURCE_CONFIG_UNDEPLOYED, SOURCE_CONFIG_UPDATED,
};
use nanosiem_core::source_configs::{
    DeploymentResult, MatchFieldPreset, NewRoutingRule, NewSourceConfiguration, RoutingRule,
    SourceConfigDeployment, SourceConfigType, SourceConfigTypeInfo, SourceConfiguration,
    SourceConfigurationWithRules, UpdateRoutingRule, UpdateSourceConfiguration,
};
use nanosiem_core::typeid::TypeIdParam;
use serde::Deserialize;
use std::collections::HashMap;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

// Permission constants for source configurations
const SOURCE_CONFIGS_VIEW: &str = "source_configs:view";
const SOURCE_CONFIGS_CREATE: &str = "source_configs:create";
const SOURCE_CONFIGS_EDIT: &str = "source_configs:edit";
const SOURCE_CONFIGS_DELETE: &str = "source_configs:delete";
const SOURCE_CONFIGS_DEPLOY: &str = "source_configs:deploy";

/// Query params for listing source configurations
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListSourceConfigsQuery {
    pub config_type: Option<String>,
    pub enabled: Option<bool>,
    pub deployed: Option<bool>,
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Comma-separated list of optional enrichments. Currently supports
    /// `telemetry`, which adds `bytes_per_day_24h` and `last_event_at` to each
    /// returned config (best-effort ClickHouse query). Omit for the cheaper
    /// default response.
    pub include: Option<String>,
}

impl ListSourceConfigsQuery {
    fn includes_telemetry(&self) -> bool {
        self.include
            .as_deref()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .any(|part| part.eq_ignore_ascii_case("telemetry"))
            })
            .unwrap_or(false)
    }
}

/// List all source configurations
#[utoipa::path(
    get,
    path = "/api/source-configurations",
    tag = "source_configs",
    params(
        ListSourceConfigsQuery
    ),
    responses(
        (status = 200, description = "List of source configurations", body = Vec<SourceConfiguration>),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_source_configs(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListSourceConfigsQuery>,
) -> Result<Json<Vec<SourceConfiguration>>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: source_configs:view".to_string()))?;

    let want_telemetry = query.includes_telemetry();
    let params = nanosiem_core::source_configs::ListParams {
        config_type: query.config_type,
        enabled: query.enabled,
        deployed: query.deployed,
        search: query.search,
        limit: query.limit,
        offset: query.offset,
    };

    let mut configs = state.source_config_service.list(Some(params)).await?;

    // Single-pass rollup-backed enrichment (NAN-733). One scoped ClickHouse
    // read against `logs_per_source_5m` returns events + bytes + last_event_at
    // for every routing-rule target_source_type touched by any config in this
    // list. A single batched Postgres query fetches all configs' rules. The
    // previous code ran an un-scoped 24h `count(*) FROM logs SAMPLE 0.1` and
    // an N+1 `list_rules` per config, which dominated this endpoint's latency.
    //
    // Best-effort: ClickHouse unavailable or any underlying error leaves the
    // telemetry fields as `None` (graceful degradation per CLAUDE.md).
    if let Err(e) = enrich_list_with_rollup(&state, &mut configs, want_telemetry).await {
        tracing::warn!(
            error = %e,
            "Failed to enrich source configurations from rollup; returning without telemetry"
        );
    }

    Ok(Json(configs))
}

/// Collect the deduped, lowercase `target_source_type`s referenced by a
/// slice of routing rules. Used to scope the rollup IN-clause query to only
/// the source_types this config actually consumes.
fn collect_target_source_types(rules: &[RoutingRule]) -> Vec<String> {
    let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for r in rules {
        set.insert(r.target_source_type.to_lowercase());
    }
    set.into_iter().collect()
}

/// Same shape as `collect_target_source_types`, but unioning across many
/// configs' rule sets so the list endpoint can scope a single rollup query
/// to every source_type any config in the page touches.
fn collect_target_source_types_for_configs(
    rules_by_config: &HashMap<Uuid, Vec<RoutingRule>>,
) -> Vec<String> {
    let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for rules in rules_by_config.values() {
        for r in rules {
            set.insert(r.target_source_type.to_lowercase());
        }
    }
    set.into_iter().collect()
}

/// Best-effort enrichment of the LIST endpoint's response with rollup-backed
/// `events_24h` (always) plus `bytes_per_day_24h` and `last_event_at`
/// (when `include_bytes_and_last_event` is set, gated on `?include=telemetry`).
///
/// Two queries total: 1 batched Postgres `list_rules_for_configs(ids)` to
/// avoid the N+1, plus 1 scoped ClickHouse rollup read across the union of
/// every routing rule's `target_source_type`. Returns `Ok(())` (and skips
/// enrichment) when ClickHouse is not configured, so PostgreSQL-only mode
/// degrades gracefully.
async fn enrich_list_with_rollup(
    state: &AppState,
    configs: &mut [SourceConfiguration],
    include_bytes_and_last_event: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if configs.is_empty() {
        return Ok(());
    }

    let ids: Vec<Uuid> = configs.iter().map(|c| c.id).collect();
    let rules_by_config = state
        .source_config_service
        .list_rules_for_configs(&ids)
        .await?;

    let union = collect_target_source_types_for_configs(&rules_by_config);
    if union.is_empty() {
        return Ok(());
    }

    let stats = state
        .log_telemetry_service
        .stats_by_source_type(&union, 24)
        .await?;

    for cfg in configs.iter_mut() {
        let Some(rules) = rules_by_config.get(&cfg.id) else {
            // Config has no rules — events_24h is 0 (we still set it so the
            // UI shows "0" instead of "—" when ClickHouse is up).
            cfg.events_24h = Some(0);
            if include_bytes_and_last_event {
                cfg.bytes_per_day_24h = Some(0);
            }
            continue;
        };

        // Aggregate over distinct target_source_types — a config may have
        // multiple rules pointing at the same parser, but we count its events
        // once at the config level.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut events_total: i64 = 0;
        let mut bytes_total: i64 = 0;
        let mut last: Option<DateTime<Utc>> = None;
        for rule in rules {
            let key = rule.target_source_type.to_lowercase();
            if !seen.insert(key.clone()) {
                continue;
            }
            if let Some(s) = stats.get(&key) {
                events_total = events_total.saturating_add(s.events as i64);
                bytes_total = bytes_total.saturating_add(s.bytes as i64);
                if let Some(ts) = s.last_event_at {
                    last = Some(last.map_or(ts, |existing| existing.max(ts)));
                }
            }
        }
        cfg.events_24h = Some(events_total);
        if include_bytes_and_last_event {
            cfg.bytes_per_day_24h = Some(bytes_total);
            cfg.last_event_at = last;
        }
    }

    Ok(())
}

/// Best-effort enrichment of the `/full` endpoint's response with every
/// telemetry field on both the config and its rules.
///
/// **Per-rule attribution choice — first-rule-wins.** Vector does not tag
/// events with the routing rule ID that matched, so we cannot directly
/// attribute events to rules. We approximate by sorting a config's rules by
/// `priority` (lower = higher priority, the same order Vector evaluates them)
/// and crediting the FIRST rule with a given `target_source_type` with all
/// events for that source_type; later rules sharing the same target get
/// `Some(0)`. This mirrors Vector's "first match wins" routing.
///
/// One scoped ClickHouse rollup read populates events / bytes / last_event_at
/// at the config level AND the per-rule fires_24h / last_fired_at — the
/// previous code ran two separate ClickHouse queries to do the same work.
async fn enrich_full_with_rollup(
    state: &AppState,
    full: &mut SourceConfigurationWithRules,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let source_types = collect_target_source_types(&full.routing_rules);
    if source_types.is_empty() {
        return Ok(());
    }

    let stats = state
        .log_telemetry_service
        .stats_by_source_type(&source_types, 24)
        .await?;

    // Config-level: events + bytes + last_event_at across distinct
    // target_source_types.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut events_total: i64 = 0;
    let mut bytes_total: i64 = 0;
    let mut last: Option<DateTime<Utc>> = None;
    for rule in &full.routing_rules {
        let key = rule.target_source_type.to_lowercase();
        if !seen.insert(key.clone()) {
            continue;
        }
        if let Some(s) = stats.get(&key) {
            events_total = events_total.saturating_add(s.events as i64);
            bytes_total = bytes_total.saturating_add(s.bytes as i64);
            if let Some(ts) = s.last_event_at {
                last = Some(last.map_or(ts, |existing| existing.max(ts)));
            }
        }
    }
    full.config.events_24h = Some(events_total);
    full.config.bytes_per_day_24h = Some(bytes_total);
    full.config.last_event_at = last;

    // Per-rule attribution — first-rule-wins. Walk rules in priority order so
    // the FIRST occurrence of a given target_source_type gets credited;
    // duplicates get 0. We mutate rules in their original return order (the
    // API output order is stable), so collect (orig-index -> credit) first.
    let mut indexed: Vec<(usize, i32, String)> = full
        .routing_rules
        .iter()
        .enumerate()
        .map(|(i, r)| (i, r.priority, r.target_source_type.to_lowercase()))
        .collect();
    indexed.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));

    let mut credited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut per_rule: HashMap<usize, (i64, Option<DateTime<Utc>>)> = HashMap::new();
    for (orig_idx, _prio, key) in indexed {
        let credit = if credited.insert(key.clone()) {
            stats
                .get(&key)
                .map(|s| (s.events as i64, s.last_event_at))
                .unwrap_or((0, None))
        } else {
            // Subsequent rules sharing the same target_source_type aren't
            // credited; we still mark known-zero so the UI shows "0" instead
            // of "—" — accurate under first-rule-wins.
            (0, None)
        };
        per_rule.insert(orig_idx, credit);
    }
    for (i, rule) in full.routing_rules.iter_mut().enumerate() {
        if let Some((events, ts)) = per_rule.get(&i) {
            rule.fires_24h = Some(*events);
            rule.last_fired_at = *ts;
        }
    }

    Ok(())
}

/// Get a source configuration by ID
#[utoipa::path(
    get,
    path = "/api/source-configurations/{id}",
    tag = "source_configs",
    params(
        ("id" = String, Path, description = "Source configuration ID")
    ),
    responses(
        (status = 200, description = "Source configuration details", body = SourceConfiguration),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_source_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<SourceConfiguration>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: source_configs:view".to_string()))?;

    let config = state.source_config_service.get(*id).await?;
    Ok(Json(config))
}

/// Get a source configuration with its routing rules
#[utoipa::path(
    get,
    path = "/api/source-configurations/{id}/full",
    tag = "source_configs",
    params(
        ("id" = String, Path, description = "Source configuration ID")
    ),
    responses(
        (status = 200, description = "Source configuration with routing rules", body = SourceConfigurationWithRules),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_source_config_with_rules(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<SourceConfigurationWithRules>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: source_configs:view".to_string()))?;

    let mut config = state.source_config_service.get_with_rules(*id).await?;

    // Detail endpoint always returns telemetry: events_24h /
    // bytes_per_day_24h / last_event_at on the config + fires_24h /
    // last_fired_at on each routing rule. Single rollup read populates
    // everything (NAN-733). Best-effort: failure leaves the fields as None.
    if let Err(e) = enrich_full_with_rollup(&state, &mut config).await {
        tracing::warn!(
            source_config_id = %config.config.id,
            error = %e,
            "Failed to enrich source configuration from rollup"
        );
    }

    Ok(Json(config))
}

/// Create a new source configuration
#[utoipa::path(
    post,
    path = "/api/source-configurations",
    tag = "source_configs",
    request_body = NewSourceConfiguration,
    responses(
        (status = 200, description = "Source configuration created", body = SourceConfiguration),
        (status = 403, description = "Forbidden"),
        (status = 400, description = "Bad request"),
    ),
    security(("api_key" = []))
)]
pub async fn create_source_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<NewSourceConfiguration>,
) -> Result<Json<SourceConfiguration>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_CREATE).map_err(|_| {
        ApiError::Forbidden("Missing permission: source_configs:create".to_string())
    })?;

    let config = state.source_config_service.create(request).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::SourceConfig, SOURCE_CONFIG_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("source_config", Some(config.id), Some(config.name.clone()))
            .client_context(&client)
            .details(serde_json::json!({ "config_type": config.config_type }))
            .build(),
    );

    Ok(Json(config))
}

/// Update a source configuration
#[utoipa::path(
    put,
    path = "/api/source-configurations/{id}",
    tag = "source_configs",
    params(
        ("id" = String, Path, description = "Source configuration ID")
    ),
    request_body = UpdateSourceConfiguration,
    responses(
        (status = 200, description = "Source configuration updated", body = SourceConfiguration),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn update_source_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateSourceConfiguration>,
) -> Result<Json<SourceConfiguration>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: source_configs:edit".to_string()))?;

    let config = state.source_config_service.update(*id, request).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::SourceConfig, SOURCE_CONFIG_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("source_config", Some(config.id), Some(config.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(config))
}

/// Delete a source configuration
#[utoipa::path(
    delete,
    path = "/api/source-configurations/{id}",
    tag = "source_configs",
    params(
        ("id" = String, Path, description = "Source configuration ID")
    ),
    responses(
        (status = 200, description = "Source configuration deleted"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_source_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_DELETE).map_err(|_| {
        ApiError::Forbidden("Missing permission: source_configs:delete".to_string())
    })?;

    state.source_config_service.delete(*id).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::SourceConfig, SOURCE_CONFIG_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("source_config", Some(*id), None)
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({"deleted": true})))
}

/// Toggle request
#[derive(Debug, Deserialize, ToSchema)]
pub struct ToggleRequest {
    pub enabled: bool,
}

/// Toggle a source configuration's enabled status
#[utoipa::path(
    post,
    path = "/api/source-configurations/{id}/toggle",
    tag = "source_configs",
    params(
        ("id" = String, Path, description = "Source configuration ID")
    ),
    request_body = ToggleRequest,
    responses(
        (status = 200, description = "Source configuration toggled", body = SourceConfiguration),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn toggle_source_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<ToggleRequest>,
) -> Result<Json<SourceConfiguration>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: source_configs:edit".to_string()))?;

    let config = state
        .source_config_service
        .toggle(*id, request.enabled)
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::SourceConfig, SOURCE_CONFIG_TOGGLED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("source_config", Some(config.id), Some(config.name.clone()))
            .client_context(&client)
            .details(serde_json::json!({ "enabled": config.enabled }))
            .build(),
    );

    Ok(Json(config))
}

/// Deploy a source configuration to Vector
#[utoipa::path(
    post,
    path = "/api/source-configurations/{id}/deploy",
    tag = "source_configs",
    params(
        ("id" = String, Path, description = "Source configuration ID")
    ),
    responses(
        (status = 200, description = "Deployment result", body = DeploymentResult),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn deploy_source_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<DeploymentResult>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_DEPLOY).map_err(|_| {
        ApiError::Forbidden("Missing permission: source_configs:deploy".to_string())
    })?;

    let result = state.source_config_service.deploy(*id).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::SourceConfig, SOURCE_CONFIG_DEPLOYED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("source_config", Some(*id), None)
            .client_context(&client)
            .details(serde_json::json!({ "success": result.success, "message": result.message }))
            .build(),
    );

    Ok(Json(result))
}

/// Undeploy a source configuration from Vector
#[utoipa::path(
    post,
    path = "/api/source-configurations/{id}/undeploy",
    tag = "source_configs",
    params(
        ("id" = String, Path, description = "Source configuration ID")
    ),
    responses(
        (status = 200, description = "Undeployment result", body = DeploymentResult),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn undeploy_source_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<DeploymentResult>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_DEPLOY).map_err(|_| {
        ApiError::Forbidden("Missing permission: source_configs:deploy".to_string())
    })?;

    let result = state.source_config_service.undeploy(*id).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::SourceConfig, SOURCE_CONFIG_UNDEPLOYED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("source_config", Some(*id), None)
            .client_context(&client)
            .details(serde_json::json!({ "success": result.success, "message": result.message }))
            .build(),
    );

    Ok(Json(result))
}

/// Deploy all enabled source configurations
#[utoipa::path(
    post,
    path = "/api/source-configurations/deploy-all",
    tag = "source_configs",
    responses(
        (status = 200, description = "Deployment results for all enabled source configurations", body = Vec<DeploymentResult>),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn deploy_all_source_configs(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<Json<Vec<DeploymentResult>>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_DEPLOY).map_err(|_| {
        ApiError::Forbidden("Missing permission: source_configs:deploy".to_string())
    })?;

    let results = state.source_config_service.deploy_all().await?;

    let success_count = results.iter().filter(|r| r.success).count();
    let fail_count = results.iter().filter(|r| !r.success).count();

    state.emit_audit(
        AuditEvent::builder(AuditSource::SourceConfig, SOURCE_CONFIG_DEPLOY_ALL)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .client_context(&client)
            .details(serde_json::json!({
                "total": results.len(),
                "success": success_count,
                "failed": fail_count,
            }))
            .build(),
    );

    Ok(Json(results))
}

/// Get deployment history for a source configuration
#[utoipa::path(
    get,
    path = "/api/source-configurations/{id}/deployments",
    tag = "source_configs",
    params(
        ("id" = String, Path, description = "Source configuration ID")
    ),
    responses(
        (status = 200, description = "Deployment history", body = Vec<SourceConfigDeployment>),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_source_config_deployments(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<Vec<SourceConfigDeployment>>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: source_configs:view".to_string()))?;

    let history = state
        .source_config_service
        .get_deployment_history(*id, Some(50))
        .await?;
    Ok(Json(history))
}

// ============================================================================
// Routing Rules Endpoints
// ============================================================================

/// List routing rules for a source configuration
#[utoipa::path(
    get,
    path = "/api/source-configurations/{source_config_id}/rules",
    tag = "source_configs",
    params(
        ("source_config_id" = String, Path, description = "Source configuration ID")
    ),
    responses(
        (status = 200, description = "List of routing rules", body = Vec<RoutingRule>),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn list_routing_rules(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(source_config_id): Path<TypeIdParam>,
) -> Result<Json<Vec<RoutingRule>>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: source_configs:view".to_string()))?;

    let rules = state
        .source_config_service
        .list_rules(*source_config_id)
        .await?;
    Ok(Json(rules))
}

/// Create a routing rule
#[utoipa::path(
    post,
    path = "/api/source-configurations/{source_config_id}/rules",
    tag = "source_configs",
    params(
        ("source_config_id" = String, Path, description = "Source configuration ID")
    ),
    request_body = NewRoutingRule,
    responses(
        (status = 200, description = "Routing rule created", body = RoutingRule),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
        (status = 400, description = "Bad request"),
    ),
    security(("api_key" = []))
)]
pub async fn create_routing_rule(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(source_config_id): Path<TypeIdParam>,
    Json(request): Json<NewRoutingRule>,
) -> Result<Json<RoutingRule>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: source_configs:edit".to_string()))?;

    let rule = state
        .source_config_service
        .create_rule(*source_config_id, request)
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::SourceConfig, ROUTING_RULE_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("routing_rule", Some(rule.id), None)
            .client_context(&client)
            .details(serde_json::json!({
                "source_config_id": *source_config_id,
                "match_field": rule.match_field,
                "match_type": rule.match_type,
            }))
            .build(),
    );

    Ok(Json(rule))
}

/// Path params for rule operations
#[derive(Debug, Deserialize, IntoParams)]
pub struct RulePath {
    #[serde(with = "nanosiem_core::typeid::source_config")]
    #[param(value_type = String)]
    pub source_config_id: Uuid,
    #[serde(with = "nanosiem_core::typeid::source_config")]
    #[param(value_type = String)]
    pub rule_id: Uuid,
}

/// Update a routing rule
#[utoipa::path(
    put,
    path = "/api/source-configurations/{source_config_id}/rules/{rule_id}",
    tag = "source_configs",
    params(
        RulePath
    ),
    request_body = UpdateRoutingRule,
    responses(
        (status = 200, description = "Routing rule updated", body = RoutingRule),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn update_routing_rule(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(path): Path<RulePath>,
    Json(request): Json<UpdateRoutingRule>,
) -> Result<Json<RoutingRule>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: source_configs:edit".to_string()))?;

    let rule = state
        .source_config_service
        .update_rule(path.rule_id, request)
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::SourceConfig, ROUTING_RULE_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("routing_rule", Some(rule.id), None)
            .client_context(&client)
            .details(serde_json::json!({ "source_config_id": path.source_config_id }))
            .build(),
    );

    Ok(Json(rule))
}

/// Delete a routing rule
#[utoipa::path(
    delete,
    path = "/api/source-configurations/{source_config_id}/rules/{rule_id}",
    tag = "source_configs",
    params(
        RulePath
    ),
    responses(
        (status = 200, description = "Routing rule deleted"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_routing_rule(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(path): Path<RulePath>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: source_configs:edit".to_string()))?;

    state
        .source_config_service
        .delete_rule(path.rule_id)
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::SourceConfig, ROUTING_RULE_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("routing_rule", Some(path.rule_id), None)
            .client_context(&client)
            .details(serde_json::json!({ "source_config_id": path.source_config_id }))
            .build(),
    );

    Ok(Json(serde_json::json!({"deleted": true})))
}

/// Reorder routing rules request
#[derive(Debug, Deserialize, ToSchema)]
pub struct ReorderRulesRequest {
    #[serde(with = "nanosiem_core::typeid::source_config::vec")]
    #[schema(value_type = Vec<String>)]
    pub rule_order: Vec<Uuid>,
}

/// Reorder routing rules
#[utoipa::path(
    post,
    path = "/api/source-configurations/{source_config_id}/rules/reorder",
    tag = "source_configs",
    params(
        ("source_config_id" = String, Path, description = "Source configuration ID")
    ),
    request_body = ReorderRulesRequest,
    responses(
        (status = 200, description = "Routing rules reordered", body = Vec<RoutingRule>),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn reorder_routing_rules(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(source_config_id): Path<TypeIdParam>,
    Json(request): Json<ReorderRulesRequest>,
) -> Result<Json<Vec<RoutingRule>>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: source_configs:edit".to_string()))?;

    let rule_order = request.rule_order.clone();
    let rules = state
        .source_config_service
        .reorder_rules(*source_config_id, request.rule_order)
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::SourceConfig, ROUTING_RULE_REORDERED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("routing_rule", None, None)
            .client_context(&client)
            .details(serde_json::json!({
                "source_config_id": *source_config_id,
                "rule_count": rule_order.len(),
            }))
            .build(),
    );

    Ok(Json(rules))
}

// ============================================================================
// Routing Rule Reachability Check
// ============================================================================

/// Request body for the reachability check.
///
/// Describes a candidate routing rule against a parent source configuration.
/// `match_field`, `match_type`, and `match_value` are accepted for forward
/// compatibility but the current implementation only checks plumbing
/// (config enabled + deployed + matching log source exists for
/// `target_source_type`). Field/type/value-level evaluation is not yet
/// implemented.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CheckReachabilityRequest {
    pub target_source_type: String,
    pub match_field: String,
    pub match_type: String,
    pub match_value: String,
}

/// Result of the reachability check.
#[derive(Debug, serde::Serialize, ToSchema)]
pub struct ReachabilityResult {
    /// True only when the source config is enabled, deployed, and a log source
    /// exists for the target_source_type.
    pub reachable: bool,
    pub source_config_enabled: bool,
    pub source_config_deployed: bool,
    pub target_log_source_exists: bool,
    /// Human-readable warnings explaining any false flags above.
    pub warnings: Vec<String>,
}

/// Check whether a candidate routing rule on a source configuration can
/// actually deliver events to a matching log source parser.
#[utoipa::path(
    post,
    path = "/api/source-configurations/{id}/rules/check-reachability",
    tag = "source_configs",
    params(
        ("id" = String, Path, description = "Source configuration ID")
    ),
    request_body = CheckReachabilityRequest,
    responses(
        (status = 200, description = "Reachability result", body = ReachabilityResult),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Source configuration not found"),
    ),
    security(("api_key" = []))
)]
pub async fn check_routing_rule_reachability(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<CheckReachabilityRequest>,
) -> Result<Json<ReachabilityResult>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: source_configs:view".to_string()))?;

    // Load the source config (404 if missing)
    let config = state.source_config_service.get(*id).await?;

    let mut warnings = Vec::new();

    if !config.enabled {
        warnings.push(format!(
            "Source configuration '{}' is disabled — no events will flow through it.",
            config.name
        ));
    }
    if !config.deployed {
        warnings.push(format!(
            "Source configuration '{}' is not deployed — Vector will not pick up its rules.",
            config.name
        ));
    }

    // Look up matching log source by source_type. We list and filter in Rust
    // so we tolerate the absence of a dedicated `find_by_source_type` repo
    // method and so this works even when ClickHouse is unavailable.
    let target = request.target_source_type.trim();
    let log_sources = state
        .log_source_service
        .list(Some(nanosiem_core::log_sources::ListParams {
            source_type: Some(target.to_string()),
            ..Default::default()
        }))
        .await
        .unwrap_or_default();

    let target_log_source_exists = log_sources
        .iter()
        .any(|ls| ls.source_type.eq_ignore_ascii_case(target));

    if !target_log_source_exists {
        warnings.push(format!(
            "No log source is configured with source_type='{}'. Events matching this rule will be dropped.",
            target
        ));
    }

    let reachable = config.enabled && config.deployed && target_log_source_exists;

    Ok(Json(ReachabilityResult {
        reachable,
        source_config_enabled: config.enabled,
        source_config_deployed: config.deployed,
        target_log_source_exists,
        warnings,
    }))
}

// ============================================================================
// Source-config type metadata (NAN-649)
// ============================================================================

/// List metadata for every supported source-config driver (HTTP, Kafka,
/// AWS S3, GCP Pub/Sub, Splunk HEC, Vector).
///
/// The frontend uses this to render the routing-rule UI in the right shape
/// per driver: pull-source drivers (broker-bound) get a "single vs.
/// multiple source types" mode switch with per-driver `match_field` presets;
/// push-source drivers (HTTP, Vector) keep the simple in-band `source_type`
/// header model.
///
/// View-permission gated because the response is purely descriptive — no
/// secrets or per-tenant data — and identical for every caller.
#[utoipa::path(
    get,
    path = "/api/source-configurations/types",
    tag = "source_configs",
    responses(
        (status = 200, description = "Per-driver source-config type metadata", body = Vec<SourceConfigTypeInfo>),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_source_config_types(
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<SourceConfigTypeInfo>>, ApiError> {
    check_permission(&auth, SOURCE_CONFIGS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: source_configs:view".to_string()))?;

    let infos: Vec<SourceConfigTypeInfo> = SourceConfigType::all_types()
        .iter()
        .copied()
        .map(SourceConfigTypeInfo::from_config_type)
        .collect();

    Ok(Json(infos))
}

// ============================================================================
// OpenAPI Documentation
// ============================================================================

/// OpenAPI documentation for source configurations endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_source_configs,
        list_source_config_types,
        get_source_config,
        get_source_config_with_rules,
        create_source_config,
        update_source_config,
        delete_source_config,
        toggle_source_config,
        deploy_source_config,
        undeploy_source_config,
        deploy_all_source_configs,
        get_source_config_deployments,
        list_routing_rules,
        create_routing_rule,
        update_routing_rule,
        delete_routing_rule,
        reorder_routing_rules,
        check_routing_rule_reachability,
    ),
    components(schemas(
        ToggleRequest,
        ReorderRulesRequest,
        CheckReachabilityRequest,
        ReachabilityResult,
        SourceConfigTypeInfo,
        MatchFieldPreset,
    ))
)]
pub struct SourceConfigsApiDoc;

impl SourceConfigsApiDoc {
    pub fn paths() -> Vec<utoipa::openapi::path::PathItem> {
        vec![]
    }

    pub fn schemas() -> Vec<(
        &'static str,
        utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
    )> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // collect_target_source_types — drives the IN-clause scope on the
    // LogTelemetryRepository read. Sanitization + SQL-shape coverage lives in
    // `nanosiem_core::log_telemetry::repository` (the helpers moved there
    // post-NAN-733).
    // ============================================================================

    fn make_rule(target_source_type: &str, priority: i32) -> RoutingRule {
        RoutingRule {
            id: uuid::Uuid::nil(),
            source_configuration_id: uuid::Uuid::nil(),
            priority,
            match_field: "source_type".to_string(),
            match_type: "exact".to_string(),
            match_value: Some("x".to_string()),
            target_source_type: target_source_type.to_string(),
            created_at: chrono::Utc::now(),
            fires_24h: None,
            last_fired_at: None,
        }
    }

    #[test]
    fn collect_target_source_types_lowercases_and_dedupes() {
        // Mixed case + duplicate target — should collapse to one entry,
        // lowercased.
        let rules = vec![
            make_rule("LimaCharlie_EDR", 1),
            make_rule("limacharlie_edr", 2),
            make_rule("AWS-CloudTrail", 3),
        ];
        let mut got = collect_target_source_types(&rules);
        got.sort();
        assert_eq!(
            got,
            vec!["aws-cloudtrail".to_string(), "limacharlie_edr".to_string()],
        );
    }

    #[test]
    fn collect_target_source_types_single_rule() {
        // The motivating LC config: 1 rule, 1 source_type — the rollup
        // IN-clause ends up tightly scoped to a single value.
        let rules = vec![make_rule("limacharlie_edr", 1)];
        let got = collect_target_source_types(&rules);
        assert_eq!(got, vec!["limacharlie_edr".to_string()]);
    }

    #[test]
    fn collect_target_source_types_empty_for_no_rules() {
        let got = collect_target_source_types(&[]);
        assert!(got.is_empty());
    }

    #[test]
    fn collect_target_source_types_for_configs_unions_across_configs() {
        // List endpoint scopes one rollup query to the union of every config's
        // rule targets — NOT one query per config. Verify the collector
        // dedupes across configs (lowercase + identity collapse).
        let mut by_config: HashMap<Uuid, Vec<RoutingRule>> = HashMap::new();
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        by_config.insert(
            id_a,
            vec![make_rule("LimaCharlie_EDR", 1), make_rule("aws-cloudtrail", 2)],
        );
        by_config.insert(
            id_b,
            vec![make_rule("LIMACHARLIE_EDR", 1), make_rule("microsoft_sysmon_json", 2)],
        );

        let mut got = collect_target_source_types_for_configs(&by_config);
        got.sort();
        assert_eq!(
            got,
            vec![
                "aws-cloudtrail".to_string(),
                "limacharlie_edr".to_string(),
                "microsoft_sysmon_json".to_string(),
            ],
        );
    }

    #[test]
    fn collect_target_source_types_for_configs_empty_for_no_configs() {
        let by_config: HashMap<Uuid, Vec<RoutingRule>> = HashMap::new();
        assert!(collect_target_source_types_for_configs(&by_config).is_empty());
    }
}
