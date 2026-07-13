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
use nanosiem_core::log_telemetry::repository::is_safe_source_type;
use nanosiem_core::inputlookup::SsrfValidator;
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
use std::collections::{BTreeSet, HashMap};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
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
    ensure_permission(&auth, SOURCE_CONFIGS_VIEW)?;

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
    //
    // NAN-1801 (P3 side-doors): the rollup read is scoped by the viewer's
    // effective per-source deny set — a viewer denied a source (or lacking
    // `audit:view`) sees that source's contribution as 0 instead of its true
    // volume/last-seen. Unrestricted viewers get byte-identical SQL.
    let deny_set = auth.effective_source_deny_set();
    if let Err(e) = enrich_list_with_rollup(&state, &mut configs, want_telemetry, &deny_set).await {
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
///
/// Unsafe values (anything outside `is_safe_source_type`'s allow-list — e.g.
/// the legacy `${source_type}` sentinel) are filtered out here so they never
/// reach the rollup sanitizer and fire its WARN. Write-time validation
/// rejects new unsafe rows; this filter handles stragglers from old DB state.
fn collect_target_source_types(rules: &[RoutingRule]) -> Vec<String> {
    let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for r in rules {
        if is_safe_source_type(&r.target_source_type) {
            set.insert(r.target_source_type.to_lowercase());
        }
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
            if is_safe_source_type(&r.target_source_type) {
                set.insert(r.target_source_type.to_lowercase());
            }
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
    deny_set: &BTreeSet<String>,
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
        .stats_by_source_type(&union, 24, deny_set)
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
    deny_set: &BTreeSet<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let source_types = collect_target_source_types(&full.routing_rules);
    if source_types.is_empty() {
        return Ok(());
    }

    let stats = state
        .log_telemetry_service
        .stats_by_source_type(&source_types, 24, deny_set)
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
    ensure_permission(&auth, SOURCE_CONFIGS_VIEW)?;

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
    ensure_permission(&auth, SOURCE_CONFIGS_VIEW)?;

    let mut config = state.source_config_service.get_with_rules(*id).await?;

    // Detail endpoint always returns telemetry: events_24h /
    // bytes_per_day_24h / last_event_at on the config + fires_24h /
    // last_fired_at on each routing rule. Single rollup read populates
    // everything (NAN-733). Best-effort: failure leaves the fields as None.
    //
    // NAN-1801: rollup read scoped by the viewer's effective per-source deny
    // set (see list_source_configs). Denied sources contribute 0 / None.
    let deny_set = auth.effective_source_deny_set();
    if let Err(e) = enrich_full_with_rollup(&state, &mut config, &deny_set).await {
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
    ensure_permission(&auth, SOURCE_CONFIGS_CREATE)?;

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
    ensure_permission(&auth, SOURCE_CONFIGS_EDIT)?;

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
    ensure_permission(&auth, SOURCE_CONFIGS_DELETE)?;

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
    ensure_permission(&auth, SOURCE_CONFIGS_EDIT)?;

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
    ensure_permission(&auth, SOURCE_CONFIGS_DEPLOY)?;

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
    ensure_permission(&auth, SOURCE_CONFIGS_DEPLOY)?;

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
    ensure_permission(&auth, SOURCE_CONFIGS_DEPLOY)?;

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
    ensure_permission(&auth, SOURCE_CONFIGS_VIEW)?;

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
    ensure_permission(&auth, SOURCE_CONFIGS_VIEW)?;

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
    ensure_permission(&auth, SOURCE_CONFIGS_EDIT)?;

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
    ensure_permission(&auth, SOURCE_CONFIGS_EDIT)?;

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
    ensure_permission(&auth, SOURCE_CONFIGS_EDIT)?;

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
    ensure_permission(&auth, SOURCE_CONFIGS_EDIT)?;

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
    /// exists for the target_source_type. For broker-bound config types
    /// (Kafka), also requires `broker_reachable` to be true.
    pub reachable: bool,
    pub source_config_enabled: bool,
    pub source_config_deployed: bool,
    pub target_log_source_exists: bool,
    /// TCP-dial result for broker-bound configs (NAN-884 K-4).
    /// `Some(true)` if at least one `bootstrap_servers` entry accepted a
    /// connection within the timeout; `Some(false)` if every entry failed;
    /// `None` for config types where the check does not apply (HTTP, Vector,
    /// HEC) or where `bootstrap_servers` is missing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broker_reachable: Option<bool>,
    /// One line per probed broker — `host:port → ok` or `host:port → <reason>`.
    /// Empty when `broker_reachable` is `None`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub broker_reachable_details: Vec<String>,
    /// Human-readable warnings explaining any false flags above.
    pub warnings: Vec<String>,
}

/// TCP-dial timeout for the Kafka broker reachability probe (NAN-884 K-4).
/// Short enough that an unreachable broker can't stall the deploy modal,
/// long enough that a slow but live broker still gets reported reachable.
const KAFKA_BROKER_PROBE_TIMEOUT_MS: u64 = 2000;

/// DNS-resolution timeout per broker. Bounds the worst-case for the SSRF
/// validation step so a slow resolver can't pin a runtime worker.
const KAFKA_BROKER_PROBE_DNS_TIMEOUT_MS: u64 = 1500;

/// Cap on brokers parsed from `bootstrap_servers` (NAN-939 H3). Each broker
/// holds a worker for up to `DNS_TIMEOUT + PROBE_TIMEOUT` ms, so an
/// uncapped list lets an authenticated user pin the runtime indefinitely.
/// Real-world Kafka clusters quote 3-5 brokers in bootstrap_servers; 10 is
/// generous and matches librdkafka guidance.
const KAFKA_BROKER_PROBE_MAX_BROKERS: usize = 10;

/// Ports accepted by the broker probe (NAN-939 H1). librdkafka defaults to
/// 9092 (plaintext) / 9093 (SSL) / 9094 (SASL_PLAINTEXT) / 9095 (SASL_SSL),
/// with 9096 as a common mTLS variant. Anything else (22, 80, 443, 6379,
/// 169.254.169.254:80 …) is a port-scan probe in disguise.
const KAFKA_BROKER_ALLOWED_PORTS: &[u16] = &[9092, 9093, 9094, 9095, 9096];

/// Parse a Kafka `bootstrap_servers` value into `(host, port)` pairs.
///
/// Vector accepts the librdkafka format: a comma-separated list of
/// `host[:port]` entries with whitespace trimmed. We default to the
/// librdkafka default port (9092) when none is specified. Empty / unparsable
/// entries are silently skipped so a single bad entry doesn't poison the
/// list. The list is capped at `KAFKA_BROKER_PROBE_MAX_BROKERS` (NAN-939)
/// so an authenticated user can't pin the runtime by persisting a 1000-entry
/// `bootstrap_servers` and triggering a probe.
/// Parse a single `host[:port]` entry from a Kafka bootstrap_servers list.
///
/// IPv4 / hostname: `broker:9092` or `broker` (port defaults to 9092).
///
/// IPv6 (NAN-951): MUST be bracketed per librdkafka's expectation, e.g.
/// `[2001:db8::1]:9092` or `[::1]:9092`. A bare unbracketed IPv6 like
/// `2001:db8::1` is ambiguous (the last `:` could be host/port or the
/// segment separator) and is rejected — librdkafka itself rejects them
/// too, so we don't try to be clever.
///
/// Returns None for empty / unparsable / disallowed entries so a single
/// bad entry doesn't poison the list. Hosts inside brackets are returned
/// WITHOUT brackets (e.g. `2001:db8::1`) — callers re-add them when
/// formatting for display.
fn parse_one_bootstrap_entry(s: &str) -> Option<(String, u16)> {
    if s.is_empty() {
        return None;
    }

    // Bracketed IPv6 form: `[host]:port` (or `[host]` — port defaults).
    // We `find` rather than `starts_with` because of leading whitespace
    // edge cases (caller trims, but be defensive).
    if let Some(stripped) = s.strip_prefix('[') {
        let close = stripped.find(']')?;
        let host = stripped[..close].trim();
        if host.is_empty() {
            return None;
        }
        // Validate the host parses as IPv6 — rejects `[broker.example.com]`
        // and other nonsense bracketed values.
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return None;
        }
        let after_bracket = &stripped[close + 1..];
        if after_bracket.is_empty() {
            return Some((host.to_string(), 9092));
        }
        // Expected form `]:port`.
        let port_str = after_bracket.strip_prefix(':')?.trim();
        let port: u16 = port_str.parse().ok()?;
        return Some((host.to_string(), port));
    }

    // Bare IPv6 (no brackets): ambiguous and rejected. We detect by
    // counting colons — IPv4 / hostnames have at most one `:` (host:port),
    // anything with `>=2` colons is either a bare IPv6 (reject) or a
    // hostname containing illegal characters (also reject).
    if s.matches(':').count() >= 2 {
        tracing::warn!(
            entry = %s,
            "rejecting unbracketed IPv6-shaped bootstrap_servers entry — use [host]:port form",
        );
        return None;
    }

    // IPv4 / hostname path: `host:port` or bare `host`.
    match s.rsplit_once(':') {
        Some((host, port_str)) => {
            let host = host.trim();
            if host.is_empty() {
                return None;
            }
            let port: u16 = port_str.trim().parse().ok()?;
            Some((host.to_string(), port))
        }
        None => Some((s.to_string(), 9092)),
    }
}

fn parse_bootstrap_servers(raw: &str) -> Vec<(String, u16)> {
    let parsed: Vec<(String, u16)> = raw
        .split(',')
        .filter_map(|entry| parse_one_bootstrap_entry(entry.trim()))
        .collect();

    if parsed.len() > KAFKA_BROKER_PROBE_MAX_BROKERS {
        tracing::warn!(
            count = parsed.len(),
            cap = KAFKA_BROKER_PROBE_MAX_BROKERS,
            "bootstrap_servers list exceeds probe cap — truncating",
        );
        parsed
            .into_iter()
            .take(KAFKA_BROKER_PROBE_MAX_BROKERS)
            .collect()
    } else {
        parsed
    }
}

/// Validate + probe a single Kafka broker.
///
/// NAN-939 H1/H2: the probe runs unauthenticated DNS + TCP connect against
/// caller-supplied addresses, so without filtering it's an SSRF / port-scan
/// primitive (loopback, RFC1918, link-local, cloud metadata, kube apiserver).
/// Every failure path collapses to `"unreachable"` in the user-facing detail
/// line; the specific reason (port disallowed, SSRF-blocked IP, DNS failure,
/// TCP refused, timeout) is logged via `tracing::warn!` for ops.
async fn validate_and_probe_broker(host: &str, port: u16) -> Result<(), &'static str> {
    use std::net::ToSocketAddrs;
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    if !KAFKA_BROKER_ALLOWED_PORTS.contains(&port) {
        tracing::warn!(host = %host, port, "kafka probe rejected: port not in allow-list");
        return Err("port_not_allowed");
    }

    let validator = SsrfValidator::default_secure();
    // NAN-951: bracket IPv6 hosts when formatting for `to_socket_addrs`.
    // `parse_one_bootstrap_entry` returns IPv6 hosts without brackets
    // (e.g. `2001:db8::1`), and `ToSocketAddrs` on `&str` requires the
    // `[host]:port` form for IPv6.
    let host_with_port = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let resolve_host = host_with_port.clone();

    let resolve_fut = tokio::task::spawn_blocking(move || {
        resolve_host
            .to_socket_addrs()
            .map(|iter| iter.collect::<Vec<_>>())
    });

    let dns_timeout = Duration::from_millis(KAFKA_BROKER_PROBE_DNS_TIMEOUT_MS);
    let addrs = match timeout(dns_timeout, resolve_fut).await {
        Ok(Ok(Ok(a))) if !a.is_empty() => a,
        Ok(Ok(Ok(_))) => {
            tracing::warn!(host = %host, port, "kafka probe rejected: DNS returned no addresses");
            return Err("dns_empty");
        }
        Ok(Ok(Err(err))) => {
            tracing::warn!(host = %host, port, error = %err, "kafka probe rejected: DNS failure");
            return Err("dns_failed");
        }
        Ok(Err(join_err)) => {
            tracing::warn!(host = %host, port, error = %join_err, "kafka probe rejected: DNS task panicked");
            return Err("dns_failed");
        }
        Err(_elapsed) => {
            tracing::warn!(host = %host, port, "kafka probe rejected: DNS timeout");
            return Err("dns_timeout");
        }
    };

    // Reject if ANY resolved IP is blocked — defends against multi-A
    // DNS-rebinding where the attacker mixes a public IP with a private one.
    let mut validated: Option<std::net::SocketAddr> = None;
    for sock in &addrs {
        if let Err(err) = validator.validate_ip_address(sock.ip()) {
            tracing::warn!(
                host = %host,
                port,
                resolved_ip = %sock.ip(),
                error = %err,
                "kafka probe rejected: SSRF guard blocked resolved IP",
            );
            return Err("blocked_address");
        }
        if validated.is_none() {
            validated = Some(*sock);
        }
    }
    let target = match validated {
        Some(t) => t,
        None => return Err("dns_empty"),
    };

    let connect_timeout = Duration::from_millis(KAFKA_BROKER_PROBE_TIMEOUT_MS);
    match timeout(connect_timeout, TcpStream::connect(target)).await {
        Ok(Ok(_stream)) => Ok(()),
        Ok(Err(err)) => {
            tracing::warn!(host = %host, port, target = %target, error = %err, "kafka probe TCP connect failed");
            Err("tcp_failed")
        }
        Err(_) => {
            tracing::warn!(host = %host, port, target = %target, "kafka probe TCP connect timed out");
            Err("tcp_timeout")
        }
    }
}

/// Probe each broker in `bootstrap_servers` with a TCP connect.
///
/// Returns `(Some(true), details)` when at least one broker accepts the
/// connection within the timeout, `(Some(false), details)` when every
/// broker fails, `(None, vec![])` when `bootstrap_servers` is missing /
/// empty so the caller can leave the field unset. Each detail line is
/// `host:port → ok` or `host:port → unreachable` — collapsed (NAN-939 H2)
/// so the response can't be used as a port-scan oracle. Detailed failure
/// reasons live in `tracing::warn!` for ops.
async fn probe_kafka_broker_reachability(
    connection_config: &serde_json::Value,
) -> (Option<bool>, Vec<String>) {
    let raw = match connection_config["bootstrap_servers"].as_str() {
        Some(s) if !s.trim().is_empty() => s,
        _ => return (None, Vec::new()),
    };

    let brokers = parse_bootstrap_servers(raw);
    if brokers.is_empty() {
        return (None, Vec::new());
    }

    let mut details = Vec::with_capacity(brokers.len());
    let mut any_ok = false;

    for (host, port) in &brokers {
        let addr = format!("{host}:{port}");
        match validate_and_probe_broker(host, *port).await {
            Ok(()) => {
                details.push(format!("{addr} → ok"));
                any_ok = true;
            }
            Err(_reason) => {
                // Generic message — see tracing::warn! for the specific
                // reason. Returning `Connection refused` vs `No route to host`
                // vs `blocked_address` vs `port_not_allowed` would tell an
                // attacker which internal hosts the API pod can reach.
                details.push(format!("{addr} → unreachable"));
            }
        }
    }

    (Some(any_ok), details)
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
    ensure_permission(&auth, SOURCE_CONFIGS_VIEW)?;

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

    // Broker-bound configs (Kafka) get a real TCP-dial probe so the deploy
    // modal can tell "broker not reachable" from "config is fine"
    // (NAN-884 K-4). Non-broker types skip the probe; an MVP TCP connect
    // catches the most common failure modes — wrong hostname, firewall,
    // broker down — without pulling in `rdkafka` for a full ApiVersions
    // request. Auth / topic-existence probes are deferred follow-up.
    let (broker_reachable, broker_reachable_details) =
        if config.config_type == "kafka" {
            probe_kafka_broker_reachability(&config.connection_config).await
        } else {
            (None, Vec::new())
        };

    if broker_reachable == Some(false) {
        warnings.push(format!(
            "No Kafka broker in `bootstrap_servers` responded within {} ms — events will not flow until at least one broker is reachable.",
            KAFKA_BROKER_PROBE_TIMEOUT_MS,
        ));
    }

    let reachable = config.enabled
        && config.deployed
        && target_log_source_exists
        && broker_reachable != Some(false);

    Ok(Json(ReachabilityResult {
        reachable,
        source_config_enabled: config.enabled,
        source_config_deployed: config.deployed,
        target_log_source_exists,
        broker_reachable,
        broker_reachable_details,
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
    ensure_permission(&auth, SOURCE_CONFIGS_VIEW)?;

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

    // ============================================================================
    // NAN-884 K-4: Kafka broker reachability probe — `parse_bootstrap_servers`
    // is pure / sync so it's exercised here without a tokio runtime; the
    // async `probe_kafka_broker_reachability` uses a TCP dial + 2s timeout
    // and is covered against a closed-port loopback + the running test stand.
    // ============================================================================

    #[test]
    fn parse_bootstrap_servers_single_host_with_port() {
        assert_eq!(
            parse_bootstrap_servers("broker.example.com:9093"),
            vec![("broker.example.com".to_string(), 9093)],
        );
    }

    #[test]
    fn parse_bootstrap_servers_defaults_port_when_missing() {
        // Default port is 9092 to match librdkafka's default — anything else
        // would silently send users to the wrong listener.
        assert_eq!(
            parse_bootstrap_servers("broker"),
            vec![("broker".to_string(), 9092)],
        );
    }

    #[test]
    fn parse_bootstrap_servers_comma_separated_and_whitespace_tolerant() {
        assert_eq!(
            parse_bootstrap_servers(" b1:9092 , b2:9093 ,b3 "),
            vec![
                ("b1".to_string(), 9092),
                ("b2".to_string(), 9093),
                ("b3".to_string(), 9092),
            ],
        );
    }

    #[test]
    fn parse_bootstrap_servers_skips_unparsable_entries() {
        // Empty entry, missing host, non-numeric port — none should panic
        // and none should poison the rest of the list.
        assert_eq!(
            parse_bootstrap_servers("good:9092,,:9092,bad:not-a-port,b2:9093"),
            vec![
                ("good".to_string(), 9092),
                ("b2".to_string(), 9093),
            ],
        );
    }

    /// Closed-port loopback dial — must fail fast (definitely under the 2s
    /// timeout) and produce one detail line. Post NAN-939 the failure path
    /// is "port not in allow-list" rather than TCP refused, but the
    /// user-visible message collapses to "unreachable" either way.
    #[tokio::test]
    async fn probe_kafka_broker_reachability_reports_unreachable_for_closed_port() {
        let cfg = serde_json::json!({
            "bootstrap_servers": "127.0.0.1:1"
        });
        let start = std::time::Instant::now();
        let (reachable, details) = probe_kafka_broker_reachability(&cfg).await;
        let elapsed = start.elapsed();

        assert_eq!(reachable, Some(false), "details: {details:?}");
        assert_eq!(details.len(), 1, "details: {details:?}");
        assert_eq!(details[0], "127.0.0.1:1 → unreachable");
        assert!(
            elapsed.as_millis() < KAFKA_BROKER_PROBE_TIMEOUT_MS as u128 + 500,
            "rejected broker should fail much faster than the timeout, took {elapsed:?}",
        );
    }

    /// Missing `bootstrap_servers` returns `(None, vec![])` so the caller
    /// can leave the field unset on the response — the deploy modal then
    /// hides the broker-reachable badge rather than rendering "false".
    #[tokio::test]
    async fn probe_kafka_broker_reachability_returns_none_when_servers_missing() {
        let cfg = serde_json::json!({});
        let (reachable, details) = probe_kafka_broker_reachability(&cfg).await;
        assert_eq!(reachable, None);
        assert!(details.is_empty(), "details: {details:?}");

        // Empty / whitespace-only string also yields None.
        let cfg = serde_json::json!({ "bootstrap_servers": "   " });
        let (reachable, details) = probe_kafka_broker_reachability(&cfg).await;
        assert_eq!(reachable, None);
        assert!(details.is_empty());
    }

    /// All-unparsable list yields `(None, vec![])` because no broker was
    /// actually probed — same shape as "missing bootstrap_servers" so the
    /// UI doesn't render a misleading "unreachable" badge for input the
    /// validator should have caught earlier.
    #[tokio::test]
    async fn probe_kafka_broker_reachability_returns_none_when_no_parsable_brokers() {
        let cfg = serde_json::json!({ "bootstrap_servers": ":,," });
        let (reachable, details) = probe_kafka_broker_reachability(&cfg).await;
        assert_eq!(reachable, None);
        assert!(details.is_empty());
    }

    /// NAN-939 H1: loopback brokers must be rejected by the SSRF guard.
    /// Even a live loopback listener on an allowed port returns "unreachable"
    /// so an authenticated user can't use the probe to fingerprint services
    /// running alongside the API pod.
    #[tokio::test]
    async fn probe_kafka_broker_reachability_rejects_loopback_brokers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ephemeral bind");
        // Bind succeeded but we use one of the Kafka allow-listed ports
        // for the probe input — the SSRF guard is what should reject the
        // dial, not the port allow-list (we test that separately).
        let _ = listener;
        let cfg = serde_json::json!({
            "bootstrap_servers": "127.0.0.1:9092,127.0.0.1:9093",
        });

        let (reachable, details) = probe_kafka_broker_reachability(&cfg).await;

        assert_eq!(reachable, Some(false), "details: {details:?}");
        assert_eq!(details.len(), 2);
        assert!(
            details.iter().all(|d| d.ends_with(" → unreachable")),
            "every loopback broker should be marked unreachable, got: {details:?}",
        );
    }

    /// NAN-939 H1: cloud-metadata endpoints must be rejected by the SSRF
    /// guard. The probe response must not let an authenticated user
    /// fingerprint whether the API pod can reach 169.254.169.254 (AWS IMDS).
    #[tokio::test]
    async fn probe_kafka_broker_reachability_rejects_aws_imds() {
        let cfg = serde_json::json!({
            "bootstrap_servers": "169.254.169.254:9092",
        });
        let (reachable, details) = probe_kafka_broker_reachability(&cfg).await;
        assert_eq!(reachable, Some(false));
        assert_eq!(details, vec!["169.254.169.254:9092 → unreachable"]);
    }

    /// NAN-939 H1: RFC1918 private ranges must be rejected.
    #[tokio::test]
    async fn probe_kafka_broker_reachability_rejects_private_ranges() {
        let cfg = serde_json::json!({
            "bootstrap_servers": "10.0.0.5:9092,192.168.1.10:9092,172.16.0.5:9092",
        });
        let (reachable, details) = probe_kafka_broker_reachability(&cfg).await;
        assert_eq!(reachable, Some(false), "details: {details:?}");
        assert_eq!(details.len(), 3);
        assert!(
            details.iter().all(|d| d.ends_with(" → unreachable")),
            "every private-range broker should be marked unreachable, got: {details:?}",
        );
    }

    /// NAN-939 H1: ports outside the librdkafka-standard allow-list must
    /// be rejected. Probing port 22 / 80 / 443 / 6379 is a port-scan
    /// disguised as a "Kafka" config.
    #[tokio::test]
    async fn probe_kafka_broker_reachability_rejects_disallowed_ports() {
        let cfg = serde_json::json!({
            "bootstrap_servers": "broker.example.com:22,broker.example.com:80,broker.example.com:6379",
        });
        let (reachable, details) = probe_kafka_broker_reachability(&cfg).await;
        assert_eq!(reachable, Some(false), "details: {details:?}");
        assert_eq!(details.len(), 3);
        assert!(
            details.iter().all(|d| d.ends_with(" → unreachable")),
            "every disallowed-port broker should be marked unreachable, got: {details:?}",
        );
    }

    /// NAN-939 H3: bootstrap_servers list must be capped so a single
    /// authenticated request can't pin a worker probing 1000 brokers.
    #[test]
    fn parse_bootstrap_servers_caps_at_max_brokers() {
        let raw = (1..=20)
            .map(|i| format!("b{i}:9092"))
            .collect::<Vec<_>>()
            .join(",");
        let parsed = parse_bootstrap_servers(&raw);
        assert_eq!(parsed.len(), KAFKA_BROKER_PROBE_MAX_BROKERS);
        // Should keep the first N — librdkafka uses brokers in list order
        // as the seed set, so truncating from the head would surprise users.
        assert_eq!(parsed[0].0, "b1");
        assert_eq!(parsed[KAFKA_BROKER_PROBE_MAX_BROKERS - 1].0, format!("b{}", KAFKA_BROKER_PROBE_MAX_BROKERS));
    }

    // ----------------------------------------------------------------------
    // NAN-951: IPv6 broker parsing. Pre-NAN-951 `rsplit_once(':')` worked
    // for `[::1]:9092` by luck (host = `[::1]`, port = 9092 — librdkafka
    // accepts both with and without brackets, but ToSocketAddrs requires
    // brackets) and silently mishandled bare `2001:db8::1` (host =
    // `2001:db8:`, port = 1). Post-NAN-951:
    //   - bracketed `[::1]:9092` parses cleanly (host stored without
    //     brackets so SocketAddr construction works downstream)
    //   - bare `2001:db8::1` is rejected (ambiguous)
    //   - non-IPv6 entries pass through unchanged
    // ----------------------------------------------------------------------

    #[test]
    fn parse_bootstrap_servers_accepts_bracketed_ipv6_loopback() {
        // [::1]:9092 — bracketed loopback, port specified.
        let parsed = parse_bootstrap_servers("[::1]:9092");
        assert_eq!(parsed, vec![("::1".to_string(), 9092)]);
    }

    #[test]
    fn parse_bootstrap_servers_accepts_bracketed_ipv6_full() {
        let parsed = parse_bootstrap_servers("[2001:db8::1]:9093");
        assert_eq!(parsed, vec![("2001:db8::1".to_string(), 9093)]);
    }

    #[test]
    fn parse_bootstrap_servers_defaults_port_for_bracketed_ipv6_without_port() {
        // [::1] with no `:port` suffix → default 9092 (librdkafka default).
        let parsed = parse_bootstrap_servers("[::1]");
        assert_eq!(parsed, vec![("::1".to_string(), 9092)]);
    }

    #[test]
    fn parse_bootstrap_servers_rejects_bare_unbracketed_ipv6() {
        // Pre-NAN-951 this silently became (host="2001:db8:", port=1).
        // Now: rejected as ambiguous (two or more `:` without brackets).
        let parsed = parse_bootstrap_servers("2001:db8::1");
        assert!(
            parsed.is_empty(),
            "bare IPv6 must be rejected — librdkafka also rejects this form: {parsed:?}"
        );
    }

    #[test]
    fn parse_bootstrap_servers_rejects_bare_ipv6_with_port_form() {
        // `2001:db8::1:9092` — last `:` is ambiguous (segment vs port).
        // Reject; user must bracket: `[2001:db8::1]:9092`.
        let parsed = parse_bootstrap_servers("2001:db8::1:9092");
        assert!(parsed.is_empty(), "ambiguous bare IPv6 must be rejected: {parsed:?}");
    }

    #[test]
    fn parse_bootstrap_servers_rejects_bracketed_non_ipv6_garbage() {
        // `[broker.example.com]:9092` is not valid librdkafka syntax;
        // brackets are reserved for IPv6.
        let parsed = parse_bootstrap_servers("[broker.example.com]:9092");
        assert!(parsed.is_empty(), "bracketed hostname must be rejected: {parsed:?}");
    }

    #[test]
    fn parse_bootstrap_servers_rejects_bracketed_ipv6_with_bad_port() {
        let parsed = parse_bootstrap_servers("[::1]:not-a-port");
        assert!(parsed.is_empty(), "bracketed IPv6 with non-numeric port must be rejected: {parsed:?}");
    }

    #[test]
    fn parse_bootstrap_servers_mixed_ipv4_and_bracketed_ipv6() {
        let parsed = parse_bootstrap_servers("b1:9092,[::1]:9093,b2:9094");
        assert_eq!(
            parsed,
            vec![
                ("b1".to_string(), 9092),
                ("::1".to_string(), 9093),
                ("b2".to_string(), 9094),
            ],
        );
    }

    #[test]
    fn parse_bootstrap_servers_ipv4_hostname_path_unchanged() {
        // Sanity: the IPv6 plumbing must not regress IPv4/hostname parsing.
        let parsed = parse_bootstrap_servers("broker.example.com:9092");
        assert_eq!(parsed, vec![("broker.example.com".to_string(), 9092)]);
        let parsed = parse_bootstrap_servers("10.0.0.5:9094");
        assert_eq!(parsed, vec![("10.0.0.5".to_string(), 9094)]);
        let parsed = parse_bootstrap_servers("bare-host");
        assert_eq!(parsed, vec![("bare-host".to_string(), 9092)]);
    }
}
