// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration collector endpoints (NAN-2189).
//!
//! A collector-category marketplace entry is the *integration*; an
//! `integration_instance` is one configured connection to a vendor tenant.
//! These endpoints manage the instances — the catalog itself is served by the
//! marketplace handler.
//!
//! Permissions are the log-source ones rather than the enrichment ones: a
//! collector produces log events, so whoever may add a log source may add a
//! collector, and whoever may not, may not. Writing credentials additionally
//! requires `credentials:use`, matching every other surface that stores a
//! secret on the operator's behalf.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, INTEGRATION_INSTANCE_CREATED,
    INTEGRATION_INSTANCE_DELETED, INTEGRATION_INSTANCE_UPDATED, INTEGRATION_RUN_TRIGGERED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::crypto::EncryptionService;
use nanosiem_core::marketplace::MarketplaceRepository;
use nanosiem_core::parser_repository::ParserRepositoryService;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_enterprise::integrations::{
    host_policy::validate_instance_hosts, types::CollectorManifest, IntegrationRepository,
    StreamProvisionReport, StreamProvisioner,
};

use crate::handlers::repository_target_authz::held_target_grants;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

// `From<IntegrationError> for ApiError` lives in
// `nanosiem-enterprise/src/api_error_impls.rs` — both types are foreign to this
// crate, so the orphan rule forbids the impl here.

// =============================================================================
// Wire types
// =============================================================================

/// An instance as returned to the UI. Credentials are never included — only
/// whether they are set.
#[derive(Debug, Serialize, ToSchema)]
pub struct IntegrationInstanceResponse {
    #[schema(value_type = String)]
    pub id: Uuid,
    #[schema(value_type = String)]
    pub catalog_id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub has_credentials: bool,
    pub enabled_streams: Vec<String>,
    pub schedule: Option<String>,
    pub backfill_from: Option<chrono::DateTime<chrono::Utc>>,
    pub last_run_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_run_status: Option<String>,
    pub last_run_duration_ms: Option<i64>,
    pub last_error: Option<String>,
    pub events_fetched: i64,
    /// True while a run holds the instance's lease.
    pub running: bool,
    pub streams: Vec<StreamStatusResponse>,
    /// NAN-2192: what happened when each enabled stream was given a log source.
    /// Only populated on create/update — the read paths do not re-provision.
    /// Anything other than `linked` means that stream is collecting into
    /// nothing an operator can see, which is the one thing worth surfacing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<serde_json::Value>)]
    pub provisioning: Vec<StreamProvisionReport>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StreamStatusResponse {
    pub stream_id: String,
    /// Label and source_type come from the catalog manifest, not the instance,
    /// so a stream renamed upstream shows its new label immediately.
    pub label: Option<String>,
    pub source_type: Option<String>,
    pub enabled: bool,
    pub has_cursor: bool,
    pub last_success_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_error: Option<String>,
    pub events_fetched: i64,
    /// Seconds since this stream last delivered anything. The number an
    /// operator actually needs: iterator APIs drop undelivered events after a
    /// retention window, so a stalled stream is data loss, not a backlog.
    pub staleness_secs: Option<i64>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateInstanceRequest {
    /// Catalog slug of the collector to instantiate.
    pub slug: String,
    pub name: String,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(default)]
    pub credentials: Option<HashMap<String, String>>,
    #[serde(default)]
    pub enabled_streams: Option<Vec<String>>,
    #[serde(default)]
    pub schedule: Option<String>,
    #[serde(default)]
    pub backfill_from: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateInstanceRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    /// Omit to keep the stored secret. The API never returns credentials, so a
    /// UI round-trip cannot send them back.
    #[serde(default)]
    pub credentials: Option<HashMap<String, String>>,
    #[serde(default)]
    pub enabled_streams: Option<Vec<String>>,
    #[serde(default)]
    pub schedule: Option<Option<String>>,
    #[serde(default)]
    pub backfill_from: Option<Option<chrono::DateTime<chrono::Utc>>>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListInstancesQuery {
    /// Restrict to one integration's instances.
    #[serde(default)]
    pub slug: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListInstancesResponse {
    pub instances: Vec<IntegrationInstanceResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TriggerRunResponse {
    pub triggered: bool,
    pub message: String,
}

// =============================================================================
// Helpers
// =============================================================================

fn require_view(auth: &AuthContext) -> Result<(), ApiError> {
    ensure_permission(auth, permissions::LOG_SOURCES_VIEW)
}

fn require_write(auth: &AuthContext) -> Result<(), ApiError> {
    ensure_permission(auth, permissions::LOG_SOURCES_EDIT)
}

/// Storing a credential is a distinct capability from editing a log source —
/// an operator may legitimately be allowed to retune streams without being
/// allowed to introduce new secrets the platform will use on their behalf.
fn require_credential_write(auth: &AuthContext) -> Result<(), ApiError> {
    ensure_permission(auth, permissions::CREDENTIALS_USE)
}

fn encrypt_credentials(
    credentials: &HashMap<String, String>,
) -> Result<(Vec<u8>, String), ApiError> {
    let encryption = EncryptionService::from_env();
    let encrypted = encryption
        .encrypt_json(credentials)
        .map_err(|e| ApiError::InternalError(format!("failed to encrypt credentials: {e}")))?;
    let ciphertext = base64_decode(&encrypted.ciphertext)?;
    Ok((ciphertext, encrypted.nonce))
}

fn base64_decode(value: &str) -> Result<Vec<u8>, ApiError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| ApiError::InternalError(format!("failed to encode credentials: {e}")))
}

/// Load the manifest for an instance's catalog entry so stream labels and
/// source types can be joined onto the response.
async fn load_manifest(
    marketplace: &MarketplaceRepository,
    catalog_id: Uuid,
) -> Result<CollectorManifest, ApiError> {
    let entry = marketplace
        .get_catalog_entry_by_id(catalog_id)
        .await
        .map_err(|e| ApiError::NotFound(e.to_string()))?;
    serde_json::from_value(entry.config.0.clone())
        .map_err(|e| ApiError::InternalError(format!("unreadable collector manifest: {e}")))
}

async fn build_response(
    repo: &IntegrationRepository,
    marketplace: &MarketplaceRepository,
    instance: nanosiem_enterprise::integrations::IntegrationInstance,
    provisioning: Vec<StreamProvisionReport>,
) -> Result<IntegrationInstanceResponse, ApiError> {
    let manifest = load_manifest(marketplace, instance.catalog_id).await?;
    let state = repo.list_stream_state(instance.id).await?;
    let now = chrono::Utc::now();

    // Report every stream the manifest declares, not just those with recorded
    // state — an enabled stream that has never run is exactly what an operator
    // is looking for when something isn't arriving.
    let streams = manifest
        .streams
        .iter()
        .map(|declared| {
            let recorded = state.iter().find(|s| s.stream_id == declared.id);
            StreamStatusResponse {
                stream_id: declared.id.clone(),
                label: Some(declared.label.clone()),
                source_type: Some(declared.source_type.clone()),
                enabled: instance.enabled_streams.contains(&declared.id),
                has_cursor: recorded.and_then(|s| s.cursor.as_ref()).is_some(),
                last_success_at: recorded.and_then(|s| s.last_success_at),
                last_error: recorded.and_then(|s| s.last_error.clone()),
                events_fetched: recorded.map(|s| s.events_fetched).unwrap_or(0),
                staleness_secs: recorded
                    .and_then(|s| s.last_success_at)
                    .map(|t| (now - t).num_seconds()),
            }
        })
        .collect();

    Ok(IntegrationInstanceResponse {
        id: instance.id,
        catalog_id: instance.catalog_id,
        name: instance.name.clone(),
        enabled: instance.enabled,
        config: instance.config.0.clone(),
        has_credentials: instance.has_credentials(),
        enabled_streams: instance.enabled_streams.clone(),
        schedule: instance.schedule.clone(),
        backfill_from: instance.backfill_from,
        last_run_at: instance.last_run_at,
        last_run_status: instance.last_run_status.clone(),
        last_run_duration_ms: instance.last_run_duration_ms,
        last_error: instance.last_error.clone(),
        events_fetched: instance.events_fetched,
        running: instance
            .run_lease_expires_at
            .map(|expiry| expiry > now)
            .unwrap_or(false),
        streams,
        provisioning,
    })
}

/// Reject stream ids the manifest does not declare.
///
/// Without this an operator could enable a stream that the collector will later
/// refuse to emit to, producing a run that fails for a reason the UI cannot
/// explain.
fn validate_streams(manifest: &CollectorManifest, requested: &[String]) -> Result<(), ApiError> {
    for stream in requested {
        if !manifest.streams.iter().any(|s| &s.id == stream) {
            return Err(ApiError::BadRequest(format!(
                "unknown stream {stream:?} for this integration"
            )));
        }
    }
    Ok(())
}

/// Reject config keys the manifest does not declare, and require the ones it
/// marks required.
fn validate_config(manifest: &CollectorManifest, config: &serde_json::Value) -> Result<(), ApiError> {
    let map = config.as_object().ok_or_else(|| {
        ApiError::BadRequest("config must be a JSON object".to_string())
    })?;

    for field in &manifest.config_fields {
        if field.required {
            let present = map
                .get(&field.name)
                .map(|v| !v.as_str().unwrap_or("").trim().is_empty())
                .unwrap_or(false);
            if !present {
                return Err(ApiError::BadRequest(format!(
                    "config field {} is required",
                    field.name
                )));
            }
        }
    }

    // Unknown keys are rejected rather than ignored: `host_policy` only
    // considers declared fields, so a typo'd key would silently never become
    // an allowed host and the run would fail with a confusing network error.
    for key in map.keys() {
        if !manifest.config_fields.iter().any(|f| &f.name == key) {
            return Err(ApiError::BadRequest(format!(
                "unknown config field {key:?} for this integration"
            )));
        }
    }

    // Reject a hostname that satisfies no declared suffix here, at save time.
    // The full SSRF check still runs before every launch — DNS can change under
    // us — but catching the typo now turns a 15-minutes-later stream failure
    // into an inline form error.
    validate_instance_hosts(manifest, config)?;

    Ok(())
}

// =============================================================================
// Handlers
// =============================================================================

#[utoipa::path(
    get,
    path = "/api/integrations/instances",
    tag = "integrations",
    params(ListInstancesQuery),
    responses((status = 200, body = ListInstancesResponse)),
    security(("api_key" = []))
)]
pub async fn list_instances(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListInstancesQuery>,
) -> Result<Json<ListInstancesResponse>, ApiError> {
    require_view(&auth)?;

    let repo = IntegrationRepository::new(state.pool.clone());
    let marketplace = MarketplaceRepository::new(state.pool.clone());

    let catalog_id = match &query.slug {
        Some(slug) => Some(
            marketplace
                .get_catalog_entry(slug)
                .await
                .map_err(|e| ApiError::NotFound(e.to_string()))?
                .id,
        ),
        None => None,
    };

    let instances = repo.list_instances(catalog_id).await?;
    let mut out = Vec::with_capacity(instances.len());
    for instance in instances {
        out.push(build_response(&repo, &marketplace, instance, Vec::new()).await?);
    }

    Ok(Json(ListInstancesResponse { instances: out }))
}

#[utoipa::path(
    get,
    path = "/api/integrations/instances/{id}",
    tag = "integrations",
    params(("id" = String, Path, description = "Instance id")),
    responses((status = 200, body = IntegrationInstanceResponse), (status = 404)),
    security(("api_key" = []))
)]
pub async fn get_instance(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<IntegrationInstanceResponse>, ApiError> {
    require_view(&auth)?;

    let repo = IntegrationRepository::new(state.pool.clone());
    let marketplace = MarketplaceRepository::new(state.pool.clone());
    let instance = repo.get_instance(id.into_uuid()).await?;

    Ok(Json(
        build_response(&repo, &marketplace, instance, Vec::new()).await?,
    ))
}

#[utoipa::path(
    post,
    path = "/api/integrations/instances",
    tag = "integrations",
    request_body = CreateInstanceRequest,
    responses((status = 200, body = IntegrationInstanceResponse), (status = 400)),
    security(("api_key" = []))
)]
pub async fn create_instance(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<CreateInstanceRequest>,
) -> Result<Json<IntegrationInstanceResponse>, ApiError> {
    require_write(&auth)?;
    if request.credentials.is_some() {
        require_credential_write(&auth)?;
    }

    let repo = IntegrationRepository::new(state.pool.clone());
    let marketplace = MarketplaceRepository::new(state.pool.clone());

    let entry = marketplace
        .get_catalog_entry(&request.slug)
        .await
        .map_err(|e| ApiError::NotFound(e.to_string()))?;
    if entry.execution_backend != "collector" {
        return Err(ApiError::BadRequest(format!(
            "{} is not a collector integration",
            request.slug
        )));
    }
    if !entry.installed {
        return Err(ApiError::BadRequest(format!(
            "{} must be installed before instances can be configured",
            request.slug
        )));
    }

    let manifest: CollectorManifest = serde_json::from_value(entry.config.0.clone())
        .map_err(|e| ApiError::InternalError(format!("unreadable collector manifest: {e}")))?;

    let config = if request.config.is_null() {
        serde_json::json!({})
    } else {
        request.config.clone()
    };
    validate_config(&manifest, &config)?;

    // Default to the streams the author marked `default: true`. Installing an
    // integration and getting nothing because no stream was selected is the
    // most likely first-run failure, and the manifest already says which
    // streams are the sensible starting set.
    let streams = request
        .enabled_streams
        .clone()
        .unwrap_or_else(|| manifest.default_stream_ids());
    validate_streams(&manifest, &streams)?;

    let encrypted = request
        .credentials
        .as_ref()
        .map(encrypt_credentials)
        .transpose()?;

    let instance = repo
        .create_instance(
            entry.id,
            &request.name,
            &config,
            encrypted.as_ref().map(|(ct, n)| (ct.as_slice(), n.as_str())),
            &streams,
            request.schedule.as_deref(),
            request.backfill_from,
            Some(auth.user_id()),
        )
        .await?;

    // Enablement is a separate step so a half-configured instance never starts
    // pulling; `create` then `update(enabled)` keeps the audit trail explicit.
    let instance = if request.enabled {
        repo.update_instance(
            instance.id,
            None,
            Some(true),
            None,
            None,
            None,
            None,
            None,
        )
        .await?
    } else {
        instance
    };


    // NAN-2192: give every enabled stream a log source, so the feed is visible
    // in Ingestion → Log Sources like any other. Grants come from the calling
    // principal, never TargetGrants::system — this is a request path, and
    // system grants exist for schedulers. An operator who cannot import parsers
    // still gets their instance saved; the report says which streams have no
    // log source and why.
    let parsers = ParserRepositoryService::new(state.pool.clone());
    let provisioner = StreamProvisioner::new(&repo, &parsers);
    let provisioning = provisioner
        .reconcile(
            instance.id,
            &manifest,
            &instance.enabled_streams,
            Some(auth.user_id()),
            &held_target_grants(&auth),
        )
        .await
        .unwrap_or_else(|e| {
            // Provisioning is best-effort by design. Failing the save because a
            // parser repository was unreachable would be a worse outcome than a
            // collector whose streams are temporarily unparsed.
            tracing::warn!(instance_id = %instance.id, error = %e, "Stream provisioning failed");
            Vec::new()
        });

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, INTEGRATION_INSTANCE_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "integration_instance",
                Some(instance.id),
                Some(instance.name.clone()),
            )
            .client_context(&client)
            .build(),
    );

    Ok(Json(
        build_response(&repo, &marketplace, instance, provisioning).await?,
    ))
}

#[utoipa::path(
    put,
    path = "/api/integrations/instances/{id}",
    tag = "integrations",
    params(("id" = String, Path, description = "Instance id")),
    request_body = UpdateInstanceRequest,
    responses((status = 200, body = IntegrationInstanceResponse), (status = 404)),
    security(("api_key" = []))
)]
pub async fn update_instance(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateInstanceRequest>,
) -> Result<Json<IntegrationInstanceResponse>, ApiError> {
    require_write(&auth)?;
    if request.credentials.is_some() {
        require_credential_write(&auth)?;
    }

    let repo = IntegrationRepository::new(state.pool.clone());
    let marketplace = MarketplaceRepository::new(state.pool.clone());

    let existing = repo.get_instance(id.into_uuid()).await?;
    let manifest = load_manifest(&marketplace, existing.catalog_id).await?;

    if let Some(config) = &request.config {
        validate_config(&manifest, config)?;
    }
    if let Some(streams) = &request.enabled_streams {
        validate_streams(&manifest, streams)?;
    }

    let encrypted = request
        .credentials
        .as_ref()
        .map(encrypt_credentials)
        .transpose()?;

    let instance = repo
        .update_instance(
            existing.id,
            request.name.as_deref(),
            request.enabled,
            request.config.as_ref(),
            encrypted.as_ref().map(|(ct, n)| (ct.as_slice(), n.as_str())),
            request.enabled_streams.as_deref(),
            request.schedule.as_ref().map(|s| s.as_deref()),
            request.backfill_from,
        )
        .await?;


    // NAN-2192: give every enabled stream a log source, so the feed is visible
    // in Ingestion → Log Sources like any other. Grants come from the calling
    // principal, never TargetGrants::system — this is a request path, and
    // system grants exist for schedulers. An operator who cannot import parsers
    // still gets their instance saved; the report says which streams have no
    // log source and why.
    let parsers = ParserRepositoryService::new(state.pool.clone());
    let provisioner = StreamProvisioner::new(&repo, &parsers);
    let provisioning = provisioner
        .reconcile(
            instance.id,
            &manifest,
            &instance.enabled_streams,
            Some(auth.user_id()),
            &held_target_grants(&auth),
        )
        .await
        .unwrap_or_else(|e| {
            // Provisioning is best-effort by design. Failing the save because a
            // parser repository was unreachable would be a worse outcome than a
            // collector whose streams are temporarily unparsed.
            tracing::warn!(instance_id = %instance.id, error = %e, "Stream provisioning failed");
            Vec::new()
        });

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, INTEGRATION_INSTANCE_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "integration_instance",
                Some(instance.id),
                Some(instance.name.clone()),
            )
            .client_context(&client)
            .build(),
    );

    Ok(Json(
        build_response(&repo, &marketplace, instance, provisioning).await?,
    ))
}

#[utoipa::path(
    delete,
    path = "/api/integrations/instances/{id}",
    tag = "integrations",
    params(("id" = String, Path, description = "Instance id")),
    responses((status = 204), (status = 404)),
    security(("api_key" = []))
)]
pub async fn delete_instance(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<axum::http::StatusCode, ApiError> {
    ensure_permission(&auth, permissions::LOG_SOURCES_DELETE)?;

    let repo = IntegrationRepository::new(state.pool.clone());
    let instance = repo.get_instance(id.into_uuid()).await?;
    repo.delete_instance(instance.id).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, INTEGRATION_INSTANCE_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "integration_instance",
                Some(instance.id),
                Some(instance.name.clone()),
            )
            .client_context(&client)
            .build(),
    );

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/integrations/instances/{id}/run",
    tag = "integrations",
    params(("id" = String, Path, description = "Instance id")),
    responses((status = 200, body = TriggerRunResponse), (status = 404)),
    security(("api_key" = []))
)]
pub async fn trigger_run(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<TriggerRunResponse>, ApiError> {
    require_write(&auth)?;

    let repo = IntegrationRepository::new(state.pool.clone());
    let instance = repo.get_instance(id.into_uuid()).await?;

    if !instance.enabled {
        return Err(ApiError::BadRequest(
            "instance is disabled; enable it before running".to_string(),
        ));
    }

    // Clear `last_run_at` so the scheduler treats it as due on its next tick,
    // rather than starting a run here. A collector run is long-lived and must
    // go through the scheduler's lease — spawning one from a request handler
    // would put a second consumer on the cursor and, on iterator APIs, lose
    // events outright.
    repo.mark_due(instance.id).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, INTEGRATION_RUN_TRIGGERED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "integration_instance",
                Some(instance.id),
                Some(instance.name.clone()),
            )
            .client_context(&client)
            .build(),
    );

    Ok(Json(TriggerRunResponse {
        triggered: true,
        message: "queued — the collector scheduler picks it up on its next tick".to_string(),
    }))
}

// =============================================================================
// OpenAPI
// =============================================================================

#[derive(OpenApi)]
#[openapi(
    paths(
        list_instances,
        get_instance,
        create_instance,
        update_instance,
        delete_instance,
        trigger_run
    ),
    components(schemas(
        IntegrationInstanceResponse,
        StreamStatusResponse,
        CreateInstanceRequest,
        UpdateInstanceRequest,
        ListInstancesResponse,
        TriggerRunResponse
    ))
)]
pub struct IntegrationsApiDoc;
