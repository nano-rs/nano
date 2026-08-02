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
    http::HeaderName,
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, CUSTOM_INTEGRATION_CREATED, CUSTOM_INTEGRATION_DELETED,
    CUSTOM_INTEGRATION_PREVIEWED, CUSTOM_INTEGRATION_UPDATED, INTEGRATION_INSTANCE_CREATED,
    INTEGRATION_INSTANCE_DELETED, INTEGRATION_INSTANCE_UPDATED, INTEGRATION_RUN_TRIGGERED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::crypto::EncryptionService;
use nanosiem_core::ingestion::VectorIngestClient;
use nanosiem_core::marketplace::{
    ConfigFieldDef, CredentialFieldDef, ManifestAuth, MarketplaceCatalogEntry,
    MarketplaceRepository, StreamDef,
};
use nanosiem_core::parser_repository::ParserRepositoryService;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_enterprise::custom_enrichment::{
    validate_allowed_domains, validate_token_url, SandboxExecutor,
};
use nanosiem_enterprise::integrations::{
    build_auth_config,
    host_policy::{resolve_allowed_domains, validate_instance_hosts, validate_suffixes},
    types::{
        CollectorManifest, CUSTOM_COLLECTOR_MAX_BACKFILL_DAYS, CUSTOM_COLLECTOR_MAX_BYTES_PER_RUN,
        CUSTOM_COLLECTOR_MAX_CODE_BYTES, CUSTOM_COLLECTOR_MAX_EVENTS_PER_EMIT,
        CUSTOM_COLLECTOR_MAX_EVENTS_PER_RUN, CUSTOM_COLLECTOR_MAX_RUN_SECS,
        CUSTOM_COLLECTOR_MIN_POLL_INTERVAL_SECS, CUSTOM_COLLECTOR_PREVIEW_MAX_BYTES,
        CUSTOM_COLLECTOR_PREVIEW_MAX_EVENTS, CUSTOM_COLLECTOR_PREVIEW_MAX_RUN_SECS,
    },
    CollectorRun, CollectorRuntime, IntegrationRepository, StreamProvisionReport,
    StreamProvisioner,
};

use crate::handlers::repository_target_authz::held_target_grants;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
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

/// Definition of a user-authored, bounded scheduled API collector. This is
/// deliberately separate from an instance: one definition can have many
/// connections, each with its own encrypted credentials and cursor state.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CustomCollectorDefinitionRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub code: String,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub allowed_domain_suffixes: Vec<String>,
    #[serde(default)]
    pub credential_fields: Vec<CredentialFieldDef>,
    #[serde(default)]
    pub config_fields: Vec<ConfigFieldDef>,
    #[serde(default)]
    pub auth_type: Option<String>,
    #[serde(default)]
    pub auth: Option<ManifestAuth>,
    pub streams: Vec<StreamDef>,
    /// Five- or six-field cron. Custom collectors cannot run more frequently
    /// than every 15 minutes.
    pub poll_schedule: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CustomCollectorDefinitionResponse {
    #[schema(value_type = String)]
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub code: String,
    pub allowed_domains: Vec<String>,
    pub allowed_domain_suffixes: Vec<String>,
    pub credential_fields: Vec<CredentialFieldDef>,
    pub config_fields: Vec<ConfigFieldDef>,
    pub auth_type: Option<String>,
    pub auth: Option<ManifestAuth>,
    pub streams: Vec<StreamDef>,
    pub poll_schedule: String,
    pub max_run_secs: u64,
    pub max_events_per_emit: usize,
    pub max_events_per_run: u64,
    pub max_bytes_per_run: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CustomCollectorValidationResponse {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Transient values used to exercise authored code. Credentials are passed
/// directly to the sandbox and are never persisted or returned.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CustomCollectorPreviewRequest {
    pub definition: CustomCollectorDefinitionRequest,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(default)]
    pub credentials: HashMap<String, String>,
    #[serde(default)]
    pub enabled_streams: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CustomCollectorPreviewEventResponse {
    pub stream: String,
    pub source_type: String,
    pub event: serde_json::Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CustomCollectorPreviewResponse {
    pub status: String,
    pub events: Vec<CustomCollectorPreviewEventResponse>,
    pub events_emitted: u64,
    pub bytes_emitted: u64,
    pub checkpoints: u64,
    pub duration_ms: u64,
    pub budget_exhausted: bool,
    pub error: Option<String>,
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

fn require_definition_code(auth: &AuthContext) -> Result<(), ApiError> {
    ensure_permission(auth, permissions::ENRICHMENTS_CODE)
}

fn is_custom_collector(entry: &MarketplaceCatalogEntry) -> bool {
    entry.source_type == "custom"
        && entry.category == "collector"
        && entry.execution_backend == "collector"
}

fn custom_definition_response(
    entry: MarketplaceCatalogEntry,
) -> Result<CustomCollectorDefinitionResponse, ApiError> {
    if !is_custom_collector(&entry) {
        return Err(ApiError::NotFound(
            "custom integration definition not found".to_string(),
        ));
    }
    let manifest: CollectorManifest = serde_json::from_value(entry.config.0.clone())
        .map_err(|e| ApiError::InternalError(format!("unreadable collector manifest: {e}")))?;
    let credential_fields: Vec<CredentialFieldDef> =
        serde_json::from_value(entry.credential_fields.0.clone()).map_err(|e| {
            ApiError::InternalError(format!("unreadable collector credential fields: {e}"))
        })?;
    let poll_schedule = manifest.effective_schedule();
    let max_run_secs = manifest.effective_max_run_secs();
    let max_events_per_emit = manifest.effective_max_events_per_emit();
    let max_events_per_run = manifest.effective_max_events_per_run();
    let max_bytes_per_run = manifest.effective_max_bytes_per_run();
    Ok(CustomCollectorDefinitionResponse {
        id: entry.id,
        slug: entry.slug,
        name: entry.name,
        description: entry.description,
        code: entry.code.unwrap_or_default(),
        allowed_domains: entry.allowed_domains,
        allowed_domain_suffixes: manifest.allowed_domain_suffixes,
        credential_fields,
        config_fields: manifest.config_fields,
        auth_type: manifest.auth_type,
        auth: manifest.auth,
        streams: manifest.streams,
        poll_schedule,
        max_run_secs,
        max_events_per_emit,
        max_events_per_run,
        max_bytes_per_run,
        created_at: entry.created_at,
        updated_at: entry.updated_at,
    })
}

fn identifier_is_safe(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn validate_custom_schedule(schedule: &str) -> Result<(), String> {
    let schedule = schedule.trim();
    if schedule.split_whitespace().count() != 5 {
        return Err("poll_schedule must use five cron fields (minute through weekday)".to_string());
    }
    let normalized = nanosiem_core::scheduler::normalize_cron(schedule);
    let parsed = cron::Schedule::from_str(&normalized)
        .map_err(|e| format!("poll_schedule is not a valid cron expression: {e}"))?;
    let mut upcoming = parsed.after(&chrono::Utc::now());
    let mut previous = upcoming
        .next()
        .ok_or_else(|| "poll_schedule has no future runs".to_string())?;

    // Cron fields form repeating cartesian sets. Checking a representative
    // sequence (rather than only the first gap) catches boundary patterns such
    // as minutes `0,55`, whose first observed gap can be 55m and the next 5m.
    for next in upcoming.take(512) {
        if (next - previous).num_seconds() < CUSTOM_COLLECTOR_MIN_POLL_INTERVAL_SECS {
            return Err(
                "custom API collectors cannot run more often than every 15 minutes".to_string(),
            );
        }
        previous = next;
    }
    Ok(())
}

fn validate_custom_backfill(
    backfill_from: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(), ApiError> {
    let Some(backfill_from) = backfill_from else {
        return Ok(());
    };
    let now = chrono::Utc::now();
    if backfill_from > now {
        return Err(ApiError::BadRequest(
            "backfill_from cannot be in the future".to_string(),
        ));
    }
    if backfill_from < now - chrono::Duration::days(CUSTOM_COLLECTOR_MAX_BACKFILL_DAYS) {
        return Err(ApiError::BadRequest(format!(
            "custom API collector backfill is limited to {CUSTOM_COLLECTOR_MAX_BACKFILL_DAYS} days"
        )));
    }
    Ok(())
}

fn validate_definition_shape(request: &CustomCollectorDefinitionRequest) -> Vec<String> {
    let mut errors = Vec::new();
    if request.name.trim().is_empty() || request.name.trim().len() > 200 {
        errors.push("name must be between 1 and 200 characters".to_string());
    }
    if !request.name.chars().any(char::is_alphanumeric) {
        errors.push("name must contain at least one letter or number".to_string());
    }
    if request
        .description
        .as_ref()
        .is_some_and(|description| description.len() > 4_000)
    {
        errors.push("description cannot exceed 4000 characters".to_string());
    }
    if request.code.trim().is_empty() {
        errors.push("collector code is required".to_string());
    }
    if request.code.len() > CUSTOM_COLLECTOR_MAX_CODE_BYTES {
        errors.push(format!(
            "collector code cannot exceed {CUSTOM_COLLECTOR_MAX_CODE_BYTES} bytes"
        ));
    }
    if !request.code.contains("export async function collect")
        && !request.code.contains("export function collect")
    {
        errors.push("code must export a collect(ctx) function".to_string());
    }
    if request.allowed_domains.len() > 20 || request.allowed_domain_suffixes.len() > 20 {
        errors.push("at most 20 static domains and 20 domain suffixes are allowed".to_string());
    }
    if request.credential_fields.len() > 20 || request.config_fields.len() > 20 {
        errors.push("at most 20 credential fields and 20 config fields are allowed".to_string());
    }
    if request.streams.is_empty() || request.streams.len() > 20 {
        errors.push("between 1 and 20 streams are required".to_string());
    } else if !request.streams.iter().any(|stream| stream.default) {
        errors.push("at least one stream must be enabled by default".to_string());
    }
    if request.allowed_domains.is_empty()
        && !request
            .config_fields
            .iter()
            .any(|field| field.field_type == "hostname")
    {
        errors.push(
            "declare at least one static API domain or a hostname connection field".to_string(),
        );
    }

    let mut names = HashSet::new();
    for field in &request.credential_fields {
        if !identifier_is_safe(&field.name) {
            errors.push(format!(
                "credential field {:?} has an invalid name",
                field.name
            ));
        }
        if !names.insert(field.name.as_str()) {
            errors.push(format!("credential field {:?} is duplicated", field.name));
        }
        if !matches!(field.field_type.as_str(), "secret" | "string") {
            errors.push(format!(
                "credential field {:?} must use type secret or string",
                field.name
            ));
        }
        if field.label.trim().is_empty() || field.label.len() > 200 {
            errors.push(format!(
                "credential field {:?} needs a label of at most 200 characters",
                field.name
            ));
        }
        if field.help.as_ref().is_some_and(|help| help.len() > 1_000) {
            errors.push(format!(
                "credential field {:?} help cannot exceed 1000 characters",
                field.name
            ));
        }
    }

    names.clear();
    for field in &request.config_fields {
        if !identifier_is_safe(&field.name) {
            errors.push(format!("config field {:?} has an invalid name", field.name));
        }
        if !names.insert(field.name.as_str()) {
            errors.push(format!("config field {:?} is duplicated", field.name));
        }
        if !matches!(
            field.field_type.as_str(),
            "string" | "hostname" | "number" | "boolean"
        ) {
            errors.push(format!(
                "config field {:?} has an unsupported type",
                field.name
            ));
        }
        if field.label.trim().is_empty() || field.label.len() > 200 {
            errors.push(format!(
                "config field {:?} needs a label of at most 200 characters",
                field.name
            ));
        }
        if field.help.as_ref().is_some_and(|help| help.len() > 1_000)
            || field
                .placeholder
                .as_ref()
                .is_some_and(|placeholder| placeholder.len() > 1_000)
        {
            errors.push(format!(
                "config field {:?} help and placeholder cannot exceed 1000 characters",
                field.name
            ));
        }
        if field.field_type == "hostname" && request.allowed_domain_suffixes.is_empty() {
            errors.push(format!(
                "hostname config field {:?} requires an allowed domain suffix",
                field.name
            ));
        }
    }

    names.clear();
    for stream in &request.streams {
        if !identifier_is_safe(&stream.id) {
            errors.push(format!("stream {:?} has an invalid id", stream.id));
        }
        if !names.insert(stream.id.as_str()) {
            errors.push(format!("stream {:?} is duplicated", stream.id));
        }
        if !identifier_is_safe(&stream.source_type) {
            errors.push(format!("stream {:?} has an invalid source_type", stream.id));
        }
        if stream.label.trim().is_empty() {
            errors.push(format!("stream {:?} needs a label", stream.id));
        }
        if stream.label.len() > 200
            || stream
                .description
                .as_ref()
                .is_some_and(|description| description.len() > 1_000)
        {
            errors.push(format!(
                "stream {:?} label or description is too long",
                stream.id
            ));
        }
        if stream
            .parser
            .as_ref()
            .is_some_and(|parser| !identifier_is_safe(parser))
        {
            errors.push(format!("stream {:?} has an invalid parser name", stream.id));
        }
    }

    if let Err(error) = validate_suffixes(&request.allowed_domain_suffixes) {
        errors.push(error.to_string());
    }
    if let Err(error) = validate_custom_schedule(&request.poll_schedule) {
        errors.push(error);
    }
    errors.extend(validate_auth_shape(request));
    errors
}

fn validate_auth_shape(request: &CustomCollectorDefinitionRequest) -> Vec<String> {
    let mut errors = Vec::new();
    let fields: HashSet<&str> = request
        .credential_fields
        .iter()
        .map(|field| field.name.as_str())
        .collect();
    let require_field = |value: Option<&String>, label: &str, errors: &mut Vec<String>| match value
    {
        Some(value) if fields.contains(value.as_str()) => {}
        Some(value) => errors.push(format!(
            "{label} references unknown credential field {value:?}"
        )),
        None => errors.push(format!("{label} is required for this auth type")),
    };
    let auth = request.auth.as_ref();
    match request.auth_type.as_deref().unwrap_or("none") {
        "none" => {}
        "bearer" => require_field(
            auth.and_then(|auth| auth.credential_field.as_ref()),
            "auth.credential_field",
            &mut errors,
        ),
        "api_key_header" => {
            require_field(
                auth.and_then(|auth| auth.credential_field.as_ref()),
                "auth.credential_field",
                &mut errors,
            );
            match auth.and_then(|auth| auth.header_name.as_deref()) {
                Some(name) if HeaderName::from_bytes(name.as_bytes()).is_ok() => {}
                Some(_) => {
                    errors.push("auth.header_name must be a valid HTTP header name".to_string())
                }
                None => errors
                    .push("auth.header_name is required for API key authentication".to_string()),
            }
        }
        "basic_auth" => {
            require_field(
                auth.and_then(|auth| auth.username_field.as_ref()),
                "auth.username_field",
                &mut errors,
            );
            require_field(
                auth.and_then(|auth| auth.password_field.as_ref()),
                "auth.password_field",
                &mut errors,
            );
        }
        "oauth2_client_credentials" => {
            require_field(
                auth.and_then(|auth| auth.client_id_field.as_ref()),
                "auth.client_id_field",
                &mut errors,
            );
            require_field(
                auth.and_then(|auth| auth.client_secret_field.as_ref()),
                "auth.client_secret_field",
                &mut errors,
            );
            if auth.and_then(|auth| auth.token_url.as_deref()).is_none() {
                errors.push("auth.token_url is required for OAuth2".to_string());
            }
        }
        unsupported => errors.push(format!("unsupported auth_type {unsupported:?}")),
    }
    errors
}

async fn validate_definition(
    request: &CustomCollectorDefinitionRequest,
) -> CustomCollectorValidationResponse {
    let mut errors = validate_definition_shape(request);
    if errors.is_empty() {
        if let Err(error) = validate_allowed_domains(&request.allowed_domains).await {
            errors.push(error.to_string());
        }
    }
    if errors.is_empty() {
        if let Some(token_url) = request
            .auth
            .as_ref()
            .and_then(|auth| auth.token_url.as_deref())
        {
            if let Err(error) = validate_token_url(token_url).await {
                errors.push(error.to_string());
            } else if let Ok(url) = reqwest::Url::parse(token_url) {
                let token_host = url.host_str().unwrap_or_default();
                let admitted = request.allowed_domains.iter().any(|domain| {
                    domain
                        .trim()
                        .split(':')
                        .next()
                        .is_some_and(|host| host.eq_ignore_ascii_case(token_host))
                });
                if !admitted {
                    errors.push(
                        "the OAuth2 token host must also appear in allowed_domains".to_string(),
                    );
                }
            }
        }
    }
    if errors.is_empty() {
        match SandboxExecutor::new().check_syntax(&request.code).await {
            Ok(result) if result.success => {}
            Ok(result) => errors.push(
                result
                    .error
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| result.stderr.trim().to_string()),
            ),
            Err(error) => errors.push(error.to_string()),
        }
    }
    CustomCollectorValidationResponse {
        valid: errors.is_empty(),
        errors,
        warnings: vec![
            "Custom integrations are for bounded scheduled API harvesting. Use a dedicated ingestion source for bulk files, streams, or firehose workloads."
                .to_string(),
        ],
    }
}

fn definition_manifest(request: &CustomCollectorDefinitionRequest) -> serde_json::Value {
    serde_json::json!({
        "streams": request.streams,
        "config_fields": request.config_fields,
        "allowed_domain_suffixes": request.allowed_domain_suffixes,
        "auth_type": request.auth_type,
        "auth": request.auth,
        "poll_schedule": request.poll_schedule,
        "max_run_secs": CUSTOM_COLLECTOR_MAX_RUN_SECS,
        "max_events_per_emit": CUSTOM_COLLECTOR_MAX_EVENTS_PER_EMIT,
        "max_events_per_run": CUSTOM_COLLECTOR_MAX_EVENTS_PER_RUN,
        "max_bytes_per_run": CUSTOM_COLLECTOR_MAX_BYTES_PER_RUN,
    })
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
fn validate_config(
    manifest: &CollectorManifest,
    config: &serde_json::Value,
) -> Result<(), ApiError> {
    let map = config
        .as_object()
        .ok_or_else(|| ApiError::BadRequest("config must be a JSON object".to_string()))?;

    for field in &manifest.config_fields {
        if field.required {
            let present = map
                .get(&field.name)
                .map(|value| match value {
                    serde_json::Value::Null => false,
                    serde_json::Value::String(value) => !value.trim().is_empty(),
                    _ => true,
                })
                .unwrap_or(false);
            if !present {
                return Err(ApiError::BadRequest(format!(
                    "config field {} is required",
                    field.name
                )));
            }
        }

        if let Some(value) = map.get(&field.name) {
            let valid_type = match field.field_type.as_str() {
                "string" | "hostname" => value.is_string(),
                "number" => value.is_number(),
                "boolean" => value.is_boolean(),
                // Repository manifests predate custom authoring and may carry
                // a UI-specific type. Their authoring path validates those;
                // do not break existing installed instances here.
                _ => true,
            };
            if !valid_type {
                return Err(ApiError::BadRequest(format!(
                    "config field {} must be a {}",
                    field.name, field.field_type
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

fn validate_credential_values(
    fields: &[CredentialFieldDef],
    credentials: Option<&HashMap<String, String>>,
) -> Result<(), ApiError> {
    let empty = HashMap::new();
    let credentials = credentials.unwrap_or(&empty);

    for key in credentials.keys() {
        if !fields.iter().any(|field| &field.name == key) {
            return Err(ApiError::BadRequest(format!(
                "unknown credential field {key:?} for this integration"
            )));
        }
    }
    for field in fields {
        let value = credentials.get(&field.name).map(|value| value.trim());
        if field.required && value.is_none_or(str::is_empty) {
            return Err(ApiError::BadRequest(format!(
                "credential field {} is required",
                field.name
            )));
        }
        if credentials
            .get(&field.name)
            .is_some_and(|value| value.len() > 64 * 1024)
        {
            return Err(ApiError::BadRequest(format!(
                "credential field {} exceeds 64 KiB",
                field.name
            )));
        }
    }
    Ok(())
}

// =============================================================================
// Handlers
// =============================================================================

#[utoipa::path(
    post,
    path = "/api/integrations/custom/validate",
    tag = "integrations",
    request_body = CustomCollectorDefinitionRequest,
    responses((status = 200, body = CustomCollectorValidationResponse), (status = 400)),
    security(("api_key" = []))
)]
pub async fn validate_custom_collector(
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<CustomCollectorDefinitionRequest>,
) -> Result<Json<CustomCollectorValidationResponse>, ApiError> {
    ensure_permission(&auth, permissions::LOG_SOURCES_CREATE)?;
    require_definition_code(&auth)?;
    Ok(Json(validate_definition(&request).await))
}

#[utoipa::path(
    post,
    path = "/api/integrations/custom/preview",
    tag = "integrations",
    request_body = CustomCollectorPreviewRequest,
    responses((status = 200, body = CustomCollectorPreviewResponse), (status = 400)),
    security(("api_key" = []))
)]
pub async fn preview_custom_collector(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<CustomCollectorPreviewRequest>,
) -> Result<Json<CustomCollectorPreviewResponse>, ApiError> {
    ensure_permission(&auth, permissions::LOG_SOURCES_CREATE)?;
    require_definition_code(&auth)?;
    if !request.credentials.is_empty() {
        require_credential_write(&auth)?;
    }

    let validation = validate_definition(&request.definition).await;
    if !validation.valid {
        return Err(ApiError::ValidationError(validation.errors.join("; ")));
    }
    validate_credential_values(
        &request.definition.credential_fields,
        Some(&request.credentials),
    )?;

    let config = if request.config.is_null() {
        serde_json::json!({})
    } else {
        request.config
    };
    let mut manifest: CollectorManifest =
        serde_json::from_value(definition_manifest(&request.definition))
            .map_err(|e| ApiError::InternalError(format!("collector manifest: {e}")))?;
    manifest.max_run_secs = Some(CUSTOM_COLLECTOR_PREVIEW_MAX_RUN_SECS);
    manifest.max_events_per_emit = Some(CUSTOM_COLLECTOR_PREVIEW_MAX_EVENTS as usize);
    manifest.max_events_per_run = Some(CUSTOM_COLLECTOR_PREVIEW_MAX_EVENTS);
    manifest.max_bytes_per_run = Some(CUSTOM_COLLECTOR_PREVIEW_MAX_BYTES);
    validate_config(&manifest, &config)?;

    let streams = if request.enabled_streams.is_empty() {
        manifest.default_stream_ids()
    } else {
        request.enabled_streams
    };
    validate_streams(&manifest, &streams)?;
    let allowed_domains =
        resolve_allowed_domains(&manifest, &request.definition.allowed_domains, &config).await?;
    let auth_config = build_auth_config(&manifest, &request.credentials, &config);
    let run = CollectorRun {
        instance_id: Uuid::nil(),
        slug: "custom-preview",
        code: &request.definition.code,
        manifest: &manifest,
        streams,
        cursors: HashMap::new(),
        credentials: request.credentials,
        config,
        allowed_domains,
        auth_config,
        backfill_from: None,
    };
    let preview = CollectorRuntime::new(VectorIngestClient::from_env())
        .preview(run)
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, CUSTOM_INTEGRATION_PREVIEWED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "custom_integration",
                None,
                Some(request.definition.name.clone()),
            )
            .client_context(&client)
            .details(serde_json::json!({
                "status": preview.outcome.status().as_str(),
                "events_emitted": preview.outcome.events_emitted,
                "bytes_emitted": preview.outcome.bytes_emitted,
                "duration_ms": preview.outcome.duration_ms,
            }))
            .build(),
    );

    Ok(Json(CustomCollectorPreviewResponse {
        status: preview.outcome.status().as_str().to_string(),
        events: preview
            .events
            .into_iter()
            .map(|event| CustomCollectorPreviewEventResponse {
                stream: event.stream,
                source_type: event.source_type,
                event: event.event,
            })
            .collect(),
        events_emitted: preview.outcome.events_emitted,
        bytes_emitted: preview.outcome.bytes_emitted,
        checkpoints: preview.outcome.checkpoints,
        duration_ms: preview.outcome.duration_ms,
        budget_exhausted: preview.outcome.budget_exhausted,
        error: preview.outcome.error,
    }))
}

#[utoipa::path(
    post,
    path = "/api/integrations/custom",
    tag = "integrations",
    request_body = CustomCollectorDefinitionRequest,
    responses((status = 200, body = CustomCollectorDefinitionResponse), (status = 400), (status = 409)),
    security(("api_key" = []))
)]
pub async fn create_custom_collector(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<CustomCollectorDefinitionRequest>,
) -> Result<Json<CustomCollectorDefinitionResponse>, ApiError> {
    ensure_permission(&auth, permissions::LOG_SOURCES_CREATE)?;
    require_definition_code(&auth)?;

    let validation = validate_definition(&request).await;
    if !validation.valid {
        return Err(ApiError::ValidationError(validation.errors.join("; ")));
    }
    let repository = MarketplaceRepository::new(state.pool.clone());
    let credential_fields = serde_json::to_value(&request.credential_fields)
        .map_err(|e| ApiError::InternalError(format!("serialize credential fields: {e}")))?;
    let manifest = definition_manifest(&request);
    let entry = repository
        .create_catalog_for_custom_collector(
            request.name.trim(),
            request.description.as_deref(),
            &request.code,
            &request.allowed_domains,
            &credential_fields,
            &manifest,
        )
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, CUSTOM_INTEGRATION_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "custom_integration",
                Some(entry.id),
                Some(entry.name.clone()),
            )
            .client_context(&client)
            .details(serde_json::json!({
                "max_events_per_run": CUSTOM_COLLECTOR_MAX_EVENTS_PER_RUN,
                "max_bytes_per_run": CUSTOM_COLLECTOR_MAX_BYTES_PER_RUN,
                "poll_schedule": request.poll_schedule,
            }))
            .build(),
    );

    Ok(Json(custom_definition_response(entry)?))
}

#[utoipa::path(
    get,
    path = "/api/integrations/custom/{id}",
    tag = "integrations",
    params(("id" = String, Path, description = "Custom integration catalog id")),
    responses((status = 200, body = CustomCollectorDefinitionResponse), (status = 404)),
    security(("api_key" = []))
)]
pub async fn get_custom_collector(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<CustomCollectorDefinitionResponse>, ApiError> {
    require_view(&auth)?;
    require_definition_code(&auth)?;
    let entry = MarketplaceRepository::new(state.pool.clone())
        .get_catalog_entry_by_id(id.into_uuid())
        .await?;
    Ok(Json(custom_definition_response(entry)?))
}

#[utoipa::path(
    put,
    path = "/api/integrations/custom/{id}",
    tag = "integrations",
    params(("id" = String, Path, description = "Custom integration catalog id")),
    request_body = CustomCollectorDefinitionRequest,
    responses((status = 200, body = CustomCollectorDefinitionResponse), (status = 400), (status = 404), (status = 409)),
    security(("api_key" = []))
)]
pub async fn update_custom_collector(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<CustomCollectorDefinitionRequest>,
) -> Result<Json<CustomCollectorDefinitionResponse>, ApiError> {
    require_write(&auth)?;
    require_definition_code(&auth)?;
    let id = id.into_uuid();
    let validation = validate_definition(&request).await;
    if !validation.valid {
        return Err(ApiError::ValidationError(validation.errors.join("; ")));
    }
    let repository = MarketplaceRepository::new(state.pool.clone());
    let credential_fields = serde_json::to_value(&request.credential_fields)
        .map_err(|e| ApiError::InternalError(format!("serialize credential fields: {e}")))?;
    let entry = repository
        .update_catalog_for_custom_collector(
            id,
            request.name.trim(),
            request.description.as_deref(),
            &request.code,
            &request.allowed_domains,
            &credential_fields,
            &definition_manifest(&request),
        )
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, CUSTOM_INTEGRATION_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "custom_integration",
                Some(entry.id),
                Some(entry.name.clone()),
            )
            .client_context(&client)
            .build(),
    );
    Ok(Json(custom_definition_response(entry)?))
}

#[utoipa::path(
    delete,
    path = "/api/integrations/custom/{id}",
    tag = "integrations",
    params(("id" = String, Path, description = "Custom integration catalog id")),
    responses((status = 204), (status = 404), (status = 409)),
    security(("api_key" = []))
)]
pub async fn delete_custom_collector(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<axum::http::StatusCode, ApiError> {
    ensure_permission(&auth, permissions::LOG_SOURCES_DELETE)?;
    require_definition_code(&auth)?;
    let id = id.into_uuid();
    let marketplace = MarketplaceRepository::new(state.pool.clone());
    let entry = marketplace.get_catalog_entry_by_id(id).await?;
    if !is_custom_collector(&entry) {
        return Err(ApiError::NotFound(
            "custom integration definition not found".to_string(),
        ));
    }
    let instances = IntegrationRepository::new(state.pool.clone())
        .list_instances(Some(id))
        .await?;
    if !instances.is_empty() {
        return Err(ApiError::Conflict(
            "delete this integration's connections before deleting its definition".to_string(),
        ));
    }
    marketplace.delete_catalog_for_custom_collector(id).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, CUSTOM_INTEGRATION_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("custom_integration", Some(id), Some(entry.name))
            .client_context(&client)
            .build(),
    );
    Ok(axum::http::StatusCode::NO_CONTENT)
}

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
    let custom_collector = is_custom_collector(&entry);
    let credential_fields: Vec<CredentialFieldDef> =
        serde_json::from_value(entry.credential_fields.0.clone()).map_err(|e| {
            ApiError::InternalError(format!("unreadable collector credential fields: {e}"))
        })?;
    validate_credential_values(&credential_fields, request.credentials.as_ref())?;

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

    let schedule = if custom_collector {
        let schedule = request
            .schedule
            .clone()
            .unwrap_or_else(|| manifest.effective_schedule());
        validate_custom_schedule(&schedule).map_err(ApiError::BadRequest)?;
        Some(schedule)
    } else {
        request.schedule.clone()
    };
    if custom_collector {
        validate_custom_backfill(request.backfill_from)?;
    }

    let instance = repo
        .create_instance(
            entry.id,
            &request.name,
            &config,
            encrypted
                .as_ref()
                .map(|(ct, n)| (ct.as_slice(), n.as_str())),
            &streams,
            schedule.as_deref(),
            request.backfill_from,
            Some(auth.user_id()),
        )
        .await?;

    // Enablement is a separate step so a half-configured instance never starts
    // pulling; `create` then `update(enabled)` keeps the audit trail explicit.
    let instance = if request.enabled {
        repo.update_instance(instance.id, None, Some(true), None, None, None, None, None)
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
    let catalog_entry = marketplace
        .get_catalog_entry_by_id(existing.catalog_id)
        .await?;
    let custom_collector = is_custom_collector(&catalog_entry);
    let manifest = load_manifest(&marketplace, existing.catalog_id).await?;

    if let Some(config) = &request.config {
        validate_config(&manifest, config)?;
    }
    if let Some(streams) = &request.enabled_streams {
        validate_streams(&manifest, streams)?;
    }
    if request.credentials.is_some() {
        let credential_fields: Vec<CredentialFieldDef> =
            serde_json::from_value(catalog_entry.credential_fields.0.clone()).map_err(|e| {
                ApiError::InternalError(format!("unreadable collector credential fields: {e}"))
            })?;
        validate_credential_values(&credential_fields, request.credentials.as_ref())?;
    }

    let encrypted = request
        .credentials
        .as_ref()
        .map(encrypt_credentials)
        .transpose()?;

    let schedule_update: Option<Option<String>> = match request.schedule.as_ref() {
        Some(Some(schedule)) if custom_collector => {
            validate_custom_schedule(schedule).map_err(ApiError::BadRequest)?;
            Some(Some(schedule.clone()))
        }
        Some(None) if custom_collector => Some(Some(manifest.effective_schedule())),
        Some(schedule) => Some(schedule.clone()),
        None => None,
    };
    if custom_collector {
        if let Some(backfill) = request.backfill_from.as_ref() {
            validate_custom_backfill(*backfill)?;
        }
    }

    let instance = repo
        .update_instance(
            existing.id,
            request.name.as_deref(),
            request.enabled,
            request.config.as_ref(),
            encrypted
                .as_ref()
                .map(|(ct, n)| (ct.as_slice(), n.as_str())),
            request.enabled_streams.as_deref(),
            schedule_update.as_ref().map(|schedule| schedule.as_deref()),
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
        validate_custom_collector,
        preview_custom_collector,
        create_custom_collector,
        get_custom_collector,
        update_custom_collector,
        delete_custom_collector,
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
        TriggerRunResponse,
        CustomCollectorDefinitionRequest,
        CustomCollectorDefinitionResponse,
        CustomCollectorValidationResponse,
        CustomCollectorPreviewRequest,
        CustomCollectorPreviewEventResponse,
        CustomCollectorPreviewResponse,
        CredentialFieldDef,
        ConfigFieldDef,
        ManifestAuth,
        StreamDef
    ))
)]
pub struct IntegrationsApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_definition() -> CustomCollectorDefinitionRequest {
        CustomCollectorDefinitionRequest {
            name: "Acme audit events".to_string(),
            description: None,
            code: "export async function collect(_ctx: unknown): Promise<void> {}".to_string(),
            allowed_domains: vec!["api.example.com".to_string()],
            allowed_domain_suffixes: Vec::new(),
            credential_fields: vec![CredentialFieldDef {
                name: "TOKEN".to_string(),
                label: "Token".to_string(),
                field_type: "secret".to_string(),
                required: true,
                help: None,
            }],
            config_fields: Vec::new(),
            auth_type: Some("bearer".to_string()),
            auth: Some(ManifestAuth {
                credential_field: Some("TOKEN".to_string()),
                ..Default::default()
            }),
            streams: vec![StreamDef {
                id: "events".to_string(),
                label: "Events".to_string(),
                source_type: "acme_events".to_string(),
                parser: None,
                default: true,
                description: None,
            }],
            poll_schedule: "*/15 * * * *".to_string(),
        }
    }

    #[test]
    fn custom_schedule_refuses_sub_fifteen_minute_polls() {
        assert!(validate_custom_schedule("*/5 * * * *").is_err());
        assert!(validate_custom_schedule("0,55 * * * *").is_err());
        assert!(validate_custom_schedule("0 */15 * * * *").is_err());
        assert!(validate_custom_schedule("*/15 * * * *").is_ok());
        assert!(validate_custom_schedule("0 * * * *").is_ok());
    }

    #[test]
    fn definition_rejects_an_empty_normalized_slug_and_oversized_code() {
        let mut request = valid_definition();
        request.name = "---".to_string();
        request.code = "x".repeat(CUSTOM_COLLECTOR_MAX_CODE_BYTES + 1);
        let errors = validate_definition_shape(&request);
        assert!(errors
            .iter()
            .any(|error| error.contains("letter or number")));
        assert!(errors.iter().any(|error| error.contains("cannot exceed")));
    }

    #[test]
    fn preview_credentials_must_match_the_declared_contract() {
        let request = valid_definition();
        assert!(validate_credential_values(&request.credential_fields, None).is_err());

        let unknown = HashMap::from([("WRONG".to_string(), "secret".to_string())]);
        assert!(validate_credential_values(&request.credential_fields, Some(&unknown)).is_err());

        let valid = HashMap::from([("TOKEN".to_string(), "secret".to_string())]);
        assert!(validate_credential_values(&request.credential_fields, Some(&valid)).is_ok());
    }

    #[test]
    fn api_key_auth_requires_a_valid_header_name() {
        let mut request = valid_definition();
        request.auth_type = Some("api_key_header".to_string());
        request.auth = Some(ManifestAuth {
            credential_field: Some("TOKEN".to_string()),
            header_name: Some("bad header".to_string()),
            ..Default::default()
        });
        assert!(validate_definition_shape(&request)
            .iter()
            .any(|error| error.contains("valid HTTP header")));
    }

    #[test]
    fn definition_requires_an_api_egress_shape() {
        let mut request = valid_definition();
        request.allowed_domains.clear();
        let errors = validate_definition_shape(&request);
        assert!(errors
            .iter()
            .any(|error| error.contains("static API domain")));

        request.config_fields.push(ConfigFieldDef {
            name: "TENANT_HOST".to_string(),
            label: "Tenant host".to_string(),
            field_type: "hostname".to_string(),
            required: true,
            help: None,
            placeholder: None,
        });
        request.allowed_domain_suffixes = vec![".example.com".to_string()];
        assert!(validate_definition_shape(&request).is_empty());
    }

    #[test]
    fn custom_manifest_always_carries_the_bounded_lane_limits() {
        let manifest: CollectorManifest =
            serde_json::from_value(definition_manifest(&valid_definition())).unwrap();
        assert_eq!(
            manifest.effective_max_run_secs(),
            CUSTOM_COLLECTOR_MAX_RUN_SECS
        );
        assert_eq!(
            manifest.effective_max_events_per_emit(),
            CUSTOM_COLLECTOR_MAX_EVENTS_PER_EMIT
        );
        assert_eq!(
            manifest.effective_max_events_per_run(),
            CUSTOM_COLLECTOR_MAX_EVENTS_PER_RUN
        );
        assert_eq!(
            manifest.effective_max_bytes_per_run(),
            CUSTOM_COLLECTOR_MAX_BYTES_PER_RUN
        );
    }

    #[test]
    fn custom_backfill_is_bounded_and_cannot_point_forward() {
        assert!(
            validate_custom_backfill(Some(chrono::Utc::now() + chrono::Duration::hours(1)))
                .is_err()
        );
        assert!(validate_custom_backfill(Some(
            chrono::Utc::now() - chrono::Duration::days(CUSTOM_COLLECTOR_MAX_BACKFILL_DAYS + 1)
        ))
        .is_err());
        assert!(
            validate_custom_backfill(Some(chrono::Utc::now() - chrono::Duration::days(1))).is_ok()
        );
    }
}
