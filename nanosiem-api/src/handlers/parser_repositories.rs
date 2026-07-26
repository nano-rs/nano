// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser Repository endpoint handlers
//!
//! Implements endpoints for managing external parser repositories,
//! syncing parser definitions from GitHub, and importing parsers as log sources.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, LOG_SOURCE_CREATED, LOG_SOURCE_UPDATED,
    PARSER_ALL_REMOVED, PARSER_BATCH_IMPORTED, PARSER_IMPORTED, PARSER_REPO_CREATED,
    PARSER_REPO_DELETED, PARSER_REPO_SYNCED, PARSER_REPO_UPDATED, PARSER_UPSTREAM_APPLIED,
    ROUTING_RULE_CREATED,
};
use nanosiem_core::auth::{permissions, TargetEffect};
use nanosiem_core::parser_repository::{
    ApplyUpstreamUpdateResult, BulkApplyUpstreamResult, NewParserRepository, ParserImportPreview,
    ParserImportRequest, ParserImportType, ParserRepository, ParserRepositoryService,
    RepositoryParser, RepositoryParserFilter, UpdateParserRepository,
    UpstreamParserDiff,
};
use nanosiem_core::typeid::TypeIdParam;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use futures::StreamExt;

use super::AuditExt;
use crate::handlers::repository_target_authz::{ensure_target_effects, held_target_grants};
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// How many import plans to preflight concurrently. Bounded so a 100-item batch
/// cannot open 100 simultaneous pool connections.
const PLAN_CONCURRENCY: usize = 16;

// =============================================================================
// Request/Response Types
// =============================================================================

/// Response for listing parser repositories
#[derive(Debug, Serialize, ToSchema)]
pub struct ListParserRepositoriesResponse {
    pub repositories: Vec<ParserRepository>,
}

/// Request to create a parser repository
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateParserRepositoryRequest {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub parsers_path: Option<String>,
    #[serde(default)]
    pub auto_sync_enabled: Option<bool>,
    #[serde(default)]
    pub sync_interval_hours: Option<i32>,
}

/// Request to update a parser repository
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateParserRepositoryRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub branch: Option<String>,
    pub parsers_path: Option<String>,
    pub auto_sync_enabled: Option<bool>,
    pub sync_interval_hours: Option<i32>,
    pub enabled: Option<bool>,
}

/// Query parameters for listing parsers
#[derive(Debug, Deserialize, Default, IntoParams)]
pub struct ListParsersQuery {
    pub category: Option<String>,
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Repository parser with import status for API response
#[derive(Debug, Serialize, ToSchema)]
pub struct RepositoryParserResponse {
    #[serde(flatten)]
    pub parser: RepositoryParser,
    pub is_imported: bool,
    #[serde(with = "nanosiem_core::typeid::log_source::opt")]
    #[schema(value_type = Option<String>)]
    pub linked_log_source_id: Option<Uuid>,
}

/// Request to import a parser
#[derive(Debug, Deserialize, ToSchema)]
pub struct ImportParserRequest {
    #[serde(default = "default_import_type")]
    pub import_type: String,
    /// The match value that activates this parser via routing rules (e.g., "apache")
    pub source_type: Option<String>,
    /// Ingestion method: routed, kafka, aws_s3, gcp_pubsub, splunk_hec, vector
    pub ingestion_method: Option<String>,
    /// NAN-928: source-configuration whose route should dispatch events
    /// into this parser. Captured by the parser-import UI's
    /// "DISPATCH FROM" picker. When set, the generator emits a `filter`
    /// on the source-config's `*_route` instead of a parser-owned source.
    #[serde(default, with = "nanosiem_core::typeid::source_config::opt")]
    #[schema(value_type = Option<String>)]
    pub dispatch_source_config_id: Option<uuid::Uuid>,
}

fn default_import_type() -> String {
    "linked".to_string()
}

/// Response for import operation
#[derive(Debug, Serialize, ToSchema)]
pub struct ImportParserResponse {
    #[serde(with = "nanosiem_core::typeid::log_source")]
    #[schema(value_type = String)]
    pub log_source_id: Uuid,
    pub import_type: String,
}

/// A single parser item in a batch import request
#[derive(Debug, Deserialize, ToSchema)]
pub struct BatchImportParserItem {
    pub path: String,
    #[serde(default = "default_import_type")]
    pub import_type: String,
    /// The match value that activates this parser via routing rules (e.g., "apache")
    pub source_type: Option<String>,
    /// Ingestion method: routed, kafka, aws_s3, gcp_pubsub, splunk_hec, vector
    pub ingestion_method: Option<String>,
    /// NAN-928: source-configuration whose route should dispatch events
    /// into this parser. See `ImportParserRequest` for semantics.
    #[serde(default, with = "nanosiem_core::typeid::source_config::opt")]
    #[schema(value_type = Option<String>)]
    pub dispatch_source_config_id: Option<uuid::Uuid>,
}

/// Request body for batch import
#[derive(Debug, Deserialize, ToSchema)]
pub struct BatchImportParsersRequest {
    /// Per-item configuration (preferred). If provided, `paths` and `import_type` are ignored.
    #[serde(default)]
    pub items: Vec<BatchImportParserItem>,
    /// Legacy: flat list of paths (used when `items` is empty)
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default = "default_import_type")]
    pub import_type: String,
}

/// Response for batch import operation
#[derive(Debug, Serialize, ToSchema)]
pub struct BatchImportParsersResponse {
    pub imported: usize,
    pub skipped: usize,
    pub failed: Vec<ParserBatchFailure>,
}

/// A failed import in a batch operation
#[derive(Debug, Serialize, ToSchema)]
pub struct ParserBatchFailure {
    pub path: String,
    pub error: String,
}

/// Response for batch remove operation
#[derive(Debug, Serialize, ToSchema)]
pub struct BatchRemoveParsersResponse {
    pub removed: i32,
    pub failed: i32,
}

/// Response for upstream updates
#[derive(Debug, Serialize, ToSchema)]
pub struct ParserUpstreamUpdatesResponse {
    pub updates: Vec<nanosiem_core::parser_repository::ParserUpstreamUpdate>,
}

/// Response for sync start
#[derive(Debug, Serialize, ToSchema)]
pub struct ParserSyncStartResponse {
    #[serde(with = "nanosiem_core::typeid::parser_repo")]
    #[schema(value_type = String)]
    pub repository_id: Uuid,
    pub status: String,
    pub message: String,
}

/// Response for sync status
#[derive(Debug, Serialize, ToSchema)]
pub struct ParserSyncStatusResponse {
    pub status: Option<String>,
    pub last_synced_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_sync_commit: Option<String>,
    pub last_sync_error: Option<String>,
    pub parser_count: i32,
}

// =============================================================================
// Repository CRUD Handlers
// =============================================================================

/// List all parser repositories
#[utoipa::path(
    get,
    path = "/api/parser-repositories",
    tag = "parser_repositories",
    responses(
        (status = 200, description = "Repositories retrieved successfully", body = ListParserRepositoriesResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_parser_repositories(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ListParserRepositoriesResponse>, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_VIEW)?;

    let service = get_parser_repo_service(&state);
    let repositories = service.list_repositories().await?;

    Ok(Json(ListParserRepositoriesResponse { repositories }))
}

/// Get a single parser repository
#[utoipa::path(
    get,
    path = "/api/parser-repositories/{id}",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "Repository retrieved successfully", body = ParserRepository),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_parser_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ParserRepository>, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_VIEW)?;

    let service = get_parser_repo_service(&state);
    let repository = service.get_repository(*id).await?;

    Ok(Json(repository))
}

/// Create a new parser repository
#[utoipa::path(
    post,
    path = "/api/parser-repositories",
    tag = "parser_repositories",
    request_body = CreateParserRepositoryRequest,
    responses(
        (status = 200, description = "Repository created successfully", body = ParserRepository),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn create_parser_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(req): Json<CreateParserRepositoryRequest>,
) -> Result<Json<ParserRepository>, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_MANAGE)?;

    let service = get_parser_repo_service(&state);

    let new_repo = NewParserRepository {
        name: req.name,
        slug: None,
        description: req.description,
        url: req.url,
        branch: req.branch,
        parsers_path: req.parsers_path,
        auto_sync_enabled: req.auto_sync_enabled,
        sync_interval_hours: req.sync_interval_hours,
    };

    let repository = service
        .create_repository(new_repo, Some(auth.user_id()))
        .await?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::ParserRepo, PARSER_REPO_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "parser_repository",
                Some(repository.id),
                Some(repository.name.clone()),
            )
            .client_context(&client)
            .build(),
    );

    Ok(Json(repository))
}

/// Update a parser repository
#[utoipa::path(
    put,
    path = "/api/parser-repositories/{id}",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    request_body = UpdateParserRepositoryRequest,
    responses(
        (status = 200, description = "Repository updated successfully", body = ParserRepository),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn update_parser_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<UpdateParserRepositoryRequest>,
) -> Result<Json<ParserRepository>, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_MANAGE)?;

    let service = get_parser_repo_service(&state);

    let update = UpdateParserRepository {
        name: req.name,
        description: req.description,
        branch: req.branch,
        parsers_path: req.parsers_path,
        auto_sync_enabled: req.auto_sync_enabled,
        sync_interval_hours: req.sync_interval_hours,
        enabled: req.enabled,
    };

    let repository = service.update_repository(*id, update).await?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::ParserRepo, PARSER_REPO_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "parser_repository",
                Some(repository.id),
                Some(repository.name.clone()),
            )
            .client_context(&client)
            .build(),
    );

    Ok(Json(repository))
}

/// Delete a parser repository
#[utoipa::path(
    delete,
    path = "/api/parser-repositories/{id}",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    responses(
        (status = 204, description = "Repository deleted successfully"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_parser_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_MANAGE)?;

    let service = get_parser_repo_service(&state);
    service.delete_repository(*id).await?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::ParserRepo, PARSER_REPO_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("parser_repository", Some(*id), None)
            .client_context(&client)
            .build(),
    );

    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// Sync Handlers
// =============================================================================

/// Start syncing a parser repository from GitHub (async - returns immediately)
#[utoipa::path(
    post,
    path = "/api/parser-repositories/{id}/sync",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "Sync started", body = ParserSyncStartResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn sync_parser_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ParserSyncStartResponse>, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_SYNC)?;

    let service = get_parser_repo_service(&state);
    let repo = service.get_repository(*id).await?;

    service.start_sync(*id).await?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::ParserRepo, PARSER_REPO_SYNCED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("parser_repository", Some(*id), None)
            .client_context(&client)
            .build(),
    );

    Ok(Json(ParserSyncStartResponse {
        repository_id: *id,
        status: "syncing".to_string(),
        message: format!("Sync started for {}", repo.name),
    }))
}

/// Get sync status for a parser repository
#[utoipa::path(
    get,
    path = "/api/parser-repositories/{id}/sync/status",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "Sync status retrieved successfully", body = ParserSyncStatusResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_parser_sync_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ParserSyncStatusResponse>, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_VIEW)?;

    let service = get_parser_repo_service(&state);
    let repository = service.get_repository(*id).await?;

    Ok(Json(ParserSyncStatusResponse {
        status: repository.last_sync_status,
        last_synced_at: repository.last_synced_at,
        last_sync_commit: repository.last_sync_commit,
        last_sync_error: repository.last_sync_error,
        parser_count: repository.parser_count,
    }))
}

// =============================================================================
// Browse Parsers Handlers
// =============================================================================

/// List parsers in a repository
#[utoipa::path(
    get,
    path = "/api/parser-repositories/{id}/parsers",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Repository ID"),
        ListParsersQuery
    ),
    responses(
        (status = 200, description = "Parsers retrieved successfully", body = Vec<RepositoryParserResponse>),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn list_repository_parsers(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Query(query): Query<ListParsersQuery>,
) -> Result<Json<Vec<RepositoryParserResponse>>, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_VIEW)?;

    let service = get_parser_repo_service(&state);

    let filter = RepositoryParserFilter {
        category: query.category,
        search: query.search,
        limit: query.limit,
        offset: query.offset,
    };

    let parsers = service.list_parsers(*id, &filter).await?;

    // Get import status for all parsers in this repository
    let imports = service.get_imports_for_repository(*id).await?;
    let import_map: std::collections::HashMap<Uuid, Uuid> = imports
        .into_iter()
        .map(|i| (i.repository_parser_id, i.log_source_id))
        .collect();

    let response: Vec<RepositoryParserResponse> = parsers
        .into_iter()
        .map(|parser| {
            let linked_log_source_id = import_map.get(&parser.id).copied();
            RepositoryParserResponse {
                parser,
                is_imported: linked_log_source_id.is_some(),
                linked_log_source_id,
            }
        })
        .collect();

    Ok(Json(response))
}

/// Get a specific parser from a repository by path
#[utoipa::path(
    get,
    path = "/api/parser-repositories/{id}/parsers/by-path/{path}",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Repository ID"),
        ("path" = String, Path, description = "File path")
    ),
    responses(
        (status = 200, description = "Parser retrieved successfully", body = RepositoryParser),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_repository_parser(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path((id, path)): Path<(TypeIdParam, String)>,
) -> Result<Json<RepositoryParser>, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_VIEW)?;

    let service = get_parser_repo_service(&state);
    let parser = service.get_parser(*id, &path).await?;

    Ok(Json(parser))
}

// =============================================================================
// Import Handlers
// =============================================================================

/// Preview importing a parser as a log source
#[utoipa::path(
    get,
    path = "/api/parser-repositories/{id}/parsers/preview/{path}",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Repository ID"),
        ("path" = String, Path, description = "File path")
    ),
    responses(
        (status = 200, description = "Preview generated successfully", body = ParserImportPreview),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn preview_parser_import(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path((id, path)): Path<(TypeIdParam, String)>,
) -> Result<Json<ParserImportPreview>, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_VIEW)?;

    let service = get_parser_repo_service(&state);
    let preview = service.preview_import(*id, &path).await?;

    Ok(Json(preview))
}

/// Import a parser from a repository as a draft log source
#[utoipa::path(
    post,
    path = "/api/parser-repositories/{id}/parsers/import/{path}",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Repository ID"),
        ("path" = String, Path, description = "File path")
    ),
    request_body = ImportParserRequest,
    responses(
        (status = 200, description = "Parser imported successfully", body = ImportParserResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden — missing parser_repositories:import, or the log_sources:create / source_configs:edit capability the import consumes"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn import_parser(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path((id, path)): Path<(TypeIdParam, String)>,
    Json(req): Json<ImportParserRequest>,
) -> Result<Json<ImportParserResponse>, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_IMPORT)?;

    let service = get_parser_repo_service(&state);

    let import_type = match req.import_type.as_str() {
        "forked" => ParserImportType::Forked,
        _ => ParserImportType::Linked,
    };

    let import_request = ParserImportRequest {
        import_type: import_type.clone(),
        source_type: req.source_type,
        ingestion_method: req.ingestion_method,
        dispatch_source_config_id: req.dispatch_source_config_id,
    };

    // NAN-2117: `parser_repositories:import` authorizes reading the catalog — it
    // is NOT a substitute for `log_sources:create` (this inserts a validated,
    // active log source) or `source_configs:edit` (this can insert an identity
    // routing rule into an ingestion source configuration, whether the caller
    // pinned it or the auto-resolution picked one). Preflight both before any
    // write; the service re-checks at the mutation itself.
    let plan = service.plan_import(*id, &path, &import_request).await?;
    ensure_target_effects(&auth, &plan.required_effects())?;
    let grants = held_target_grants(&auth);

    let result = service
        .import_parser(*id, &path, &import_request, Some(auth.user_id()), &grants)
        .await?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::ParserRepo, PARSER_IMPORTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("parser", None, Some(path.clone()))
            .client_context(&client)
            .build(),
    );

    // NAN-2117: also emit the TARGET-resource records. `parser_imported` alone
    // left an audit blind spot — a live log source (and possibly a routing rule
    // on a source configuration) appeared with nothing naming them.
    state.emit_audit(
        AuditEvent::builder(AuditSource::ParserRepo, LOG_SOURCE_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "log_source",
                Some(result.log_source_id),
                Some(result.log_source_name.clone()),
            )
            .client_context(&client)
            .details(serde_json::json!({
                "source": "parser_repository_import",
                "repository_id": id.to_string(),
                "repository_path": path.clone(),
            }))
            .build(),
    );
    // Only when a rule was ACTUALLY inserted — the service dedupes against an
    // existing identity rule and treats an insert failure as non-fatal, so the
    // plan's `mutates_source_config` is authorization intent, not an outcome.
    if let Some(routing_rule_id) = result.routing_rule_id {
        state.emit_audit(
            AuditEvent::builder(AuditSource::ParserRepo, ROUTING_RULE_CREATED)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource(
                    "routing_rule",
                    Some(routing_rule_id),
                    Some(result.log_source_name.clone()),
                )
                .client_context(&client)
                .details(serde_json::json!({
                    "source": "parser_repository_import",
                    "repository_id": id.to_string(),
                    "repository_path": path.clone(),
                    "log_source_id": result.log_source_id.to_string(),
                }))
                .build(),
        );
    }

    Ok(Json(ImportParserResponse {
        log_source_id: result.log_source_id,
        import_type: req.import_type,
    }))
}

/// Batch import multiple parsers from a repository
#[utoipa::path(
    post,
    path = "/api/parser-repositories/{id}/parsers/import-batch",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    request_body = BatchImportParsersRequest,
    responses(
        (status = 200, description = "Batch import completed", body = BatchImportParsersResponse),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Forbidden — missing parser_repositories:import, or the log_sources:create / source_configs:edit capability some item in the batch consumes"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn batch_import_parsers(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<BatchImportParsersRequest>,
) -> Result<Json<BatchImportParsersResponse>, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_IMPORT)?;

    // Build per-item list: use `items` if provided, otherwise fall back to legacy `paths`
    let items: Vec<BatchImportParserItem> = if !req.items.is_empty() {
        req.items
    } else {
        req.paths
            .into_iter()
            .map(|path| BatchImportParserItem {
                path,
                import_type: req.import_type.clone(),
                source_type: None,
                ingestion_method: None,
                dispatch_source_config_id: None,
            })
            .collect()
    };

    if items.len() > 100 {
        return Err(ApiError::BadRequest(format!(
            "Batch import limited to 100 parsers, got {}",
            items.len()
        )));
    }

    let service = get_parser_repo_service(&state);

    // Build every item's import request up front so the authorization preflight
    // sees exactly what the execution loop will submit.
    let requests: Vec<(String, ParserImportRequest)> = items
        .into_iter()
        .map(|item| {
            let import_type = match item.import_type.as_str() {
                "forked" => ParserImportType::Forked,
                _ => ParserImportType::Linked,
            };
            (
                item.path,
                ParserImportRequest {
                    import_type,
                    source_type: item.source_type,
                    ingestion_method: item.ingestion_method,
                    dispatch_source_config_id: item.dispatch_source_config_id,
                },
            )
        })
        .collect();

    // NAN-2117: preflight the WHOLE batch before importing anything. Batch import
    // is where the dispatch config is auto-resolved, so a caller with only
    // `parser_repositories:import` could otherwise mutate up to 100 log sources
    // and their source-config routing tables. Items whose plan errors are left to
    // the execution loop — `plan_import` reads a strict subset of
    // `import_parser`'s lookups, so the same error recurs there before any write.
    //
    // Planned with bounded concurrency so the preflight does not add ~100
    // sequential round trips before the first import starts.
    let plan_futures: Vec<_> = requests
        .iter()
        .map(|(path, import_req)| service.plan_import(*id, path, import_req))
        .collect();
    let plans: Vec<_> = futures::stream::iter(plan_futures)
        .buffered(PLAN_CONCURRENCY)
        .collect()
        .await;

    let mut required_effects: Vec<TargetEffect> = Vec::new();
    for plan in plans.into_iter().flatten() {
        // (errored plans are deferred to the execution loop, which fails the same way)
        for effect in plan.required_effects() {
            if !required_effects.contains(&effect) {
                required_effects.push(effect);
            }
        }
    }
    ensure_target_effects(&auth, &required_effects)?;
    let grants = held_target_grants(&auth);

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut failed = Vec::new();

    for (path, import_req) in &requests {
        match service
            .import_parser(*id, path, import_req, Some(auth.user_id()), &grants)
            .await
        {
            Ok(_) => imported += 1,
            Err(nanosiem_core::parser_repository::ParserRepositoryError::AlreadyImported {
                ..
            }) => skipped += 1,
            // A target-capability denial is never a per-item soft failure: the
            // preflight should have rejected the whole request, so reaching here
            // means the outcome changed under a race. Fail the batch.
            Err(e @ nanosiem_core::parser_repository::ParserRepositoryError::Forbidden(_)) => {
                return Err(e.into());
            }
            Err(e) => {
                failed.push(ParserBatchFailure {
                    path: path.clone(),
                    error: e.to_string(),
                });
            }
        }
    }

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::ParserRepo, PARSER_BATCH_IMPORTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("parser_repository", Some(*id), None)
            .client_context(&client)
            .details(serde_json::json!({
                "imported": imported,
                "skipped": skipped,
                "failed": failed.len(),
            }))
            .build(),
    );

    Ok(Json(BatchImportParsersResponse {
        imported,
        skipped,
        failed,
    }))
}

/// Remove all imported parsers for a repository (deletes log sources)
#[utoipa::path(
    post,
    path = "/api/parser-repositories/{id}/parsers/remove-all-imported",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "All imported parsers removed", body = BatchRemoveParsersResponse),
        (status = 403, description = "Forbidden — missing parser_repositories:manage or log_sources:delete"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn remove_all_imported_parsers(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<BatchRemoveParsersResponse>, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_MANAGE)?;
    // NAN-2111: this deletes first-class log sources. `parser_repositories:manage`
    // covers the repository row ("Create, edit, and delete parser repositories"),
    // never the linked log sources — `DELETE /api/log-sources/{id}` requires
    // `log_sources:delete`. Re-checked inside the service before the imports are
    // even loaded.
    ensure_target_effects(&auth, &[TargetEffect::LogSourceDelete])?;

    let service = get_parser_repo_service(&state);
    let (removed, failed) = service
        .remove_all_imported(*id, &held_target_grants(&auth))
        .await?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::ParserRepo, PARSER_ALL_REMOVED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("parser_repository", Some(*id), None)
            .client_context(&client)
            .build(),
    );

    Ok(Json(BatchRemoveParsersResponse { removed, failed }))
}

// =============================================================================
// Upstream Change Detection
// =============================================================================

/// Get list of imported parsers with upstream changes
#[utoipa::path(
    get,
    path = "/api/parser-repositories/{id}/upstream-updates",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "Upstream updates retrieved successfully", body = ParserUpstreamUpdatesResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_parser_upstream_updates(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(repo_id): Path<TypeIdParam>,
) -> Result<Json<ParserUpstreamUpdatesResponse>, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_VIEW)?;

    let service = get_parser_repo_service(&state);
    let updates = service.get_upstream_updates(*repo_id).await?;

    Ok(Json(ParserUpstreamUpdatesResponse { updates }))
}

/// Get diff between imported parser log source and upstream
#[utoipa::path(
    get,
    path = "/api/log-sources/{id}/upstream-diff",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    responses(
        (status = 200, description = "Upstream diff retrieved successfully", body = UpstreamParserDiff),
        (status = 403, description = "Forbidden — missing parser_repositories:view or log_sources:view"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_log_source_upstream_diff(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(log_source_id): Path<TypeIdParam>,
) -> Result<Json<UpstreamParserDiff>, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_VIEW)?;
    // NAN-2103: the diff serializes the LIVE log source's deployed `parser_vrl` /
    // `normalize_vrl` as `current_vrl`. Repository visibility authorizes the
    // upstream/catalog half only — reading the live object is what
    // `GET /api/log-sources/{id}` gates behind `log_sources:view`.
    ensure_target_effects(&auth, &[TargetEffect::LogSourceView])?;

    let service = get_parser_repo_service(&state);
    let diff = service.get_upstream_diff(*log_source_id).await?;

    Ok(Json(diff))
}

/// Dismiss upstream changes for a log source (acknowledge without updating)
#[utoipa::path(
    post,
    path = "/api/log-sources/{id}/upstream-diff/dismiss",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    responses(
        (status = 204, description = "Upstream changes dismissed successfully"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn dismiss_parser_upstream_changes(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(log_source_id): Path<TypeIdParam>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, permissions::PARSERS_EDIT)?;

    let service = get_parser_repo_service(&state);
    service.dismiss_upstream_changes(*log_source_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Apply upstream update to a log source's parser VRL
#[utoipa::path(
    post,
    path = "/api/log-sources/{id}/apply-upstream-update",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    responses(
        (status = 200, description = "Upstream update applied successfully", body = ApplyUpstreamUpdateResult),
        (status = 403, description = "Forbidden — missing parsers:edit or log_sources:edit"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn apply_upstream_update(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(log_source_id): Path<TypeIdParam>,
) -> Result<Json<ApplyUpstreamUpdateResult>, ApiError> {
    ensure_permission(&auth, permissions::PARSERS_EDIT)?;
    // NAN-2120: applying an upstream update rewrites the live log source's VRL,
    // description and (now) `match_values` — the routing metadata the global
    // fixup used to churn. Same composite policy as the fixup endpoint.
    ensure_target_effects(&auth, &[TargetEffect::ParserEdit, TargetEffect::LogSourceEdit])?;

    let service = get_parser_repo_service(&state);
    let result = service
        .apply_upstream_update(*log_source_id, &held_target_grants(&auth))
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::ParserRepo, PARSER_UPSTREAM_APPLIED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("log_source", Some(*log_source_id), None::<String>)
            .client_context(&client)
            .build(),
    );

    Ok(Json(result))
}

/// Apply all pending upstream updates for a parser repository
#[utoipa::path(
    post,
    path = "/api/parser-repositories/{id}/apply-all-upstream-updates",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "Upstream updates applied", body = BulkApplyUpstreamResult),
        (status = 403, description = "Forbidden — missing parsers:edit or log_sources:edit"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn apply_all_upstream_updates(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(repo_id): Path<TypeIdParam>,
) -> Result<Json<BulkApplyUpstreamResult>, ApiError> {
    ensure_permission(&auth, permissions::PARSERS_EDIT)?;
    ensure_target_effects(&auth, &[TargetEffect::ParserEdit, TargetEffect::LogSourceEdit])?;

    let service = get_parser_repo_service(&state);
    let result = service
        .apply_all_upstream_updates(*repo_id, &held_target_grants(&auth))
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::ParserRepo, PARSER_UPSTREAM_APPLIED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("parser_repository", Some(*repo_id), None::<String>)
            .details(serde_json::json!({
                "updated": result.updated,
                "failed": result.failed,
            }))
            .client_context(&client)
            .build(),
    );

    Ok(Json(result))
}

// =============================================================================
// Helper Functions
// =============================================================================

fn get_parser_repo_service(state: &AppState) -> ParserRepositoryService {
    ParserRepositoryService::new(state.pool.clone())
}

// =============================================================================
// Fixup match_values
// =============================================================================

/// Re-sync match_values from upstream YAML for one repository's imported log sources
#[utoipa::path(
    post,
    path = "/api/parser-repositories/{id}/fixup-match-values",
    tag = "parser_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "Match values fixup completed", body = FixupMatchValuesResponse),
        (status = 403, description = "Forbidden — missing parser_repositories:manage, parsers:edit or log_sources:edit"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn fixup_match_values(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<FixupMatchValuesResponse>, ApiError> {
    ensure_permission(&auth, permissions::PARSER_REPOSITORIES_MANAGE)?;
    // NAN-2120: this rewrites `log_sources.match_values` — LIVE ingestion-routing
    // metadata deciding which upstream source-type aliases activate a parser.
    // Repository management is not a licence to edit those targets; require the
    // canonical parser and log-source edit capabilities too. Re-checked inside
    // the service. The route is also repository-scoped now: the old global
    // `/api/parser-repositories/fixup-match-values` rewrote every import in the
    // tenant from one request.
    ensure_target_effects(&auth, &[TargetEffect::ParserEdit, TargetEffect::LogSourceEdit])?;

    let service = get_parser_repo_service(&state);
    // 404 for an unknown repository before any target work, so the endpoint is
    // not an existence oracle for repositories.
    let _ = service.get_repository(*id).await?;

    let updated = service
        .fixup_imported_match_values(*id, &held_target_grants(&auth))
        .await?;

    // One record per log source that actually changed, under the canonical
    // `log_source` resource type — an audit search for log-source updates must
    // be able to name every target this repair touched. A no-op fixup emits
    // nothing.
    for log_source_id in &updated {
        state.emit_audit(
            AuditEvent::builder(AuditSource::ParserRepo, LOG_SOURCE_UPDATED)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource("log_source", Some(*log_source_id), None::<String>)
                .client_context(&client)
                .details(serde_json::json!({
                    "source": "parser_repository_fixup_match_values",
                    "repository_id": id.to_string(),
                    "field": "match_values",
                }))
                .build(),
        );
    }

    Ok(Json(FixupMatchValuesResponse {
        updated: updated.len() as u32,
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FixupMatchValuesResponse {
    pub updated: u32,
}

// Note: `From<ParserRepositoryError> for ApiError` lifted to
// nanosiem-api-lib in NAN-752 (orphan rule — `ApiError` lives there now).

// =============================================================================
// OpenAPI Documentation
// =============================================================================

/// OpenAPI documentation for parser repository endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_parser_repositories,
        get_parser_repository,
        create_parser_repository,
        update_parser_repository,
        delete_parser_repository,
        sync_parser_repository,
        get_parser_sync_status,
        list_repository_parsers,
        get_repository_parser,
        preview_parser_import,
        import_parser,
        batch_import_parsers,
        remove_all_imported_parsers,
        get_parser_upstream_updates,
        get_log_source_upstream_diff,
        dismiss_parser_upstream_changes,
        apply_upstream_update,
        apply_all_upstream_updates,
        fixup_match_values,
    ),
    components(schemas(
        ListParserRepositoriesResponse,
        CreateParserRepositoryRequest,
        UpdateParserRepositoryRequest,
        RepositoryParserResponse,
        ImportParserRequest,
        ImportParserResponse,
        BatchImportParserItem,
        BatchImportParsersRequest,
        BatchImportParsersResponse,
        ParserBatchFailure,
        BatchRemoveParsersResponse,
        ParserUpstreamUpdatesResponse,
        ParserSyncStartResponse,
        ParserSyncStatusResponse,
        FixupMatchValuesResponse,
        ApplyUpstreamUpdateResult,
        BulkApplyUpstreamResult,
    ))
)]
pub struct ParserRepositoriesApiDoc;
