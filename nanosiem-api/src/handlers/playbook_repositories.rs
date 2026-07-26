// SPDX-License-Identifier: AGPL-3.0-or-later

//! Playbook Repository endpoint handlers.
//!
//! Manages external git-hosted playbook libraries: add repositories
//! (allowlist-enforced), trigger sync, browse cached content, and import
//! playbooks into the main `playbooks` library.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::auth::{permissions, TargetEffect};
use nanosiem_core::playbook_repository::{
    NewPlaybookRepository, PlaybookImportRequest, PlaybookImportResponse, PlaybookImportType,
    PlaybookRepository, PlaybookRepositoryError, PlaybookRepositoryService, RepositoryPlaybook,
    RepositoryPlaybookFilter, UpdatePlaybookRepository,
};
use nanosiem_core::typeid::TypeIdParam;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::handlers::repository_target_authz::{ensure_target_effects, held_target_grants};
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Target-resource effects every playbook-import route consumes (NAN-2119).
///
/// Import always CREATES (`AlreadyImported` is a 409, never an update), so the
/// set is a single effect. Declared once so single-import, import-all and
/// sync-and-import cannot drift apart.
const PLAYBOOK_IMPORT_EFFECTS: &[TargetEffect] = &[TargetEffect::PlaybookCreate];

// NAN-845: hardcoded URL allowlist for the only repo we sync from. The
// frontend reshape (drop add/edit dialogs) makes this unreachable via the UI,
// but the API stays callable directly — guard the surface so direct callers
// can't register an arbitrary repo and silently leak playbook content.
const ALLOWED_REPO_URLS: &[&str] = &["https://github.com/nano-rs/playbooks"];

fn validate_repo_url(url: &str) -> Result<(), ApiError> {
    if ALLOWED_REPO_URLS.iter().any(|allowed| *allowed == url) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "Repository URL not on allowlist (only nano-rs/playbooks is permitted): {}",
            url
        )))
    }
}

// =============================================================================
// Request/Response Types
// =============================================================================

#[derive(Debug, Serialize, ToSchema)]
pub struct ListPlaybookRepositoriesResponse {
    pub repositories: Vec<PlaybookRepository>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePlaybookRepositoryRequest {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub playbooks_path: Option<String>,
    #[serde(default)]
    pub auto_sync_enabled: Option<bool>,
    #[serde(default)]
    pub sync_interval_hours: Option<i32>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePlaybookRepositoryRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub branch: Option<String>,
    pub playbooks_path: Option<String>,
    pub auto_sync_enabled: Option<bool>,
    pub sync_interval_hours: Option<i32>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PlaybookSyncStartResponse {
    #[serde(with = "nanosiem_core::typeid::playbook_repo")]
    #[schema(value_type = String)]
    pub repository_id: Uuid,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PlaybookSyncStatusResponse {
    pub status: Option<String>,
    pub last_synced_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_sync_commit: Option<String>,
    pub last_sync_error: Option<String>,
    pub playbook_count: i32,
}

#[derive(Debug, Deserialize, Default, IntoParams)]
pub struct ListRepositoryPlaybooksQuery {
    pub category: Option<String>,
    pub parse_status: Option<String>,
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListRepositoryPlaybooksResponse {
    pub playbooks: Vec<RepositoryPlaybook>,
}

/// Bulk import request body.
///
/// NAN-611: today the only knob is `import_type` (linked vs. forked) — applied
/// uniformly to every playbook. Per-item overrides (à la `BatchImportItem` for
/// rules) can be added later when there's a UI for it; mass-syncing the stock
/// nano repo doesn't need them.
#[derive(Debug, Deserialize, ToSchema, Default)]
pub struct ImportAllPlaybooksRequest {
    /// Defaults to `linked` so future syncs continue to flow into imports.
    #[serde(default)]
    pub import_type: Option<PlaybookImportType>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImportAllPlaybooksResponse {
    /// Newly imported into the library.
    pub imported: usize,
    /// Already imported (idempotent re-runs after sync).
    pub skipped: usize,
    /// Cached rows that failed to parse on sync — never imported.
    pub unparseable: usize,
    /// Per-path failure messages.
    pub failed: Vec<ImportAllFailure>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImportAllFailure {
    pub path: String,
    pub error: String,
}

// =============================================================================
// Helpers
// =============================================================================

fn get_service(state: &AppState) -> PlaybookRepositoryService {
    PlaybookRepositoryService::new(state.pool.clone())
}

// =============================================================================
// Repository CRUD
// =============================================================================

/// List all playbook repositories
#[utoipa::path(
    get,
    path = "/api/playbook-repositories",
    tag = "playbook_repositories",
    responses(
        (status = 200, description = "Repositories retrieved successfully", body = ListPlaybookRepositoriesResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_playbook_repositories(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ListPlaybookRepositoriesResponse>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOK_REPOSITORIES_VIEW)?;
    let service = get_service(&state);
    let repositories = service.list_repositories().await?;
    Ok(Json(ListPlaybookRepositoriesResponse { repositories }))
}

/// Get a single playbook repository
#[utoipa::path(
    get,
    path = "/api/playbook-repositories/{id}",
    tag = "playbook_repositories",
    params(("id" = String, Path, description = "Repository TypeID")),
    responses(
        (status = 200, description = "Repository retrieved successfully", body = PlaybookRepository),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_playbook_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<PlaybookRepository>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOK_REPOSITORIES_VIEW)?;
    let service = get_service(&state);
    let repo = service.get_repository(*id).await?;
    Ok(Json(repo))
}

/// Create a new playbook repository
#[utoipa::path(
    post,
    path = "/api/playbook-repositories",
    tag = "playbook_repositories",
    request_body = CreatePlaybookRepositoryRequest,
    responses(
        (status = 200, description = "Repository created successfully", body = PlaybookRepository),
        (status = 403, description = "Forbidden"),
        (status = 400, description = "Bad request"),
    ),
    security(("api_key" = []))
)]
pub async fn create_playbook_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreatePlaybookRepositoryRequest>,
) -> Result<Json<PlaybookRepository>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOK_REPOSITORIES_MANAGE)?;
    validate_repo_url(&req.url)?;
    let service = get_service(&state);
    let new_repo = NewPlaybookRepository {
        name: req.name,
        slug: None,
        description: req.description,
        url: req.url,
        branch: req.branch,
        playbooks_path: req.playbooks_path,
        auto_sync_enabled: req.auto_sync_enabled,
        sync_interval_hours: req.sync_interval_hours,
    };
    let repo = service
        .create_repository(new_repo, Some(auth.user_id()))
        .await?;
    Ok(Json(repo))
}

/// Update a playbook repository
#[utoipa::path(
    patch,
    path = "/api/playbook-repositories/{id}",
    tag = "playbook_repositories",
    params(("id" = String, Path, description = "Repository TypeID")),
    request_body = UpdatePlaybookRepositoryRequest,
    responses(
        (status = 200, description = "Repository updated successfully", body = PlaybookRepository),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn update_playbook_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<UpdatePlaybookRepositoryRequest>,
) -> Result<Json<PlaybookRepository>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOK_REPOSITORIES_MANAGE)?;
    let service = get_service(&state);
    let update = UpdatePlaybookRepository {
        name: req.name,
        description: req.description,
        branch: req.branch,
        playbooks_path: req.playbooks_path,
        auto_sync_enabled: req.auto_sync_enabled,
        sync_interval_hours: req.sync_interval_hours,
        enabled: req.enabled,
    };
    let repo = service.update_repository(*id, update).await?;
    Ok(Json(repo))
}

/// Delete a playbook repository
#[utoipa::path(
    delete,
    path = "/api/playbook-repositories/{id}",
    tag = "playbook_repositories",
    params(("id" = String, Path, description = "Repository TypeID")),
    responses(
        (status = 204, description = "Repository deleted successfully"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_playbook_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOK_REPOSITORIES_MANAGE)?;
    let service = get_service(&state);
    service.delete_repository(*id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// Sync
// =============================================================================

/// Start syncing a playbook repository from GitHub (non-blocking)
#[utoipa::path(
    post,
    path = "/api/playbook-repositories/{id}/sync",
    tag = "playbook_repositories",
    params(("id" = String, Path, description = "Repository TypeID")),
    responses(
        (status = 200, description = "Sync started", body = PlaybookSyncStartResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn sync_playbook_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<PlaybookSyncStartResponse>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOK_REPOSITORIES_SYNC)?;
    let service = get_service(&state);
    let repo = service.get_repository(*id).await?;
    service.start_sync(*id).await?;
    Ok(Json(PlaybookSyncStartResponse {
        repository_id: *id,
        status: "syncing".to_string(),
        message: format!("Sync started for {}", repo.name),
    }))
}

/// Get sync status for a playbook repository
#[utoipa::path(
    get,
    path = "/api/playbook-repositories/{id}/sync/status",
    tag = "playbook_repositories",
    params(("id" = String, Path, description = "Repository TypeID")),
    responses(
        (status = 200, description = "Sync status retrieved", body = PlaybookSyncStatusResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_playbook_sync_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<PlaybookSyncStatusResponse>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOK_REPOSITORIES_VIEW)?;
    let service = get_service(&state);
    let repo = service.get_repository(*id).await?;
    Ok(Json(PlaybookSyncStatusResponse {
        status: repo.last_sync_status,
        last_synced_at: repo.last_synced_at,
        last_sync_commit: repo.last_sync_commit,
        last_sync_error: repo.last_sync_error,
        playbook_count: repo.playbook_count.unwrap_or(0),
    }))
}

// =============================================================================
// Browse + Import
// =============================================================================

/// List cached playbooks for a repository
#[utoipa::path(
    get,
    path = "/api/playbook-repositories/{id}/playbooks",
    tag = "playbook_repositories",
    params(
        ("id" = String, Path, description = "Repository TypeID"),
        ListRepositoryPlaybooksQuery,
    ),
    responses(
        (status = 200, description = "Cached playbooks retrieved", body = ListRepositoryPlaybooksResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn list_repository_playbooks(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Query(q): Query<ListRepositoryPlaybooksQuery>,
) -> Result<Json<ListRepositoryPlaybooksResponse>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOK_REPOSITORIES_VIEW)?;
    let service = get_service(&state);
    let filter = RepositoryPlaybookFilter {
        category: q.category,
        parse_status: q.parse_status,
        search: q.search,
        limit: q.limit,
        offset: q.offset,
    };
    let playbooks = service.list_repository_playbooks(*id, &filter).await?;
    Ok(Json(ListRepositoryPlaybooksResponse { playbooks }))
}

/// Import a repository playbook into the main library.
///
/// NAN-453: path is a catch-all suffix (`{*path}`) so multi-segment file
/// paths like `identity/credential_reuse.md` round-trip cleanly. Matches
/// `/api/rule-repositories/{id}/rules/import/{*path}` from rule_repositories.
#[utoipa::path(
    post,
    path = "/api/playbook-repositories/{id}/playbooks/import/{path}",
    tag = "playbook_repositories",
    params(
        ("id" = String, Path, description = "Repository TypeID"),
        ("path" = String, Path, description = "Playbook file path (URL-encoded, multi-segment supported)"),
    ),
    request_body = PlaybookImportRequest,
    responses(
        (status = 200, description = "Playbook imported", body = PlaybookImportResponse),
        (status = 403, description = "Forbidden — missing playbook_repositories:import, or the playbooks:manage capability the import consumes"),
        (status = 404, description = "Not found"),
        (status = 409, description = "Already imported"),
    ),
    security(("api_key" = []))
)]
pub async fn import_repository_playbook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path((id, path)): Path<(TypeIdParam, String)>,
    Json(req): Json<PlaybookImportRequest>,
) -> Result<Json<PlaybookImportResponse>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOK_REPOSITORIES_IMPORT)?;
    // NAN-2119: importing materializes a first-class library playbook + its
    // initial version — the same rows `POST /api/playbooks` creates behind
    // `playbooks:manage`. Preflight the target capability BEFORE any write, and
    // hand the grant set to the service so it re-checks at the create branch.
    ensure_target_effects(&auth, PLAYBOOK_IMPORT_EFFECTS)?;
    let grants = held_target_grants(&auth);
    let service = get_service(&state);
    let response = service
        .import_playbook(*id, &path, req, Some(auth.user_id()), &grants)
        .await?;
    Ok(Json(response))
}

/// Import every parseable cached playbook from a repository into the library.
///
/// NAN-611: closes the sync→library gap. Sync alone only populates the staging
/// `repository_playbooks` cache; users were left wondering why "16 playbooks
/// synced" never showed up at `/playbooks`. This is the bulk equivalent of the
/// per-path import endpoint — mirrors `batch_import_rules` for rule
/// repositories. Idempotent: previously-imported rows return as `skipped`.
#[utoipa::path(
    post,
    path = "/api/playbook-repositories/{id}/playbooks/import-all",
    tag = "playbook_repositories",
    params(("id" = String, Path, description = "Repository TypeID")),
    request_body = ImportAllPlaybooksRequest,
    responses(
        (status = 200, description = "Bulk import completed", body = ImportAllPlaybooksResponse),
        (status = 403, description = "Forbidden — missing playbook_repositories:import, or the playbooks:manage capability the import consumes"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn import_all_repository_playbooks(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<ImportAllPlaybooksRequest>,
) -> Result<Json<ImportAllPlaybooksResponse>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOK_REPOSITORIES_IMPORT)?;
    // NAN-2119: bulk import creates up to `max_playbooks_per_repo` library
    // playbooks. Preflighted here so authorization cannot fail PART-WAY through
    // and leave a partially-populated library.
    ensure_target_effects(&auth, PLAYBOOK_IMPORT_EFFECTS)?;
    let grants = held_target_grants(&auth);
    let service = get_service(&state);
    // Confirm the repo exists (404 if not) before doing any work.
    service.get_repository(*id).await?;

    let import_type = req.import_type.unwrap_or(PlaybookImportType::Linked);

    // Pull every cached row for this repo. The single-import service method
    // re-fetches by path, but that's fine — total round-trips are bounded by
    // `max_playbooks_per_repo` (1000) and the volumes here are small.
    let cached = service
        .list_repository_playbooks(*id, &RepositoryPlaybookFilter::default())
        .await?;

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut unparseable = 0usize;
    let mut failed: Vec<ImportAllFailure> = Vec::new();

    for entry in cached {
        // Skip rows that failed to parse during sync — importing them would
        // just shove a broken doc into the library.
        if entry.parse_status != "success" {
            unparseable += 1;
            continue;
        }
        let path = entry.file_path.clone();
        let import_req = PlaybookImportRequest {
            import_type,
            owner_team: None,
        };
        match service
            .import_playbook(*id, &path, import_req, Some(auth.user_id()), &grants)
            .await
        {
            Ok(_) => imported += 1,
            Err(PlaybookRepositoryError::AlreadyImported { .. }) => skipped += 1,
            Err(e) => {
                tracing::warn!(
                    "Failed to import repository playbook {} from repo {}: {}",
                    path,
                    *id,
                    e
                );
                failed.push(ImportAllFailure {
                    path,
                    error: e.to_string(),
                });
            }
        }
    }

    tracing::info!(
        "Bulk playbook import for repo {}: imported={}, skipped={}, unparseable={}, failed={}",
        *id,
        imported,
        skipped,
        unparseable,
        failed.len()
    );

    Ok(Json(ImportAllPlaybooksResponse {
        imported,
        skipped,
        unparseable,
        failed,
    }))
}

/// Combined response: sync stats + bulk import stats. Returned by the
/// "Sync now" affordance on the Playbooks library so the toast can show a
/// single human-readable summary in one round-trip.
#[derive(Debug, Serialize, ToSchema)]
pub struct SyncAndImportResponse {
    /// Total playbooks the repo carries after sync.
    pub playbooks_total: i32,
    /// Newly added cached rows on this sync (the upstream had new files).
    pub playbooks_added: i32,
    /// Rows promoted to the library on this call.
    pub imported: usize,
    /// Already in the library (idempotent re-runs).
    pub skipped: usize,
    /// Cached rows that failed to parse on sync — never imported.
    pub unparseable: usize,
    /// Per-path failure messages from the import pass.
    pub failed: Vec<ImportAllFailure>,
}

/// Synchronously sync the repository and then bulk-import every parseable
/// cached playbook into the library, in one round-trip.
///
/// Wraps `sync_repository` (the blocking variant) → `import_all_repository_playbooks`
/// so the Playbooks library "Sync now" button can show a single combined toast
/// instead of polling sync status from the client. Permissions: the caller
/// needs both `playbook_repositories:sync` and `playbook_repositories:import`.
#[utoipa::path(
    post,
    path = "/api/playbook-repositories/{id}/sync-and-import",
    tag = "playbook_repositories",
    params(("id" = String, Path, description = "Repository TypeID")),
    request_body = ImportAllPlaybooksRequest,
    responses(
        (status = 200, description = "Sync + import completed", body = SyncAndImportResponse),
        (status = 403, description = "Forbidden — missing playbook_repositories:sync / :import, or the playbooks:manage capability the import consumes"),
        (status = 404, description = "Not found"),
        (status = 409, description = "Sync already in progress"),
    ),
    security(("api_key" = []))
)]
pub async fn sync_and_import_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<ImportAllPlaybooksRequest>,
) -> Result<Json<SyncAndImportResponse>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOK_REPOSITORIES_SYNC)?;
    ensure_permission(&auth, permissions::PLAYBOOK_REPOSITORIES_IMPORT)?;
    // NAN-2119: enforced BEFORE the sync so an under-scoped caller cannot even
    // trigger the network fetch, let alone reach the library-creating loop.
    ensure_target_effects(&auth, PLAYBOOK_IMPORT_EFFECTS)?;
    let grants = held_target_grants(&auth);
    let service = get_service(&state);
    service.get_repository(*id).await?;

    let sync_result = service.sync_repository(*id).await?;

    let import_type = req.import_type.unwrap_or(PlaybookImportType::Linked);
    let cached = service
        .list_repository_playbooks(*id, &RepositoryPlaybookFilter::default())
        .await?;

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut unparseable = 0usize;
    let mut failed: Vec<ImportAllFailure> = Vec::new();

    for entry in cached {
        if entry.parse_status != "success" {
            unparseable += 1;
            continue;
        }
        let path = entry.file_path.clone();
        let import_req = PlaybookImportRequest {
            import_type,
            owner_team: None,
        };
        match service
            .import_playbook(*id, &path, import_req, Some(auth.user_id()), &grants)
            .await
        {
            Ok(_) => imported += 1,
            Err(PlaybookRepositoryError::AlreadyImported { .. }) => skipped += 1,
            Err(e) => {
                tracing::warn!(
                    "Failed to import repository playbook {} from repo {}: {}",
                    path,
                    *id,
                    e
                );
                failed.push(ImportAllFailure {
                    path,
                    error: e.to_string(),
                });
            }
        }
    }

    tracing::info!(
        "Sync+import for playbook repo {}: total={}, added={}, imported={}, skipped={}, unparseable={}, failed={}",
        *id,
        sync_result.playbooks_total,
        sync_result.playbooks_added,
        imported,
        skipped,
        unparseable,
        failed.len()
    );

    Ok(Json(SyncAndImportResponse {
        playbooks_total: sync_result.playbooks_total,
        playbooks_added: sync_result.playbooks_added,
        imported,
        skipped,
        unparseable,
        failed,
    }))
}

// Note: `From<PlaybookRepositoryError> for ApiError` lifted to
// nanosiem-api-lib in NAN-752 (orphan rule — `ApiError` lives there now).

// =============================================================================
// OpenAPI
// =============================================================================

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_playbook_repositories,
        get_playbook_repository,
        create_playbook_repository,
        update_playbook_repository,
        delete_playbook_repository,
        sync_playbook_repository,
        get_playbook_sync_status,
        list_repository_playbooks,
        import_repository_playbook,
        import_all_repository_playbooks,
        sync_and_import_repository,
    ),
    components(schemas(
        ListPlaybookRepositoriesResponse,
        CreatePlaybookRepositoryRequest,
        UpdatePlaybookRepositoryRequest,
        PlaybookSyncStartResponse,
        PlaybookSyncStatusResponse,
        ListRepositoryPlaybooksResponse,
        ImportAllPlaybooksRequest,
        ImportAllPlaybooksResponse,
        ImportAllFailure,
        SyncAndImportResponse,
    ))
)]
pub struct PlaybookRepositoriesApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_repo_url_accepts_official() {
        assert!(validate_repo_url("https://github.com/nano-rs/playbooks").is_ok());
    }

    #[test]
    fn validate_repo_url_rejects_arbitrary() {
        let err = validate_repo_url("https://github.com/attacker/evil").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn validate_repo_url_rejects_off_by_trailing_slash() {
        // Strict equality — trailing-slash variants are not allowed.
        assert!(validate_repo_url("https://github.com/nano-rs/playbooks/").is_err());
    }
}
