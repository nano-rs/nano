// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment Marketplace endpoint handlers
//!
//! Unified catalog for data enrichments, agent enrichments, custom enrichments,
//! and identity providers. Includes GitHub repository sync for community content.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
// Marketplace's deno-runtime call sites (sync_enrichment "deno" arm and
// preview_enrichment) are cfg-gated for enterprise — Phase 3.3 of NAN-744
// lifted custom_enrichment to the enterprise crate. Catalog list / install /
// uninstall / repo sync paths stay open since they only touch PG.
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::custom_enrichment::{execute_agent_enrichment, SandboxExecutor};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, MARKETPLACE_CONFIGURED, MARKETPLACE_INSTALLED,
    MARKETPLACE_REPO_CREATED, MARKETPLACE_REPO_SYNCED, MARKETPLACE_REPO_UPDATED,
    MARKETPLACE_SYNC_TRIGGERED, MARKETPLACE_UNINSTALLED, MARKETPLACE_UPDATED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::marketplace::{
    ArtifactCoverage, CatalogFilter, CatalogStats, ConfigureRequest, CoverageState,
    CreateMarketplaceRepo, CredentialFieldDef, EnrichmentMarketplaceRepo, EnrichmentStatus,
    InstallRequest, MarketplaceCatalogEntry, MarketplaceCoverage, MarketplaceCoverageService,
    MarketplaceInstallService, MarketplaceManifest, MarketplaceRepository,
    MarketplaceSyncService, RepoBrowseEntry, UpdateMarketplaceRepo,
};
use nanosiem_core::typeid::TypeIdParam;
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

// =============================================================================
// Response Types
// =============================================================================

#[derive(Debug, Serialize, ToSchema)]
pub struct ListCatalogResponse {
    pub entries: Vec<MarketplaceCatalogEntry>,
    pub total: i64,
    pub stats: CatalogStats,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListReposResponse {
    pub repos: Vec<EnrichmentMarketplaceRepo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BrowseRepoResponse {
    pub entries: Vec<RepoBrowseEntry>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExportResponse {
    /// The enrichment slug (used as directory name)
    pub slug: String,
    /// Suggested directory path in repo (e.g. "enrichments/agent/my-enrichment/")
    pub directory: String,
    /// manifest.yaml content
    pub manifest_yaml: String,
    /// code.ts content
    pub code: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PreviewRequest {
    /// Sample artifact value to enrich. Defaults are picked per `artifact_type`
    /// when omitted (e.g. `8.8.8.8` for ip, `example.com` for domain).
    pub artifact: Option<String>,
    /// Artifact type the enrichment is run against. Accepts `ip` | `domain` |
    /// `hash` | `url` | `email` | `filename`. Defaults to `ip`.
    pub artifact_type: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PreviewResponse {
    /// Whether the sandbox returned a parseable result.
    pub success: bool,
    /// What was actually run (may be the request's value or the per-type default).
    pub artifact: String,
    pub artifact_type: String,
    /// Parsed JSON output from the enrichment script (the AgentEnrichmentResult).
    pub output: Option<serde_json::Value>,
    /// Raw stdout — useful for debugging when output parsing fails.
    pub stdout: String,
    /// Raw stderr.
    pub stderr: String,
    pub duration_ms: u64,
    /// User-readable status when preview is unsupported (native / identity backend,
    /// missing credentials, sandbox failure, etc.). `null` on success.
    pub note: Option<String>,
    pub error: Option<String>,
}

// =============================================================================
// Catalog Handlers
// =============================================================================

/// List marketplace catalog entries with filtering
#[utoipa::path(
    get,
    path = "/api/marketplace/catalog",
    tag = "marketplace",
    params(CatalogFilter),
    responses(
        (status = 200, description = "Catalog entries retrieved", body = ListCatalogResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_catalog(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(filter): Query<CatalogFilter>,
) -> Result<Json<ListCatalogResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".to_string()))?;

    let repo = MarketplaceRepository::new(state.pool.clone());
    let entries = repo.list_catalog(&filter).await?;
    let stats = repo.get_catalog_stats().await?;

    Ok(Json(ListCatalogResponse {
        total: entries.len() as i64,
        entries,
        stats,
    }))
}

/// Get a single catalog entry by slug
#[utoipa::path(
    get,
    path = "/api/marketplace/catalog/{slug}",
    tag = "marketplace",
    params(("slug" = String, Path, description = "Catalog entry slug")),
    responses(
        (status = 200, description = "Catalog entry retrieved", body = MarketplaceCatalogEntry),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_catalog_entry(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(slug): Path<String>,
) -> Result<Json<MarketplaceCatalogEntry>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".to_string()))?;

    let repo = MarketplaceRepository::new(state.pool.clone());
    let entry = repo.get_catalog_entry(&slug).await?;
    Ok(Json(entry))
}

/// Install an enrichment from the catalog
#[utoipa::path(
    post,
    path = "/api/marketplace/catalog/{slug}/install",
    tag = "marketplace",
    params(("slug" = String, Path, description = "Catalog entry slug")),
    request_body = InstallRequest,
    responses(
        (status = 200, description = "Enrichment installed", body = MarketplaceCatalogEntry),
        (status = 400, description = "Credential required"),
        (status = 409, description = "Already installed"),
    ),
    security(("api_key" = []))
)]
pub async fn install_enrichment(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(slug): Path<String>,
    Json(request): Json<InstallRequest>,
) -> Result<Json<MarketplaceCatalogEntry>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    let service = MarketplaceInstallService::new(state.pool.clone());
    let entry = service.install(&slug, &request, auth.user_id()).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Marketplace, MARKETPLACE_INSTALLED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("enrichment", Some(entry.id), Some(entry.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(entry))
}

/// Uninstall an enrichment
#[utoipa::path(
    post,
    path = "/api/marketplace/catalog/{slug}/uninstall",
    tag = "marketplace",
    params(("slug" = String, Path, description = "Catalog entry slug")),
    responses(
        (status = 200, description = "Enrichment uninstalled", body = MarketplaceCatalogEntry),
        (status = 400, description = "Not installed"),
    ),
    security(("api_key" = []))
)]
pub async fn uninstall_enrichment(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(slug): Path<String>,
) -> Result<Json<MarketplaceCatalogEntry>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    let service = MarketplaceInstallService::new(state.pool.clone());
    let entry = service.uninstall(&slug).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Marketplace, MARKETPLACE_UNINSTALLED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("enrichment", Some(entry.id), Some(entry.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(entry))
}

/// Configure an installed enrichment (credentials, config, enable/disable)
#[utoipa::path(
    put,
    path = "/api/marketplace/catalog/{slug}/configure",
    tag = "marketplace",
    params(("slug" = String, Path, description = "Catalog entry slug")),
    request_body = ConfigureRequest,
    responses(
        (status = 200, description = "Enrichment configured", body = MarketplaceCatalogEntry),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn configure_enrichment(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(slug): Path<String>,
    Json(request): Json<ConfigureRequest>,
) -> Result<Json<MarketplaceCatalogEntry>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    let repo = MarketplaceRepository::new(state.pool.clone());

    // Handle credential update if provided
    let creds_updated = request.credentials.is_some();
    if let Some(ref credentials) = request.credentials {
        let install_service = MarketplaceInstallService::new(state.pool.clone());
        install_service
            .update_credentials(&slug, credentials)
            .await?;
    }

    let entry = repo
        .update_catalog_config(
            &slug,
            request.config.as_ref(),
            request.enabled,
            None, // credentials already updated above
            None,
        )
        .await?;

    // Propagate enabled flag to the underlying source so the scheduler respects it
    if let Some(enabled) = request.enabled {
        if let Some(ref source_id) = entry.native_source_id {
            if let Err(e) = sqlx::query("UPDATE enrichment_sources SET enabled = $2, updated_at = NOW() WHERE id = $1")
                .bind(source_id)
                .bind(enabled)
                .execute(&state.pool)
                .await
            {
                tracing::warn!(source_id = %source_id, error = %e, "Failed to propagate enabled flag to enrichment_sources");
            }
        }
        if let Some(ref provider_id) = entry.identity_provider_id {
            if let Err(e) = sqlx::query("UPDATE identity_providers SET enabled = $2 WHERE id = $1")
                .bind(provider_id)
                .bind(enabled)
                .execute(&state.pool)
                .await
            {
                tracing::warn!(provider_id = %provider_id, error = %e, "Failed to propagate enabled flag to identity_providers");
            }
        }
        if let Some(ref ce_id) = entry.custom_enrichment_id {
            if let Err(e) = sqlx::query("UPDATE custom_enrichments SET enabled = $2 WHERE id = $1")
                .bind(ce_id)
                .bind(enabled)
                .execute(&state.pool)
                .await
            {
                tracing::warn!(enrichment_id = %ce_id, error = %e, "Failed to propagate enabled flag to custom_enrichments");
            }
        }
    }

    state.emit_audit(
        AuditEvent::builder(AuditSource::Marketplace, MARKETPLACE_CONFIGURED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("enrichment", Some(entry.id), Some(entry.name.clone()))
            .details(serde_json::json!({
                "enabled": request.enabled,
                "credentials_updated": creds_updated,
            }))
            .client_context(&client)
            .build(),
    );

    Ok(Json(entry))
}

/// Update an installed enrichment to the latest version
#[utoipa::path(
    post,
    path = "/api/marketplace/catalog/{slug}/update",
    tag = "marketplace",
    params(("slug" = String, Path, description = "Catalog entry slug")),
    responses(
        (status = 200, description = "Enrichment updated", body = MarketplaceCatalogEntry),
        (status = 400, description = "Not installed"),
    ),
    security(("api_key" = []))
)]
pub async fn update_enrichment(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(slug): Path<String>,
) -> Result<Json<MarketplaceCatalogEntry>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    let service = MarketplaceInstallService::new(state.pool.clone());
    let entry = service.update(&slug).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Marketplace, MARKETPLACE_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("enrichment", Some(entry.id), Some(entry.name.clone()))
            .details(serde_json::json!({ "version": entry.installed_version }))
            .client_context(&client)
            .build(),
    );

    Ok(Json(entry))
}

/// Trigger data sync for an installed enrichment
#[utoipa::path(
    post,
    path = "/api/marketplace/catalog/{slug}/sync",
    tag = "marketplace",
    params(("slug" = String, Path, description = "Catalog entry slug")),
    responses(
        (status = 200, description = "Sync triggered", body = MessageResponse),
        (status = 400, description = "Not installed"),
    ),
    security(("api_key" = []))
)]
pub async fn sync_enrichment(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(slug): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    // Capture audit fields before auth is potentially moved
    let actor_id = auth.user_id();
    let api_key_id = auth.api_key_id;
    let api_key_name = auth.api_key_name.clone();

    let repo = MarketplaceRepository::new(state.pool.clone());
    let entry = repo.get_catalog_entry(&slug).await?;

    if !entry.installed {
        return Err(ApiError::BadRequest(
            "Enrichment is not installed".to_string(),
        ));
    }

    match entry.execution_backend.as_str() {
        "native" => {
            // Only IPinfo Lite is native — everything else is Deno via the GitHub repo
            let enrichment = state.enrichment.clone();
            let slug_owned = slug.clone();

            tokio::spawn(async move {
                let service = enrichment.read().await;
                let result = service.sync_ipinfo_lite().await;
                match result {
                    Ok(r) if r.success => {
                        tracing::info!(slug = %slug_owned, records = r.records_loaded, "IPinfo Lite sync completed");
                    }
                    Ok(r) => {
                        tracing::warn!(slug = %slug_owned, error = ?r.error, "IPinfo Lite sync completed with errors");
                    }
                    Err(e) => {
                        tracing::error!(slug = %slug_owned, error = %e, "IPinfo Lite sync failed");
                    }
                }
            });
        }
        "deno" => {
            // Deno-backed marketplace entries delegate to
            // `custom_enrichment::trigger_run`, which lives in the enterprise
            // handler module after Phase 3.3. Open-core builds reject deno
            // entries at sync time — catalogs that include deno entries
            // simply can't sync those rows.
            #[cfg(feature = "enterprise")]
            {
                if let Some(ce_id) = entry.custom_enrichment_id {
                    // Fire-and-forget: a Deno sync (fetch + thousands of CH
                    // inserts) can take minutes. Awaiting it inline blocked the
                    // HTTP response and — worse — tied the run to the request
                    // lifecycle, so a client disconnect cancelled the handler
                    // future before `complete_run()` fired and orphaned the run
                    // in `status='running'` (NAN-1113). Spawn it like the
                    // `native` branch; the run record + is_syncing polling
                    // (NAN-1108) surface progress.
                    let state_spawn = state.clone();
                    let client_spawn = client.clone();
                    let slug_spawn = slug.clone();
                    tokio::spawn(async move {
                        if let Err(e) = super::custom_enrichment::trigger_run(
                            State(state_spawn),
                            Extension(auth),
                            Extension(client_spawn),
                            Path(TypeIdParam(ce_id)),
                        )
                        .await
                        {
                            tracing::error!(slug = %slug_spawn, error = %e, "Deno enrichment sync failed");
                        }
                    });
                } else {
                    return Err(ApiError::BadRequest(
                        "Deno enrichment has no custom_enrichment_id".to_string(),
                    ));
                }
            }
            #[cfg(not(feature = "enterprise"))]
            {
                let _ = entry;
                return Err(ApiError::BadRequest(
                    "Deno enrichment runtime is not available in the open-core build".to_string(),
                ));
            }
        }
        "identity" => {
            // Same fire-and-forget treatment as the deno path (NAN-1113):
            // don't block the HTTP response on the provider sync.
            let install_service = MarketplaceInstallService::new(state.pool.clone());
            let slug_spawn = slug.clone();
            tokio::spawn(async move {
                if let Err(e) = install_service.trigger_sync(&slug_spawn).await {
                    tracing::error!(slug = %slug_spawn, error = %e, "Identity provider sync failed");
                }
            });
        }
        _ => {
            return Err(ApiError::BadRequest(format!(
                "Unknown execution backend: {}",
                entry.execution_backend
            )));
        }
    }

    state.emit_audit(
        AuditEvent::builder(AuditSource::Marketplace, MARKETPLACE_SYNC_TRIGGERED)
            .actor(Some(actor_id), None)
            .api_key(api_key_id, api_key_name)
            .resource("enrichment", None, Some(slug.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(MessageResponse {
        message: format!("Sync triggered for {}", slug),
    }))
}

/// Get status for an installed enrichment
#[utoipa::path(
    get,
    path = "/api/marketplace/catalog/{slug}/status",
    tag = "marketplace",
    params(("slug" = String, Path, description = "Catalog entry slug")),
    responses(
        (status = 200, description = "Status retrieved", body = EnrichmentStatus),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_enrichment_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(slug): Path<String>,
) -> Result<Json<EnrichmentStatus>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".to_string()))?;

    let repo = MarketplaceRepository::new(state.pool.clone());
    let entry = repo.get_catalog_entry(&slug).await?;

    Ok(Json(EnrichmentStatus {
        slug: entry.slug,
        installed: entry.installed,
        enabled: entry.enabled,
        last_sync_at: entry.last_sync_at,
        last_sync_status: entry.last_sync_status,
        last_error: entry.last_error,
        record_count: entry.record_count,
    }))
}

/// Export an enrichment as manifest.yaml + code.ts for contributing to a repo
#[utoipa::path(
    get,
    path = "/api/marketplace/catalog/{slug}/export",
    tag = "marketplace",
    params(("slug" = String, Path, description = "Catalog entry slug")),
    responses(
        (status = 200, description = "Enrichment exported", body = ExportResponse),
        (status = 400, description = "Not exportable (native backend)"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn export_enrichment(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(slug): Path<String>,
) -> Result<Json<ExportResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".to_string()))?;

    let repo = MarketplaceRepository::new(state.pool.clone());
    let entry = repo.get_catalog_entry(&slug).await?;

    if entry.execution_backend == "native" || entry.execution_backend == "identity" {
        return Err(ApiError::BadRequest(
            "Native and identity enrichments cannot be exported".to_string(),
        ));
    }

    let code = entry.code.clone().unwrap_or_default();

    // Parse credential_fields from JSON column back to Vec<CredentialFieldDef>
    let credential_fields: Vec<CredentialFieldDef> =
        serde_json::from_value(entry.credential_fields.0.clone()).unwrap_or_default();

    // Build manifest struct
    let manifest = MarketplaceManifest {
        name: entry.name.clone(),
        slug: entry.slug.clone(),
        category: entry.category.clone(),
        description: entry.description.clone().unwrap_or_default(),
        icon: entry.icon.clone(),
        author: entry
            .author
            .clone()
            .unwrap_or_else(|| "Community".to_string()),
        version: entry.manifest_version,
        requires_credential: entry.requires_credential.clone(),
        credential_fields,
        allowed_domains: entry.allowed_domains.clone(),
        config: entry.config.0.clone(),
        tags: entry.tags.clone(),
        output_mapping: None,
        changelog: entry.changelog.clone(),
    };

    let manifest_yaml = serde_yaml::to_string(&manifest)
        .map_err(|e| ApiError::InternalError(format!("Failed to serialize manifest: {}", e)))?;

    let directory = format!("enrichments/{}/{}/", entry.category, entry.slug);

    Ok(Json(ExportResponse {
        slug: entry.slug,
        directory,
        manifest_yaml,
        code,
    }))
}

// =============================================================================
// Repository Handlers
// =============================================================================

/// List enrichment marketplace repos
#[utoipa::path(
    get,
    path = "/api/marketplace/repos",
    tag = "marketplace",
    responses(
        (status = 200, description = "Repos listed", body = ListReposResponse),
    ),
    security(("api_key" = []))
)]
pub async fn list_repos(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ListReposResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".to_string()))?;

    let repo = MarketplaceRepository::new(state.pool.clone());
    let repos = repo.list_repos().await?;
    Ok(Json(ListReposResponse { repos }))
}

/// Add a new enrichment marketplace repo
#[utoipa::path(
    post,
    path = "/api/marketplace/repos",
    tag = "marketplace",
    request_body = CreateMarketplaceRepo,
    responses(
        (status = 201, description = "Repo created", body = EnrichmentMarketplaceRepo),
        (status = 409, description = "Already exists"),
    ),
    security(("api_key" = []))
)]
pub async fn create_repo(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<CreateMarketplaceRepo>,
) -> Result<Json<EnrichmentMarketplaceRepo>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    let repo = MarketplaceRepository::new(state.pool.clone());
    let created = repo.create_repo(&request, Some(auth.user_id())).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Marketplace, MARKETPLACE_REPO_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "marketplace_repo",
                Some(created.id),
                Some(created.name.clone()),
            )
            .client_context(&client)
            .build(),
    );

    Ok(Json(created))
}

/// Update a repo
#[utoipa::path(
    put,
    path = "/api/marketplace/repos/{id}",
    tag = "marketplace",
    params(("id" = String, Path, description = "Repository ID")),
    request_body = UpdateMarketplaceRepo,
    responses(
        (status = 200, description = "Repo updated", body = EnrichmentMarketplaceRepo),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn update_repo(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateMarketplaceRepo>,
) -> Result<Json<EnrichmentMarketplaceRepo>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    let repo = MarketplaceRepository::new(state.pool.clone());
    let updated = repo.update_repo(*id, &request).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Marketplace, MARKETPLACE_REPO_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("marketplace_repo", Some(*id), None)
            .client_context(&client)
            .build(),
    );

    Ok(Json(updated))
}

/// Delete a repo
#[utoipa::path(
    delete,
    path = "/api/marketplace/repos/{id}",
    tag = "marketplace",
    params(("id" = String, Path, description = "Repository ID")),
    responses(
        (status = 200, description = "Repo deleted", body = MessageResponse),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_repo(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<MessageResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    let repo = MarketplaceRepository::new(state.pool.clone());
    repo.delete_repo(*id).await?;
    Ok(Json(MessageResponse {
        message: "Repository deleted".to_string(),
    }))
}

/// Sync a repo from GitHub
#[utoipa::path(
    post,
    path = "/api/marketplace/repos/{id}/sync",
    tag = "marketplace",
    params(("id" = String, Path, description = "Repository ID")),
    responses(
        (status = 200, description = "Sync started", body = MessageResponse),
        (status = 409, description = "Sync already in progress"),
    ),
    security(("api_key" = []))
)]
pub async fn sync_repo(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<MessageResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    let sync_service = MarketplaceSyncService::new(state.pool.clone());
    sync_service.start_sync(*id).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Marketplace, MARKETPLACE_REPO_SYNCED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("marketplace_repo", Some(*id), None)
            .client_context(&client)
            .build(),
    );

    Ok(Json(MessageResponse {
        message: "Repository sync started".to_string(),
    }))
}

/// Browse the enrichments directory of a repo
#[utoipa::path(
    get,
    path = "/api/marketplace/repos/{id}/browse",
    tag = "marketplace",
    params(("id" = String, Path, description = "Repository ID")),
    responses(
        (status = 200, description = "Repo browsed", body = BrowseRepoResponse),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn browse_repo(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<BrowseRepoResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".to_string()))?;

    let sync_service = MarketplaceSyncService::new(state.pool.clone());
    let entries = sync_service.browse_repo(*id).await?;
    Ok(Json(BrowseRepoResponse { entries }))
}

// Note: `From<MarketplaceError> for ApiError` lifted to nanosiem-api-lib in
// NAN-752 (orphan rule — `ApiError` lives there now).

// =============================================================================
// Preview Output (dry-run for `deno`-backend enrichments)
// =============================================================================

/// Default sample artifact for each supported artifact_type. Picked to be
/// (a) globally well-known and (b) cheap to look up against any typical
/// threat-intel API. Keeps `?artifact=` optional so the drawer button is a
/// one-click flow.
///
/// Only called from `preview_enrichment`, which is enterprise-only after
/// Phase 3.3 of NAN-744 — gate the helper to silence the dead-code warning.
#[cfg(feature = "enterprise")]
fn default_sample_artifact(artifact_type: &str) -> &'static str {
    match artifact_type {
        "ip" => "8.8.8.8",
        "domain" => "example.com",
        "hash" => "44d88612fea8a8f36de82e1278abb02f", // EICAR test file MD5
        "url" => "https://example.com/test",
        "email" => "test@example.com",
        "filename" => "example.txt",
        _ => "8.8.8.8",
    }
}

/// Run the enrichment against a sample artifact and return the parsed result.
///
/// Only `deno`-backed entries are previewable today — `native` (IPinfo Lite)
/// and `identity` (SSO providers) backends return a friendly note explaining
/// why preview is unavailable. The frontend renders the note as-is.
#[utoipa::path(
    post,
    path = "/api/marketplace/catalog/{slug}/preview",
    tag = "marketplace",
    params(("slug" = String, Path, description = "Catalog entry slug")),
    request_body = PreviewRequest,
    responses(
        (status = 200, description = "Preview result", body = PreviewResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
#[cfg(feature = "enterprise")]
pub async fn preview_enrichment(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(slug): Path<String>,
    Json(req): Json<PreviewRequest>,
) -> Result<Json<PreviewResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".to_string()))?;

    let repo = MarketplaceRepository::new(state.pool.clone());
    let entry = repo.get_catalog_entry(&slug).await?;

    let artifact_type = req
        .artifact_type
        .unwrap_or_else(|| "ip".to_string())
        .to_lowercase();
    let artifact = req
        .artifact
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| default_sample_artifact(&artifact_type).to_string());

    // 1. Backend gate — only deno is previewable today.
    if entry.execution_backend != "deno" {
        return Ok(Json(PreviewResponse {
            success: false,
            artifact,
            artifact_type,
            output: None,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
            note: Some(format!(
                "Preview is only available for `deno`-backed enrichments. \
                 `{}` uses the `{}` backend, which is invoked directly by the engine.",
                entry.slug, entry.execution_backend
            )),
            error: None,
        }));
    }

    // 2. Code gate — the catalog row should always have code for a deno entry,
    // but defend against a row that arrived from a malformed manifest.
    let code = match entry.code.as_deref() {
        Some(c) if !c.is_empty() => c,
        _ => {
            return Ok(Json(PreviewResponse {
                success: false,
                artifact,
                artifact_type,
                output: None,
                stdout: String::new(),
                stderr: String::new(),
                duration_ms: 0,
                note: Some(
                    "This enrichment has no code attached. Re-sync the repository or \
                     re-install to populate it."
                        .to_string(),
                ),
                error: None,
            }));
        }
    };

    // 3. Decrypt credentials if present. Missing credentials don't block the
    // run (some scripts have public modes), but most IOC providers will return
    // an "auth required" error from the API itself, which surfaces in stderr.
    let credentials = match (&entry.credentials_encrypted, &entry.credentials_nonce) {
        (Some(ciphertext), Some(nonce)) => state
            .encryption_service
            .decrypt_credentials_bytea(ciphertext, nonce)
            .unwrap_or_default(),
        _ => std::collections::HashMap::new(),
    };

    // 4. Invoke the sandbox. 5s timeout — preview is interactive, not the
    // 30s+ that the real enrichment scheduler tolerates.
    const PREVIEW_TIMEOUT_SECS: u64 = 5;
    let executor = SandboxExecutor::new();
    let started = std::time::Instant::now();
    let result = execute_agent_enrichment(
        &executor,
        code,
        credentials,
        entry.allowed_domains.clone(),
        &artifact,
        &artifact_type,
        None,
        PREVIEW_TIMEOUT_SECS,
    )
    .await;

    Ok(Json(match result {
        Ok(r) => PreviewResponse {
            success: r.success,
            artifact,
            artifact_type,
            output: r.output,
            stdout: r.stdout,
            stderr: r.stderr,
            duration_ms: r.duration_ms,
            note: None,
            error: r.error.map(|e| e.to_string()),
        },
        Err(e) => PreviewResponse {
            success: false,
            artifact,
            artifact_type,
            output: None,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: started.elapsed().as_millis() as u64,
            note: None,
            error: Some(format!("Sandbox error: {}", e)),
        },
    }))
}

// =============================================================================
// Coverage Hero
// =============================================================================

/// Get marketplace coverage by artifact type. Backed by a 6h
/// Dragonfly-shared cache (NAN-609) — `computed_at` in the response is the
/// time the SQL was last *actually* run, not the time this request was
/// served. Use `POST /api/marketplace/coverage/refresh` to force a
/// recompute from the UI.
#[utoipa::path(
    get,
    path = "/api/marketplace/coverage",
    tag = "marketplace",
    responses(
        (status = 200, description = "Coverage rows retrieved", body = MarketplaceCoverage),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn get_coverage(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<MarketplaceCoverage>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".to_string()))?;

    let svc = build_coverage_service(&state);
    let coverage = svc.compute().await?;
    Ok(Json(coverage))
}

/// Force a recompute of the marketplace coverage hero. Invalidates the
/// shared Dragonfly cache, runs the SQL fresh, returns the new payload
/// (which is also `set()` back into the cache by `compute()`). Same
/// permission as the GET endpoint.
#[utoipa::path(
    post,
    path = "/api/marketplace/coverage/refresh",
    tag = "marketplace",
    responses(
        (status = 200, description = "Coverage recomputed and re-cached", body = MarketplaceCoverage),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn refresh_coverage(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<MarketplaceCoverage>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".to_string()))?;

    // Drop the cached entry so concurrent in-flight readers also miss and
    // recompute (last write wins — see cache.rs concurrency note).
    state.marketplace_coverage_cache.invalidate().await;

    let svc = build_coverage_service(&state);
    let coverage = svc.compute().await?;
    Ok(Json(coverage))
}

/// Construct a coverage service wired to the shared cache. Factored out so
/// the GET and refresh handlers can't drift apart on which cache they use.
fn build_coverage_service(state: &AppState) -> MarketplaceCoverageService {
    MarketplaceCoverageService::new_with_cache(
        state.pool.clone(),
        state.dual_pool.clickhouse().clone(),
        (*state.marketplace_coverage_cache).clone(),
    )
}

// =============================================================================
// OpenAPI Doc
// =============================================================================

// Two cfg-gated derives — `preview_enrichment` only compiles on enterprise
// (Phase 3.3 of NAN-744 lifted the deno sandbox), so the OpenAPI registration
// has to fork the same way. SettingsApiDoc + EnrichmentApiDoc use the same
// pattern.
#[cfg(feature = "enterprise")]
#[derive(OpenApi)]
#[openapi(
    paths(
        list_catalog,
        get_catalog_entry,
        install_enrichment,
        uninstall_enrichment,
        update_enrichment,
        configure_enrichment,
        sync_enrichment,
        get_enrichment_status,
        export_enrichment,
        preview_enrichment,
        get_coverage,
        refresh_coverage,
        list_repos,
        create_repo,
        update_repo,
        delete_repo,
        sync_repo,
        browse_repo,
    ),
    components(schemas(
        ListCatalogResponse,
        ListReposResponse,
        BrowseRepoResponse,
        MessageResponse,
        ExportResponse,
        PreviewRequest,
        PreviewResponse,
        MarketplaceCatalogEntry,
        EnrichmentMarketplaceRepo,
        CatalogStats,
        EnrichmentStatus,
        InstallRequest,
        ConfigureRequest,
        CreateMarketplaceRepo,
        UpdateMarketplaceRepo,
        RepoBrowseEntry,
        MarketplaceCoverage,
        ArtifactCoverage,
        CoverageState,
    ))
)]
pub struct MarketplaceApiDoc;

#[cfg(not(feature = "enterprise"))]
#[derive(OpenApi)]
#[openapi(
    paths(
        list_catalog,
        get_catalog_entry,
        install_enrichment,
        uninstall_enrichment,
        update_enrichment,
        configure_enrichment,
        sync_enrichment,
        get_enrichment_status,
        export_enrichment,
        get_coverage,
        refresh_coverage,
        list_repos,
        create_repo,
        update_repo,
        delete_repo,
        sync_repo,
        browse_repo,
    ),
    components(schemas(
        ListCatalogResponse,
        ListReposResponse,
        BrowseRepoResponse,
        MessageResponse,
        ExportResponse,
        MarketplaceCatalogEntry,
        EnrichmentMarketplaceRepo,
        CatalogStats,
        EnrichmentStatus,
        InstallRequest,
        ConfigureRequest,
        CreateMarketplaceRepo,
        UpdateMarketplaceRepo,
        RepoBrowseEntry,
        MarketplaceCoverage,
        ArtifactCoverage,
        CoverageState,
    ))
)]
pub struct MarketplaceApiDoc;
