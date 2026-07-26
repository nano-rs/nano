// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment Marketplace endpoint handlers
//!
//! Unified catalog for data enrichments, agent enrichments, custom enrichments,
//! and identity providers. Includes GitHub repository sync for community content.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use std::collections::BTreeSet;
// Marketplace's deno-runtime call sites (sync_enrichment "deno" arm and
// preview_enrichment) are cfg-gated for enterprise — Phase 3.3 of NAN-744
// lifted custom_enrichment to the enterprise crate. Catalog list / install /
// uninstall / repo sync paths stay open since they only touch PG.
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::custom_enrichment::{
    execute_agent_enrichment, execute_data_enrichment, SandboxExecutor,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, MARKETPLACE_CONFIGURED, MARKETPLACE_INSTALLED,
    MARKETPLACE_REPO_CREATED, MARKETPLACE_REPO_SYNCED, MARKETPLACE_REPO_UPDATED,
    MARKETPLACE_SYNC_TRIGGERED, MARKETPLACE_UNINSTALLED, MARKETPLACE_UPDATED,
};
#[cfg(feature = "enterprise")]
use nanosiem_core::audit::MARKETPLACE_PREVIEW_EXECUTED;
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
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Marketplace source follows the same composite read boundary as custom
/// enrichment source (NAN-2129).
fn may_return_marketplace_code(auth: &AuthContext) -> bool {
    auth.has_permission(permissions::ENRICHMENTS_VIEW)
        && auth.has_permission(permissions::ENRICHMENTS_CODE)
}

fn require_marketplace_code_read(auth: &AuthContext) -> Result<(), ApiError> {
    ensure_permission(auth, permissions::ENRICHMENTS_VIEW)?;
    ensure_permission(auth, permissions::ENRICHMENTS_CODE)
}

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
    ensure_permission(&auth, permissions::ENRICHMENTS_VIEW)?;

    let repo = MarketplaceRepository::new(state.pool.clone());
    let entries = repo.list_catalog(&filter).await?;
    let stats = repo.get_catalog_stats().await?;

    // NAN-2069: one unfiltered call returned every published enrichment's
    // `config.auth_config` in cleartext. Mask before serializing.
    let include_code = may_return_marketplace_code(&auth);
    let entries: Vec<MarketplaceCatalogEntry> = entries
        .into_iter()
        .map(|entry| entry.redacted_with_code_access(include_code))
        .collect();

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
    ensure_permission(&auth, permissions::ENRICHMENTS_VIEW)?;

    let repo = MarketplaceRepository::new(state.pool.clone());
    let entry = repo.get_catalog_entry(&slug).await?;
    Ok(Json(entry.redacted_with_code_access(
        may_return_marketplace_code(&auth),
    )))
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
    ensure_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)?;

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

    Ok(Json(entry.redacted_with_code_access(
        may_return_marketplace_code(&auth),
    )))
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
    ensure_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)?;

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

    Ok(Json(entry.redacted_with_code_access(
        may_return_marketplace_code(&auth),
    )))
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
    ensure_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)?;

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

    Ok(Json(entry.redacted_with_code_access(
        may_return_marketplace_code(&auth),
    )))
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
    ensure_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)?;

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

    Ok(Json(entry.redacted_with_code_access(
        may_return_marketplace_code(&auth),
    )))
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
    ensure_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)?;

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

    // Air-gap guard: refuse cleanly BEFORE any egress for connectivity-required
    // entries (identity sync, native bulk feed, deno with allowed_domains). No
    // fetch attempt, no timeout — the operator side-loads a signed bundle via
    // the air-gap import surface instead.
    if state.config.airgap && entry.requires_network {
        return Err(ApiError::Conflict(
            "Unavailable in air-gapped mode — import a signed data bundle instead.".to_string(),
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
    ensure_permission(&auth, permissions::ENRICHMENTS_VIEW)?;

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
    require_marketplace_code_read(&auth)?;

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
        // NAN-2069: the export re-emits `config` inside `manifest_yaml`, so it
        // is a second serialization path for the same secrets and needs its
        // own handling — `redacted()` on the response entry does not reach it.
        //
        // STRIP rather than mask here: this manifest is meant to be shared and
        // re-imported, and the placeholder is data. Repository sync persists
        // the manifest config verbatim and an install without an override uses
        // it unchanged, so masking would produce an imported enrichment that
        // authenticates with the literal `***REDACTED***`. Omitting the keys
        // yields an honest manifest — the importer supplies their own secret.
        config: {
            let mut config = entry.config.0.clone();
            nanosiem_core::config_secrets::strip_config_secrets(&mut config);
            config
        },
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
    ensure_permission(&auth, permissions::ENRICHMENTS_VIEW)?;

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
    ensure_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)?;

    // Air-gap guard: a GitHub-backed repo only makes sense with outbound
    // internet (the create path validates the URL with a live DNS/SSRF check
    // and every later sync egresses). Refuse cleanly rather than create a repo
    // that can never sync.
    if state.config.airgap {
        return Err(ApiError::Conflict(
            "Unavailable in air-gapped mode — repositories sync from GitHub, which requires outbound internet."
                .to_string(),
        ));
    }

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
    ensure_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)?;

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
    ensure_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)?;

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
    ensure_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)?;

    // Air-gap guard: a repo sync clones from GitHub — refuse before egress.
    if state.config.airgap {
        return Err(ApiError::Conflict(
            "Unavailable in air-gapped mode — repository sync requires outbound internet."
                .to_string(),
        ));
    }

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
    ensure_permission(&auth, permissions::ENRICHMENTS_VIEW)?;

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

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone)]
struct PreviewEntry {
    id: uuid::Uuid,
    slug: String,
    name: String,
    execution_backend: String,
    category: String,
    code: Option<String>,
    allowed_domains: Vec<String>,
    config: serde_json::Value,
    credentials_encrypted: Option<Vec<u8>>,
    credentials_nonce: Option<String>,
}

#[cfg(feature = "enterprise")]
struct PreviewExecutionRequest {
    code: String,
    credentials: std::collections::HashMap<String, String>,
    allowed_domains: Vec<String>,
    artifact: String,
    artifact_type: String,
    is_data_enrichment: bool,
}

#[cfg(feature = "enterprise")]
#[derive(Debug, Clone)]
struct PreviewExecutionResult {
    success: bool,
    output: Option<serde_json::Value>,
    stdout: String,
    stderr: String,
    duration_ms: u64,
    error: Option<String>,
}

/// Stateful preview operations are isolated behind this trait so tests exercise
/// the exact production workflow and can prove denied callers never reach a
/// catalog read, credential decrypt, or sandbox execution.
#[cfg(feature = "enterprise")]
#[async_trait::async_trait]
trait MarketplacePreviewRuntime: Send + Sync {
    async fn load_entry(&self, slug: &str) -> Result<PreviewEntry, ApiError>;

    fn decrypt_credentials(
        &self,
        ciphertext: &[u8],
        nonce: &str,
    ) -> Result<std::collections::HashMap<String, String>, String>;

    async fn execute_preview(
        &self,
        request: PreviewExecutionRequest,
    ) -> Result<PreviewExecutionResult, String>;

    fn emit_preview_audit(&self, event: AuditEvent);
}

#[cfg(feature = "enterprise")]
#[async_trait::async_trait]
impl MarketplacePreviewRuntime for AppState {
    async fn load_entry(&self, slug: &str) -> Result<PreviewEntry, ApiError> {
        let repo = MarketplaceRepository::new(self.pool.clone());
        let entry = repo.get_catalog_entry(slug).await?;
        Ok(PreviewEntry {
            id: entry.id,
            slug: entry.slug,
            name: entry.name,
            execution_backend: entry.execution_backend,
            category: entry.category,
            code: entry.code,
            allowed_domains: entry.allowed_domains,
            config: entry.config.0,
            credentials_encrypted: entry.credentials_encrypted,
            credentials_nonce: entry.credentials_nonce,
        })
    }

    fn decrypt_credentials(
        &self,
        ciphertext: &[u8],
        nonce: &str,
    ) -> Result<std::collections::HashMap<String, String>, String> {
        self.encryption_service
            .decrypt_credentials_bytea(ciphertext, nonce)
            .map_err(|error| error.to_string())
    }

    async fn execute_preview(
        &self,
        request: PreviewExecutionRequest,
    ) -> Result<PreviewExecutionResult, String> {
        const PREVIEW_TIMEOUT_SECS: u64 = 5;
        let executor = SandboxExecutor::new();
        let result = if request.is_data_enrichment {
            // Bulk feed: pass a watermark so the script fetches the
            // incremental (not full-backfill) window.
            execute_data_enrichment(
                &executor,
                &request.code,
                request.credentials,
                request.allowed_domains,
                Some(chrono::Utc::now().to_rfc3339()),
                None,
                PREVIEW_TIMEOUT_SECS,
            )
            .await
        } else {
            execute_agent_enrichment(
                &executor,
                &request.code,
                request.credentials,
                request.allowed_domains,
                &request.artifact,
                &request.artifact_type,
                None,
                PREVIEW_TIMEOUT_SECS,
            )
            .await
        }
        .map_err(|error| error.to_string())?;

        Ok(PreviewExecutionResult {
            success: result.success,
            output: result.output,
            stdout: result.stdout,
            stderr: result.stderr,
            duration_ms: result.duration_ms,
            error: result.error.map(|error| error.to_string()),
        })
    }

    fn emit_preview_audit(&self, event: AuditEvent) {
        self.emit_audit(event);
    }
}

#[cfg(feature = "enterprise")]
fn secret_patterns(
    credentials: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    let mut patterns = credentials
        .values()
        .filter(|value| !value.is_empty())
        .flat_map(|value| {
            let json_escaped = serde_json::to_string(value).ok().and_then(|encoded| {
                encoded
                    .strip_prefix('"')
                    .and_then(|encoded| encoded.strip_suffix('"'))
                    .map(ToString::to_string)
            });
            std::iter::once(value.clone()).chain(json_escaped)
        })
        .collect::<Vec<_>>();
    patterns.sort_by_key(|value| std::cmp::Reverse(value.len()));
    patterns.dedup();
    patterns
}

#[cfg(feature = "enterprise")]
fn redact_text(mut value: String, secret_patterns: &[String]) -> String {
    for secret in secret_patterns {
        value = value.replace(secret, "[REDACTED]");
    }
    value
}

#[cfg(feature = "enterprise")]
fn redact_json(value: &mut serde_json::Value, secret_patterns: &[String]) {
    match value {
        serde_json::Value::String(text) => {
            *text = redact_text(std::mem::take(text), secret_patterns);
        }
        serde_json::Value::Array(values) => {
            for value in values {
                redact_json(value, secret_patterns);
            }
        }
        serde_json::Value::Object(values) => {
            let original = std::mem::take(values);
            for (key, mut value) in original {
                redact_json(&mut value, secret_patterns);
                values.insert(redact_text(key, secret_patterns), value);
            }
        }
        _ => {}
    }
}

#[cfg(feature = "enterprise")]
#[allow(clippy::too_many_arguments)]
fn audit_preview<R: MarketplacePreviewRuntime>(
    runtime: &R,
    auth: &AuthContext,
    client: &ClientContext,
    entry: &PreviewEntry,
    artifact_type: &str,
    duration_ms: u64,
    success: bool,
    credentials_used: bool,
) {
    runtime.emit_preview_audit(
        AuditEvent::builder(AuditSource::Marketplace, MARKETPLACE_PREVIEW_EXECUTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("enrichment", Some(entry.id), Some(entry.name.clone()))
            .client_context(client)
            .success(success)
            .details(serde_json::json!({
                "slug": entry.slug,
                "artifact_type": artifact_type,
                "duration_ms": duration_ms,
                "credentials_used": credentials_used,
            }))
            .build(),
    );
}

#[cfg(feature = "enterprise")]
async fn run_marketplace_preview<R: MarketplacePreviewRuntime>(
    runtime: &R,
    auth: &AuthContext,
    client: &ClientContext,
    slug: &str,
    req: PreviewRequest,
) -> Result<Json<PreviewResponse>, ApiError> {
    // This must remain the first operation. Loading the catalog entry exposes
    // executable code and encrypted credential material; everything after the
    // guard can decrypt credentials, make outbound requests, and run code.
    ensure_permission(auth, permissions::ENRICHMENTS_CONFIGURE)?;

    let entry = runtime.load_entry(slug).await?;
    let started = std::time::Instant::now();
    let artifact_type = req
        .artifact_type
        .unwrap_or_else(|| "ip".to_string())
        .to_lowercase();
    let artifact = req
        .artifact
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default_sample_artifact(&artifact_type).to_string());

    if entry.execution_backend != "deno" {
        audit_preview(
            runtime,
            auth,
            client,
            &entry,
            &artifact_type,
            started.elapsed().as_millis() as u64,
            false,
            false,
        );
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

    let code = match entry.code.clone() {
        Some(code) if !code.is_empty() => code,
        _ => {
            audit_preview(
                runtime,
                auth,
                client,
                &entry,
                &artifact_type,
                started.elapsed().as_millis() as u64,
                false,
                false,
            );
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

    let credentials = match (
        entry.credentials_encrypted.as_deref(),
        entry.credentials_nonce.as_deref(),
    ) {
        (Some(ciphertext), Some(nonce)) => match runtime.decrypt_credentials(ciphertext, nonce) {
            Ok(credentials) => credentials,
            Err(error) => {
                tracing::warn!(
                    slug = %entry.slug,
                    error = %error,
                    "Marketplace preview could not decrypt stored credentials"
                );
                let duration_ms = started.elapsed().as_millis() as u64;
                audit_preview(
                    runtime,
                    auth,
                    client,
                    &entry,
                    &artifact_type,
                    duration_ms,
                    false,
                    false,
                );
                return Ok(Json(PreviewResponse {
                    success: false,
                    artifact,
                    artifact_type,
                    output: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    duration_ms,
                    note: None,
                    error: Some(
                        "Stored credentials could not be loaded. Re-save the enrichment configuration."
                            .to_string(),
                    ),
                }));
            }
        },
        _ => std::collections::HashMap::new(),
    };

    let credentials_used = !credentials.is_empty();
    let secret_patterns = secret_patterns(&credentials);
    let execution = runtime
        .execute_preview(PreviewExecutionRequest {
            code,
            credentials,
            allowed_domains: entry.allowed_domains.clone(),
            artifact: artifact.clone(),
            artifact_type: artifact_type.clone(),
            is_data_enrichment: nanosiem_core::marketplace::infer_enrichment_type(
                &entry.category,
                &entry.config,
            ) == "data",
        })
        .await;

    let mut response = match execution {
        Ok(result) => PreviewResponse {
            success: result.success,
            artifact,
            artifact_type: artifact_type.clone(),
            output: result.output,
            stdout: result.stdout,
            stderr: result.stderr,
            duration_ms: result.duration_ms,
            note: None,
            error: result.error,
        },
        Err(error) => PreviewResponse {
            success: false,
            artifact,
            artifact_type: artifact_type.clone(),
            output: None,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: started.elapsed().as_millis() as u64,
            note: None,
            error: Some(format!("Sandbox error: {error}")),
        },
    };

    if let Some(output) = response.output.as_mut() {
        redact_json(output, &secret_patterns);
    }
    response.stdout = redact_text(response.stdout, &secret_patterns);
    response.stderr = redact_text(response.stderr, &secret_patterns);
    response.error = response
        .error
        .map(|error| redact_text(error, &secret_patterns));

    audit_preview(
        runtime,
        auth,
        client,
        &entry,
        &artifact_type,
        response.duration_ms,
        response.success,
        credentials_used,
    );

    Ok(Json(response))
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
        (status = 403, description = "Missing enrichments:configure permission"),
        (status = 404, description = "Not found"),
        (status = 429, description = "Preview rate limit exceeded"),
    ),
    security(("api_key" = []))
)]
#[cfg(feature = "enterprise")]
pub async fn preview_enrichment(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(slug): Path<String>,
    Json(req): Json<PreviewRequest>,
) -> Result<Json<PreviewResponse>, ApiError> {
    run_marketplace_preview(&state, &auth, &client, &slug, req).await
}

#[cfg(all(test, feature = "enterprise"))]
mod preview_tests {
    use super::*;
    use nanosiem_core::auth::api_key::ApiKeyInfo;
    use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
    use nanosiem_core::auth::TokenClaims;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use uuid::Uuid;

    struct SpyPreviewRuntime {
        entry: PreviewEntry,
        credentials: HashMap<String, String>,
        execution_result: PreviewExecutionResult,
        loads: AtomicUsize,
        decrypts: AtomicUsize,
        executions: AtomicUsize,
        audits: Mutex<Vec<AuditEvent>>,
    }

    impl SpyPreviewRuntime {
        fn successful() -> Self {
            Self {
                entry: PreviewEntry {
                    id: Uuid::now_v7(),
                    slug: "test-provider".to_string(),
                    name: "Test Provider".to_string(),
                    execution_backend: "deno".to_string(),
                    category: "agent".to_string(),
                    code: Some("export function enrich() { return {}; }".to_string()),
                    allowed_domains: vec!["api.example.com".to_string()],
                    config: serde_json::json!({}),
                    credentials_encrypted: None,
                    credentials_nonce: None,
                },
                credentials: HashMap::new(),
                execution_result: PreviewExecutionResult {
                    success: true,
                    output: Some(serde_json::json!({"ok": true})),
                    stdout: String::new(),
                    stderr: String::new(),
                    duration_ms: 12,
                    error: None,
                },
                loads: AtomicUsize::new(0),
                decrypts: AtomicUsize::new(0),
                executions: AtomicUsize::new(0),
                audits: Mutex::new(Vec::new()),
            }
        }

        fn leaking(secret: &str) -> Self {
            let mut runtime = Self::successful();
            runtime.entry.credentials_encrypted = Some(vec![1, 2, 3]);
            runtime.entry.credentials_nonce = Some("nonce".to_string());
            runtime
                .credentials
                .insert("api_key".to_string(), secret.to_string());
            let escaped = serde_json::to_string(secret).unwrap();
            runtime.execution_result = PreviewExecutionResult {
                success: false,
                output: Some(serde_json::json!({
                    "nested": [
                        secret,
                        {format!("key-{secret}"): format!("value={secret}")}
                    ]
                })),
                stdout: format!("stdout credential={secret}"),
                stderr: format!("stderr json={escaped}"),
                duration_ms: 19,
                error: Some(format!("provider rejected {secret}")),
            };
            runtime
        }

        fn assert_no_side_effects(&self) {
            assert_eq!(self.loads.load(Ordering::SeqCst), 0);
            assert_eq!(self.decrypts.load(Ordering::SeqCst), 0);
            assert_eq!(self.executions.load(Ordering::SeqCst), 0);
            assert!(self.audits.lock().unwrap().is_empty());
        }
    }

    #[async_trait::async_trait]
    impl MarketplacePreviewRuntime for SpyPreviewRuntime {
        async fn load_entry(&self, _slug: &str) -> Result<PreviewEntry, ApiError> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            Ok(self.entry.clone())
        }

        fn decrypt_credentials(
            &self,
            _ciphertext: &[u8],
            _nonce: &str,
        ) -> Result<HashMap<String, String>, String> {
            self.decrypts.fetch_add(1, Ordering::SeqCst);
            Ok(self.credentials.clone())
        }

        async fn execute_preview(
            &self,
            _request: PreviewExecutionRequest,
        ) -> Result<PreviewExecutionResult, String> {
            self.executions.fetch_add(1, Ordering::SeqCst);
            Ok(self.execution_result.clone())
        }

        fn emit_preview_audit(&self, event: AuditEvent) {
            self.audits.lock().unwrap().push(event);
        }
    }

    fn session(permissions: &[&str]) -> AuthContext {
        AuthContext::from_jwt(TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: Vec::new(),
            permissions: permissions.iter().map(ToString::to_string).collect(),
            exp: chrono::Utc::now().timestamp() + 60,
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        })
    }

    fn api_key(permissions: &[&str]) -> AuthContext {
        AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "marketplace-preview".to_string(),
            permissions: permissions.iter().map(ToString::to_string).collect(),
            user_id: Some(Uuid::now_v7()),
        })
    }

    fn request() -> PreviewRequest {
        PreviewRequest {
            artifact: None,
            artifact_type: Some("ip".to_string()),
        }
    }

    #[tokio::test]
    async fn denied_principals_never_read_decrypt_or_execute() {
        // This calls the production workflow, not a copied permission
        // predicate. The spy makes every stateful boundary observable.
        for auth in [
            session(&[]),
            session(&[permissions::ENRICHMENTS_VIEW]),
            session(&[permissions::SEARCH_VIEW]),
            api_key(&[]),
            api_key(&[permissions::ENRICHMENTS_VIEW]),
            api_key(&[permissions::SEARCH_VIEW]),
        ] {
            let runtime = SpyPreviewRuntime::successful();
            let result = run_marketplace_preview(
                &runtime,
                &auth,
                &ClientContext::default(),
                "test-provider",
                request(),
            )
            .await;

            assert!(matches!(result, Err(ApiError::Forbidden(_))));
            runtime.assert_no_side_effects();
        }
    }

    #[tokio::test]
    async fn configure_permission_executes_for_sessions_and_api_keys() {
        for auth in [
            session(&[permissions::ENRICHMENTS_CONFIGURE]),
            api_key(&[permissions::ENRICHMENTS_CONFIGURE]),
        ] {
            let expected_api_key_id = auth.api_key_id;
            let expected_actor_id = auth.user_id();
            let runtime = SpyPreviewRuntime::successful();
            let expected_entry_id = runtime.entry.id;
            let response = run_marketplace_preview(
                &runtime,
                &auth,
                &ClientContext::default(),
                "test-provider",
                request(),
            )
            .await
            .expect("configure principal should be allowed")
            .0;

            assert!(response.success);
            assert_eq!(runtime.loads.load(Ordering::SeqCst), 1);
            assert_eq!(runtime.decrypts.load(Ordering::SeqCst), 0);
            assert_eq!(runtime.executions.load(Ordering::SeqCst), 1);
            let audits = runtime.audits.lock().unwrap();
            assert_eq!(audits.len(), 1);
            assert_eq!(audits[0].api_key_id, expected_api_key_id);
            assert_eq!(audits[0].actor_id, Some(expected_actor_id));
            assert_eq!(audits[0].resource_id, Some(expected_entry_id));
            assert_eq!(audits[0].action, MARKETPLACE_PREVIEW_EXECUTED);
            assert!(audits[0].success);
            assert_eq!(
                audits[0].details.as_ref().unwrap(),
                &serde_json::json!({
                    "slug": "test-provider",
                    "artifact_type": "ip",
                    "duration_ms": 12,
                    "credentials_used": false,
                })
            );
        }
    }

    #[tokio::test]
    async fn credential_values_are_scrubbed_from_all_preview_channels_and_audit() {
        let secret = "super\"secret\\value";
        let runtime = SpyPreviewRuntime::leaking(secret);
        let response = run_marketplace_preview(
            &runtime,
            &session(&[permissions::ENRICHMENTS_CONFIGURE]),
            &ClientContext::default(),
            "test-provider",
            request(),
        )
        .await
        .expect("preview should return a redacted sandbox result")
        .0;

        let serialized = serde_json::to_string(&response).unwrap();
        assert!(!serialized.contains(secret));
        assert!(!serialized.contains("super\\\"secret\\\\value"));
        assert!(serialized.matches("[REDACTED]").count() >= 5);
        assert_eq!(runtime.decrypts.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.executions.load(Ordering::SeqCst), 1);

        let audits = runtime.audits.lock().unwrap();
        assert_eq!(audits.len(), 1);
        let audit_json = serde_json::to_string(&audits[0]).unwrap();
        assert!(!audit_json.contains(secret));
        assert_eq!(
            audits[0].details.as_ref().unwrap()["credentials_used"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            audits[0].details.as_ref().unwrap()["artifact_type"],
            "ip"
        );
    }
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
    let denied_sources = authorize_coverage(&auth)?;

    let svc = build_coverage_service(&state, denied_sources);
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
    let denied_sources = authorize_coverage(&auth)?;

    let svc = build_coverage_service(&state, denied_sources);
    let coverage = svc.refresh().await?;
    Ok(Json(coverage))
}

/// Coverage reads live log data as well as marketplace metadata. Require both
/// capabilities, then compose SOURCE grants with the implicit audit deny in one
/// canonical place before any cache or database operation.
fn authorize_coverage(auth: &AuthContext) -> Result<BTreeSet<String>, ApiError> {
    ensure_permission(auth, permissions::ENRICHMENTS_VIEW)?;
    ensure_permission(auth, permissions::SEARCH_EXECUTE)?;
    Ok(auth.effective_source_deny_set())
}

/// Construct a coverage service wired to the shared cache. Factored out so
/// the GET and refresh handlers can't drift apart on cache or source scope.
fn build_coverage_service(
    state: &AppState,
    denied_sources: BTreeSet<String>,
) -> MarketplaceCoverageService {
    MarketplaceCoverageService::new_with_cache(
        state.pool.clone(),
        state.dual_pool.clickhouse().clone(),
        (*state.marketplace_coverage_cache).clone(),
        state.config.schema_profile(),
        denied_sources,
    )
}

#[cfg(test)]
mod coverage_authz_tests {
    use super::*;
    use nanosiem_core::auth::api_key::ApiKeyInfo;
    use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
    use nanosiem_core::auth::{ScopeSet, TokenClaims};
    use uuid::Uuid;

    fn jwt_auth(values: &[&str]) -> AuthContext {
        AuthContext::from_jwt(TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: Vec::new(),
            permissions: values.iter().map(ToString::to_string).collect(),
            exp: chrono::Utc::now().timestamp() + 60,
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        })
    }

    fn api_key_auth(values: &[&str]) -> AuthContext {
        AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "coverage-probe".to_string(),
            permissions: values.iter().map(ToString::to_string).collect(),
            user_id: Some(Uuid::now_v7()),
        })
    }

    fn both_principals(values: &[&str]) -> [AuthContext; 2] {
        [jwt_auth(values), api_key_auth(values)]
    }

    #[test]
    fn coverage_denies_missing_composite_capabilities_for_jwt_and_api_keys() {
        for permissions in [
            vec![],
            vec![permissions::ENRICHMENTS_VIEW],
            vec![permissions::SEARCH_EXECUTE],
            vec![permissions::DASHBOARDS_VIEW],
        ] {
            for auth in both_principals(&permissions) {
                assert!(
                    matches!(authorize_coverage(&auth), Err(ApiError::Forbidden(_))),
                    "permissions {permissions:?} must not authorize coverage"
                );
            }
        }
    }

    #[test]
    fn coverage_accepts_composite_capabilities_and_composes_effective_scope() {
        let required = [permissions::ENRICHMENTS_VIEW, permissions::SEARCH_EXECUTE];
        for mut auth in both_principals(&required) {
            auth.denied_sources =
                ScopeSet::from_denied(["restricted"].into_iter().map(str::to_string).collect());

            let denied = authorize_coverage(&auth).expect("composite grant should authorize");
            assert_eq!(
                denied,
                ["audit", "restricted"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                "SOURCE grant-derived denies and implicit audit deny must both apply"
            );
        }
    }

    #[test]
    fn audit_view_removes_only_the_implicit_audit_deny() {
        let permissions = [
            permissions::ENRICHMENTS_VIEW,
            permissions::SEARCH_EXECUTE,
            permissions::AUDIT_VIEW,
        ];
        for mut auth in both_principals(&permissions) {
            auth.denied_sources =
                ScopeSet::from_denied(["restricted"].into_iter().map(str::to_string).collect());

            assert_eq!(
                authorize_coverage(&auth).unwrap(),
                ["restricted"].into_iter().map(str::to_string).collect()
            );
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::auth::{api_key::ApiKeyInfo, types::TokenClaims};

    fn jwt_auth(permissions: &[&str]) -> AuthContext {
        AuthContext::from_jwt(TokenClaims {
            iss: "test".to_string(),
            aud: "test".to_string(),
            sub: uuid::Uuid::nil(),
            roles: Vec::new(),
            permissions: permissions
                .iter()
                .map(|permission| permission.to_string())
                .collect(),
            exp: i64::MAX,
            iat: 0,
            jti: uuid::Uuid::nil(),
            purpose: "access".to_string(),
        })
    }

    fn api_key_auth(permissions: &[&str]) -> AuthContext {
        AuthContext::from_api_key(&ApiKeyInfo {
            id: uuid::Uuid::nil(),
            name: "test-key".to_string(),
            permissions: permissions
                .iter()
                .map(|permission| permission.to_string())
                .collect(),
            user_id: Some(uuid::Uuid::nil()),
        })
    }

    #[test]
    fn marketplace_source_requires_view_and_code_for_sessions_and_api_keys() {
        for auth in [
            jwt_auth(&[]),
            jwt_auth(&["settings:view"]),
            jwt_auth(&[permissions::ENRICHMENTS_VIEW]),
            jwt_auth(&[permissions::ENRICHMENTS_CODE]),
            api_key_auth(&[]),
            api_key_auth(&["settings:view"]),
            api_key_auth(&[permissions::ENRICHMENTS_VIEW]),
            api_key_auth(&[permissions::ENRICHMENTS_CODE]),
        ] {
            assert!(!may_return_marketplace_code(&auth));
            assert!(matches!(
                require_marketplace_code_read(&auth),
                Err(ApiError::Forbidden(_))
            ));
        }

        for auth in [
            jwt_auth(&[permissions::ENRICHMENTS_VIEW, permissions::ENRICHMENTS_CODE]),
            api_key_auth(&[permissions::ENRICHMENTS_VIEW, permissions::ENRICHMENTS_CODE]),
        ] {
            assert!(may_return_marketplace_code(&auth));
            assert!(require_marketplace_code_read(&auth).is_ok());
        }
    }

    #[test]
    fn marketplace_code_revocation_takes_effect_on_the_next_read() {
        for (before_revocation, after_revocation) in [
            (
                jwt_auth(&[permissions::ENRICHMENTS_VIEW, permissions::ENRICHMENTS_CODE]),
                jwt_auth(&[permissions::ENRICHMENTS_VIEW]),
            ),
            (
                api_key_auth(&[permissions::ENRICHMENTS_VIEW, permissions::ENRICHMENTS_CODE]),
                api_key_auth(&[permissions::ENRICHMENTS_VIEW]),
            ),
        ] {
            assert!(may_return_marketplace_code(&before_revocation));
            assert!(!may_return_marketplace_code(&after_revocation));
            assert!(matches!(
                require_marketplace_code_read(&after_revocation),
                Err(ApiError::Forbidden(_))
            ));
        }
    }
}

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
