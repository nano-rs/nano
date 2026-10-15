// SPDX-License-Identifier: AGPL-3.0-or-later

//! GitHub repository sync engine for the enrichment marketplace
//!
//! Clones/pulls enrichment repos, parses manifest.yaml files, and upserts
//! catalog entries. Follows the same pattern as `rule_repository::service.rs`.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use regex::Regex;
use sqlx::PgPool;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Maximum recursion depth for directory walking
const MAX_DIR_DEPTH: usize = 10;
/// Maximum manifest file size (1MB)
const MAX_MANIFEST_SIZE: u64 = 1_048_576;

/// Version of the manifest parse/record logic in [`run_sync`] (NAN-3514).
///
/// A successful sync stores it next to `last_sync_commit`
/// (`enrichment_marketplace_repos.last_sync_schema_version`). Sync skips a
/// repository only when both the HEAD commit AND this version match what was
/// stored, so a repo whose content has not moved still re-parses once after
/// the code learns something new.
///
/// **Bump this whenever the parse or record logic gains or changes a recorded
/// field** (a new manifest key copied into the catalog row, a changed
/// derivation such as `execution_backend` or `config`, etc.).
///
/// History:
/// - 0: rows synced before the version was recorded (column default).
/// - 1: NAN-3490 `runtime` / `connector_spec` / `connector_spec_sha256` in
///   `config` (NAN-3514 introduced the version).
/// - 2: NAN-3490 item 5 `hosted_connector_spec` /
///   `hosted_connector_spec_sha256` in `config`.
/// - 3: NAN-3503 `categories` / `components` (identity component spec text
///   and SHA-256) in `config`.
pub const SYNC_SCHEMA_VERSION: i32 = 3;

/// Whether `repo` is already synced at `commit` by the running sync code.
///
/// True only for a successful prior sync at the same commit by this
/// [`SYNC_SCHEMA_VERSION`] or a newer one; anything else needs a full parse
/// and apply.
pub(super) fn is_up_to_date(repo: &EnrichmentMarketplaceRepo, commit: &str) -> bool {
    repo.last_sync_commit.as_deref() == Some(commit)
        && repo.last_sync_status.as_deref() == Some("success")
        // A version from newer code counts as current: during a roll, old
        // and new pods must not re-sync the same commit back and forth.
        && repo.last_sync_schema_version >= SYNC_SCHEMA_VERSION
}

use super::error::MarketplaceError;
use super::repository::MarketplaceRepository;
use super::types::*;

/// Service for syncing enrichment marketplace repos from GitHub
pub struct MarketplaceSyncService {
    repository: MarketplaceRepository,
    syncing_repos: Arc<RwLock<HashSet<Uuid>>>,
    data_dir: PathBuf,
}

impl MarketplaceSyncService {
    pub fn new(pool: PgPool) -> Self {
        let data_dir = std::env::var("NANOSIEM_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data"));

        Self {
            repository: MarketplaceRepository::new(pool),
            syncing_repos: Arc::new(RwLock::new(HashSet::new())),
            data_dir,
        }
    }

    pub fn repository(&self) -> &MarketplaceRepository {
        &self.repository
    }

    /// Start a non-blocking background sync for a repo
    pub async fn start_sync(&self, repo_id: Uuid) -> Result<(), MarketplaceError> {
        // Check not already syncing
        {
            let syncing = self.syncing_repos.read().await;
            if syncing.contains(&repo_id) {
                return Err(MarketplaceError::SyncInProgress(repo_id));
            }
        }

        // Mark as syncing
        {
            let mut syncing = self.syncing_repos.write().await;
            syncing.insert(repo_id);
        }

        let repo = self.repository.get_repo(repo_id).await?;
        let repository = self.repository.clone();
        let syncing_repos = Arc::clone(&self.syncing_repos);
        let data_dir = self.data_dir.clone();

        tokio::spawn(async move {
            let start = std::time::Instant::now();
            info!(repo_id = %repo.id, repo_name = %repo.name, "Starting enrichment repo sync");

            // Update status to syncing
            let _ = repository
                .update_repo_sync_status(repo.id, "syncing", None, None, None)
                .await;

            match run_sync(&repo, &repository, &data_dir).await {
                Ok(result) => {
                    info!(
                        repo_id = %repo.id,
                        added = result.enrichments_added,
                        updated = result.enrichments_updated,
                        removed = result.enrichments_removed,
                        duration_ms = start.elapsed().as_millis() as u64,
                        "Enrichment repo sync completed"
                    );
                    let _ = repository
                        .update_repo_sync_status(
                            repo.id,
                            "success",
                            result.commit.as_deref(),
                            Some(result.enrichment_count),
                            None,
                        )
                        .await;
                }
                Err(e) => {
                    error!(repo_id = %repo.id, error = %e, "Enrichment repo sync failed");
                    let _ = repository
                        .update_repo_sync_status(
                            repo.id,
                            "failed",
                            None,
                            None,
                            Some(&e.to_string()),
                        )
                        .await;
                }
            }

            // Unmark syncing
            let mut syncing = syncing_repos.write().await;
            syncing.remove(&repo.id);
        });

        Ok(())
    }

    /// Run a repository sync in the caller's task for structured leadership.
    pub async fn sync_repository(&self, repo_id: Uuid) -> Result<RepoSyncResult, MarketplaceError> {
        let repo = self.repository.get_repo(repo_id).await?;
        {
            let mut syncing = self.syncing_repos.write().await;
            if !syncing.insert(repo_id) {
                return Err(MarketplaceError::SyncInProgress(repo_id));
            }
        }
        if let Err(error) = self
            .repository
            .update_repo_sync_status(repo.id, "syncing", None, None, None)
            .await
        {
            self.syncing_repos.write().await.remove(&repo_id);
            return Err(error);
        }

        let result = run_sync(&repo, &self.repository, &self.data_dir).await;
        let status_result = match &result {
            Ok(sync) => {
                self.repository
                    .update_repo_sync_status(
                        repo.id,
                        "success",
                        sync.commit.as_deref(),
                        Some(sync.enrichment_count),
                        None,
                    )
                    .await
            }
            Err(error) => {
                self.repository
                    .update_repo_sync_status(
                        repo.id,
                        "failed",
                        None,
                        None,
                        Some(&error.to_string()),
                    )
                    .await
            }
        };
        self.syncing_repos.write().await.remove(&repo_id);
        status_result?;
        result
    }

    /// Platform tables use the control pool, never a signed tenant transaction.
    pub async fn sync_platform_repository(&self, pool: &PgPool, id: Uuid) -> Result<RepoSyncResult, MarketplaceError> {
        super::platform_sync::sync(pool, &self.repository, &self.data_dir, id).await
    }

    /// Auto-sync all repos that are due
    pub async fn auto_sync_all(&self) -> Result<Vec<Uuid>, MarketplaceError> {
        let repos = self.repository.list_repos_for_auto_sync().await?;
        let mut synced = Vec::new();

        for repo in repos {
            match self.start_sync(repo.id).await {
                Ok(()) => synced.push(repo.id),
                Err(MarketplaceError::SyncInProgress(_)) => {
                    debug!(repo_id = %repo.id, "Skipping auto-sync, already in progress");
                }
                Err(e) => {
                    warn!(repo_id = %repo.id, error = %e, "Failed to start auto-sync");
                }
            }
        }

        Ok(synced)
    }

    /// Browse the enrichments directory of a repo (from cached clone)
    pub async fn browse_repo(
        &self,
        repo_id: Uuid,
    ) -> Result<Vec<RepoBrowseEntry>, MarketplaceError> {
        let repo = self.repository.get_repo(repo_id).await?;
        let repo_dir = self.data_dir.join("enrichment_repos").join(&repo.slug);

        if !repo_dir.exists() {
            return Ok(Vec::new());
        }

        let enrichments_dir = repo_dir.join(&repo.enrichments_path);
        if !enrichments_dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        browse_directory(&enrichments_dir, &enrichments_dir, &mut entries, 0);
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }
}

/// Validate that a repo URL is safe (HTTPS only, no ext::, file://, ssh://, flag injection)
async fn validate_repo_url(url: &str) -> Result<(), MarketplaceError> {
    let url_lower = url.trim().to_lowercase();
    if !url_lower.starts_with("https://") {
        return Err(MarketplaceError::InvalidUrl(
            "Only HTTPS URLs are allowed for enrichment repositories".to_string(),
        ));
    }
    if url.starts_with('-') {
        return Err(MarketplaceError::InvalidUrl(
            "URL must not start with a dash".to_string(),
        ));
    }
    // H3: SSRF validation — block private IPs, localhost, cloud metadata
    let ssrf_validator = crate::inputlookup::SsrfValidator::default_secure();
    ssrf_validator
        .validate_with_dns(url.trim())
        .await
        .map_err(|e| {
            MarketplaceError::InvalidUrl(format!("URL blocked by security policy: {}", e))
        })?;
    Ok(())
}

/// Validate that a branch name is safe (no flag injection, no shell chars)
fn validate_branch(branch: &str) -> Result<(), MarketplaceError> {
    if branch.is_empty() {
        return Err(MarketplaceError::GitError(
            "Branch name cannot be empty".to_string(),
        ));
    }
    if branch.starts_with('-') {
        return Err(MarketplaceError::GitError(
            "Branch name must not start with a dash".to_string(),
        ));
    }
    let safe = Regex::new(r"^[a-zA-Z0-9._/\-]+$").unwrap();
    if !safe.is_match(branch) {
        return Err(MarketplaceError::GitError(
            "Branch name contains invalid characters (only alphanumeric, dots, dashes, slashes allowed)".to_string(),
        ));
    }
    Ok(())
}

/// Sanitize git stderr output to remove embedded credentials from URLs
fn sanitize_git_stderr(stderr: &str) -> String {
    let cred_re = Regex::new(r"://[^@\s]+@").unwrap();
    cred_re.replace_all(stderr, "://***@").to_string()
}

/// Verify that a resolved path stays under the expected base directory
fn verify_path_containment(base: &PathBuf, target: &PathBuf) -> Result<(), MarketplaceError> {
    let canonical_base = base.canonicalize().map_err(|e| {
        MarketplaceError::GitError(format!("Failed to canonicalize base path: {}", e))
    })?;
    let canonical_target = target.canonicalize().map_err(|e| {
        MarketplaceError::GitError(format!("Failed to canonicalize target path: {}", e))
    })?;
    if !canonical_target.starts_with(&canonical_base) {
        return Err(MarketplaceError::GitError(
            "Path escapes repository directory (possible path traversal)".to_string(),
        ));
    }
    Ok(())
}

/// Internal sync implementation
pub(super) async fn run_sync(
    repo: &EnrichmentMarketplaceRepo,
    repository: &MarketplaceRepository,
    data_dir: &PathBuf,
) -> Result<RepoSyncResult, MarketplaceError> {
    let start = std::time::Instant::now();

    // Validate URL and branch before any git operations
    validate_repo_url(&repo.url).await?;
    validate_branch(&repo.branch)?;

    // Validate slug is safe for filesystem use
    if repo.slug.is_empty() || repo.slug.contains("..") || repo.slug.contains('/') {
        return Err(MarketplaceError::GitError(
            "Invalid repository slug".to_string(),
        ));
    }

    let repo_dir = data_dir.join("enrichment_repos").join(&repo.slug);

    // Clone or pull
    let commit = if repo_dir.exists() {
        git_pull(&repo_dir, &repo.branch).await?
    } else {
        git_clone(&repo.url, &repo_dir, &repo.branch).await?
    };

    // Skip only when neither the content (commit) nor the sync code
    // (SYNC_SCHEMA_VERSION) changed since the last successful sync.
    if is_up_to_date(repo, &commit) {
        info!(repo_id = %repo.id, "No changes since last sync (commit {})", &commit[..8.min(commit.len())]);
        return Ok(RepoSyncResult {
            repository_id: repo.id,
            status: "success".to_string(),
            commit: Some(commit),
            enrichment_count: repo.enrichment_count,
            enrichments_added: 0,
            enrichments_updated: 0,
            enrichments_removed: 0,
            duration_ms: start.elapsed().as_millis() as u64,
            error: None,
        });
    }

    if repo.last_sync_commit.as_deref() == Some(commit.as_str())
        && repo.last_sync_schema_version < SYNC_SCHEMA_VERSION
    {
        info!(
            repo_id = %repo.id,
            stored_version = repo.last_sync_schema_version,
            current_version = SYNC_SCHEMA_VERSION,
            "Sync schema version changed; re-parsing at unchanged commit {}",
            &commit[..8.min(commit.len())]
        );
    }

    // Walk enrichments directory and find manifests
    let enrichments_dir = repo_dir.join(&repo.enrichments_path);
    if !enrichments_dir.exists() {
        warn!(
            repo_id = %repo.id,
            path = %enrichments_dir.display(),
            "Enrichments directory not found"
        );
        return Err(MarketplaceError::GitError(format!(
            "Enrichments directory not found: {}",
            repo.enrichments_path
        )));
    }

    // Verify enrichments_path doesn't escape the repo directory
    verify_path_containment(&repo_dir, &enrichments_dir)?;

    let manifests = find_manifests(&enrichments_dir, 0);
    info!(
        repo_id = %repo.id,
        manifest_count = manifests.len(),
        "Found enrichment manifests"
    );

    let mut added = 0i32;
    let mut updated = 0i32;
    let mut seen_slugs = Vec::new();

    for (manifest_path, manifest) in &manifests {
        // NAN-3490 item 5: `_mock` slugs are reserved for operator
        // live-validation rows; a repository may not ship or overwrite one.
        if super::repository::is_validation_mock_slug(&manifest.slug) {
            warn!(path = %manifest_path.display(), slug = %manifest.slug, "Skipping manifest: `_mock` slugs are reserved for live-validation entries");
            continue;
        }
        // NAN-3490: a manifest that names a connector spec carries it into the
        // catalog row; one that asks for the connector runtime without a
        // readable spec is skipped rather than synced half-formed.
        let config = match catalog_config(manifest_path, manifest) {
            Ok(config) => config,
            Err(reason) => {
                warn!(path = %manifest_path.display(), slug = %manifest.slug, %reason, "Skipping manifest");
                continue;
            }
        };
        seen_slugs.push(manifest.slug.clone());

        // Read adjacent code file
        let code_path = manifest_path.with_extension("ts");
        let code_alt_path = manifest_path.parent().map(|p| p.join("code.ts"));

        let code = if code_path.exists() {
            tokio::fs::read_to_string(&code_path).await.ok()
        } else if let Some(ref alt) = code_alt_path {
            if alt.exists() {
                tokio::fs::read_to_string(alt).await.ok()
            } else {
                None
            }
        } else {
            None
        };

        // Determine relative path from enrichments dir
        let rel_path = manifest_path
            .strip_prefix(&enrichments_dir)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // Check if entry already exists
        let existing = match repository.get_catalog_entry(&manifest.slug).await {
            Ok(entry) => Some(entry),
            Err(MarketplaceError::CatalogEntryNotFound(_)) => None,
            Err(error) => return Err(error),
        };
        let is_update = existing.is_some();

        // Build catalog entry
        let entry = MarketplaceCatalogEntry {
            id: existing.as_ref().map(|e| e.id).unwrap_or_else(Uuid::now_v7),
            slug: manifest.slug.clone(),
            name: manifest.name.clone(),
            description: Some(manifest.description.clone()),
            category: manifest.category.clone(),
            tags: manifest.tags.clone(),
            icon: manifest.icon.clone(),
            author: Some(manifest.author.clone()),
            source_type: "repository".to_string(),
            repository_id: Some(repo.id),
            repository_file_path: Some(rel_path),
            manifest_version: manifest.version,
            execution_backend: execution_backend_for(manifest).to_string(),
            custom_enrichment_id: existing.as_ref().and_then(|e| e.custom_enrichment_id),
            native_source_id: None,
            identity_provider_id: None,
            installed: existing.as_ref().map(|e| e.installed).unwrap_or(false),
            installed_at: existing.as_ref().and_then(|e| e.installed_at),
            installed_version: existing.as_ref().and_then(|e| e.installed_version),
            requires_credential: manifest.requires_credential.clone(),
            credential_fields: sqlx::types::Json(
                serde_json::to_value(&manifest.credential_fields).unwrap_or_default(),
            ),
            credentials_encrypted: existing
                .as_ref()
                .and_then(|e| e.credentials_encrypted.clone()),
            credentials_nonce: existing.as_ref().and_then(|e| e.credentials_nonce.clone()),
            has_credentials: false, // computed field, set by hydrate()
            code,
            allowed_domains: manifest.allowed_domains.clone(),
            config: sqlx::types::Json(config),
            enabled: existing.as_ref().map(|e| e.enabled).unwrap_or(false),
            last_sync_at: existing.as_ref().and_then(|e| e.last_sync_at),
            last_sync_status: existing.as_ref().and_then(|e| e.last_sync_status.clone()),
            last_error: existing.as_ref().and_then(|e| e.last_error.clone()),
            record_count: existing.as_ref().map(|e| e.record_count).unwrap_or(0),
            is_syncing: false,       // derived per-query in repository; not stored
            requires_network: false, // derived in repository hydrate; not stored
            changelog: manifest.changelog.clone(),
            created_at: existing
                .as_ref()
                .map(|e| e.created_at)
                .unwrap_or_else(chrono::Utc::now),
            updated_at: chrono::Utc::now(),
        };

        repository.upsert_catalog_entry(&entry).await?;
        if is_update { updated += 1; } else { added += 1; }
    }

    // Remove stale entries (only non-installed ones)
    let removed = repository
        .remove_stale_repo_entries(repo.id, &seen_slugs)
        .await?;

    Ok(RepoSyncResult {
        repository_id: repo.id,
        status: "success".to_string(),
        commit: Some(commit),
        enrichment_count: seen_slugs.len() as i32,
        enrichments_added: added,
        enrichments_updated: updated,
        enrichments_removed: removed,
        duration_ms: start.elapsed().as_millis() as u64,
        error: None,
    })
}

/// Clone a git repo (shallow)
async fn git_clone(url: &str, target: &PathBuf, branch: &str) -> Result<String, MarketplaceError> {
    // Create parent directory
    if let Some(parent) = target.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            MarketplaceError::GitError(format!("Failed to create directory: {}", e))
        })?;
    }

    let output = tokio::process::Command::new("git")
        .kill_on_drop(true)
        .args([
            "clone",
            "--depth=1",
            "--branch",
            branch,
            "--single-branch",
            url,
            &target.to_string_lossy(),
        ])
        .output()
        .await
        .map_err(|e| MarketplaceError::GitError(format!("Failed to run git clone: {}", e)))?;

    if !output.status.success() {
        let stderr = sanitize_git_stderr(&String::from_utf8_lossy(&output.stderr));
        return Err(MarketplaceError::GitError(format!(
            "git clone failed: {}",
            stderr
        )));
    }

    get_head_commit(target).await
}

/// Pull latest changes
async fn git_pull(repo_dir: &PathBuf, branch: &str) -> Result<String, MarketplaceError> {
    // Fetch
    let output = tokio::process::Command::new("git")
        .kill_on_drop(true)
        .args(["fetch", "--depth=1", "origin", branch])
        .current_dir(repo_dir)
        .output()
        .await
        .map_err(|e| MarketplaceError::GitError(format!("Failed to run git fetch: {}", e)))?;

    if !output.status.success() {
        let stderr = sanitize_git_stderr(&String::from_utf8_lossy(&output.stderr));
        return Err(MarketplaceError::GitError(format!(
            "git fetch failed: {}",
            stderr
        )));
    }

    // Reset to fetched
    let output = tokio::process::Command::new("git")
        .kill_on_drop(true)
        .args(["reset", "--hard", &format!("origin/{}", branch)])
        .current_dir(repo_dir)
        .output()
        .await
        .map_err(|e| MarketplaceError::GitError(format!("Failed to run git reset: {}", e)))?;

    if !output.status.success() {
        let stderr = sanitize_git_stderr(&String::from_utf8_lossy(&output.stderr));
        return Err(MarketplaceError::GitError(format!(
            "git reset failed: {}",
            stderr
        )));
    }

    get_head_commit(repo_dir).await
}

/// Get HEAD commit hash
async fn get_head_commit(repo_dir: &PathBuf) -> Result<String, MarketplaceError> {
    let output = tokio::process::Command::new("git")
        .kill_on_drop(true)
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_dir)
        .output()
        .await
        .map_err(|e| MarketplaceError::GitError(format!("Failed to get HEAD commit: {}", e)))?;

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// NAN-2189: a manifest declaring streams is a collector; everything else is a
/// Deno enrichment.
///
/// Keyed off `streams` rather than `category` deliberately — the category
/// string comes from user-authored YAML in an external repo, so a typo there
/// would otherwise route a collector through the enrichment executor, which
/// would run it once and throw its output away.
pub fn is_collector_manifest(manifest: &MarketplaceManifest) -> bool {
    !manifest.streams.is_empty()
}

pub fn execution_backend_for(manifest: &MarketplaceManifest) -> &'static str {
    if is_collector_manifest(manifest) {
        "collector"
    } else {
        "deno"
    }
}

/// Fold the collector-only manifest fields into the catalog row's `config`
/// JSONB.
///
/// The alternative — adding five columns to `marketplace_catalog` — would put
/// enterprise-only collector schema on an open-tier table for no gain: nothing
/// queries these fields relationally, they are read as a unit when a run
/// starts. Enrichment manifests are untouched, so their stored config stays
/// byte-identical to what pre-NAN-2189 sync wrote.
pub fn effective_config(manifest: &MarketplaceManifest) -> serde_json::Value {
    if !is_collector_manifest(manifest) {
        return manifest.config.clone();
    }

    let mut config = match manifest.config.clone() {
        serde_json::Value::Object(map) => map,
        // A collector whose `config:` block is absent or malformed still needs
        // its streams persisted, so fall back to an empty object rather than
        // dropping the collector metadata on the floor.
        _ => serde_json::Map::new(),
    };

    config.insert(
        "streams".to_string(),
        serde_json::to_value(&manifest.streams).unwrap_or(serde_json::Value::Null),
    );
    config.insert(
        "config_fields".to_string(),
        serde_json::to_value(&manifest.config_fields).unwrap_or(serde_json::Value::Null),
    );
    config.insert(
        "allowed_domain_suffixes".to_string(),
        serde_json::to_value(&manifest.allowed_domain_suffixes).unwrap_or(serde_json::Value::Null),
    );
    if let Some(auth_type) = &manifest.auth_type {
        config.insert(
            "auth_type".to_string(),
            serde_json::Value::String(auth_type.clone()),
        );
    }
    if let Some(auth) = &manifest.auth {
        config.insert(
            "auth".to_string(),
            serde_json::to_value(auth).unwrap_or(serde_json::Value::Null),
        );
    }

    serde_json::Value::Object(config)
}

/// Everything sync records in a catalog row's `config`: the manifest config
/// and collector fields, the connector runtime and specs (NAN-3490) and the
/// marketplace layout (NAN-3503). `Err` names why the manifest is skipped.
pub fn catalog_config(manifest_path: &std::path::Path, manifest: &MarketplaceManifest) -> Result<serde_json::Value, String> {
    let spec = read_connector_spec(manifest_path, manifest)?;
    let config = apply_connector_runtime(effective_config(manifest), manifest, spec.as_deref())?;
    let hosted = read_hosted_connector_spec(manifest_path, manifest)?;
    let config = apply_hosted_connector_spec(config, hosted.as_deref());
    apply_components(config, manifest_path, manifest)
}

/// NAN-3503: record the marketplace layout in `config`:
///
/// - `categories`: the sections the card lists under (`logs`, `identity`)
/// - `components`: one object per component with `id`, `label`, `kind`,
///   `description`, `streams`, `config_fields`, `default` and `setup`; an
///   identity component also carries its spec as `connector_spec` (text) +
///   `connector_spec_sha256`, and its hosted twin as
///   `hosted_connector_spec` + `hosted_connector_spec_sha256`, the same keys
///   the entry itself uses.
///
/// A manifest with neither key keeps its config unchanged. A malformed
/// layout skips the manifest, like an unreadable spec: half a card would
/// install the wrong things.
pub fn apply_components(
    config: serde_json::Value,
    manifest_path: &std::path::Path,
    manifest: &MarketplaceManifest,
) -> Result<serde_json::Value, String> {
    use sha2::{Digest, Sha256};
    use serde_json::{json, Value};
    if manifest.categories.is_empty() && manifest.components.is_empty() {
        return Ok(config);
    }
    let mut map = match config {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    for category in &manifest.categories {
        if category != COMPONENT_KIND_LOGS && category != COMPONENT_KIND_IDENTITY {
            return Err(format!("categories: unknown category '{category}'"));
        }
    }
    let stream_ids: std::collections::BTreeMap<&str, &StreamDef> = manifest.streams.iter().map(|s| (s.id.as_str(), s)).collect();
    let field_names: std::collections::BTreeSet<&str> = manifest.config_fields.iter().map(|f| f.name.as_str()).collect();
    let mut ids = std::collections::BTreeSet::new();
    let mut claimed = std::collections::BTreeSet::new();
    let mut out = Vec::with_capacity(manifest.components.len());
    for c in &manifest.components {
        let at = format!("components.{}", c.id);
        let valid_id = !c.id.is_empty()
            && c.id.len() <= 64
            && c.id.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_');
        if !valid_id {
            return Err(format!("components: id '{}' must be [a-z0-9_], at most 64 characters", c.id));
        }
        if !ids.insert(c.id.as_str()) {
            return Err(format!("{at}: duplicate id"));
        }
        if c.label.trim().is_empty() {
            return Err(format!("{at}: label is empty"));
        }
        for field in &c.config_fields {
            if !field_names.contains(field.as_str()) {
                return Err(format!("{at}: config field '{field}' is not in config_fields"));
            }
        }
        let mut entry = json!({
            "id": c.id,
            "label": c.label,
            "kind": c.kind,
            "description": c.description,
            "streams": c.streams,
            "config_fields": c.config_fields,
            "default": c.default,
            "setup": c.setup,
        });
        match c.kind.as_str() {
            COMPONENT_KIND_LOGS => {
                if c.streams.is_empty() {
                    return Err(format!("{at}: a logs component needs streams"));
                }
                if c.connector_spec.is_some() || c.hosted_connector_spec.is_some() {
                    return Err(format!("{at}: a logs component runs the entry's own spec"));
                }
                for stream in &c.streams {
                    match stream_ids.get(stream.as_str()) {
                        None => return Err(format!("{at}: unknown stream '{stream}'")),
                        Some(s) if s.source_type == IDENTITY_SOURCE_TYPE => {
                            return Err(format!("{at}: stream '{stream}' is an identity stream"))
                        }
                        Some(_) => {}
                    }
                    if !claimed.insert(stream.as_str()) {
                        return Err(format!("{at}: stream '{stream}' belongs to another component"));
                    }
                }
            }
            COMPONENT_KIND_IDENTITY => {
                if !c.streams.is_empty() {
                    return Err(format!("{at}: an identity component names no streams"));
                }
                let spec = read_spec_file(manifest_path, &format!("{at}.connector_spec"), c.connector_spec.as_deref())?
                    .ok_or_else(|| format!("{at}: an identity component needs connector_spec"))?;
                let hosted = read_spec_file(manifest_path, &format!("{at}.hosted_connector_spec"), c.hosted_connector_spec.as_deref())?;
                let digest = |text: &str| hex::encode(Sha256::digest(text.as_bytes()));
                entry["connector_spec_sha256"] = Value::String(digest(&spec));
                entry["connector_spec"] = Value::String(spec);
                if let Some(hosted) = hosted {
                    entry["hosted_connector_spec_sha256"] = Value::String(digest(&hosted));
                    entry["hosted_connector_spec"] = Value::String(hosted);
                }
            }
            other => return Err(format!("{at}: kind must be 'logs' or 'identity', got '{other}'")),
        }
        out.push(entry);
    }
    if !manifest.categories.is_empty() {
        map.insert("categories".to_string(), json!(manifest.categories));
    }
    if !out.is_empty() {
        map.insert("components".to_string(), Value::Array(out));
    }
    Ok(Value::Object(map))
}

/// NAN-3490: read the nano-connector spec a manifest names. It must be a plain
/// file name next to the manifest (no path, no symlink) and no larger than a
/// manifest. `Ok(None)` when the manifest names no spec.
fn read_connector_spec(manifest_path: &std::path::Path, manifest: &MarketplaceManifest) -> Result<Option<String>, String> {
    read_spec_file(manifest_path, "connector_spec", manifest.connector_spec.as_deref())
}

/// NAN-3490 item 5: the hosted-only spec (`hosted_connector_spec`), read
/// under exactly the same rules as `connector_spec`.
fn read_hosted_connector_spec(manifest_path: &std::path::Path, manifest: &MarketplaceManifest) -> Result<Option<String>, String> {
    read_spec_file(manifest_path, "hosted_connector_spec", manifest.hosted_connector_spec.as_deref())
}

fn read_spec_file(manifest_path: &std::path::Path, field: &str, name: Option<&str>) -> Result<Option<String>, String> {
    let Some(name) = name else { return Ok(None) };
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.starts_with('.') {
        return Err(format!("{field} '{name}' must be a file name next to the manifest"));
    }
    let path = manifest_path.with_file_name(name);
    let meta = std::fs::symlink_metadata(&path).map_err(|e| format!("{field} '{name}': {e}"))?;
    if !meta.file_type().is_file() {
        return Err(format!("{field} '{name}' is not a regular file"));
    }
    if meta.len() > MAX_MANIFEST_SIZE {
        return Err(format!("{field} '{name}' is larger than {MAX_MANIFEST_SIZE} bytes"));
    }
    std::fs::read_to_string(&path).map(Some).map_err(|e| format!("{field} '{name}': {e}"))
}

/// NAN-3490 item 5: record the hosted-only spec as
/// `config.hosted_connector_spec` + `config.hosted_connector_spec_sha256`.
/// Without one the config is unchanged.
pub fn apply_hosted_connector_spec(config: serde_json::Value, spec: Option<&str>) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    let Some(text) = spec else { return config };
    let mut map = match config {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    map.insert("hosted_connector_spec".to_string(), serde_json::Value::String(text.to_string()));
    map.insert(
        "hosted_connector_spec_sha256".to_string(),
        serde_json::Value::String(hex::encode(Sha256::digest(text.as_bytes()))),
    );
    serde_json::Value::Object(map)
}

/// NAN-3490: record which runtime runs this entry, and the connector spec, in
/// the catalog row's `config`:
///
/// - `runtime`: `deno` or `connector`
/// - `connector_spec`: the spec text
/// - `connector_spec_sha256`: its hex SHA-256, so a feed can pin the spec it
///   was configured against
///
/// A manifest with neither field keeps its config byte-identical. The
/// `execution_backend` column is left alone: `collector` vs `deno` still says
/// whether the entry streams events or returns enrichment results.
pub fn apply_connector_runtime(
    config: serde_json::Value,
    manifest: &MarketplaceManifest,
    spec: Option<&str>,
) -> Result<serde_json::Value, String> {
    use sha2::{Digest, Sha256};
    let runtime = manifest.runtime.as_deref().unwrap_or("deno");
    if runtime != "deno" && runtime != CONNECTOR_RUNTIME {
        return Err(format!("runtime must be 'deno' or '{CONNECTOR_RUNTIME}', got '{runtime}'"));
    }
    if runtime == CONNECTOR_RUNTIME && spec.is_none() {
        return Err("runtime 'connector' needs connector_spec".to_string());
    }
    if manifest.runtime.is_none() && spec.is_none() {
        return Ok(config);
    }
    let mut map = match config {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    map.insert("runtime".to_string(), serde_json::Value::String(runtime.to_string()));
    if let Some(text) = spec {
        map.insert("connector_spec".to_string(), serde_json::Value::String(text.to_string()));
        map.insert(
            "connector_spec_sha256".to_string(),
            serde_json::Value::String(hex::encode(Sha256::digest(text.as_bytes()))),
        );
    }
    Ok(serde_json::Value::Object(map))
}

/// Find all manifest.yaml files in a directory tree
fn find_manifests(dir: &PathBuf, depth: usize) -> Vec<(PathBuf, MarketplaceManifest)> {
    let mut manifests = Vec::new();

    if depth > MAX_DIR_DEPTH {
        warn!(path = %dir.display(), "Maximum directory depth exceeded, skipping");
        return manifests;
    }

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();

            // Skip symlinks to prevent following links outside the repo
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                if meta.file_type().is_symlink() {
                    debug!(path = %path.display(), "Skipping symlink");
                    continue;
                }
            }

            if path.is_dir() {
                manifests.extend(find_manifests(&path, depth + 1));
            } else if path
                .file_name()
                .map(|n| n == "manifest.yaml" || n == "manifest.yml")
                == Some(true)
            {
                // Check file size before reading
                if let Ok(meta) = std::fs::metadata(&path) {
                    if meta.len() > MAX_MANIFEST_SIZE {
                        warn!(path = %path.display(), size = meta.len(), "Manifest file too large, skipping");
                        continue;
                    }
                }

                match std::fs::read_to_string(&path) {
                    Ok(content) => match serde_yaml::from_str::<MarketplaceManifest>(&content) {
                        Ok(manifest) => {
                            manifests.push((path, manifest));
                        }
                        Err(e) => {
                            warn!(
                                path = %path.display(),
                                error = %e,
                                "Failed to parse manifest"
                            );
                        }
                    },
                    Err(e) => {
                        warn!(
                            path = %path.display(),
                            error = %e,
                            "Failed to read manifest file"
                        );
                    }
                }
            }
        }
    }

    manifests
}

/// Recursively browse a directory for the browse API
fn browse_directory(
    base: &PathBuf,
    current: &PathBuf,
    entries: &mut Vec<RepoBrowseEntry>,
    depth: usize,
) {
    if depth > MAX_DIR_DEPTH {
        return;
    }

    if let Ok(dir_entries) = std::fs::read_dir(current) {
        for entry in dir_entries.flatten() {
            let path = entry.path();

            // Skip symlinks
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                if meta.file_type().is_symlink() {
                    continue;
                }
            }

            let rel_path = path
                .strip_prefix(base)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            if path.is_dir() {
                let has_manifest =
                    path.join("manifest.yaml").exists() || path.join("manifest.yml").exists();

                entries.push(RepoBrowseEntry {
                    path: rel_path,
                    name: path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    entry_type: "directory".to_string(),
                    has_manifest,
                });

                browse_directory(base, &path, entries, depth + 1);
            }
        }
    }
}

#[cfg(test)]
mod tests;
