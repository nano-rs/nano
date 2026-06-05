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
async fn run_sync(
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

    // Check if commit changed (skip if same)
    if repo.last_sync_commit.as_deref() == Some(&commit) {
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
        let existing = repository.get_catalog_entry(&manifest.slug).await.ok();
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
            execution_backend: "deno".to_string(),
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
            config: sqlx::types::Json(manifest.config.clone()),
            enabled: existing.as_ref().map(|e| e.enabled).unwrap_or(false),
            last_sync_at: existing.as_ref().and_then(|e| e.last_sync_at),
            last_sync_status: existing.as_ref().and_then(|e| e.last_sync_status.clone()),
            last_error: existing.as_ref().and_then(|e| e.last_error.clone()),
            record_count: existing.as_ref().map(|e| e.record_count).unwrap_or(0),
            is_syncing: false, // derived per-query in repository; not stored
            requires_network: false, // derived in repository hydrate; not stored
            changelog: manifest.changelog.clone(),
            created_at: existing
                .as_ref()
                .map(|e| e.created_at)
                .unwrap_or_else(chrono::Utc::now),
            updated_at: chrono::Utc::now(),
        };

        match repository.upsert_catalog_entry(&entry).await {
            Ok(_) => {
                if is_update {
                    updated += 1;
                } else {
                    added += 1;
                }
            }
            Err(e) => {
                warn!(
                    slug = %manifest.slug,
                    error = %e,
                    "Failed to upsert catalog entry"
                );
            }
        }
    }

    // Remove stale entries (only non-installed ones)
    let removed = repository
        .remove_stale_repo_entries(repo.id, &seen_slugs)
        .await
        .unwrap_or(0);

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
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_dir)
        .output()
        .await
        .map_err(|e| MarketplaceError::GitError(format!("Failed to get HEAD commit: {}", e)))?;

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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
