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
/// - 1: NAN-3514 introduced the version (every existing repo re-parses once).
/// - 2: NAN-5284 `runtime: connector` agent entries map to `lookup`.
pub const SYNC_SCHEMA_VERSION: i32 = 2;

/// Whether `repo` is already synced at `commit` by the running sync code.
///
/// True only for a successful prior sync at the same commit and the same
/// [`SYNC_SCHEMA_VERSION`]; anything else needs a full parse and apply.
pub(super) fn is_up_to_date(repo: &EnrichmentMarketplaceRepo, commit: &str) -> bool {
    repo.last_sync_commit.as_deref() == Some(commit)
        && repo.last_sync_status.as_deref() == Some("success")
        && repo.last_sync_schema_version == SYNC_SCHEMA_VERSION
}

use super::error::MarketplaceError;
use super::repository::MarketplaceRepository;
use super::types::*;

/// Service for syncing enrichment marketplace repos from GitHub
pub struct MarketplaceSyncService {
    pool: PgPool,
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
            repository: MarketplaceRepository::new(pool.clone()),
            pool,
            syncing_repos: Arc::new(RwLock::new(HashSet::new())),
            data_dir,
        }
    }

    /// A service rooted at an explicit data dir (tests; no env lookup).
    #[cfg(test)]
    pub(crate) fn with_data_dir(pool: PgPool, data_dir: PathBuf) -> Self {
        Self {
            repository: MarketplaceRepository::new(pool.clone()),
            pool,
            syncing_repos: Arc::new(RwLock::new(HashSet::new())),
            data_dir,
        }
    }

    pub fn repository(&self) -> &MarketplaceRepository {
        &self.repository
    }

    /// Start a non-blocking background sync for a repo
    pub async fn start_sync(&self, repo_id: Uuid) -> Result<(), MarketplaceError> {
        // Process-local fast path: test-and-insert under one write lock.
        if !self.syncing_repos.write().await.insert(repo_id) {
            return Err(MarketplaceError::SyncInProgress(repo_id));
        }
        // NAN-4946: the cross-replica exclusion is a PostgreSQL advisory lock
        // held for the whole sync (see `RepoSyncLock`).
        let lock = match RepoSyncLock::try_acquire(&self.pool, repo_id).await {
            Ok(Some(lock)) => lock,
            Ok(None) => {
                self.syncing_repos.write().await.remove(&repo_id);
                return Err(MarketplaceError::SyncInProgress(repo_id));
            }
            Err(e) => {
                self.syncing_repos.write().await.remove(&repo_id);
                return Err(e);
            }
        };

        // NAN-4946: refuse a non-first-party repository before any work.
        let repo = match self.repository.get_repo(repo_id).await.and_then(|repo| {
            super::first_party::validate_first_party_repo_url(&repo.url).map(|()| repo)
        }) {
            Ok(repo) => repo,
            Err(e) => {
                lock.release().await;
                self.syncing_repos.write().await.remove(&repo_id);
                return Err(e);
            }
        };
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

            lock.release().await;
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
        let lock = match RepoSyncLock::try_acquire(&self.pool, repo_id).await {
            Ok(Some(lock)) => lock,
            Ok(None) => {
                self.syncing_repos.write().await.remove(&repo_id);
                return Err(MarketplaceError::SyncInProgress(repo_id));
            }
            Err(e) => {
                self.syncing_repos.write().await.remove(&repo_id);
                return Err(e);
            }
        };
        if let Err(error) = self
            .repository
            .update_repo_sync_status(repo.id, "syncing", None, None, None)
            .await
        {
            lock.release().await;
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
        lock.release().await;
        self.syncing_repos.write().await.remove(&repo_id);
        status_result?;
        result
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

/// NAN-4946: cross-replica, cross-service exclusion for one repository's
/// sync. A transaction-scoped PostgreSQL advisory lock on a dedicated
/// connection, held for the whole sync: whichever way the sync ends (success,
/// error, panic, process death) the transaction ends and the lock goes with
/// it, so it can never be left held on a pooled connection.
pub(crate) struct RepoSyncLock {
    tx: sqlx::Transaction<'static, sqlx::Postgres>,
}

impl RepoSyncLock {
    pub(crate) async fn try_acquire(pool: &PgPool, repo_id: Uuid) -> Result<Option<Self>, MarketplaceError> {
        let mut tx = pool.begin().await?;
        let (acquired,): (bool,) =
            sqlx::query_as("SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(format!("marketplace_repo_sync:{repo_id}"))
                .fetch_one(&mut *tx)
                .await?;
        Ok(acquired.then_some(Self { tx }))
    }

    pub(crate) async fn release(self) {
        let _ = self.tx.rollback().await;
    }
}

/// Validate that a repo URL is safe (HTTPS only, no ext::, file://, ssh://, flag injection)
async fn validate_repo_url(url: &str) -> Result<(), MarketplaceError> {
    // NAN-4946: only nano's first-party catalogs, no embedded credentials.
    super::first_party::validate_first_party_repo_url(url)?;
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
#[cfg(test)]
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

    // NAN-4955: a catalog is never cloned from GitHub; its tree is the
    // installed nano content channel snapshot. Only unit tests drive a local
    // git repository (`test_git_checkout`); production has no git path.
    let commit = match first_party_repo(&repo.url).filter(|_| !test_git_source()) {
        Some((owner, name)) => snapshot_into(&repo_dir, &owner, &name, &repo.branch).await?,
        None => test_git_checkout(repo, &repo_dir).await?,
    };

    // Skip only when neither the content (commit) nor the sync code
    // (SYNC_SCHEMA_VERSION) changed since the last successful sync.
    if is_up_to_date(repo, &commit) {
        info!(repo_id = %repo.id, "No changes since last sync (commit {})", crate::text_bounds::prefix_at_most(&commit, 8));
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
        && repo.last_sync_schema_version != SYNC_SCHEMA_VERSION
    {
        info!(
            repo_id = %repo.id,
            stored_version = repo.last_sync_schema_version,
            current_version = SYNC_SCHEMA_VERSION,
            "Sync schema version changed; re-parsing at unchanged commit {}",
            crate::text_bounds::prefix_at_most(&commit, 8)
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
    let mut entries = Vec::with_capacity(manifests.len());

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
        // NAN-4930: only "not found" means new; any other read failure
        // fails the sync rather than silently re-creating the entry.
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
            config: sqlx::types::Json(effective_config(manifest)),
            enabled: existing.as_ref().map(|e| e.enabled).unwrap_or(false),
            last_sync_at: existing.as_ref().and_then(|e| e.last_sync_at),
            last_sync_status: existing.as_ref().and_then(|e| e.last_sync_status.clone()),
            last_error: existing.as_ref().and_then(|e| e.last_error.clone()),
            record_count: existing.as_ref().map(|e| e.record_count).unwrap_or(0),
            is_syncing: false, // derived per-query in repository; not stored
            requires_network: false, // derived in repository hydrate; not stored
            platform_feed_id: None, // derived in repository hydrate; not stored
            changelog: manifest.changelog.clone(),
            created_at: existing
                .as_ref()
                .map(|e| e.created_at)
                .unwrap_or_else(chrono::Utc::now),
            updated_at: chrono::Utc::now(),
        };

        if is_update {
            updated += 1;
        } else {
            added += 1;
        }
        entries.push(entry);
    }

    // NAN-4930: every upsert and the stale cleanup (non-installed entries
    // only) apply in one transaction, and any failure fails the sync. A
    // partial apply would otherwise be stamped with the current
    // SYNC_SCHEMA_VERSION and never retried at the unchanged commit.
    let removed = repository
        .apply_repo_sync(repo.id, &entries, &seen_slugs)
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

/// A `git` command for the unit tests' local repositories: no redirects,
/// credential helpers, prompts or system/global config influence.
#[cfg(test)]
fn hardened_git() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("git");
    cmd.args([
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "protocol.file.allow=always",
        "-c", "http.followRedirects=false",
        "-c", "credential.helper=",
        "-c", "core.askPass=",
    ])
    .env("GIT_TERMINAL_PROMPT", "0")
    .env("GIT_CONFIG_NOSYSTEM", "1")
    .env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd
}

#[cfg(test)]
thread_local! {
    /// Unit tests that drive the manifest parse/record logic through a local
    /// git repository (NAN-3514 / NAN-4946) opt out of the content-channel
    /// source for first-party URLs; production never can.
    pub(super) static TEST_GIT_SOURCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn test_git_source() -> bool {
    TEST_GIT_SOURCE.with(|f| f.get())
}

#[cfg(not(test))]
fn test_git_source() -> bool {
    false
}

/// Production: a repository that is not a first-party content channel is
/// refused (admission already rejects one; this keeps sync fail closed).
#[cfg(not(test))]
async fn test_git_checkout(repo: &EnrichmentMarketplaceRepo, _repo_dir: &PathBuf) -> Result<String, MarketplaceError> {
    Err(MarketplaceError::GitError(format!(
        "{} is not a nano content channel; third-party repositories are not fetched",
        repo.url
    )))
}

/// Unit tests: drive the manifest parse/record logic through a local git
/// repository (NAN-3514 / NAN-4946).
#[cfg(test)]
async fn test_git_checkout(repo: &EnrichmentMarketplaceRepo, repo_dir: &PathBuf) -> Result<String, MarketplaceError> {
    if repo_dir.exists() {
        git_pull(repo_dir, &repo.branch).await
    } else {
        git_clone(&repo.url, repo_dir, &repo.branch).await
    }
}

/// `(owner, repo)` of a first-party catalog URL (`nano-rs` / `nanos-sh`).
fn first_party_repo(url: &str) -> Option<(String, String)> {
    let (owner, name) = crate::rule_repository::GitHubClient::parse_url(url).ok()?;
    let lowered = url.trim().to_ascii_lowercase();
    let on_github = lowered.starts_with("https://github.com/") || lowered.starts_with("https://www.github.com/");
    (on_github && crate::content_bundle::source::is_first_party(&owner)).then_some((owner, name))
}

/// Replace `repo_dir` with the installed content channel snapshot of
/// `owner/name@branch` (a no-op when it already holds that commit). The
/// snapshot is staged in a sibling directory and swapped in, so a failed
/// write never leaves a half tree. Returns the snapshot's commit.
async fn snapshot_into(repo_dir: &PathBuf, owner: &str, name: &str, branch: &str) -> Result<String, MarketplaceError> {
    use crate::content_bundle::source;
    let want = source::commit(owner, name, branch)
        .await
        .map_err(|e| MarketplaceError::GitError(e.to_string()))?;
    let marker = repo_dir.join(source::COMMIT_MARKER);
    if tokio::fs::read_to_string(&marker).await.is_ok_and(|c| c.trim() == want) {
        return Ok(want);
    }
    let parent = repo_dir
        .parent()
        .ok_or_else(|| MarketplaceError::GitError("repository directory has no parent".into()))?;
    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|e| MarketplaceError::GitError(format!("create repo parent: {e}")))?;
    let staging = parent.join(format!(".staging-{}", uuid::Uuid::now_v7().simple()));
    tokio::fs::create_dir(&staging)
        .await
        .map_err(|e| MarketplaceError::GitError(format!("staging dir: {e}")))?;
    let commit = match source::materialize(owner, name, branch, &[], &staging).await {
        Ok(c) => c,
        Err(e) => {
            let _ = tokio::fs::remove_dir_all(&staging).await;
            return Err(MarketplaceError::GitError(e.to_string()));
        }
    };
    if tokio::fs::symlink_metadata(repo_dir).await.is_ok() {
        // An old git clone (pre-NAN-4955) or an older snapshot.
        tokio::fs::remove_dir_all(repo_dir)
            .await
            .map_err(|e| MarketplaceError::GitError(format!("replace repo dir: {e}")))?;
    }
    tokio::fs::rename(&staging, repo_dir)
        .await
        .map_err(|e| MarketplaceError::GitError(format!("swap repo dir: {e}")))?;
    Ok(commit)
}

/// Clone a git repo (shallow)
#[cfg(test)]
async fn git_clone(url: &str, target: &PathBuf, branch: &str) -> Result<String, MarketplaceError> {
    // Create parent directory
    if let Some(parent) = target.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            MarketplaceError::GitError(format!("Failed to create directory: {}", e))
        })?;
    }

    let output = hardened_git()
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
#[cfg(test)]
async fn git_pull(repo_dir: &PathBuf, branch: &str) -> Result<String, MarketplaceError> {
    // `origin` is the local test repository the checkout was cloned from.
    let output = hardened_git()
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
#[cfg(test)]
async fn get_head_commit(repo_dir: &PathBuf) -> Result<String, MarketplaceError> {
    let output = tokio::process::Command::new("git")
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
fn is_collector_manifest(manifest: &MarketplaceManifest) -> bool {
    !manifest.streams.is_empty()
}

fn execution_backend_for(manifest: &MarketplaceManifest) -> &'static str {
    if is_collector_manifest(manifest) {
        "collector"
    } else if is_official_lookup_manifest(manifest) {
        "lookup"
    } else {
        "deno"
    }
}

/// NAN-5284: an agent manifest that asks for its connector runtime and names
/// an official lookup spec installs that lookup instead of `code.ts`.
/// Enterprise only: the open edition has no threat-intel service, so the row
/// stays `deno` and its install keeps being refused as enterprise-only.
pub(crate) fn is_official_lookup_manifest(manifest: &MarketplaceManifest) -> bool {
    cfg!(feature = "enterprise")
        && manifest.category == "agent"
        && manifest.runtime.as_deref().map(str::trim) == Some("connector")
        && super::types::OFFICIAL_LOOKUP_PROVIDERS.contains(&manifest.slug.as_str())
}

/// Fold the collector-only manifest fields into the catalog row's `config`
/// JSONB.
///
/// The alternative — adding five columns to `marketplace_catalog` — would put
/// enterprise-only collector schema on an open-tier table for no gain: nothing
/// queries these fields relationally, they are read as a unit when a run
/// starts. Enrichment manifests are untouched, so their stored config stays
/// byte-identical to what pre-NAN-2189 sync wrote.
fn effective_config(manifest: &MarketplaceManifest) -> serde_json::Value {
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
                    Ok(content) => match crate::yaml_budget::from_str::<MarketplaceManifest>(&content) {
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
#[path = "sync_service_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "sync_service_db_tests.rs"]
mod db_tests;
#[cfg(test)]
#[path = "sync_service_owner_db_tests.rs"]
mod owner_db_tests;
