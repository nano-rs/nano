// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser Repository Service
//!
//! Provides high-level operations for managing external parser repositories,
//! syncing parsers from GitHub, and importing parsers as log sources.

use sqlx::PgPool;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::{TargetEffect, TargetGrants};
use crate::log_sources::{LogSourceRepository, NewLogSource, UpdateLogSource};
use crate::log_telemetry::repository::is_safe_source_type;
use crate::rule_repository::GitHubClient;

use super::error::ParserRepositoryError;
use super::models::{
    ApplyUpstreamUpdateResult, BulkApplyUpstreamResult, BundleImportResult, NewParserRepository,
    ParserImport, ParserImportPreview, ParserImportRequest, ParserImportType, ParserRepository,
    RepositoryParser, RepositoryParserFilter, SyncResult, SyncStatus, UpdateParserRepository,
    UpstreamParserDiff,
};
use super::repository::{
    ParserImportsRepository, ParserRepositoryRepository, RepositoryParsersRepository,
};
use super::yaml_parser::parse_parser_yaml;

/// Allowed parser repository sources (owner/repo format, lowercase)
const ALLOWED_REPOSITORIES: &[&str] = &["nano-rs/parsers"];

/// Stable slug + display name for the synthetic repository that air-gapped
/// parser bundles (NAN-1201/NAN-1204) are imported into. Lazily created on
/// first bundle upload; never network-synced.
const AIRGAP_REPOSITORY_SLUG: &str = "airgap-parsers";
const AIRGAP_REPOSITORY_NAME: &str = "Air-gapped Parser Bundles";

/// Outcome-aware authorization plan for one parser import (NAN-2117).
///
/// Preflighted by [`ParserRepositoryService::plan_import`] so a handler can
/// enforce the complete capability policy — and reject a whole batch — before
/// any database write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParserImportPlan {
    /// False when the parser is already imported: `import_parser` returns
    /// `AlreadyImported` and writes nothing, so no capability is consumed.
    pub creates_log_source: bool,
    /// True when the import will accept (or auto-resolve) a dispatch
    /// source-configuration and can therefore insert an identity routing rule
    /// into that config's routing table.
    pub mutates_source_config: bool,
}

impl ParserImportPlan {
    /// The target-resource capabilities this import will consume.
    pub fn required_effects(&self) -> Vec<TargetEffect> {
        let mut effects = Vec::new();
        if self.creates_log_source {
            effects.push(TargetEffect::LogSourceCreate);
        }
        if self.mutates_source_config {
            effects.push(TargetEffect::SourceConfigEdit);
        }
        effects
    }
}

/// What a completed parser import actually wrote.
///
/// The routing-rule insert is deduped and best-effort, so the caller cannot
/// infer it from the plan — audit records must reflect what happened, not what
/// was authorized (NAN-2117).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserImportResult {
    /// The log source that was created.
    pub log_source_id: Uuid,
    /// Its display name — what the canonical `POST /api/log-sources` audit
    /// records as the resource name, and what audit search matches on.
    pub log_source_name: String,
    /// The identity routing rule inserted on the dispatch source-configuration,
    /// if one was actually created (absent when no dispatch config resolved, the
    /// rule already existed, the parser is an enrichment flavor, or the
    /// non-fatal insert failed).
    pub routing_rule_id: Option<Uuid>,
}

/// Configuration for the parser repository service
#[derive(Debug, Clone)]
pub struct ParserRepositoryServiceConfig {
    pub max_parsers_per_repo: usize,
}

impl Default for ParserRepositoryServiceConfig {
    fn default() -> Self {
        Self {
            max_parsers_per_repo: 1000,
        }
    }
}

/// Service for managing parser repositories
pub struct ParserRepositoryService {
    repo_repository: ParserRepositoryRepository,
    parsers_repository: RepositoryParsersRepository,
    imports_repository: ParserImportsRepository,
    github_client: GitHubClient,
    log_source_repository: Option<LogSourceRepository>,
    config: ParserRepositoryServiceConfig,
    pg_pool: PgPool,
    syncing_repos: Arc<RwLock<std::collections::HashSet<Uuid>>>,
}

impl ParserRepositoryService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            repo_repository: ParserRepositoryRepository::new(pool.clone()),
            parsers_repository: RepositoryParsersRepository::new(pool.clone()),
            imports_repository: ParserImportsRepository::new(pool.clone()),
            github_client: GitHubClient::new(),
            log_source_repository: Some(LogSourceRepository::new(pool.clone())),
            config: ParserRepositoryServiceConfig::default(),
            pg_pool: pool,
            syncing_repos: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    /// Compatibility check between a `source_configurations.config_type`
    /// and a parser's `ingestion_method`. NAN-943.
    ///
    /// The dispatch picker (`SourceConfigForm.tsx` → `SOURCE_TYPE_MAP`)
    /// only surfaces 1:1 pairs for the pull-style sources, so the matrix
    /// here mirrors that map:
    ///
    /// | config_type   | ingestion_method | dispatch-bound?      |
    /// |---------------|------------------|----------------------|
    /// | kafka         | kafka            | yes                  |
    /// | aws_s3 / s3   | aws_s3           | yes                  |
    /// | gcp_pubsub    | gcp_pubsub       | yes                  |
    /// | splunk_hec    | splunk_hec       | yes                  |
    /// | http          | routed           | no (always-on)       |
    /// | vector        | vector           | no (always-on)       |
    ///
    /// Always-on sources don't need a per-config dispatch, but callers
    /// who DO pass `dispatch_source_config_id` for a routed/vector parser
    /// must point at the matching config_type. The check is symmetric:
    /// it rejects both "kafka parser + s3 dispatch" AND "s3 parser + kafka
    /// dispatch".
    fn is_dispatch_compatible(config_type: &str, ingestion_method: &str) -> bool {
        let normalized_ct = match config_type {
            // `SourceConfigType::from_str` accepts the legacy short forms;
            // database rows have always stored the canonical name, but
            // defense-in-depth.
            "s3" => "aws_s3",
            "pubsub" => "gcp_pubsub",
            "splunk" | "hec" => "splunk_hec",
            other => other,
        };
        matches!(
            (normalized_ct, ingestion_method),
            ("kafka", "kafka")
                | ("aws_s3", "aws_s3")
                | ("gcp_pubsub", "gcp_pubsub")
                | ("splunk_hec", "splunk_hec")
                | ("http", "routed")
                | ("vector", "vector")
        )
    }

    // =========================================================================
    // Repository CRUD
    // =========================================================================

    pub async fn list_repositories(&self) -> Result<Vec<ParserRepository>, ParserRepositoryError> {
        self.repo_repository
            .list()
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))
    }

    pub async fn get_repository(
        &self,
        id: Uuid,
    ) -> Result<ParserRepository, ParserRepositoryError> {
        self.repo_repository
            .find_by_id(id)
            .await
            .map_err(|e| match e {
                super::repository::ParserRepositoryRepositoryError::NotFound(id) => {
                    ParserRepositoryError::RepositoryNotFound(id)
                }
                other => ParserRepositoryError::Internal(other.to_string()),
            })
    }

    pub async fn create_repository(
        &self,
        req: NewParserRepository,
        user_id: Option<Uuid>,
    ) -> Result<ParserRepository, ParserRepositoryError> {
        // Validate URL is in allowlist
        self.validate_url(&req.url)?;

        self.repo_repository
            .create(&req, user_id)
            .await
            .map_err(|e| match e {
                super::repository::ParserRepositoryRepositoryError::AlreadyExists(name) => {
                    ParserRepositoryError::RepositoryAlreadyExists(name)
                }
                other => ParserRepositoryError::Internal(other.to_string()),
            })
    }

    pub async fn update_repository(
        &self,
        id: Uuid,
        update: UpdateParserRepository,
    ) -> Result<ParserRepository, ParserRepositoryError> {
        self.repo_repository
            .update(id, &update)
            .await
            .map_err(|e| match e {
                super::repository::ParserRepositoryRepositoryError::NotFound(id) => {
                    ParserRepositoryError::RepositoryNotFound(id)
                }
                other => ParserRepositoryError::Internal(other.to_string()),
            })
    }

    pub async fn delete_repository(&self, id: Uuid) -> Result<(), ParserRepositoryError> {
        self.repo_repository.delete(id).await.map_err(|e| match e {
            super::repository::ParserRepositoryRepositoryError::NotFound(id) => {
                ParserRepositoryError::RepositoryNotFound(id)
            }
            other => ParserRepositoryError::Internal(other.to_string()),
        })
    }

    // =========================================================================
    // Sync
    // =========================================================================

    /// Start a background sync task
    pub async fn start_sync(&self, id: Uuid) -> Result<(), ParserRepositoryError> {
        let repo = self.get_repository(id).await?;

        if !repo.enabled {
            return Err(ParserRepositoryError::RepositoryDisabled);
        }

        // Check if already syncing
        {
            let syncing = self.syncing_repos.read().await;
            if syncing.contains(&id) {
                return Err(ParserRepositoryError::SyncInProgress(id));
            }
        }

        // Mark as syncing
        self.repo_repository
            .update_sync_status(id, "syncing", None, None, None)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        // Spawn background task
        let pool = self.pg_pool.clone();
        let syncing_repos = self.syncing_repos.clone();

        tokio::spawn(async move {
            {
                let mut syncing = syncing_repos.write().await;
                syncing.insert(id);
            }

            let service = ParserRepositoryService::new(pool);
            let result = service.run_sync(id).await;

            {
                let mut syncing = syncing_repos.write().await;
                syncing.remove(&id);
            }

            if let Err(e) = result {
                warn!(repo_id = %id, error = %e, "Parser repository sync failed");
            }
        });

        Ok(())
    }

    /// Run a repository sync in the caller's task.
    ///
    /// Leader-owned schedulers use this form so aborting the scheduler also
    /// cancels every in-flight network, parse, and status-write future.
    pub async fn sync_repository(&self, id: Uuid) -> Result<SyncResult, ParserRepositoryError> {
        let repo = self.get_repository(id).await?;
        if !repo.enabled {
            return Err(ParserRepositoryError::RepositoryDisabled);
        }
        {
            let mut syncing = self.syncing_repos.write().await;
            if !syncing.insert(id) {
                return Err(ParserRepositoryError::SyncInProgress(id));
            }
        }

        if let Err(error) = self
            .repo_repository
            .update_sync_status(id, "syncing", None, None, None)
            .await
        {
            self.syncing_repos.write().await.remove(&id);
            return Err(ParserRepositoryError::Internal(error.to_string()));
        }
        let result = self.run_sync(id).await;
        if let Err(error) = &result {
            let _ = self
                .repo_repository
                .update_sync_status(id, "failed", None, None, Some(&error.to_string()))
                .await;
        }
        self.syncing_repos.write().await.remove(&id);
        result
    }

    /// Run sync (blocking, called from background task)
    async fn run_sync(&self, id: Uuid) -> Result<SyncResult, ParserRepositoryError> {
        let start = Instant::now();
        let repo = self.get_repository(id).await?;

        let (owner, repo_name) = GitHubClient::parse_url(&repo.url).map_err(
            |e: crate::rule_repository::GitHubClientError| {
                ParserRepositoryError::GitHubApi(e.to_string())
            },
        )?;

        // NAN-1266: under NANO_SCHEMA_PROFILE=ocsf the sync walks the sibling
        // `parsers-ocsf/` tree so imported parsers emit OCSF; UDM is unchanged.
        let parsers_path =
            crate::schema::active_repo_path(repo.parsers_path.as_deref().unwrap_or("parsers/"));
        let parsers_path = parsers_path.as_str();
        let branch = &repo.branch;

        info!(repo_id = %id, owner = %owner, repo = %repo_name, "Starting parser repository sync");

        // Get the latest commit
        let commit = self
            .github_client
            .get_latest_commit(&owner, &repo_name, branch)
            .await
            .map_err(|e| ParserRepositoryError::GitHubApi(e.to_string()))?;

        // NAN-1149: enrichment parsers live under `enrichments/` in the same
        // repo. Walk both trees and tag each file with its base path so the loop
        // resolves the raw-file path correctly. The `enrichments/` dir is
        // optional (a repo may ship only log parsers), so a missing/erroring
        // subtree is tolerated.
        let enrichments_path = "enrichments/";

        let parsers_tree = self
            .github_client
            .get_tree(&owner, &repo_name, branch, Some(parsers_path))
            .await
            .map_err(|e| ParserRepositoryError::GitHubApi(e.to_string()))?;
        let enrichments_tree = self
            .github_client
            .get_tree(&owner, &repo_name, branch, Some(enrichments_path))
            .await
            .unwrap_or_else(|e| {
                warn!(repo_id = %id, error = %e, "No enrichments/ tree (optional); skipping");
                Vec::new()
            });

        let yaml_files: Vec<(_, &str)> = parsers_tree
            .iter()
            .filter(|entry| {
                entry.path.ends_with("/parser.yaml") || entry.path.ends_with("/parser.yml")
            })
            .map(|e| (e, parsers_path))
            .chain(
                enrichments_tree
                    .iter()
                    .filter(|entry| {
                        entry.path.ends_with("/parser.yaml") || entry.path.ends_with("/parser.yml")
                    })
                    .map(|e| (e, enrichments_path)),
            )
            .collect();

        let mut added = 0i32;
        let mut updated = 0i32;
        let mut synced_paths = Vec::new();

        for &(entry, base_path) in &yaml_files {
            if synced_paths.len() >= self.config.max_parsers_per_repo {
                warn!(repo_id = %id, "Max parsers per repo reached, stopping sync");
                break;
            }

            let full_path = if entry.path.starts_with(base_path) {
                entry.path.clone()
            } else {
                format!("{}{}", base_path, entry.path)
            };

            // Check if file changed (by SHA)
            let existing = self
                .parsers_repository
                .find_by_path(id, &entry.path)
                .await
                .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

            let file_sha = Some(entry.sha.as_str());
            let needs_update = existing
                .as_ref()
                .map(|e| e.file_sha.as_deref() != file_sha)
                .unwrap_or(true);

            if !needs_update {
                synced_paths.push(entry.path.clone());
                continue;
            }

            // Fetch file content using commit SHA (not branch ref) to avoid CDN caching
            let content = self
                .github_client
                .get_raw_file(&owner, &repo_name, &full_path, &commit)
                .await
                .map_err(|e| ParserRepositoryError::GitHubApi(e.to_string()))?;

            // Parse YAML
            match parse_parser_yaml(&content) {
                Ok(parsed) => {
                    let is_new = existing.is_none();
                    // NAN-1149: files under enrichments/ are enrichment parsers
                    // even if the yaml omits `kind`; otherwise honor the yaml.
                    let kind = if base_path == enrichments_path {
                        "enrichment"
                    } else {
                        parsed.kind.as_deref().unwrap_or("parser")
                    };
                    self.parsers_repository
                        .upsert(
                            id,
                            &entry.path,
                            file_sha,
                            &content,
                            Some(&parsed.name),
                            parsed.display_name.as_deref(),
                            parsed.description.as_deref(),
                            parsed.version.as_deref(),
                            parsed.category.as_deref(),
                            parsed.vendor.as_deref(),
                            parsed.product.as_deref(),
                            parsed.parser_vrl.as_deref(),
                            kind,
                            parsed.enrich_kind.as_deref(),
                            parsed.enrich_source.as_deref(),
                            parsed.target_table.as_deref(),
                            parsed.normalize_vrl.as_deref(),
                        )
                        .await
                        .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

                    if is_new {
                        added += 1;
                    } else {
                        updated += 1;
                        // Mark linked imports as upstream_changed
                        self.imports_repository
                            .mark_upstream_changed(existing.unwrap().id)
                            .await
                            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;
                    }

                    synced_paths.push(entry.path.clone());
                }
                Err(e) => {
                    warn!(
                        repo_id = %id,
                        path = %entry.path,
                        error = %e,
                        "Failed to parse parser.yaml"
                    );
                    // Still track the path so we don't delete it
                    synced_paths.push(entry.path.clone());
                }
            }
        }

        // Remove parsers no longer in repo
        let removed =
            self.parsers_repository
                .delete_not_in_paths(id, &synced_paths)
                .await
                .map_err(|e| ParserRepositoryError::Internal(e.to_string()))? as i32;

        let total = synced_paths.len() as i32;
        let duration_ms = start.elapsed().as_millis() as u64;

        // Update repo status
        self.repo_repository
            .update_sync_status(id, "success", Some(&commit), Some(total), None)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        let result = SyncResult {
            repository_id: id,
            status: SyncStatus::Success,
            commit: Some(commit),
            parsers_added: added,
            parsers_updated: updated,
            parsers_removed: removed,
            parsers_total: total,
            duration_ms,
            error: None,
        };

        info!(
            repo_id = %id,
            added = added,
            updated = updated,
            removed = removed,
            total = total,
            duration_ms = duration_ms,
            "Parser repository sync completed"
        );

        // NAN-2120: sync is CATALOG-ONLY. It used to finish by calling the
        // global `fixup_imported_match_values()`, which rewrote
        // `log_sources.match_values` for every imported parser across every
        // repository — live ingestion-routing metadata — as an unauthorized side
        // effect of a `parser_repositories:sync` request (and of the leader's
        // scheduled sync). The upsert loop above already marks each linked
        // import `upstream_changed`; the operator applies that to the live log
        // source explicitly via apply-upstream-update / fixup-match-values,
        // where the target edit capabilities are enforced.

        Ok(result)
    }

    // =========================================================================
    // Browse Parsers
    // =========================================================================

    pub async fn list_parsers(
        &self,
        repo_id: Uuid,
        filter: &RepositoryParserFilter,
    ) -> Result<Vec<RepositoryParser>, ParserRepositoryError> {
        // Verify repo exists
        let _ = self.get_repository(repo_id).await?;

        self.parsers_repository
            .list(repo_id, filter)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))
    }

    pub async fn get_parser(
        &self,
        repo_id: Uuid,
        path: &str,
    ) -> Result<RepositoryParser, ParserRepositoryError> {
        self.parsers_repository
            .find_by_path(repo_id, path)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?
            .ok_or_else(|| ParserRepositoryError::ParserNotFound {
                repo_id,
                path: path.to_string(),
            })
    }

    // =========================================================================
    // Import Preview
    // =========================================================================

    pub async fn preview_import(
        &self,
        repo_id: Uuid,
        path: &str,
    ) -> Result<ParserImportPreview, ParserRepositoryError> {
        let parser = self.get_parser(repo_id, path).await?;

        // Check if already imported
        let imports = self
            .imports_repository
            .find_by_repository_parser(parser.id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        let already_imported = !imports.is_empty();
        let existing_import_type = imports.first().map(|i| i.import_type.clone());
        let existing_log_source_id = imports.first().map(|i| i.log_source_id);

        let proposed_name = parser
            .display_name
            .clone()
            .unwrap_or_else(|| parser.name.clone().unwrap_or_else(|| path.to_string()));

        Ok(ParserImportPreview {
            proposed_name,
            proposed_description: parser.description.clone(),
            proposed_category: parser.category.clone(),
            proposed_vendor: parser.vendor.clone(),
            proposed_product: parser.product.clone(),
            already_imported,
            existing_import_type,
            existing_log_source_id,
            repository_parser: parser,
        })
    }

    // =========================================================================
    // Import Parser as Log Source
    // =========================================================================

    /// Preflight what [`Self::import_parser`] would do to live resources,
    /// **without writing anything** (NAN-2117).
    ///
    /// Performs a strict subset of `import_parser`'s reads so a handler can
    /// enforce the composite `log_sources:create` + `source_configs:edit` policy
    /// (and reject a whole batch) before the first mutation. Errors raised here
    /// are raised identically by `import_parser` at the same point, before any
    /// write.
    pub async fn plan_import(
        &self,
        repo_id: Uuid,
        path: &str,
        req: &ParserImportRequest,
    ) -> Result<ParserImportPlan, ParserRepositoryError> {
        let _ = self.get_repository(repo_id).await?;
        let parser = self.get_parser(repo_id, path).await?;

        let existing = self
            .imports_repository
            .find_by_repository_parser(parser.id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;
        if !existing.is_empty() {
            // `import_parser` short-circuits with AlreadyImported and writes
            // nothing.
            return Ok(ParserImportPlan {
                creates_log_source: false,
                mutates_source_config: false,
            });
        }

        // Enrichment parsers route through the enrichment lane, never through a
        // source-config routing rule.
        let is_enrichment = parser.kind == "enrichment";
        let dispatch_source_config_id = self.resolve_dispatch_source_config(req).await?;

        Ok(ParserImportPlan {
            creates_log_source: true,
            mutates_source_config: !is_enrichment && dispatch_source_config_id.is_some(),
        })
    }

    /// Resolve the dispatch source-configuration an import will bind to.
    ///
    /// Either the caller's explicit `dispatch_source_config_id`, or (NAN-1270)
    /// the first deployed source-config whose `config_type` matches the parser's
    /// `ingestion_method`. Shared by [`Self::plan_import`] and
    /// [`Self::import_parser`] so the preflight cannot disagree with the write
    /// path about whether a source config is touched.
    async fn resolve_dispatch_source_config(
        &self,
        req: &ParserImportRequest,
    ) -> Result<Option<Uuid>, ParserRepositoryError> {
        if let Some(id) = req.dispatch_source_config_id {
            return Ok(Some(id));
        }
        let ingestion_method = req.ingestion_method.as_deref().unwrap_or("routed");
        let config_type = Self::config_type_for_ingestion_method(ingestion_method);
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM source_configurations WHERE config_type = $1 \
             ORDER BY created_at ASC LIMIT 1",
        )
        .bind(config_type)
        .fetch_optional(&self.pg_pool)
        .await
        .map_err(ParserRepositoryError::Database)
    }

    /// Import a repository parser as a live log source.
    ///
    /// `grants` carries the target-resource capabilities the caller was verified
    /// to hold (NAN-2117). They are re-checked here, immediately before the
    /// writes, so a race that changes the resolved dispatch config cannot
    /// launder a missing `source_configs:edit`. Internal SYSTEM callers pass
    /// [`TargetGrants::system`]; anything else must pass a principal-derived set.
    pub async fn import_parser(
        &self,
        repo_id: Uuid,
        path: &str,
        req: &ParserImportRequest,
        user_id: Option<Uuid>,
        grants: &TargetGrants,
    ) -> Result<ParserImportResult, ParserRepositoryError> {
        let repo = self.get_repository(repo_id).await?;
        let parser = self.get_parser(repo_id, path).await?;

        // Check not already imported
        let existing = self
            .imports_repository
            .find_by_repository_parser(parser.id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        if !existing.is_empty() {
            return Err(ParserRepositoryError::AlreadyImported {
                import_type: existing[0].import_type.clone(),
            });
        }

        // NAN-2117: this creates a first-class, validated, active `log_sources`
        // row — exactly what `POST /api/log-sources` gates behind
        // `log_sources:create`. `parser_repositories:import` authorizes the
        // catalog read, never the target creation.
        grants
            .ensure(TargetEffect::LogSourceCreate)
            .map_err(|effect| ParserRepositoryError::Forbidden(effect.permission().to_string()))?;

        // NAN-1149: an enrichment parser (kind = "enrichment") deploys as a
        // `kind='enrichment'` log_sources row carrying the per-source normalize
        // VRL + routing columns instead of a log `source_type`. The deploy
        // engine (`generate_enrichment_lane`) keys off these columns; without
        // them a synced enrichment parser would land as an inert `kind='log'`
        // row and never reach the enrichment lane. The match_values/ingestion/
        // dispatch machinery below is log-only and is skipped for this flavor.
        let is_enrichment = parser.kind == "enrichment";
        if is_enrichment {
            Self::validate_enrichment_import(&parser, path)?;
        }

        let parser_vrl = parser.parser_vrl.clone().unwrap_or_default();

        // Build log source name from parser name
        let display_name = parser
            .display_name
            .clone()
            .unwrap_or_else(|| parser.name.clone().unwrap_or_else(|| path.to_string()));

        // match_values: union the UI's `source_type` override (parser name
        // by default), the YAML's `match_values` list, and the parser's
        // canonical name as a fallback. See `resolve_match_values` for the
        // ordering rationale. NAN-920.
        let parsed_yaml = super::yaml_parser::parse_parser_yaml(&parser.raw_content).ok();
        let yaml_match_values = parsed_yaml
            .as_ref()
            .and_then(|y| y.match_values.clone())
            .unwrap_or_default();
        let match_values = Self::resolve_match_values(
            req.source_type.as_deref(),
            &yaml_match_values,
            parser.name.as_deref(),
        );

        // ingestion_method: how logs arrive (routed, kafka, aws_s3, etc.)
        let ingestion_method = req
            .ingestion_method
            .clone()
            .unwrap_or_else(|| "routed".to_string());

        // NAN-1270: resolve the dispatch source-configuration. The single-import
        // UI pins one (and creates the routing rule); batch import / raw API
        // callers leave it None — which left the imported log source unwired to
        // any source config (no association, no routing rule) while single
        // import worked. Auto-resolve the deployed source-config whose
        // config_type matches this parser's ingestion_method so every import
        // path behaves identically. NULL only if none is deployed for that
        // method (the "create/deploy a source config first" case).
        let dispatch_source_config_id = self.resolve_dispatch_source_config(req).await?;

        // NAN-2117: binding the new log source to a source-configuration and
        // inserting its identity routing rule mutates a separately administered
        // resource — `POST /api/source-configurations/{id}/rules` requires
        // `source_configs:edit`. Enforce it here whether the caller pinned the
        // config explicitly or the auto-resolution picked one for them, and
        // before ANY write so a denial cannot leave a half-wired log source.
        // Enrichment imports route via the enrichment lane, not routing rules.
        if !is_enrichment && dispatch_source_config_id.is_some() {
            grants
                .ensure(TargetEffect::SourceConfigEdit)
                .map_err(|effect| {
                    ParserRepositoryError::Forbidden(effect.permission().to_string())
                })?;
        }

        // Primary source_type for the auto-created routing rule (below). Captured
        // before `match_values` is moved into the NewLogSource.
        let primary_source_type = match_values.first().cloned();

        // NAN-943: when the caller pairs a parser with a specific
        // source-configuration via `dispatch_source_config_id`, that
        // source-config's `config_type` must be compatible with the
        // parser's `ingestion_method`. Without this guard the FK
        // constraint passes, the parser is created, and at deploy time
        // it filters on `<wrong_config>_route` and receives zero events
        // — the exact silent-failure mode NAN-928 set out to eliminate.
        // The web UI guards via SOURCE_TYPE_MAP, but the API has no
        // enforcement; a hand-rolled POST with mismatched
        // (ingestion_method=kafka, dispatch_source_config_id=<aws_s3 id>)
        // would be accepted.
        if let Some(dispatch_id) = dispatch_source_config_id {
            let row: Option<(String,)> =
                sqlx::query_as("SELECT config_type FROM source_configurations WHERE id = $1")
                    .bind(dispatch_id)
                    .fetch_optional(&self.pg_pool)
                    .await
                    .map_err(ParserRepositoryError::Database)?;
            let config_type = row.map(|(ct,)| ct).ok_or_else(|| {
                ParserRepositoryError::InvalidRequest(format!(
                    "dispatch_source_config_id {dispatch_id} does not match any source-configuration",
                ))
            })?;
            if !Self::is_dispatch_compatible(&config_type, &ingestion_method) {
                return Err(ParserRepositoryError::InvalidRequest(format!(
                    "dispatch_source_config_id config_type '{config_type}' is incompatible with parser ingestion_method '{ingestion_method}'; \
                     pick a {ingestion_method} source-configuration or change the parser's ingestion_method",
                )));
            }
        }

        let new_log_source = NewLogSource {
            name: display_name,
            description: parser.description.clone(),
            namespace: "default".to_string(),
            timezone: "UTC".to_string(),
            source_type: ingestion_method,
            parser_vrl,
            output_fields: None,
            dispatch_source_config_id,
            category: parser.category.clone(),
            vendor: parser.vendor.clone(),
            product: parser.product.clone(),
            icon: None,
            color: None,
            match_field: None,
            match_pattern: None,
            match_values: Some(match_values),
            sampling_ratio: None,
            sampling_exclude_condition: None,
            // NAN-1920: repo imports create real, immediately-usable feeds —
            // not wizard drafts — so they stay 'active' (the INSERT default).
            lifecycle_status: None,
        };

        // NAN-950: do the log_sources and parser_imports writes inside one
        // sqlx transaction so an API crash between statements can't leave
        // a half-imported log_source — pre-NAN-950 the orphan had
        // the import metadata missing and produced broken state.
        //
        // We bypass LogSourceRepository::create + ParserImportsRepository::create
        // for this path because they each take `&PgPool`; the transaction
        // requires `&mut Transaction`. The SQL below mirrors those two
        // methods (kept in sync with `log_sources/repository/crud.rs::create`
        // and `parser_repository/repository.rs::ParserImportsRepository::create`);
        // future column additions to log_sources or parser_imports must
        // also be made here.
        let is_linked = matches!(req.import_type, ParserImportType::Linked);
        let import_type_str = req.import_type.to_string();

        // NAN-1149: enrichment-flavor columns. For a log import these stay at
        // the schema default (kind='log', the rest NULL) so the deploy split
        // treats the row exactly as before; for an enrichment import they carry
        // the synced parser's routing + normalize VRL into the lane generator.
        let ls_kind = if is_enrichment { "enrichment" } else { "log" };
        let enrich_kind = is_enrichment.then(|| parser.enrich_kind.clone()).flatten();
        let enrich_source = is_enrichment
            .then(|| parser.enrich_source.clone())
            .flatten();
        let target_table = is_enrichment.then(|| parser.target_table.clone()).flatten();
        let normalize_vrl = is_enrichment
            .then(|| parser.normalize_vrl.clone())
            .flatten();

        let mut tx = self
            .pg_pool
            .begin()
            .await
            .map_err(ParserRepositoryError::Database)?;

        // Duplicate-name check — must be inside the transaction so two
        // concurrent imports of the same parser can't both pass.
        let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM log_sources WHERE name = $1")
            .bind(&new_log_source.name)
            .fetch_one(&mut *tx)
            .await
            .map_err(ParserRepositoryError::Database)?;
        if existing > 0 {
            return Err(ParserRepositoryError::LogSourceService(format!(
                "Log source with name '{}' already exists",
                new_log_source.name
            )));
        }

        // Single INSERT sets validated/source_parser_* in one round-trip while
        // inside the transaction.
        let log_source_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO log_sources (
                name, description, namespace, timezone, source_type,
                parser_vrl, output_fields, category, vendor, product, icon, color,
                match_field, match_pattern, match_values, dispatch_source_config_id,
                validated, validation_error,
                source_parser_repository_id, source_parser_path, source_parser_linked,
                kind, enrich_kind, enrich_source, target_table, normalize_vrl
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                    $13, $14, $15, $16,
                    true, NULL,
                    $17, $18, $19,
                    $20, $21, $22, $23, $24)
            RETURNING id
            "#,
        )
        .bind(&new_log_source.name)
        .bind(&new_log_source.description)
        .bind(&new_log_source.namespace)
        .bind(&new_log_source.timezone)
        .bind(&new_log_source.source_type)
        .bind(&new_log_source.parser_vrl)
        .bind(&new_log_source.output_fields)
        .bind(&new_log_source.category)
        .bind(&new_log_source.vendor)
        .bind(&new_log_source.product)
        .bind(&new_log_source.icon)
        .bind(&new_log_source.color)
        .bind(&new_log_source.match_field)
        .bind(&new_log_source.match_pattern)
        .bind(&new_log_source.match_values)
        .bind(&new_log_source.dispatch_source_config_id)
        .bind(repo_id)
        .bind(path)
        .bind(is_linked)
        .bind(ls_kind)
        .bind(&enrich_kind)
        .bind(&enrich_source)
        .bind(&target_table)
        .bind(&normalize_vrl)
        .fetch_one(&mut *tx)
        .await
        .map_err(ParserRepositoryError::Database)?;

        // Create the parser_imports row inside the same transaction so a
        // crash between INSERTs rolls back the log_source.
        sqlx::query(
            r#"
            INSERT INTO parser_imports (
                repository_parser_id, log_source_id, import_type,
                imported_by, imported_commit, last_sync_commit
            )
            VALUES ($1, $2, $3, $4, $5, $5)
            "#,
        )
        .bind(parser.id)
        .bind(log_source_id)
        .bind(&import_type_str)
        .bind(user_id)
        .bind(repo.last_sync_commit.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(ParserRepositoryError::Database)?;

        tx.commit().await.map_err(ParserRepositoryError::Database)?;

        // NAN-1270: create the identity routing rule on the dispatch source
        // config (source_type -> same source_type), mirroring what the
        // single-import UI did out-of-band. Best-effort + deduped: a missing
        // rule no longer silently differs between single and batch import.
        // Enrichment imports route via the enrichment lane, not source_type.
        let mut routing_rule_id: Option<Uuid> = None;
        if !is_enrichment {
            if let (Some(cfg_id), Some(src_type)) =
                (dispatch_source_config_id, primary_source_type.as_deref())
            {
                let exists: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM routing_rules \
                     WHERE source_configuration_id = $1 AND match_field = 'source_type' AND match_value = $2",
                )
                .bind(cfg_id)
                .bind(src_type)
                .fetch_one(&self.pg_pool)
                .await
                .unwrap_or(0);
                if exists == 0 {
                    let next_priority: i32 = sqlx::query_scalar(
                        "SELECT COALESCE(MAX(priority), 99) + 1 FROM routing_rules \
                         WHERE source_configuration_id = $1",
                    )
                    .bind(cfg_id)
                    .fetch_one(&self.pg_pool)
                    .await
                    .unwrap_or(100);
                    // NAN-2117: RETURNING the id so the caller audits the routing
                    // rule that was ACTUALLY created — this insert is deduped
                    // above and non-fatal below, so "a dispatch config resolved"
                    // is not evidence that a rule appeared.
                    match sqlx::query_scalar::<_, Uuid>(
                        "INSERT INTO routing_rules \
                         (source_configuration_id, priority, match_field, match_type, match_value, target_source_type) \
                         VALUES ($1, $2, 'source_type', 'exact', $3, $3) RETURNING id",
                    )
                    .bind(cfg_id)
                    .bind(next_priority)
                    .bind(src_type)
                    .fetch_one(&self.pg_pool)
                    .await
                    {
                        Ok(id) => routing_rule_id = Some(id),
                        Err(e) => {
                            warn!(log_source_id = %log_source_id, source_type = %src_type, error = %e,
                                "Imported parser: failed to auto-create routing rule (non-fatal)");
                        }
                    }
                }
            }
        }

        info!(
            repo_id = %repo_id,
            parser_path = %path,
            log_source_id = %log_source_id,
            import_type = %req.import_type,
            "Parser imported as log source"
        );

        Ok(ParserImportResult {
            log_source_id,
            log_source_name: new_log_source.name,
            routing_rule_id,
        })
    }

    /// Map a parser `ingestion_method` to the `source_configurations.config_type`
    /// that carries it (inverse of [`Self::is_dispatch_compatible`]). Used to
    /// auto-resolve the dispatch source-config when an importer doesn't pin one
    /// (NAN-1270). Unknown methods fall through unchanged.
    fn config_type_for_ingestion_method(ingestion_method: &str) -> &str {
        match ingestion_method {
            "routed" => "http",
            other => other, // kafka/aws_s3/gcp_pubsub/splunk_hec/vector are identity
        }
    }

    // =========================================================================
    // Batch Import
    // =========================================================================

    pub async fn batch_import(
        &self,
        repo_id: Uuid,
        paths: &[String],
        import_type: &ParserImportType,
        user_id: Option<Uuid>,
        grants: &TargetGrants,
    ) -> Result<Vec<Result<Uuid, String>>, ParserRepositoryError> {
        let mut results = Vec::new();

        for path in paths {
            let req = ParserImportRequest {
                import_type: import_type.clone(),
                source_type: None,
                ingestion_method: None, // Defaults to "routed"
                dispatch_source_config_id: None,
            };
            match self
                .import_parser(repo_id, path, &req, user_id, grants)
                .await
            {
                Ok(result) => results.push(Ok(result.log_source_id)),
                Err(ParserRepositoryError::AlreadyImported { .. }) => {
                    results.push(Err("Already imported".to_string()));
                }
                Err(e) => {
                    results.push(Err(e.to_string()));
                }
            }
        }

        Ok(results)
    }

    // =========================================================================
    // Remove All Imported
    // =========================================================================

    /// Delete every log source imported from `repo_id`.
    ///
    /// NAN-2111: `parser_repositories:manage` authorizes managing the repository
    /// catalog, not mass-deleting the first-class log sources it produced —
    /// `DELETE /api/log-sources/{id}` requires `log_sources:delete`. The check
    /// runs before the imports are even loaded so a denied caller learns nothing
    /// about how many targets exist.
    pub async fn remove_all_imported(
        &self,
        repo_id: Uuid,
        grants: &TargetGrants,
    ) -> Result<(i32, i32), ParserRepositoryError> {
        grants
            .ensure(TargetEffect::LogSourceDelete)
            .map_err(|effect| ParserRepositoryError::Forbidden(effect.permission().to_string()))?;

        let imports = self
            .imports_repository
            .list_for_repository(repo_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        let ls_repo = self.log_source_repository.as_ref().ok_or_else(|| {
            ParserRepositoryError::Internal("Log source repository not available".to_string())
        })?;

        let mut removed = 0i32;
        let mut failed = 0i32;

        for import in &imports {
            match ls_repo.delete(import.log_source_id).await {
                Ok(_) => removed += 1,
                Err(e) => {
                    warn!(log_source_id = %import.log_source_id, error = %e, "Failed to delete imported log source");
                    failed += 1;
                }
            }
        }

        Ok((removed, failed))
    }

    // =========================================================================
    // Upstream Changes
    // =========================================================================

    pub async fn get_upstream_updates(
        &self,
        repo_id: Uuid,
    ) -> Result<Vec<super::models::ParserUpstreamUpdate>, ParserRepositoryError> {
        let imports = self
            .imports_repository
            .list_upstream_changed(repo_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        let mut updates = Vec::with_capacity(imports.len());
        for import in imports {
            let parser = self
                .parsers_repository
                .find_by_id(import.repository_parser_id)
                .await
                .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

            updates.push(super::models::ParserUpstreamUpdate {
                log_source_id: import.log_source_id,
                repository_parser_id: import.repository_parser_id,
                file_path: parser
                    .as_ref()
                    .map(|p| p.file_path.clone())
                    .unwrap_or_default(),
                display_name: parser.and_then(|p| p.display_name.or(p.name)),
                version: None, // version from upstream comes via get_upstream_diff
                import_type: import.import_type,
            });
        }
        Ok(updates)
    }

    pub async fn get_upstream_diff(
        &self,
        log_source_id: Uuid,
    ) -> Result<UpstreamParserDiff, ParserRepositoryError> {
        let import = self
            .imports_repository
            .find_by_log_source(log_source_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?
            .ok_or(ParserRepositoryError::ImportNotFound(log_source_id))?;

        let repo_parser = self
            .parsers_repository
            .find_by_id(import.repository_parser_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?
            .ok_or_else(|| {
                ParserRepositoryError::Internal("Repository parser not found".to_string())
            })?;

        // Get current log source VRL
        let ls_repo = self.log_source_repository.as_ref().ok_or_else(|| {
            ParserRepositoryError::Internal("Log source repository not available".to_string())
        })?;

        let log_source = ls_repo
            .find_by_id(log_source_id)
            .await
            .map_err(|e| ParserRepositoryError::LogSourceService(e.to_string()))?;

        // NAN-1151: diff the VRL the flavor actually uses — enrichment parsers
        // carry `normalize_vrl`, log parsers `parser_vrl`.
        let is_enrichment = repo_parser.kind == "enrichment";
        let (upstream_vrl, current_vrl) = if is_enrichment {
            (
                repo_parser.normalize_vrl.clone().unwrap_or_default(),
                log_source.normalize_vrl.clone().unwrap_or_default(),
            )
        } else {
            (
                repo_parser.parser_vrl.clone().unwrap_or_default(),
                log_source.parser_vrl.clone(),
            )
        };
        let has_changes = upstream_vrl != current_vrl;

        Ok(UpstreamParserDiff {
            log_source_id,
            repository_parser_id: repo_parser.id,
            file_path: repo_parser.file_path.clone(),
            upstream_display_name: repo_parser.display_name.clone(),
            upstream_description: repo_parser.description.clone(),
            upstream_version: repo_parser.version.clone(),
            upstream_vrl,
            current_vrl,
            has_changes,
        })
    }

    pub async fn dismiss_upstream_changes(
        &self,
        log_source_id: Uuid,
    ) -> Result<(), ParserRepositoryError> {
        self.imports_repository
            .dismiss_upstream_changes(log_source_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))
    }

    /// Apply upstream parser update to a log source.
    ///
    /// Updates the VRL code + description, re-syncs `match_values` from the
    /// upstream YAML, and clears the `upstream_changed` flag.
    ///
    /// NAN-2120: this is now the ONE authorized path that keeps routing metadata
    /// in step with the parser it deploys. Repository sync used to do it as a
    /// global, principal-free side effect; here it is per-target, operator-
    /// initiated, and gated on the same `parsers:edit` + `log_sources:edit` the
    /// canonical log-source route requires. Unlike the old global fixup it also
    /// PRESERVES the operator's primary alias instead of recomputing it as
    /// `None` — recomputing is what silently orphaned source-config routing
    /// rules that pointed at the previous primary.
    pub async fn apply_upstream_update(
        &self,
        log_source_id: Uuid,
        grants: &TargetGrants,
    ) -> Result<ApplyUpstreamUpdateResult, ParserRepositoryError> {
        for effect in [TargetEffect::ParserEdit, TargetEffect::LogSourceEdit] {
            grants.ensure(effect).map_err(|effect| {
                ParserRepositoryError::Forbidden(effect.permission().to_string())
            })?;
        }

        let ls_repo = self.log_source_repository.as_ref().ok_or_else(|| {
            ParserRepositoryError::Internal("Log source repository not available".to_string())
        })?;

        // Get the import record
        let import = self
            .imports_repository
            .find_by_log_source(log_source_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?
            .ok_or(ParserRepositoryError::ImportNotFound(log_source_id))?;

        // Get the upstream parser
        let repo_parser = self
            .parsers_repository
            .find_by_id(import.repository_parser_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?
            .ok_or_else(|| {
                ParserRepositoryError::Internal("Repository parser not found".to_string())
            })?;

        // NAN-1151: enrichment parsers carry their mapping in `normalize_vrl`,
        // not the log `parser_vrl` — without this branch a linked enrichment
        // parser can never take an upstream update ("Upstream parser has no VRL").
        let is_enrichment = repo_parser.kind == "enrichment";
        let upstream_vrl = if is_enrichment {
            repo_parser.normalize_vrl.clone()
        } else {
            repo_parser.parser_vrl.clone()
        }
        .ok_or_else(|| ParserRepositoryError::Internal("Upstream parser has no VRL".to_string()))?;

        // Get current log source to check deployed state
        let log_source = ls_repo
            .find_by_id(log_source_id)
            .await
            .map_err(|e| ParserRepositoryError::LogSourceService(e.to_string()))?;

        // Update the log source VRL (the field depends on the parser flavor).
        let mut update = UpdateLogSource::default();
        if is_enrichment {
            update.normalize_vrl = Some(upstream_vrl);
        } else {
            update.parser_vrl = Some(upstream_vrl);
        }
        // Also update description if upstream has one
        if let Some(ref desc) = repo_parser.description {
            update.description = Some(desc.clone());
        }

        // NAN-2120: re-sync `match_values` from the upstream YAML here, where
        // `run_sync` used to do it globally and unauthorized. Enrichment parsers
        // route via the enrichment lane, so they carry no match_values.
        if !is_enrichment {
            let parsed_yaml = super::yaml_parser::parse_parser_yaml(&repo_parser.raw_content).ok();
            let yaml_match_values = parsed_yaml
                .as_ref()
                .and_then(|y| y.match_values.clone())
                .unwrap_or_default();
            // The current primary is the alias existing `routing_rules` point
            // at — feed it back in as the override so accepting an upstream
            // update adds new aliases without silently dropping the operator's
            // primary and orphaning its routing rule.
            let existing_primary = log_source
                .match_values
                .as_ref()
                .and_then(|values| values.first().cloned());
            let resolved = Self::resolve_match_values(
                existing_primary.as_deref(),
                &yaml_match_values,
                parsed_yaml.as_ref().map(|y| y.name.as_str()),
            );
            // NAN-2249: union, never narrow. `resolve_match_values` builds a
            // fresh list from the primary plus whatever upstream still lists,
            // so an alias upstream has since dropped would just vanish here.
            // That is a silent routing loss: events tagged with the dropped
            // alias stop matching this parser, fall through to
            // `source_router.generic`, and land raw — no error, and the update
            // reports success. Accepting a new parser version is consent to a
            // better VRL, not to routing less traffic. Pruning stays an
            // explicit edit on the log source.
            let merged = Self::union_match_values(
                log_source.match_values.as_deref().unwrap_or(&[]),
                &resolved,
            );
            if !merged.is_empty() && log_source.match_values.as_ref() != Some(&merged) {
                update.match_values = Some(merged);
            }
        }

        ls_repo
            .update(log_source_id, &update)
            .await
            .map_err(|e| ParserRepositoryError::LogSourceService(e.to_string()))?;

        // Clear upstream_changed flag
        self.imports_repository
            .dismiss_upstream_changes(log_source_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        info!(
            "Applied upstream update for log source '{}' from {}",
            log_source.name, repo_parser.file_path
        );

        Ok(ApplyUpstreamUpdateResult {
            log_source_id,
            updated: true,
            needs_deploy: log_source.deployed,
            message: format!("Updated '{}' parser VRL from upstream", log_source.name),
        })
    }

    /// Apply all pending upstream updates for a repository.
    ///
    /// NAN-2120: same composite capability policy as the single-target variant,
    /// enforced up front so a denied caller never starts the loop.
    pub async fn apply_all_upstream_updates(
        &self,
        repo_id: Uuid,
        grants: &TargetGrants,
    ) -> Result<BulkApplyUpstreamResult, ParserRepositoryError> {
        for effect in [TargetEffect::ParserEdit, TargetEffect::LogSourceEdit] {
            grants.ensure(effect).map_err(|effect| {
                ParserRepositoryError::Forbidden(effect.permission().to_string())
            })?;
        }

        let updates = self.get_upstream_updates(repo_id).await?;

        let mut results = Vec::new();
        let mut updated = 0u32;
        let mut failed = 0u32;

        for update in updates {
            match self
                .apply_upstream_update(update.log_source_id, grants)
                .await
            {
                Ok(result) => {
                    updated += 1;
                    results.push(result);
                }
                Err(e) => {
                    failed += 1;
                    warn!(
                        "Failed to apply upstream update for log source {}: {}",
                        update.log_source_id, e
                    );
                    results.push(ApplyUpstreamUpdateResult {
                        log_source_id: update.log_source_id,
                        updated: false,
                        needs_deploy: false,
                        message: format!("Failed: {}", e),
                    });
                }
            }
        }

        Ok(BulkApplyUpstreamResult {
            updated,
            failed,
            results,
        })
    }

    // =========================================================================
    // Imports lookup
    // =========================================================================

    pub async fn get_imports_for_repository(
        &self,
        repo_id: Uuid,
    ) -> Result<Vec<ParserImport>, ParserRepositoryError> {
        self.imports_repository
            .list_for_repository(repo_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))
    }

    // =========================================================================
    // Match values fixup
    // =========================================================================

    /// Re-sync match_values from upstream YAML for the log sources imported from
    /// ONE repository. Fixes log sources imported before match_values threading
    /// was added.
    ///
    /// NAN-2120: this is a **live parser-routing mutation**, not a catalog
    /// operation — it rewrites `log_sources.match_values`, which decides which
    /// upstream source-type aliases activate a parser. Three things changed:
    ///
    /// * it requires the canonical parser AND log-source edit capabilities in
    ///   addition to whatever repository permission got the caller here;
    /// * it is scoped to `repo_id` instead of every import in the tenant; and
    /// * it is no longer invoked as an automatic side effect of repository sync
    ///   — `run_sync` marks linked imports `upstream_changed` and the operator
    ///   applies the change explicitly.
    ///
    /// Returns the IDs of the log sources that were ACTUALLY rewritten, so the
    /// caller can emit one per-target audit record naming each changed object
    /// rather than a single opaque repository-level count.
    pub async fn fixup_imported_match_values(
        &self,
        repo_id: Uuid,
        grants: &TargetGrants,
    ) -> Result<Vec<Uuid>, ParserRepositoryError> {
        for effect in [TargetEffect::ParserEdit, TargetEffect::LogSourceEdit] {
            grants.ensure(effect).map_err(|effect| {
                ParserRepositoryError::Forbidden(effect.permission().to_string())
            })?;
        }

        let ls_repo = self.log_source_repository.as_ref().ok_or_else(|| {
            ParserRepositoryError::Internal("Log source repository not available".to_string())
        })?;

        let rows = self
            .imports_repository
            .list_with_raw_content(repo_id)
            .await
            .map_err(|e| ParserRepositoryError::Internal(e.to_string()))?;

        let mut updated: Vec<Uuid> = Vec::new();
        for (log_source_id, raw_content) in &rows {
            let parsed = match super::yaml_parser::parse_parser_yaml(raw_content) {
                Ok(p) => p,
                Err(_) => continue,
            };
            // Use the same union logic as import_parser so periodic sync
            // doesn't clobber the parser's canonical name from match_values.
            // We don't track the original UI-provided source_type override
            // across syncs, so we pass None — the parser's name (from the
            // YAML's `name:` field) is what we anchor on. NAN-920.
            let yaml_match_values = parsed.match_values.clone().unwrap_or_default();
            let resolved =
                Self::resolve_match_values(None, &yaml_match_values, Some(parsed.name.as_str()));
            if resolved.is_empty() {
                continue;
            }

            let update = crate::log_sources::UpdateLogSource {
                match_values: Some(resolved),
                ..Default::default()
            };
            if let Err(e) = ls_repo.update(*log_source_id, &update).await {
                warn!(
                    "Failed to fixup match_values for log source {}: {}",
                    log_source_id, e
                );
                continue;
            }
            updated.push(*log_source_id);
        }

        if !updated.is_empty() {
            info!(
                repo_id = %repo_id,
                updated = updated.len(),
                "Fixed match_values for imported log sources"
            );
        }
        Ok(updated)
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /// NAN-1149: gate an enrichment-flavor import. The Vector lane is
    /// generated from `normalize_vrl` (the mapping) into the sink for
    /// `target_table`; an enrichment parser missing either would deploy as an
    /// empty transform that writes nothing — a silent no-op. Reject it here so
    /// the failure surfaces at import time, not as missing enrichment data
    /// later. (NAN-1150 adds the deeper VRL-compile check at deploy time.)
    pub(super) fn validate_enrichment_import(
        parser: &RepositoryParser,
        path: &str,
    ) -> Result<(), ParserRepositoryError> {
        if parser
            .normalize_vrl
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            return Err(ParserRepositoryError::InvalidRequest(format!(
                "enrichment parser '{path}' has no normalize_vrl; nothing to deploy",
            )));
        }
        if parser
            .target_table
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            return Err(ParserRepositoryError::InvalidRequest(format!(
                "enrichment parser '{path}' has no target_table; cannot route its writes",
            )));
        }
        Ok(())
    }

    /// NAN-920: build the `match_values` list for an imported / re-synced
    /// log source. We union three sources, dedup-preserving order:
    ///
    /// 1. UI override (`req.source_type`) — when present, lands first so
    ///    the parser's canonical identifier is the primary entry.
    /// 2. YAML's `match_values` — legacy aliases that drive OOTB routing
    ///    rule targets (e.g. apache_http_server's YAML declares
    ///    `[apache, apache_access, apache_error]`; without these, HEC's
    ///    seeded rules with target `apache` would render as orphans).
    /// 3. Parser name fallback — last-resort identifier when neither of
    ///    the above produced any entries.
    ///
    /// Falls back to `["unknown"]` if all sources are empty (e.g. a
    /// minimal parser YAML with no name and no UI input).
    pub(super) fn resolve_match_values(
        ui_source_type: Option<&str>,
        yaml_match_values: &[String],
        parser_name: Option<&str>,
    ) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        // NAN-945: silently drop values that don't pass the source_type
        // allow-list. Match values flow into the `_unclaimed` router
        // substitution (router.rs:129+), the routing-rule orphan check,
        // and per-parser HEC filters via `escape_vrl_string` (sources.rs:440).
        // VRL escape blocks immediate injection at emit, but allow-listing
        // at resolve-time stops unsafe values from reaching any of those
        // downstream surfaces in the first place. Mirrors
        // `validate_routing_rule_values` in source_configs/service.rs.
        let push = |out: &mut Vec<String>,
                    seen: &mut std::collections::HashSet<String>,
                    value: &str,
                    source_label: &str| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return;
            }
            if !is_safe_source_type(trimmed) {
                tracing::warn!(
                    source = source_label,
                    value = trimmed,
                    "resolve_match_values: dropping unsafe match_value (must be alphanumeric + `_` or `-`)",
                );
                return;
            }
            if seen.insert(trimmed.to_string()) {
                out.push(trimmed.to_string());
            }
        };

        if let Some(st) = ui_source_type {
            push(&mut out, &mut seen, st, "ui_source_type");
        }
        for alias in yaml_match_values {
            push(&mut out, &mut seen, alias, "yaml_match_value");
        }
        if out.is_empty() {
            if let Some(n) = parser_name {
                push(&mut out, &mut seen, n, "parser_name");
            }
        }
        if out.is_empty() {
            out.push("unknown".to_string());
        }
        out
    }

    /// NAN-2249: merge an upstream-resolved match_value list into what a log
    /// source already routes on, keeping every existing value.
    ///
    /// `resolved` leads so its first element stays the primary — routing rules
    /// point at that, and reordering would orphan them. Existing values upstream
    /// no longer lists follow in their original relative order rather than being
    /// dropped.
    ///
    /// Deliberately does NOT drop existing values that fail
    /// `is_safe_source_type`: they are already persisted and already routing
    /// traffic, and discarding one here because it fails a validator added
    /// after it was stored would be the exact silent narrowing this function
    /// exists to prevent. New values arrive via `resolved`, which is
    /// allow-listed at resolve time.
    ///
    /// It does warn on them. Before this function, rebuilding the list from
    /// `resolved` incidentally sanitized such a value away on the next update;
    /// keeping it means that no longer happens, so the value has to become
    /// visible some other way or it simply persists unnoticed. Values reaching
    /// the router and per-parser filters are escaped at emit
    /// (`escape_vrl_string_for_router`), so this is defence in depth, not a
    /// live hole.
    /// NAN-2256: make sure a log source routes the given `source_type`, adding
    /// it if absent. Returns whether anything changed.
    ///
    /// Collector streams share one log source: the first to provision creates
    /// it, the rest link to the existing one. Only the creating stream's
    /// `source_type` ever reached `match_values`, so every later stream's
    /// events matched nothing and landed unparsed — silently, since the streams
    /// still report as linked. It went unnoticed because the community parsers
    /// happen to enumerate one alias per stream, which `resolve_match_values`
    /// folded in as a side effect. Coverage belongs to the manifest that
    /// declares the streams, not to a parsers-repo alias list nobody links to
    /// it (the NAN-2248 argument, applied to the second job those aliases were
    /// quietly doing).
    ///
    /// Additive only, per NAN-2249 — a stream is never a reason to stop routing
    /// something. `LogSourceEdit` is demanded only when a write is actually
    /// needed, so a correctly-covered log source costs the caller no permission.
    pub async fn ensure_log_source_claims_source_type(
        &self,
        log_source_id: Uuid,
        source_type: &str,
        grants: &TargetGrants,
    ) -> Result<bool, ParserRepositoryError> {
        let ls_repo = self.log_source_repository.as_ref().ok_or_else(|| {
            ParserRepositoryError::Internal("Log source repository not available".to_string())
        })?;

        let log_source = ls_repo
            .find_by_id(log_source_id)
            .await
            .map_err(|e| ParserRepositoryError::LogSourceService(e.to_string()))?;

        let existing = log_source.match_values.clone().unwrap_or_default();
        if existing.iter().any(|v| v == source_type) {
            return Ok(false);
        }

        grants
            .ensure(TargetEffect::LogSourceEdit)
            .map_err(|effect| ParserRepositoryError::Forbidden(effect.permission().to_string()))?;

        // `add_match_value`, not a read-modify-write through `update`: two
        // callers provisioning streams onto the same log source would otherwise
        // interleave and lose one of the additions. It appends (never
        // reorders), so the operator's primary keeps its place — routing rules
        // point at `match_values.first()`.
        //
        // The read above is only to decide whether a grant is owed. The append
        // re-checks under the row lock, so a value another caller added between
        // the two is a no-op here rather than a duplicate.
        ls_repo
            .add_match_value(log_source_id, source_type)
            .await
            .map_err(|e| ParserRepositoryError::LogSourceService(e.to_string()))
    }

    pub(super) fn union_match_values(existing: &[String], resolved: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::with_capacity(existing.len() + resolved.len());
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for value in resolved.iter().chain(existing.iter()) {
            if seen.insert(value.as_str()) {
                if !crate::log_telemetry::repository::is_safe_source_type(value) {
                    tracing::warn!(
                        match_value = %value,
                        "union_match_values: keeping a stored match_value that fails the \
                         source_type allow-list — it is already routing traffic, so it is not \
                         dropped here, but it should be pruned from the log source",
                    );
                }
                out.push(value.clone());
            }
        }
        out
    }

    // =========================================================================
    // Air-gapped Bundle Sync (NAN-1226)
    // =========================================================================

    /// Sync parser definitions delivered via an offline (air-gapped) bundle
    /// into the synthetic air-gap parser repository's catalog (NAN-1226).
    ///
    /// The caller (the API handler) is responsible for verifying the bundle
    /// signature + checksums (`nanosiem_core::airgap::verify_bundle`) and
    /// extracting the parser YAML payloads; this method takes the already-
    /// verified `(file_path, raw_yaml)` pairs and upserts each into
    /// `repository_parsers` — the *exact same* catalog upsert performed by
    /// `run_sync` for GitHub-synced repos. This is the offline equivalent of a
    /// repo *sync*: the parsers land as available-to-import (a
    /// `repository_parsers` row with no `parser_imports` row / log source), and
    /// the operator selectively imports + deploys them from the repositories
    /// page afterward.
    ///
    /// Nothing is imported or deployed here — no log source is created and
    /// Vector is never touched. The bundle's parsers are upserted into a
    /// synthetic, always-present air-gap parser repository (created on first
    /// use via the `AIRGAP_REPOSITORY_SLUG`). Returns the number of parsers
    /// synced (successfully upserted) into the catalog.
    pub async fn sync_parser_bundle(
        &self,
        content_version: &str,
        parsers: &[(String, String)],
        user_id: Option<Uuid>,
    ) -> Result<BundleImportResult, ParserRepositoryError> {
        let repo = self.find_or_create_airgap_repository(user_id).await?;

        let mut synced = 0usize;

        for (path, raw_content) in parsers {
            // Parse + upsert the parser definition into repository_parsers so
            // it shows up as available-to-import on the repositories page.
            // Mirrors the GitHub sync upsert in `run_sync`.
            let parsed = match parse_parser_yaml(raw_content) {
                Ok(p) => p,
                Err(e) => {
                    warn!(repo_id = %repo.id, path = %path, error = %e, "Invalid parser.yaml in air-gap bundle; skipping");
                    continue;
                }
            };

            // NAN-1149: honor an explicit `kind: enrichment`; air-gap bundles
            // carry the kind in the YAML (no enrichments/ path convention).
            let kind = parsed.kind.as_deref().unwrap_or("parser");

            if let Err(e) = self
                .parsers_repository
                .upsert(
                    repo.id,
                    path,
                    None,
                    raw_content,
                    Some(&parsed.name),
                    parsed.display_name.as_deref(),
                    parsed.description.as_deref(),
                    parsed.version.as_deref(),
                    parsed.category.as_deref(),
                    parsed.vendor.as_deref(),
                    parsed.product.as_deref(),
                    parsed.parser_vrl.as_deref(),
                    kind,
                    parsed.enrich_kind.as_deref(),
                    parsed.enrich_source.as_deref(),
                    parsed.target_table.as_deref(),
                    parsed.normalize_vrl.as_deref(),
                )
                .await
            {
                warn!(repo_id = %repo.id, path = %path, error = %e, "Failed to upsert air-gap parser into catalog");
                continue;
            }

            synced += 1;
        }

        info!(
            repo_id = %repo.id,
            content_version = %content_version,
            synced,
            "Air-gapped parser bundle synced into catalog"
        );

        Ok(BundleImportResult {
            repository_id: repo.id,
            content_version: content_version.to_string(),
            synced,
        })
    }

    /// Find (or lazily create) the synthetic repository that air-gapped
    /// parser bundles are imported into. It is a normal `parser_repositories`
    /// row (so it shows up in the parser-repo browser) but with auto-sync
    /// disabled and a non-GitHub sentinel URL — it's never synced over the
    /// network. Bypasses `create_repository`'s GitHub URL allowlist on
    /// purpose by going straight through the repository layer.
    async fn find_or_create_airgap_repository(
        &self,
        user_id: Option<Uuid>,
    ) -> Result<ParserRepository, ParserRepositoryError> {
        if let Ok(existing) = self
            .repo_repository
            .find_by_slug(AIRGAP_REPOSITORY_SLUG)
            .await
        {
            return Ok(existing);
        }

        let new_repo = NewParserRepository {
            name: AIRGAP_REPOSITORY_NAME.to_string(),
            slug: Some(AIRGAP_REPOSITORY_SLUG.to_string()),
            description: Some(
                "Parsers imported from offline air-gapped bundles (NAN-1201).".to_string(),
            ),
            // Sentinel, never-fetched URL — air-gap bundles are uploaded, not synced.
            url: "airgap://parsers".to_string(),
            branch: None,
            parsers_path: None,
            auto_sync_enabled: Some(false),
            sync_interval_hours: None,
        };

        match self.repo_repository.create(&new_repo, user_id).await {
            Ok(repo) => Ok(repo),
            // Lost a create race with a concurrent bundle upload — re-fetch.
            Err(super::repository::ParserRepositoryRepositoryError::AlreadyExists(_)) => self
                .repo_repository
                .find_by_slug(AIRGAP_REPOSITORY_SLUG)
                .await
                .map_err(|e| ParserRepositoryError::Internal(e.to_string())),
            Err(e) => Err(ParserRepositoryError::Internal(e.to_string())),
        }
    }

    fn validate_url(&self, url: &str) -> Result<(), ParserRepositoryError> {
        let normalized = url
            .trim_end_matches('/')
            .trim_end_matches(".git")
            .to_lowercase();

        let is_allowed = ALLOWED_REPOSITORIES.iter().any(|allowed| {
            let suffix = format!("github.com/{}", allowed);
            normalized == format!("https://{}", suffix)
                || normalized == format!("http://{}", suffix)
        });

        if !is_allowed {
            return Err(ParserRepositoryError::RepositoryNotAllowed(url.to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-920: a UI source_type override (e.g. parser name) plus YAML
    /// match_values aliases unions cleanly with the override first and
    /// no duplicates.
    #[test]
    fn resolve_match_values_unions_ui_override_and_yaml_aliases() {
        let result = ParserRepositoryService::resolve_match_values(
            Some("apache_http_server"),
            &[
                "apache".into(),
                "apache_access".into(),
                "apache_error".into(),
            ],
            Some("apache_http_server"),
        );
        assert_eq!(
            result,
            vec![
                "apache_http_server".to_string(),
                "apache".to_string(),
                "apache_access".to_string(),
                "apache_error".to_string(),
            ]
        );
    }

    /// Dedups when the UI override appears in YAML match_values too —
    /// preserves first-occurrence ordering.
    #[test]
    fn resolve_match_values_dedups_when_override_is_in_yaml() {
        let result = ParserRepositoryService::resolve_match_values(
            Some("apache"),
            &["apache".into(), "apache_access".into()],
            Some("apache"),
        );
        assert_eq!(
            result,
            vec!["apache".to_string(), "apache_access".to_string()]
        );
    }

    /// Fixup path: no UI override (None), parser name + YAML aliases.
    #[test]
    fn resolve_match_values_fixup_path_includes_parser_name_if_no_yaml_match() {
        let result =
            ParserRepositoryService::resolve_match_values(None, &[], Some("custom_parser"));
        assert_eq!(result, vec!["custom_parser".to_string()]);
    }

    /// Fixup path with YAML aliases that already include the parser name —
    /// doesn't duplicate.
    #[test]
    fn resolve_match_values_fixup_path_with_yaml_aliases() {
        let result = ParserRepositoryService::resolve_match_values(
            None,
            &["apache_http_server".into(), "apache".into()],
            Some("apache_http_server"),
        );
        assert_eq!(
            result,
            vec!["apache_http_server".to_string(), "apache".to_string()]
        );
    }

    /// Empty / whitespace-only entries are skipped, never end up in the
    /// list. Guards against bad YAML.
    #[test]
    fn resolve_match_values_skips_empty_and_whitespace_entries() {
        let result = ParserRepositoryService::resolve_match_values(
            Some(""),
            &["".into(), "   ".into(), "apache".into()],
            Some(""),
        );
        assert_eq!(result, vec!["apache".to_string()]);
    }

    /// Last-resort fallback when literally everything is empty: ["unknown"].
    #[test]
    fn resolve_match_values_falls_back_to_unknown() {
        let result = ParserRepositoryService::resolve_match_values(None, &[], None);
        assert_eq!(result, vec!["unknown".to_string()]);
    }

    // ----------------------------------------------------------------------
    // NAN-943: dispatch compatibility matrix.
    // ----------------------------------------------------------------------

    #[test]
    fn is_dispatch_compatible_accepts_canonical_pair_for_each_pull_source() {
        assert!(ParserRepositoryService::is_dispatch_compatible(
            "kafka", "kafka"
        ));
        assert!(ParserRepositoryService::is_dispatch_compatible(
            "aws_s3", "aws_s3"
        ));
        assert!(ParserRepositoryService::is_dispatch_compatible(
            "gcp_pubsub",
            "gcp_pubsub"
        ));
        assert!(ParserRepositoryService::is_dispatch_compatible(
            "splunk_hec",
            "splunk_hec"
        ));
    }

    #[test]
    fn is_dispatch_compatible_accepts_always_on_sources() {
        // http maps to ingestion_method "routed" (matches SOURCE_TYPE_MAP).
        assert!(ParserRepositoryService::is_dispatch_compatible(
            "http", "routed"
        ));
        // vector is identity.
        assert!(ParserRepositoryService::is_dispatch_compatible(
            "vector", "vector"
        ));
    }

    #[test]
    fn is_dispatch_compatible_normalizes_legacy_short_forms() {
        // Stored canonical form is "aws_s3"/"gcp_pubsub"/"splunk_hec"; legacy
        // ingest paths used "s3"/"pubsub"/"splunk"/"hec". from_str on
        // SourceConfigType accepts both; the dispatch check must too.
        assert!(ParserRepositoryService::is_dispatch_compatible(
            "s3", "aws_s3"
        ));
        assert!(ParserRepositoryService::is_dispatch_compatible(
            "pubsub",
            "gcp_pubsub"
        ));
        assert!(ParserRepositoryService::is_dispatch_compatible(
            "splunk",
            "splunk_hec"
        ));
        assert!(ParserRepositoryService::is_dispatch_compatible(
            "hec",
            "splunk_hec"
        ));
    }

    #[test]
    fn is_dispatch_compatible_rejects_kafka_parser_against_s3_dispatch() {
        // The exact silent-failure mode NAN-928 set out to eliminate —
        // FK passes, parser filters on `<s3_config>_route`, receives zero
        // events. The reverse must also reject.
        assert!(!ParserRepositoryService::is_dispatch_compatible(
            "aws_s3", "kafka"
        ));
        assert!(!ParserRepositoryService::is_dispatch_compatible(
            "kafka", "aws_s3"
        ));
    }

    #[test]
    fn is_dispatch_compatible_rejects_all_cross_pairs() {
        let drivers = [
            "kafka",
            "aws_s3",
            "gcp_pubsub",
            "splunk_hec",
            "http",
            "vector",
        ];
        let methods = [
            "kafka",
            "aws_s3",
            "gcp_pubsub",
            "splunk_hec",
            "routed",
            "vector",
        ];
        for ct in &drivers {
            for im in &methods {
                let expected_ok = matches!(
                    (*ct, *im),
                    ("kafka", "kafka")
                        | ("aws_s3", "aws_s3")
                        | ("gcp_pubsub", "gcp_pubsub")
                        | ("splunk_hec", "splunk_hec")
                        | ("http", "routed")
                        | ("vector", "vector")
                );
                assert_eq!(
                    ParserRepositoryService::is_dispatch_compatible(ct, im),
                    expected_ok,
                    "compat({ct}, {im}) returned the wrong answer",
                );
            }
        }
    }

    #[test]
    fn is_dispatch_compatible_rejects_unknown_config_type() {
        // A future / typo'd config_type should fail closed.
        assert!(!ParserRepositoryService::is_dispatch_compatible(
            "rabbitmq", "kafka"
        ));
        assert!(!ParserRepositoryService::is_dispatch_compatible("", ""));
    }

    // ----------------------------------------------------------------------
    // NAN-945: allow-list match_values. The function silently drops any
    // value that fails `is_safe_source_type` (must be non-empty + alphanumeric
    // / `_` / `-`). Existing imports are alphanumeric+_- already, so this
    // is defense-in-depth — but the dropped values must not leak into the
    // downstream `_unclaimed` substitution or VRL filter conditions.
    // ----------------------------------------------------------------------

    #[test]
    fn resolve_match_values_drops_unsafe_quote_in_yaml_alias() {
        let result = ParserRepositoryService::resolve_match_values(
            Some("apache"),
            &[
                "apache_access".into(),
                // VRL injection attempt — quotes + semicolons.
                "evil\"; .source_type = \"x".into(),
                "apache_error".into(),
            ],
            None,
        );
        // Safe values preserved in order, unsafe one dropped silently.
        assert_eq!(
            result,
            vec![
                "apache".to_string(),
                "apache_access".to_string(),
                "apache_error".to_string()
            ],
        );
    }

    #[test]
    fn resolve_match_values_drops_unsafe_dot_and_space_and_newline() {
        let result = ParserRepositoryService::resolve_match_values(
            Some("good_one"),
            &[
                "dot.in.name".into(),
                "space in name".into(),
                "newline\nin\nname".into(),
                "valid-with-dash".into(),
            ],
            None,
        );
        assert_eq!(
            result,
            vec!["good_one".to_string(), "valid-with-dash".to_string()],
        );
    }

    #[test]
    fn resolve_match_values_drops_unsafe_ui_source_type_then_falls_back() {
        // If the only candidates are unsafe, fall through to parser_name.
        let result = ParserRepositoryService::resolve_match_values(
            Some("ui_evil\""),
            &["yaml.dot".into()],
            Some("parser_name_ok"),
        );
        assert_eq!(result, vec!["parser_name_ok".to_string()]);
    }

    #[test]
    fn resolve_match_values_drops_unsafe_parser_name_too_and_uses_unknown() {
        // If even the parser_name fallback fails the allow-list, we land
        // on the "unknown" sentinel rather than persisting unsafe input.
        let result =
            ParserRepositoryService::resolve_match_values(None, &[], Some("bad parser name"));
        assert_eq!(result, vec!["unknown".to_string()]);
    }

    #[test]
    fn resolve_match_values_preserves_dash_and_underscore() {
        // Sanity: the allow-list must not over-fire on legitimate names.
        let result = ParserRepositoryService::resolve_match_values(
            Some("apache_http_server"),
            &[
                "ms-windows-sysmon".into(),
                "cisco_asa".into(),
                "fortinet-fortigate".into(),
            ],
            None,
        );
        assert_eq!(
            result,
            vec![
                "apache_http_server".to_string(),
                "ms-windows-sysmon".to_string(),
                "cisco_asa".to_string(),
                "fortinet-fortigate".to_string(),
            ],
        );
    }

    // ---- NAN-1149: enrichment import gate -----------------------------------

    fn enrichment_repo_parser(
        normalize_vrl: Option<&str>,
        target_table: Option<&str>,
    ) -> RepositoryParser {
        let now = chrono::Utc::now();
        RepositoryParser {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            file_path: "enrichments/identity/ad/parser.yaml".to_string(),
            file_sha: None,
            raw_content: String::new(),
            name: Some("ad_identity".to_string()),
            display_name: None,
            description: None,
            version: None,
            category: None,
            vendor: None,
            product: None,
            parser_vrl: None,
            kind: "enrichment".to_string(),
            enrich_kind: Some("identity".to_string()),
            enrich_source: Some("ad".to_string()),
            target_table: target_table.map(str::to_string),
            normalize_vrl: normalize_vrl.map(str::to_string),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn validate_enrichment_import_accepts_complete_parser() {
        let parser = enrichment_repo_parser(Some(".user = .external_id"), Some("user_registry"));
        assert!(
            ParserRepositoryService::validate_enrichment_import(&parser, &parser.file_path).is_ok()
        );
    }

    #[test]
    fn validate_enrichment_import_rejects_missing_normalize_vrl() {
        // None and whitespace-only both count as "no mapping".
        for vrl in [None, Some("   \n  ")] {
            let parser = enrichment_repo_parser(vrl, Some("user_registry"));
            let err =
                ParserRepositoryService::validate_enrichment_import(&parser, &parser.file_path)
                    .unwrap_err();
            assert!(
                matches!(err, ParserRepositoryError::InvalidRequest(ref m) if m.contains("normalize_vrl")),
                "expected normalize_vrl rejection, got {err:?}"
            );
        }
    }

    #[test]
    fn validate_enrichment_import_rejects_missing_target_table() {
        let parser = enrichment_repo_parser(Some(".user = .external_id"), None);
        let err = ParserRepositoryService::validate_enrichment_import(&parser, &parser.file_path)
            .unwrap_err();
        assert!(
            matches!(err, ParserRepositoryError::InvalidRequest(ref m) if m.contains("target_table")),
            "expected target_table rejection, got {err:?}"
        );
    }

    // =====================================================================
    // NAN-2249: accepting an update must never narrow match_values
    // =====================================================================

    /// The NAN-2246 case: upstream collapsed to one canonical value. The
    /// operator's aliases — which their forwarders are actively tagging with —
    /// must survive. Dropping them stops routing silently.
    #[test]
    fn union_keeps_aliases_upstream_has_dropped() {
        let existing = vec![
            "apache_access".to_string(),
            "apache".to_string(),
            "apache_error".to_string(),
        ];
        let resolved = vec!["apache_access".to_string()];

        let merged = ParserRepositoryService::union_match_values(&existing, &resolved);

        assert_eq!(
            merged,
            vec!["apache_access", "apache", "apache_error"],
            "an update that narrows upstream must not narrow the log source"
        );
    }

    /// Widening still works — that is the whole point of re-syncing.
    #[test]
    fn union_applies_values_upstream_added() {
        let existing = vec!["fortinet".to_string()];
        let resolved = vec!["fortinet".to_string(), "fortigate".to_string()];

        let merged = ParserRepositoryService::union_match_values(&existing, &resolved);

        assert_eq!(merged, vec!["fortinet", "fortigate"]);
    }

    /// `resolved` leads, so its first element stays the primary. Routing rules
    /// point at the primary; reordering it would orphan them.
    #[test]
    fn union_keeps_resolved_primary_first() {
        let existing = vec!["cloudtrail".to_string(), "aws_ct".to_string()];
        // resolve_match_values feeds the existing primary back in first.
        let resolved = vec!["cloudtrail".to_string(), "aws_cloudtrail".to_string()];

        let merged = ParserRepositoryService::union_match_values(&existing, &resolved);

        assert_eq!(merged[0], "cloudtrail", "primary must not move");
        assert!(merged.contains(&"aws_ct".to_string()), "alias must survive");
        assert!(merged.contains(&"aws_cloudtrail".to_string()), "new value applied");
    }

    /// No duplicates when the two lists overlap.
    #[test]
    fn union_dedupes() {
        let existing = vec!["okta".to_string(), "okta_system".to_string()];
        let resolved = vec!["okta".to_string()];

        let merged = ParserRepositoryService::union_match_values(&existing, &resolved);

        assert_eq!(merged, vec!["okta", "okta_system"]);
    }

    /// A fresh import has nothing to merge with — the canonical single value
    /// passes through unchanged, so new installs get the clean model.
    #[test]
    fn union_on_empty_existing_is_just_resolved() {
        let merged =
            ParserRepositoryService::union_match_values(&[], &["windows_sysmon".to_string()]);
        assert_eq!(merged, vec!["windows_sysmon"]);
    }

    /// An existing value that would fail today's `is_safe_source_type` is still
    /// kept. It is already persisted and already routing; dropping it here
    /// would be the silent narrowing this guard exists to prevent.
    #[test]
    fn union_does_not_revalidate_already_persisted_values() {
        let existing = vec!["legacy value with spaces".to_string()];
        let resolved = vec!["clean_value".to_string()];

        let merged = ParserRepositoryService::union_match_values(&existing, &resolved);

        assert_eq!(merged, vec!["clean_value", "legacy value with spaces"]);
    }
}
