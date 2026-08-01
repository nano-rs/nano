// SPDX-License-Identifier: AGPL-3.0-or-later

//! Import repository playbooks into the main `playbooks` table.

use tracing::info;
use uuid::Uuid;

use crate::auth::{TargetEffect, TargetGrants};
use crate::hunts::{HuntRepository, HuntSpecDraft};
use crate::playbooks::models::{
    CreatePlaybookRequest, PlaybookCategory, PlaybookKind, PlaybookScope, PlaybookStatus,
};
use crate::playbooks::{parse_playbook, split_frontmatter, PlaybookService};

use super::super::error::PlaybookRepositoryError;
use super::super::models::{
    PlaybookImportRequest, PlaybookImportResponse, PlaybookImportType, RepositoryPlaybook,
};
use super::sync::repo_accepts_kind;
use super::PlaybookRepositoryService;

impl PlaybookRepositoryService {
    /// Import a repository playbook into the main library.
    ///
    /// NAN-2119: this materializes a **first-class tenant playbook** — a
    /// `playbooks` row, its initial `playbook_versions` row, and an import
    /// provenance record — exactly what `POST /api/playbooks` creates behind
    /// `playbooks:manage`. `playbook_repositories:import` authorizes reading the
    /// catalog and must never substitute for the target capability, so `grants`
    /// is re-checked HERE, at the branch that actually writes, rather than only
    /// in the handler preflight (the handler's plan can be stale by the time a
    /// bulk loop reaches this row).
    ///
    /// NAN-2238: the same endpoint now materializes one of TWO things, and
    /// which one is decided by the file's own frontmatter. A hunt takes the
    /// hunt branch — `hunts:manage`, a `kind = 'hunt'` row, a `hunt_specs`
    /// extension, no version row — and lands **disabled**.
    pub async fn import_playbook(
        &self,
        repo_id: Uuid,
        path: &str,
        req: PlaybookImportRequest,
        user_id: Option<Uuid>,
        grants: &TargetGrants,
    ) -> Result<PlaybookImportResponse, PlaybookRepositoryError> {
        let repo = self.get_repository(repo_id).await?;
        let repo_playbook = self.get_repository_playbook(repo_id, path).await?;

        // Re-read the kind from the file's own content rather than trusting
        // `repository_playbooks.kind`, which is a browse cache written at sync
        // time. The write path decides from the source of truth: a cache row
        // that drifted — or was edited — must not be able to send a document
        // down the hunt branch, or a hunt down the document branch.
        //
        // And never from the path. `playbooks_path` is operator-configurable,
        // so `hunts/x.md` is a fact about configuration, not about the file.
        let (fm, body) = split_frontmatter(&repo_playbook.raw_content)
            .map_err(|e| PlaybookRepositoryError::Parse(e.to_string()))?;
        let kind = fm.as_ref().map(|f| f.kind).unwrap_or(PlaybookKind::Response);

        if !repo_accepts_kind(&repo, kind.as_str()) {
            return Err(PlaybookRepositoryError::KindNotAllowed {
                kind: kind.as_str().to_string(),
                allowed: repo.allowed_kinds.join(", "),
            });
        }

        // The capability the CANONICAL route for this resource enforces, chosen
        // by what is about to be created. Authoring a hunt is `hunts:manage`;
        // it is not something `playbooks:manage` should reach, and vice versa.
        grants.ensure(Self::effect_for_kind(kind)).map_err(|e| {
            PlaybookRepositoryError::Forbidden(format!("Missing permission: {}", e.permission()))
        })?;

        // Check if already imported
        let existing = self
            .imports_repository
            .find_by_repository_playbook(repo_playbook.id)
            .await
            .map_err(PlaybookRepositoryError::from_repo_error)?;
        if !existing.is_empty() {
            return Err(PlaybookRepositoryError::AlreadyImported {
                import_type: existing[0].import_type.clone(),
            });
        }

        let create = Self::build_create_request(&repo_playbook, path, repo_id, &req);

        let playbook_id = match kind {
            PlaybookKind::Response => {
                let service = PlaybookService::new(self.pg_pool.clone());
                service
                    .create(create, user_id)
                    .await
                    .map_err(|e| PlaybookRepositoryError::Internal(e.to_string()))?
                    .id
            }
            PlaybookKind::Hunt => {
                // Everything the hunt file was allowed to decide. `enabled` is
                // not on that list and has no field to travel in — see
                // `crate::hunts::spec`.
                let draft = HuntSpecDraft::from_frontmatter(fm.as_ref(), &parse_playbook(body))
                    .map_err(|e| PlaybookRepositoryError::HuntSpec(e.to_string()))?;
                let parsed_steps = crate::playbooks::service::parse_and_serialize(&create.doc);
                HuntRepository::new(self.pg_pool.clone())
                    .create_from_import(&create, parsed_steps.as_ref(), &draft, user_id)
                    .await
                    .map_err(|e| PlaybookRepositoryError::Internal(e.to_string()))?
                    .id
            }
        };

        // Record the import
        self.imports_repository
            .create(
                repo_playbook.id,
                playbook_id,
                &req.import_type.to_string(),
                user_id,
                repo.last_sync_commit.as_deref(),
            )
            .await
            .map_err(|e| match e {
                super::super::repository::PlaybookImportsRepositoryError::AlreadyExists => {
                    PlaybookRepositoryError::AlreadyImported {
                        import_type: req.import_type.to_string(),
                    }
                }
                other => PlaybookRepositoryError::from_repo_error(other),
            })?;

        info!(
            "Imported {} {} from {}/{} as {}",
            kind.as_str(),
            playbook_id,
            repo.name,
            path,
            req.import_type
        );

        Ok(PlaybookImportResponse {
            playbook_id,
            import_type: req.import_type.to_string(),
            kind: kind.as_str().to_string(),
        })
    }

    /// The target-resource capability importing `path` will consume.
    ///
    /// Handlers preflight this before any write; [`Self::import_playbook`]
    /// re-checks the same effect at the branch that writes, from the file's
    /// content rather than from this plan, so a catalog row that changes
    /// underneath a bulk loop cannot launder a missing capability.
    pub async fn plan_import_effects(
        &self,
        repo_id: Uuid,
        path: &str,
    ) -> Result<Vec<TargetEffect>, PlaybookRepositoryError> {
        let repo_playbook = self.get_repository_playbook(repo_id, path).await?;
        // The cached kind is enough for a PREFLIGHT — its only job is to fail
        // an under-scoped caller early with the right capability named. The
        // authoritative read happens at the write branch.
        let kind = PlaybookKind::parse(&repo_playbook.kind).unwrap_or(PlaybookKind::Response);
        Ok(vec![Self::effect_for_kind(kind)])
    }

    /// Every target capability a BULK import of this repository could consume.
    ///
    /// Derived from the repository's declared `allowed_kinds` rather than from
    /// what happens to be in the catalog today: a preflight that flips the
    /// moment upstream adds a file is a preflight that fails unpredictably.
    /// An operator who does not want to hold `hunts:manage` to bulk-import
    /// runbooks narrows the repository to `{response}` — which is the same act
    /// as separating the two merge gates, and is the point of the column.
    pub async fn plan_bulk_import_effects(
        &self,
        repo_id: Uuid,
    ) -> Result<Vec<TargetEffect>, PlaybookRepositoryError> {
        let repo = self.get_repository(repo_id).await?;
        Ok(repo
            .allowed_kinds
            .iter()
            .filter_map(|k| PlaybookKind::parse(k))
            .map(Self::effect_for_kind)
            .collect())
    }

    /// The capability the canonical route for this kind enforces. A hunt is
    /// `hunts:manage`, never `playbooks:manage` — see
    /// [`TargetEffect::HuntCreate`].
    fn effect_for_kind(kind: PlaybookKind) -> TargetEffect {
        match kind {
            PlaybookKind::Response => TargetEffect::PlaybookCreate,
            PlaybookKind::Hunt => TargetEffect::HuntCreate,
        }
    }

    /// Shared definition metadata, assembled from the cached catalog row.
    ///
    /// Both kinds are `playbooks` rows and share every field here — which is
    /// the point of the shared definition layer. They diverge only in what is
    /// written alongside: a version row for a response playbook, a `hunt_specs`
    /// row for a hunt.
    fn build_create_request(
        repo_playbook: &RepositoryPlaybook,
        path: &str,
        repo_id: Uuid,
        req: &PlaybookImportRequest,
    ) -> CreatePlaybookRequest {
        let category = repo_playbook
            .category
            .as_deref()
            .and_then(PlaybookCategory::parse)
            .unwrap_or(PlaybookCategory::Identity);
        let scope = repo_playbook
            .scope
            .as_deref()
            .and_then(PlaybookScope::parse)
            .unwrap_or(PlaybookScope::Tenant);

        let danger_policy: Option<std::collections::HashMap<String, String>> = repo_playbook
            .danger_policy
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let title = repo_playbook
            .title
            .clone()
            .unwrap_or_else(|| path.rsplit('/').next().unwrap_or(path).to_string());

        CreatePlaybookRequest {
            title,
            subtitle: repo_playbook.subtitle.clone(),
            category,
            doc: repo_playbook.raw_content.clone(),
            match_signals: repo_playbook.match_signals.clone().unwrap_or_default(),
            danger_policy,
            review_cadence: repo_playbook.review_cadence.clone(),
            scope: Some(scope),
            tags: repo_playbook.tags.clone().unwrap_or_default(),
            owner_team: req.owner_team.clone().or(repo_playbook.owner_team.clone()),
            status: Some(PlaybookStatus::Draft),
            adaptive: Some(false),
            adaptive_source: None,
            source_playbook_path: Some(path.to_string()),
            source_repository_id: Some(repo_id),
            source_linked: Some(matches!(req.import_type, PlaybookImportType::Linked)),
        }
    }

    /// Sync a signed, air-gapped playbook bundle into the synthetic air-gap
    /// playbook repository's catalog (NAN-1226).
    ///
    /// The bundle has already been verified upstream (Ed25519 signature +
    /// per-file SHA-256 checksums via `nanosiem_core::airgap::verify_bundle`);
    /// this method takes the already-verified `(file_path, raw_content)` pairs
    /// and upserts each into `repository_playbooks` — the *exact same* catalog
    /// upsert (frontmatter parse → upsert) performed by `run_sync` for
    /// GitHub-synced repos. This is the offline equivalent of a repo *sync*:
    /// the playbooks land as available-to-import (a `repository_playbooks` row
    /// with no `playbook_imports` row), and the operator selectively imports
    /// them from the repositories page afterward.
    ///
    /// Nothing is imported or activated here — no library playbook is created.
    /// The bundle's playbooks are upserted into a synthetic, always-present
    /// air-gap playbook repository (created on first use via
    /// `AIRGAP_PLAYBOOK_REPOSITORY_SLUG`). Returns the number of playbooks
    /// synced (successfully upserted) into the catalog.
    pub async fn sync_playbook_bundle(
        &self,
        content_version: &str,
        playbooks: &[(String, String)],
        user_id: Option<Uuid>,
    ) -> Result<super::super::models::PlaybookBundleImportResult, PlaybookRepositoryError> {
        use super::super::models::PlaybookBundleImportResult;
        use super::sync::{catalog_kind, is_syncable_playbook_file};

        let repo = self.find_or_create_airgap_playbook_repository(user_id).await?;

        let mut synced = 0usize;

        for (path, content) in playbooks {
            // Same file filter the GitHub sync applies. A bundle is built from
            // a repository tree, so it carries that tree's README.md and
            // CONTRIBUTING.md too — and documentation handed to the hunt parser
            // is documentation catalogued as a definition.
            if !is_syncable_playbook_file(path, &self.config.playbook_extensions) {
                continue;
            }

            // Split frontmatter + parse body for metadata. Mirrors `run_sync`.
            // Unparseable files are still upserted with a `failed` parse status
            // (exactly as `run_sync` does) so they remain visible in the
            // catalog rather than silently dropped.
            let (fm, parse_status, parse_error, step_count) = match split_frontmatter(content) {
                Ok((fm, body)) => {
                    let tree = parse_playbook(body);
                    let steps: i32 = (tree.phases.iter().map(|p| p.steps.len()).sum::<usize>()
                        + tree.steps.len()) as i32;
                    (fm, "success", None, Some(steps))
                }
                Err(e) => (None, "failed", Some(e.to_string()), None),
            };

            let title = fm.as_ref().and_then(|f| f.title.clone());
            let subtitle = fm.as_ref().and_then(|f| f.subtitle.clone());
            let category = fm.as_ref().and_then(|f| f.category.clone());
            let match_signals = fm.as_ref().map(|f| f.match_signals.clone());
            let tags = fm.as_ref().map(|f| f.tags.clone());
            let owner_team = fm.as_ref().and_then(|f| f.owner.clone());
            let authored_date = fm.as_ref().and_then(|f| f.authored);
            let danger_policy = fm
                .as_ref()
                .map(|f| serde_json::to_value(&f.danger_policy).unwrap_or(serde_json::Value::Null));
            let review_cadence = fm.as_ref().and_then(|f| f.review_cadence.clone());
            let scope = fm.as_ref().and_then(|f| f.scope.clone());
            let kind = catalog_kind(fm.as_ref());

            if let Err(e) = self
                .playbooks_repository
                .upsert(
                    repo.id,
                    path,
                    None,
                    content,
                    kind.as_str(),
                    title.as_deref(),
                    subtitle.as_deref(),
                    category.as_deref(),
                    match_signals.as_deref(),
                    tags.as_deref(),
                    owner_team.as_deref(),
                    authored_date,
                    danger_policy.as_ref(),
                    review_cadence.as_deref(),
                    scope.as_deref(),
                    parse_status,
                    parse_error.as_deref(),
                    step_count,
                )
                .await
            {
                info!(
                    "Failed to upsert air-gap playbook {} into catalog: {}",
                    path, e
                );
                continue;
            }

            synced += 1;
        }

        info!(
            "Air-gapped playbook bundle synced into repo {} catalog (content_version={}): synced={}",
            repo.id, content_version, synced
        );

        Ok(PlaybookBundleImportResult {
            repository_id: repo.id,
            content_version: content_version.to_string(),
            synced,
        })
    }

    /// Find (or lazily create) the synthetic repository that air-gapped
    /// playbook bundles are imported into. A normal `playbook_repositories`
    /// row (so it shows up in the playbook-repo browser) with auto-sync
    /// disabled and a non-GitHub sentinel URL — never network-synced.
    async fn find_or_create_airgap_playbook_repository(
        &self,
        user_id: Option<Uuid>,
    ) -> Result<super::super::models::PlaybookRepository, PlaybookRepositoryError> {
        use super::super::models::NewPlaybookRepository;

        const AIRGAP_PLAYBOOK_REPOSITORY_SLUG: &str = "airgap-playbooks";
        const AIRGAP_PLAYBOOK_REPOSITORY_NAME: &str = "Air-gapped Playbook Bundles";

        if let Ok(existing) = self
            .repo_repository
            .find_by_slug(AIRGAP_PLAYBOOK_REPOSITORY_SLUG)
            .await
        {
            return Ok(existing);
        }

        let new_repo = NewPlaybookRepository {
            name: AIRGAP_PLAYBOOK_REPOSITORY_NAME.to_string(),
            slug: Some(AIRGAP_PLAYBOOK_REPOSITORY_SLUG.to_string()),
            description: Some(
                "Playbooks imported from offline air-gapped bundles (NAN-1220).".to_string(),
            ),
            // Sentinel, never-fetched URL — air-gap bundles are uploaded, not synced.
            url: "airgap://playbooks".to_string(),
            branch: None,
            playbooks_path: None,
            auto_sync_enabled: Some(false),
            sync_interval_hours: None,
            // None = the column default (both kinds). A bundle is whatever the
            // operator built offline, so this synthetic repository stays as
            // permissive as a fresh GitHub one; narrowing it is the same
            // deliberate act either way.
            allowed_kinds: None,
        };

        match self.repo_repository.create(&new_repo, user_id).await {
            Ok(repo) => Ok(repo),
            // Lost a create race with a concurrent bundle upload — re-fetch.
            Err(super::super::repository::PlaybookRepoRepositoryError::AlreadyExists(_)) => self
                .repo_repository
                .find_by_slug(AIRGAP_PLAYBOOK_REPOSITORY_SLUG)
                .await
                .map_err(|e| PlaybookRepositoryError::Internal(e.to_string())),
            Err(e) => Err(PlaybookRepositoryError::Internal(e.to_string())),
        }
    }
}
