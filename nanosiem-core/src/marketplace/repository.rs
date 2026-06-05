// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database operations for the enrichment marketplace

use sqlx::PgPool;
use tracing::instrument;
use uuid::Uuid;

use super::error::MarketplaceError;
use super::types::*;

/// Repository for marketplace catalog and enrichment repo CRUD
#[derive(Clone)]
pub struct MarketplaceRepository {
    pool: PgPool,
}

/// Live sync state for a native enrichment, read from `enrichment_sources`
/// (the source of truth for native syncs — IPinfo Lite et al. have no
/// `custom_enrichment_runs` row). Used to hydrate catalog cards (NAN-1122).
#[derive(sqlx::FromRow)]
struct NativeSyncState {
    id: String,
    last_sync_status: Option<String>,
    last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
    last_sync_error: Option<String>,
    record_count: i64,
}

impl MarketplaceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Populate cheap row-local computed fields (only `has_credentials`
    /// today) that don't depend on other tables.
    ///
    /// All public methods that return a [`MarketplaceCatalogEntry`] (reads
    /// AND mutator returns) additionally call
    /// [`Self::hydrate_with_run_state`] (single) or
    /// [`Self::hydrate_vec_with_run_state`] (batched) so the in-flight
    /// `is_syncing` signal is populated against `custom_enrichment_runs`.
    /// Keep that invariant when adding new entry-returning methods —
    /// otherwise the catalog card's syncing-vs-active distinction breaks
    /// for whichever path skips it (NAN-1108).
    fn hydrate(mut entry: MarketplaceCatalogEntry) -> MarketplaceCatalogEntry {
        entry.has_credentials = entry.credentials_encrypted.is_some();
        // requires_network is a derived field (execution backend + allowed_domains),
        // not a stored column — compute it here so every entry-returning path carries
        // it (the air-gap marketplace badges + egress-gating depend on it).
        entry.requires_network = entry.compute_requires_network();
        entry
    }

    fn hydrate_vec(entries: Vec<MarketplaceCatalogEntry>) -> Vec<MarketplaceCatalogEntry> {
        entries.into_iter().map(Self::hydrate).collect()
    }

    /// Mark `is_syncing=true` for every entry whose `custom_enrichment_id`
    /// currently has an in-flight run (status='running', completed_at IS
    /// NULL). One batched query covers the whole catalog list.
    ///
    /// Native entries (a `native_source_id` and no `custom_enrichment_id`,
    /// e.g. IPinfo Lite) have no `custom_enrichment_runs` row — their live
    /// sync state lives in `enrichment_sources` keyed by `id`. For those we
    /// read `last_sync_status` ('in_progress' ⇒ syncing) and also refresh
    /// `last_sync_at` / `last_error` / `record_count` from the source of
    /// truth so the card can show "synced <time>" (NAN-1122). The Deno path
    /// above is untouched.
    async fn hydrate_vec_with_run_state(
        &self,
        mut entries: Vec<MarketplaceCatalogEntry>,
    ) -> Result<Vec<MarketplaceCatalogEntry>, MarketplaceError> {
        // --- Deno path: in-flight custom_enrichment_runs ---
        let ce_ids: Vec<Uuid> = entries
            .iter()
            .filter_map(|e| e.custom_enrichment_id)
            .collect();

        if !ce_ids.is_empty() {
            let running: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT DISTINCT enrichment_id FROM custom_enrichment_runs \
                 WHERE enrichment_id = ANY($1) AND status = 'running' AND completed_at IS NULL",
            )
            .bind(&ce_ids)
            .fetch_all(&self.pool)
            .await?;

            let running: std::collections::HashSet<Uuid> =
                running.into_iter().map(|(id,)| id).collect();

            for e in &mut entries {
                if let Some(ce_id) = e.custom_enrichment_id {
                    e.is_syncing = running.contains(&ce_id);
                }
            }
        }

        // --- Native path: enrichment_sources.last_sync_status ---
        let native_ids: Vec<String> = entries
            .iter()
            .filter(|e| e.custom_enrichment_id.is_none())
            .filter_map(|e| e.native_source_id.clone())
            .collect();

        if !native_ids.is_empty() {
            let sources: Vec<NativeSyncState> = sqlx::query_as(
                "SELECT id, last_sync_status, last_sync_at, last_sync_error, record_count \
                 FROM enrichment_sources WHERE id = ANY($1)",
            )
            .bind(&native_ids)
            .fetch_all(&self.pool)
            .await?;

            let by_id: std::collections::HashMap<String, NativeSyncState> =
                sources.into_iter().map(|s| (s.id.clone(), s)).collect();

            for e in &mut entries {
                if e.custom_enrichment_id.is_some() {
                    continue;
                }
                if let Some(src_id) = &e.native_source_id {
                    if let Some(s) = by_id.get(src_id) {
                        e.is_syncing = s.last_sync_status.as_deref() == Some("in_progress");
                        e.last_sync_status = s.last_sync_status.clone();
                        e.last_sync_at = s.last_sync_at;
                        e.last_error = s.last_sync_error.clone();
                        e.record_count = s.record_count;
                    }
                }
            }
        }

        Ok(entries)
    }

    /// Single-entry variant of [`Self::hydrate_vec_with_run_state`].
    async fn hydrate_with_run_state(
        &self,
        mut entry: MarketplaceCatalogEntry,
    ) -> Result<MarketplaceCatalogEntry, MarketplaceError> {
        if let Some(ce_id) = entry.custom_enrichment_id {
            // Deno path: in-flight custom_enrichment_runs.
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM custom_enrichment_runs \
                 WHERE enrichment_id = $1 AND status = 'running' AND completed_at IS NULL)",
            )
            .bind(ce_id)
            .fetch_one(&self.pool)
            .await?;
            entry.is_syncing = exists;
        } else if let Some(src_id) = entry.native_source_id.clone() {
            // Native path: enrichment_sources.last_sync_status (NAN-1122).
            let source: Option<NativeSyncState> = sqlx::query_as(
                "SELECT id, last_sync_status, last_sync_at, last_sync_error, record_count \
                 FROM enrichment_sources WHERE id = $1",
            )
            .bind(&src_id)
            .fetch_optional(&self.pool)
            .await?;
            if let Some(s) = source {
                entry.is_syncing = s.last_sync_status.as_deref() == Some("in_progress");
                entry.last_sync_status = s.last_sync_status;
                entry.last_sync_at = s.last_sync_at;
                entry.last_error = s.last_sync_error;
                entry.record_count = s.record_count;
            }
        }
        Ok(entry)
    }

    // =========================================================================
    // Catalog operations
    // =========================================================================

    /// List catalog entries with optional filtering
    #[instrument(skip(self))]
    pub async fn list_catalog(
        &self,
        filter: &CatalogFilter,
    ) -> Result<Vec<MarketplaceCatalogEntry>, MarketplaceError> {
        let mut query = String::from("SELECT * FROM marketplace_catalog WHERE 1=1");
        let mut bind_idx = 1u32;

        if filter.category.is_some() {
            query.push_str(&format!(" AND category = ${}", bind_idx));
            bind_idx += 1;
        }
        if filter.installed.is_some() {
            query.push_str(&format!(" AND installed = ${}", bind_idx));
            bind_idx += 1;
        }
        if filter.tag.is_some() {
            query.push_str(&format!(" AND ${} = ANY(tags)", bind_idx));
            bind_idx += 1;
        }
        if filter.search.is_some() {
            query.push_str(&format!(
                " AND (lower(name) LIKE ${idx} OR lower(description) LIKE ${idx})",
                idx = bind_idx
            ));
            bind_idx += 1;
        }
        if filter.source_type.is_some() {
            query.push_str(&format!(" AND source_type = ${}", bind_idx));
            // bind_idx += 1;  // last, not needed
        }

        query.push_str(" ORDER BY category, name");

        let mut q = sqlx::query_as::<_, MarketplaceCatalogEntry>(&query);

        if let Some(ref category) = filter.category {
            q = q.bind(category);
        }
        if let Some(installed) = filter.installed {
            q = q.bind(installed);
        }
        if let Some(ref tag) = filter.tag {
            q = q.bind(tag);
        }
        if let Some(ref search) = filter.search {
            // Escape LIKE wildcards (%, _, \) so user input is treated literally
            let escaped = search
                .to_lowercase()
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            q = q.bind(format!("%{}%", escaped));
        }
        if let Some(ref source_type) = filter.source_type {
            q = q.bind(source_type);
        }

        let entries = q.fetch_all(&self.pool).await?;
        let entries = Self::hydrate_vec(entries);
        self.hydrate_vec_with_run_state(entries).await
    }

    /// Get catalog stats
    #[instrument(skip(self))]
    pub async fn get_catalog_stats(&self) -> Result<CatalogStats, MarketplaceError> {
        let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64)>(
            r#"
            SELECT
                COUNT(*) as total_entries,
                COUNT(*) FILTER (WHERE installed = true) as installed_count,
                COUNT(*) FILTER (WHERE category = 'data') as data_count,
                COUNT(*) FILTER (WHERE category = 'agent') as agent_count,
                COUNT(*) FILTER (WHERE category = 'identity') as identity_count,
                COUNT(*) FILTER (WHERE category = 'security') as security_count
            FROM marketplace_catalog
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(CatalogStats {
            total_entries: row.0,
            installed_count: row.1,
            data_count: row.2,
            agent_count: row.3,
            identity_count: row.4,
            security_count: row.5,
        })
    }

    /// Get a single catalog entry by slug
    #[instrument(skip(self))]
    pub async fn get_catalog_entry(
        &self,
        slug: &str,
    ) -> Result<MarketplaceCatalogEntry, MarketplaceError> {
        let entry = sqlx::query_as::<_, MarketplaceCatalogEntry>(
            "SELECT * FROM marketplace_catalog WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await?
        .map(Self::hydrate)
        .ok_or_else(|| MarketplaceError::CatalogEntryNotFound(slug.to_string()))?;

        self.hydrate_with_run_state(entry).await
    }

    /// Get a single catalog entry by ID
    #[instrument(skip(self))]
    pub async fn get_catalog_entry_by_id(
        &self,
        id: Uuid,
    ) -> Result<MarketplaceCatalogEntry, MarketplaceError> {
        let entry = sqlx::query_as::<_, MarketplaceCatalogEntry>(
            "SELECT * FROM marketplace_catalog WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .map(Self::hydrate)
        .ok_or_else(|| MarketplaceError::CatalogEntryNotFound(id.to_string()))?;

        self.hydrate_with_run_state(entry).await
    }

    /// Upsert a catalog entry (used during repo sync)
    #[instrument(skip(self, entry))]
    pub async fn upsert_catalog_entry(
        &self,
        entry: &MarketplaceCatalogEntry,
    ) -> Result<MarketplaceCatalogEntry, MarketplaceError> {
        let result = sqlx::query_as::<_, MarketplaceCatalogEntry>(
            r#"
            INSERT INTO marketplace_catalog (
                slug, name, description, category, tags, icon, author,
                source_type, repository_id, repository_file_path, manifest_version,
                execution_backend, custom_enrichment_id, native_source_id, identity_provider_id,
                requires_credential, credential_fields, code, allowed_domains, config, changelog
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7,
                $8, $9, $10, $11,
                $12, $13, $14, $15,
                $16, $17, $18, $19, $20, $21
            )
            ON CONFLICT (slug) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                tags = EXCLUDED.tags,
                icon = EXCLUDED.icon,
                author = EXCLUDED.author,
                repository_file_path = EXCLUDED.repository_file_path,
                manifest_version = EXCLUDED.manifest_version,
                requires_credential = EXCLUDED.requires_credential,
                credential_fields = EXCLUDED.credential_fields,
                code = EXCLUDED.code,
                allowed_domains = EXCLUDED.allowed_domains,
                config = EXCLUDED.config,
                changelog = EXCLUDED.changelog,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(&entry.slug)
        .bind(&entry.name)
        .bind(&entry.description)
        .bind(&entry.category)
        .bind(&entry.tags)
        .bind(&entry.icon)
        .bind(&entry.author)
        .bind(&entry.source_type)
        .bind(entry.repository_id)
        .bind(&entry.repository_file_path)
        .bind(entry.manifest_version)
        .bind(&entry.execution_backend)
        .bind(entry.custom_enrichment_id)
        .bind(&entry.native_source_id)
        .bind(&entry.identity_provider_id)
        .bind(&entry.requires_credential)
        .bind(&entry.credential_fields)
        .bind(&entry.code)
        .bind(&entry.allowed_domains)
        .bind(&entry.config)
        .bind(&entry.changelog)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("marketplace_catalog_slug_key") {
                    return MarketplaceError::SlugAlreadyExists(entry.slug.clone());
                }
            }
            MarketplaceError::Database(e)
        })?;

        self.hydrate_with_run_state(Self::hydrate(result)).await
    }

    /// Create a marketplace catalog entry for a user-created custom enrichment
    #[instrument(skip(self))]
    pub async fn create_catalog_for_custom_enrichment(
        &self,
        custom_enrichment_id: Uuid,
        name: &str,
        description: Option<&str>,
        enrichment_type: &str,
        code: Option<&str>,
        allowed_domains: &[String],
        config: &serde_json::Value,
        credential_id: Option<Uuid>,
    ) -> Result<MarketplaceCatalogEntry, MarketplaceError> {
        let slug = name
            .to_lowercase()
            .replace(' ', "-")
            .replace(|c: char| !c.is_alphanumeric() && c != '-', "");
        let category = match enrichment_type {
            "data" => "data",
            _ => "agent",
        };
        let requires_credential = if credential_id.is_some() {
            "required"
        } else {
            "none"
        };

        let result = sqlx::query_as::<_, MarketplaceCatalogEntry>(
            r#"
            INSERT INTO marketplace_catalog (
                slug, name, description, category, tags, icon, author,
                source_type, manifest_version,
                execution_backend, custom_enrichment_id,
                requires_credential, credential_fields, code, allowed_domains, config,
                installed, installed_at, installed_version, enabled
            ) VALUES (
                $1, $2, $3, $4, '{}', 'code', 'Custom',
                'custom', 1,
                'deno', $5,
                $6, '[]', $7, $8, $9,
                false, NULL, NULL, false
            )
            ON CONFLICT (slug) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                code = EXCLUDED.code,
                allowed_domains = EXCLUDED.allowed_domains,
                config = EXCLUDED.config,
                custom_enrichment_id = EXCLUDED.custom_enrichment_id,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(&slug)
        .bind(name)
        .bind(description)
        .bind(category)
        .bind(custom_enrichment_id)
        .bind(requires_credential)
        .bind(code)
        .bind(allowed_domains)
        .bind(config)
        .fetch_one(&self.pool)
        .await
        .map_err(MarketplaceError::Database)?;

        self.hydrate_with_run_state(Self::hydrate(result)).await
    }

    /// Delete a marketplace catalog entry by custom_enrichment_id
    #[instrument(skip(self))]
    pub async fn delete_catalog_by_custom_enrichment_id(
        &self,
        custom_enrichment_id: Uuid,
    ) -> Result<(), MarketplaceError> {
        sqlx::query("DELETE FROM marketplace_catalog WHERE custom_enrichment_id = $1")
            .bind(custom_enrichment_id)
            .execute(&self.pool)
            .await
            .map_err(MarketplaceError::Database)?;
        Ok(())
    }

    /// Mark a catalog entry as installed
    #[instrument(skip(self, credentials_encrypted, credentials_nonce))]
    pub async fn set_installed(
        &self,
        slug: &str,
        installed: bool,
        credentials_encrypted: Option<&[u8]>,
        credentials_nonce: Option<&str>,
    ) -> Result<MarketplaceCatalogEntry, MarketplaceError> {
        let result = sqlx::query_as::<_, MarketplaceCatalogEntry>(
            r#"
            UPDATE marketplace_catalog SET
                installed = $2,
                installed_at = CASE WHEN $2 THEN NOW() ELSE NULL END,
                installed_version = CASE WHEN $2 THEN manifest_version ELSE NULL END,
                enabled = $2,
                credentials_encrypted = COALESCE($3, credentials_encrypted),
                credentials_nonce = COALESCE($4, credentials_nonce)
            WHERE slug = $1
            RETURNING *
            "#,
        )
        .bind(slug)
        .bind(installed)
        .bind(credentials_encrypted)
        .bind(credentials_nonce)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| MarketplaceError::CatalogEntryNotFound(slug.to_string()))?;

        self.hydrate_with_run_state(Self::hydrate(result)).await
    }

    /// Update installed_version to match manifest_version (after an update)
    #[instrument(skip(self))]
    pub async fn update_installed_version(
        &self,
        slug: &str,
    ) -> Result<MarketplaceCatalogEntry, MarketplaceError> {
        let result = sqlx::query_as::<_, MarketplaceCatalogEntry>(
            r#"
            UPDATE marketplace_catalog SET
                installed_version = manifest_version,
                updated_at = NOW()
            WHERE slug = $1 AND installed = true
            RETURNING *
            "#,
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| MarketplaceError::NotInstalled(slug.to_string()))?;

        self.hydrate_with_run_state(Self::hydrate(result)).await
    }

    /// Update catalog entry configuration
    #[instrument(skip(self, credentials_encrypted, credentials_nonce))]
    pub async fn update_catalog_config(
        &self,
        slug: &str,
        config: Option<&serde_json::Value>,
        enabled: Option<bool>,
        credentials_encrypted: Option<&[u8]>,
        credentials_nonce: Option<&str>,
    ) -> Result<MarketplaceCatalogEntry, MarketplaceError> {
        let result = sqlx::query_as::<_, MarketplaceCatalogEntry>(
            r#"
            UPDATE marketplace_catalog SET
                config = COALESCE($2, config),
                enabled = COALESCE($3, enabled),
                credentials_encrypted = COALESCE($4, credentials_encrypted),
                credentials_nonce = COALESCE($5, credentials_nonce)
            WHERE slug = $1
            RETURNING *
            "#,
        )
        .bind(slug)
        .bind(config)
        .bind(enabled)
        .bind(credentials_encrypted)
        .bind(credentials_nonce)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| MarketplaceError::CatalogEntryNotFound(slug.to_string()))?;

        self.hydrate_with_run_state(Self::hydrate(result)).await
    }

    /// Update sync status for a catalog entry
    #[instrument(skip(self))]
    pub async fn update_sync_status(
        &self,
        slug: &str,
        status: &str,
        error: Option<&str>,
        record_count: Option<i64>,
    ) -> Result<(), MarketplaceError> {
        sqlx::query(
            r#"
            UPDATE marketplace_catalog SET
                last_sync_at = NOW(),
                last_sync_status = $2,
                last_error = $3,
                record_count = COALESCE($4, record_count)
            WHERE slug = $1
            "#,
        )
        .bind(slug)
        .bind(status)
        .bind(error)
        .bind(record_count)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Delete catalog entries from a repository that are no longer in the repo
    #[instrument(skip(self, keep_slugs))]
    pub async fn remove_stale_repo_entries(
        &self,
        repo_id: Uuid,
        keep_slugs: &[String],
    ) -> Result<i32, MarketplaceError> {
        let result = sqlx::query(
            r#"
            DELETE FROM marketplace_catalog
            WHERE repository_id = $1
              AND NOT (slug = ANY($2))
              AND installed = false
            "#,
        )
        .bind(repo_id)
        .bind(keep_slugs)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as i32)
    }

    // =========================================================================
    // Enrichment marketplace repo operations
    // =========================================================================

    /// List all enrichment repos
    #[instrument(skip(self))]
    pub async fn list_repos(&self) -> Result<Vec<EnrichmentMarketplaceRepo>, MarketplaceError> {
        let repos = sqlx::query_as::<_, EnrichmentMarketplaceRepo>(
            r#"
            SELECT
                r.id,
                r.name,
                r.slug,
                r.description,
                r.url,
                r.branch,
                r.enrichments_path,
                r.auto_sync_enabled,
                r.sync_interval_hours,
                r.last_synced_at,
                r.last_sync_commit,
                r.last_sync_status,
                r.last_sync_error,
                COALESCE((
                    SELECT COUNT(*)
                    FROM marketplace_catalog c
                    WHERE c.repository_id = r.id
                ), 0)::int4 AS enrichment_count,
                r.enabled,
                r.created_by,
                r.created_at,
                r.updated_at
            FROM enrichment_marketplace_repos r
            ORDER BY r.name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(repos)
    }

    /// List repos due for auto-sync
    #[instrument(skip(self))]
    pub async fn list_repos_for_auto_sync(
        &self,
    ) -> Result<Vec<EnrichmentMarketplaceRepo>, MarketplaceError> {
        let repos = sqlx::query_as::<_, EnrichmentMarketplaceRepo>(
            r#"
            SELECT
                r.id,
                r.name,
                r.slug,
                r.description,
                r.url,
                r.branch,
                r.enrichments_path,
                r.auto_sync_enabled,
                r.sync_interval_hours,
                r.last_synced_at,
                r.last_sync_commit,
                r.last_sync_status,
                r.last_sync_error,
                COALESCE((
                    SELECT COUNT(*)
                    FROM marketplace_catalog c
                    WHERE c.repository_id = r.id
                ), 0)::int4 AS enrichment_count,
                r.enabled,
                r.created_by,
                r.created_at,
                r.updated_at
            FROM enrichment_marketplace_repos r
            WHERE r.enabled = true
              AND r.auto_sync_enabled = true
              AND (r.last_synced_at IS NULL OR
                   r.last_synced_at + (r.sync_interval_hours || ' hours')::INTERVAL < NOW())
            ORDER BY r.last_synced_at NULLS FIRST
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(repos)
    }

    /// Get a repo by ID
    #[instrument(skip(self))]
    pub async fn get_repo(&self, id: Uuid) -> Result<EnrichmentMarketplaceRepo, MarketplaceError> {
        sqlx::query_as::<_, EnrichmentMarketplaceRepo>(
            r#"
            SELECT
                r.id,
                r.name,
                r.slug,
                r.description,
                r.url,
                r.branch,
                r.enrichments_path,
                r.auto_sync_enabled,
                r.sync_interval_hours,
                r.last_synced_at,
                r.last_sync_commit,
                r.last_sync_status,
                r.last_sync_error,
                COALESCE((
                    SELECT COUNT(*)
                    FROM marketplace_catalog c
                    WHERE c.repository_id = r.id
                ), 0)::int4 AS enrichment_count,
                r.enabled,
                r.created_by,
                r.created_at,
                r.updated_at
            FROM enrichment_marketplace_repos r
            WHERE r.id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(MarketplaceError::RepositoryNotFound(id))
    }

    /// Create a new enrichment repo
    #[instrument(skip(self))]
    pub async fn create_repo(
        &self,
        request: &CreateMarketplaceRepo,
        created_by: Option<Uuid>,
    ) -> Result<EnrichmentMarketplaceRepo, MarketplaceError> {
        // Validate URL — only HTTPS allowed
        let url_lower = request.url.trim().to_lowercase();
        if !url_lower.starts_with("https://") {
            return Err(MarketplaceError::InvalidUrl(
                "Only HTTPS URLs are allowed for enrichment repositories".to_string(),
            ));
        }

        // H3: SSRF validation — block private IPs, localhost, cloud metadata
        let ssrf_validator = crate::inputlookup::SsrfValidator::default_secure();
        ssrf_validator
            .validate_with_dns(request.url.trim())
            .await
            .map_err(|e| {
                MarketplaceError::InvalidUrl(format!("URL blocked by security policy: {}", e))
            })?;

        let slug = request
            .name
            .to_lowercase()
            .replace(' ', "-")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .collect::<String>();

        if slug.is_empty() {
            return Err(MarketplaceError::InvalidUrl(
                "Repository name must contain at least one alphanumeric character".to_string(),
            ));
        }

        let result = sqlx::query_as::<_, EnrichmentMarketplaceRepo>(
            r#"
            INSERT INTO enrichment_marketplace_repos (
                name, slug, description, url, branch, enrichments_path,
                auto_sync_enabled, sync_interval_hours, created_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(&request.name)
        .bind(&slug)
        .bind(&request.description)
        .bind(&request.url)
        .bind(&request.branch)
        .bind(&request.enrichments_path)
        .bind(request.auto_sync_enabled)
        .bind(request.sync_interval_hours)
        .bind(created_by)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("enrichment_marketplace_repos_slug_key") {
                    return MarketplaceError::RepositoryAlreadyExists(request.name.clone());
                }
            }
            MarketplaceError::Database(e)
        })?;

        Ok(result)
    }

    /// Update a repo
    #[instrument(skip(self))]
    pub async fn update_repo(
        &self,
        id: Uuid,
        request: &UpdateMarketplaceRepo,
    ) -> Result<EnrichmentMarketplaceRepo, MarketplaceError> {
        let result = sqlx::query_as::<_, EnrichmentMarketplaceRepo>(
            r#"
            UPDATE enrichment_marketplace_repos SET
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                branch = COALESCE($4, branch),
                enrichments_path = COALESCE($5, enrichments_path),
                auto_sync_enabled = COALESCE($6, auto_sync_enabled),
                sync_interval_hours = COALESCE($7, sync_interval_hours),
                enabled = COALESCE($8, enabled)
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(&request.branch)
        .bind(&request.enrichments_path)
        .bind(request.auto_sync_enabled)
        .bind(request.sync_interval_hours)
        .bind(request.enabled)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(MarketplaceError::RepositoryNotFound(id))?;

        Ok(result)
    }

    /// Delete a repo (cascade removes non-installed catalog entries)
    #[instrument(skip(self))]
    pub async fn delete_repo(&self, id: Uuid) -> Result<(), MarketplaceError> {
        // First remove non-installed catalog entries from this repo
        sqlx::query(
            "DELETE FROM marketplace_catalog WHERE repository_id = $1 AND installed = false",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        // Set repository_id to NULL for installed entries (they keep working)
        sqlx::query("UPDATE marketplace_catalog SET repository_id = NULL WHERE repository_id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        // Delete the repo
        let result = sqlx::query("DELETE FROM enrichment_marketplace_repos WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(MarketplaceError::RepositoryNotFound(id));
        }

        Ok(())
    }

    /// Update repo sync status
    #[instrument(skip(self))]
    pub async fn update_repo_sync_status(
        &self,
        id: Uuid,
        status: &str,
        commit: Option<&str>,
        enrichment_count: Option<i32>,
        error: Option<&str>,
    ) -> Result<(), MarketplaceError> {
        sqlx::query(
            r#"
            UPDATE enrichment_marketplace_repos SET
                last_synced_at = NOW(),
                last_sync_status = $2,
                last_sync_commit = COALESCE($3, last_sync_commit),
                enrichment_count = COALESCE($4, enrichment_count),
                last_sync_error = $5
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(status)
        .bind(commit)
        .bind(enrichment_count)
        .bind(error)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
