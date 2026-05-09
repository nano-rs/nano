// SPDX-License-Identifier: AGPL-3.0-or-later

//! Migration execution: applying individual migrations, running init.sql,
//! loading migration files, and orchestrating the full migration run.

use super::{ClickHouseMigrateError, ClickHouseMigrator, Migration};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

// Migration filenames look like `109_drop_windowed_prevalence_dicts.sql` — and
// occasionally `075a_*.sql` for sub-migrations. The leading digit run is
// required so that init.sql, README.md, and any non-numbered SQL co-resident
// in the migrations dir are skipped (init.sql is loaded separately via
// `run_init_sql`; applying it through the migration runner would record it as
// version `init.sql` and replay it on every startup).
static MIGRATION_FILENAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\d+[a-z]*_.+\.sql$").expect("valid regex"));

impl ClickHouseMigrator {
    /// Apply a single migration
    async fn apply_migration(
        &self,
        migration: &Migration,
        is_cloud: bool,
        cluster_name: Option<&str>,
    ) -> Result<(), ClickHouseMigrateError> {
        // Substitute PostgreSQL dictionary connection details from env vars.
        // Defaults match Docker Compose (host='postgres', password='nanosiem').
        let migration_sql = Self::substitute_postgres_vars(&migration.sql);

        // NAN-707: Substitute `{clickhouse_self_*}` placeholders in dict source
        // blocks that reference the local CH instance. Without this, a migration
        // that uses the placeholders gets the literal text and CH rejects it,
        // and a migration with hardcoded creds breaks any tenant whose
        // password is rotated off the default. init.sql has always done this
        // — now numbered migrations do too.
        let migration_sql = Self::substitute_clickhouse_self_vars(&migration_sql);

        // Sanitize entire migration SQL for CH Cloud before splitting into statements.
        // This strips incompatible settings/index types so the core DDL executes cleanly.
        let migration_sql = if is_cloud {
            Self::sanitize_for_cloud(&migration_sql)
        } else {
            migration_sql
        };

        // Strip SQL line comments before splitting on semicolons.
        // This prevents semicolons inside comments from creating bogus statements.
        // (ClickHouse doesn't support multiple statements in one query)
        let migration_sql: String = migration_sql
            .lines()
            .map(|line| {
                if let Some(pos) = line.find("--") {
                    &line[..pos]
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Collect SET key=value pairs to append as SETTINGS clause to DDL queries
        let mut settings: Vec<(String, String)> = Vec::new();

        for statement in migration_sql.split(';') {
            let sql = statement.trim();
            if sql.is_empty() {
                continue;
            }

            // Apply cluster transformation if in cluster mode
            let sql = if let Some(cluster) = cluster_name {
                let transformed = Self::transform_for_cluster(sql, cluster, &self.database);
                if transformed.trim().is_empty() {
                    continue; // Statement was intentionally skipped (e.g., non_replicated_dedup)
                }
                transformed
            } else {
                sql.to_string()
            };

            // Check if this is a SET statement - parse and collect for SETTINGS clause
            let sql_upper = sql.to_uppercase();
            if sql_upper.starts_with("SET ") {
                if is_cloud {
                    // On CH Cloud, skip SET statements for restricted settings entirely
                    let key = sql[4..]
                        .split('=')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_lowercase();
                    if key.contains("full_text_index") || key.contains("experimental") {
                        tracing::debug!("Skipping restricted SET statement on CH Cloud: {}", sql);
                        continue;
                    }
                }
                // Parse "SET key = value" format
                if let Some(eq_pos) = sql.find('=') {
                    let key = sql[4..eq_pos].trim().to_string();
                    let value = sql[eq_pos + 1..].trim().to_string();
                    settings.push((key, value));
                }
                continue;
            }

            // For ALTER TABLE statements, append SETTINGS clause if we have settings
            let full_sql = if !settings.is_empty() && sql_upper.starts_with("ALTER TABLE") {
                // On CH Cloud, filter out restricted settings before appending
                let filtered_settings: Vec<_> = if is_cloud {
                    settings
                        .iter()
                        .filter(|(k, _)| {
                            let kl = k.to_lowercase();
                            !kl.contains("full_text_index")
                                && !kl.contains("experimental")
                                && !kl.contains("storage_policy")
                        })
                        .collect()
                } else {
                    settings.iter().collect()
                };

                if filtered_settings.is_empty() {
                    sql.clone()
                } else {
                    let settings_str = filtered_settings
                        .iter()
                        .map(|(k, v)| format!("{} = {}", k, v))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("{} SETTINGS {}", sql, settings_str)
                }
            } else {
                sql.clone()
            };

            // Some statements may fail on ClickHouse Cloud:
            // - CREATE DICTIONARY: CH Cloud can't reach Docker-internal PostgreSQL
            // - GRANT statements: CH Cloud uses its own permission model
            // Treat these as non-fatal so the rest of the migration proceeds.
            let is_soft_fail = sql_upper.starts_with("CREATE DICTIONARY")
                || sql_upper.starts_with("CREATE OR REPLACE DICTIONARY")
                || sql_upper.starts_with("GRANT ");

            match self.client.query(&full_sql).execute().await {
                Ok(_) => {}
                Err(e) if is_soft_fail => {
                    tracing::warn!(
                        "Migration statement failed (non-fatal, skipping): {} - {}",
                        migration.filename,
                        e
                    );
                    continue;
                }
                Err(e) => {
                    return Err(ClickHouseMigrateError::ClickHouse(format!(
                        "Failed to execute migration {} statement: {} - Error: {}",
                        migration.filename, sql, e
                    )));
                }
            }
        }

        Ok(())
    }

    /// Run init.sql to create the base schema (database, tables, MVs, dictionaries).
    ///
    /// This is idempotent — all CREATE statements use IF NOT EXISTS.
    /// In cluster mode, DDL is transformed to use ON CLUSTER + Replicated engines.
    /// Call this before `run_migrations()` for initial setup or disaster recovery.
    ///
    /// Stores a SHA-256 hash of init.sql in the `_migrations` table and skips
    /// execution on subsequent startups if the hash hasn't changed. This avoids
    /// ~40s of ON CLUSTER DDL overhead on every restart.
    pub async fn run_init_sql(&mut self, init_sql: &str) -> Result<(), ClickHouseMigrateError> {
        let is_cloud = self.detect_cloud().await?;
        let cluster_name = self.detect_cluster().await?;

        let mode_label = match (&cluster_name, is_cloud) {
            (Some(c), _) => format!(" [cluster: {}]", c),
            (_, true) => " [cloud mode]".to_string(),
            _ => String::new(),
        };

        // Check if init.sql has changed since last run by comparing SHA-256 hashes.
        // The hash is stored in the _migrations table under version '__init_sql'.
        use sha2::{Sha256, Digest};
        let hash = hex::encode(Sha256::digest(init_sql.as_bytes()));

        self.ensure_migrations_table().await?;

        let stored_hash: Option<String> = self
            .client
            .query(&format!(
                "SELECT checksum FROM {}._migrations WHERE version = '__init_sql' LIMIT 1",
                self.database
            ))
            .fetch_all::<String>()
            .await
            .ok()
            .and_then(|rows| rows.into_iter().next());

        if stored_hash.as_deref() == Some(hash.as_str()) {
            tracing::info!("init.sql unchanged (hash match) — skipping{}", mode_label);
            return Ok(());
        }

        tracing::info!("Running init.sql{}", mode_label);

        // Substitute placeholders that point at the local CH instance and the
        // platform PostgreSQL. NAN-707 lifted the CH-self substitution out of
        // this function so numbered migrations share the same helper.
        let sql = Self::substitute_clickhouse_self_vars(init_sql);
        let sql = Self::substitute_postgres_vars(&sql);

        // Sanitize for cloud if needed
        let sql = if is_cloud {
            Self::sanitize_for_cloud(&sql)
        } else {
            sql
        };

        // Strip SQL line comments before splitting on semicolons.
        let sql: String = sql
            .lines()
            .map(|line| {
                if let Some(pos) = line.find("--") {
                    &line[..pos]
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let mut settings: Vec<(String, String)> = Vec::new();

        for statement in sql.split(';') {
            let sql_stmt = statement.trim();
            if sql_stmt.is_empty() {
                continue;
            }

            // Apply cluster transformation
            let sql_stmt = if let Some(ref cluster) = cluster_name {
                let transformed = Self::transform_for_cluster(sql_stmt, cluster, &self.database);
                if transformed.trim().is_empty() {
                    continue;
                }
                transformed
            } else {
                sql_stmt.to_string()
            };

            let sql_upper = sql_stmt.to_uppercase();

            // Handle SET statements
            if sql_upper.starts_with("SET ") {
                if is_cloud {
                    let key = sql_stmt[4..]
                        .split('=')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_lowercase();
                    if key.contains("full_text_index") || key.contains("experimental") {
                        continue;
                    }
                }
                if let Some(eq_pos) = sql_stmt.find('=') {
                    let key = sql_stmt[4..eq_pos].trim().to_string();
                    let value = sql_stmt[eq_pos + 1..].trim().to_string();
                    settings.push((key, value));
                }
                continue;
            }

            // For ALTER TABLE, append collected SETTINGS
            let full_sql = if !settings.is_empty() && sql_upper.starts_with("ALTER TABLE") {
                let filtered_settings: Vec<_> = if is_cloud {
                    settings
                        .iter()
                        .filter(|(k, _)| {
                            let kl = k.to_lowercase();
                            !kl.contains("full_text_index")
                                && !kl.contains("experimental")
                                && !kl.contains("storage_policy")
                        })
                        .collect()
                } else {
                    settings.iter().collect()
                };
                if filtered_settings.is_empty() {
                    sql_stmt.clone()
                } else {
                    let settings_str = filtered_settings
                        .iter()
                        .map(|(k, v)| format!("{} = {}", k, v))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("{} SETTINGS {}", sql_stmt, settings_str)
                }
            } else {
                sql_stmt.clone()
            };

            // Dictionaries, GRANTs, and settings profiles are non-fatal
            // (may fail in cross-cluster setups or CH Cloud)
            let is_soft_fail = sql_upper.starts_with("CREATE DICTIONARY")
                || sql_upper.starts_with("GRANT ")
                || sql_upper.starts_with("CREATE SETTINGS PROFILE");

            match self.client.query(&full_sql).execute().await {
                Ok(_) => {}
                Err(e) if is_soft_fail => {
                    tracing::warn!(
                        "Init SQL statement failed (non-fatal): {} - {}",
                        &sql_stmt[..sql_stmt.len().min(80)],
                        e
                    );
                }
                Err(e) => {
                    return Err(ClickHouseMigrateError::ClickHouse(format!(
                        "Failed to execute init SQL: {} - Error: {}",
                        &sql_stmt[..sql_stmt.len().min(120)],
                        e
                    )));
                }
            }
        }

        tracing::info!("Init SQL completed successfully");

        // Store the hash so we can skip init.sql on next startup
        let upsert_sql = format!(
            "INSERT INTO {}._migrations (version, name, checksum) VALUES ('__init_sql', 'init.sql', '{}')",
            self.database, hash
        );
        // Use ALTER + DELETE for replicated tables (no REPLACE INTO in ClickHouse)
        let delete_sql = format!(
            "ALTER TABLE {}._migrations DELETE WHERE version = '__init_sql'",
            self.database
        );
        // Best-effort: don't fail startup if hash storage fails
        let _ = self.client.query(&delete_sql).execute().await;
        if let Err(e) = self.client.query(&upsert_sql).execute().await {
            tracing::warn!("Failed to store init.sql hash: {} — next startup will re-run init.sql", e);
        }

        // Seed baseline migrations on fresh deployments so the runner
        // won't try to re-apply migrations already baked into init.sql
        let seeded = self.seed_baseline_migrations().await?;
        if seeded > 0 {
            tracing::info!(
                "Fresh deployment detected — seeded {} baseline migrations",
                seeded
            );
        }

        Ok(())
    }

    /// Load migrations from a directory
    pub fn load_migrations_from_dir(dir: &Path) -> Result<Vec<Migration>, ClickHouseMigrateError> {
        let mut migrations = Vec::new();

        if !dir.exists() {
            tracing::warn!("ClickHouse migrations directory does not exist: {:?}", dir);
            return Ok(migrations);
        }

        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|name| MIGRATION_FILENAME_RE.is_match(name))
                    .unwrap_or(false)
            })
            .collect();

        // Sort by filename to ensure order
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            let filename = entry.file_name().to_string_lossy().to_string();

            // Parse version from filename (e.g., "001_init.sql" -> "001")
            let version = filename
                .split('_')
                .next()
                .ok_or_else(|| ClickHouseMigrateError::InvalidFileName(filename.clone()))?
                .to_string();

            // Parse name from filename (e.g., "001_init_clickhouse.sql" -> "init_clickhouse")
            let name = filename
                .strip_suffix(".sql")
                .unwrap_or(&filename)
                .splitn(2, '_')
                .nth(1)
                .unwrap_or("unknown")
                .to_string();

            let sql = std::fs::read_to_string(&path)?;

            migrations.push(Migration {
                version,
                name,
                filename,
                sql,
            });
        }

        Ok(migrations)
    }

    /// Verify that every migration file on disk has a matching applied row in
    /// `_migrations`. Read-only — does not create the `_migrations` table or
    /// modify schema in any way.
    ///
    /// Used by app binaries (api/search/jobs) at startup to refuse to serve
    /// traffic when the schema is behind the binary. The pre-deploy migrator
    /// is responsible for applying migrations; this check is the safety net
    /// that catches a deploy that bypassed it.
    ///
    /// Performs two checks:
    /// 1. **Presence**: every numbered migration file on disk has a row in
    ///    `_migrations` (returns `SchemaBehind { missing }` otherwise).
    /// 2. **Content**: for migrations applied via `apply_migration` (which
    ///    stores a SHA-256 checksum), the checksum on disk matches what was
    ///    recorded at apply time (returns `ChecksumMismatch { drifted }`
    ///    otherwise). Empty checksums (legacy / baseline-seeded rows) skip
    ///    this check — there's no recorded hash to compare against.
    ///
    /// Returns `Err(ClickHouse(...))` if `_migrations` doesn't exist, which
    /// means the pre-deploy migrator has never run successfully.
    pub async fn check_schema_up_to_date(
        &self,
        migrations_dir: &Path,
    ) -> Result<(), ClickHouseMigrateError> {
        use sha2::{Digest, Sha256};

        let expected = Self::load_migrations_from_dir(migrations_dir)?;
        let applied = self.get_applied_migration_checksums().await?;

        let mut missing: Vec<String> = Vec::new();
        let mut drifted: Vec<String> = Vec::new();

        for migration in &expected {
            match applied.get(&migration.version) {
                None => missing.push(migration.filename.clone()),
                Some(stored_checksum) if stored_checksum.is_empty() => {
                    // Legacy or baseline-seeded row — skip content check.
                }
                Some(stored_checksum) => {
                    let file_checksum = hex::encode(Sha256::digest(migration.sql.as_bytes()));
                    if &file_checksum != stored_checksum {
                        drifted.push(migration.filename.clone());
                    }
                }
            }
        }

        if !missing.is_empty() {
            return Err(ClickHouseMigrateError::SchemaBehind { missing });
        }
        if !drifted.is_empty() {
            return Err(ClickHouseMigrateError::ChecksumMismatch { drifted });
        }

        Ok(())
    }

    /// Run all pending migrations from the given directory
    pub async fn run_migrations(
        &mut self,
        migrations_dir: &Path,
    ) -> Result<usize, ClickHouseMigrateError> {
        // Detect if we're on ClickHouse Cloud (affects SQL sanitization)
        let is_cloud = self.detect_cloud().await?;

        // Detect if we're on a cluster (affects DDL transformation)
        let cluster_name = self.detect_cluster().await?;

        // Ensure migrations table exists (cluster-aware)
        self.ensure_migrations_table().await?;

        // Get already applied migrations
        let applied = self.get_applied_migrations().await?;

        // Load migrations from directory
        let migrations = Self::load_migrations_from_dir(migrations_dir)?;

        let mut applied_count = 0;

        for migration in migrations {
            if applied.contains(&migration.version) {
                tracing::debug!(
                    "ClickHouse migration {} already applied, skipping",
                    migration.filename
                );
                continue;
            }

            let mode_label = match (&cluster_name, is_cloud) {
                (Some(c), _) => format!(" [cluster: {}]", c),
                (_, true) => " [cloud mode]".to_string(),
                _ => String::new(),
            };
            tracing::info!(
                "Applying ClickHouse migration: {} ({}){}",
                migration.filename,
                migration.name,
                mode_label
            );

            self.apply_migration(&migration, is_cloud, cluster_name.as_deref())
                .await?;
            self.record_migration(&migration).await?;

            tracing::info!(
                "ClickHouse migration {} applied successfully",
                migration.filename
            );
            applied_count += 1;
        }

        Ok(applied_count)
    }
}
