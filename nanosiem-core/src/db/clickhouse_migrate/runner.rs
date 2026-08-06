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

/// NAN-1028 default for ON CLUSTER DDL. Real-world data volumes routinely
/// push a single index drop / materialize past ClickHouse's 180s default.
/// 900s (15min) is generous enough that index churn on multi-shard prod
/// clusters fits inside one statement and still bounds the worst case so a
/// truly stuck DDL doesn't hang the deploy indefinitely.
const DEFAULT_DISTRIBUTED_DDL_TIMEOUT_SECS: u64 = 900;

/// Inject `distributed_ddl_task_timeout = 900` for `ON CLUSTER` DDL when
/// the operator hasn't already specified one. Per-query client setting only —
/// does not change the source file checksum, so checksum verification
/// across tenants is unaffected.
///
/// NAN-1051: applies ONLY to `ALTER TABLE` and `CREATE TABLE` (the long-
/// running cases NAN-1028 was designed for). Other DDL forms — `CREATE
/// DICTIONARY`, `CREATE [MATERIALIZED] VIEW`, `CREATE FUNCTION`, `CREATE
/// NAMED COLLECTION`, etc. — either reject a trailing `SETTINGS` clause
/// outright or have ambiguous grammar, and are all metadata-only operations
/// that complete well inside the 180s default. Whitelisting the two
/// known-safe forms is safer than maintaining a deny-list as ClickHouse
/// grows new DDL grammar.
fn ensure_distributed_ddl_timeout(sql: &str) -> String {
    let sql_upper = sql.to_uppercase();
    if !sql_upper.contains(" ON CLUSTER ") {
        return sql.to_string();
    }
    if sql_upper.contains("DISTRIBUTED_DDL_TASK_TIMEOUT") {
        return sql.to_string();
    }
    let trimmed_upper = sql_upper.trim_start();
    let is_target_ddl = trimmed_upper.starts_with("ALTER TABLE")
        || trimmed_upper.starts_with("CREATE TABLE");
    if !is_target_ddl {
        return sql.to_string();
    }

    // NAN-1487: `ALTER TABLE … MODIFY REFRESH …` (refreshable-MV cadence
    // reschedules, e.g. migration 137) is an ALTER TABLE form whose trailing
    // SETTINGS clause binds to the MV's refresh/table settings, NOT query-level
    // settings — so a `distributed_ddl_task_timeout` there is rejected as
    // UNKNOWN_SETTING (Code 115). It only surfaces on clustered tenants
    // (Saturn): the cluster transform adds `ON CLUSTER`, which is the trigger
    // for injection; single-node boxes never hit it. These reschedules are
    // metadata-only and finish inside the default timeout, so skip injection.
    if trimmed_upper.contains("MODIFY REFRESH") {
        return sql.to_string();
    }

    // NAN-1728 (M-7/D12): `ALTER TABLE <mv> … MODIFY QUERY …` (refreshable /
    // incremental MV redefinition, e.g. migration 156) is an ALTER TABLE form
    // whose trailing text is the MV's SELECT and, crucially, a
    // `SETTINGS distributed_ddl_task_timeout = 900` appended here would be baked
    // INTO the stored MV definition — it binds to the view's query settings, not
    // the DDL execution, so it silently alters MV behavior forever (and CH may
    // reject it outright). Skip injection exactly like MODIFY REFRESH; these
    // redefinitions are metadata-only and finish inside the default timeout.
    if trimmed_upper.contains("MODIFY QUERY") {
        return sql.to_string();
    }

    // Find a top-level SETTINGS clause (not inside parens — e.g. CREATE TABLE
    // column defs / TTL / ENGINE() args may contain `SETTINGS` as a keyword
    // for the engine config; we only want to amend the trailing query-level
    // SETTINGS clause).
    let mut depth: i32 = 0;
    let bytes = sql.as_bytes();
    let upper_bytes = sql_upper.as_bytes();
    let mut top_level_settings: Option<usize> = None;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0
            && i + 10 <= upper_bytes.len()
            && &upper_bytes[i..i + 10] == b" SETTINGS "
        {
            top_level_settings = Some(i);
        }
        i += 1;
    }

    let injection = format!(
        "distributed_ddl_task_timeout = {}",
        DEFAULT_DISTRIBUTED_DDL_TIMEOUT_SECS
    );
    match top_level_settings {
        Some(pos) => {
            // Insert "<injection>, " right after " SETTINGS "
            let insert_at = pos + " SETTINGS ".len();
            let (head, tail) = sql.split_at(insert_at);
            format!("{}{}, {}", head, injection, tail)
        }
        None => format!("{} SETTINGS {}", sql.trim_end_matches(';'), injection),
    }
}

impl ClickHouseMigrator {
    /// Apply a single migration
    async fn apply_migration(
        &self,
        migration: &Migration,
        is_cloud: bool,
        cluster_name: Option<&str>,
    ) -> Result<(), ClickHouseMigrateError> {
        // NAN-788: order matters. Strip `--` line comments BEFORE substituting
        // any credentials — a generated password containing `--` (legitimate
        // base64url) would otherwise look like a comment start and eat the
        // closing `'` of the surrounding literal, corrupting the SQL.
        let migration_sql = Self::strip_sql_line_comments(&migration.sql);

        // Substitute PostgreSQL dictionary connection details from env vars.
        // Defaults match Docker Compose (host='postgres', password='nanosiem').
        let migration_sql = Self::substitute_postgres_vars(&migration_sql);

        // NAN-707: Substitute `{clickhouse_self_*}` placeholders in dict source
        // blocks that reference the local CH instance. Without this, a migration
        // that uses the placeholders gets the literal text and CH rejects it,
        // and a migration with hardcoded creds breaks any tenant whose
        // password is rotated off the default. init.sql has always done this
        // — now numbered migrations do too.
        let migration_sql = Self::substitute_clickhouse_self_vars(&migration_sql);

        // NAN-1728: resolve the `{dist_suffix}` placeholder to `_distributed` on
        // clusters (read the reconciler-created wrapper — fans across shards) or
        // `` on single-node (read the local, complete table). Keyed on the SAME
        // cluster signal the reconciler uses to create the wrappers, so the read
        // target always matches wrapper existence.
        let migration_sql = Self::substitute_dist_suffix(&migration_sql, cluster_name.is_some());

        // NAN-2330: the admin-owned process view reads the local system table on
        // single-node, and fans out only inside its SQL SECURITY DEFINER body on
        // clusters. The runtime user therefore never needs REMOTE.
        let migration_sql =
            Self::substitute_system_processes_source(&migration_sql, cluster_name);

        // NAN-2330: access-control DDL places ON CLUSTER immediately after
        // GRANT. Keep that special syntax explicit to this migration instead of
        // changing every historical GRANT transformed by the migrator.
        let migration_sql = Self::substitute_grant_on_cluster(
            &migration_sql,
            cluster_name,
            &self.database,
            is_cloud,
        );

        // NAN-2330: security-definer DDL follows the configured admin/runtime
        // identities, including renamed BYOC users, with identifier quoting.
        let migration_sql = Self::substitute_clickhouse_users(&migration_sql);
        // NAN-2346: size the prevalence CACHE dicts' SIZE_IN_CELLS to the box.
        // Unset, this resolves to the historical literals, so only tenants whose
        // generated .env carries the vars change behavior.
        let migration_sql = Self::substitute_prevalence_cache_cells(&migration_sql);

        // Sanitize entire migration SQL for CH Cloud before splitting into statements.
        // This strips incompatible settings/index types so the core DDL executes cleanly.
        let migration_sql = if is_cloud {
            Self::sanitize_for_cloud(&migration_sql)
        } else {
            migration_sql
        };

        // Collect SET key=value pairs to append as SETTINGS clause to DDL queries
        let mut settings: Vec<(String, String)> = Vec::new();

        for statement in migration_sql.split(';') {
            let sql = statement.trim();
            if sql.is_empty() {
                continue;
            }

            // Apply cluster transformation if in cluster mode
            let sql = if let Some(cluster) = cluster_name {
                let transformed = Self::transform_for_cluster(sql, cluster, &self.database, is_cloud);
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

            let full_sql = ensure_distributed_ddl_timeout(&full_sql);

            // Some statements may fail on ClickHouse Cloud:
            // - CREATE DICTIONARY: CH Cloud can't reach Docker-internal PostgreSQL
            // - GRANT statements: CH Cloud uses its own permission model
            // Treat these as non-fatal so the rest of the migration proceeds.
            let is_soft_fail = sql_upper.starts_with("CREATE DICTIONARY")
                || sql_upper.starts_with("CREATE OR REPLACE DICTIONARY")
                || sql_upper.starts_with("GRANT ");

            // NAN-1384: profile-gated tables (e.g. nanosiem.ocsf_logs, which
            // only exists on NANO_SCHEMA_PROFILE=ocsf deployments) cannot be
            // guarded in SQL — ClickHouse has no `ALTER TABLE IF EXISTS`. A
            // statement carrying the `nano:skip-if-unknown-table` block-comment
            // marker is skipped when its target table does not exist, instead
            // of failing the whole migration run. Any OTHER error on the same
            // statement still aborts (the marker only tolerates absence).
            let skip_if_unknown_table = Self::has_skip_if_unknown_table_marker(&sql);

            match self.client.query(&full_sql).execute().await {
                Ok(_) => {}
                Err(e) if skip_if_unknown_table && Self::is_unknown_table_error(&e.to_string()) => {
                    tracing::warn!(
                        "Migration statement skipped (target table absent on this \
                         deployment profile): {} - {}",
                        migration.filename,
                        e
                    );
                    continue;
                }
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
    /// Parse the target table identifier from a `CREATE TABLE [IF NOT EXISTS]
    /// <name>` statement (handles an optional `db.table` qualifier, backticks,
    /// and a trailing `(` or `ON CLUSTER`). Returns `None` if the statement
    /// isn't a CREATE TABLE. (NAN-1115)
    pub(crate) fn parse_create_table_name(stmt: &str) -> Option<String> {
        let upper = stmt.to_uppercase();
        let after = if let Some(i) = upper.find("CREATE TABLE IF NOT EXISTS ") {
            &stmt[i + "CREATE TABLE IF NOT EXISTS ".len()..]
        } else if let Some(i) = upper.find("CREATE TABLE ") {
            &stmt[i + "CREATE TABLE ".len()..]
        } else {
            return None;
        };
        let token: String = after
            .trim_start()
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != '(')
            .collect();
        let name = token.replace('`', "");
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    /// Best-effort `EXISTS TABLE` check for a CREATE TABLE statement's target.
    /// Used by `run_init_sql` to tell a real schema failure apart from CH merely
    /// re-validating an already-existing table's dict-backed MATERIALIZED
    /// defaults against a transiently-FAILED dictionary (NAN-1115).
    async fn create_table_target_exists(&self, create_stmt: &str) -> bool {
        let Some(name) = Self::parse_create_table_name(create_stmt) else {
            return false;
        };
        let qualified = if name.contains('.') {
            name
        } else {
            format!("{}.{}", self.database, name)
        };
        matches!(
            self.client
                .query(&format!("EXISTS TABLE {}", qualified))
                .fetch_all::<u8>()
                .await,
            Ok(rows) if rows.first().copied() == Some(1)
        )
    }

    /// NAN-1116: report any FAILED ClickHouse dictionaries, loudly. A FAILED
    /// dictionary referenced by a `dictGet()`-backed MATERIALIZED column (the
    /// `nanosiem.logs` `ioc_*`/`enriched_*`/`user_identity_*` columns) makes the
    /// lookup THROW on every INSERT, so 100% of ingestion is dropped (Vector's
    /// buffer discards on the resulting 500s) with nothing surfaced in the app
    /// logs — only in `system.query_log`. Logging FAILED dicts at the end of
    /// every migrate turns that silent outage into a visible deploy-log error.
    /// Returns the count of FAILED dictionaries (0 = healthy). Never fails the
    /// migrate — failing here would re-create the very deadlock NAN-1115 fixes.
    pub async fn report_failed_dictionaries(&self) -> usize {
        let rows: Vec<String> = self
            .client
            .query(&format!(
                "SELECT concat(database, '.', name, ' :: ', substring(last_exception, 1, 200)) \
                 FROM system.dictionaries WHERE database = '{}' AND status = 'FAILED'",
                self.database
            ))
            .fetch_all::<String>()
            .await
            .unwrap_or_default();
        if rows.is_empty() {
            tracing::info!("ClickHouse dictionaries: all healthy");
        } else {
            tracing::error!(
                count = rows.len(),
                "FAILED ClickHouse dictionaries detected — every INSERT into a table with a \
                 dictGet()-backed MATERIALIZED column on these will be dropped until they load \
                 (NAN-1116)"
            );
            for r in &rows {
                tracing::error!("  FAILED dict: {}", r);
            }
        }
        rows.len()
    }

    /// Shared implementation for `run_init_sql` (the primary schema) and
    /// `run_overlay_init_sql` (profile overlays like OCSF). `version_key` is the
    /// `_migrations` row the SHA-256 idempotency hash is stored under, `label`
    /// is the human name used in logs, and `seed_baseline` controls whether the
    /// numbered-migration baseline is seeded afterward (only the primary init
    /// does this — an overlay merely adds profile-specific objects on top of an
    /// already-seeded schema).
    async fn run_init_sql_inner(
        &mut self,
        init_sql: &str,
        version_key: &str,
        label: &str,
        seed_baseline: bool,
    ) -> Result<(), ClickHouseMigrateError> {
        let is_cloud = self.detect_cloud().await?;
        let cluster_name = self.detect_cluster().await?;

        let mode_label = match (&cluster_name, is_cloud) {
            (Some(c), _) => format!(" [cluster: {}]", c),
            (_, true) => " [cloud mode]".to_string(),
            _ => String::new(),
        };

        // Check if the script has changed since last run by comparing SHA-256
        // hashes. The hash is stored in the _migrations table under version_key.
        use sha2::{Sha256, Digest};
        let hash = hex::encode(Sha256::digest(init_sql.as_bytes()));

        self.ensure_migrations_table().await?;

        let stored_hash: Option<String> = self
            .client
            .query(&format!(
                "SELECT checksum FROM {}._migrations WHERE version = '{}' LIMIT 1",
                self.database, version_key
            ))
            .fetch_all::<String>()
            .await
            .ok()
            .and_then(|rows| rows.into_iter().next());

        if stored_hash.as_deref() == Some(hash.as_str()) {
            tracing::info!("{} unchanged (hash match) — skipping{}", label, mode_label);
            return Ok(());
        }

        tracing::info!("Running {}{}", label, mode_label);

        // NAN-788: strip `--` line comments BEFORE substitution so a generated
        // password containing `--` can't be misread as a comment start. See
        // sql_transform::strip_sql_line_comments for the full rationale.
        let sql = Self::strip_sql_line_comments(init_sql);

        // Substitute placeholders that point at the local CH instance and the
        // platform PostgreSQL. NAN-707 lifted the CH-self substitution out of
        // this function so numbered migrations share the same helper.
        let sql = Self::substitute_clickhouse_self_vars(&sql);
        let sql = Self::substitute_postgres_vars(&sql);
        // NAN-1728: topology-correct `{dist_suffix}` read target. See
        // substitute_dist_suffix. `cluster_name.is_some()` is the same signal
        // that gates wrapper creation.
        let sql = Self::substitute_dist_suffix(&sql, cluster_name.is_some());
        // NAN-2346: box-sized prevalence CACHE dict SIZE_IN_CELLS. Must run on the
        // init.sql path too — a fresh bootstrap creates these dicts from init.sql,
        // never from the numbered migration.
        let sql = Self::substitute_prevalence_cache_cells(&sql);

        // Sanitize for cloud if needed
        let sql = if is_cloud {
            Self::sanitize_for_cloud(&sql)
        } else {
            sql
        };

        let mut settings: Vec<(String, String)> = Vec::new();

        for statement in sql.split(';') {
            let sql_stmt = statement.trim();
            if sql_stmt.is_empty() {
                continue;
            }

            // Apply cluster transformation
            let sql_stmt = if let Some(ref cluster) = cluster_name {
                let transformed = Self::transform_for_cluster(sql_stmt, cluster, &self.database, is_cloud);
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

            let full_sql = ensure_distributed_ddl_timeout(&full_sql);

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
                    // NAN-1115: a `CREATE TABLE [IF NOT EXISTS]` can fail during
                    // init.sql not because of a real schema problem but because
                    // ClickHouse re-validates the table's dict-backed
                    // MATERIALIZED column DEFAULTs at CREATE time, and a
                    // referenced dictionary is currently FAILED (e.g. a
                    // PG-sourced dict whose creds broke). The table already
                    // exists, so the statement is a logical no-op — letting it
                    // abort would block the WHOLE migrate and the deploy gated
                    // on it, and the numbered migration that repairs the dict
                    // never gets to run (init.sql runs first). If the target
                    // table already exists, downgrade to a warning and continue.
                    if sql_upper.starts_with("CREATE TABLE")
                        && self.create_table_target_exists(&sql_stmt).await
                    {
                        tracing::warn!(
                            "Init SQL CREATE TABLE failed but the table already exists — \
                             continuing (likely a FAILED dependent dictionary re-validated \
                             at CREATE time; see NAN-1115): {} - {}",
                            &sql_stmt[..sql_stmt.len().min(120)],
                            e
                        );
                    } else {
                        return Err(ClickHouseMigrateError::ClickHouse(format!(
                            "Failed to execute init SQL: {} - Error: {}",
                            &sql_stmt[..sql_stmt.len().min(120)],
                            e
                        )));
                    }
                }
            }
        }

        tracing::info!("{} completed successfully", label);

        // Store the hash so we can skip this script on next startup
        let upsert_sql = format!(
            "INSERT INTO {}._migrations (version, name, checksum) VALUES ('{}', '{}', '{}')",
            self.database, version_key, label, hash
        );
        // Use ALTER + DELETE for replicated tables (no REPLACE INTO in ClickHouse).
        //
        // NAN-1728 (W11): on an explicit operator-managed cluster the DELETE must
        // be ON CLUSTER so the mutation is submitted on every node. `_migrations`
        // is now cluster-wide replicated (one group across all shards, see
        // `ensure_migrations_table`), so the INSERT below replicates on its own;
        // but a bare ALTER … DELETE only issues the mutation on the connected
        // node's replica set — ON CLUSTER guarantees it fans out. Cloud /
        // Replicated-database mode auto-propagates DDL, so no clause there
        // (matching `ensure_migrations_table` / `transform_for_cluster` gating).
        let migrations_on_cluster = match cluster_name.as_ref() {
            Some(c) if !is_cloud && c != &self.database => format!(" ON CLUSTER '{}'", c),
            _ => String::new(),
        };
        let delete_sql = format!(
            "ALTER TABLE {}._migrations{} DELETE WHERE version = '{}'",
            self.database, migrations_on_cluster, version_key
        );
        // Best-effort: don't fail startup if hash storage fails
        let _ = self.client.query(&delete_sql).execute().await;
        if let Err(e) = self.client.query(&upsert_sql).execute().await {
            tracing::warn!("Failed to store {} hash: {} — next startup will re-run it", label, e);
        }

        // Seed baseline migrations on fresh deployments so the runner
        // won't try to re-apply migrations already baked into init.sql.
        // Overlays skip this — the primary init already seeded the baseline.
        if seed_baseline {
            let seeded = self.seed_baseline_migrations().await?;
            if seeded > 0 {
                tracing::info!(
                    "Fresh deployment detected — seeded {} baseline migrations",
                    seeded
                );
            }
        }

        Ok(())
    }

    /// Run the primary `init.sql` schema: hash-tracked under `__init_sql` and
    /// followed by baseline-migration seeding. The canonical entry point used
    /// by every deployment regardless of schema profile.
    pub async fn run_init_sql(&mut self, init_sql: &str) -> Result<(), ClickHouseMigrateError> {
        self.run_init_sql_inner(init_sql, "__init_sql", "init.sql", true)
            .await
    }

    /// Apply a profile-overlay init script (e.g. `clickhouse/ocsf/init.sql`) on
    /// top of the primary schema. Tracked under its own `version_key` so it
    /// never clobbers the `__init_sql` hash, and does NOT seed baseline
    /// migrations — the overlay only adds profile-specific objects (OCSF
    /// tables/MVs) and relies on the shared dictionaries/`signals` already
    /// created by `run_init_sql` + the numbered migrations. Must run AFTER
    /// those so the overlay's `dictGet`-backed columns resolve.
    pub async fn run_overlay_init_sql(
        &mut self,
        init_sql: &str,
        version_key: &str,
        label: &str,
    ) -> Result<(), ClickHouseMigrateError> {
        self.run_init_sql_inner(init_sql, version_key, label, false)
            .await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_cluster_ddl_is_unchanged() {
        let sql = "ALTER TABLE nanosiem.logs DROP INDEX IF EXISTS idx_foo";
        assert_eq!(ensure_distributed_ddl_timeout(sql), sql);
    }

    #[test]
    fn cluster_ddl_without_settings_gets_timeout_appended() {
        // NAN-1028 repro: this exact statement timed out at 180s on Saturn
        // and Hetzner org while dropping a real idx_ext_text.
        let sql = "ALTER TABLE nanosiem.logs ON CLUSTER 'default' DROP INDEX IF EXISTS idx_ext_text";
        let out = ensure_distributed_ddl_timeout(sql);
        assert_eq!(
            out,
            "ALTER TABLE nanosiem.logs ON CLUSTER 'default' DROP INDEX IF EXISTS idx_ext_text \
             SETTINGS distributed_ddl_task_timeout = 900"
        );
    }

    #[test]
    fn cluster_ddl_with_existing_settings_gets_timeout_prepended() {
        let sql = "ALTER TABLE x ON CLUSTER 'default' MODIFY COLUMN y Int32 SETTINGS mutations_sync = 2";
        let out = ensure_distributed_ddl_timeout(sql);
        assert_eq!(
            out,
            "ALTER TABLE x ON CLUSTER 'default' MODIFY COLUMN y Int32 \
             SETTINGS distributed_ddl_task_timeout = 900, mutations_sync = 2"
        );
    }

    #[test]
    fn cluster_ddl_with_caller_supplied_timeout_is_untouched() {
        // If the migration author already wrote SET distributed_ddl_task_timeout=…
        // (or pasted it inline), trust that decision.
        let sql = "ALTER TABLE x ON CLUSTER 'default' DROP INDEX idx_foo SETTINGS distributed_ddl_task_timeout = 60";
        assert_eq!(ensure_distributed_ddl_timeout(sql), sql);
    }

    #[test]
    fn settings_keyword_inside_parens_is_ignored() {
        // `SETTINGS` is also valid syntax inside CREATE TABLE engine config —
        // we must amend the trailing query-level SETTINGS clause, not append
        // inside the engine() parens.
        let sql = "CREATE TABLE x ON CLUSTER 'default' (a Int32) \
                   ENGINE = MergeTree() ORDER BY a SETTINGS index_granularity = 8192";
        let out = ensure_distributed_ddl_timeout(sql);
        assert!(
            out.contains("distributed_ddl_task_timeout = 900, index_granularity = 8192"),
            "expected timeout to be folded into trailing SETTINGS, got: {out}"
        );
    }

    #[test]
    fn non_table_ddl_on_cluster_is_not_amended() {
        // NAN-1051 regression: only ALTER TABLE / CREATE TABLE accept a trailing
        // `SETTINGS distributed_ddl_task_timeout = ...` clause. Other DDL forms
        // either reject it outright (DICTIONARY, FUNCTION, NAMED COLLECTION) or
        // have ambiguous grammar (MATERIALIZED VIEW with TO target). All of
        // these are metadata-only and don't need the 900s timeout — leave them
        // untouched.
        let cases = [
            // CREATE DICTIONARY — grammar ends with SOURCE / LAYOUT / LIFETIME / RANGE.
            "CREATE DICTIONARY IF NOT EXISTS nanosiem.ip_enrichment_dict \
             ON CLUSTER 'default' (network String) PRIMARY KEY network \
             SOURCE(POSTGRESQL()) LIFETIME(MIN 300 MAX 600) LAYOUT(IP_TRIE())",
            "CREATE OR REPLACE DICTIONARY nanosiem.hash_prevalence_dict \
             ON CLUSTER 'default' (file_hash String, host_count UInt32) \
             PRIMARY KEY file_hash SOURCE(CLICKHOUSE()) \
             LIFETIME(MIN 300 MAX 600) LAYOUT(HASHED())",
            // CREATE MATERIALIZED VIEW with TO target — trailing SETTINGS would
            // be ambiguous (query-level vs engine-level).
            "CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.foo_mv \
             ON CLUSTER 'default' TO nanosiem.foo_agg AS SELECT 1",
            // CREATE FUNCTION — no SETTINGS clause in grammar.
            "CREATE FUNCTION ON CLUSTER 'default' my_fn AS (x) -> x + 1",
            // CREATE NAMED COLLECTION — no SETTINGS clause in grammar.
            "CREATE NAMED COLLECTION foo ON CLUSTER 'default' AS host = 'localhost'",
        ];
        for sql in cases {
            assert_eq!(
                ensure_distributed_ddl_timeout(sql),
                sql,
                "non-table DDL should be left untouched: {sql}"
            );
        }
    }

    #[test]
    fn modify_refresh_on_cluster_is_not_amended() {
        // NAN-1487 repro: migration 137 reschedules refreshable-MV cadences.
        // The cluster transform makes each `ON CLUSTER`, and an injected
        // `SETTINGS distributed_ddl_task_timeout = 900` binds to the MV's
        // refresh settings → CH rejects it as UNKNOWN_SETTING. Must stay
        // verbatim despite being an `ALTER TABLE … ON CLUSTER` statement.
        let cases = [
            "ALTER TABLE nanosiem.ip_enrichment_dict_refresh ON CLUSTER 'default' MODIFY REFRESH EVERY 6 HOUR",
            "ALTER TABLE nanosiem.user_registry_dict_refresh ON CLUSTER 'default' MODIFY REFRESH EVERY 1 HOUR",
        ];
        for sql in cases {
            assert_eq!(
                ensure_distributed_ddl_timeout(sql),
                sql,
                "MODIFY REFRESH must not get a query-level SETTINGS clause: {sql}"
            );
        }
    }

    #[test]
    fn modify_query_on_cluster_is_not_amended() {
        // NAN-1728 (M-7/D12): `ALTER TABLE <mv> … MODIFY QUERY …` (migration 156)
        // redefines the MV's SELECT. An injected `SETTINGS
        // distributed_ddl_task_timeout = 900` would bind to / be baked into the
        // stored MV query, not the DDL execution — must stay verbatim despite
        // being an `ALTER TABLE … ON CLUSTER` statement.
        let cases = [
            "ALTER TABLE nanosiem.otel_service_red_1m_mv ON CLUSTER 'default' MODIFY QUERY SELECT 1",
            "ALTER TABLE nanosiem.foo_mv ON CLUSTER 'default' MODIFY QUERY SELECT a, b FROM nanosiem.logs",
        ];
        for sql in cases {
            assert_eq!(
                ensure_distributed_ddl_timeout(sql),
                sql,
                "MODIFY QUERY must not get a query-level SETTINGS clause: {sql}"
            );
        }
    }

    #[test]
    fn no_settings_clause_keeps_existing_terminator_handled() {
        // Some statements may arrive with a trailing semicolon from a careless
        // split — we strip it before appending SETTINGS so the result is a
        // valid single statement.
        let sql = "ALTER TABLE x ON CLUSTER 'default' DROP INDEX idx_foo;";
        let out = ensure_distributed_ddl_timeout(sql);
        assert!(out.ends_with("distributed_ddl_task_timeout = 900"));
        assert!(!out.contains("; SETTINGS"));
    }
}
