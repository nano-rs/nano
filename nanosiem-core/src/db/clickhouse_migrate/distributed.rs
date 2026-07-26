// SPDX-License-Identifier: AGPL-3.0-or-later

//! Distributed table management for ClickHouse clusters.

use super::{ClickHouseMigrateError, ClickHouseMigrator};

impl ClickHouseMigrator {
    /// Tables that need Distributed wrappers for cross-shard queries.
    ///
    /// NAN-1728 (L-5/D9): re-exports the **single canonical list** in
    /// `crate::db::dual_pool::DISTRIBUTED_TABLES` so the reconciler's wrapper set
    /// and the read-routing set (`TableNames`) can never drift — they are the
    /// same slice. See that definition for the reference-table rationale
    /// (`custom_enrichment_results` etc. are deliberately absent — cluster-wide
    /// replicated) and the prevalence-summary additions.
    pub(super) const DISTRIBUTED_TABLES: &'static [&'static str] =
        crate::db::dual_pool::DISTRIBUTED_TABLES;

    /// ALIAS / MATERIALIZED columns that must be re-applied to Distributed
    /// wrappers after they've been added to the underlying local table.
    ///
    /// Distributed tables snapshot the column list of `source_table` at
    /// `CREATE TABLE ... AS source_table` time. Any column added to the local
    /// table afterwards (`ALTER TABLE source_table ADD COLUMN ...`) does NOT
    /// propagate. The wrapper has to be ALTERed independently or recreated.
    ///
    /// Format: `(table, column_name, column_definition_after_name)`.
    /// Example: ("logs", "event_type", "LowCardinality(String) ALIAS action").
    pub(super) const DISTRIBUTED_ALIASES: &'static [(&'static str, &'static str, &'static str)] = &[
        // NAN-700 / migration 113: event_type is a read alias for action.
        ("logs", "event_type", "LowCardinality(String) ALIAS action"),
    ];

    /// NAN-2001: (re)create the RESTRICTIVE audit row policies for the
    /// `nanosiem_rawsql_noaudit` identity — the raw-SQL audit boundary. For each
    /// audit-bearing, policy-coverable table it attaches a PERMISSIVE `USING 1`
    /// base policy plus a RESTRICTIVE `lower(<col>) != 'audit'` policy (ClickHouse
    /// ANDs RESTRICTIVE with all access, so a future PERMISSIVE policy on the same
    /// table can never widen it).
    ///
    /// The SELECT grants that form the allowlist come from users.d XML or
    /// [`Self::ensure_rawsql_users`] — a user defined in users.xml cannot receive
    /// a SQL `GRANT` (495 ACCESS_STORAGE_READONLY), but a SQL row policy CAN
    /// target it, so only the policies are created here.
    ///
    /// Topology-aware + drift-proof: the policy attaches to the PHYSICAL,
    /// data-holding table — `<table>_local` when a Distributed-wrapper split
    /// exists (detected at runtime via `system.tables`, robust against wrapper-set
    /// drift between this reconciler and `init-clickhouse-cluster.sh`), else the
    /// bare name — and fans out `ON CLUSTER` on an operator-managed cluster.
    /// Attaching to the physical `_local` (never the Distributed wrapper) is what
    /// makes remote-shard reads honor the policy (handoff §3.5). Idempotent (`OR
    /// REPLACE`); must run AFTER tables (+ any `_local` split) exist. Requires an
    /// access-management client (the migrator's `nanosiem_admin`). Returns the
    /// count of tables a policy pair was applied to.
    ///
    /// DEPLOY INVARIANT (security): the app grants `nanosiem_rawsql_noaudit`
    /// SELECT via declarative config, but AUDIT-HIDING depends on THESE policies.
    /// The app can't self-verify them at boot (the noaudit user can't read
    /// `system.row_policies`, and the raw-SQL-serving search service has no
    /// access-management client), so it trusts this step ran. The migrator is a
    /// REQUIRED init step ordered before the app in every deploy (compose
    /// `depends_on`, k8s migrate-job) and fails closed if a policy can't be
    /// created — so a successful migrator run always leaves the policies in place
    /// before the app serves raw SQL. On a version-skew upgrade, run the CURRENT
    /// migrator (with this step) before the upgraded app, or a noaudit caller
    /// would have grants but no policy → audit leak.
    pub async fn ensure_rawsql_row_policies(&mut self) -> Result<usize, ClickHouseMigrateError> {
        // (table, source-identity column). `identity_observations` retains
        // `source` (renamed from `source_type` by its MV); everything else uses
        // `source_type`. A copy-pasted column here is a SILENT audit leak, so it
        // is picked per table, never templated.
        const RAWSQL_AUDIT_POLICY_TABLES: &[(&str, &str)] = &[
            ("logs", "source_type"),
            ("ocsf_logs", "source_type"),
            ("signals", "source_type"),
            ("identity_observations", "source"),
        ];

        let cluster_name = self.detect_cluster().await?;
        // ON CLUSTER only for an operator-managed explicit cluster. A Replicated
        // database (cluster == db) auto-propagates access-entity DDL; single-node
        // has no cluster. Mirrors `ensure_distributed_tables`.
        let on_cluster = match &cluster_name {
            Some(c) if c != &self.database => format!(" ON CLUSTER '{}'", c),
            _ => String::new(),
        };

        let mut applied = 0usize;
        for &(table, col) in RAWSQL_AUDIT_POLICY_TABLES {
            // Resolve the physical table: prefer `<table>_local` when it exists
            // (Distributed topology), else the bare name (single-node, or an
            // unwrapped per-shard local table).
            let local_name = format!("{}_local", table);
            let local_exists: u64 = self
                .client
                .query(&format!(
                    "SELECT count() FROM system.tables WHERE database = '{}' AND name = '{}'",
                    self.database, local_name
                ))
                .fetch_one()
                .await
                .unwrap_or(0);
            let physical = if local_exists > 0 { local_name.as_str() } else { table };

            let baseline = format!(
                "CREATE ROW POLICY OR REPLACE rawsql_baseline_{name} ON {db}.{tbl}{oc} \
                 USING 1 AS PERMISSIVE TO nanosiem_rawsql_noaudit",
                name = table,
                db = self.database,
                tbl = physical,
                oc = on_cluster,
            );
            let hide_audit = format!(
                "CREATE ROW POLICY OR REPLACE rawsql_hide_audit_{name} ON {db}.{tbl}{oc} \
                 USING lower({col}) != 'audit' AS RESTRICTIVE TO nanosiem_rawsql_noaudit",
                name = table,
                db = self.database,
                tbl = physical,
                oc = on_cluster,
                col = col,
            );

            for sql in [baseline, hide_audit] {
                self.client.query(&sql).execute().await.map_err(|e| {
                    ClickHouseMigrateError::ClickHouse(format!(
                        "creating raw-SQL audit row policy on {}.{}: {}",
                        self.database, physical, e
                    ))
                })?;
            }
            tracing::info!(
                "NAN-2001: raw-SQL audit row policies ensured on {}.{} (source col '{}'){}",
                self.database,
                physical,
                col,
                if on_cluster.is_empty() {
                    ""
                } else {
                    " ON CLUSTER"
                }
            );
            applied += 1;
        }
        Ok(applied)
    }

    /// NAN-2003: bootstrap the two NAN-2001 raw-SQL feature users
    /// (`nanosiem_rawsql` / `nanosiem_rawsql_noaudit`) when they don't already
    /// exist. This is the guarantee that `ensure_rawsql_row_policies` (which
    /// grants row policies TO `nanosiem_rawsql_noaudit`) and the app tier (which
    /// authenticates as both) depend on — and it must run BEFORE the policy step.
    ///
    /// Why it exists: on an EXISTING tenant the users were never created. The
    /// compose `clickhouse-init.sh` `CREATE USER`s them only on a *fresh* CH data
    /// dir; the k8s bootstrap Job was fire-and-forget/non-fatal and raced the
    /// migrate Job. Either way the migrator's policy step then died on
    /// `UNKNOWN_ROLE` and the fail-closed app never started. The migrator runs on
    /// every migrate (before the app in every deploy shape), has the admin
    /// client, so it is the one place that can repair this uniformly.
    ///
    /// Safe across every deploy shape:
    /// - A user is created + granted ONLY if absent from `system.users`. An
    ///   already-present user is left completely untouched — open-core users live
    ///   in `users.xml` storage where a SQL `GRANT` fails `495
    ///   ACCESS_STORAGE_READONLY`, so their grants MUST stay declarative. We only
    ///   ever create+grant the SQL-storage users we own.
    /// - The `rawsql` settings profile is created only when we're about to create
    ///   a user AND it's absent (so open-core, whose users already exist, never
    ///   touches profile DDL — no risk of a spurious migrate failure there).
    /// - Fail-closed: a missing user with no password errors rather than minting a
    ///   blank-password identity. Compose passes the
    ///   `${CLICKHOUSE_RAWSQL_PASSWORD:-${CLICKHOUSE_PASSWORD}}` fallback and k8s
    ///   passes the secret, so a real password is essentially always present.
    /// - Topology-aware `ON CLUSTER` (same gate as the sibling reconcilers).
    ///
    /// Grants mirror the DECLARATIVE allowlists in `dual_pool` (single source of
    /// truth) so a users.xml user and a migrator-created user carry byte-identical
    /// privileges. Returns the number of users this call actually created.
    pub async fn ensure_rawsql_users(
        &mut self,
        rawsql_password: Option<&str>,
        noaudit_password: Option<&str>,
    ) -> Result<usize, ClickHouseMigrateError> {
        let cluster_name = self.detect_cluster().await?;
        // ON CLUSTER only for an operator-managed explicit cluster; a Replicated
        // database auto-propagates access-entity DDL, single-node has no cluster.
        let on_cluster = match &cluster_name {
            Some(c) if c != &self.database => format!(" ON CLUSTER '{}'", c),
            _ => String::new(),
        };

        // (user, password, SELECT allowlist) — the allowlists are the single
        // canonical lists re-used from `dual_pool` so they can never drift.
        let users: [(&str, Option<&str>, &[&str]); 2] = [
            (
                "nanosiem_rawsql",
                rawsql_password,
                crate::db::dual_pool::RAWSQL_ALLOWED_TABLES,
            ),
            (
                "nanosiem_rawsql_noaudit",
                noaudit_password,
                crate::db::dual_pool::RAWSQL_NOAUDIT_ALLOWED_TABLES,
            ),
        ];

        let mut profile_ensured = false;
        let mut created = 0usize;
        for (user, password, tables) in users {
            let exists: u64 = self
                .client
                .query(&format!(
                    "SELECT count() FROM system.users WHERE name = '{}'",
                    user
                ))
                .fetch_one()
                .await
                .map_err(|e| {
                    ClickHouseMigrateError::ClickHouse(format!(
                        "checking whether raw-SQL user '{}' exists: {}",
                        user, e
                    ))
                })?;
            if exists > 0 {
                tracing::info!(
                    "NAN-2003: raw-SQL user '{}' already present — leaving its \
                     declaratively-managed grants untouched",
                    user
                );
                continue;
            }

            let password = password.filter(|p| !p.is_empty()).ok_or_else(|| {
                ClickHouseMigrateError::ClickHouse(format!(
                    "raw-SQL user '{}' is missing and no password is set — refusing to \
                     create a blank-password identity. Set CLICKHOUSE_RAWSQL_PASSWORD / \
                     CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD (they fall back to \
                     CLICKHOUSE_PASSWORD in the shipped compose) so the migrator can \
                     bootstrap it.",
                    user
                ))
            })?;

            // Lazily ensure the `rawsql` profile exists — only when we actually
            // need to create a user, and only if absent (a check, not a
            // permission-dependent IF NOT EXISTS), so the open-core path that
            // skips user creation never runs profile DDL.
            if !profile_ensured {
                let profile_exists: u64 = self
                    .client
                    .query("SELECT count() FROM system.settings_profiles WHERE name = 'rawsql'")
                    .fetch_one()
                    .await
                    .map_err(|e| {
                        ClickHouseMigrateError::ClickHouse(format!(
                            "checking whether raw-SQL settings profile exists: {}",
                            e
                        ))
                    })?;
                if profile_exists == 0 {
                    // Byte-identical to the users.xml / clickhouse-init.sh profile:
                    // readonly=2 lets the app set per-query settings; CONST locks the
                    // security-relevant ones; MAX bounds cap the rest.
                    let profile_sql = format!(
                        "CREATE SETTINGS PROFILE IF NOT EXISTS rawsql{oc} SETTINGS \
                         readonly = 2 CONST, allow_ddl = 0 CONST, \
                         allow_introspection_functions = 0 CONST, \
                         skip_unavailable_shards = 0 CONST, \
                         max_execution_time = 300 MAX 600, \
                         max_result_rows = 1000000 MAX 5000000, \
                         max_threads = 16 MAX 32, \
                         max_memory_usage = 20000000000 MAX 40000000000",
                        oc = on_cluster,
                    );
                    self.client
                        .query(&profile_sql)
                        .execute()
                        .await
                        .map_err(|e| {
                            ClickHouseMigrateError::ClickHouse(format!(
                                "creating raw-SQL settings profile: {}",
                                e
                            ))
                        })?;
                }
                profile_ensured = true;
            }

            let create_sql = format!(
                "CREATE USER IF NOT EXISTS {user}{oc} IDENTIFIED BY ? \
                 SETTINGS PROFILE 'rawsql'",
                user = user,
                oc = on_cluster,
            );
            self.client
                .query(&create_sql)
                .bind(password)
                .execute()
                .await
                .map_err(|e| {
                    ClickHouseMigrateError::ClickHouse(format!(
                        "creating raw-SQL user '{}': {}",
                        user, e
                    ))
                })?;

            let grant_prefix = format!("GRANT{}", on_cluster);
            let mut grant_count = 0usize;
            for table in tables {
                // Match the fresh-tenant init job: clustered deployments use
                // bare Distributed wrappers plus `_local` physical tables and
                // retain legacy `_distributed` aliases. ClickHouse stores a
                // grant by object name even before that object exists, so these
                // three grants are safe on single-node deployments too.
                let local = format!("{}_local", table);
                let distributed = format!("{}_distributed", table);
                for object in [*table, local.as_str(), distributed.as_str()] {
                    let grant_sql = format!(
                        "{prefix} SELECT ON {db}.{tbl} TO {user}",
                        prefix = grant_prefix,
                        db = self.database,
                        tbl = object,
                        user = user,
                    );
                    self.client.query(&grant_sql).execute().await.map_err(|e| {
                        ClickHouseMigrateError::ClickHouse(format!(
                            "granting SELECT on {}.{} to raw-SQL user '{}': {}",
                            self.database, object, user, e
                        ))
                    })?;
                    grant_count += 1;
                }
            }

            created += 1;
            tracing::info!(
                "NAN-2003: created raw-SQL user '{}' with {} SELECT grant(s){}",
                user,
                grant_count,
                if on_cluster.is_empty() {
                    ""
                } else {
                    " ON CLUSTER"
                }
            );
        }

        Ok(created)
    }

    /// Create Distributed table wrappers for cross-shard queries.
    ///
    /// For each data table, creates `{table}_distributed` using Distributed engine.
    /// These tables route queries to all shards transparently.
    /// Only runs in cluster mode; no-op on single-node.
    pub async fn ensure_distributed_tables(&mut self) -> Result<usize, ClickHouseMigrateError> {
        let cluster_name = match self.detect_cluster().await? {
            Some(name) => name,
            None => return Ok(0), // Not a cluster, nothing to do
        };

        // M-9: gate ON CLUSTER exactly like the sibling reconcile fns — a
        // Replicated database (cluster == db) auto-propagates the CREATE, so no
        // explicit clause; an operator-managed explicit cluster needs it to fan
        // the DDL out. (Previously this always emitted ON CLUSTER, diverging from
        // its siblings.)
        let on_cluster = if cluster_name == self.database {
            String::new()
        } else {
            format!(" ON CLUSTER '{}'", cluster_name)
        };

        let mut created = 0;

        for table in Self::DISTRIBUTED_TABLES {
            let dist_name = format!("{}_distributed", table);

            // Check if distributed table already exists. NOTE: this is a
            // create-if-missing path only — it never rewrites an existing
            // wrapper. A wrapper whose sharding key is stale (e.g. the old
            // `rand()` before NAN-1728) is repaired by
            // `reconcile_distributed_columns`, which drops+recreates on
            // sharding-key or type drift. CREATE IF NOT EXISTS here can't do that.
            let exists: u64 = self
                .client
                .query(&format!(
                    "SELECT count() FROM system.tables WHERE database = '{}' AND name = '{}'",
                    self.database, dist_name
                ))
                .fetch_one()
                .await
                .unwrap_or(0);

            if exists > 0 {
                continue;
            }

            // Check if source table exists
            let source_exists: u64 = self
                .client
                .query(&format!(
                    "SELECT count() FROM system.tables WHERE database = '{}' AND name = '{}'",
                    self.database, table
                ))
                .fetch_one()
                .await
                .unwrap_or(0);

            if source_exists == 0 {
                tracing::debug!(
                    "Source table {}.{} doesn't exist, skipping distributed table",
                    self.database,
                    table
                );
                continue;
            }

            let sql = Self::distributed_create_sql(
                &self.database,
                &dist_name,
                &on_cluster,
                &cluster_name,
                table,
                sharding_key_for(table),
            );

            match self.client.query(&sql).execute().await {
                Ok(_) => {
                    tracing::info!(
                        "Created distributed table {}.{} (sharding key {})",
                        self.database,
                        dist_name,
                        sharding_key_for(table)
                    );
                    created += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to create distributed table {}.{}: {}",
                        self.database,
                        dist_name,
                        e
                    );
                }
            }
        }

        if created > 0 {
            tracing::info!("Created {} distributed table(s)", created);
        }
        Ok(created)
    }

    /// Build the `CREATE TABLE ... AS <source> ENGINE = Distributed(...)`
    /// statement for a wrapper. Shared by `ensure_distributed_tables` (initial
    /// create) and `reconcile_distributed_columns` (drift recreate) so both use
    /// the same sharding key + ON CLUSTER form. The Distributed engine's first
    /// arg is the cluster name regardless of ON CLUSTER gating.
    fn distributed_create_sql(
        db: &str,
        dist_name: &str,
        on_cluster: &str,
        cluster_name: &str,
        table: &str,
        sharding_key: &str,
    ) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {db}.{dist}{on_cluster} \
             AS {db}.{table} \
             ENGINE = Distributed('{cluster}', '{db}', '{table}', {key})",
            db = db,
            dist = dist_name,
            on_cluster = on_cluster,
            cluster = cluster_name,
            table = table,
            key = sharding_key,
        )
    }

    /// Sync ALIAS / MATERIALIZED columns from local tables onto their existing
    /// Distributed wrappers (NAN-700).
    ///
    /// Distributed tables don't pick up `ALTER TABLE source ADD COLUMN`
    /// applied to their backing table — the wrapper's column list is fixed
    /// at create time. Without this step, a migration that adds an alias to
    /// `nanosiem.logs` (e.g. migration 113's `event_type ALIAS action`) leaves
    /// `nanosiem.logs_distributed` without that column, and any read query
    /// that references the alias fails with `UNKNOWN_IDENTIFIER` because the
    /// search service queries the wrapper in cluster mode.
    ///
    /// Idempotent — uses `ADD COLUMN IF NOT EXISTS` and pre-checks
    /// `system.columns`. No-op on single-node deployments (no cluster
    /// detected, hence no `_distributed` wrappers).
    pub async fn sync_distributed_aliases(&mut self) -> Result<usize, ClickHouseMigrateError> {
        // `self.database` is configured at migrator startup (CLICKHOUSE_DATABASE
        // env / config), trusted to the same degree as every other DDL string
        // we splice in this module. ClickHouse identifiers can't be supplied
        // via bind parameters, so callers must keep the value to a plain
        // identifier (alphanumeric + underscore).
        debug_assert!(
            is_safe_identifier(&self.database),
            "CLICKHOUSE_DATABASE must be a plain identifier, got: {}",
            self.database
        );

        let cluster_name = match self.detect_cluster().await? {
            Some(name) => name,
            None => return Ok(0),
        };

        // Replicated database (cluster_name == database) auto-propagates DDL
        // without an explicit ON CLUSTER clause — same convention as
        // `transform_for_cluster`. Explicit clusters (e.g. operator's
        // `nanosiem_cluster`) need the clause to fan the ALTER out.
        let on_cluster = if cluster_name == self.database {
            String::new()
        } else {
            format!(" ON CLUSTER '{}'", cluster_name)
        };

        let mut applied = 0;
        for (table, col_name, col_def) in Self::DISTRIBUTED_ALIASES {
            let dist_name = format!("{}_distributed", table);

            let dist_exists: u64 = self
                .client
                .query(&format!(
                    "SELECT count() FROM system.tables WHERE database = '{}' AND name = '{}'",
                    self.database, dist_name
                ))
                .fetch_one()
                .await
                .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;
            if dist_exists == 0 {
                continue;
            }

            // `"table"` is quoted because `table` is a SQL keyword shadowed by
            // the `system.columns.table` column; CH parses it as a column name
            // only when quoted.
            let col_exists: u64 = self
                .client
                .query(&format!(
                    "SELECT count() FROM system.columns WHERE database = '{}' AND \"table\" = '{}' AND name = '{}'",
                    self.database, dist_name, col_name
                ))
                .fetch_one()
                .await
                .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;
            if col_exists > 0 {
                continue;
            }

            let sql = format!(
                "ALTER TABLE {db}.{dist}{on_cluster} ADD COLUMN IF NOT EXISTS {col} {def}",
                db = self.database,
                dist = dist_name,
                on_cluster = on_cluster,
                col = col_name,
                def = col_def,
            );

            match self.client.query(&sql).execute().await {
                Ok(_) => {
                    tracing::info!(
                        "Added alias column {} to {}.{}",
                        col_name,
                        self.database,
                        dist_name
                    );
                    applied += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to add alias column {} to {}.{}: {}",
                        col_name,
                        self.database,
                        dist_name,
                        e
                    );
                }
            }
        }

        if applied > 0 {
            tracing::info!(
                "Synced {} alias column(s) onto distributed wrappers",
                applied
            );
        }
        Ok(applied)
    }

    /// Converge each Distributed wrapper's column set to its backing local table
    /// (NAN-1652 drop half + NAN-1655 add half).
    ///
    /// Distributed wrappers snapshot the source column list at CREATE and don't
    /// track `ALTER TABLE source ADD/DROP COLUMN`. Search queries the wrapper in
    /// cluster mode, so any drift breaks reads with `UNKNOWN_IDENTIFIER`:
    /// - **Drop drift**: a column dropped from the source (e.g. migration 149's
    ///   flexible-enrichment cleanup) lingers on the wrapper; `SELECT *` expands
    ///   it and forwards it to shards that dropped it → every fetch-by-id /
    ///   row-expand `SELECT *, <materialized_cols>` 400s.
    /// - **Add drift**: a column added to the source after the wrapper snapshot
    ///   (e.g. `tags`, `trace_id`, the `process` alias) never reaches the
    ///   wrapper, so `SELECT tags FROM logs_distributed` / an nPL `tags=` filter
    ///   fails on the cluster.
    ///
    /// Both are invisible on single-node (no wrapper), so migrations that only
    /// ALTER the local table pass every test yet break clusters. This makes the
    /// wrapper converge on every migrate: ADD each source column the wrapper
    /// lacks (definition reconstructed from `system.columns`), then DROP each
    /// wrapper column the source no longer has. Idempotent (`ADD/DROP COLUMN IF
    /// [NOT] EXISTS`), no-op on single-node (no cluster detected), non-fatal per
    /// column. This subsumes the hardcoded `DISTRIBUTED_ALIASES` add.
    pub async fn reconcile_distributed_columns(&mut self) -> Result<usize, ClickHouseMigrateError> {
        debug_assert!(
            is_safe_identifier(&self.database),
            "CLICKHOUSE_DATABASE must be a plain identifier, got: {}",
            self.database
        );

        let cluster_name = match self.detect_cluster().await? {
            Some(name) => name,
            None => return Ok(0),
        };

        // Same ON CLUSTER convention as sync_distributed_aliases: a Replicated
        // database (cluster == db) auto-propagates DDL, explicit clusters need
        // the clause to fan the ALTER out to every node's wrapper.
        let on_cluster = if cluster_name == self.database {
            String::new()
        } else {
            format!(" ON CLUSTER '{}'", cluster_name)
        };

        let mut changed = 0;
        for table in Self::DISTRIBUTED_TABLES {
            let dist_name = format!("{}_distributed", table);

            // Wrapper must exist (created by ensure_distributed_tables in
            // cluster mode). `"table"` is quoted because it shadows the
            // system.columns.table column otherwise. Full specs so we can detect
            // TYPE drift on columns present in both (M-1/D4).
            let dist_specs: Vec<(String, String, String, String)> = self
                .client
                .query(&format!(
                    "SELECT name, type, default_kind, default_expression \
                     FROM system.columns WHERE database = '{}' AND \"table\" = '{}'",
                    self.database, dist_name
                ))
                .fetch_all()
                .await
                .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;
            if dist_specs.is_empty() {
                continue;
            }
            let dist_cols: Vec<String> = dist_specs.iter().map(|(n, ..)| n.clone()).collect();

            // Full source specs so a missing column can be re-added with its
            // exact definition (type + DEFAULT/MATERIALIZED/ALIAS expression).
            let source_specs: Vec<(String, String, String, String)> = self
                .client
                .query(&format!(
                    "SELECT name, type, default_kind, default_expression \
                     FROM system.columns WHERE database = '{}' AND \"table\" = '{}'",
                    self.database, table
                ))
                .fetch_all()
                .await
                .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?;
            // A missing/empty source is not a signal to touch the wrapper —
            // skip rather than strip every column.
            if source_specs.is_empty() {
                continue;
            }

            // ── Drift repair: DROP + recreate the wrapper (M-1/D4 + C4/W2) ──
            // Wrappers are metadata-only, so a recreate is cheap and, because it
            // re-runs `CREATE ... AS source`, it also propagates local-table
            // TYPE MODIFYs (e.g. migration 127's `ocsf_logs.timestamp` retype)
            // that plain ADD/DROP-COLUMN can't. Two triggers:
            //   1. Sharding-key drift — the migration that first added the
            //      content-hash key can't rewrite an existing wrapper via CREATE
            //      IF NOT EXISTS, so an old `rand()` wrapper is repaired here
            //      (C4/W2: retries must land on the same shard for block dedup).
            //   2. TYPE drift on a column present in both — the wrapper would
            //      deserialize shard data with the wrong type. (Only TYPE, not
            //      DEFAULT/MATERIALIZED/ALIAS expressions: the wrapper merely
            //      forwards those columns — the expression is evaluated on the
            //      local source — so its own stored expression is not
            //      query-relevant, and comparing it would risk a recreate loop if
            //      `AS source` normalizes expressions differently.)
            // Presence-only differences are left to the idempotent ADD/DROP path
            // below (recreating for those would churn the ALIAS re-add every run).
            let intended_key = sharding_key_for(table);
            let wrapper_create: Option<String> = self
                .client
                .query(&format!(
                    "SELECT create_table_query FROM system.tables \
                     WHERE database = '{}' AND name = '{}'",
                    self.database, dist_name
                ))
                .fetch_all::<String>()
                .await
                .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?
                .into_iter()
                .next();

            let key_drift = wrapper_create
                .as_deref()
                .map(|cq| !wrapper_sharding_key_matches(cq, intended_key))
                .unwrap_or(false);
            let type_drift = columns_type_drift(&dist_specs, &source_specs);

            if key_drift || type_drift {
                let drop_sql = format!(
                    "DROP TABLE IF EXISTS {db}.{dist}{on_cluster}{sync}",
                    db = self.database,
                    dist = dist_name,
                    on_cluster = on_cluster,
                    // SYNC only meaningful/valid with ON CLUSTER; ensures every
                    // node's wrapper is gone before we recreate.
                    sync = if on_cluster.is_empty() { "" } else { " SYNC" },
                );
                let create_sql = Self::distributed_create_sql(
                    &self.database,
                    &dist_name,
                    &on_cluster,
                    &cluster_name,
                    table,
                    intended_key,
                );
                let drop_res = self
                    .client
                    .query(&drop_sql)
                    .execute()
                    .await
                    .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()));
                let recreate_res = match drop_res {
                    Ok(_) => self
                        .client
                        .query(&create_sql)
                        .execute()
                        .await
                        .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string())),
                    Err(e) => Err(e),
                };
                match recreate_res {
                    Ok(_) => {
                        tracing::info!(
                            "Recreated distributed wrapper {}.{} (key_drift={}, type_drift={}, sharding key {})",
                            self.database,
                            dist_name,
                            key_drift,
                            type_drift,
                            intended_key
                        );
                        changed += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to recreate distributed wrapper {}.{}: {}",
                            self.database,
                            dist_name,
                            e
                        );
                    }
                }
                // Fresh wrapper is already fully in sync with the source; skip
                // the ADD/DROP passes for this table.
                continue;
            }

            // ADD source columns the wrapper lacks. ALIAS columns are ordered
            // last so their referenced base columns are already present.
            for (name, typ, kind, expr) in columns_to_add(&dist_cols, &source_specs) {
                // Names are spliced into DDL — keep the module's identifier
                // guard. (`type`/`default_expression` come from ClickHouse's own
                // catalog for our schema, spliced verbatim like the hardcoded
                // `DISTRIBUTED_ALIASES` definitions.)
                if !is_safe_identifier(name) {
                    tracing::warn!(
                        "Skipping reconcile add of non-identifier column {:?} on {}.{}",
                        name,
                        self.database,
                        dist_name
                    );
                    continue;
                }
                let clause = build_add_column_clause(name, typ, kind, expr);
                let sql = format!(
                    "ALTER TABLE {db}.{dist}{on_cluster} ADD COLUMN IF NOT EXISTS {clause}",
                    db = self.database,
                    dist = dist_name,
                    on_cluster = on_cluster,
                    clause = clause,
                );
                match self.client.query(&sql).execute().await {
                    Ok(_) => {
                        tracing::info!(
                            "Added missing column {} to {}.{} (present on source {})",
                            name,
                            self.database,
                            dist_name,
                            table
                        );
                        changed += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to add column {} to {}.{}: {}",
                            name,
                            self.database,
                            dist_name,
                            e
                        );
                    }
                }
            }

            // DROP wrapper columns the source no longer has.
            let source_names: Vec<String> =
                source_specs.iter().map(|(n, ..)| n.clone()).collect();
            for col in stale_wrapper_columns(&dist_cols, &source_names) {
                if !is_safe_identifier(&col) {
                    tracing::warn!(
                        "Skipping reconcile drop of non-identifier column {:?} on {}.{}",
                        col,
                        self.database,
                        dist_name
                    );
                    continue;
                }

                let sql = format!(
                    "ALTER TABLE {db}.{dist}{on_cluster} DROP COLUMN IF EXISTS {col}",
                    db = self.database,
                    dist = dist_name,
                    on_cluster = on_cluster,
                    col = col,
                );

                match self.client.query(&sql).execute().await {
                    Ok(_) => {
                        tracing::info!(
                            "Dropped stale column {} from {}.{} (absent on source {})",
                            col,
                            self.database,
                            dist_name,
                            table
                        );
                        changed += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to drop stale column {} from {}.{}: {}",
                            col,
                            self.database,
                            dist_name,
                            e
                        );
                    }
                }
            }
        }

        if changed > 0 {
            tracing::info!(
                "Reconciled {} column(s) on distributed wrappers",
                changed
            );
        }
        Ok(changed)
    }

    /// Dictionary-refresh MVs whose FROM base reference table must be repointed
    /// to its `_distributed` wrapper on a cluster (NAN-1728 C2), keyed
    /// `(mv_name, base_table)`.
    ///
    /// `init.sql` creates these five refreshable MVs reading the LOCAL base
    /// table. That is mandatory: refreshable-MV DDL validates its FROM source
    /// EAGERLY (unlike `CREATE OR REPLACE DICTIONARY`, which defers binding), and
    /// the `<base>_distributed` wrapper does not exist until
    /// `ensure_distributed_tables` runs — which is AFTER `run_init_sql` /
    /// `run_migrations`. Reading the wrapper at init time would abort cluster boot
    /// with `UNKNOWN_TABLE`.
    const DICT_REFRESH_MV_BASES: &'static [(&'static str, &'static str)] = &[
        ("ip_enrichment_dict_refresh", "ip_enrichments"),
        ("ioc_enrichment_dict_refresh", "custom_enrichment_results"),
        ("custom_enrichment_dict_refresh", "custom_enrichment_results"),
        ("custom_ioc_enrichment_dict_refresh", "custom_enrichment_results"),
        ("user_registry_dict_refresh", "user_registry"),
        // NAN-1732 (P2-D): prevalence finalized-host_count refresh MVs. Their FROM
        // (and the two-step `GLOBAL IN` recent-keys subquery — repoint_from_table
        // rewrites EVERY base reference) reads the *_prevalence_summary_distributed
        // wrapper on clusters so uniqMerge fans in the global count; single-node
        // keeps the local summary. See clickhouse/160_prevalence_finalized_host_count.sql.
        ("hash_prevalence_final_refresh", "hash_prevalence_summary"),
        ("domain_prevalence_final_refresh", "domain_prevalence_summary"),
        ("ip_prevalence_final_refresh", "ip_prevalence_summary"),
    ];

    /// Repoint the dict-refresh MVs' FROM at the reference-table `_distributed`
    /// wrappers, AFTER `ensure_distributed_tables` has created them (NAN-1728 C2 /
    /// P0). This is the second half of the split that keeps cluster boot working:
    /// init.sql creates the MVs reading the LOCAL base (so the eager FROM
    /// validation passes at init time), and this step swaps the FROM to the
    /// wrapper once it exists so each per-node staging dict sees the COMPLETE
    /// cross-shard keyspace (otherwise the per-node dicts silently miss IOCs /
    /// blank `enriched_*` / `user_identity_*` on ~2/3 of rows).
    ///
    /// Cluster-only: on single-node (`detect_cluster() == None`) it is a no-op —
    /// the MVs keep reading the local base (already complete on one shard) and NO
    /// `_distributed` object is ever created or referenced. Idempotent: the body
    /// is read live from `system.tables.as_select` and only rewritten when it
    /// still references the bare local base, so it is safe to run every boot and
    /// re-applies after a drift-repair wrapper recreate. Because the body is taken
    /// verbatim from the deployed MV (which came from init.sql) and only the FROM
    /// table is swapped, the dedup projection can never drift from init.sql.
    /// Non-fatal per MV.
    pub async fn repoint_dict_refresh_mvs_distributed(
        &mut self,
    ) -> Result<usize, ClickHouseMigrateError> {
        debug_assert!(
            is_safe_identifier(&self.database),
            "CLICKHOUSE_DATABASE must be a plain identifier, got: {}",
            self.database
        );

        let cluster_name = match self.detect_cluster().await? {
            Some(name) => name,
            None => return Ok(0),
        };

        // Same ON CLUSTER gating as the sibling reconcile fns (M-9): a Replicated
        // database auto-propagates DDL; an explicit cluster needs the clause to
        // fan the MODIFY QUERY out to every node's MV.
        let on_cluster = if cluster_name == self.database {
            String::new()
        } else {
            format!(" ON CLUSTER '{}'", cluster_name)
        };

        let mut repointed = 0;
        for (mv, base) in Self::DICT_REFRESH_MV_BASES {
            // The MV's current SELECT body, straight from ClickHouse's catalog.
            // `as_select` is the canonical query text CH will accept back verbatim
            // via MODIFY QUERY (which takes the SELECT directly — no `AS`, NAN-1727).
            let body: Option<String> = self
                .client
                .query(&format!(
                    "SELECT as_select FROM system.tables WHERE database = '{}' AND name = '{}'",
                    self.database, mv
                ))
                .fetch_all::<String>()
                .await
                .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?
                .into_iter()
                .next();

            let Some(body) = body else {
                tracing::debug!(
                    "dict-refresh MV {}.{} not present — skipping repoint",
                    self.database,
                    mv
                );
                continue;
            };
            if body.trim().is_empty() {
                continue;
            }

            let Some(new_body) = repoint_from_table(&body, &self.database, base) else {
                // Already reads the wrapper (idempotent) or has no bare base ref.
                continue;
            };

            let sql = format!(
                "ALTER TABLE {db}.{mv}{on_cluster} MODIFY QUERY {query}",
                db = self.database,
                mv = mv,
                on_cluster = on_cluster,
                query = new_body,
            );
            match self.client.query(&sql).execute().await {
                Ok(_) => {
                    tracing::info!(
                        "Repointed dict-refresh MV {}.{} FROM {} -> {}_distributed",
                        self.database,
                        mv,
                        base,
                        base
                    );
                    repointed += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to repoint dict-refresh MV {}.{} to {}_distributed: {}",
                        self.database,
                        mv,
                        base,
                        e
                    );
                }
            }
        }

        if repointed > 0 {
            tracing::info!(
                "Repointed {} dict-refresh MV(s) to _distributed reference-table wrappers",
                repointed
            );
        }
        Ok(repointed)
    }
}

/// Swap a `FROM <db>.<base>` reference in an MV SELECT body to
/// `<db>.<base>_distributed`, boundary-aware so it never matches the
/// already-suffixed `<db>.<base>_distributed`, nor a longer identifier that
/// merely starts with the base name. Returns `None` when the body already
/// references the wrapper (idempotent no-op) or contains no bare reference to the
/// base table — in both cases no MODIFY QUERY is issued.
///
/// Split out so the rewrite is unit-testable without a live cluster.
pub(super) fn repoint_from_table(body: &str, db: &str, base: &str) -> Option<String> {
    let needle = format!("{}.{}", db, base);
    let wrapper = format!("{}.{}_distributed", db, base);
    if body.contains(&wrapper) {
        return None; // already repointed
    }
    let nb = needle.as_bytes();
    let bytes = body.as_bytes();
    let mut out = String::with_capacity(body.len() + 16);
    let mut i = 0;
    let mut replaced = false;
    while i < body.len() {
        if body[i..].starts_with(&needle) {
            let after = bytes.get(i + nb.len()).copied();
            let is_ident =
                matches!(after, Some(c) if c.is_ascii_alphanumeric() || c == b'_');
            if !is_ident {
                out.push_str(&wrapper);
                i += nb.len();
                replaced = true;
                continue;
            }
        }
        let ch = body[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    if replaced {
        Some(out)
    } else {
        None
    }
}

/// Columns present on the Distributed wrapper but absent from its source table.
/// These are stale (the source dropped them) and must be dropped from the
/// wrapper so `SELECT *` doesn't forward a non-existent column to the shards.
///
/// Split out from [`ClickHouseMigrator::reconcile_distributed_columns`] so the
/// set difference is unit-testable without a live cluster.
pub(super) fn stale_wrapper_columns(wrapper: &[String], source: &[String]) -> Vec<String> {
    let source_set: std::collections::HashSet<&str> =
        source.iter().map(String::as_str).collect();
    wrapper
        .iter()
        .filter(|c| !source_set.contains(c.as_str()))
        .cloned()
        .collect()
}

/// Source columns (as `(name, type, default_kind, default_expression)` specs
/// from `system.columns`) that the wrapper is missing and must gain. ALIAS
/// columns are ordered LAST so the base columns they reference are added first.
///
/// Split out so the selection + ordering is unit-testable without a cluster.
pub(super) fn columns_to_add<'a>(
    wrapper: &[String],
    source_specs: &'a [(String, String, String, String)],
) -> Vec<(&'a String, &'a String, &'a String, &'a String)> {
    let wrapper_set: std::collections::HashSet<&str> =
        wrapper.iter().map(String::as_str).collect();
    let mut missing: Vec<_> = source_specs
        .iter()
        .filter(|(name, ..)| !wrapper_set.contains(name.as_str()))
        .map(|(n, t, k, e)| (n, t, k, e))
        .collect();
    // Stable partition: non-ALIAS first, ALIAS last (they reference other cols).
    missing.sort_by_key(|(_, _, kind, _)| kind.as_str() == "ALIAS");
    missing
}

/// Build the `ADD COLUMN` clause body (`name type [DEFAULT|MATERIALIZED|ALIAS
/// expr]`) from a `system.columns` spec. `default_kind` is `''` for a plain
/// column, else `DEFAULT` / `MATERIALIZED` / `ALIAS`.
pub(super) fn build_add_column_clause(
    name: &str,
    typ: &str,
    default_kind: &str,
    default_expr: &str,
) -> String {
    match default_kind {
        "DEFAULT" => format!("{name} {typ} DEFAULT {default_expr}"),
        "MATERIALIZED" => format!("{name} {typ} MATERIALIZED {default_expr}"),
        "ALIAS" => format!("{name} {typ} ALIAS {default_expr}"),
        _ => format!("{name} {typ}"),
    }
}

/// The Distributed-wrapper sharding key for `table` (NAN-1728 C4/W2).
///
/// The sharding key is evaluated per row only for INSERTs routed **through** the
/// `_distributed` wrapper; it does not affect reads. It matters because a
/// committed insert whose HTTP ACK times out is retried on a fresh LB'd
/// connection: with `rand()` the retry scatters to a different shard where
/// ClickHouse's per-shard block dedup can't see the original, so the whole batch
/// duplicates. A **content hash of a stable row id** makes the retry deterministic
/// — it lands on the same shard, and block dedup suppresses it.
///
///   - `logs` / `ocsf_logs` / `signals` / `ingestion_errors`: have a stable `id`
///     UUID column → `cityHash64(id)`. (logs/ocsf_logs are the real write-through
///     lanes — audit durable clone, detection findings, and, post-Phase-3, the
///     Vector sink. signals/ingestion_errors get it for free since they carry an
///     id and it's strictly better than rand() if ever written through a wrapper.)
///   - `otel_spans` / `otel_spans_trace_id_ts`: colocate a whole trace on one
///     shard by `trace_id` → `cityHash64(trace_id)` (no per-row `id`; trace_id is
///     the natural affinity key for trace-assembly reads).
///   - Everything else — the MV-fed aggregate/rollup targets (all `*_prevalence_*`,
///     `entity_time_range_agg`, `entity_dimension_day_agg` +
///     `ocsf_entity_dimension_day_agg`, `cloud_user_activity_agg`,
///     `logs_per_source_5m`, `parser_health_5m`,
///     `identity_observations`, `otel_metrics{,_1m,_1h}`, `otel_service_red_1m`)
///     and the `synthetic_check_results` sample stream — is written to the LOCAL
///     table (by a materialized view or a single-writer scheduler), never through
///     the wrapper, so the wrapper's sharding key is never exercised. Keep
///     `rand()`; there is no cross-connection retry-dedup hazard to defend.
pub(super) fn sharding_key_for(table: &str) -> &'static str {
    match table {
        "logs" | "ocsf_logs" | "signals" | "ingestion_errors" => "cityHash64(id)",
        "otel_spans" | "otel_spans_trace_id_ts" => "cityHash64(trace_id)",
        _ => "rand()",
    }
}

/// True when the existing wrapper's `create_table_query` already uses
/// `intended_key` as its Distributed sharding key. Whitespace- and
/// case-insensitive; scoped to the `Distributed(...)` engine args so a column
/// name can't accidentally match. Returns `false` (→ recreate) when the create
/// query can't be parsed as a Distributed table, which is the safe default.
///
/// Split out so the parse is unit-testable without a live cluster.
pub(super) fn wrapper_sharding_key_matches(create_query: &str, intended_key: &str) -> bool {
    let cq_lower = create_query.to_lowercase();
    let Some(idx) = cq_lower.find("distributed(") else {
        return false;
    };
    let args = &cq_lower[idx + "distributed(".len()..];
    let norm_args: String = args.chars().filter(|c| !c.is_whitespace()).collect();
    let norm_key: String = intended_key
        .to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    // The sharding key is the 4th positional arg — always preceded by the
    // comma after the `'table'` arg. Matching `,<key>` avoids matching a prefix
    // of a longer expression.
    norm_args.contains(&format!(",{}", norm_key))
}

/// True when any column present on BOTH the wrapper and its source has a
/// differing `type` (M-1/D4). Only TYPE is compared — DEFAULT/MATERIALIZED/ALIAS
/// expressions are intentionally ignored (the wrapper forwards the column; the
/// expression is evaluated on the source, so the wrapper's stored expression is
/// not query-relevant and comparing it risks a recreate loop). Columns present
/// on only one side are handled by the idempotent ADD/DROP path, not here.
///
/// Split out so the diff is unit-testable without a live cluster.
pub(super) fn columns_type_drift(
    wrapper_specs: &[(String, String, String, String)],
    source_specs: &[(String, String, String, String)],
) -> bool {
    let src: std::collections::HashMap<&str, &str> = source_specs
        .iter()
        .map(|(n, t, ..)| (n.as_str(), t.as_str()))
        .collect();
    wrapper_specs
        .iter()
        .any(|(n, t, ..)| matches!(src.get(n.as_str()), Some(&st) if st != t.as_str()))
}

/// True when `s` is a plain ClickHouse identifier (alphanumeric + `_`,
/// non-empty, doesn't start with a digit). Used as a debug-only sanity check
/// on the configured database name before splicing it into DDL.
pub(super) fn is_safe_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
