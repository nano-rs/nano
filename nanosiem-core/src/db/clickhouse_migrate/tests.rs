// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for ClickHouse migration system.

#[cfg(test)]
mod tests {
    use crate::db::clickhouse_migrate::*;
    use std::io::Write;
    use std::path::Path;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static CLICKHOUSE_SELF_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn database_bootstrap_is_cluster_wide_only_for_explicit_clusters() {
        let client = clickhouse::Client::default();
        let mut migrator = ClickHouseMigrator::new(client, "nanosiem");
        assert_eq!(
            migrator.database_bootstrap_sql(),
            "CREATE DATABASE IF NOT EXISTS nanosiem"
        );
        assert!(migrator.database_bootstrap_visibility_sql().is_none());

        migrator.cluster = Some(Some("default".to_string()));
        assert_eq!(
            migrator.database_bootstrap_sql(),
            "CREATE DATABASE IF NOT EXISTS nanosiem ON CLUSTER 'default'"
        );
        assert_eq!(
            migrator.database_bootstrap_visibility_sql().as_deref(),
            Some(
                "SELECT countIf(name = 'nanosiem') AS visible_nodes, uniqExact(shardNum()) AS answering_nodes, (SELECT count() FROM system.clusters WHERE cluster = 'default' AND (database_replica_name = '' OR (SELECT countIf(database_replica_name = '') FROM system.clusters WHERE cluster = 'default') = 0)) AS expected_nodes FROM clusterAllReplicas('default', system.databases)"
            )
        );

        migrator.cluster = Some(Some("nanosiem".to_string()));
        assert_eq!(
            migrator.database_bootstrap_sql(),
            "CREATE DATABASE IF NOT EXISTS nanosiem"
        );
        assert!(migrator.database_bootstrap_visibility_sql().is_none());

        migrator.cluster = Some(Some("default".to_string()));
        migrator.is_cloud = Some(true);
        assert_eq!(
            migrator.database_bootstrap_sql(),
            "CREATE DATABASE IF NOT EXISTS nanosiem"
        );
        assert!(migrator.database_bootstrap_visibility_sql().is_none());
    }

    /// NAN-700: every entry in `DISTRIBUTED_ALIASES` must reference a table
    /// that has a `_distributed` wrapper. Otherwise `sync_distributed_aliases`
    /// would silently never run for that entry.
    #[test]
    fn distributed_aliases_reference_known_distributed_tables() {
        for (table, col, _def) in ClickHouseMigrator::DISTRIBUTED_ALIASES {
            assert!(
                ClickHouseMigrator::DISTRIBUTED_TABLES.contains(table),
                "DISTRIBUTED_ALIASES references {}.{}, but {} has no _distributed wrapper",
                table,
                col,
                table
            );
        }
    }

    /// NAN-700: `is_safe_identifier` must accept the kinds of database names
    /// real deployments use (`nanosiem`, `nanosiem_cloud`) and reject anything
    /// that could break out of the splicing context where it's used.
    #[test]
    fn is_safe_identifier_accepts_real_db_names_and_rejects_injections() {
        use crate::db::clickhouse_migrate::distributed::is_safe_identifier;
        assert!(is_safe_identifier("nanosiem"));
        assert!(is_safe_identifier("nanosiem_prod"));
        assert!(is_safe_identifier("_underscore_lead"));
        assert!(is_safe_identifier("db123"));
        assert!(!is_safe_identifier(""));
        assert!(!is_safe_identifier("123db"));
        assert!(!is_safe_identifier("foo bar"));
        assert!(!is_safe_identifier("foo'; DROP TABLE x;--"));
        assert!(!is_safe_identifier("foo.bar"));
        assert!(!is_safe_identifier("foo`bar"));
    }

    /// NAN-1668 (audit gap G4): `reconcile_distributed_columns` fixes wrapper
    /// column drift by iterating `DISTRIBUTED_TABLES`, so a table is only
    /// protected from `_distributed` ALTER-drift if it's in that list. The
    /// prevalence/risk audit flagged `signals` and the three `*_prevalence_agg`
    /// tables as the drift-prone ones (they take ALTERs and are queried across
    /// shards). Pin them here so a future refactor can't silently drop them from
    /// reconciliation and reopen the gap.
    #[test]
    fn drift_prone_tables_are_reconciled_by_distributed_columns() {
        for table in [
            "signals",
            "domain_prevalence_agg",
            "hash_prevalence_agg",
            "ip_prevalence_agg",
        ] {
            assert!(
                ClickHouseMigrator::DISTRIBUTED_TABLES.contains(&table),
                "{table} must stay in DISTRIBUTED_TABLES so reconcile_distributed_columns \
                 keeps its cluster wrapper free of ALTER-drift (NAN-1668 / audit gap G4)"
            );
        }
    }

    /// NAN-1652: `stale_wrapper_columns` returns exactly the columns present on
    /// the Distributed wrapper but gone from the source table — the set the
    /// reconcile step must drop. This is the flexible-enrichment repro:
    /// migration 149 dropped `enrichment_label_*` / `enrichment_value_*` from
    /// `logs` but the wrapper kept them.
    #[test]
    fn stale_wrapper_columns_returns_wrapper_only_columns() {
        use crate::db::clickhouse_migrate::distributed::stale_wrapper_columns;
        let s = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();

        let wrapper = s(&[
            "id",
            "timestamp",
            "message",
            "enrichment_label_1",
            "enrichment_value_1",
            "event_type", // alias present on both — must NOT be dropped
        ]);
        let source = s(&["id", "timestamp", "message", "event_type"]);

        let mut stale = stale_wrapper_columns(&wrapper, &source);
        stale.sort();
        assert_eq!(stale, s(&["enrichment_label_1", "enrichment_value_1"]));
    }

    /// A wrapper already in sync with its source yields nothing to drop — the
    /// reconcile is idempotent and a converged cluster does no work.
    #[test]
    fn stale_wrapper_columns_empty_when_in_sync() {
        use crate::db::clickhouse_migrate::distributed::stale_wrapper_columns;
        let s = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let cols = s(&["id", "timestamp", "message"]);
        assert!(stale_wrapper_columns(&cols, &cols).is_empty());
        // The wrapper never dictates additions here — columns the source has
        // but the wrapper lacks are NOT returned (that's the alias-sync path).
        assert!(stale_wrapper_columns(&s(&["id"]), &s(&["id", "new_col"])).is_empty());
    }

    /// NAN-1655: `columns_to_add` returns source columns the wrapper lacks, with
    /// ALIAS columns ordered LAST so their referenced base columns are added
    /// first. Repro of the Saturn add-drift (`process` ALIAS, `tags` DEFAULT).
    #[test]
    fn columns_to_add_returns_missing_source_columns_alias_last() {
        use crate::db::clickhouse_migrate::distributed::columns_to_add;
        let spec = |n: &str, t: &str, k: &str, e: &str| {
            (n.to_string(), t.to_string(), k.to_string(), e.to_string())
        };
        let wrapper = vec!["id".to_string(), "command_line".to_string()];
        let source = vec![
            spec("id", "UUID", "", ""),
            spec("command_line", "String", "", ""),
            spec("process", "String", "ALIAS", "command_line"), // missing, ALIAS
            spec("tags", "Array(String)", "DEFAULT", "[]"),      // missing, DEFAULT
        ];
        let add = columns_to_add(&wrapper, &source);
        let names: Vec<&str> = add.iter().map(|(n, ..)| n.as_str()).collect();
        // Only the two missing; ALIAS (`process`) sorted after the DEFAULT.
        assert_eq!(names, vec!["tags", "process"]);
    }

    /// NAN-1655: the ADD clause reconstructs each `system.columns` default_kind.
    #[test]
    fn build_add_column_clause_covers_every_kind() {
        use crate::db::clickhouse_migrate::distributed::build_add_column_clause;
        assert_eq!(build_add_column_clause("span_id", "String", "", ""), "span_id String");
        assert_eq!(
            build_add_column_clause("tags", "Array(String)", "DEFAULT", "[]"),
            "tags Array(String) DEFAULT []"
        );
        assert_eq!(
            build_add_column_clause("process", "String", "ALIAS", "command_line"),
            "process String ALIAS command_line"
        );
        assert_eq!(
            build_add_column_clause("enr", "String", "MATERIALIZED", "dictGet('d','k',x)"),
            "enr String MATERIALIZED dictGet('d','k',x)"
        );
    }

    #[test]
    fn test_load_migrations_from_dir() {
        let temp_dir = TempDir::new().unwrap();

        // Create test migration files
        let mut file1 = std::fs::File::create(temp_dir.path().join("001_init.sql")).unwrap();
        writeln!(file1, "CREATE TABLE test1 (id Int32);").unwrap();

        let mut file2 = std::fs::File::create(temp_dir.path().join("002_add_column.sql")).unwrap();
        writeln!(file2, "ALTER TABLE test1 ADD COLUMN name String;").unwrap();

        // Create a non-sql file that should be ignored
        std::fs::File::create(temp_dir.path().join("readme.md")).unwrap();

        let migrations = ClickHouseMigrator::load_migrations_from_dir(temp_dir.path()).unwrap();

        assert_eq!(migrations.len(), 2);
        assert_eq!(migrations[0].version, "001");
        assert_eq!(migrations[0].name, "init");
        assert_eq!(migrations[1].version, "002");
        assert_eq!(migrations[1].name, "add_column");
    }

    #[test]
    fn test_load_migrations_skips_init_sql_and_non_numbered_files() {
        // Repro for NAN-606: when the runner is pointed at the same dir
        // that holds init.sql, init.sql must NOT be picked up as a migration
        // (it's loaded separately via run_init_sql). Same for any non-numbered
        // SQL co-resident in the dir.
        let temp_dir = TempDir::new().unwrap();

        let mut valid = std::fs::File::create(temp_dir.path().join("109_real_migration.sql")).unwrap();
        writeln!(valid, "CREATE TABLE foo (id Int32);").unwrap();

        // Sub-migration form (e.g. 075a_*.sql) must still load.
        let mut sub = std::fs::File::create(temp_dir.path().join("075a_sub_migration.sql")).unwrap();
        writeln!(sub, "ALTER TABLE foo ADD COLUMN bar String;").unwrap();

        // Files that must be skipped:
        std::fs::File::create(temp_dir.path().join("init.sql")).unwrap();
        std::fs::File::create(temp_dir.path().join("README.md")).unwrap();
        std::fs::File::create(temp_dir.path().join("prevalence_tracking.sql")).unwrap();
        std::fs::File::create(temp_dir.path().join("notes.txt")).unwrap();

        let migrations = ClickHouseMigrator::load_migrations_from_dir(temp_dir.path()).unwrap();

        assert_eq!(
            migrations.len(),
            2,
            "Only numbered migrations should load, got: {:?}",
            migrations.iter().map(|m| &m.filename).collect::<Vec<_>>()
        );
        // Sorted by filename, so "075a..." comes before "109..."
        assert_eq!(migrations[0].version, "075a");
        assert_eq!(migrations[1].version, "109");
    }

    #[test]
    fn test_load_migrations_empty_dir() {
        let temp_dir = TempDir::new().unwrap();
        let migrations = ClickHouseMigrator::load_migrations_from_dir(temp_dir.path()).unwrap();
        assert!(migrations.is_empty());
    }

    #[test]
    fn test_load_migrations_nonexistent_dir() {
        let migrations =
            ClickHouseMigrator::load_migrations_from_dir(Path::new("/nonexistent")).unwrap();
        assert!(migrations.is_empty());
    }

    #[test]
    fn test_sanitize_strips_storage_policy() {
        let sql = "SETTINGS index_granularity = 8192, storage_policy = 'tiered', allow_experimental_full_text_index = 1";
        let result = ClickHouseMigrator::sanitize_for_cloud(sql);
        assert!(
            !result.contains("storage_policy"),
            "storage_policy should be stripped: {}",
            result
        );
        assert!(result.contains("index_granularity = 8192"));
    }

    #[test]
    fn test_sanitize_strips_full_text_settings() {
        let sql = "ALTER TABLE logs ADD COLUMN foo String SETTINGS allow_experimental_full_text_index = 1, enable_full_text_index = 1";
        let result = ClickHouseMigrator::sanitize_for_cloud(sql);
        assert!(!result.contains("allow_experimental_full_text_index"));
        assert!(!result.contains("enable_full_text_index"));
    }

    #[test]
    fn test_sanitize_strips_text_index_with_nested_parens() {
        let sql = r#"CREATE TABLE logs (
    `id` UUID,
    INDEX idx_message_ft lower(message) TYPE text(tokenizer = ngrams(3)) GRANULARITY 100000000,
    INDEX idx_message_ngram message TYPE ngrambf_v1(3, 262144, 3, 0) GRANULARITY 4
)"#;
        let result = ClickHouseMigrator::sanitize_for_cloud(sql);
        assert!(
            !result.contains("idx_message_ft"),
            "text() index should be stripped: {}",
            result
        );
        assert!(
            result.contains("idx_message_ngram"),
            "ngrambf_v1 index should be preserved: {}",
            result
        );
    }

    #[test]
    fn test_sanitize_preserves_non_cloud_incompatible_sql() {
        let sql = "ALTER TABLE logs ADD COLUMN process String DEFAULT ''";
        let result = ClickHouseMigrator::sanitize_for_cloud(sql);
        assert_eq!(result, sql, "Non-cloud SQL should be unchanged");
    }

    #[test]
    fn test_sanitize_cleans_empty_settings() {
        let sql =
            "CREATE TABLE foo (id Int32) ENGINE = MergeTree SETTINGS storage_policy = 'tiered';";
        let result = ClickHouseMigrator::sanitize_for_cloud(sql);
        assert!(
            !result.contains("SETTINGS"),
            "Empty SETTINGS clause should be removed: {}",
            result
        );
    }

    // ========================================================================
    // Cluster transformation tests
    // ========================================================================

    #[test]
    fn test_cluster_create_database() {
        let sql = "CREATE DATABASE IF NOT EXISTS nanosiem";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should add ON CLUSTER: {}",
            result
        );
        assert!(result.contains("CREATE DATABASE IF NOT EXISTS nanosiem ON CLUSTER"));
    }

    #[test]
    fn test_cluster_create_table_mergetree() {
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.logs (id UUID) ENGINE = MergeTree PARTITION BY toYYYYMMDD(timestamp) ORDER BY (timestamp) SETTINGS index_granularity = 8192";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should add ON CLUSTER: {}",
            result
        );
        assert!(
            result.contains("ReplicatedMergeTree("),
            "Should convert to ReplicatedMergeTree: {}",
            result
        );
        assert!(
            result.contains("/clickhouse/tables/{shard}/nanosiem/logs"),
            "Should have correct zoo path: {}",
            result
        );
        assert!(
            result.contains("'{replica}'"),
            "Should have replica macro: {}",
            result
        );
        assert!(
            result.contains("storage_policy = 'tiered'"),
            "Should add storage_policy for logs: {}",
            result
        );
    }

    #[test]
    fn test_cluster_global_replication_omits_shard_macro() {
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.sovereign_license_clock_witness /* nano:global-replication */ (generation UInt64) ENGINE = MergeTree ORDER BY generation";
        let result = ClickHouseMigrator::transform_for_cluster(
            sql,
            "nanosiem_cluster",
            "nanosiem",
            false,
        );
        assert!(result.contains("/clickhouse/tables/nanosiem/sovereign_license_clock_witness"));
        assert!(
            !result.contains(
                "/clickhouse/tables/{shard}/nanosiem/sovereign_license_clock_witness"
            )
        );
    }

    #[test]
    fn test_cluster_create_table_aggregating() {
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.domain_prevalence_agg (domain String) ENGINE = AggregatingMergeTree() ORDER BY (domain)";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("ReplicatedAggregatingMergeTree("),
            "Should convert to ReplicatedAggregatingMergeTree: {}",
            result
        );
    }

    #[test]
    fn test_cluster_create_table_replacing() {
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.custom_enrichment_results (key String) ENGINE = ReplacingMergeTree(version) ORDER BY (key)";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("ReplicatedReplacingMergeTree("),
            "Should convert to ReplicatedReplacingMergeTree: {}",
            result
        );
        assert!(
            result.contains("version)"),
            "Should preserve version argument: {}",
            result
        );
    }

    #[test]
    fn test_keep_local_engine_marker_skips_engine_conversion() {
        // NAN-1407: dictionary staging tables stay PLAIN MergeTree per node —
        // converting them to Replicated* would make ClickHouse refuse the
        // full-replace refreshable MV that repopulates them ("no APPEND,
        // non-replicated database, replicated table"). The marker keeps the
        // engine as written while still fanning the DDL out ON CLUSTER.
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.ip_enrichment_dict_staging (network String) ENGINE = MergeTree /* nano:keep-local-engine */ ORDER BY network";
        let result =
            ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should still add ON CLUSTER: {}",
            result
        );
        assert!(
            !result.contains("Replicated"),
            "Marker must keep the engine plain: {}",
            result
        );
        assert!(
            result.contains("ENGINE = MergeTree"),
            "Engine should be untouched: {}",
            result
        );
    }

    #[test]
    fn test_keep_local_engine_marker_replicated_db_mode() {
        // Replicated-database mode (cluster == db, e.g. CH Cloud): no ON
        // CLUSTER, and the marker still keeps the engine plain (Cloud
        // auto-converts plain MergeTree to SharedMergeTree, the coordinated-
        // refresh shape refreshable MVs expect there).
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.ip_enrichment_dict_staging (network String) ENGINE = MergeTree /* nano:keep-local-engine */ ORDER BY network";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem", "nanosiem", false);
        assert!(
            !result.contains("Replicated"),
            "Marker must keep the engine plain in Replicated-DB mode: {}",
            result
        );
        assert!(
            !result.contains("ON CLUSTER"),
            "Replicated-DB mode never adds ON CLUSTER: {}",
            result
        );
    }

    #[test]
    fn test_replicated_db_empty_args() {
        // When cluster name == database name (Replicated database auto-cluster),
        // use empty args — CH manages ZooKeeper paths automatically
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.logs (id UUID) ENGINE = MergeTree PARTITION BY toYYYYMMDD(timestamp) ORDER BY (timestamp) SETTINGS index_granularity = 8192";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem", "nanosiem", false);
        assert!(
            result.contains("ReplicatedMergeTree()"),
            "Should use empty args for Replicated database: {}",
            result
        );
        assert!(
            !result.contains("/clickhouse/tables/"),
            "Should NOT have explicit zoo path: {}",
            result
        );
        assert!(
            !result.contains("ON CLUSTER"),
            "Should NOT have ON CLUSTER for Replicated database: {}",
            result
        );
    }

    #[test]
    fn test_replicated_db_replacing_preserves_version() {
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.custom_enrichment_results (key String) ENGINE = ReplacingMergeTree(version) ORDER BY (key)";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem", "nanosiem", false);
        assert!(
            result.contains("ReplicatedReplacingMergeTree(version)"),
            "Should preserve version arg without zoo path: {}",
            result
        );
    }

    #[test]
    fn test_replicated_db_skips_create_database() {
        let sql = "CREATE DATABASE IF NOT EXISTS nanosiem";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem", "nanosiem", false);
        assert!(
            !result.contains("ON CLUSTER"),
            "Should NOT add ON CLUSTER for Replicated database: {}",
            result
        );
        assert_eq!(result, sql, "Should return CREATE DATABASE unchanged");
    }

    // ========================================================================
    // ClickHouse Cloud tests (NAN-1092)
    //
    // CH Cloud reports cluster_name="default" but the user-facing database can
    // be named anything (e.g. "nanosiem"). The underlying Replicated database
    // engine forbids explicit zookeeper_path/replica_name in Replicated*MergeTree
    // args (BAD_ARGUMENTS, Code 36). With is_cloud=true the transform must use
    // empty engine args regardless of cluster vs db name.
    // ========================================================================

    #[test]
    fn test_cloud_mergetree_uses_empty_args() {
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.logs (id UUID) ENGINE = MergeTree PARTITION BY toYYYYMMDD(timestamp) ORDER BY (timestamp) SETTINGS index_granularity = 8192";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "default", "nanosiem", true);
        assert!(
            result.contains("ReplicatedMergeTree()"),
            "CH Cloud should use empty args: {}",
            result
        );
        assert!(
            !result.contains("/clickhouse/tables/"),
            "CH Cloud must NOT splice explicit zoo path: {}",
            result
        );
        assert!(
            !result.contains("'{replica}'"),
            "CH Cloud must NOT splice replica macro: {}",
            result
        );
        assert!(
            !result.contains("ON CLUSTER"),
            "CH Cloud must NOT add ON CLUSTER: {}",
            result
        );
    }

    #[test]
    fn test_cloud_aggregating_mergetree_uses_empty_args() {
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.domain_prevalence_agg (domain String) ENGINE = AggregatingMergeTree() ORDER BY (domain)";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "default", "nanosiem", true);
        assert!(
            result.contains("ReplicatedAggregatingMergeTree()"),
            "CH Cloud should use empty args for AggregatingMergeTree: {}",
            result
        );
        assert!(
            !result.contains("/clickhouse/tables/"),
            "CH Cloud must NOT splice explicit zoo path: {}",
            result
        );
    }

    #[test]
    fn test_cloud_replacing_mergetree_preserves_version_no_zoo_path() {
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.custom_enrichment_results (key String) ENGINE = ReplacingMergeTree(version) ORDER BY (key)";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "default", "nanosiem", true);
        assert!(
            result.contains("ReplicatedReplacingMergeTree(version)"),
            "CH Cloud should preserve version arg without splicing zoo path: {}",
            result
        );
        assert!(
            !result.contains("/clickhouse/tables/"),
            "CH Cloud must NOT splice explicit zoo path: {}",
            result
        );
    }

    #[test]
    fn test_cloud_summing_mergetree_uses_empty_args() {
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.summary (k String) ENGINE = SummingMergeTree() ORDER BY (k)";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "default", "nanosiem", true);
        assert!(
            result.contains("ReplicatedSummingMergeTree()"),
            "CH Cloud should use empty args for SummingMergeTree: {}",
            result
        );
        assert!(
            !result.contains("/clickhouse/tables/"),
            "CH Cloud must NOT splice explicit zoo path: {}",
            result
        );
    }

    #[test]
    fn test_cloud_skips_create_database() {
        // The Replicated database already exists on CH Cloud — CREATE DATABASE
        // should be returned unchanged (same behavior as the cluster==db case).
        let sql = "CREATE DATABASE IF NOT EXISTS nanosiem";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "default", "nanosiem", true);
        assert_eq!(result, sql, "CH Cloud should return CREATE DATABASE unchanged");
    }

    #[test]
    fn test_cloud_does_not_inject_storage_policy_tiered() {
        // CH Cloud manages hot/warm tiering internally and rejects
        // `storage_policy = 'tiered'` with UNKNOWN_POLICY (Code 478). The
        // transform must NOT re-inject the storage_policy after
        // sanitize_for_cloud has stripped it. NAN-1096.
        for table in ["logs", "signals", "ingestion_errors", "custom_enrichment_results"] {
            let sql = format!(
                "CREATE TABLE IF NOT EXISTS nanosiem.{} (id UUID) ENGINE = MergeTree ORDER BY id SETTINGS index_granularity = 8192",
                table
            );
            let result = ClickHouseMigrator::transform_for_cluster(&sql, "default", "nanosiem", true);
            assert!(
                !result.to_lowercase().contains("storage_policy"),
                "CH Cloud must NOT inject storage_policy for {}: {}",
                table,
                result
            );
        }
    }

    #[test]
    fn test_in_cluster_still_injects_storage_policy_tiered() {
        // Regression guard: operator-managed in-cluster deploys must still get
        // `storage_policy = 'tiered'` injected on the main data tables.
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.logs (id UUID) ENGINE = MergeTree ORDER BY id SETTINGS index_granularity = 8192";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("storage_policy = 'tiered'"),
            "In-cluster mode must still inject storage_policy for logs: {}",
            result
        );
    }

    #[test]
    fn test_cloud_does_not_break_explicit_cluster() {
        // Regression guard: is_cloud=false against an explicit operator cluster
        // must still produce the legacy explicit-zoo-path form for in-cluster
        // CH deployments. NAN-1092 only changes behavior when is_cloud=true.
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.logs (id UUID) ENGINE = MergeTree PARTITION BY toYYYYMMDD(timestamp) ORDER BY (timestamp) SETTINGS index_granularity = 8192";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Explicit cluster mode must keep ON CLUSTER: {}",
            result
        );
        assert!(
            result.contains("/clickhouse/tables/{shard}/nanosiem/logs"),
            "Explicit cluster mode must keep zoo path: {}",
            result
        );
        assert!(
            result.contains("'{replica}'"),
            "Explicit cluster mode must keep replica macro: {}",
            result
        );
    }

    #[test]
    fn test_cluster_no_duplicate_storage_policy() {
        // Migration 085 already has storage_policy in SETTINGS — don't duplicate it
        let sql = "CREATE TABLE nanosiem.logs (id UUID) ENGINE = MergeTree PARTITION BY toYYYYMMDD(timestamp) ORDER BY (timestamp) SETTINGS index_granularity = 8192, storage_policy = 'tiered', allow_experimental_full_text_index = 1";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        let count = result.matches("storage_policy").count();
        assert_eq!(
            count, 1,
            "Should NOT duplicate storage_policy (found {} occurrences): {}",
            count, result
        );
        assert!(
            result.contains("ReplicatedMergeTree("),
            "Should still convert engine: {}",
            result
        );
    }

    #[test]
    fn test_cluster_create_table_summing() {
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.nat_candidates (src_ip String, count UInt64) ENGINE = SummingMergeTree() ORDER BY (src_ip)";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("ReplicatedSummingMergeTree("),
            "Should convert to ReplicatedSummingMergeTree: {}",
            result
        );
        assert!(
            result.contains("/clickhouse/tables/{shard}/nanosiem/nat_candidates"),
            "Should have correct zoo path: {}",
            result
        );
    }

    #[test]
    fn test_cluster_create_table_unqualified() {
        let sql = "CREATE TABLE IF NOT EXISTS identity_observations (ip String) ENGINE = MergeTree() ORDER BY (ip) SETTINGS index_granularity = 8192";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should add ON CLUSTER for unqualified table: {}",
            result
        );
        assert!(
            result.contains("/clickhouse/tables/{shard}/nanosiem/identity_observations"),
            "Should use default db in zoo path: {}",
            result
        );
    }

    #[test]
    fn test_cluster_alter_table() {
        let sql = "ALTER TABLE nanosiem.logs ADD COLUMN IF NOT EXISTS foo String DEFAULT ''";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should add ON CLUSTER to ALTER: {}",
            result
        );
    }

    #[test]
    fn test_cluster_alter_table_unqualified() {
        let sql = "ALTER TABLE logs DROP INDEX IF EXISTS idx_command_line";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should add ON CLUSTER to unqualified ALTER: {}",
            result
        );
    }

    #[test]
    fn test_cluster_materialized_view() {
        let sql = "CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.domain_prevalence_mv TO nanosiem.domain_prevalence_agg AS SELECT 1";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should add ON CLUSTER to MV: {}",
            result
        );
    }

    #[test]
    fn test_cluster_dictionary() {
        let sql = "CREATE DICTIONARY IF NOT EXISTS nanosiem.hash_prevalence_dict (file_hash String) PRIMARY KEY file_hash SOURCE(CLICKHOUSE(HOST 'localhost' PORT 9000 USER 'nanosiem' DB 'nanosiem')) LIFETIME(MIN 300 MAX 600) LAYOUT(SPARSE_HASHED())";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should add ON CLUSTER to DICTIONARY: {}",
            result
        );
        assert!(
            result.contains("PORT 9000"),
            "Should preserve the rendered self port: {}",
            result
        );
    }

    #[test]
    fn cluster_dictionary_preserves_configured_tls_self_endpoint() {
        let sql = "CREATE OR REPLACE DICTIONARY nanosiem.hash_prevalence_dict \
                   (file_hash String) PRIMARY KEY file_hash \
                   SOURCE(CLICKHOUSE(HOST '{clickhouse_self_host}' \
                   PORT {clickhouse_self_port} USER '{clickhouse_self_user}' \
                   PASSWORD '{clickhouse_self_password}' DB 'nanosiem')) \
                   LIFETIME(0) LAYOUT(HASHED())";
        for port in ["9000", "9001"] {
            let rendered = ClickHouseMigrator::substitute_clickhouse_self_vars_with_secure(
                sql,
                "localhost",
                port,
                "nanosiem",
                "secret",
                true,
            );
            let transformed =
                ClickHouseMigrator::transform_for_cluster(&rendered, "default", "nanosiem", false);
            assert!(
                transformed.contains(&format!("PORT {port}")),
                "configured port changed during cluster rendering: {transformed}"
            );
            assert!(
                transformed.contains("SECURE 1"),
                "TLS clause was lost during cluster rendering: {transformed}"
            );
            assert!(
                transformed.contains("ON CLUSTER 'default'"),
                "explicit cluster fan-out was lost: {transformed}"
            );
        }
    }

    #[test]
    fn test_cluster_create_or_replace_dictionary() {
        let sql = "CREATE OR REPLACE DICTIONARY nanosiem.hash_prevalence_dict (file_hash String) PRIMARY KEY file_hash SOURCE(CLICKHOUSE(HOST 'localhost' PORT 9000 USER 'nanosiem' DB 'nanosiem')) LIFETIME(MIN 300 MAX 600) LAYOUT(SPARSE_HASHED())";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should add ON CLUSTER to CREATE OR REPLACE DICTIONARY: {}",
            result
        );
    }

    #[test]
    fn test_cluster_truncate_table() {
        let sql = "TRUNCATE TABLE nanosiem.logs";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should add ON CLUSTER to TRUNCATE: {}",
            result
        );
    }

    #[test]
    fn test_cluster_skip_non_replicated_dedup() {
        let sql =
            "ALTER TABLE nanosiem.logs MODIFY SETTING non_replicated_deduplication_window = 1000";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.trim().is_empty(),
            "Should skip non_replicated_deduplication_window: '{}'",
            result
        );
    }

    #[test]
    fn test_cluster_skips_set_statements() {
        let sql = "SET allow_experimental_full_text_index = 1";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert_eq!(result, sql, "SET statements should pass through unchanged");
    }

    #[test]
    fn test_cluster_preserves_existing_on_cluster() {
        let sql = "CREATE TABLE nanosiem.test ON CLUSTER 'my_cluster' (id Int32) ENGINE = ReplicatedMergeTree('/path', '{replica}') ORDER BY id";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert_eq!(
            result, sql,
            "Should not modify SQL that already has ON CLUSTER"
        );
    }

    #[test]
    fn test_cluster_drop_table() {
        let sql = "DROP TABLE IF EXISTS nanosiem.old_table";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should add ON CLUSTER to DROP: {}",
            result
        );
    }

    #[test]
    fn test_substitute_postgres_vars_defaults() {
        // Without env vars set, should keep defaults
        let sql = "CREATE DICTIONARY nanosiem.test SOURCE(POSTGRESQL(host 'postgres' port 5432 user 'nanosiem' password 'nanosiem' db 'nanosiem'))";
        let result = ClickHouseMigrator::substitute_postgres_vars(sql);
        assert!(
            result.contains("host 'postgres'")
                || result.contains("host 'postgres.nanosiem.svc.cluster.local'"),
            "Should keep default host when env not set: {}",
            result
        );
    }

    #[test]
    fn test_substitute_postgres_vars_custom() {
        std::env::set_var("POSTGRES_DICT_HOST", "postgres.nanosiem.svc.cluster.local");
        std::env::set_var("POSTGRES_DICT_PORT", "15432");
        std::env::set_var("POSTGRES_DICT_PASSWORD", "s3cret");
        let sql = "CREATE DICTIONARY nanosiem.test SOURCE(POSTGRESQL(host 'postgres' port 5432 user 'nanosiem' password 'nanosiem' db 'nanosiem'))";
        let result = ClickHouseMigrator::substitute_postgres_vars(sql);
        assert!(
            result.contains("host 'postgres.nanosiem.svc.cluster.local'"),
            "Should substitute host: {}",
            result
        );
        assert!(
            result.contains("password 's3cret'"),
            "Should substitute password: {}",
            result
        );
        assert!(
            result.contains("port 15432"),
            "Should substitute port: {}",
            result
        );
        std::env::remove_var("POSTGRES_DICT_HOST");
        std::env::remove_var("POSTGRES_DICT_PORT");
        std::env::remove_var("POSTGRES_DICT_PASSWORD");
    }

    /// NAN-707: numbered migrations now get the same `{clickhouse_self_*}`
    /// substitution that init.sql has always done. Without this, a migration
    /// like `CREATE OR REPLACE DICTIONARY ... USER '{clickhouse_self_user}'`
    /// would write the literal placeholder text into the dict definition and
    /// dictGet would fail authentication.
    #[test]
    fn test_substitute_clickhouse_self_vars_replaces_placeholders_and_enables_tls() {
        let _env_guard = CLICKHOUSE_SELF_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        std::env::set_var("CLICKHOUSE_SELF_HOST", "ch-shard-0.svc");
        std::env::set_var("CLICKHOUSE_SELF_PORT", "9001");
        std::env::set_var("CLICKHOUSE_SELF_USER", "rotated_admin");
        std::env::set_var("CLICKHOUSE_SELF_PASSWORD", "rotated_pw_xyz");
        std::env::set_var("CLICKHOUSE_SELF_SECURE", "true");

        let sql = "SOURCE(CLICKHOUSE(HOST '{clickhouse_self_host}' PORT {clickhouse_self_port} \
                   USER '{clickhouse_self_user}' PASSWORD '{clickhouse_self_password}' DB 'nanosiem'))";
        let result = ClickHouseMigrator::substitute_clickhouse_self_vars(sql);

        assert!(result.contains("HOST 'ch-shard-0.svc'"), "host: {}", result);
        assert!(result.contains("PORT 9001"), "port: {}", result);
        assert!(result.contains("SECURE 1"), "secure: {}", result);
        assert!(
            result.contains("USER 'rotated_admin'"),
            "user: {}",
            result
        );
        assert!(
            result.contains("PASSWORD 'rotated_pw_xyz'"),
            "password: {}",
            result
        );
        assert!(
            !result.contains("{clickhouse_self_"),
            "no unsubstituted placeholders should remain: {}",
            result
        );

        std::env::remove_var("CLICKHOUSE_SELF_HOST");
        std::env::remove_var("CLICKHOUSE_SELF_PORT");
        std::env::remove_var("CLICKHOUSE_SELF_USER");
        std::env::remove_var("CLICKHOUSE_SELF_PASSWORD");
        std::env::remove_var("CLICKHOUSE_SELF_SECURE");
    }

    /// Sanity: the helper falls back to localhost:9000 / default user when
    /// no env is set. This is the dev / single-node default.
    #[test]
    fn test_substitute_clickhouse_self_vars_defaults_when_unset() {
        let _env_guard = CLICKHOUSE_SELF_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // Serialize with the env-mutating companion test, then clear any
        // ambient values so this case really exercises the defaults.
        std::env::remove_var("CLICKHOUSE_SELF_HOST");
        std::env::remove_var("CLICKHOUSE_SELF_PORT");
        std::env::remove_var("CLICKHOUSE_SELF_SECURE");

        let sql = "HOST '{clickhouse_self_host}' PORT {clickhouse_self_port}";
        let result = ClickHouseMigrator::substitute_clickhouse_self_vars(sql);

        assert!(result.contains("HOST 'localhost'"), "host: {}", result);
        assert!(result.contains("PORT 9000"), "port: {}", result);
        assert!(!result.contains("SECURE"), "secure: {}", result);
    }

    /// NAN-1384: the `nano:skip-if-unknown-table` marker lets a migration
    /// statement targeting a profile-gated table (nanosiem.ocsf_logs exists
    /// only on OCSF-profile deployments; ClickHouse has no `ALTER TABLE IF
    /// EXISTS`) tolerate exactly an UNKNOWN_TABLE failure. The marker must be
    /// a `/* */` block comment so it survives `strip_sql_line_comments`, and
    /// the error matcher must not treat unrelated failures as skippable.
    #[test]
    fn skip_if_unknown_table_marker_detected_and_survives_comment_strip() {
        let stmt = "ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */ \
                    MODIFY TTL timestamp + toIntervalDay(365)";
        assert!(ClickHouseMigrator::has_skip_if_unknown_table_marker(stmt));
        // Block-comment marker survives the line-comment strip that runs
        // before statement splitting in apply_migration.
        let stripped = ClickHouseMigrator::strip_sql_line_comments(stmt);
        assert!(ClickHouseMigrator::has_skip_if_unknown_table_marker(&stripped));
        // Unmarked statements are never skip-eligible.
        assert!(!ClickHouseMigrator::has_skip_if_unknown_table_marker(
            "ALTER TABLE nanosiem.ocsf_logs MODIFY TTL timestamp + toIntervalDay(365)"
        ));
    }

    #[test]
    fn unknown_table_error_matcher_is_precise() {
        // Real CH 26.4 shape for an ALTER on a missing table.
        assert!(ClickHouseMigrator::is_unknown_table_error(
            "Code: 60. DB::Exception: Table nanosiem.ocsf_logs does not exist. (UNKNOWN_TABLE)"
        ));
        // A marked statement failing for any OTHER reason must still abort.
        assert!(!ClickHouseMigrator::is_unknown_table_error(
            "Code: 62. DB::Exception: Syntax error: failed at position 16"
        ));
        assert!(!ClickHouseMigrator::is_unknown_table_error(
            "Code: 497. DB::Exception: Not enough privileges. (ACCESS_DENIED)"
        ));
    }

    /// NAN-788: strip_sql_line_comments must remove `--` line comments, but
    /// the order in runner.rs is what matters most — comments are stripped
    /// before credentials are substituted, so a password containing `--`
    /// can never be mistaken for a comment start.
    #[test]
    fn strip_sql_line_comments_removes_full_line_and_trailing_comments() {
        let sql = "-- header comment\nSELECT 1; -- trailing\nSELECT 2;";
        let stripped = ClickHouseMigrator::strip_sql_line_comments(sql);
        assert_eq!(stripped, "\nSELECT 1; \nSELECT 2;");
    }

    /// NAN-788 repro: before the fix, `--` in a substituted password ate the
    /// rest of the line including the closing `'`, turning the next line into
    /// mid-string content and tripping CH 26.3's parser. After the fix
    /// (strip-comments-first), the password literal survives intact.
    ///
    /// Uses the env-free `_with` helper so this doesn't race with other
    /// tests that mutate `CLICKHOUSE_SELF_PASSWORD`.
    #[test]
    fn nan_788_password_with_double_dash_survives_pipeline() {
        let password = "EBLYDBRzEjytXINQ6--XXXXXXXXXXXXX";
        let sql =
            "    PASSWORD '{clickhouse_self_password}'\n    DB 'nanosiem'\n    QUERY 'SELECT 1'";

        // Production order: strip → substitute.
        let stripped = ClickHouseMigrator::strip_sql_line_comments(sql);
        let result = ClickHouseMigrator::substitute_clickhouse_self_vars_with(
            &stripped, "localhost", "9000", "default", password,
        );

        assert!(
            result.contains("PASSWORD 'EBLYDBRzEjytXINQ6--XXXXXXXXXXXXX'"),
            "password literal lost its `--` or closing quote: {}",
            result
        );
        assert!(
            result.contains("DB 'nanosiem'"),
            "next-line clause was eaten: {}",
            result
        );
        assert!(
            result.contains("QUERY 'SELECT 1'"),
            "subsequent clause was eaten: {}",
            result
        );
        let quote_count = result.chars().filter(|&c| c == '\'').count();
        assert_eq!(
            quote_count % 2,
            0,
            "unbalanced single quotes after pipeline: {} (count={})",
            result,
            quote_count
        );
    }

    /// NAN-788: confirms the *wrong* order (substitute first, then strip) is
    /// what produces the original bug — locks in the failure mode so a future
    /// refactor that re-introduces the wrong order is caught.
    #[test]
    fn nan_788_substitute_then_strip_is_the_buggy_order() {
        let password = "EBLYDBRzEjytXINQ6--XXXXXXXXXXXXX";
        let sql =
            "    PASSWORD '{clickhouse_self_password}'\n    DB 'nanosiem'\n    QUERY 'SELECT 1'";

        // The buggy order: substitute → strip.
        let substituted = ClickHouseMigrator::substitute_clickhouse_self_vars_with(
            sql, "localhost", "9000", "default", password,
        );
        let result = ClickHouseMigrator::strip_sql_line_comments(&substituted);

        // The closing quote and the `DB 'nanosiem'` line get eaten because
        // `--` is mid-literal. This proves the order is load-bearing.
        assert!(
            !result.contains("PASSWORD 'EBLYDBRzEjytXINQ6--XXXXXXXXXXXXX'"),
            "buggy order should have lost the closing quote: {}",
            result
        );
    }

    /// NAN-788: passwords containing `'` must be SQL-escaped at substitution
    /// time so they can't close the surrounding literal early.
    #[test]
    fn nan_788_password_with_single_quote_is_escaped() {
        let result = ClickHouseMigrator::substitute_clickhouse_self_vars_with(
            "PASSWORD '{clickhouse_self_password}' DB 'nanosiem'",
            "localhost",
            "9000",
            "default",
            "foo'bar",
        );

        assert!(
            result.contains("PASSWORD 'foo''bar'"),
            "single quote not escaped: {}",
            result
        );
        let quote_count = result.chars().filter(|&c| c == '\'').count();
        assert_eq!(
            quote_count % 2,
            0,
            "unbalanced single quotes: {} (count={})",
            result,
            quote_count
        );
    }

    /// NAN-788: backslashes are CH's in-string escape char and must be doubled
    /// before splicing so a value like `foo\` can't escape the closing quote.
    #[test]
    fn nan_788_password_with_backslash_is_escaped() {
        let result = ClickHouseMigrator::substitute_clickhouse_self_vars_with(
            "PASSWORD '{clickhouse_self_password}' DB 'nanosiem'",
            "localhost",
            "9000",
            "default",
            "foo\\bar",
        );

        assert!(
            result.contains("PASSWORD 'foo\\\\bar'"),
            "backslash not doubled: {}",
            result
        );
    }

    /// NAN-788: combined pathological password (`--` + `'` + `\`) — the
    /// pipeline (strip → substitute) must produce a literal that is both
    /// quote-balanced and preserves every character of the original password.
    #[test]
    fn nan_788_password_with_dash_quote_and_backslash() {
        let sql =
            "    PASSWORD '{clickhouse_self_password}'\n    DB 'nanosiem'\n    QUERY 'SELECT 1'";
        let stripped = ClickHouseMigrator::strip_sql_line_comments(sql);
        let result = ClickHouseMigrator::substitute_clickhouse_self_vars_with(
            &stripped,
            "localhost",
            "9000",
            "default",
            "a--b'c\\d",
        );

        // After escape: `'` → `''`, `\` → `\\`; `--` survives because
        // comments were stripped before substitution.
        assert!(
            result.contains("PASSWORD 'a--b''c\\\\d'"),
            "combined-escape password mangled: {}",
            result
        );
        assert!(
            result.contains("DB 'nanosiem'") && result.contains("QUERY 'SELECT 1'"),
            "subsequent clauses lost: {}",
            result
        );
    }

    /// NAN-788 follow-up: port is spliced naked (no surrounding quotes) into
    /// the SQL, so a non-numeric value would produce an opaque CH parse
    /// failure. Panic loudly at the substitution site instead.
    #[test]
    #[should_panic(expected = "CLICKHOUSE_SELF_PORT must be a valid u16")]
    fn nan_788_port_must_parse_as_u16() {
        ClickHouseMigrator::substitute_clickhouse_self_vars_with(
            "PORT {clickhouse_self_port}",
            "localhost",
            "9000; DROP TABLE x",
            "default",
            "pw",
        );
    }

    /// Sanity: valid numeric port passes through unchanged.
    #[test]
    fn nan_788_port_valid_passes_through() {
        let result = ClickHouseMigrator::substitute_clickhouse_self_vars_with(
            "PORT {clickhouse_self_port}",
            "localhost",
            "9001",
            "default",
            "pw",
        );
        assert!(result.contains("PORT 9001"), "{}", result);
    }

    /// NAN-788: same fix applied to `substitute_postgres_vars`. A pg password
    /// containing `'` or `\` must be escaped at substitution time so the
    /// dictionary's `password '...'` literal stays balanced.
    #[test]
    fn nan_788_postgres_password_with_special_chars_is_escaped() {
        let sql = "SOURCE(POSTGRESQL(host 'postgres' port 5432 user 'nanosiem' password 'nanosiem' db 'nanosiem'))";
        let result = ClickHouseMigrator::substitute_postgres_vars_with(
            sql,
            "pg.svc",
            "5432",
            "pw'with\\stuff",
        );

        assert!(
            result.contains("password 'pw''with\\\\stuff'"),
            "pg password not escaped: {}",
            result
        );
    }

    #[test]
    #[should_panic(expected = "POSTGRES_DICT_PORT must be a valid u16")]
    fn nan_4986_postgres_dictionary_port_must_parse_as_u16() {
        ClickHouseMigrator::substitute_postgres_vars_with(
            "SOURCE(POSTGRESQL(host 'postgres' port 5432 password 'nanosiem'))",
            "pg.svc",
            "5432; DROP TABLE x",
            "pw",
        );
    }

    /// NAN-1115: the CREATE TABLE name parser drives the "table already exists?"
    /// soft-fail guard, so it must pull the right identifier across the forms
    /// init.sql actually emits (qualified, IF NOT EXISTS, backticks, ON CLUSTER,
    /// newline-before-paren) and decline non-CREATE-TABLE statements.
    #[test]
    fn parse_create_table_name_variants() {
        let cases = [
            ("CREATE TABLE IF NOT EXISTS nanosiem.logs (\n  id UUID\n)", Some("nanosiem.logs")),
            ("CREATE TABLE nanosiem.logs(id UUID)", Some("nanosiem.logs")),
            ("create table if not exists nanosiem.foo (x Int8)", Some("nanosiem.foo")),
            ("CREATE TABLE IF NOT EXISTS `nanosiem`.`logs` (id UUID)", Some("nanosiem.logs")),
            ("CREATE TABLE IF NOT EXISTS nanosiem.logs ON CLUSTER default (id UUID)", Some("nanosiem.logs")),
            ("CREATE TABLE bare_table (id UUID)", Some("bare_table")),
            ("CREATE DICTIONARY nanosiem.ioc_enrichment_dict (k String)", None),
            ("CREATE MATERIALIZED VIEW nanosiem.mv TO nanosiem.logs AS SELECT 1", None),
            ("ALTER TABLE nanosiem.logs ADD COLUMN x Int8", None),
        ];
        for (sql, want) in cases {
            assert_eq!(
                ClickHouseMigrator::parse_create_table_name(sql).as_deref(),
                want,
                "parse_create_table_name({sql:?})"
            );
        }
    }

    // ── NAN-1728 M-2/D5: CREATE VIEW / SETTINGS PROFILE / inline-engine MV ──

    #[test]
    fn create_workload_and_resource_get_on_cluster() {
        let workload = ClickHouseMigrator::transform_for_cluster(
            "CREATE WORKLOAD IF NOT EXISTS ingest IN nano SETTINGS max_concurrent_threads = 4",
            "nanosiem_cluster",
            "nanosiem",
            false,
        );
        assert!(
            workload.contains("ingest ON CLUSTER 'nanosiem_cluster' IN nano"),
            "workload must get ON CLUSTER after its name: {workload}"
        );

        let resource = ClickHouseMigrator::transform_for_cluster(
            "CREATE RESOURCE IF NOT EXISTS cpu (MASTER THREAD, WORKER THREAD)",
            "nanosiem_cluster",
            "nanosiem",
            false,
        );
        assert!(
            resource.contains("cpu ON CLUSTER 'nanosiem_cluster' (MASTER THREAD"),
            "resource must get ON CLUSTER after its name: {resource}"
        );
    }

    #[test]
    fn replicated_database_workload_ddl_still_fans_out() {
        for sql in [
            "CREATE WORKLOAD default SETTINGS weight = 4",
            "CREATE RESOURCE cpu (MASTER THREAD, WORKER THREAD)",
        ] {
            let result = ClickHouseMigrator::transform_for_cluster(
                sql,
                "nanosiem",
                "nanosiem",
                false,
            );
            assert!(result.contains("ON CLUSTER 'nanosiem'"),
                "server-scoped workload DDL must fan out even with a Replicated database: {result}");
        }
    }

    #[test]
    fn migration_189_uses_a_definer_landing_view_for_udm_logs() {
        let migration = include_str!("../../../../clickhouse/189_ingest_watchdog.sql");
        assert!(migration.contains(
            "CREATE TABLE IF NOT EXISTS nanosiem.logs_ingest AS nanosiem.logs\nENGINE = Null"
        ));
        assert!(migration.contains("TO nanosiem.logs\nDEFINER = CURRENT_USER\nSQL SECURITY DEFINER"));
        assert!(migration.contains("AS SELECT * FROM nanosiem.logs_ingest"));
        assert!(migration.contains(
            "ALTER TABLE nanosiem.ocsf_logs_raw_mv /* nano:skip-if-unknown-table */\n\
             MODIFY SQL SECURITY DEFINER DEFINER = CURRENT_USER"
        ));
    }

    #[test]
    fn create_or_replace_view_gets_on_cluster() {
        let sql = "CREATE OR REPLACE VIEW nanosiem.nat_candidates_view AS SELECT 1";
        let result =
            ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("nanosiem.nat_candidates_view ON CLUSTER 'nanosiem_cluster'"),
            "plain VIEW must get ON CLUSTER after the name: {result}"
        );
    }

    #[test]
    fn create_settings_profile_gets_on_cluster() {
        let sql = "CREATE SETTINGS PROFILE IF NOT EXISTS 'nanosiem_realtime' SETTINGS max_threads = 4";
        let result =
            ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("'nanosiem_realtime' ON CLUSTER 'nanosiem_cluster'"),
            "SETTINGS PROFILE must get ON CLUSTER after the quoted name: {result}"
        );
    }

    #[test]
    fn to_form_materialized_view_is_not_engine_rewritten() {
        // TO-form MVs have no ENGINE — only ON CLUSTER is added, no engine rewrite.
        let sql = "CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.foo_mv TO nanosiem.foo_agg AS SELECT 1";
        let result =
            ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(result.contains("ON CLUSTER 'nanosiem_cluster'"), "{result}");
        assert!(!result.contains("Replicated"), "TO-form MV must not gain an engine: {result}");
    }

    #[test]
    fn inline_engine_materialized_view_is_replicated() {
        // Latent guard (all MVs are TO-form today): an inline-engine MV must get
        // a Replicated engine like a CREATE TABLE.
        let sql = "CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.foo_mv ENGINE = AggregatingMergeTree() ORDER BY k AS SELECT k FROM nanosiem.logs";
        let result =
            ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(result.contains("ON CLUSTER 'nanosiem_cluster'"), "{result}");
        assert!(
            result.contains("ReplicatedAggregatingMergeTree("),
            "inline-engine MV must be replicated: {result}"
        );
        assert!(
            result.contains("/clickhouse/tables/{shard}/nanosiem/foo_mv"),
            "inline-engine MV zoo path keyed on the view name: {result}"
        );
    }

    // ── NAN-1728 M-7/D12: DROP ... ON CLUSTER gets SYNC ──

    #[test]
    fn drop_table_on_cluster_gets_sync() {
        let sql = "DROP TABLE IF EXISTS nanosiem.logs";
        let result =
            ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(result.contains("ON CLUSTER 'nanosiem_cluster'"), "{result}");
        assert!(result.trim_end().ends_with("SYNC"), "DROP TABLE must end with SYNC: {result}");
    }

    /// NAN-4903: `SYNC` written before a SETTINGS clause is recognized — no
    /// second SYNC (that is a syntax error and aborted migration 180 on
    /// two-shard tenants).
    #[test]
    fn drop_table_sync_before_settings_not_duplicated() {
        let sql = "DROP TABLE IF EXISTS nanosiem.ocsf_logs SYNC SETTINGS check_table_dependencies = 0";
        let result =
            ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert_eq!(
            result,
            "DROP TABLE IF EXISTS nanosiem.ocsf_logs ON CLUSTER 'nanosiem_cluster' SYNC SETTINGS check_table_dependencies = 0"
        );
    }

    /// NAN-4903: a DROP without SYNC but with SETTINGS gets SYNC before SETTINGS.
    #[test]
    fn drop_table_settings_gets_sync_before_settings() {
        let sql = "DROP TABLE IF EXISTS nanosiem.ocsf_logs_raw SETTINGS check_table_dependencies = 0;";
        let result =
            ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert_eq!(
            result,
            "DROP TABLE IF EXISTS nanosiem.ocsf_logs_raw ON CLUSTER 'nanosiem_cluster' SYNC SETTINGS check_table_dependencies = 0;"
        );
    }

    /// NAN-4903: RENAME fans out with ON CLUSTER on explicit clusters (after the
    /// pairs and any marker comment), and is untouched in Replicated-DB mode.
    #[test]
    fn rename_table_on_cluster() {
        let sql = "RENAME TABLE nanosiem.ocsf_logs TO nanosiem.ocsf_logs_legacy_v179 /* nano:skip-if-unknown-table */";
        let result =
            ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert_eq!(
            result,
            "RENAME TABLE nanosiem.ocsf_logs TO nanosiem.ocsf_logs_legacy_v179 /* nano:skip-if-unknown-table */ ON CLUSTER 'nanosiem_cluster'"
        );
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem", "nanosiem", false);
        assert_eq!(result, sql);
    }

    /// NAN-4903: `nano:zk-path-name` keeps the recreated table off its renamed
    /// predecessor's ZooKeeper path.
    #[test]
    fn zk_path_name_marker_overrides_replica_path() {
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.ocsf_logs /* nano:zk-path-name=ocsf_logs_v180 */ (`a` String) ENGINE = MergeTree ORDER BY a";
        let result =
            ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(
            result.contains("/clickhouse/tables/{shard}/nanosiem/ocsf_logs_v180"),
            "{result}"
        );
        assert!(!result.contains("/nanosiem/ocsf_logs'"), "{result}");
    }

    /// NAN-4903: every statement of migration 180, as the migrator sends it to
    /// an explicit two-shard cluster, fans out with ON CLUSTER exactly once and
    /// carries at most one SYNC (DROP TABLE only).
    #[test]
    fn migration_180_renders_for_explicit_cluster() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../clickhouse/180_ocsf_version_agnostic_store.sql"
        ));
        let sql = ClickHouseMigrator::strip_sql_line_comments(raw);
        let mut n = 0;
        for stmt in sql.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            let out = ClickHouseMigrator::transform_for_cluster(stmt, "nanosiem_cluster", "nanosiem", false);
            assert_eq!(out.matches("ON CLUSTER 'nanosiem_cluster'").count(), 1, "{out}");
            let syncs = out.to_uppercase().matches(" SYNC").count();
            if out.starts_with("DROP TABLE") {
                assert_eq!(syncs, 1, "{out}");
            } else {
                assert_eq!(syncs, 0, "{out}");
            }
            if out.starts_with("RENAME TABLE") {
                assert!(out.ends_with("ON CLUSTER 'nanosiem_cluster'"), "{out}");
            }
            n += 1;
        }
        assert_eq!(n, 27, "2 ingest MVs + 21 readers + 3 tables + 1 rename");
    }

    #[test]
    fn drop_table_replicated_db_mode_no_sync() {
        // Replicated-DB / single-cluster mode → no ON CLUSTER, hence no SYNC.
        let sql = "DROP TABLE IF EXISTS nanosiem.logs";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem", "nanosiem", false);
        assert!(!result.contains("ON CLUSTER"), "{result}");
        assert!(!result.trim_end().ends_with("SYNC"), "no SYNC without ON CLUSTER: {result}");
    }

    #[test]
    fn drop_dictionary_on_cluster_no_sync() {
        // SYNC is a table-drop modifier; DROP DICTIONARY must not get it.
        let sql = "DROP DICTIONARY IF EXISTS nanosiem.ioc_enrichment_dict";
        let result =
            ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem", false);
        assert!(result.contains("ON CLUSTER 'nanosiem_cluster'"), "{result}");
        assert!(!result.trim_end().ends_with("SYNC"), "DROP DICTIONARY must not get SYNC: {result}");
    }

    // ── NAN-1728: {dist_suffix} read target resolves per topology ──

    /// The general `{dist_suffix}` placeholder must resolve to `""` (the local
    /// table) on a single-node deployment — where no `_distributed` wrapper
    /// exists and a hardcoded `_distributed` would halt ingest with
    /// CACHE_DICTIONARY_UPDATE_FAIL — and to `_distributed` (the wrapper) on a
    /// cluster. Works after ANY base table name (prevalence summary AND the
    /// reference tables).
    #[test]
    fn dist_suffix_resolves_per_topology() {
        let query = "QUERY 'SELECT file_hash FROM nanosiem.hash_prevalence_summary{dist_suffix} GROUP BY file_hash'";
        // Single-node → local table, NO wrapper name.
        let single = ClickHouseMigrator::substitute_dist_suffix(query, false);
        assert!(
            single.contains("FROM nanosiem.hash_prevalence_summary GROUP BY"),
            "single-node must read the plain local table: {single}"
        );
        assert!(!single.contains("_distributed"), "no wrapper on single-node: {single}");
        assert!(!single.contains("{dist_suffix}"), "placeholder must be substituted: {single}");

        // Cluster → the _distributed wrapper.
        let clustered = ClickHouseMigrator::substitute_dist_suffix(query, true);
        assert!(
            clustered.contains("FROM nanosiem.hash_prevalence_summary_distributed GROUP BY"),
            "cluster must read the _distributed wrapper: {clustered}"
        );
        assert!(!clustered.contains("{dist_suffix}"), "placeholder must be substituted: {clustered}");

        // General: works after a reference-table name too.
        let refq = "SELECT * FROM nanosiem.ip_enrichments{dist_suffix}";
        assert_eq!(
            ClickHouseMigrator::substitute_dist_suffix(refq, false),
            "SELECT * FROM nanosiem.ip_enrichments"
        );
        assert_eq!(
            ClickHouseMigrator::substitute_dist_suffix(refq, true),
            "SELECT * FROM nanosiem.ip_enrichments_distributed"
        );
    }

    #[test]
    fn system_processes_view_source_resolves_per_topology() {
        let sql = "SELECT * FROM {system_processes_source}";
        assert_eq!(
            ClickHouseMigrator::substitute_system_processes_source(sql, None),
            "SELECT * FROM system.processes"
        );
        assert_eq!(
            ClickHouseMigrator::substitute_system_processes_source(
                sql,
                Some("nanosiem_cluster")
            ),
            "SELECT * FROM clusterAllReplicas('nanosiem_cluster', system.processes)"
        );
        assert_eq!(
            ClickHouseMigrator::substitute_system_processes_source(sql, Some("  ")),
            "SELECT * FROM system.processes"
        );
    }

    #[test]
    fn process_grants_fan_out_only_on_explicit_clusters() {
        let sql = "GRANT{grant_on_cluster} SELECT ON system.processes TO nanosiem";
        assert_eq!(
            ClickHouseMigrator::substitute_grant_on_cluster(
                sql,
                Some("nanosiem_cluster"),
                "nanosiem",
                false,
            ),
            "GRANT ON CLUSTER 'nanosiem_cluster' SELECT ON system.processes TO nanosiem"
        );
        assert_eq!(
            ClickHouseMigrator::substitute_grant_on_cluster(
                sql,
                Some("nanosiem"),
                "nanosiem",
                false,
            ),
            "GRANT SELECT ON system.processes TO nanosiem"
        );
        assert_eq!(
            ClickHouseMigrator::substitute_grant_on_cluster(
                sql,
                Some("default"),
                "nanosiem",
                true,
            ),
            "GRANT SELECT ON system.processes TO nanosiem"
        );
    }

    #[test]
    fn lookup_rows_delete_grant_resolves_for_runtime_user_and_topology() {
        let migration =
            include_str!("../../../../clickhouse/183_lookup_rows_alter_delete_grant.sql");
        assert!(migration.contains("GRANT{grant_on_cluster} ALTER DELETE ON nanosiem.lookup_rows TO {clickhouse_runtime_user};"));

        for (cluster, is_cloud, expected_cluster) in [
            (
                Some("nanosiem_cluster"),
                false,
                " ON CLUSTER 'nanosiem_cluster'",
            ),
            (Some("nanosiem"), false, ""),
            (Some("default"), true, ""),
            (None, false, ""),
        ] {
            let sql = ClickHouseMigrator::substitute_grant_on_cluster(
                migration, cluster, "nanosiem", is_cloud,
            );
            let sql =
                ClickHouseMigrator::substitute_clickhouse_users_with(&sql, "admin", "runtime-user");
            assert!(sql.contains(&format!(
                "GRANT{expected_cluster} ALTER DELETE ON nanosiem.lookup_rows TO `runtime-user`;"
            )));
            assert!(!sql.contains("{grant_on_cluster}"));
            assert!(!sql.contains("{clickhouse_runtime_user}"));
        }
    }

    #[test]
    fn security_definer_users_are_configurable_and_identifier_quoted() {
        let sql = "DEFINER = {clickhouse_admin_user}; GRANT SELECT TO {clickhouse_runtime_user}";
        assert_eq!(
            ClickHouseMigrator::substitute_clickhouse_users_with(
                sql,
                "byoc-admin",
                "tenant`runtime"
            ),
            "DEFINER = `byoc-admin`; GRANT SELECT TO `tenant\\`runtime`"
        );
    }

    #[test]
    fn cluster_processes_migration_exposes_only_the_required_projection() {
        let migration = include_str!("../../../../clickhouse/173_cluster_processes.sql");
        for required in [
            "CREATE OR REPLACE VIEW cluster_processes",
            "SQL SECURITY DEFINER",
            "{clickhouse_admin_user}",
            "{clickhouse_runtime_user}",
            "{system_processes_source}",
            "{grant_on_cluster}",
            "SELECT ON system.processes",
            "SELECT ON cluster_processes",
            "normalizeQuery(query)",
            "query_snippet",
        ] {
            assert!(migration.contains(required), "migration missing {required}");
        }
        assert!(
            !migration.contains("\n    query,\n"),
            "the definer view must not expose raw query text"
        );
        assert!(
            !migration.contains("GRANT REMOTE"),
            "REMOTE must remain admin-only through the view body"
        );
        assert!(
            !migration.contains("VIEW nanosiem.cluster_processes"),
            "the migration must resolve the configured client database"
        );
    }

    #[test]
    fn historical_grants_are_not_globally_rewritten() {
        let sql = "GRANT SELECT ON nanosiem.cluster_processes TO nanosiem";
        let result = ClickHouseMigrator::transform_for_cluster(
            sql,
            "nanosiem_cluster",
            "nanosiem",
            false,
        );
        assert_eq!(result, sql);
        }

    // ── NAN-2346: box-sized prevalence CACHE dict SIZE_IN_CELLS ──

    /// Unset vars must reproduce the historical literals exactly. This is the
    /// property that keeps k8s, BYOC, CH Cloud, dev compose and open-core installs
    /// byte-identical — only a managed-compose tenant whose generated .env carries
    /// the vars gets a smaller cache.
    #[test]
    fn prevalence_cache_cells_default_to_the_historical_literals() {
        let ddl = "LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS {prevalence_cache_cells_ip}));\n\
                   LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS {prevalence_cache_cells}));";
        let out = ClickHouseMigrator::substitute_prevalence_cache_cells_with(ddl, "5000000", "1000000");
        assert_eq!(
            out,
            "LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 5000000));\n\
             LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 1000000));"
        );
        assert!(!out.contains('{'), "no placeholder may survive: {out}");
    }

    /// The ip placeholder must not be clipped by the shorter name — a naive
    /// shortest-first replace would leave a dangling `_ip}` in the DDL and CH
    /// would reject the LAYOUT clause.
    #[test]
    fn prevalence_cache_cells_ip_placeholder_is_not_clipped() {
        let ddl = "SIZE_IN_CELLS {prevalence_cache_cells_ip}";
        let out = ClickHouseMigrator::substitute_prevalence_cache_cells_with(ddl, "262144", "262144");
        assert_eq!(out, "SIZE_IN_CELLS 262144");
        assert!(!out.contains("_ip"), "the _ip suffix must be consumed: {out}");
    }

    /// Both dict classes are independently sizable — the ip trie is the expensive
    /// one (2^23 cells ≈ 320 MiB) and may warrant a different budget than the two
    /// small HASHED caches.
    #[test]
    fn prevalence_cache_cells_sizes_ip_independently() {
        let ddl = "ip={prevalence_cache_cells_ip} other={prevalence_cache_cells}";
        assert_eq!(
            ClickHouseMigrator::substitute_prevalence_cache_cells_with(ddl, "262144", "65536"),
            "ip=262144 other=65536"
        );
    }

    /// Values are spliced naked into the DDL, so a non-numeric or zero value must
    /// fail loudly at migrator startup rather than as a confusing ClickHouse parse
    /// error (or a dict that can cache nothing) far from the misconfiguration.
    #[test]
    #[should_panic(expected = "NANO_PREVALENCE_CACHE_CELLS")]
    fn prevalence_cache_cells_rejects_non_numeric() {
        ClickHouseMigrator::substitute_prevalence_cache_cells_with("x", "5000000", "not-a-number");
    }

    #[test]
    #[should_panic(expected = "greater than 0")]
    fn prevalence_cache_cells_rejects_zero() {
        ClickHouseMigrator::substitute_prevalence_cache_cells_with("x", "5000000", "0");
    }

    // ── NAN-1728 C2/P0: dict-refresh MV repoint to _distributed wrapper ──

    /// `repoint_from_table` swaps the bare local base for its `_distributed`
    /// wrapper, is boundary-aware (never double-suffixes), and is idempotent
    /// (returns None when already pointing at the wrapper or when there's no bare
    /// base reference). This is what the migrator's post-reconcile MODIFY QUERY
    /// step uses; single-node never calls it (the whole step is cluster-gated).
    /// NAN-4902 lane G (migration 182): the custom IOC refresh MV reads TWO
    /// bases — custom_enrichment_results and the ioc_list_commits GLOBAL IN
    /// subquery — and both are registered, so the post-reconcile step rewrites
    /// both on clusters (each entry re-reads the live body).
    #[test]
    fn custom_ioc_refresh_repoints_both_bases() {
        use crate::db::clickhouse_migrate::distributed::repoint_from_table;
        let bases: Vec<&str> = ClickHouseMigrator::DICT_REFRESH_MV_BASES
            .iter()
            .filter(|(mv, _)| *mv == "custom_ioc_enrichment_dict_refresh")
            .map(|(_, base)| *base)
            .collect();
        assert_eq!(bases, vec!["custom_enrichment_results", "ioc_list_commits"]);
        for base in &bases {
            assert!(ClickHouseMigrator::DISTRIBUTED_TABLES.contains(base), "{base} needs a wrapper");
        }
        let mig = include_str!("../../../../clickhouse/182_ioc_list_commits.sql");
        let mut body = mig[mig.find("MODIFY QUERY ").unwrap() + "MODIFY QUERY ".len()..].to_string();
        for base in &bases {
            body = repoint_from_table(&body, "nanosiem", base).expect("base referenced");
        }
        assert!(body.contains("FROM nanosiem.custom_enrichment_results_distributed"), "{body}");
        assert!(
            body.contains("GLOBAL IN (SELECT max(version) FROM nanosiem.ioc_list_commits_distributed GROUP BY list_id)"),
            "{body}"
        );
    }

    /// NAN-4948 (migration 184): the IP and marketplace-IOC refresh MVs read the
    /// platform_feed_commits GLOBAL IN subquery too, so both bases of each are
    /// registered and rewritten on clusters.
    #[test]
    fn platform_feed_refreshes_repoint_both_bases() {
        use crate::db::clickhouse_migrate::distributed::repoint_from_table;
        let mig = include_str!("../../../../clickhouse/184_platform_feed_commits.sql");
        for (mv, data_base) in [
            ("ip_enrichment_dict_refresh", "ip_enrichments"),
            ("ioc_enrichment_dict_refresh", "custom_enrichment_results"),
        ] {
            let bases: Vec<&str> = ClickHouseMigrator::DICT_REFRESH_MV_BASES
                .iter()
                .filter(|(m, _)| *m == mv)
                .map(|(_, base)| *base)
                .collect();
            assert_eq!(bases, vec![data_base, "platform_feed_commits"], "{mv}");
            for base in &bases {
                assert!(ClickHouseMigrator::DISTRIBUTED_TABLES.contains(base), "{base} needs a wrapper");
            }
            let head = format!("ALTER TABLE nanosiem.{mv}\nMODIFY QUERY ");
            let start = mig.find(&head).unwrap_or_else(|| panic!("{mv} not modified")) + head.len();
            let mut body = mig[start..].split(';').next().unwrap().to_string();
            for base in &bases {
                body = repoint_from_table(&body, "nanosiem", base).expect("base referenced");
            }
            assert!(body.contains(&format!("FROM nanosiem.{data_base}_distributed")), "{body}");
            assert!(
                body.contains("GLOBAL IN (SELECT argMax(storage_key, (sequence, committed_at)) FROM nanosiem.platform_feed_commits_distributed GROUP BY feed_id)"),
                "{body}"
            );
        }
    }

    #[test]
    fn repoint_from_table_swaps_base_to_wrapper_idempotently() {
        use crate::db::clickhouse_migrate::distributed::repoint_from_table;

        // Bare local base → wrapper.
        assert_eq!(
            repoint_from_table(
                "SELECT network FROM nanosiem.ip_enrichments GROUP BY network",
                "nanosiem",
                "ip_enrichments"
            )
            .as_deref(),
            Some("SELECT network FROM nanosiem.ip_enrichments_distributed GROUP BY network")
        );

        // Idempotent: already the wrapper → None (no MODIFY QUERY issued), and it
        // must NOT double-suffix.
        assert_eq!(
            repoint_from_table(
                "SELECT network FROM nanosiem.ip_enrichments_distributed GROUP BY network",
                "nanosiem",
                "ip_enrichments"
            ),
            None
        );

        // Base appears inside a subquery (user_registry shape) → still swapped.
        let sub = "SELECT * FROM (SELECT username_lc FROM nanosiem.user_registry WHERE x) WHERE y";
        assert_eq!(
            repoint_from_table(sub, "nanosiem", "user_registry").as_deref(),
            Some("SELECT * FROM (SELECT username_lc FROM nanosiem.user_registry_distributed WHERE x) WHERE y")
        );

        // Multiple references (custom_enrichment_results can appear twice) → all
        // swapped.
        let multi = "SELECT a FROM nanosiem.custom_enrichment_results, nanosiem.custom_enrichment_results b";
        assert_eq!(
            repoint_from_table(multi, "nanosiem", "custom_enrichment_results").as_deref(),
            Some("SELECT a FROM nanosiem.custom_enrichment_results_distributed, nanosiem.custom_enrichment_results_distributed b")
        );

        // No reference to the base → None.
        assert_eq!(
            repoint_from_table("SELECT 1 FROM nanosiem.other_table", "nanosiem", "ip_enrichments"),
            None
        );
    }

    // ── NAN-1728 C4/W2 + M-1/D4: sharding keys & wrapper drift ──

    #[test]
    fn sharding_key_content_hash_for_write_through_lanes() {
        use crate::db::clickhouse_migrate::distributed::sharding_key_for;
        assert_eq!(sharding_key_for("logs"), "cityHash64(id)");
        assert_eq!(sharding_key_for("ocsf_logs"), "cityHash64(id)");
        assert_eq!(sharding_key_for("signals"), "cityHash64(id)");
        assert_eq!(sharding_key_for("ingestion_errors"), "cityHash64(id)");
        assert_eq!(sharding_key_for("otel_spans"), "cityHash64(trace_id)");
        assert_eq!(sharding_key_for("otel_spans_trace_id_ts"), "cityHash64(trace_id)");
        // MV-fed aggregate wrappers keep rand() (never inserted through the wrapper).
        assert_eq!(sharding_key_for("hash_prevalence_summary"), "rand()");
        assert_eq!(sharding_key_for("entity_time_range_agg"), "rand()");
        assert_eq!(sharding_key_for("identity_observations"), "rand()");
        assert_eq!(sharding_key_for("synthetic_check_results"), "rand()");
    }

    /// NAN-5203: the write-only ingest landing wrappers are content-keyed, never
    /// in the read-routing set (a Null source reads back empty), and their key
    /// text matches ClickHouse's own `create_table_query` formatting (captured
    /// from 26.10.3.7) so the drift check does not recreate them every migrate.
    #[test]
    fn ingest_write_wrappers_are_content_keyed_and_write_only() {
        use crate::db::clickhouse_migrate::distributed::{
            sharding_key_for, wrapper_sharding_key_matches,
        };
        assert_eq!(
            ClickHouseMigrator::INGEST_WRITE_WRAPPER_SOURCES,
            &["otel_spans_raw", "otel_metrics_raw", "ocsf_logs_raw"]
        );
        for table in ClickHouseMigrator::INGEST_WRITE_WRAPPER_SOURCES {
            assert!(
                !ClickHouseMigrator::DISTRIBUTED_TABLES.contains(table),
                "{table} wrapper is write-only and must not route reads"
            );
            assert_ne!(sharding_key_for(table), "rand()", "{table} needs a content key");
            assert!(
                ClickHouseMigrator::wrapper_sources().any(|t| t == *table),
                "{table} must be created and reconciled with the other wrappers"
            );
        }
        assert_eq!(sharding_key_for("otel_metrics_raw"), "cityHash64(event)");
        assert_eq!(sharding_key_for("ocsf_logs_raw"), "cityHash64(event, source_type)");
        let spans_created = "CREATE TABLE nanosiem.otel_spans_raw_distributed \
            (`event` String DEFAULT '{}') ENGINE = Distributed('default', 'nanosiem', \
            'otel_spans_raw', cityHash64(if(JSONExtractString(event, 'traceId') != '', \
            lower(JSONExtractString(event, 'traceId')), event)))";
        assert!(wrapper_sharding_key_matches(
            spans_created,
            sharding_key_for("otel_spans_raw")
        ));
    }

    fn spec(name: &str, typ: &str, kind: &str, expr: &str) -> (String, String, String, String) {
        (name.into(), typ.into(), kind.into(), expr.into())
    }

    /// NAN-5203 M1: the OCSF write wrapper must never carry `id` or `timestamp`
    /// (per-row random DEFAULTs evaluated by the wrapper would make every retry
    /// a different block). Reconcile filters source specs through the same
    /// allowlist, so its ADD pass can never put them back.
    #[test]
    fn ocsf_write_wrapper_allowlist_excludes_random_defaults() {
        use crate::db::clickhouse_migrate::distributed::{
            columns_to_add, narrow_wrapper_create_sql, wrapper_source_specs,
            write_wrapper_columns,
        };
        let source = vec![
            spec("event", "JSON(max_dynamic_paths = 1024)", "DEFAULT", "'{}'"),
            spec("future_timestamp_skew_seconds", "UInt64", "DEFAULT", "86400"),
            spec("timestamp", "DateTime64(3, 'UTC')", "DEFAULT", "now64(3, 'UTC')"),
            spec("source_type", "LowCardinality(String)", "DEFAULT", "'unknown'"),
            spec("id", "UUID", "DEFAULT", "generateUUIDv7()"),
        ];
        let narrowed = wrapper_source_specs("ocsf_logs_raw", source.clone());
        let names: Vec<&str> = narrowed.iter().map(|(n, ..)| n.as_str()).collect();
        assert_eq!(names, ["event", "future_timestamp_skew_seconds", "source_type"]);
        // A reconcile against the narrow wrapper adds nothing, least of all id/timestamp.
        let wrapper_cols: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        assert!(columns_to_add(&wrapper_cols, &narrowed).is_empty());
        // Full-width wrappers are untouched by the allowlist.
        assert_eq!(write_wrapper_columns("otel_spans_raw"), None);
        assert_eq!(wrapper_source_specs("otel_spans_raw", source.clone()).len(), 5);

        let sql = narrow_wrapper_create_sql(
            "nanosiem", "ocsf_logs_raw_distributed", " ON CLUSTER 'default'", "default",
            "ocsf_logs_raw", "cityHash64(event, source_type)", &narrowed,
        );
        assert!(!sql.contains(" id ") && !sql.contains("timestamp DateTime64"), "{sql}");
        assert!(!sql.contains(" AS nanosiem."), "narrow wrapper must not copy the source: {sql}");
        assert!(sql.contains("ENGINE = Distributed('default', 'nanosiem', 'ocsf_logs_raw', cityHash64(event, source_type))"), "{sql}");
    }

    /// NAN-5203 M2: a DEFAULT change on a column the write wrapper carries is
    /// drift (the wrapper evaluates it); presence-only and type-equal columns are not.
    #[test]
    fn write_wrapper_default_drift_is_detected() {
        use crate::db::clickhouse_migrate::distributed::columns_default_drift;
        let source = vec![spec("source_type", "LowCardinality(String)", "DEFAULT", "lower(x)")];
        let same = vec![spec("source_type", "LowCardinality(String)", "DEFAULT", "lower(x)")];
        let changed = vec![spec("source_type", "LowCardinality(String)", "DEFAULT", "'unknown'")];
        let kind_changed = vec![spec("source_type", "LowCardinality(String)", "", "")];
        let other = vec![spec("event", "String", "", "")];
        assert!(!columns_default_drift(&same, &source));
        assert!(columns_default_drift(&changed, &source));
        assert!(columns_default_drift(&kind_changed, &source));
        assert!(!columns_default_drift(&other, &source));
    }

    #[test]
    fn wrapper_sharding_key_matches_detects_drift() {
        use crate::db::clickhouse_migrate::distributed::wrapper_sharding_key_matches;
        let rand_wrapper =
            "CREATE TABLE nanosiem.logs_distributed (id UUID) ENGINE = Distributed('c', 'nanosiem', 'logs', rand())";
        let hashed_wrapper =
            "CREATE TABLE nanosiem.logs_distributed (id UUID) ENGINE = Distributed('c', 'nanosiem', 'logs', cityHash64(id))";
        // Old rand() wrapper vs intended content hash → drift (no match).
        assert!(!wrapper_sharding_key_matches(rand_wrapper, "cityHash64(id)"));
        // Correct content-hash wrapper → match.
        assert!(wrapper_sharding_key_matches(hashed_wrapper, "cityHash64(id)"));
        // rand() wrapper with intended rand() → match (whitespace-insensitive).
        assert!(wrapper_sharding_key_matches(rand_wrapper, "rand()"));
        assert!(wrapper_sharding_key_matches(
            "ENGINE = Distributed('c','nanosiem','logs', cityHash64(id) )",
            "cityHash64(id)"
        ));
        // Non-Distributed / unparseable → treated as drift (safe: recreate).
        assert!(!wrapper_sharding_key_matches("CREATE TABLE x (id UUID) ENGINE = MergeTree", "rand()"));
    }

    #[test]
    fn columns_type_drift_only_flags_type_changes_on_common_columns() {
        use crate::db::clickhouse_migrate::distributed::columns_type_drift;
        let s = |n: &str, t: &str| (n.to_string(), t.to_string(), String::new(), String::new());
        // Identical → no drift.
        let a = vec![s("id", "UUID"), s("ts", "DateTime64(6)")];
        assert!(!columns_type_drift(&a, &a));
        // Type changed on a common column (migration 127 timestamp retype) → drift.
        let wrapper = vec![s("id", "UUID"), s("ts", "DateTime64(3)")];
        let source = vec![s("id", "UUID"), s("ts", "DateTime64(6)")];
        assert!(columns_type_drift(&wrapper, &source));
        // Presence-only difference (source has an extra column) → NOT drift
        // (handled by the ADD path, not recreate).
        let wrapper = vec![s("id", "UUID")];
        let source = vec![s("id", "UUID"), s("new_col", "String")];
        assert!(!columns_type_drift(&wrapper, &source));
        // Expression/default-only difference on a common column → NOT drift.
        let wrapper = vec![(
            "c".to_string(),
            "UInt8".to_string(),
            "MATERIALIZED".to_string(),
            "1".to_string(),
        )];
        let source = vec![(
            "c".to_string(),
            "UInt8".to_string(),
            "MATERIALIZED".to_string(),
            "2".to_string(),
        )];
        assert!(!columns_type_drift(&wrapper, &source));
    }

    // NAN-4906: version-gated MergeTree settings.
    const AGG_DDL: &str = "CREATE TABLE IF NOT EXISTS nanosiem.ip_prevalence_agg (ip String, is_private UInt8, \
        n SimpleAggregateFunction(sum, UInt64)) ENGINE = AggregatingMergeTree() ORDER BY ip \
        SETTINGS index_granularity = 8192, allow_dimensions_outside_sorting_key = 1;";

    #[test]
    fn test_parse_server_version() {
        assert_eq!(ClickHouseMigrator::parse_server_version("26.10.3.7"), Some((26, 10)));
        assert_eq!(
            ClickHouseMigrator::parse_server_version("26.4.5.143 (official build)"),
            Some((26, 4))
        );
        assert_eq!(ClickHouseMigrator::parse_server_version("garbage"), None);
        assert_eq!(ClickHouseMigrator::parse_server_version(""), None);
    }

    #[test]
    fn test_strip_settings_unsupported_by_old_server() {
        let out = ClickHouseMigrator::strip_settings_unsupported_by(AGG_DDL, Some((26, 4)));
        assert!(!out.contains("allow_dimensions_outside_sorting_key"), "{out}");
        assert!(out.contains("SETTINGS index_granularity = 8192;"), "{out}");
    }

    #[test]
    fn test_strip_settings_kept_on_new_or_unknown_server() {
        for v in [Some((26, 7)), Some((26, 10)), Some((27, 1)), None] {
            assert_eq!(ClickHouseMigrator::strip_settings_unsupported_by(AGG_DDL, v), AGG_DDL);
        }
    }

    #[test]
    fn test_repo_agg_ddl_carries_dimensions_setting() {
        // Every prevalence *_agg table in both init files opts in, or a fresh
        // 26.7+ install fails at CREATE (Code 36).
        for path in ["../clickhouse/init.sql", "../clickhouse/ocsf/init.sql"] {
            let sql = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
                .expect("read init sql");
            for t in ["domain_prevalence_agg", "hash_prevalence_agg", "ip_prevalence_agg"] {
                let start = sql
                    .find(&format!("CREATE TABLE IF NOT EXISTS nanosiem.{t}"))
                    .unwrap_or_else(|| panic!("{t} missing in {path}"));
                let stmt = &sql[start..start + sql[start..].find("SETTINGS").unwrap() + 120];
                assert!(stmt.contains("allow_dimensions_outside_sorting_key = 1"), "{t} in {path}");
            }
        }
    }

    /// NAN-4906: plain columns of an AggregatingMergeTree CREATE that are in
    /// neither the sorting key nor the partition key. CH 26.7+ rejects such a
    /// table (Code 36) unless it sets `allow_dimensions_outside_sorting_key = 1`.
    fn agg_dimensions_outside_key(stmt: &str) -> Vec<String> {
        let ident = regex::Regex::new(r"[A-Za-z_][A-Za-z0-9_]*").unwrap();
        let Some(engine_at) = stmt.find("ENGINE") else { return vec![] };
        let Some(open) = stmt[..engine_at].find('(') else { return vec![] }; // CREATE ... AS
        // Column list: from the first '(' to its matching ')'.
        let (mut depth, mut close) = (0usize, None);
        for (i, c) in stmt[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let cols = &stmt[open + 1..close.expect("unbalanced column list")];
        let mut items = Vec::new();
        let (mut depth, mut start) = (0usize, 0usize);
        for (i, c) in cols.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                ',' if depth == 0 => {
                    items.push(&cols[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
        items.push(&cols[start..]);

        // Identifiers referenced by ORDER BY / PARTITION BY.
        let tail = &stmt[engine_at..];
        let clause = regex::Regex::new(
            r"(?s)(?:ORDER|PARTITION) BY(.*?)(?:\bORDER BY\b|\bPARTITION BY\b|\bPRIMARY KEY\b|\bSAMPLE BY\b|\bTTL\b|\bSETTINGS\b|$)",
        )
        .unwrap();
        let mut key: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut pos = 0;
        while let Some(m) = clause.captures(&tail[pos..]) {
            let g = m.get(1).unwrap();
            key.extend(ident.find_iter(g.as_str()).map(|i| i.as_str().to_string()));
            pos += g.end();
            if g.as_str().is_empty() {
                break;
            }
        }

        let mut out = Vec::new();
        for item in items {
            let item = item.trim();
            let upper = item.to_ascii_uppercase();
            if item.is_empty()
                || ["INDEX ", "PROJECTION ", "CONSTRAINT "].iter().any(|k| upper.starts_with(k))
                || upper.contains(" ALIAS ")
                || upper.contains(" EPHEMERAL")
            {
                continue;
            }
            let (name, ty) = item.split_once(char::is_whitespace).unwrap_or((item, ""));
            let name = name.trim_matches('`');
            let ty = ty.trim_start();
            if ty.starts_with("AggregateFunction") || ty.starts_with("SimpleAggregateFunction") {
                continue;
            }
            if !key.contains(name) {
                out.push(name.to_string());
            }
        }
        out
    }

    #[test]
    fn test_agg_dimension_detector_flags_unopted_ddl() {
        let unopted = AGG_DDL.replace(", allow_dimensions_outside_sorting_key = 1", "");
        assert_eq!(agg_dimensions_outside_key(&unopted), vec!["is_private".to_string()]);
    }

    #[test]
    fn test_every_agg_ddl_is_valid_on_26_7_plus() {
        // NAN-4906: any AggregatingMergeTree CREATE the migrator can run on a
        // 26.7+ server (pending numbered migrations on an old tenant, or either
        // init file) must either keep every plain column in the sorting /
        // partition key or opt in with allow_dimensions_outside_sorting_key = 1.
        // Otherwise that tenant's boot fails with Code 36 after the upgrade.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../clickhouse");
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&root)
            .expect("read clickhouse dir")
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.extension().is_some_and(|e| e == "sql")
                    && p.file_name().unwrap().to_string_lossy().starts_with(|c: char| c.is_ascii_digit())
            })
            .collect();
        files.push(root.join("init.sql"));
        files.push(root.join("ocsf/init.sql"));
        let mut checked = 0;
        let mut bad = Vec::new();
        for f in &files {
            let sql = ClickHouseMigrator::strip_sql_line_comments(&std::fs::read_to_string(f).unwrap());
            for stmt in sql.split(';') {
                if !stmt.contains("CREATE TABLE") || !stmt.contains("AggregatingMergeTree") {
                    continue;
                }
                checked += 1;
                if stmt.contains("allow_dimensions_outside_sorting_key = 1") {
                    continue;
                }
                let dims = agg_dimensions_outside_key(stmt);
                if !dims.is_empty() {
                    let table = ClickHouseMigrator::parse_create_table_name(stmt).unwrap_or_default();
                    bad.push(format!("{}: {table} {dims:?}", f.display()));
                }
            }
        }
        assert!(checked >= 20, "only {checked} AggregatingMergeTree CREATEs found; detector broken?");
        assert!(bad.is_empty(), "AggregatingMergeTree dimensions outside the key without the opt-in:\n{}", bad.join("\n"));
    }
}
