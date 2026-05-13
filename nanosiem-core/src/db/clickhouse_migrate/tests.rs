// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for ClickHouse migration system.

#[cfg(test)]
mod tests {
    use crate::db::clickhouse_migrate::*;
    use std::io::Write;
    use std::path::Path;
    use tempfile::TempDir;

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
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
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
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
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
    fn test_cluster_create_table_aggregating() {
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.domain_prevalence_agg (domain String) ENGINE = AggregatingMergeTree() ORDER BY (domain)";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
        assert!(
            result.contains("ReplicatedAggregatingMergeTree("),
            "Should convert to ReplicatedAggregatingMergeTree: {}",
            result
        );
    }

    #[test]
    fn test_cluster_create_table_replacing() {
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.custom_enrichment_results (key String) ENGINE = ReplacingMergeTree(version) ORDER BY (key)";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
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
    fn test_replicated_db_empty_args() {
        // When cluster name == database name (Replicated database auto-cluster),
        // use empty args — CH manages ZooKeeper paths automatically
        let sql = "CREATE TABLE IF NOT EXISTS nanosiem.logs (id UUID) ENGINE = MergeTree PARTITION BY toYYYYMMDD(timestamp) ORDER BY (timestamp) SETTINGS index_granularity = 8192";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem", "nanosiem");
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
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem", "nanosiem");
        assert!(
            result.contains("ReplicatedReplacingMergeTree(version)"),
            "Should preserve version arg without zoo path: {}",
            result
        );
    }

    #[test]
    fn test_replicated_db_skips_create_database() {
        let sql = "CREATE DATABASE IF NOT EXISTS nanosiem";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem", "nanosiem");
        assert!(
            !result.contains("ON CLUSTER"),
            "Should NOT add ON CLUSTER for Replicated database: {}",
            result
        );
        assert_eq!(result, sql, "Should return CREATE DATABASE unchanged");
    }

    #[test]
    fn test_cluster_no_duplicate_storage_policy() {
        // Migration 085 already has storage_policy in SETTINGS — don't duplicate it
        let sql = "CREATE TABLE nanosiem.logs (id UUID) ENGINE = MergeTree PARTITION BY toYYYYMMDD(timestamp) ORDER BY (timestamp) SETTINGS index_granularity = 8192, storage_policy = 'tiered', allow_experimental_full_text_index = 1";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
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
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
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
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
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
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should add ON CLUSTER to ALTER: {}",
            result
        );
    }

    #[test]
    fn test_cluster_alter_table_unqualified() {
        let sql = "ALTER TABLE logs DROP INDEX IF EXISTS idx_command_line";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should add ON CLUSTER to unqualified ALTER: {}",
            result
        );
    }

    #[test]
    fn test_cluster_materialized_view() {
        let sql = "CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.domain_prevalence_mv TO nanosiem.domain_prevalence_agg AS SELECT 1";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should add ON CLUSTER to MV: {}",
            result
        );
    }

    #[test]
    fn test_cluster_dictionary() {
        let sql = "CREATE DICTIONARY IF NOT EXISTS nanosiem.hash_prevalence_dict (file_hash String) PRIMARY KEY file_hash SOURCE(CLICKHOUSE(HOST 'localhost' PORT 9000 USER 'nanosiem' DB 'nanosiem')) LIFETIME(MIN 300 MAX 600) LAYOUT(SPARSE_HASHED())";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should add ON CLUSTER to DICTIONARY: {}",
            result
        );
        assert!(
            result.contains("PORT 9001"),
            "Should fix port to 9001: {}",
            result
        );
        assert!(
            !result.contains("PORT 9000"),
            "Should NOT have old port 9000: {}",
            result
        );
    }

    #[test]
    fn test_cluster_create_or_replace_dictionary() {
        let sql = "CREATE OR REPLACE DICTIONARY nanosiem.hash_prevalence_dict (file_hash String) PRIMARY KEY file_hash SOURCE(CLICKHOUSE(HOST 'localhost' PORT 9000 USER 'nanosiem' DB 'nanosiem')) LIFETIME(MIN 300 MAX 600) LAYOUT(SPARSE_HASHED())";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
        assert!(
            result.contains("ON CLUSTER 'nanosiem_cluster'"),
            "Should add ON CLUSTER to CREATE OR REPLACE DICTIONARY: {}",
            result
        );
    }

    #[test]
    fn test_cluster_truncate_table() {
        let sql = "TRUNCATE TABLE nanosiem.logs";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
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
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
        assert!(
            result.trim().is_empty(),
            "Should skip non_replicated_deduplication_window: '{}'",
            result
        );
    }

    #[test]
    fn test_cluster_skips_set_statements() {
        let sql = "SET allow_experimental_full_text_index = 1";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
        assert_eq!(result, sql, "SET statements should pass through unchanged");
    }

    #[test]
    fn test_cluster_preserves_existing_on_cluster() {
        let sql = "CREATE TABLE nanosiem.test ON CLUSTER 'my_cluster' (id Int32) ENGINE = ReplicatedMergeTree('/path', '{replica}') ORDER BY id";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
        assert_eq!(
            result, sql,
            "Should not modify SQL that already has ON CLUSTER"
        );
    }

    #[test]
    fn test_cluster_drop_table() {
        let sql = "DROP TABLE IF EXISTS nanosiem.old_table";
        let result = ClickHouseMigrator::transform_for_cluster(sql, "nanosiem_cluster", "nanosiem");
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
        std::env::remove_var("POSTGRES_DICT_HOST");
        std::env::remove_var("POSTGRES_DICT_PASSWORD");
    }

    /// NAN-707: numbered migrations now get the same `{clickhouse_self_*}`
    /// substitution that init.sql has always done. Without this, a migration
    /// like `CREATE OR REPLACE DICTIONARY ... USER '{clickhouse_self_user}'`
    /// would write the literal placeholder text into the dict definition and
    /// dictGet would fail authentication.
    #[test]
    fn test_substitute_clickhouse_self_vars_replaces_all_four_placeholders() {
        std::env::set_var("CLICKHOUSE_SELF_HOST", "ch-shard-0.svc");
        std::env::set_var("CLICKHOUSE_SELF_PORT", "9001");
        std::env::set_var("CLICKHOUSE_SELF_USER", "rotated_admin");
        std::env::set_var("CLICKHOUSE_SELF_PASSWORD", "rotated_pw_xyz");

        let sql = "SOURCE(CLICKHOUSE(HOST '{clickhouse_self_host}' PORT {clickhouse_self_port} \
                   USER '{clickhouse_self_user}' PASSWORD '{clickhouse_self_password}' DB 'nanosiem'))";
        let result = ClickHouseMigrator::substitute_clickhouse_self_vars(sql);

        assert!(result.contains("HOST 'ch-shard-0.svc'"), "host: {}", result);
        assert!(result.contains("PORT 9001"), "port: {}", result);
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
    }

    /// Sanity: the helper falls back to localhost:9000 / default user when
    /// no env is set. This is the dev / single-node default.
    #[test]
    fn test_substitute_clickhouse_self_vars_defaults_when_unset() {
        // Make sure no env vars from other tests leak in (cargo runs tests in
        // parallel by default, so we can't fully isolate, but we can clear).
        std::env::remove_var("CLICKHOUSE_SELF_HOST");
        std::env::remove_var("CLICKHOUSE_SELF_PORT");

        let sql = "HOST '{clickhouse_self_host}' PORT {clickhouse_self_port}";
        let result = ClickHouseMigrator::substitute_clickhouse_self_vars(sql);

        assert!(result.contains("HOST 'localhost'"), "host: {}", result);
        assert!(result.contains("PORT 9000"), "port: {}", result);
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
            "pw'with\\stuff",
        );

        assert!(
            result.contains("password 'pw''with\\\\stuff'"),
            "pg password not escaped: {}",
            result
        );
    }
}
