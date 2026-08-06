// SPDX-License-Identifier: AGPL-3.0-or-later

//! SQL transformation utilities for ClickHouse Cloud and cluster compatibility.

use super::ClickHouseMigrator;
use regex::Regex;

/// `SIZE_IN_CELLS` for `ip_prevalence_dict` when `NANO_PREVALENCE_CACHE_CELLS_IP`
/// is unset — the NAN-706 bump, preserved so un-provisioned installs are
/// byte-identical. See `substitute_prevalence_cache_cells`.
pub(super) const DEFAULT_PREVALENCE_CACHE_CELLS_IP: u32 = 5_000_000;

/// `SIZE_IN_CELLS` for `domain_prevalence_dict` / `hash_prevalence_dict` when
/// `NANO_PREVALENCE_CACHE_CELLS` is unset.
pub(super) const DEFAULT_PREVALENCE_CACHE_CELLS: u32 = 1_000_000;

impl ClickHouseMigrator {
    /// Strip `--` line comments from SQL.
    ///
    /// NAN-788: must run **before** any credential substitution. After
    /// substitution, a generated password containing `--` (legitimate in
    /// base64url alphabets) would otherwise look like a comment start and
    /// eat the rest of the line — including the closing `'` of the
    /// surrounding string literal — turning the next line into mid-string
    /// content and tripping a "Single quoted string is not closed" parse
    /// error in ClickHouse 26.3+.
    ///
    /// The source SQL we control has no `--` inside string literals, so a
    /// naive line-by-line strip is safe pre-substitution.
    pub(super) fn strip_sql_line_comments(sql: &str) -> String {
        sql.lines()
            .map(|line| match line.find("--") {
                Some(pos) => &line[..pos],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// NAN-1384: detect the `nano:skip-if-unknown-table` block-comment marker.
    ///
    /// ClickHouse has no `ALTER TABLE IF EXISTS`, so migrations that target a
    /// profile-gated table (e.g. `nanosiem.ocsf_logs`, which only exists on
    /// OCSF-profile deployments) tag each statement with an inline
    /// `/* nano:skip-if-unknown-table */` marker. The runner then tolerates an
    /// UNKNOWN_TABLE failure on exactly those statements. The marker must be a
    /// `/* */` block comment — `--` line comments are stripped before
    /// statement splitting (see `strip_sql_line_comments`).
    pub(super) fn has_skip_if_unknown_table_marker(sql: &str) -> bool {
        sql.contains("nano:skip-if-unknown-table")
    }

    /// NAN-1384: does this ClickHouse error message indicate the target table
    /// does not exist? Matches the stable `UNKNOWN_TABLE` error-code name that
    /// CH embeds in the exception text (e.g. `Code: 60. DB::Exception: Table
    /// nanosiem.ocsf_logs does not exist. (UNKNOWN_TABLE)`).
    pub(super) fn is_unknown_table_error(message: &str) -> bool {
        message.contains("UNKNOWN_TABLE")
    }

    /// NAN-1407: detect the `nano:keep-local-engine` block-comment marker.
    ///
    /// The dictionary staging tables (`*_dict_staging`) must stay PLAIN
    /// MergeTree on every topology: each replica keeps its own local copy,
    /// refreshed by its own refreshable MV. `transform_for_cluster` normally
    /// rewrites `MergeTree` → `ReplicatedMergeTree` for cluster deployments,
    /// but a replicated staging table is not just wrong — ClickHouse REFUSES
    /// to create a full-replace (non-APPEND) refreshable MV targeting a
    /// replicated table in a non-Replicated database ("Each refresh would
    /// replace the replicated table locally, but other replicas wouldn't see
    /// it"), so the conversion would abort the migration on exactly the
    /// clustered tenants this pattern protects. A statement carrying this
    /// marker still gets `ON CLUSTER` fan-out (the DDL runs on every node)
    /// but keeps its engine as written. Must be a `/* */` block comment —
    /// `--` line comments are stripped before statement splitting.
    pub(super) fn has_keep_local_engine_marker(sql: &str) -> bool {
        sql.contains("nano:keep-local-engine")
    }


    /// Escape a value for use inside a single-quoted ClickHouse string literal.
    ///
    /// CH treats `\` as an escape character inside `'...'` strings, so a
    /// backslash in a substituted value can escape the closing quote and
    /// break the literal. Double `\` first, then double `'`. NAN-788.
    fn escape_for_string_literal(value: &str) -> String {
        value.replace('\\', "\\\\").replace('\'', "''")
    }

    /// Substitute `{clickhouse_self_*}` placeholders in dictionary SOURCE blocks
    /// that reference the local CH instance.
    ///
    /// NAN-707: Historically only `init.sql` ran this substitution (see the
    /// inline `replace(...)` chain in `runner::run_init_sql`). Numbered migrations
    /// got the placeholder text verbatim, so any migration referencing the local
    /// CH instance had to hardcode credentials — and `nanosiem`/`nanosiem` only
    /// happened to work because most tenants kept the default password. Saturn
    /// rotated, migration 114 hit AUTHENTICATION_FAILED, and every dictGet
    /// against the IP prevalence dict broke.
    ///
    /// Now both code paths share this helper so the same placeholder semantics
    /// apply everywhere.
    ///
    /// NAN-788: host/user/password are spliced into `'...'` string literals in
    /// the source SQL, so `'` and `\` in those values are SQL-escaped before
    /// substitution. Port is numeric and not escaped.
    pub(super) fn substitute_clickhouse_self_vars(sql: &str) -> String {
        let ch_self_host =
            std::env::var("CLICKHOUSE_SELF_HOST").unwrap_or_else(|_| "localhost".into());
        let ch_self_port =
            std::env::var("CLICKHOUSE_SELF_PORT").unwrap_or_else(|_| "9000".into());
        let ch_self_user = std::env::var("CLICKHOUSE_SELF_USER")
            .or_else(|_| std::env::var("CLICKHOUSE_USER"))
            .unwrap_or_else(|_| "default".into());
        let ch_self_password = std::env::var("CLICKHOUSE_SELF_PASSWORD")
            .or_else(|_| std::env::var("CLICKHOUSE_PASSWORD"))
            .unwrap_or_default();
        Self::substitute_clickhouse_self_vars_with(
            sql,
            &ch_self_host,
            &ch_self_port,
            &ch_self_user,
            &ch_self_password,
        )
    }

    /// Env-free variant exposed for tests so escape/substitute behavior can be
    /// exercised deterministically without `cargo test`'s parallel env races.
    ///
    /// NAN-788 follow-up: `port` is validated as a u16 because it's spliced
    /// naked (no surrounding quotes) into the SQL. A non-numeric value would
    /// produce a confusing CH parse error far from the configuration site;
    /// panicking here surfaces the misconfiguration at migrator startup with
    /// a clear message.
    pub(super) fn substitute_clickhouse_self_vars_with(
        sql: &str,
        host: &str,
        port: &str,
        user: &str,
        password: &str,
    ) -> String {
        if port.parse::<u16>().is_err() {
            panic!(
                "CLICKHOUSE_SELF_PORT must be a valid u16 (1-65535), got {:?}",
                port
            );
        }
        sql.replace(
            "{clickhouse_self_host}",
            &Self::escape_for_string_literal(host),
        )
        .replace("{clickhouse_self_port}", port)
        .replace(
            "{clickhouse_self_user}",
            &Self::escape_for_string_literal(user),
        )
        .replace(
            "{clickhouse_self_password}",
            &Self::escape_for_string_literal(password),
        )
    }

    /// NAN-1728: resolve the general `{dist_suffix}` placeholder — appended after
    /// ANY base table name in migration / init SQL — to the correct read target
    /// for the detected topology, from ONE static definition:
    ///   - clustered  → `{dist_suffix}` = `"_distributed"` (read the wrapper)
    ///   - single-node → `{dist_suffix}` = `""`            (read the local table)
    ///
    /// Used wherever SQL must read cross-shard on a cluster but the plain local
    /// table on single-node — e.g. the prevalence CACHE-dict SOURCE QUERYs
    /// (`FROM nanosiem.hash_prevalence_summary{dist_suffix}`) and reference-table
    /// reads (`FROM nanosiem.ip_enrichments{dist_suffix}`). The three
    /// `*_prevalence_summary` tables are per-shard AggregatingMergeTree summaries;
    /// a dict reading the LOCAL summary on a multi-shard cluster sees only ~1/N of
    /// the hosts (broken rare/common verdicts, C3), so on a cluster it must read
    /// the reconciler-created `_distributed` wrapper to fan `uniqMerge` across
    /// shards. On a TRUE single-node deployment (dev / open-core install.sh, no
    /// `<remote_servers>`) `detect_cluster()` is `None`, `ensure_distributed_tables`
    /// is a no-op, and no wrapper exists — the SQL must read the plain local table.
    /// Hardcoding `_distributed` breaks single-node with
    /// `CACHE_DICTIONARY_UPDATE_FAIL` on the first ingest-time `dictGet` (a
    /// fail-closed ingest halt); creating a `*_distributed` object on single-node
    /// is forbidden (it would false-positive `DualPool`'s
    /// `logs_distributed`-presence cluster detection). Hence a substitution.
    ///
    /// The `is_clustered` signal is the SAME `detect_cluster()` result the
    /// reconciler uses to decide whether to create the wrappers, so the read
    /// target and wrapper existence can never disagree.
    pub(super) fn substitute_dist_suffix(sql: &str, is_clustered: bool) -> String {
        let suffix = if is_clustered { "_distributed" } else { "" };
        sql.replace("{dist_suffix}", suffix)
    }

    /// NAN-2346: resolve `{prevalence_cache_cells}` / `{prevalence_cache_cells_ip}`
    /// — the `SIZE_IN_CELLS` of the three prevalence CACHE dicts — so a small box
    /// can size them to its own memory instead of inheriting a fleet-wide constant.
    ///
    /// `COMPLEX_KEY_CACHE` preallocates its ENTIRE cell array at the first
    /// `dictGet`, regardless of how many keys are ever resident, and ClickHouse
    /// rounds `SIZE_IN_CELLS` UP to the next power of two. The hardcoded 5,000,000
    /// therefore allocates 2^23 cells; measured at ~40 B/cell that is 320 MiB, and
    /// the three dicts together preallocate ~400 MiB. (In-repo comments citing
    /// "~80 B/row" are wrong — 320.02 MiB / 2^23 is exactly 40.0 B/cell.)
    ///
    /// That budget buys nothing in practice: `therange` held 2 / 8 / 1 elements,
    /// and `org` — the central aggregator, ~12M dictionary queries — holds 1 each
    /// at a 99.6–99.99% hit rate. On a 4 GB hobby box (CH capped at 1.6 GiB before
    /// NAN-2346) those 400 MiB were a quarter of the server's whole budget, enough
    /// that `ip_enrichment_dict` could not build its ~3.4M-range IP_TRIE and sat
    /// `LOADED` with `element_count 0` — silently serving enrichment defaults while
    /// ingest looked perfectly healthy.
    ///
    /// Shrinking is only safe from migration 162 onward, where the SOURCE became a
    /// point lookup on the local `*_prevalence_final` (~326 KiB per miss). Against
    /// the pre-162 per-miss `uniqMerge` fan-out a small cache meant NAN-706 CPU
    /// pinning and 6000 ms dict-source timeouts falling back to the 9999 "common"
    /// default (NAN-1761 #2). Since these placeholders only ever appear in ≥172
    /// bodies, that ordering is structural.
    ///
    /// Unset, both resolve to today's literals (5,000,000 for ip — the NAN-706
    /// bump — and 1,000,000 for domain/hash), so k8s, BYOC, dev compose and
    /// open-core installs stay byte-identical; only tenants whose generated `.env`
    /// carries the vars get a smaller cache. Values are validated as `u32` for the
    /// same reason `{clickhouse_self_port}` is: they are spliced naked into the
    /// DDL, so a non-numeric value would surface as a confusing CH parse error far
    /// from the misconfiguration site.
    pub(super) fn substitute_prevalence_cache_cells(sql: &str) -> String {
        let ip_cells = std::env::var("NANO_PREVALENCE_CACHE_CELLS_IP")
            .unwrap_or_else(|_| DEFAULT_PREVALENCE_CACHE_CELLS_IP.to_string());
        let cells = std::env::var("NANO_PREVALENCE_CACHE_CELLS")
            .unwrap_or_else(|_| DEFAULT_PREVALENCE_CACHE_CELLS.to_string());
        Self::substitute_prevalence_cache_cells_with(sql, &ip_cells, &cells)
    }

    /// Env-free variant exposed for tests, mirroring
    /// `substitute_clickhouse_self_vars_with` so behavior can be exercised without
    /// `cargo test`'s parallel env races.
    pub(super) fn substitute_prevalence_cache_cells_with(
        sql: &str,
        ip_cells: &str,
        cells: &str,
    ) -> String {
        for (name, value) in [
            ("NANO_PREVALENCE_CACHE_CELLS_IP", ip_cells),
            ("NANO_PREVALENCE_CACHE_CELLS", cells),
        ] {
            match value.parse::<u32>() {
                Ok(0) => panic!("{name} must be greater than 0, got {value:?}"),
                Ok(_) => {}
                Err(_) => panic!("{name} must be a valid u32, got {value:?}"),
            }
        }
        // The closing brace disambiguates the two names, so replacement order is
        // not load-bearing; longest-first is kept as defensive style in case a
        // future placeholder is added without one.
        sql.replace("{prevalence_cache_cells_ip}", ip_cells)
            .replace("{prevalence_cache_cells}", cells)
    }

    /// Substitute PostgreSQL connection details in dictionary SOURCE blocks.
    ///
    /// Replaces hardcoded Docker Compose defaults (`host 'postgres'`, `password 'nanosiem'`)
    /// with values from environment variables so dictionaries work in cloud deployments
    /// where Postgres runs at a different hostname with a generated password.
    pub(super) fn substitute_postgres_vars(sql: &str) -> String {
        let pg_host = std::env::var("POSTGRES_DICT_HOST")
            .or_else(|_| std::env::var("POSTGRES_HOST"))
            .unwrap_or_else(|_| "postgres".into());
        let pg_password = std::env::var("POSTGRES_DICT_PASSWORD")
            .or_else(|_| std::env::var("POSTGRES_PASSWORD"))
            .unwrap_or_else(|_| "nanosiem".into());
        Self::substitute_postgres_vars_with(sql, &pg_host, &pg_password)
    }

    /// Env-free variant exposed for tests. See `substitute_postgres_vars`.
    pub(super) fn substitute_postgres_vars_with(
        sql: &str,
        host: &str,
        password: &str,
    ) -> String {
        // NAN-788: pg_host/pg_password are spliced into `'...'` literals;
        // SQL-escape `'` and `\` so a generated password can't break the literal.
        let pg_host = Self::escape_for_string_literal(host);
        let pg_password = Self::escape_for_string_literal(password);

        // Replace the hardcoded values in SOURCE(POSTGRESQL(...)) blocks
        let re_host =
            Regex::new(r"(?i)(SOURCE\s*\(\s*POSTGRESQL\s*\([^)]*?)host\s+'postgres'").unwrap();
        let result = re_host
            .replace_all(sql, |caps: &regex::Captures| {
                format!("{}host '{}'", &caps[1], pg_host)
            })
            .to_string();

        let re_pass =
            Regex::new(r"(?i)(SOURCE\s*\(\s*POSTGRESQL\s*\([^)]*?)password\s+'nanosiem'").unwrap();
        re_pass
            .replace_all(&result, |caps: &regex::Captures| {
                format!("{}password '{}'", &caps[1], pg_password)
            })
            .to_string()
    }

    /// Sanitize SQL for ClickHouse Cloud compatibility.
    ///
    /// CH Cloud has restrictions that self-hosted doesn't:
    /// - `storage_policy = 'tiered'` - Cloud manages storage internally
    /// - `allow_experimental_full_text_index` - constrained, cannot be changed
    /// - `enable_full_text_index` - doesn't exist in some CH Cloud versions
    /// - `text()` index type - requires the experimental setting above
    ///
    /// Instead of skipping entire statements, we strip the incompatible parts
    /// so the core DDL still executes.
    pub(super) fn sanitize_for_cloud(sql: &str) -> String {
        let mut s = sql.to_string();

        // 1. Remove storage_policy from SETTINGS clauses
        //    e.g. ", storage_policy = 'tiered'" or "storage_policy = 'tiered', "
        let re = Regex::new(r#"(?i),?\s*storage_policy\s*=\s*'[^']*'\s*,?"#).unwrap();
        s = re
            .replace_all(&s, |caps: &regex::Captures| {
                // If it matched comma on both sides, keep one comma
                let m = caps.get(0).unwrap().as_str();
                if m.starts_with(',') && m.ends_with(',') {
                    ","
                } else {
                    ""
                }
                .to_string()
            })
            .to_string();

        // 2. Remove full-text index experimental settings from inline SETTINGS clauses
        //    Handles: allow_experimental_full_text_index = 1, enable_full_text_index = 1
        for setting_name in &[
            "allow_experimental_full_text_index",
            "enable_full_text_index",
        ] {
            let re = Regex::new(&format!(
                r"(?i),?\s*{}\s*=\s*\d+\s*,?",
                regex::escape(setting_name)
            ))
            .unwrap();
            s = re
                .replace_all(&s, |caps: &regex::Captures| {
                    let m = caps.get(0).unwrap().as_str();
                    if m.starts_with(',') && m.trim_end().ends_with(',') {
                        ","
                    } else {
                        ""
                    }
                    .to_string()
                })
                .to_string();
        }

        // 3. Remove `text()` index type declarations (requires experimental setting)
        //    e.g. "INDEX idx_message_ft lower(message) TYPE text(tokenizer = ngrams(3)) GRANULARITY 100000000"
        //    Handle nested parens: text(tokenizer = ngrams(3))
        let re = Regex::new(
            r"(?i),?\s*INDEX\s+\w+\s+(?:\w+(?:\([^)]*\))?|\w+)\s+TYPE\s+text\([^()]*(?:\([^()]*\))?[^()]*\)\s+GRANULARITY\s+\d+"
        ).unwrap();
        s = re.replace_all(&s, "").to_string();

        // 4. Clean up empty or trailing SETTINGS clauses
        //    "SETTINGS ;" -> ";"   "SETTINGS \n" -> ""
        let re = Regex::new(r"(?i)SETTINGS\s*([;\n]|$)").unwrap();
        s = re.replace_all(&s, "$1").to_string();
        // "SETTINGS ," -> "SETTINGS "
        let re = Regex::new(r"(?i)SETTINGS\s*,").unwrap();
        s = re.replace_all(&s, "SETTINGS ").to_string();

        s
    }

    /// Rewrite a `*MergeTree` engine clause to its `Replicated*` variant in
    /// place, preserving any version argument for ReplacingMergeTree.
    ///
    /// Shared by the `CREATE TABLE` and inline-engine `CREATE MATERIALIZED VIEW`
    /// transform branches (M-2/D5) so both replicate the engine identically.
    /// `replicated_db` (CH Cloud or a Replicated-database self-hosted setup) →
    /// empty engine args (CH manages zoo paths); an explicit cluster → the given
    /// `zoo_path` + `{replica}` macro.
    fn replicate_engine(mut s: String, zoo_path: &str, replicated_db: bool) -> String {
        let (mt_args, amt_args, smt_args) = if replicated_db {
            ("()".to_string(), "()".to_string(), "()".to_string())
        } else {
            (
                format!("('{}', '{{replica}}')", zoo_path),
                format!("('{}', '{{replica}}')", zoo_path),
                format!("('{}', '{{replica}}')", zoo_path),
            )
        };

        // MergeTree (with or without empty parens)
        let re_mt = Regex::new(r"(?i)\bENGINE\s*=\s*MergeTree(?:\s*\(\s*\))?").unwrap();
        if re_mt.is_match(&s) {
            s = re_mt
                .replace(
                    &s,
                    format!("ENGINE = ReplicatedMergeTree{}", mt_args).as_str(),
                )
                .to_string();
        }

        // AggregatingMergeTree (with or without empty parens)
        let re_amt =
            Regex::new(r"(?i)\bENGINE\s*=\s*AggregatingMergeTree(?:\s*\(\s*\))?").unwrap();
        if re_amt.is_match(&s) {
            s = re_amt
                .replace(
                    &s,
                    format!("ENGINE = ReplicatedAggregatingMergeTree{}", amt_args).as_str(),
                )
                .to_string();
        }

        // ReplacingMergeTree(version_col) - preserve the version argument
        let re_rmt = Regex::new(r"(?i)\bENGINE\s*=\s*ReplacingMergeTree\(([^)]+)\)").unwrap();
        if re_rmt.is_match(&s) {
            s = re_rmt
                .replace(&s, |caps: &regex::Captures| {
                    if replicated_db {
                        format!("ENGINE = ReplicatedReplacingMergeTree({})", &caps[1])
                    } else {
                        format!(
                            "ENGINE = ReplicatedReplacingMergeTree('{}', '{{replica}}', {})",
                            zoo_path, &caps[1]
                        )
                    }
                })
                .to_string();
        }

        // SummingMergeTree (with or without empty parens)
        let re_smt = Regex::new(r"(?i)\bENGINE\s*=\s*SummingMergeTree(?:\s*\(\s*\))?").unwrap();
        if re_smt.is_match(&s) {
            s = re_smt
                .replace(
                    &s,
                    format!("ENGINE = ReplicatedSummingMergeTree{}", smt_args).as_str(),
                )
                .to_string();
        }

        s
    }

    /// Transform a SQL statement for cluster mode.
    ///
    /// Applies the following transformations:
    /// - Adds `ON CLUSTER '{cluster}'` to DDL statements (CREATE, ALTER, DROP, TRUNCATE)
    /// - Converts MergeTree -> ReplicatedMergeTree with ZooKeeper paths
    /// - Converts AggregatingMergeTree -> ReplicatedAggregatingMergeTree
    /// - Converts ReplacingMergeTree -> ReplicatedReplacingMergeTree
    /// - Adds `storage_policy = 'tiered'` to main data tables (logs, signals)
    /// - Fixes ClickHouse dictionary source ports (9000 -> 9001 for operator)
    ///
    /// Statements that already contain ON CLUSTER are returned unchanged.
    ///
    /// `is_cloud=true` forces "Replicated database" mode regardless of cluster vs
    /// db name: ClickHouse Cloud reports `cluster_name="default"` against an
    /// arbitrarily-named database (e.g. `nanosiem`), but the database engine is
    /// always Replicated and rejects explicit `zookeeper_path` / `replica_name`
    /// args in `ReplicatedMergeTree(...)` with `BAD_ARGUMENTS (36)`. Treating
    /// `is_cloud` as "replicated DB" yields empty engine args (NAN-1092).
    pub(super) fn transform_for_cluster(
        statement: &str,
        cluster_name: &str,
        default_db: &str,
        is_cloud: bool,
    ) -> String {
        let trimmed = statement.trim();
        if trimmed.is_empty() {
            return statement.to_string();
        }

        let upper = trimmed.to_uppercase();

        // Skip if already has ON CLUSTER
        if upper.contains("ON CLUSTER") {
            return statement.to_string();
        }

        // Skip non-DDL statements (SET, INSERT, SELECT, SYSTEM, etc.)
        //
        // M-2/D5 TODO: GRANT/REVOKE are left untouched deliberately. Access
        // control DDL takes `ON CLUSTER` in the form `GRANT ON CLUSTER 'c' <priv>
        // ON db.* TO role` (the clause sits *before* the privilege, not after a
        // table name), so it can't reuse the append-after-name machinery below,
        // and a malformed rewrite would silently break dictionary-permission
        // grants (which are already soft-fail). On explicit clusters the operator
        // provisions users/roles cluster-wide out of band, so per-node GRANTs are
        // currently benign. If migrations start issuing GRANTs that must fan out,
        // add a dedicated `GRANT ON CLUSTER` branch (with its own tests) rather
        // than widening this one. Same reasoning for REVOKE.
        if upper.starts_with("SET ")
            || upper.starts_with("INSERT ")
            || upper.starts_with("SELECT ")
            || upper.starts_with("SYSTEM ")
            || upper.starts_with("GRANT ")
            || upper.starts_with("REVOKE ")
            || upper.starts_with("OPTIMIZE ")
        {
            return statement.to_string();
        }

        let mut s = statement.to_string();

        // Replicated-database mode: either (a) cluster name matches the database
        // (self-hosted Replicated DB setup) or (b) we're on ClickHouse Cloud
        // (cluster is always `default` regardless of db name; the engine forbids
        // explicit zoo args). Either way: no ON CLUSTER, empty engine args.
        // Explicit clusters (operator-managed `nanosiem_cluster`) still get the
        // ON CLUSTER clause and explicit zoo path + replica macro. NAN-1092.
        let replicated_db = is_cloud || cluster_name == default_db;
        let on_cluster_clause = if replicated_db {
            String::new()
        } else {
            format!(" ON CLUSTER '{}'", cluster_name)
        };

        // Helper: split "db.table" into (db, table), defaulting db if unqualified
        let split_name = |name: &str| -> (String, String) {
            if let Some(dot) = name.find('.') {
                (name[..dot].to_string(), name[dot + 1..].to_string())
            } else {
                (default_db.to_string(), name.to_string())
            }
        };

        // 1. CREATE DATABASE — skip entirely for Replicated DB (already exists, auto-propagates)
        if upper.starts_with("CREATE DATABASE") {
            if replicated_db {
                return s; // No-op: Replicated database already exists on all nodes
            }
            let re =
                Regex::new(r"(?i)(CREATE\s+DATABASE\s+(?:IF\s+NOT\s+EXISTS\s+)?)(\w+)").unwrap();
            s = re
                .replace(&s, |caps: &regex::Captures| {
                    format!("{}{}{}", &caps[1], &caps[2], on_cluster_clause)
                })
                .to_string();
            return s;
        }

        // 2. CREATE TABLE
        if upper.starts_with("CREATE TABLE") {
            // Extract name (qualified or unqualified)
            let re_name =
                Regex::new(r"(?i)(CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?)(\w+(?:\.\w+)?)")
                    .unwrap();

            let (db_name, table_name) = if let Some(caps) = re_name.captures(&s) {
                split_name(&caps[2])
            } else {
                return s;
            };

            // Insert ON CLUSTER after the table name (empty for Replicated DB)
            s = re_name
                .replace(&s, |caps: &regex::Captures| {
                    format!("{}{}{}", &caps[1], &caps[2], on_cluster_clause)
                })
                .to_string();

            // NAN-1407: per-replica local tables (dictionary staging) keep
            // their engine as written — ON CLUSTER fans the DDL out, but each
            // node gets an independent plain MergeTree. Converting these to
            // Replicated* would make ClickHouse REFUSE the full-replace
            // refreshable MV that repopulates them (see
            // has_keep_local_engine_marker). On CH Cloud plain MergeTree
            // auto-converts to SharedMergeTree, which is the coordinated-
            // refresh shape Cloud expects.
            if Self::has_keep_local_engine_marker(&s) {
                return s;
            }

            // Convert engine: MergeTree -> ReplicatedMergeTree
            //
            // Replicated-DB mode (either cluster==db OR CH Cloud) → empty args,
            // CH manages ZooKeeper paths automatically. Explicit clusters
            // (operator-managed nanosiem_cluster) → supply zoo path + replica
            // macro. NAN-1092.
            let replicated_db = is_cloud || cluster_name == default_db;
            let zoo_path = format!("/clickhouse/tables/{{shard}}/{}/{}", db_name, table_name);
            s = Self::replicate_engine(s, &zoo_path, replicated_db);

            // Add storage_policy = 'tiered' for main data tables (skip if already present).
            // ClickHouse Cloud manages hot/warm tiering internally — there's no
            // user-defined `tiered` policy on Cloud and the operator rejects the
            // setting with UNKNOWN_POLICY (Code 478). sanitize_for_cloud strips
            // `storage_policy` clauses from the source SQL, so skipping the
            // re-injection here is the matching half of that pass. NAN-1096.
            if !is_cloud
                && matches!(
                    table_name.as_str(),
                    "logs" | "signals" | "ingestion_errors" | "custom_enrichment_results"
                )
            {
                let upper_check = s.to_uppercase();
                if !upper_check.contains("STORAGE_POLICY") {
                    if let Some(settings_pos) = upper_check.rfind("SETTINGS ") {
                        let insert_at = settings_pos + "SETTINGS ".len();
                        s.insert_str(insert_at, "storage_policy = 'tiered', ");
                    }
                }
            }

            return s;
        }

        // 3. CREATE MATERIALIZED VIEW
        if upper.starts_with("CREATE MATERIALIZED VIEW") {
            let re = Regex::new(
                r"(?i)(CREATE\s+MATERIALIZED\s+VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?)(\w+(?:\.\w+)?)",
            )
            .unwrap();
            let (db_name, view_name) = if let Some(caps) = re.captures(&s) {
                split_name(&caps[2])
            } else {
                (default_db.to_string(), String::new())
            };
            s = re
                .replace(&s, |caps: &regex::Captures| {
                    format!("{}{}{}", &caps[1], &caps[2], on_cluster_clause)
                })
                .to_string();

            // M-2/D5: an inline-engine MV (`... ENGINE = *MergeTree ... AS
            // SELECT`, i.e. NOT the `TO <table>` form) owns its own storage and
            // must get a Replicated engine like a CREATE TABLE, otherwise it is a
            // non-replicated table on one node. Every MV in the tree is TO-form
            // today, so this branch is latent — but leaving it silent would
            // reintroduce the bug the moment an inline-engine MV is added. TO-form
            // MVs have no `ENGINE =`, so `replicate_engine` is a no-op for them.
            let re_engine = Regex::new(r"(?i)\bENGINE\s*=\s*\w*MergeTree").unwrap();
            if re_engine.is_match(&s) && !view_name.is_empty() {
                let zoo_path =
                    format!("/clickhouse/tables/{{shard}}/{}/{}", db_name, view_name);
                s = Self::replicate_engine(s, &zoo_path, replicated_db);
            }
            return s;
        }

        // 4. CREATE DICTIONARY (also handles CREATE OR REPLACE DICTIONARY)
        if upper.starts_with("CREATE DICTIONARY")
            || upper.starts_with("CREATE OR REPLACE DICTIONARY")
        {
            let re = Regex::new(
                r"(?i)(CREATE\s+(?:OR\s+REPLACE\s+)?DICTIONARY\s+(?:IF\s+NOT\s+EXISTS\s+)?)(\w+(?:\.\w+)?)",
            )
            .unwrap();
            s = re
                .replace(&s, |caps: &regex::Captures| {
                    format!("{}{}{}", &caps[1], &caps[2], on_cluster_clause)
                })
                .to_string();

            // Fix ClickHouse self-referencing dictionary port (operator uses 9001, not 9000)
            // Skip for Replicated DB — dictionaries connect to localhost:9000 inside the pod
            if !replicated_db {
                let re_port = Regex::new(r"(?i)\bPORT\s+9000\b").unwrap();
                s = re_port.replace_all(&s, "PORT 9001").to_string();
            }

            return s;
        }

        // 4b. CREATE [OR REPLACE] VIEW — plain (non-materialized) view. M-2/D5:
        // e.g. `nat_candidates_view`; without ON CLUSTER it exists on one node
        // only and any reader hitting another node 400s. (Checked AFTER the
        // MATERIALIZED VIEW branch, which returns first, so this only sees plain
        // views.)
        if upper.starts_with("CREATE VIEW") || upper.starts_with("CREATE OR REPLACE VIEW") {
            let re = Regex::new(
                r"(?i)(CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?)(\w+(?:\.\w+)?)",
            )
            .unwrap();
            s = re
                .replace(&s, |caps: &regex::Captures| {
                    format!("{}{}{}", &caps[1], &caps[2], on_cluster_clause)
                })
                .to_string();
            return s;
        }

        // 4c. CREATE [OR REPLACE] SETTINGS PROFILE — M-2/D5. The profile name is
        // a single-quoted literal (`'nanosiem_realtime'`); ON CLUSTER follows it.
        // Without ON CLUSTER the profile exists on one node, so the roles/users
        // that reference it resolve to different settings per shard.
        if upper.starts_with("CREATE SETTINGS PROFILE")
            || upper.starts_with("CREATE OR REPLACE SETTINGS PROFILE")
        {
            let re = Regex::new(
                r"(?i)(CREATE\s+(?:OR\s+REPLACE\s+)?SETTINGS\s+PROFILE\s+(?:IF\s+NOT\s+EXISTS\s+)?)('[^']+'|\w+)",
            )
            .unwrap();
            s = re
                .replace(&s, |caps: &regex::Captures| {
                    format!("{}{}{}", &caps[1], &caps[2], on_cluster_clause)
                })
                .to_string();
            return s;
        }

        // 5. ALTER TABLE
        if upper.starts_with("ALTER TABLE") {
            // In cluster mode, skip non_replicated_deduplication_window
            // (replicated_deduplication_window is set in global server config)
            if upper.contains("NON_REPLICATED_DEDUPLICATION_WINDOW") {
                tracing::debug!("Skipping non_replicated_deduplication_window in cluster mode");
                return String::new();
            }

            let re = Regex::new(r"(?i)(ALTER\s+TABLE\s+)(\w+(?:\.\w+)?)").unwrap();
            s = re
                .replace(&s, |caps: &regex::Captures| {
                    format!("{}{}{}", &caps[1], &caps[2], on_cluster_clause)
                })
                .to_string();
            return s;
        }

        // 6. TRUNCATE TABLE
        if upper.starts_with("TRUNCATE") {
            let re = Regex::new(r"(?i)(TRUNCATE\s+(?:TABLE\s+)?)(\w+(?:\.\w+)?)").unwrap();
            s = re
                .replace(&s, |caps: &regex::Captures| {
                    format!("{}{}{}", &caps[1], &caps[2], on_cluster_clause)
                })
                .to_string();
            return s;
        }

        // 7. DROP TABLE/VIEW/DICTIONARY
        if upper.starts_with("DROP ") {
            let is_drop_table = upper.starts_with("DROP TABLE");
            let re = Regex::new(
                r"(?i)(DROP\s+(?:TABLE|VIEW|DICTIONARY|MATERIALIZED\s+VIEW)\s+(?:IF\s+EXISTS\s+)?)(\w+(?:\.\w+)?)",
            )
            .unwrap();
            s = re
                .replace(&s, |caps: &regex::Captures| {
                    format!("{}{}{}", &caps[1], &caps[2], on_cluster_clause)
                })
                .to_string();

            // M-7/D12: `DROP TABLE ... ON CLUSTER` on a Replicated table must be
            // SYNC, otherwise the drop is asynchronous and a subsequent CREATE
            // with the same ZooKeeper path can race the still-registered replica
            // (the "poisoned znode" class — a leftover `/clickhouse/tables/...`
            // node makes the recreate fail with REPLICA_ALREADY_EXISTS). SYNC
            // waits for the local drop to fully deregister before returning.
            // Scoped to DROP TABLE (SYNC is a table-drop modifier); only when we
            // actually emitted ON CLUSTER (explicit cluster).
            if is_drop_table && !on_cluster_clause.is_empty() {
                let already_sync = {
                    let u = s.to_uppercase();
                    let t = u.trim_end();
                    t.ends_with("SYNC") || t.ends_with("SYNC;")
                };
                if !already_sync {
                    let had_semi = s.trim_end().ends_with(';');
                    let core = s.trim_end().trim_end_matches(';').trim_end();
                    s = if had_semi {
                        format!("{} SYNC;", core)
                    } else {
                        format!("{} SYNC", core)
                    };
                }
            }
            return s;
        }

        s
    }
}
