// SPDX-License-Identifier: AGPL-3.0-or-later

    use super::*;
    use crate::query::parser::parse_query;
    use crate::query::TimeRange;

    fn time_range() -> TimeRange {
        TimeRange {
            start: "2024-01-01T00:00:00Z".parse().unwrap(),
            end: "2024-01-02T00:00:00Z".parse().unwrap(),
        }
    }

    /// A1 (NAN-1623): every `MATERIALIZED_COLUMNS` entry must also appear in
    /// `EXPLICIT_COLUMNS`. MATERIALIZED columns are physical `logs` columns that
    /// ClickHouse excludes from `SELECT *`; the CTE re-add list (MATERIALIZED) and
    /// the field-router universe (EXPLICIT) are two hand-maintained lists that must
    /// stay in lockstep. If a MATERIALIZED column is absent from EXPLICIT, the
    /// router classifies it as an `ext` JSON field, so a filter like
    /// `enriched_src_country=US` silently reads `ext.enriched_src_country` (always
    /// NULL) instead of the real column — a no-exception wrong-results drift.
    /// Passes today (MATERIALIZED − EXPLICIT = ∅); fails the build on divergence.
    #[test]
    fn materialized_columns_are_subset_of_explicit() {
        let explicit: std::collections::HashSet<&str> = EXPLICIT_COLUMNS.iter().copied().collect();
        let missing: Vec<&str> = MATERIALIZED_COLUMNS
            .iter()
            .copied()
            .filter(|c| !explicit.contains(c))
            .collect();
        assert!(
            missing.is_empty(),
            "MATERIALIZED_COLUMNS entries absent from EXPLICIT_COLUMNS (would route to ext JSON \
             and silently return NULL): {missing:?}"
        );
    }

    /// NAN-1410: with `limit: None` (executor-owned pagination) the generator
    /// must NOT bake a trailing LIMIT into a raw single-stage query — a baked
    /// LIMIT turned the executor's LIMIT/OFFSET injection into a silent no-op,
    /// so page N re-served page 1's rows and total_count was capped at the
    /// page size.
    #[test]
    fn raw_single_stage_with_limit_none_emits_no_limit() {
        let gen = ClickHouseSqlGenerator::new();
        let query = parse_query("error").unwrap();
        let options = QueryOptions {
            limit: None,
            ..Default::default()
        };
        let sql = gen
            .generate_with_options(&query, &time_range(), &options)
            .unwrap();
        assert!(
            !sql.to_uppercase().contains(" LIMIT "),
            "executor-paginated raw query must carry no generator LIMIT, got:\n{sql}"
        );
        assert!(
            sql.contains("ORDER BY timestamp DESC"),
            "ordering must be preserved, got:\n{sql}"
        );
    }

    /// NAN-1410: default options keep the safety bound for callers that
    /// execute the generated SQL directly (explain, detection) — unchanged
    /// from the pre-fix behavior.
    #[test]
    fn raw_single_stage_default_options_keeps_safety_limit() {
        let gen = ClickHouseSqlGenerator::new();
        let query = parse_query("error").unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        assert!(
            sql.contains(&format!(
                "LIMIT {} ",
                ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT
            )),
            "default options must keep the safety LIMIT, got:\n{sql}"
        );
    }

    /// NAN-1410: an explicit caller limit is still baked (aggregation /
    /// tree / asset paths pass their own caps).
    #[test]
    fn raw_single_stage_explicit_limit_is_baked() {
        let gen = ClickHouseSqlGenerator::new();
        let query = parse_query("error").unwrap();
        let options = QueryOptions {
            limit: Some(10_000),
            ..Default::default()
        };
        let sql = gen
            .generate_with_options(&query, &time_range(), &options)
            .unwrap();
        assert!(
            sql.contains("LIMIT 10000 "),
            "explicit caller limit must be baked, got:\n{sql}"
        );
    }

    /// NAN-1410: a user `| head N` is query semantics, not pagination — it
    /// must keep its LIMIT even when the executor owns pagination. The
    /// executor then wraps the query so pages slice within the head cap
    /// (page past N is empty) instead of replacing or ignoring it.
    #[test]
    fn user_head_limit_survives_executor_owned_pagination() {
        let gen = ClickHouseSqlGenerator::new();
        let query = parse_query("error | head 10").unwrap();
        let options = QueryOptions {
            limit: None,
            ..Default::default()
        };
        let sql = gen
            .generate_with_options(&query, &time_range(), &options)
            .unwrap();
        assert!(
            sql.contains("LIMIT 10 "),
            "user head cap must be preserved, got:\n{sql}"
        );
        assert!(
            !sql.contains(&format!("LIMIT {}", ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT)),
            "no safety LIMIT should stack on top of the head cap, got:\n{sql}"
        );
    }

    /// NAN-1410: multi-stage row-preserving pipelines (the NAN-1159 shape)
    /// keep their LIMIT-free CTE tail under executor-owned pagination, so the
    /// count companion (which wraps this SQL) still returns the true total.
    #[test]
    fn multistage_raw_pipeline_with_limit_none_emits_no_limit() {
        let gen = ClickHouseSqlGenerator::new();
        let query = parse_query("error | where src_ip!=\"\"").unwrap();
        let options = QueryOptions {
            limit: None,
            ..Default::default()
        };
        let sql = gen
            .generate_with_options(&query, &time_range(), &options)
            .unwrap();
        assert!(
            sql.trim_start().starts_with("WITH "),
            "expected a CTE chain, got:\n{sql}"
        );
        assert!(
            !sql.to_uppercase().contains(" LIMIT "),
            "row-preserving CTE pipeline must carry no LIMIT, got:\n{sql}"
        );
    }

    /// NAN-1311: under OCSF a `sequence` step-capture column whose field is dotted
    /// (`[process.name=…]` → emitted alias `step1_process_name`) must be registered
    /// as a computed column, so a downstream `| table step1_process_name` references
    /// it bare. Previously it was JSON-tailed as `JSONExtractString(event,
    /// 'step1_process_name')`, but the sequence output stage drops `event` →
    /// `Code 47 UNKNOWN_IDENTIFIER: event`.
    #[test]
    fn ocsf_sequence_capture_column_not_json_tailed() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        let query = parse_query(
            "| sequence by user.name maxspan=2h [process.name=\"whoami.exe\"] \
             [process.name=\"net.exe\"] | table step1_time, step2_time, user.name, step1_process_name",
        )
        .unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        // The fatal scope is the downstream `| table` stage (stage_2): its source
        // is the sequence output, which drops `event`. Re-deriving the capture from
        // `event` there is the Code 47. (stage_0 still pre-projects the computed
        // columns from `event` as harmless, unused noise — it carries `event`.)
        let downstream = &sql[sql
            .find("stage_2 AS")
            .expect("expected a stage_2 for the trailing table command")..];
        assert!(
            !downstream.contains("JSONExtractString(event"),
            "downstream sequence stage must not JSON-tail capture columns from `event` (NAN-1311), got:\n{downstream}"
        );
        assert!(
            downstream.contains("step1_process_name FROM stage_"),
            "downstream stage should select step1_process_name as a bare computed column, got:\n{downstream}"
        );
    }

    /// NAN-1384 (G18): `source_type` equality must be case-tolerant under OCSF.
    /// `ocsf_logs` accepts direct client INSERTs, and a client-written DEFAULT
    /// column cannot be lowercase-normalized server-side — so a MixedCase
    /// `source_type` row used to be silently invisible to the
    /// `source_type = '<lowered>'` fast-path (verified live: a `MixedCase` probe
    /// row matched 0 rows). The generator must emit `lower(source_type)` in both
    /// WHERE and PREWHERE under OCSF, while UDM (whose ingest is exclusively
    /// Vector-owned and lowercases at the edge) keeps the index fast-path.
    #[test]
    fn ocsf_source_type_eq_is_case_tolerant_udm_keeps_fast_path() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query("source_type=MixedCase").unwrap();

        let ocsf = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        let ocsf_sql = ocsf.generate(&q, &time_range()).unwrap();
        assert!(
            ocsf_sql.contains("lower(source_type) = 'mixedcase'"),
            "OCSF source_type equality must lower() the stored column, got:\n{ocsf_sql}"
        );
        assert!(
            !ocsf_sql.contains("source_type = 'mixedcase'"),
            "OCSF must not emit the bare ingest-lowercased fast-path, got:\n{ocsf_sql}"
        );
        // NAN-1412: a single WHERE carries the filter — no explicit PREWHERE
        // (it suppressed `optimize_move_to_prewhere`).
        assert!(
            !ocsf_sql.contains("PREWHERE"),
            "no explicit PREWHERE may be emitted (NAN-1412), got:\n{ocsf_sql}"
        );

        // UDM safety: byte-identical fast-path emission (no lower() wrapper).
        let udm = ClickHouseSqlGenerator::new();
        let udm_sql = udm.generate(&q, &time_range()).unwrap();
        assert!(
            udm_sql.contains("source_type = 'mixedcase'"),
            "UDM must keep the ingest-lowercased equality fast-path, got:\n{udm_sql}"
        );
        assert!(
            !udm_sql.contains("lower(source_type)"),
            "UDM source_type emission must be unchanged by NAN-1384, got:\n{udm_sql}"
        );
    }

    /// NAN-1323: `| resolve_identity` must not reference UDM column names that do
    /// not exist under OCSF (`src_mac`, `user`, `user_identity_*`) — doing so 500s
    /// with an unknown-identifier error. Across src_host / src_ip / user lookups the
    /// OCSF SQL must (a) not `EXCEPT` or `main.`-reference those bare UDM names, and
    /// (b) key the registry dict on the resolved physical user column (`user.name`).
    /// Validated end-to-end on live OCSF CH.
    #[test]
    fn ocsf_resolve_identity_avoids_udm_only_columns() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        for field in ["src_host", "src_ip", "user"] {
            let q = parse_query(&format!("source_type=x | resolve_identity {field}")).unwrap();
            let sql = gen.generate(&q, &time_range()).unwrap();
            let stage = &sql[sql.find("ASOF LEFT JOIN").map(|i| sql[..i].rfind("SELECT").unwrap()).unwrap()..];
            assert!(
                !stage.contains("EXCEPT (") && !stage.contains("main.src_mac") && !stage.contains("main.\"user\""),
                "OCSF resolve_identity {field} must not EXCEPT/reference bare UDM columns, got:\n{stage}"
            );
            assert!(
                !stage.contains("main.user_identity_"),
                "OCSF resolve_identity {field} must not read physical user_identity_* (absent in ocsf_logs), got:\n{stage}"
            );
            // The IP/user lookups key the registry dict on the resolved physical
            // user column (`user.name`) — this is the `main."user"` → `main."user.name"`
            // fix. (src_host is a HOST reverse lookup, keyed on the hostname instead.)
            if field != "src_host" {
                assert!(
                    stage.contains("\"user.name\""),
                    "OCSF resolve_identity {field} should key the user dict on user.name, got:\n{stage}"
                );
            }
        }
    }

    /// NAN-1323 parity: UDM `resolve_identity` is byte-identical — it still EXCEPTs
    /// the physical UDM columns and reads them via `main.<col>`.
    #[test]
    fn udm_resolve_identity_unchanged() {
        let gen = ClickHouseSqlGenerator::new();
        let sql = gen
            .generate(&parse_query("source_type=x | resolve_identity src_host").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql.contains("main.* EXCEPT (src_mac, user)")
                && sql.contains("if(main.src_mac = '' OR main.src_mac IS NULL"),
            "UDM resolve_identity must keep the EXCEPT + main.<col> fill form, got:\n{sql}"
        );
    }

    /// NAN-1299: under OCSF, UDM-alias `field=value` search terms must resolve to
    /// the promoted OCSF column in the WHERE filter, never the raw UDM token.
    /// Emitting the bare token (`src_ip = '…'`) references a column that does not
    /// exist in `ocsf_logs` → Code 47 (500) / silent 0-rows. (NAN-1412 moved the
    /// filter from PREWHERE to the single WHERE — same resolution contract.)
    #[test]
    fn ocsf_udm_alias_filter_resolves_to_promoted_column() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));

        // src_ip → src_endpoint.ip ; dest_ip → dst_endpoint.ip. NAN-1412: the
        // equality must be the RAW column form (`"src_endpoint.ip" = '…'`, no
        // lower() wrapper) — these columns are ingest-lowercased and carry
        // raw-expression bloom indexes that `lower(col) =` orphans. The raw
        // form previously lived only in the explicit-PREWHERE duplicate
        // (resolved in extract_prewhere_conditions); with the single WHERE
        // the resolved-column lowercased check must fire here instead
        // (EXPLAIN-verified: idx_src_endpoint_ip 553→88 granules, local CH).
        for (query_str, expected_col) in [
            ("src_ip=\"89.248.167.131\"", "src_endpoint.ip"),
            ("dest_ip=\"10.0.0.1\"", "dst_endpoint.ip"),
        ] {
            let query = parse_query(query_str).unwrap();
            let sql = gen.generate(&query, &time_range()).unwrap();
            let where_clause = where_slice(&sql);
            let value = query_str.split('"').nth(1).unwrap();
            assert!(
                where_clause.contains(&format!("(\"{expected_col}\" = '{value}')")),
                "OCSF WHERE for `{query_str}` should compare the promoted column \
                 \"{expected_col}\" in raw (bloom-served) form, got WHERE:\n{where_clause}"
            );
            assert!(
                !where_clause.contains(&format!("lower(\"{expected_col}\")")),
                "OCSF WHERE for `{query_str}` must not lower()-wrap the ingest-lowercased \
                 column (orphans the raw bloom index, NAN-1412), got:\n{where_clause}"
            );
            // The raw UDM token must NOT appear as a bare WHERE identifier.
            let raw_token = query_str.split('=').next().unwrap();
            assert!(
                !where_clause.contains(&format!("lower({raw_token}) ="))
                    && !where_clause.contains(&format!("{raw_token} =")),
                "OCSF WHERE for `{query_str}` must not emit the raw UDM token, got:\n{where_clause}"
            );
            assert!(
                !sql.contains("PREWHERE"),
                "no explicit PREWHERE may be emitted (NAN-1412), got:\n{sql}"
            );
        }
    }

    /// NAN-1319: a UDM-semantic concept OCSF splits across columns by event class
    /// (`src_host` → `src_endpoint.hostname` on network events, `device.hostname`
    /// on endpoint/sysmon events) must GROUP BY / project the class-spanning value,
    /// not just the primary column — otherwise `stats count by src_host` buckets
    /// every endpoint event as empty (on local OCSF data the empty bucket held
    /// 1.07M rows; the fix attributes them to their device host).
    /// NAN-1333: the group key + projection now reference the INDEXED unified column
    /// (`src_host_unified`), which materializes that same union — identical buckets,
    /// but the words index can prune. Both SELECT and GROUP BY use the same column.
    #[test]
    fn ocsf_stats_by_class_split_host_groups_on_the_union() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        let query = parse_query("* | stats count by src_host").unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        assert!(
            sql.contains("SELECT src_host_unified AS src_host"),
            "OCSF `stats by src_host` must PROJECT the indexed unified column, got:\n{sql}"
        );
        assert!(
            sql.contains("GROUP BY src_host_unified"),
            "OCSF `stats by src_host` must GROUP BY the same unified column, got:\n{sql}"
        );
        // No inline `if(...)` union should leak into the projection/group anymore.
        assert!(
            !sql.contains("if(\"src_endpoint.hostname\""),
            "OCSF `stats by src_host` must not emit the skip-index-opaque if(...), got:\n{sql}"
        );
        // The other class-split concepts go through the same seam (consistency).
        let q2 = parse_query("* | stats count by user").unwrap();
        let sql2 = gen.generate(&q2, &time_range()).unwrap();
        assert!(
            sql2.contains("GROUP BY user_unified"),
            "OCSF `stats by user` must group on the indexed unified column, got:\n{sql2}"
        );
    }

    /// NAN-1413: under OCSF a `| join user [search …]` must resolve the join key
    /// through the schema profile — `user` is class-split, so both sides of the
    /// join carry the INDEXED unified column (`user_unified`), exactly like
    /// `stats by user` (NAN-1333). The legacy emission referenced `main."user"`,
    /// a column that does not exist on ocsf_logs → ClickHouse Code 47
    /// UNKNOWN_IDENTIFIER → 500. Validated end-to-end on live OCSF CH:
    /// pre-fix Code 47; post-fix the joined-row count matches a hand-written
    /// equivalent JOIN (50/50, and 9/9 on a single-user deterministic variant).
    #[test]
    fn ocsf_join_key_resolves_through_profile() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event]",
        )
        .unwrap();
        let sql = gen.generate(&q, &time_range()).unwrap();
        assert!(
            sql.contains("ON main.user_unified = sub.user_unified"),
            "OCSF join must compare the profile-resolved unified column on both sides, got:\n{sql}"
        );
        // The per-key empty-eviction filter and LIMIT BY must bind to the SAME
        // resolved column, or the anti-explosion cap misses the join key.
        assert!(
            sql.contains("toString(user_unified) != ''"),
            "OCSF join empty-key eviction must filter the resolved column, got:\n{sql}"
        );
        assert!(
            sql.contains("LIMIT 1 BY user_unified"),
            "OCSF join per-key cap must LIMIT BY the resolved column, got:\n{sql}"
        );
        assert!(
            !sql.contains("main.\"user\"") && !sql.contains("sub.\"user\""),
            "OCSF join must not reference the bare UDM `user` column (Code 47), got:\n{sql}"
        );
    }

    /// NAN-1413 parity pin: UDM join emission is byte-unchanged — every branch of
    /// the per-side key resolution collapses to the legacy
    /// `escape_identifier(normalize_field_name(f))` under UDM (no class split, and
    /// an explicit column's access expression is its escaped name). Verified
    /// byte-for-byte against main's generator output during the fix; pinned here.
    #[test]
    fn udm_join_sql_unchanged() {
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            sql.contains("ON main.\"user\" = sub.\"user\""),
            "UDM join must keep the legacy bare-column condition, got:\n{sql}"
        );
        assert!(
            sql.contains("toString(\"user\") != ''") && sql.contains("LIMIT 1 BY \"user\""),
            "UDM join key filter/cap must stay on the bare column, got:\n{sql}"
        );
        assert!(
            !sql.contains("user_unified"),
            "UDM must never reference OCSF unified columns, got:\n{sql}"
        );
    }

    /// NAN-1413: multi-field join resolves EACH key independently per profile —
    /// under OCSF `user` is class-split (→ `user_unified`) while `src_ip` is a
    /// dotted promoted column (→ `"src_endpoint.ip"`, which stays valid under the
    /// `main.`/`sub.` qualifiers). UDM keeps both keys bare. Executed live on
    /// both tables (OCSF 8 joined rows = hand-written tuple-IN equivalent).
    #[test]
    fn join_multi_field_key_resolution_both_profiles() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query(
            "source_type=windows_sysmon | join user, src_ip [search source_type=windows_event]",
        )
        .unwrap();
        let ocsf_sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            ocsf_sql.contains(
                "ON main.user_unified = sub.user_unified AND main.\"src_endpoint.ip\" = sub.\"src_endpoint.ip\""
            ),
            "OCSF multi-field join must resolve each key through the profile, got:\n{ocsf_sql}"
        );
        assert!(
            ocsf_sql.contains("LIMIT 1 BY user_unified, \"src_endpoint.ip\""),
            "OCSF multi-field per-key cap must use the resolved columns, got:\n{ocsf_sql}"
        );

        let udm_sql = ClickHouseSqlGenerator::new()
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            udm_sql.contains("ON main.\"user\" = sub.\"user\" AND main.src_ip = sub.src_ip"),
            "UDM multi-field join must keep the legacy bare columns, got:\n{udm_sql}"
        );
        assert!(
            udm_sql.contains("LIMIT 1 BY \"user\", src_ip"),
            "UDM multi-field per-key cap must stay on the bare columns, got:\n{udm_sql}"
        );
    }

    /// NAN-1413: the two sides of a join resolve INDEPENDENTLY. An aggregated
    /// subsearch (`[… | stats count by user]`) projects the key back under its
    /// bare normalized name (`user_unified AS user`), so the sub side references
    /// `sub."user"` while the wide outer side references `main.user_unified` —
    /// forcing one shared name on both sides would make one of them Code 47.
    /// Executed live on OCSF CH: 50 joined rows, equal to the wide-sub variant
    /// and to a hand-written IN-subquery equivalent.
    #[test]
    fn ocsf_join_aggregated_subsearch_resolves_sides_independently() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event | stats count by user]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            sql.contains("ON main.user_unified = sub.\"user\""),
            "OCSF join with aggregated sub must mix sides (wide main → unified, projected sub → bare alias), got:\n{sql}"
        );
        assert!(
            sql.contains("toString(\"user\") != ''") && sql.contains("LIMIT 1 BY \"user\""),
            "sub-side filter/cap must bind to the sub's projected key column, got:\n{sql}"
        );
    }

    /// NAN-1413: an upstream eval that value-computes exactly the normalized key
    /// name shadows the schema column (NAN-1341) — the outer side must reference
    /// the bare computed column, not re-resolve to the unified column the eval
    /// just shadowed.
    #[test]
    fn ocsf_join_eval_computed_key_stays_bare() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query(
            "source_type=windows_sysmon | eval user=\"x\" | join user [search source_type=windows_event]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            sql.contains("ON main.\"user\" = sub.user_unified"),
            "eval-computed key must shadow the profile resolution on the main side only, got:\n{sql}"
        );
    }

    /// NAN-1420: a second `| join` chained after a wide-sub join must still
    /// resolve its keys through the schema profile. The first wide join used to
    /// collapse the pipeline shape to `Unknown` (Wide+Wide), so the second
    /// join's main-side key fell back to the legacy bare emission —
    /// `main.src_ip` does not exist on ocsf_logs → Code 47. The wide guarantee
    /// now carries through as `WideJoined`, and the chained join's subsearch
    /// gets a stage-unique alias (`sub_2`): the prior join's `SELECT *` leaked
    /// literal `sub.<col>` columns into the main side, and ClickHouse binds a
    /// reused `sub."x"` qualifier to that dotted main-side column instead of
    /// the new sub table (Code 48 "JOIN ON constant", observed live).
    /// Validated end-to-end on live OCSF CH (1.19M rows): pre-fix Code 47;
    /// post-fix a deterministic chain (sub filters < 10k rows) returns 64
    /// matched rows = a hand-written double-JOIN equivalent.
    #[test]
    fn ocsf_chained_join_resolves_second_key_with_unique_alias() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event] | join src_ip [search source_type=conduit_proxy]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&q, &time_range())
            .unwrap();
        // First join: byte-unchanged from NAN-1413.
        assert!(
            sql.contains(") AS sub ON main.user_unified = sub.user_unified"),
            "first OCSF join must keep the NAN-1413 emission, got:\n{sql}"
        );
        // Second join: profile-resolved key on BOTH sides, stage-unique alias.
        assert!(
            sql.contains(") AS sub_2 ON main.\"src_endpoint.ip\" = sub_2.\"src_endpoint.ip\""),
            "chained OCSF join must resolve the second key through the profile \
             under a stage-unique sub alias, got:\n{sql}"
        );
        assert!(
            !sql.contains("main.src_ip"),
            "chained OCSF join must not fall back to the bare UDM key (Code 47), got:\n{sql}"
        );
    }

    /// NAN-1420: every chained join gets its own stage-unique alias — a third
    /// join after two wide joins must not collide with `sub.<col>` OR
    /// `sub_2.<col>` columns leaked by the earlier stages.
    #[test]
    fn ocsf_triple_chained_join_aliases_stay_unique() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event] | join src_ip [search source_type=conduit_proxy] | join dest_ip [search source_type=aws_cloudtrail]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            sql.contains(") AS sub_2 ON main.\"src_endpoint.ip\" = sub_2.\"src_endpoint.ip\"")
                && sql.contains(") AS sub_3 ON main.\"dst_endpoint.ip\" = sub_3.\"dst_endpoint.ip\""),
            "each chained join must use a distinct per-stage sub alias, got:\n{sql}"
        );
    }

    /// NAN-1423: UDM chained joins get the same stage-unique sub alias as OCSF
    /// (`sub_2`, `sub_3`, …). The predecessor pin (`udm_chained_join_sql_unchanged`,
    /// NAN-1420) deliberately froze the legacy reused-`sub` emission for byte
    /// parity — but that emission had ALWAYS died on ClickHouse with Code 48
    /// ("JOIN ON constant"): the first join's `SELECT *` leaks literal
    /// `sub.<col>` columns into the main side and the second join's reused
    /// `sub."x"` qualifier binds to that dotted column, collapsing the ON to
    /// one table. There was no working behavior to preserve, so the gate is
    /// gone. Key RESOLUTION stays legacy-bare under UDM (no unified columns).
    /// Validated end-to-end on live UDM CH (`logs`, 2.06M rows): the pre-fix
    /// SQL reproduces Code 48; post-fix a deterministic chain (bounded subs,
    /// LIMIT never truncating) returns matched rows equal to a hand-written
    /// double-JOIN equivalent.
    #[test]
    fn udm_chained_join_uses_stage_unique_alias() {
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event] | join src_ip [search source_type=conduit_proxy]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&q, &time_range())
            .unwrap();
        // First join: byte-unchanged legacy emission (plain `sub`, bare key).
        assert!(
            sql.contains(") AS sub ON main.\"user\" = sub.\"user\""),
            "first UDM join must keep the legacy `sub` alias and bare key, got:\n{sql}"
        );
        // Second join: stage-unique alias, keys still legacy-bare.
        assert!(
            sql.contains(") AS sub_2 ON main.src_ip = sub_2.src_ip"),
            "chained UDM join must use a stage-unique sub alias (Code 48 \
             leak-capture fix, NAN-1423), got:\n{sql}"
        );
        assert!(
            !sql.contains("user_unified"),
            "UDM must never resolve keys to OCSF unified columns, got:\n{sql}"
        );
    }

    /// NAN-1423: a SINGLE (non-chained) UDM join keeps the plain `sub` alias
    /// byte-for-byte — the stage-unique alias only kicks in when the main side
    /// is already `WideJoined` (i.e. second+ joins), exactly as under OCSF.
    #[test]
    fn udm_single_join_keeps_plain_sub_alias() {
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            sql.contains(") AS sub ON main.\"user\" = sub.\"user\""),
            "single UDM join must keep the legacy `sub` alias and bare key, got:\n{sql}"
        );
        assert!(
            !sql.contains("sub_2"),
            "single UDM join must not get a stage-unique alias, got:\n{sql}"
        );
    }

    /// NAN-1420 (quirk pinned deliberately): `eval username=… | join username`
    /// resolves the key to the BASE schema column (`user_unified` under OCSF),
    /// not the eval'd `username` column — the join key normalizes
    /// `username` → `user` before the NAN-1341 shadow check, and the eval
    /// created a column literally named `username`, which never shadows the
    /// normalized name. Parity-correct with UDM legacy semantics (UDM joins on
    /// the `user` column there too); pinned so a future change is a decision,
    /// not an accident.
    #[test]
    fn ocsf_join_eval_aliased_key_resolves_to_base_column() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query(
            "source_type=windows_sysmon | eval username=\"x\" | join username [search source_type=windows_event]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            sql.contains("ON main.user_unified = sub.user_unified"),
            "`join username` must resolve to the base unified column (legacy-parity \
             quirk), got:\n{sql}"
        );
        assert!(
            !sql.contains("main.\"username\""),
            "the eval'd `username` column must not capture the normalized join key, got:\n{sql}"
        );
    }

    /// NAN-1420 append safety: the Wide+Wide join rule used to collapse to
    /// `Unknown`, which made a downstream `append` refuse with the actionable
    /// shape error. The new `WideJoined` shape must keep that refusal —
    /// the join stage's `SELECT *` output carries leaked `sub.<col>` duplicates
    /// and is NOT positionally alignable with a passthrough UNION arm.
    #[test]
    fn append_after_wide_join_still_refuses() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event] | append [search source_type=conduit_proxy]",
        )
        .unwrap();
        for gen in [
            ClickHouseSqlGenerator::new(),
            ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new())),
        ] {
            let err = gen.generate(&q, &time_range()).unwrap_err();
            assert!(
                matches!(&err, SqlGenError::UnsupportedOperation(m) if m.contains("append")),
                "append after a wide-sub join must keep refusing with the shape \
                 error (pre-NAN-1420 behavior), got: {err:?}"
            );
        }
    }

    /// NAN-1319 parity: under UDM a class-split concept does not exist — `src_host`
    /// IS one column, so `class_split_value_sql` returns `None` and GROUP BY / the
    /// projection stay the bare column, byte-for-byte unchanged.
    #[test]
    fn udm_stats_by_src_host_unchanged() {
        let query = parse_query("* | stats count by src_host").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("SELECT src_host AS src_host") && sql.contains("GROUP BY src_host"),
            "UDM `stats by src_host` must stay the bare column (no `if(...)`), got:\n{sql}"
        );
        assert!(
            !sql.contains("device.hostname"),
            "UDM must never reference OCSF columns, got:\n{sql}"
        );
    }

    /// NAN-1321: an OCSF search FILTER on a class-split concept (`src_host="x"`)
    /// must match the union (so it finds the host on `device.hostname` endpoint
    /// events) — never a single primary column that would silently drop every
    /// device-host row. Validated end-to-end on live OCSF CH: 39 → 464.
    /// NAN-1333: the WHERE predicate now references the INDEXED unified column
    /// (`src_host_unified`) instead of the inline value-pick `if(...)`, so the words
    /// index prunes granules (prototype: 640/640 → 294/640, identical match counts).
    #[test]
    fn ocsf_filter_on_class_split_host_uses_unified_column() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        let col = "src_host_unified";

        // Equality: WHERE matches the unified column; PREWHERE must not carry the host.
        // NAN-1333: no `toString` wrapper — `lower(<col>_unified)` matches the words
        // text index by expression and prunes (the toString form orphans the index).
        let sql = gen
            .generate(&parse_query("src_host=\"ws-01\"").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql.contains(&format!("lower({col}) = 'ws-01'"))
                && !sql.contains(&format!("lower(toString({col}))")),
            "OCSF src_host= must filter on the unified column WITHOUT toString (index-matchable), got:\n{sql}"
        );
        // The skip-index-opaque inline if(...) must NOT appear in WHERE anymore.
        assert!(
            !sql.contains("if(\"src_endpoint.hostname\""),
            "OCSF src_host= must not emit the inline if(...), got:\n{sql}"
        );
        // NAN-1412: no explicit PREWHERE anywhere — placement is ClickHouse's
        // call, so the old "must not promote the primary column" hazard is gone
        // structurally.
        assert!(
            !sql.contains("PREWHERE"),
            "no explicit PREWHERE may be emitted (NAN-1412), got:\n{sql}"
        );

        // Negation stays correct with the single column (no De Morgan).
        let sql_ne = gen
            .generate(&parse_query("src_host!=\"ws-01\"").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql_ne.contains(&format!("lower({col}) != 'ws-01'")),
            "OCSF src_host!= must negate the unified column, got:\n{sql_ne}"
        );

        // IN-list (the UDM alias is not a promoted column, so it must be routed
        // explicitly rather than falling to the empty metadata-JSON branch).
        let sql_in = gen
            .generate(&parse_query("src_host IN (\"a\",\"b\")").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql_in.contains(&format!("lower({col}) IN ('a', 'b')")),
            "OCSF src_host IN must match the unified column, got:\n{sql_in}"
        );
    }

    /// NAN-1321 parity: UDM has no class-split, so a `src_host="x"` filter stays
    /// the single column in WHERE with the hostname FQDN expansion. The lower()
    /// form is deliberate — the `lower(src_host)` text index serves both OR arms
    /// (equality + startsWith), while the raw form's startsWith arm is not
    /// bloom-servable (2026-06-12 query audit, verified on local CH).
    #[test]
    fn udm_filter_on_src_host_unchanged() {
        let sql = ClickHouseSqlGenerator::new()
            .generate(&parse_query("src_host=\"ws-01\"").unwrap(), &time_range())
            .unwrap();
        let where_clause = where_slice(&sql);
        assert!(
            where_clause.contains("lower(src_host) = 'ws-01'")
                && where_clause.contains("startsWith(lower(src_host), 'ws-01.')"),
            "UDM src_host= must keep the lower()-column equality + FQDN expansion in WHERE, got:\n{where_clause}"
        );
        assert!(
            !sql.contains("device.hostname") && !sql.contains("if("),
            "UDM must never emit OCSF columns or the class-split `if(...)`, got:\n{sql}"
        );
    }

    /// NAN-1412: every generated query carries a SINGLE WHERE with all conjuncts
    /// (time bounds first) and never an explicit PREWHERE. An explicit PREWHERE
    /// disables ClickHouse's `optimize_move_to_prewhere`, so every non-promoted
    /// filter (ranges, CONTAINS/regex, JSON-tail, unified columns) was evaluated
    /// only after reading the full projection — measured up to 349x read_bytes
    /// on zero-match entity hunts. A plain WHERE was byte-identical in I/O to a
    /// hand-tuned PREWHERE in every probe, including the previously-promoted
    /// paths (`source_type=` did not regress).
    #[test]
    fn single_where_no_prewhere_both_profiles() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let udm = ClickHouseSqlGenerator::new();
        let ocsf = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));

        // Cover every emission shape: plain search, search|head (fast path),
        // multi-stage CTE, stats aggregation, subsearch join, and subsearch IN.
        let queries = [
            "error",
            "source_type=windows_sysmon user=\"admin\"",
            "error | head 50",
            "dest_port>=1024 dest_port<=2048 | stats count by src_ip | where count > 10",
            "* | stats count by source_type",
            "user=\"a\" | join user [search source_type=x | head 5]",
            "src_ip IN [search dest_port=443 | return src_ip]",
        ];
        for (gen, profile) in [(&udm, "UDM"), (&ocsf, "OCSF")] {
            for q in queries {
                let sql = gen
                    .generate(&parse_query(q).unwrap(), &time_range())
                    .unwrap();
                assert!(
                    !sql.contains("PREWHERE"),
                    "{profile} `{q}` must not emit an explicit PREWHERE (NAN-1412), got:\n{sql}"
                );
                // Time bounds stay in the WHERE conjunct chain, same DateTime64
                // literal format as before (only the keyword changed).
                assert!(
                    sql.contains("WHERE timestamp BETWEEN '2024-01-01 00:00:00.000000' AND '2024-01-02 00:00:00.000000'"),
                    "{profile} `{q}` must carry the time bounds as the first WHERE conjunct, got:\n{sql}"
                );
                // Exactly one base-scan filter keyword per table scan: every WHERE
                // is followed by the timestamp guard (no second filter clause on
                // the raw table), except CTE-stage WHEREs on derived stages.
                assert!(
                    !sql.contains("WHERE (1) WHERE") && !sql.contains(") WHERE ("),
                    "{profile} `{q}` must not emit split filter clauses, got:\n{sql}"
                );
            }
        }
    }

    /// NAN-1412: the read-in-order toggle survives the PREWHERE removal — a
    /// selective indexed equality (src_ip/user/…) still disables
    /// `optimize_read_in_order`; a broad source_type filter keeps it on.
    #[test]
    fn read_in_order_toggle_survives_single_where() {
        let gen = ClickHouseSqlGenerator::new();
        let selective = gen
            .generate(&parse_query("src_ip=\"10.0.0.1\"").unwrap(), &time_range())
            .unwrap();
        assert!(
            selective.contains("optimize_read_in_order=0"),
            "selective indexed equality must disable read-in-order, got:\n{selective}"
        );
        let broad = gen
            .generate(&parse_query("source_type=windows_sysmon").unwrap(), &time_range())
            .unwrap();
        assert!(
            broad.contains("optimize_read_in_order=1"),
            "broad source_type filter must keep read-in-order, got:\n{broad}"
        );
    }

    /// NAN-1299 parity: UDM filter output keeps the identity-column raw-equality
    /// fast path (`src_ip = '…'`, no lower() wrapper) in the single WHERE.
    #[test]
    fn udm_where_keeps_raw_equality_for_alias_fields() {
        let query = parse_query("src_ip=\"89.248.167.131\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        let where_clause = where_slice(&sql);
        assert!(
            where_clause.contains("src_ip = '89.248.167.131'"),
            "UDM WHERE must keep the direct `src_ip = '…'` fast path, got:\n{where_clause}"
        );
    }

    /// NAN-1381 (root cause of NAN-1247): non-Eq string operators on a UDM alias
    /// that resolves to a plain non-null String column must reference `lower(col)`,
    /// never `toString(col)` — ClickHouse matches a text/bloom skip index by
    /// EXPRESSION, so the toString wrapper orphans every `lower(col)` index and
    /// full-scans (601/601 granules vs 55/601 via idx_user_unified_words on a
    /// `user CONTAINS "intern"` probe, local CH; counts identical — toString is a
    /// semantic no-op on a MATERIALIZED-'' String column).
    #[test]
    fn ocsf_alias_string_pattern_ops_use_lower_not_tostring() {
        use crate::schema::OcsfProfile;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));

        // Class-split alias → unified column, every string-pattern arm.
        for (q, want) in [
            ("user CONTAINS \"intern\"", "lower(user_unified) iLike '%intern%'"),
            (
                "NOT user CONTAINS \"intern\"",
                "lower(user_unified) iLike '%intern%'",
            ),
            ("user=/intern/", "lower(user_unified) iLike '%intern%'"),
            ("user=\"inte*\"", "lower(user_unified) iLike 'inte%'"),
            ("user!=\"inte*\"", "lower(user_unified) NOT iLike 'inte%'"),
            ("user STARTSWITH \"inte\"", "lower(user_unified) iLike 'inte%'"),
            ("user ENDSWITH \"ern\"", "lower(user_unified) iLike '%ern'"),
            ("user LIKE \"%intern%\"", "lower(user_unified) iLike '%intern%'"),
        ] {
            let sql = gen.generate(&parse_query(q).unwrap(), &time_range()).unwrap();
            assert!(
                sql.contains(want) && !sql.contains("toString(user_unified)"),
                "OCSF `{q}` must use the index-matchable lower(user_unified) form, got:\n{sql}"
            );
        }

        // Promoted-column alias (Eq exception broadened beyond class-split):
        // NAN-1412 — the resolved column is in `OCSF_LOWERCASED_AT_INGEST`, so
        // Eq drops the lower() wrapper entirely and the RAW-column bloom index
        // can prune (lower(col)= orphans it; pre-NAN-1412 the raw form lived in
        // the explicit-PREWHERE duplicate, now this arm is the only emission).
        // The literal still lowercases — data is ingest-lowercased.
        let sql = gen
            .generate(&parse_query("file_hash=\"ab12\"").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql.contains("(\"file.hashes.sha256\" = 'ab12')")
                && !sql.contains("toString(\"file.hashes.sha256\")"),
            "OCSF file_hash= must compare the raw ingest-lowercased column (NAN-1412), got:\n{sql}"
        );
        let sql = gen
            .generate(
                &parse_query("file_hash CONTAINS \"ab12\"").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            sql.contains("lower(\"file.hashes.sha256\") iLike '%ab12%'"),
            "OCSF file_hash CONTAINS must use lower(col), got:\n{sql}"
        );

        // A UDM alias resolving to a NUMERIC column must keep the toString guard —
        // the type check consults the RESOLVED column (`is_numeric_field("src_port")`
        // is false under OCSF even though `src_endpoint.port` is UInt16; lower()
        // on a numeric column is a CH type error).
        let sql = gen
            .generate(
                &parse_query("src_port CONTAINS \"44\"").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            sql.contains("toString(\"src_endpoint.port\") iLike '%44%'"),
            "OCSF src_port CONTAINS must keep toString on the numeric target, got:\n{sql}"
        );

        // An unpromoted JSON-tail field keeps the NAN-1161 toString null-guard:
        // a missing key must read as '' so negation keeps absent-key rows.
        // NAN-1426: the tail access is native subcolumn (the multiIf parity
        // form), no longer `JSONExtractString(…)` which re-serialized the whole
        // JSON per row; the multiIf itself yields '' for missing keys and the
        // outer toString wrapper is preserved. NAN-1443: the tail column is the
        // stored `unmapped` spill (was the now-EPHEMERAL `event`).
        let sql = gen
            .generate(
                &parse_query("custom_tail_key CONTAINS \"x\"").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            sql.contains(
                "toString(multiIf(isNotNull(unmapped.\"custom_tail_key\"), \
                 toString(unmapped.\"custom_tail_key\"), \
                 toJSONString(unmapped.^\"custom_tail_key\") != '{}', \
                 toJSONString(unmapped.^\"custom_tail_key\"), '')) iLike '%x%'"
            ),
            "OCSF JSON-tail CONTAINS must keep the toString null-guard over the subcolumn access, got:\n{sql}"
        );
    }

    /// NAN-1426: OCSF JSON-tail filters access the `event` column via native
    /// subcolumns, never `JSONExtract*(event, …)` (which re-serializes the whole
    /// event per row — 8.06 GiB vs 64 MiB read on the local 3M-row headline
    /// probe). Pins the two filter-arm parity forms end-to-end:
    /// - string negation keeps the NAN-1161 guarantee: the multiIf yields ''
    ///   (never NULL) for missing keys, so `!=` keeps absent-key rows;
    /// - numeric comparisons carry the MANDATORY coalesce(…, 0.) — without it
    ///   `=0` flips 2.7M→0 and `!=N` drops every absent-key row (measured).
    #[test]
    fn nan1426_ocsf_tail_filters_use_subcolumn_access() {
        use crate::schema::OcsfProfile;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));

        // Negated string compare on an unpromoted tail path.
        let sql = gen
            .generate(
                &parse_query("unmapped.signature_status != \"valid\"").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            sql.contains(
                "lower(toString(multiIf(isNotNull(unmapped.\"signature_status\"), \
                 toString(unmapped.\"signature_status\"), \
                 toJSONString(unmapped.^\"signature_status\") != '{}', \
                 toJSONString(unmapped.^\"signature_status\"), ''))) != 'valid'"
            ) && !sql.contains("JSONExtractString(unmapped"),
            "OCSF negated tail string compare must use the ''-defaulting subcolumn multiIf, got:\n{sql}"
        );

        // Numeric compare on an unpromoted tail path.
        let sql = gen
            .generate(
                &parse_query("unmapped.error_code=23").unwrap(),
                &time_range(),
            )
            .unwrap();
        // NAN-1443: the spill is the stored `unmapped` column, addressed with a
        // RELATIVE path (was `event."unmapped"."error_code"` pre-chop).
        assert!(
            sql.contains(
                "coalesce(accurateCastOrNull(unmapped.\"error_code\", 'Float64'), 0.) = 23"
            ) && !sql.contains("JSONExtractFloat("),
            "OCSF numeric tail compare must use the coalesced subcolumn cast, got:\n{sql}"
        );

        // Bool tail compare deliberately keeps JSONExtractBool (cast form is
        // not parity-safe for string-typed "true" values).
        let sql = gen
            .generate(
                &parse_query("unmapped.signed=true").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            sql.contains("JSONExtractBool(unmapped, 'signed')"),
            "OCSF bool tail compare must keep JSONExtractBool, got:\n{sql}"
        );
    }

    /// NAN-1426 unit pins for `json_tail_access_sql` — one per parity
    /// carve-out. The empirical battery (identical counts/checksums vs the old
    /// JSONExtract emission on 3M-row local ocsf_logs, incl. the missing-key
    /// `=0`/`!=N` flips, object-valued paths, and arrays) lives in the PR.
    #[test]
    fn nan1426_json_tail_access_sql_carveouts() {
        // String → the multiIf parity form: scalar/array leaves via
        // toString(sub) (JSONExtractString-over-a-JSON-column formats arrays
        // identically — it operates on the column's own CH serialization);
        // object-valued paths via toJSONString(event.^…) (byte-equal to the
        // old raw-JSON return); missing keys/JSON nulls → '' never NULL
        // (NAN-1161: negation keeps absent-key rows).
        assert_eq!(
            json_tail_access_sql(
                "event",
                &["unmapped".to_string(), "signature_status".to_string()],
                "String"
            ),
            "multiIf(isNotNull(event.\"unmapped\".\"signature_status\"), \
             toString(event.\"unmapped\".\"signature_status\"), \
             toJSONString(event.^\"unmapped\".\"signature_status\") != '{}', \
             toJSONString(event.^\"unmapped\".\"signature_status\"), '')"
        );

        // Float → coalesce(accurateCastOrNull(…, 'Float64'), 0.). The coalesce
        // is MANDATORY (missing key: JSONExtractFloat=0, bare cast=NULL).
        assert_eq!(
            json_tail_access_sql(
                "event",
                &["unmapped".to_string(), "EventID".to_string()],
                "Float"
            ),
            "coalesce(accurateCastOrNull(event.\"unmapped\".\"EventID\", 'Float64'), 0.)"
        );

        // Bool stays on JSONExtractBool: accurateCastOrNull('true','Bool') is
        // true where JSONExtractBool returns false for string-typed values.
        assert_eq!(
            json_tail_access_sql("event", &["unmapped".to_string(), "signed".to_string()], "Bool"),
            "JSONExtractBool(event, 'unmapped', 'signed')"
        );

        // Raw/array suffixes keep the legacy JSONExtract forms untouched
        // (arrayFirst/hashes/enrichment patterns depend on raw-JSON returns).
        assert_eq!(
            json_tail_access_sql("event", &["file".to_string(), "hashes".to_string()], "ArrayRaw"),
            "JSONExtractArrayRaw(event, 'file', 'hashes')"
        );

        // Path segments embed as double-quoted identifiers, backslash-escaped
        // FIRST then ""-doubled — CH honors both escape forms inside quoted
        // identifiers (verified on 26.4), so a raw `\` would silently address
        // the wrong key and an embedded quote could break out.
        assert_eq!(
            json_tail_access_sql("event", &["se\"lect".to_string()], "Float"),
            "coalesce(accurateCastOrNull(event.\"se\"\"lect\", 'Float64'), 0.)"
        );
        assert_eq!(
            json_tail_access_sql("event", &["a\\b".to_string()], "Float"),
            "coalesce(accurateCastOrNull(event.\"a\\\\b\", 'Float64'), 0.)"
        );
    }

    /// NAN-1426: `generate_json_extract` (the seam OCSF dotted tails route
    /// through in eval/where/sort contexts) emits the SAME subcolumn forms —
    /// the two chokepoints stay in lockstep — while UDM stays byte-unchanged
    /// on both its spill arm and the metadata column (a plain String column,
    /// where subcolumn syntax does not apply).
    #[test]
    fn nan1426_chokepoints_lockstep_and_udm_pinned() {
        use crate::schema::OcsfProfile;
        let ocsf = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        assert_eq!(
            ocsf.generate_json_extract("unmapped.error_code", "Float"),
            // NAN-1443: spill addressed relative to the stored `unmapped` column.
            "coalesce(accurateCastOrNull(unmapped.\"error_code\", 'Float64'), 0.)"
        );
        assert_eq!(
            ocsf.generate_json_extract("connection_info.direction", "String"),
            ocsf.field_access_expr("connection_info.direction", "String"),
        );

        // UDM byte-unchanged: the spill arm already does native ext.{field}
        // subcolumn access, and resolve never yields JsonPath.
        let udm = ClickHouseSqlGenerator::new();
        assert_eq!(udm.field_access_expr("custom_key", "String"), "ext.custom_key");
        assert_eq!(udm.field_access_expr("custom_key", "Float"), "ext.custom_key");
        assert_eq!(
            udm.generate_json_extract("metadata_endpoint", "String"),
            "JSONExtractString(metadata, 'endpoint')"
        );
    }

    /// NAN-1381 (UDM side of the shared gap): wildcard / STARTSWITH / ENDSWITH /
    /// LIKE previously emitted the bare column (`user iLike 'bob%'`), which cannot
    /// use the `lower(col)` text indexes. They now emit the lowered form the
    /// Contains/Regex arms already used — iLike is case-insensitive either way, so
    /// matches are unchanged (count-identity verified on local CH, 543/543 →
    /// 334/543 granules on a `user` contains-shaped probe).
    #[test]
    fn udm_wildcard_prefix_suffix_like_use_lowered_column() {
        let gen = ClickHouseSqlGenerator::new();
        for (q, want) in [
            ("user=\"bob*\"", "lower(\"user\") iLike 'bob%'"),
            ("user!=\"bob*\"", "lower(\"user\") NOT iLike 'bob%'"),
            ("user STARTSWITH \"bob\"", "lower(\"user\") iLike 'bob%'"),
            ("user ENDSWITH \"son\"", "lower(\"user\") iLike '%son'"),
            ("user LIKE \"%wilson%\"", "lower(\"user\") iLike '%wilson%'"),
            // Contains was already lowered (NAN-1026/NAN-1247) — pinned here so the
            // whole pattern family stays on one form.
            ("user CONTAINS \"wilson\"", "lower(\"user\") iLike '%wilson%'"),
        ] {
            let sql = gen.generate(&parse_query(q).unwrap(), &time_range()).unwrap();
            assert!(
                sql.contains(want),
                "UDM `{q}` must use the lowered index-matchable form, got:\n{sql}"
            );
        }

        // UDM ext-spill fields keep the NAN-1161 toString null-guard on the
        // pattern arms (missing key must read '' so negation keeps absent rows).
        let sql = gen
            .generate(
                &parse_query("integrity_level CONTAINS \"high\"").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            sql.contains("toString(ext.integrity_level) iLike '%high%'"),
            "UDM ext CONTAINS must keep the toString null-guard, got:\n{sql}"
        );

        // UDM equality stays the bare indexed comparison; the bare keyword now
        // drives idx_message_words via hasAllTokens (NAN-1515).
        let sql = gen
            .generate(&parse_query("user=\"bob\" error").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql.contains("\"user\" = 'bob'")
                && sql.contains("hasAllTokens(lower(message), 'error')"),
            "UDM Eq stays bare; bare keyword uses hasAllTokens, got:\n{sql}"
        );
    }

    /// Extract the PREWHERE clause text (up to the following WHERE/GROUP/ORDER/LIMIT).
    /// Extract the WHERE clause text (up to the following GROUP/ORDER/LIMIT or
    /// CTE close) so assertions don't accidentally match SELECT-list aliases.
    fn where_slice(sql: &str) -> String {
        let start = match sql.find("WHERE") {
            Some(i) => i,
            None => return String::new(),
        };
        let rest = &sql[start..];
        let end = ["GROUP BY", "ORDER BY", "LIMIT", "\n)"]
            .iter()
            .filter_map(|m| rest.find(m))
            .min()
            .unwrap_or(rest.len());
        rest[..end].to_string()
    }

    /// NAN-671: the unfiltered SELECT * path must drop the physical `action`
    /// column from result projections and surface it as `event_type` instead.
    /// ClickHouse returns physical column names (not aliases) for `SELECT *`,
    /// so the canonical UDM name only reaches result headers if we explicitly
    /// EXCEPT the column and re-project under the alias name.
    #[test]
    fn select_star_excepts_action_and_renames_to_event_type() {
        let query = parse_query("error").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("* EXCEPT (action)"),
            "expected `* EXCEPT (action)` to drop the legacy column from SELECT *, got:\n{}",
            sql
        );
        assert!(
            sql.contains("action AS event_type"),
            "expected `action AS event_type` so result header carries the canonical UDM name, got:\n{}",
            sql
        );
    }

    /// NAN-876: multi-stage CTE chains must keep `action` accessible to
    /// downstream stages. The shadow_hunting LLM agent generates queries
    /// like `... | stats count by action` and `... | where action="foo"`,
    /// and the previous SELECT clause stripped `action` in stage_0 of the
    /// wildcard path, causing ClickHouse to fail with `Unknown expression
    /// identifier \`action\` in scope stage_1`. Pin: when stage_0 falls
    /// back to `SELECT *` (no field-pruning), it must NOT also apply the
    /// NAN-671 EXCEPT — the alias still gets projected, but `action`
    /// stays inside `*` so downstream stages can reference it.
    ///
    /// Uses `sort -timestamp` because it doesn't drive field_analysis to
    /// enumerate explicit columns; it preserves the wildcard path that
    /// the original NAN-876 reproducer (saturn shadow_hunting at
    /// 16:40:51 UTC) hit.
    #[test]
    fn cte_stage_0_preserves_action_for_downstream_reference() {
        let query = parse_query("error | sort -timestamp").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        let stage_0_marker = "stage_0 AS (";
        let stage_0_start = sql
            .find(stage_0_marker)
            .expect("expected a stage_0 CTE for a piped query");
        let stage_0_end = sql[stage_0_start..]
            .find("),")
            .or_else(|| sql[stage_0_start..].find(')'))
            .map(|i| stage_0_start + i)
            .unwrap_or(sql.len());
        let stage_0_body = &sql[stage_0_start..stage_0_end];

        assert!(
            !stage_0_body.contains("* EXCEPT (action)"),
            "stage_0 must preserve `action` for downstream stages (NAN-876), got:\n{}",
            stage_0_body
        );
        assert!(
            stage_0_body.contains("action AS event_type"),
            "stage_0 should still expose the `event_type` alias alongside `action`, got:\n{}",
            stage_0_body
        );
    }

    /// NAN-876: non-aggregating multi-stage pipelines should still hide
    /// `action` from the final user-facing result, matching NAN-671's
    /// intent. The outer SELECT applies `* EXCEPT (action)` when the
    /// pipeline didn't transform columns away.
    #[test]
    fn cte_outer_select_strips_redundant_action_when_no_aggregation() {
        let query = parse_query("error | sort -timestamp").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        // Locate the outer SELECT (the one after the last CTE closes).
        // It should EXCEPT(action) because `sort` preserves columns.
        let last_select = sql
            .rfind("SELECT")
            .map(|i| &sql[i..])
            .expect("outer SELECT present");
        assert!(
            last_select.contains("* EXCEPT (action)"),
            "outer SELECT must drop the redundant `action` column when the last stage didn't aggregate, got:\n{}",
            last_select
        );
    }

    /// NAN-876: aggregating pipelines (stats / table / timechart) produce
    /// their own column set in the last CTE — `action` is gone by then,
    /// and the outer SELECT must NOT attempt EXCEPT(action) (CH would
    /// reject the reference). Plain `SELECT *` from the last CTE.
    #[test]
    fn cte_outer_select_plain_when_aggregation_ran() {
        let query = parse_query("error | stats count by user").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        let last_select = sql
            .rfind("SELECT")
            .map(|i| &sql[i..])
            .expect("outer SELECT present");
        assert!(
            !last_select.contains("EXCEPT (action)"),
            "outer SELECT after an aggregation must not reference `action`, got:\n{}",
            last_select
        );
    }

    // ---- NAN-1026 Phase 2 regression coverage ---------------------------
    // hasToken*-based codegen silently dropped fragment matches when the needle
    // wasn't a whole CH token in the data. Phase 2 lowers all alphanumeric
    // needles to substring iLike instead. These tests pin the bug shapes that
    // motivated the fix so we don't regress to whole-token semantics.

    /// `src_host = /dc/` must lower to substring iLike, not hasTokenCaseInsensitive.
    /// Pre-fix: hosts like `srv-dc01.corp.local` tokenize to `[srv, dc01, corp, local]`
    /// and silently fail the `dc` whole-token check, so all DCs slip through
    /// "find DCs" / "exclude DCs" filters.
    #[test]
    fn regex_fragment_on_udm_field_uses_ilike_not_hastoken() {
        let query = parse_query("src_host = /dc/").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("iLike '%dc%'"),
            "expected substring iLike, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("hasToken"),
            "must NOT lower to any hasToken variant (silently drops `dc` inside `dc01`), got:\n{}",
            sql
        );
    }

    /// NAN-1157: a literal backslash in a CONTAINS/keyword must reach `\\` in the
    /// iLike pattern *value* — i.e. `\\\\` in the SQL text — or ClickHouse iLike
    /// consumes the backslash as its escape char and the Windows-path filter
    /// silently matches nothing (every `\Windows\System32\`-style rule did).
    /// Verified against real data: the 4-backslash form matches 552k sysmon
    /// rows; the 2-backslash form matches 0.
    #[test]
    fn backslash_contains_quad_escapes_for_ilike() {
        let query = parse_query(r#"process_path CONTAINS "C:\Windows\System32\""#).unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains(r"c:\\\\windows\\\\system32\\\\"),
            "literal backslashes must be 4x-escaped in the SQL text for iLike, got:\n{}",
            sql
        );

        // The `| where … CONTAINS` command is a SEPARATE codegen path
        // (generate_where_condition) that inlined the escaping — it must get the
        // same 4-backslash form, or the rules (which all use `| where`) match 0.
        let piped = parse_query(
            r#"source_type="windows_sysmon" | where process_path CONTAINS "C:\Windows\System32\""#,
        )
        .unwrap();
        let psql = ClickHouseSqlGenerator::new()
            .generate(&piped, &time_range())
            .unwrap();
        assert!(
            psql.contains(r"c:\\\\windows\\\\system32\\\\"),
            "| where CONTAINS must also 4x-escape backslashes, got:\n{}",
            psql
        );
    }

    /// `src_host != /ws/` should NOT iLike — same fragment concern, just negated.
    /// Pre-fix: workstations `ws-mkt-088` were correctly excluded but WSUS hosts
    /// `srv-wsus01` (tokens `[srv, wsus01, corp, local]`) leaked through because
    /// `ws` isn't a whole token there.
    #[test]
    fn negated_regex_fragment_on_udm_field_uses_not_ilike() {
        let query = parse_query("src_host != /ws/").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("NOT iLike '%ws%'"),
            "expected NOT iLike on substring, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("hasToken"),
            "must NOT lower to NOT hasTokenCaseInsensitive (leaked WSUS), got:\n{}",
            sql
        );
    }

    /// `message contains "anom"` must match "anomalous" rows.
    /// The `rules/credential_access/golden_ticket.yml` rule literally has this
    /// pattern and was silently returning 0 hits under hasToken.
    #[test]
    fn contains_fragment_on_message_uses_ilike_not_hastoken() {
        let query = parse_query("message contains \"anom\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("lower(message) iLike '%anom%'"),
            "expected substring iLike on message, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("hasToken"),
            "must NOT lower to hasToken (would never match `anomalous` rows), got:\n{}",
            sql
        );
    }

    /// NAN-1515: a single-token bare keyword is now a TOKEN match
    /// (`hasAllTokens`, posting-list lookup), not a substring iLike. This is the
    /// one deliberate semantic change — bare `anom` no longer matches
    /// `anomalous`; substring intent goes through `*kw*` / `CONTAINS` (still
    /// iLike). The substring form was 77–250× slower at Saturn scale.
    #[test]
    fn bare_keyword_single_token_uses_hasalltokens() {
        let query = parse_query("anom").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("hasAllTokens(lower(message), 'anom')"),
            "single-token bare keyword should use hasAllTokens, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("lower(message) iLike "),
            "single-token bare keyword must NOT emit a substring iLike, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("position("),
            "single clean token must NOT grow a position guard, got:\n{}",
            sql
        );
    }

    /// NAN-1515: whole-token analyst patterns (`mimikatz`, `kerberos`) lower to
    /// a bare `hasAllTokens` — a posting-list lookup on idx_message_words, no
    /// position guard (single clean token = token match).
    #[test]
    fn bare_whole_token_keyword_uses_hasalltokens() {
        let query = parse_query("mimikatz").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("hasAllTokens(lower(message), 'mimikatz')"),
            "whole-token keyword should lower to a bare hasAllTokens, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("position(") && !sql.contains("iLike"),
            "single clean token must be bare hasAllTokens (no position, no iLike), got:\n{}",
            sql
        );
    }

    /// NAN-1515: multi-token / structured needles (`file.exe`, snake_case) lower
    /// to a bare `hasAllTokens` — token-AND via posting-list lookup, same shape as
    /// single-token. No position guard, no iLike. Replaces the NAN-1416 guard.
    #[test]
    fn bare_special_char_keyword_uses_hasalltokens() {
        let query = parse_query("svchost.exe").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("hasAllTokens(lower(message), 'svchost.exe')"),
            "multi-token keyword should emit bare hasAllTokens, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("iLike") && !sql.contains("position("),
            "multi-token keyword must NOT emit iLike or position, got:\n{}",
            sql
        );
    }

    /// NAN-1515: quoted phrase → hasAllTokens(both tokens). Token-AND, no
    /// adjacency guard — `"failed login"` matches rows with tokens `failed` AND
    /// `login` (Splunk parity).
    #[test]
    fn quoted_phrase_keyword_uses_hasalltokens() {
        let query = parse_query("\"failed login\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("hasAllTokens(lower(message), 'failed login')"),
            "phrase keyword should emit bare hasAllTokens, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("position(") && !sql.contains("iLike"),
            "phrase keyword must NOT emit position or iLike, got:\n{}",
            sql
        );
    }

    /// NAN-1515: every structured needle (IPs, dotted names, snake_case) takes
    /// the same bare hasAllTokens path — no per-token length heuristics, no
    /// position, no iLike. CH tokenizes the string needle itself.
    #[test]
    fn structured_keyword_uses_hasalltokens() {
        for needle in ["a.b.c", "10.0.0.52", "cmd.exe", "192.168.1.100", "event_data"] {
            let query = parse_query(&format!("\"{}\"", needle)).unwrap();
            let sql = ClickHouseSqlGenerator::new()
                .generate(&query, &time_range())
                .unwrap();

            assert!(
                sql.contains(&format!("hasAllTokens(lower(message), '{needle}')")),
                "structured needle {:?} should emit bare hasAllTokens, got:\n{}",
                needle,
                sql
            );
            assert!(
                !sql.contains("iLike") && !sql.contains("position("),
                "structured needle {:?} must NOT emit iLike or position, got:\n{}",
                needle,
                sql
            );
        }
    }

    /// NAN-1515: an explicit wildcard in a bare keyword (`cmd*`, `c?d`) is
    /// partial-match intent → iLike pattern (the escape hatch from token search),
    /// not a hasAllTokens token lookup.
    #[test]
    fn bare_keyword_wildcard_uses_ilike_not_hasalltokens() {
        for (q, want) in [
            ("cmd*", "lower(message) iLike 'cmd%'"),
            ("c?d", "lower(message) iLike 'c_d'"),
        ] {
            let sql = ClickHouseSqlGenerator::new()
                .generate(&parse_query(q).unwrap(), &time_range())
                .unwrap();
            assert!(
                sql.contains(want) && !sql.contains("hasAllTokens"),
                "wildcard keyword {q:?} should emit {want:?} (no hasAllTokens), got:\n{sql}"
            );
        }
    }

    /// NAN-1515 edge cases: LIKE metachars are literal (no escaping — hasAllTokens
    /// takes a literal string); all-symbol needles fall back to substring iLike
    /// (no index tokens); non-ASCII stays inside a CH token.
    #[test]
    fn keyword_edge_cases() {
        // Spaces are token separators; the needle is just tokenized by CH.
        let query = parse_query("\" error \"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("hasAllTokens(lower(message), ' error ')")
                && !sql.contains("position(")
                && !sql.contains("iLike"),
            "spaced phrase lowers to bare hasAllTokens, got:\n{}",
            sql
        );

        // LIKE metachars `%`/`_` are ordinary literals to hasAllTokens — no escaping.
        let query = parse_query("\"100%_download\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("hasAllTokens(lower(message), '100%_download')"),
            "LIKE metachars must be literal in hasAllTokens, got:\n{}",
            sql
        );

        // All-separator needle with no wildcard → no index tokens → substring iLike.
        let query = parse_query("\"!!!\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(message) iLike '%!!!%'") && !sql.contains("hasAllTokens"),
            "all-separator needle falls back to substring iLike, got:\n{}",
            sql
        );

        // Unicode: non-ASCII stays inside a CH token, so `café` is a real token.
        let query = parse_query("\"café attachment\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("hasAllTokens(lower(message), 'café attachment')")
                && !sql.contains("position(")
                && !sql.contains("iLike"),
            "unicode phrase searches café as a token via hasAllTokens, got:\n{}",
            sql
        );
    }

    /// NAN-1416: `contains` on an indexed plain-String column mirrors the
    /// keyword guard; ext/JSON targets (no index) and negations get none.
    #[test]
    fn contains_multi_token_gets_guard_only_on_plain_string_columns() {
        // message contains a phrase → guard.
        let query = parse_query("message contains \"failed login\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains(
                "lower(message) iLike '%failed login%' AND lower(message) iLike '%failed%'"
            ),
            "multi-token CONTAINS on message should emit the guard, got:\n{}",
            sql
        );

        // Single-token CONTAINS keeps the exact pre-NAN-1416 shape.
        let query = parse_query("message contains \"anom\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("(lower(message) iLike '%anom%')")
                && !sql.contains(" AND lower(message) iLike "),
            "single-token CONTAINS must stay a single bare iLike, got:\n{}",
            sql
        );

        // Negated CONTAINS: NOT full ≢ guard ∧ NOT full — never guarded.
        let query = parse_query("message NOT contains \"failed login\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(message) NOT iLike '%failed login%'")
                && !sql.contains("AND lower(message) iLike '%failed%'"),
            "negated CONTAINS must NOT be guarded, got:\n{}",
            sql
        );

        // ext-JSON target (UDM field without explicit column): no index to
        // serve a guard → unguarded toString shape unchanged.
        let query = parse_query("ssl_hash contains \"failed login\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(toString(ext.ssl_hash)) iLike '%failed login%'")
                && !sql.contains("AND lower(message) iLike '%failed%'"),
            "ext-JSON CONTAINS must stay unguarded, got:\n{}",
            sql
        );
    }

    /// NAN-1515: the keyword codegen is profile-independent — OCSF keywords go
    /// through the same `lower(message)` arm (ocsf_logs carries the identical
    /// splitByNonAlpha index on lower(message)).
    #[test]
    fn ocsf_keyword_matches_udm_shape() {
        let gen = ClickHouseSqlGenerator::new()
            .with_profile(std::sync::Arc::new(crate::schema::OcsfProfile::new()));

        let query = parse_query("\"failed login\"").unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        assert!(
            sql.contains("hasAllTokens(lower(message), 'failed login')")
                && !sql.contains("position(")
                && !sql.contains("iLike"),
            "OCSF multi-token keyword should emit the same bare hasAllTokens shape, got:\n{}",
            sql
        );

        let query = parse_query("mimikatz").unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        assert!(
            sql.contains("hasAllTokens(lower(message), 'mimikatz')")
                && !sql.contains("position(")
                && !sql.contains("iLike"),
            "OCSF single-token keyword must be a bare hasAllTokens, got:\n{}",
            sql
        );
    }

    /// NAN-1416: regex pre-filters pick a single index-servable token — both
    /// the simple-literal lowering and the BloomGuard literal extraction.
    #[test]
    fn regex_prefilter_guard_is_single_token() {
        // Simple multi-token literal regex → full-needle iLike + guard.
        let query = parse_query("message=/failed login/").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains(
                "lower(message) iLike '%failed login%' AND lower(message) iLike '%failed%'"
            ),
            "multi-token literal regex should emit full iLike + guard, got:\n{}",
            sql
        );

        // Single-token literal regex pins the pre-NAN-1416 shape.
        let query = parse_query("message=/mimikatz/").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("(lower(message) iLike '%mimikatz%')")
                && !sql.contains(" AND lower(message) iLike "),
            "single-token literal regex must stay a single bare iLike, got:\n{}",
            sql
        );

        // Complex regex: extract_longest_literal must tokenize its winning
        // literal (`svchost.exe `) down to `svchost`, not emit the
        // index-useless multi-token guard `'%svchost.exe %'`.
        let query = parse_query("message=/svchost\\.exe (started|stopped)/").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(message) iLike '%svchost%' AND match(message,"),
            "complex regex pre-filter should guard on the longest single token, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("iLike '%svchost.exe %'"),
            "must NOT emit the multi-token (index-useless) literal guard, got:\n{}",
            sql
        );
    }

    /// NAN-1395: the field-stats companion gate. Wide (filter-only / row-shape
    /// preserving) pipelines keep the companion; transformative pipelines whose
    /// output projection replaces the base columns — `Columns(...)` from
    /// stats/chart/table/fields, or `Unknown` from funnel/sequence/transaction
    /// and any unmodeled command — must report non-wide so the companion is
    /// skipped instead of firing a guaranteed-Code-47 query.
    #[test]
    fn pipeline_output_is_wide_gates_field_stats_companion() {
        let generator = ClickHouseSqlGenerator::new();
        let wide = [
            "error",
            "status=500 | head 5",
            "* | where status=500 | sort -timestamp",
            "* | eval hash = md5(message) | head 10",
            "* | dedup src_ip | eval x = 1 | rename x as y",
        ];
        for q in wide {
            let query = parse_query(q).unwrap();
            assert!(
                generator.pipeline_output_is_wide(&query),
                "expected wide output (companion runs) for: {q}"
            );
        }

        let non_wide = [
            // Columns(...) — explicit reprojection.
            "* | stats count by src_ip",
            "* | chart count() by src_ip",
            "* | head 10 | table timestamp, src_ip, user",
            "* | fields src_ip, user",
            // Unknown — transformative commands not statically modeled.
            "* | transaction user",
            "* | sequence by src_ip maxspan=300s [status=403] [status=200]",
            // Columns appears mid-pipeline: downstream filters keep the
            // transformed (non-base) projection.
            "* | stats count by src_ip | where count > 10",
        ];
        for q in non_wide {
            let query = parse_query(q).unwrap();
            assert!(
                !generator.pipeline_output_is_wide(&query),
                "expected non-wide output (companion skipped) for: {q}"
            );
        }
    }

    /// NAN-1415: `logs.rule_id` is a plain String, but UUID_FIELDS routed it
    /// through `toString(rule_id) = '<lowered literal>'` — a case-SENSITIVE
    /// compare against a lowered literal, so uppercase-stored vendor rule ids
    /// never matched (empirically: the same form against an uppercase-stored
    /// hash matches 0 rows; the lower() form matches). It must emit
    /// `lower(rule_id) = …`, the exact expression the migration-132
    /// `idx_rule_id_lower` bloom is built on.
    #[test]
    fn rule_id_eq_emits_lower_not_tostring() {
        let query = parse_query("rule_id=\"AB-1234-Suspicious\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("lower(rule_id) = 'ab-1234-suspicious'"),
            "rule_id equality must emit lower(rule_id) = '<lowered>', got:\n{sql}"
        );
        assert!(
            !sql.contains("toString(rule_id)"),
            "rule_id must not be toString-wrapped (case-sensitive vs lowered literal + orphans the lower-expression bloom), got:\n{sql}"
        );
    }

    /// `id` stays on the UUID arm: it is a genuine CH UUID column where
    /// lower() is a type error and toString() renders lowercase already.
    #[test]
    fn id_eq_keeps_tostring_uuid_arm() {
        let query = parse_query("id=\"018F3A2B-0000-7000-8000-000000000000\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("toString(id) = '018f3a2b-0000-7000-8000-000000000000'"),
            "id (real UUID column) must keep the toString compare, got:\n{sql}"
        );
    }

    // NAN-1464: equality on an Array(String) column must compile to has()
    // (membership), never scalar `col = 'v'` (a CH type error that silently
    // matches nothing).
    #[test]
    fn tags_eq_emits_has_membership() {
        let query = parse_query("tags=\"web\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("has(tags, 'web')"),
            "tags equality must emit has(tags, '<lowered>'), got:\n{sql}"
        );
        assert!(!sql.contains("tags = "), "must not scalar-compare an array, got:\n{sql}");
    }

    #[test]
    fn tags_ne_emits_not_has() {
        let query = parse_query("tags!=\"web\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("NOT has(tags, 'web')"),
            "tags inequality must emit NOT has(...), got:\n{sql}"
        );
    }

    #[test]
    fn tags_wildcard_emits_array_exists() {
        let query = parse_query("tags=\"web*\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("arrayExists(x -> lower(x) iLike 'web%', tags)"),
            "tags wildcard must emit arrayExists over the elements, got:\n{sql}"
        );
    }

    // The pre-existing `*_tags` enrichment columns were subject to the same bug;
    // they now route through the same has() path.
    #[test]
    fn ioc_tags_eq_emits_has_membership() {
        let query = parse_query("ioc_tags=\"phishing\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("has(ioc_tags, 'phishing')"),
            "ioc_tags equality must emit has(), got:\n{sql}"
        );
    }

    /// NAN-1415: src_user is downcased at ingest (Vector clickhouse_mapping),
    /// so equality compares RAW and the whole-value `idx_src_user` bloom
    /// engages. dest_user is NOT ingest-normalized (mixed-case history) and
    /// must keep the lower() form — a raw compare would silently drop
    /// uppercase-stored matches.
    #[test]
    fn src_user_eq_compares_raw_dest_user_keeps_lower() {
        let query = parse_query("src_user=\"CORP-Admin\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("src_user = 'corp-admin'"),
            "src_user is ingest-lowercased; equality must compare raw for bloom pruning, got:\n{sql}"
        );
        assert!(
            !sql.contains("lower(src_user)"),
            "src_user must not be lower-wrapped on equality, got:\n{sql}"
        );

        let query = parse_query("dest_user=\"CORP-Admin\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(dest_user) = 'corp-admin'"),
            "dest_user has mixed-case history and must keep the lower() compare, got:\n{sql}"
        );
    }

    /// NAN-1415: the IOC-hunt equality fields must emit exactly `lower(col) =`
    /// — the expression the migration-132 `idx_<col>_lower` blooms are built
    /// on (ClickHouse matches skip indexes by expression). These columns have
    /// mixed-case history, so they must NOT join LOWERCASE_NORMALIZED_FIELDS
    /// even though ingest now canonicalizes hashes.
    #[test]
    fn ioc_equality_fields_emit_lower_form_matching_expression_blooms() {
        let cases = [
            ("process_hash", "7E48FDDCA1227FC511CEFA2EE473DC9C"),
            ("file_hash", "DEADBEEF"),
            ("process_guid", "40D3C75628DAEBB6"),
            ("user_id", "S-1-5-21-1888852550-2391102044-1519127082-9493"),
            ("url_domain", "DL-srv01"),
            ("file_name", "Tmp31a5fdf6.TMP"),
            ("signature_id", "4688"),
        ];
        for (field, value) in cases {
            let query = parse_query(&format!("{field}=\"{value}\"")).unwrap();
            let sql = ClickHouseSqlGenerator::new()
                .generate(&query, &time_range())
                .unwrap();
            let expected = format!("lower({field}) = '{}'", value.to_lowercase());
            assert!(
                sql.contains(&expected),
                "{field} equality must emit `{expected}` (the indexed expression), got:\n{sql}"
            );
        }
    }

    // ── NAN-1580: IOC observable-anywhere term expansion ──────────────────

    /// `ioc=<v>` emits ONE index-friendly predicate per observable column using
    /// an IN-list of the (lowercased) values: RAW (`col IN ('<lowered>')`) for
    /// the ingest-lowercased columns, `lower(col) IN (…)` for the mixed-case ones.
    /// IN on an indexed column prunes like equality but collapses the clause count
    /// from values×columns to columns (NAN-1580 P1-f).
    #[test]
    fn ioc_term_expands_across_observable_columns_index_friendly() {
        let query = parse_query("ioc=\"1.2.3.4\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        // Single WHERE, full partition-pruning time bound, NO explicit PREWHERE.
        assert!(
            sql.contains("WHERE timestamp BETWEEN") && !sql.contains("PREWHERE"),
            "ioc term must emit a single WHERE with no PREWHERE, got:\n{sql}"
        );

        // NAN-1590: an IP indicator type-scopes to the 3 IP columns (each bloom-
        // pruned); the OR penalty + non-prunable lower(text) legs are gone.
        for raw in [
            "src_ip IN ('1.2.3.4')",
            "dest_ip IN ('1.2.3.4')",
            "dvc_ip IN ('1.2.3.4')",
        ] {
            assert!(sql.contains(raw), "missing raw observable leg `{raw}`, got:\n{sql}");
        }
        // The irrelevant `lower(text)` legs (a hash/url/user/cve column can't hold
        // an IP) must NOT be emitted — that was the perf wall (NAN-1590).
        for absent in [
            "lower(file_hash)",
            "lower(url_domain)",
            "lower(query)",
            "lower(user_id)",
            "lower(cve)",
            "lower(signature_id)",
        ] {
            assert!(
                !sql.contains(absent),
                "IP scope must drop non-IP leg `{absent}`, got:\n{sql}"
            );
        }
        // The per-observable IP legs are OR'd (single disjunctive matchset).
        assert!(sql.contains(" OR "), "observable legs must be OR'd, got:\n{sql}");
    }

    /// NAN-1580 (OCSF-aware): under an `OcsfProfile`-configured generator the
    /// `ioc` term must resolve the LOGICAL observable names to the promoted OCSF
    /// physical columns (dotted → backtick-quoted), never the raw UDM column
    /// names — those don't exist on `ocsf_logs`, so emitting them would 500.
    /// Observables OCSF has no column for (`dvc_ip`, …) are silently skipped.
    #[test]
    fn ioc_term_resolves_ocsf_columns_under_ocsf_profile() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let query = parse_query("ioc=\"1.2.3.4\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("WHERE timestamp BETWEEN") && !sql.contains("PREWHERE"),
            "single WHERE, no PREWHERE, got:\n{sql}"
        );
        // RAW ingest-lowercased OCSF ip columns as IN-lists (escape_identifier
        // double-quotes dotted names).
        assert!(
            sql.contains("\"src_endpoint.ip\" IN ('1.2.3.4')"),
            "src_ip must resolve to src_endpoint.ip, got:\n{sql}"
        );
        assert!(
            sql.contains("\"dst_endpoint.ip\" IN ('1.2.3.4')"),
            "dest_ip must resolve to dst_endpoint.ip, got:\n{sql}"
        );
        // NAN-1590: an IP type-scopes to IP columns, so the hash MATCH leg must
        // NOT be emitted (it can't hold an IP). (The bare column may still appear
        // in the SELECT projection — assert on the predicate leg, not the column.)
        assert!(
            !sql.contains("lower(\"file.hashes.sha256\") IN"),
            "IP scope must drop the hash match leg under OCSF, got:\n{sql}"
        );
        // No bare UDM observable column leaks through.
        assert!(!sql.contains("src_ip IN ('1.2.3.4')"), "raw UDM src_ip leaked, got:\n{sql}");
        assert!(!sql.contains("lower(file_hash)"), "raw UDM file_hash leaked, got:\n{sql}");
        // dvc_ip has no OCSF mapping → skipped (and IP-scoped, so no UDM leak).
        assert!(!sql.contains("dvc_ip"), "dvc_ip should be skipped under OCSF, got:\n{sql}");
    }

    /// `ioc in [a, b]` emits ONE IN-list per observable column carrying every
    /// value (not value×column equalities). Both values are domains, so the term
    /// type-scopes to the domain columns (NAN-1590) — IP columns are dropped.
    #[test]
    fn ioc_in_list_expands_each_value() {
        let query = parse_query("ioc in [\"evil.com\", \"bad.net\"]").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        // Both values in a single IN-list on each (domain) observable column.
        assert!(
            sql.contains("lower(url_domain) IN ('evil.com', 'bad.net')"),
            "values must collapse into one IN-list per observable, got:\n{sql}"
        );
        assert!(
            sql.contains("lower(sender_domain) IN ('evil.com', 'bad.net')"),
            "values must collapse into one IN-list per (domain) observable, got:\n{sql}"
        );
        // Domain scope drops the IP columns (a domain can't be an IP).
        assert!(
            !sql.contains("src_ip IN ("),
            "domain scope must drop IP legs, got:\n{sql}"
        );
    }

    /// `ioc in feed("arg")` resolves the indicator set via a
    /// `custom_enrichment_results` IN-subquery (live IOC rows only).
    #[test]
    fn ioc_feed_term_emits_enrichment_subquery() {
        let query = parse_query("ioc in threatfox(\"apt29\")").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("custom_enrichment_results")
                && sql.contains("is_ioc = 1")
                && sql.contains("expires_at > now()"),
            "feed term must pull live IOCs from custom_enrichment_results, got:\n{sql}"
        );
        assert!(
            sql.contains("has(tags, 'apt29')") || sql.contains("LIKE '%apt29%'"),
            "feed arg must filter by tag or name, got:\n{sql}"
        );
        // Subquery wired into the observable columns via IN (…).
        assert!(
            sql.contains("src_ip IN (") && sql.contains("lower(file_hash) IN ("),
            "feed indicators must match each observable column via IN, got:\n{sql}"
        );
    }
