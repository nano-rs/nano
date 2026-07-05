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

    /// NAN-1635 (finding 3.6): multi-stage SQL must apply `QueryOptions.limit`
    /// to the final SELECT — previously it was dropped entirely, so the
    /// documented safety bound vanished for every piped query (a streamed
    /// high-cardinality `| stats count by col` ran unbounded, and deployments
    /// with query_limits.xml turned the graceful cap into a hard
    /// max_result_rows error).
    #[test]
    fn cte_final_select_applies_options_limit() {
        let gen = ClickHouseSqlGenerator::new();
        for q in [
            "error | where src_ip!=\"\"",          // row-preserving tail (implicit ORDER BY)
            "* | stats count by src_ip",           // aggregation tail
            "* | stats count by src_ip | sort -count", // ordering tail
        ] {
            let sql = gen
                .generate(&parse_query(q).unwrap(), &time_range())
                .unwrap();
            let final_select = sql
                .rfind("\nSELECT ")
                .map(|p| &sql[p..])
                .unwrap_or_else(|| panic!("no final SELECT in:\n{sql}"));
            assert!(
                final_select.contains(&format!(
                    "LIMIT {} ",
                    ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT
                )),
                "`{q}` final select must carry the safety LIMIT, got:\n{sql}"
            );
        }
    }

    /// NAN-1635 (finding 3.6): the limit stays offset-aware — `limit: None`
    /// keeps the CTE tail LIMIT-free for callers that own the bound themselves:
    /// the executor's injected LIMIT/OFFSET (pagination) and the prevalence
    /// JOIN wrapper (whose ORDER-BY-anchored stripper would miss a bare
    /// trailing `LIMIT` on a projected base like `| fields -`). The
    /// row-preserving tail is pinned by
    /// `multistage_raw_pipeline_with_limit_none_emits_no_limit` above.
    #[test]
    fn cte_final_select_skips_limit_for_executor_pagination() {
        let gen = ClickHouseSqlGenerator::new();
        let options = QueryOptions {
            limit: None,
            ..Default::default()
        };
        for q in ["* | stats count by src_ip", "error | fields - message"] {
            let sql = gen
                .generate_with_options(&parse_query(q).unwrap(), &time_range(), &options)
                .unwrap();
            assert!(
                !sql.to_uppercase().contains(" LIMIT "),
                "`{q}` with limit: None must keep the CTE tail LIMIT-free, got:\n{sql}"
            );
        }
    }

    /// NAN-1635 (finding 2.2): the histogram companion's base shape — with
    /// `unordered` + `limit: None` the generator emits a flat scan with no
    /// trailing ORDER BY and no LIMIT, so the wrapping GROUP BY buckets the
    /// FULL match set (the old `ORDER BY timestamp DESC LIMIT 1000000` base
    /// forced a top-1M sort AND silently truncated the timeline to the newest
    /// 1M events). Subsearch caps inside the base expression survive — they
    /// are query semantics, and dropping them would change the match set.
    #[test]
    fn unordered_limit_none_emits_flat_base_scan() {
        let gen = ClickHouseSqlGenerator::new();
        let options = QueryOptions {
            limit: None,
            unordered: true,
            ..Default::default()
        };
        for q in ["*", "error", "src_ip=\"10.0.0.1\""] {
            let sql = gen
                .generate_with_options(&parse_query(q).unwrap(), &time_range(), &options)
                .unwrap();
            assert!(
                !sql.contains("ORDER BY"),
                "`{q}` unordered base must have no sort, got:\n{sql}"
            );
            assert!(
                !sql.to_uppercase().contains(" LIMIT "),
                "`{q}` unbounded base must have no LIMIT, got:\n{sql}"
            );
        }

        // Subsearch cap is query semantics — it survives; only the trailing
        // ORDER BY is dropped.
        let sql = gen
            .generate_with_options(
                &parse_query("src_ip IN [search error | return src_ip]").unwrap(),
                &time_range(),
                &options,
            )
            .unwrap();
        assert!(
            sql.to_uppercase().contains(" LIMIT "),
            "subsearch cap must survive the unbounded base, got:\n{sql}"
        );
        assert!(
            !sql.contains("ORDER BY timestamp DESC"),
            "trailing sort must still be dropped, got:\n{sql}"
        );
    }

    /// NAN-1635 (findings 2.3/3.4) + NAN-1657: `unordered` on count-companion
    /// regenerations drops the implicit trailing ORDER BY and keeps user
    /// LIMITs (`| head N` bounds the count). NAN-1657 extended this to
    /// explicit `| sort` stages: a sort never changes the row count, so when
    /// nothing downstream is value-dependent it is dropped too (NAN-1635 had
    /// kept it, leaving a full-sort barrier inside the count wrap).
    #[test]
    fn unordered_keeps_user_head_and_sort_semantics() {
        let gen = ClickHouseSqlGenerator::new();
        let options = QueryOptions {
            limit: None,
            unordered: true,
            ..Default::default()
        };
        let head_sql = gen
            .generate_with_options(
                &parse_query("error | head 10").unwrap(),
                &time_range(),
                &options,
            )
            .unwrap();
        assert!(
            head_sql.contains("LIMIT 10 "),
            "user head cap must bound the count, got:\n{head_sql}"
        );
        assert!(
            !head_sql.contains("ORDER BY"),
            "implicit sort must be dropped (ORDER BY + LIMIT = top-N under the \
             count's inner LIMIT), got:\n{head_sql}"
        );

        // NAN-1657: a terminal `| sort` cannot change the count — dropped.
        let sort_sql = gen
            .generate_with_options(
                &parse_query("error | sort -bytes_out").unwrap(),
                &time_range(),
                &options,
            )
            .unwrap();
        assert!(
            !sort_sql.contains("ORDER BY"),
            "count-invariant terminal `| sort` must be dropped under unordered \
             (NAN-1657), got:\n{sort_sql}"
        );
    }

    /// NAN-1657: the matches-page incident shape. The count companion for
    /// `<filter> | sort -timestamp | head 10` regenerates with `unordered`;
    /// the sort is count-invariant (only a head follows), so it must be
    /// dropped — which collapses the pipeline onto the `search | head N`
    /// flat fast path where the LIMIT can genuinely early-terminate. With
    /// the sort kept (NAN-1635 behavior), the stage_1 ORDER BY was a full
    /// sort barrier and the count scanned the entire match set (Saturn:
    /// 151M rows to compute a count that is ≤ 10).
    #[test]
    fn unordered_drops_count_invariant_sort_before_head() {
        let gen = ClickHouseSqlGenerator::new();
        let options = QueryOptions {
            limit: None,
            unordered: true,
            ..Default::default()
        };
        let sql = gen
            .generate_with_options(
                &parse_query("src_ip=\"10.0.0.1\" | sort -timestamp | head 10").unwrap(),
                &time_range(),
                &options,
            )
            .unwrap();
        assert!(
            !sql.contains("ORDER BY"),
            "sort before a terminal head is count-invariant — must be dropped, got:\n{sql}"
        );
        assert!(
            sql.contains("LIMIT 10 "),
            "the head cap bounds the count and must survive, got:\n{sql}"
        );
        assert!(
            !sql.contains("WITH stage_0"),
            "with the sort gone this must collapse to the flat search|head fast \
             path (no CTE chain), got:\n{sql}"
        );

        // Ordered generation (the data fetch) is untouched — sort stays.
        let ordered = gen
            .generate_with_options(
                &parse_query("src_ip=\"10.0.0.1\" | sort -timestamp | head 10").unwrap(),
                &time_range(),
                &QueryOptions {
                    limit: None,
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(
            ordered.contains("ORDER BY"),
            "ordered fetch keeps the user sort, got:\n{ordered}"
        );
    }

    /// NAN-1657: a value-dependent stage AFTER a head makes the preceding sort
    /// count-RELEVANT (which 10 rows survive the cut changes what the filter
    /// sees), so the sort must be kept under unordered. Projections after the
    /// head stay benign.
    #[test]
    fn unordered_keeps_sort_when_filter_follows_head() {
        let gen = ClickHouseSqlGenerator::new();
        let options = QueryOptions {
            limit: None,
            unordered: true,
            ..Default::default()
        };
        let sql = gen
            .generate_with_options(
                &parse_query("error | sort -timestamp | head 10 | where status=500").unwrap(),
                &time_range(),
                &options,
            )
            .unwrap();
        assert!(
            sql.contains("ORDER BY"),
            "sort feeding head|where is count-relevant — must be kept, got:\n{sql}"
        );

        // Projection after the head is count-safe — sort still droppable.
        let proj_sql = gen
            .generate_with_options(
                &parse_query("error | sort -timestamp | head 10 | table src_ip, dest_ip")
                    .unwrap(),
                &time_range(),
                &options,
            )
            .unwrap();
        assert!(
            !proj_sql.contains("ORDER BY"),
            "sort before head|table is count-invariant — must be dropped, got:\n{proj_sql}"
        );
    }

    /// NAN-1657: a LIMITED sort (`sort N -field`) is a top-N — it CAPS the row
    /// count, so it must never be dropped by the unordered regeneration (only
    /// `limit: None` sorts are pure reorders).
    #[test]
    fn unordered_keeps_limited_sort_top_n() {
        let gen = ClickHouseSqlGenerator::new();
        let options = QueryOptions {
            limit: None,
            unordered: true,
            ..Default::default()
        };
        let sql = gen
            .generate_with_options(
                &parse_query("error | sort 5 -bytes_out").unwrap(),
                &time_range(),
                &options,
            )
            .unwrap();
        assert!(
            sql.contains("LIMIT 5"),
            "limited sort caps the count — its LIMIT must survive, got:\n{sql}"
        );
    }

    /// NAN-1635 (finding p12): the read-in-order toggle applies to CTE tails
    /// too — CH 26.4 inlines the CTEs and pushes the outer `ORDER BY timestamp
    /// DESC` down to the base read, so a piped query with a selective indexed
    /// equality must disable `optimize_read_in_order` exactly like its
    /// single-stage form (Saturn: ~23% wall on a pinned-source_type hunt and
    /// 78.91k rows read on a zero-match probe vs 0). A broad source_type-only
    /// pipe keeps it on.
    #[test]
    fn read_in_order_toggle_applies_to_cte_tail() {
        let gen = ClickHouseSqlGenerator::new();
        let selective = gen
            .generate(
                &parse_query(
                    "source_type=aws_cloudtrail src_ip=\"1.2.3.4\" | where dest_port=443",
                )
                .unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            selective.contains("optimize_read_in_order=0"),
            "piped selective indexed equality must disable read-in-order, got:\n{selective}"
        );
        let broad = gen
            .generate(
                &parse_query("source_type=aws_cloudtrail | where dest_port=443").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            broad.contains("optimize_read_in_order=1"),
            "broad piped source_type filter must keep read-in-order, got:\n{broad}"
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

    /// NAN-1698: OCSF `user.name` / `actor.user.name` are client-writable on the
    /// direct-INSERT-into-`ocsf_logs` path (which bypasses the derivation MV's
    /// lower()), so equality must lower() the stored column — same reasoning as
    /// source_type. UDM `user` already lowers (NAN-1697).
    #[test]
    fn ocsf_user_name_eq_is_case_tolerant() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let ocsf = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        for field in ["user.name", "actor.user.name"] {
            let q = parse_query(&format!("{field}=MixedUser")).unwrap();
            let sql = ocsf.generate(&q, &time_range()).unwrap();
            assert!(
                sql.contains(&format!("lower(\"{field}\") = 'mixeduser'")),
                "OCSF {field} equality must lower() the stored column, got:\n{sql}"
            );
            assert!(
                !sql.contains(&format!("\"{field}\" = 'mixeduser'")),
                "OCSF {field} must not emit the bare ingest-lowercased fast-path, got:\n{sql}"
            );
        }
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

    /// NAN-1643: the raw (no lower()) form on ingest-lowercased columns is
    /// Eq ONLY — for Eq it is row-identical to the lower() form while the
    /// ingest-lowercase invariant holds; for Ne it is not (an uppercase row
    /// flips from excluded to included), and a bloom can never prune a
    /// negation anyway. Ne must keep the lower() wrapper.
    #[test]
    fn udm_ne_on_ingest_lowercased_field_keeps_lower_wrapper() {
        let gen = ClickHouseSqlGenerator::new();
        for (q, want, forbid) in [
            (
                "src_ip!=\"89.248.167.131\"",
                "lower(src_ip) != '89.248.167.131'",
                "src_ip != '89.248.167.131'",
            ),
            (
                "user!=\"Admin\"",
                "lower(\"user\") != 'admin'",
                "\"user\" != 'admin'",
            ),
        ] {
            let sql = gen.generate(&parse_query(q).unwrap(), &time_range()).unwrap();
            let where_clause = where_slice(&sql);
            assert!(
                where_clause.contains(want) && !where_clause.contains(forbid),
                "UDM `{q}` must negate on lower(col), never the raw column (NAN-1643), got:\n{where_clause}"
            );
        }
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

        // NAN-1697: `user` Eq now emits the case-insensitive `lower("user")`
        // form (ingest doesn't downcase it — see LOWERCASE_NORMALIZED_FIELDS),
        // served by idx_user_words. The bare keyword drives idx_message_words
        // via hasAllTokens (NAN-1515).
        let sql = gen
            .generate(&parse_query("user=\"bob\" error").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(\"user\") = 'bob'")
                && sql.contains("hasAllTokens(lower(message), 'error')"),
            "UDM `user` Eq is case-insensitive; bare keyword uses hasAllTokens, got:\n{sql}"
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

    /// NAN-1697: `user` is NOT downcased at ingest (OTLP / Windows-event write
    /// it verbatim — mixed-case domain accounts), so equality must keep the
    /// case-insensitive `lower("user")` form, served by idx_user_words. A raw
    /// compare silently dropped those matches. (`user` is a CH reserved word →
    /// quoted.)
    #[test]
    fn user_eq_keeps_lower_for_mixed_case_accounts() {
        let query = parse_query("user=\"CORP-Admin\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(\"user\") = 'corp-admin'"),
            "user has mixed-case history and must keep the lower() compare, got:\n{sql}"
        );
    }

    /// NAN-1647 (NAN-1632 finding 3.9): dvc_ip is downcased at ingest (NAN-1646)
    /// and full-retention history is all-lowercase (Saturn: 0/1.75B rows
    /// mixed-case), so equality compares RAW and the whole-value dvc_ip bloom
    /// engages — `lower(dvc_ip)` matched no index. Negation keeps the
    /// `lower(dvc_ip)` form: NAN-1643 made the raw compare Eq-only (an uppercase
    /// row flips excluded→included under a raw `!=`, and no bloom prunes a
    /// negation anyway).
    #[test]
    fn dvc_ip_eq_and_ne_compare_raw() {
        let query = parse_query("dvc_ip=\"FE80::1ABC:2DEF\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("dvc_ip = 'fe80::1abc:2def'"),
            "dvc_ip is ingest-lowercased; equality must compare raw for bloom pruning, got:\n{sql}"
        );
        assert!(
            !sql.contains("lower(dvc_ip)"),
            "dvc_ip must not be lower-wrapped on equality, got:\n{sql}"
        );

        let query = parse_query("dvc_ip!=\"FE80::1ABC:2DEF\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(dvc_ip) != 'fe80::1abc:2def'"),
            "dvc_ip negation keeps the lower() form (NAN-1643 raw compare is Eq-only), got:\n{sql}"
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

    // === NAN-1634: secondary filter paths route through index-form selection ===
    //
    // Saturn-measured (CLICKHOUSE_SQLGEN_PERF_FINDINGS.md): the `| where` pipe,
    // IN-lists, subsearch IN, and field=function() filters bypassed the form
    // selection the primary search path applies, wrapping physical columns in
    // lower(toString(col)) / lower(col) / toString(col) — none of which match
    // the raw blooms, the lower(col) text indexes, or PK analysis.

    /// `| where col="v"` on an ingest-lowercased base column must compare RAW
    /// (bloom/set/PK engage via predicate pushdown into stage_0) — measured
    /// 31.8x read_rows vs the previous `lower(toString(src_ip))` wrap.
    #[test]
    fn where_pipe_eq_on_ingest_lowercased_column_compares_raw() {
        let query = parse_query("* | where src_ip=\"10.1.6.161\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("src_ip = '10.1.6.161'"),
            "where-pipe Eq on src_ip must be raw, got:\n{sql}"
        );
        assert!(
            !sql.contains("lower(toString(src_ip))"),
            "index-defeating wrap must be gone, got:\n{sql}"
        );
    }

    /// `| where col!="v"` must KEEP the case-insensitive wrap — raw negation
    /// flips invariant-violating rows from excluded to included, and no skip
    /// index prunes a negation anyway (the "Eq ONLY" rule the OCSF alias path
    /// documents).
    #[test]
    fn where_pipe_ne_keeps_case_insensitive_wrap() {
        let query = parse_query("* | where user!=\"admin\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(toString(\"user\")) != 'admin'"),
            "where-pipe Ne must stay case-insensitive, got:\n{sql}"
        );
    }

    /// NOT IN keeps the `lower()` wrap on both the search path and the
    /// where-pipe path — same negation rule as Ne.
    #[test]
    fn not_in_keeps_lower_wrap_on_ingest_lowercased_columns() {
        let query = parse_query("src_ip NOT IN (\"10.1.2.3\")").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            where_slice(&sql).contains("lower(src_ip) NOT IN ('10.1.2.3')"),
            "search-path NOT IN must keep lower(), got:\n{sql}"
        );

        let query = parse_query("* | where src_ip NOT IN (\"10.1.2.3\")").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(src_ip) NOT IN ('10.1.2.3')"),
            "where-pipe NOT IN must keep lower(), got:\n{sql}"
        );
    }

    /// A text-indexed column that is NOT lowercased at ingest takes the
    /// `lower(col)` form (the migration-119 text indexes are built on
    /// `lower(col)`; `lower(toString(col))` matches no index expression).
    #[test]
    fn where_pipe_eq_on_text_column_uses_lower_form() {
        let query = parse_query("* | where dest_user=\"Administrator\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(dest_user) = 'administrator'"),
            "where-pipe Eq on dest_user must use lower(col) (mixed-case history — raw would drop matches), got:\n{sql}"
        );
    }

    /// A pipeline-computed name shadowing a physical column (NAN-1341) must
    /// KEEP the scope-relative normalizing wrap — its values are not the
    /// ingest-normalized column values.
    #[test]
    fn where_pipe_eq_on_shadowed_column_keeps_tostring_wrap() {
        let query = parse_query("* | eval user=upper(src_host) | where user=\"WS01\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(toString(\"user\")) = 'ws01'"),
            "computed `user` must keep the lower(toString()) wrap, got:\n{sql}"
        );
    }

    /// where-pipe IN on an ingest-lowercased base column drops the `lower()`.
    #[test]
    fn where_pipe_in_list_on_ingest_lowercased_column_compares_raw() {
        let query = parse_query("* | where src_ip IN (\"10.1.2.3\", \"10.4.5.6\")").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("src_ip IN ('10.1.2.3', '10.4.5.6')"),
            "where-pipe IN on src_ip must be raw, got:\n{sql}"
        );
        assert!(
            !sql.contains("lower(src_ip)"),
            "lower() must not wrap src_ip, got:\n{sql}"
        );
    }

    /// Search-path IN-list on an ingest-lowercased column compares RAW,
    /// mirroring the Eq arm (measured 8.6x read_rows on a 7d two-IP hunt);
    /// a mixed-case-history column keeps `lower(col) IN`.
    #[test]
    fn search_in_list_form_selection_matches_eq_arm() {
        let query = parse_query("src_ip IN (\"10.1.2.3\", \"10.4.5.6\")").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        let where_clause = where_slice(&sql);
        assert!(
            where_clause.contains("src_ip IN ('10.1.2.3', '10.4.5.6')"),
            "IN-list on src_ip must be raw so idx_src_ip + PK prune, got:\n{where_clause}"
        );

        let query = parse_query("dest_user IN (\"Alice\", \"Bob\")").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        let where_clause = where_slice(&sql);
        assert!(
            where_clause.contains("lower(dest_user) IN ('alice', 'bob')"),
            "IN-list on mixed-case-history dest_user must keep lower(), got:\n{where_clause}"
        );
    }

    /// Subsearch IN with plain physical String columns on BOTH sides drops the
    /// `toString()` wraps (strict identity on non-Nullable String DEFAULT '')
    /// so the outer column's expression-matched bloom engages (2.98x granules).
    #[test]
    fn subsearch_in_plain_string_both_sides_drops_tostring() {
        let query = parse_query("src_ip IN [search error | return src_ip]").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("src_ip IN (SELECT DISTINCT src_ip FROM"),
            "plain-String subsearch IN must compare bare columns, got:\n{sql}"
        );
        assert!(
            !sql.contains("toString(src_ip)"),
            "toString wrap must be gone on the String/String path, got:\n{sql}"
        );
    }

    /// A UUID outer side (the NAN-1562 coercion class) KEEPS the normalizing
    /// `toString()` wrap.
    #[test]
    fn subsearch_in_uuid_side_keeps_tostring() {
        let query = parse_query("id IN [search error | return id]").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("toString(id) IN (SELECT DISTINCT toString(id) FROM"),
            "UUID subsearch IN must keep the toString coercion, got:\n{sql}"
        );
    }

    /// `field=function(...)` on an explicit column must compare the PHYSICAL
    /// column — the previous unconditional `JSONExtractString(metadata, …)`
    /// probe is empty for every promoted field (metadata carries no copies),
    /// so `user=lower(dest_user)` degenerated to `'' = rhs` and matched WRONG
    /// rows.
    #[test]
    fn field_function_filter_resolves_explicit_column_not_metadata() {
        let query = parse_query("user=lower(dest_user)").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        let where_clause = where_slice(&sql);
        // NAN-1697: `user` is no longer in LOWERCASE_NORMALIZED_FIELDS, so the
        // LHS is `lower("user")`, not the raw column — still the PHYSICAL column
        // (the point of this test), never the metadata JSON probe.
        assert!(
            where_clause.contains("lower(\"user\") = lower(lower(dest_user))"),
            "LHS must be the physical column (lower-wrapped), got:\n{where_clause}"
        );
        assert!(
            !where_clause.contains("JSONExtractString(metadata, 'user')"),
            "metadata probe must be gone for explicit columns, got:\n{where_clause}"
        );
    }

    /// Numeric explicit columns skip lower() on both sides (CH Code 43).
    #[test]
    fn field_function_filter_numeric_column_skips_lower() {
        let query = parse_query("src_port=abs(dest_port)").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        let where_clause = where_slice(&sql);
        assert!(
            where_clause.contains("src_port = abs(dest_port)"),
            "numeric field=function() must compare raw, got:\n{where_clause}"
        );
    }

    /// Unknown fields keep the metadata-JSON fallback (pre-NAN-1634 behavior).
    #[test]
    fn field_function_filter_unknown_field_keeps_metadata_fallback() {
        let query = parse_query("weird_custom_field=lower(user)").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        let where_clause = where_slice(&sql);
        assert!(
            where_clause.contains("JSONExtractString(metadata, 'weird_custom_field')"),
            "unknown fields must keep the metadata-JSON access, got:\n{where_clause}"
        );
    }

    /// NAN-1639 (finding 3.8): the executor-injected `| sort -count` on a
    /// grouped stats query must not emit a bogus `ext.count` column, and the
    /// stage_0 base read must stay on the pruned projection instead of the
    /// wide `SELECT *` + MATERIALIZED re-adds.
    #[test]
    fn injected_sort_on_grouped_stats_keeps_pruned_stage_0() {
        let gen = ClickHouseSqlGenerator::new();
        let query = parse_query("* | stats count by src_ip | sort -count").unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        assert!(
            !sql.contains("ext.count"),
            "aggregation output alias must not be spilled from ext, got:\n{sql}"
        );
        let stage_0 = sql
            .split("stage_1")
            .next()
            .expect("stage_0 present");
        assert!(
            !stage_0.contains("SELECT *"),
            "grouped stats + injected sort must keep the pruned stage_0, got:\n{sql}"
        );
        assert!(
            stage_0.contains("src_ip"),
            "group-by column must be projected in stage_0, got:\n{sql}"
        );
        assert!(
            sql.contains("ORDER BY count DESC"),
            "sort must still bind the stats output column, got:\n{sql}"
        );
    }

    /// NAN-1639 (finding 2.4): in table_view a row-preserving pipe keeps the
    /// slim summary stage_0 (the same projection a bare search gets) plus the
    /// pipe's referenced fields — not `SELECT *` + 78 MATERIALIZED re-adds.
    #[test]
    fn table_view_where_pipe_keeps_slim_stage_0() {
        let gen = ClickHouseSqlGenerator::new();
        let query = parse_query("error | where dest_port=443").unwrap();
        let options = QueryOptions {
            table_view: true,
            ..Default::default()
        };
        let sql = gen
            .generate_with_options(&query, &time_range(), &options)
            .unwrap();
        let stage_0 = sql.split("stage_1").next().expect("stage_0 present");
        assert!(
            !stage_0.contains("SELECT *"),
            "table_view where-pipe must keep the slim stage_0, got:\n{sql}"
        );
        // Slim summary columns + the pipe-referenced field are projected.
        for col in ["dest_port", "src_ip", "enriched_src_country", "prevalence_min"] {
            assert!(
                stage_0.contains(col),
                "slim stage_0 missing {col}, got:\n{sql}"
            );
        }
        // The where stage still filters on the projected column.
        assert!(sql.contains("WHERE dest_port = 443"), "got:\n{sql}");
    }

    /// NAN-1639 (finding 2.4) scope guards: a structural command (rex) keeps
    /// the wide stage_0 even in table_view, and a NON-table_view where-pipe
    /// keeps the historical full-row projection for API/detection consumers.
    #[test]
    fn wide_stage_0_retained_where_full_rows_are_required() {
        let gen = ClickHouseSqlGenerator::new();
        for (q, table_view) in [
            ("error | rex \"(?P<foo>bar)\"", true),
            ("error | where dest_port=443", false),
        ] {
            let options = QueryOptions {
                table_view,
                ..Default::default()
            };
            let sql = gen
                .generate_with_options(&parse_query(q).unwrap(), &time_range(), &options)
                .unwrap();
            let stage_0 = sql.split("stage_1").next().expect("stage_0 present");
            assert!(
                stage_0.contains("SELECT *, action AS event_type"),
                "{q} (table_view={table_view}) must keep the wide stage_0, got:\n{sql}"
            );
        }
    }

    /// NAN-1644 (finding 2.6): `ext.*` in a GROUP BY must be projected as the
    /// native subcolumn in stage_0's SELECT list (`toString(ext.<key>) AS
    /// "ext.<key>"`) with the aggregation binding the alias — NOT extracted
    /// from `metadata` (which never carries an 'ext' key: every row collapsed
    /// into one '' bucket), and NOT re-derived in the aggregation stage (a
    /// stage_1 expression over the base read defeats ClickHouse 26.4
    /// JSON-subcolumn pruning — local A/B: 1.65 GiB vs 103 MiB read_bytes).
    #[test]
    fn ext_dotted_group_by_binds_stage_0_native_subcolumn() {
        let gen = ClickHouseSqlGenerator::new();
        for q in [
            "* | stats count by ext.threat_name",
            "* | stats count by ext.threat_name | sort -count",
            "* | top ext.threat_name",
            "* | timechart span=1h count by ext.threat_name",
        ] {
            let sql = gen.generate(&parse_query(q).unwrap(), &time_range()).unwrap();
            let stage_0 = sql.split("stage_1").next().expect("stage_0 present");
            assert!(
                stage_0.contains("toString(ext.threat_name) AS \"ext.threat_name\""),
                "{q}: stage_0 must project the native ext subcolumn, got:\n{sql}"
            );
            assert!(
                !sql.contains("JSONExtractString(metadata, 'ext'"),
                "{q}: ext.* must never be extracted from metadata, got:\n{sql}"
            );
            // The aggregation stage binds the projected alias — the expression
            // must not be re-derived outside stage_0.
            let post_stage_0 = &sql[sql.find("stage_1").unwrap()..];
            assert!(
                !post_stage_0.contains("toString(ext."),
                "{q}: ext access re-derived outside stage_0 (pruning trap), got:\n{sql}"
            );
        }
    }

    /// NAN-1644: the wide (`SELECT *`) base — forced here by `| fillnull` —
    /// must ALSO carry the explicit `toString(ext.<key>)` projection: `ext.*`
    /// materialization is needs_all-independent, or the GROUP BY alias has
    /// nothing to bind.
    #[test]
    fn ext_dotted_projection_survives_wide_stage_0() {
        let gen = ClickHouseSqlGenerator::new();
        let query =
            parse_query("* | stats count by ext.threat_name | fillnull value=\"-\"").unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        let stage_0 = sql.split("stage_1").next().expect("stage_0 present");
        assert!(
            stage_0.contains("SELECT *")
                && stage_0.contains("toString(ext.threat_name) AS \"ext.threat_name\""),
            "wide stage_0 must still project the ext subcolumn explicitly, got:\n{sql}"
        );
    }

    /// NAN-1644: `metadata_`-prefixed fields keep metadata JSON extraction —
    /// and the slim projection passes the backing `metadata` column through
    /// (the aggregation stage re-derives `JSONExtractString(metadata, …)` per
    /// reference), instead of the previous junk `toString(ext.metadata_foo)`
    /// spill that shadowed nothing.
    #[test]
    fn metadata_prefixed_group_by_keeps_metadata_extraction() {
        let gen = ClickHouseSqlGenerator::new();
        let query = parse_query("* | stats count by metadata_channel").unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        assert!(
            sql.contains("GROUP BY toString(JSONExtractString(metadata, 'channel'))"),
            "metadata_ prefix must keep metadata JSON extraction, got:\n{sql}"
        );
        let stage_0 = sql.split("stage_1").next().expect("stage_0 present");
        assert!(
            stage_0.contains(" metadata FROM logs") || stage_0.contains(", metadata,"),
            "slim stage_0 must pass the metadata column through, got:\n{sql}"
        );
        assert!(
            !sql.contains("ext.metadata_channel"),
            "metadata_ field must not be spilled from ext, got:\n{sql}"
        );
    }

    /// NAN-1644: a `| where` on an `ext.*` field filters via the stage_0
    /// projected alias (native subcolumn semantics), not metadata JSON.
    #[test]
    fn where_pipe_on_ext_dotted_binds_projected_alias() {
        let gen = ClickHouseSqlGenerator::new();
        let options = QueryOptions {
            table_view: true,
            ..Default::default()
        };
        let sql = gen
            .generate_with_options(
                &parse_query("error | where ext.threat_name=\"x\"").unwrap(),
                &time_range(),
                &options,
            )
            .unwrap();
        let stage_0 = sql.split("stage_1").next().expect("stage_0 present");
        assert!(
            stage_0.contains("toString(ext.threat_name) AS \"ext.threat_name\""),
            "stage_0 must materialize the ext field, got:\n{sql}"
        );
        assert!(
            sql.contains("lower(toString(\"ext.threat_name\")) = 'x'"),
            "where stage must bind the projected alias, got:\n{sql}"
        );
    }

    /// NAN-1644 scope guard: under OCSF, `ext.*` resolves into the JSON tail
    /// (JsonPath → the `unmapped` column) — the UDM alias-binding branch must
    /// not hijack it, and it must never read `metadata`.
    #[test]
    fn ocsf_ext_dotted_group_by_keeps_json_tail_access() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        let query = parse_query("* | stats count by ext.threat_name").unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        assert!(
            sql.contains("unmapped.\"threat_name\""),
            "OCSF ext.* must route to the unmapped JSON tail, got:\n{sql}"
        );
        assert!(
            !sql.contains("JSONExtractString(metadata, 'ext'"),
            "OCSF ext.* must not read metadata, got:\n{sql}"
        );
    }

    /// NAN-1644: an `ext.*` referenced only INSIDE a join subsearch must be
    /// materialized in the subsearch's own base scan (the outer analysis walks
    /// the subsearch pipeline), and its GROUP BY binds the projected alias.
    #[test]
    fn join_subsearch_ext_dotted_is_materialized_in_sub_base() {
        let gen = ClickHouseSqlGenerator::new();
        let query = parse_query(
            "* | join user [search error | stats count by ext.threat_name, user]",
        )
        .unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        assert!(
            sql.contains("toString(ext.threat_name) AS \"ext.threat_name\""),
            "subsearch base scan must project the ext subcolumn, got:\n{sql}"
        );
        assert!(
            sql.contains("GROUP BY \"ext.threat_name\", \"user\""),
            "subsearch GROUP BY must bind the projected alias, got:\n{sql}"
        );
        assert!(
            !sql.contains("JSONExtractString(metadata, 'ext'"),
            "ext.* must never be extracted from metadata, got:\n{sql}"
        );
    }


    // ── dedup survivor-id rewrite (NAN-1636, finding 2.7) ──────────────────
    //
    // The legacy `ORDER BY <keys>, timestamp LIMIT 1 BY <keys>` full-sorts
    // every wide row — Code 241 OOM at ≥~15min windows under the production
    // 3GiB/query profile. Over the deterministic base scan the stage instead
    // filters to per-key argMin(id, timestamp) survivors. Every guard trips
    // back to the legacy shape.

    /// `dedup` directly over the base scan (stage_0) must emit the survivor-id
    /// shape: no sort, keep-oldest via argMin(id, timestamp).
    #[test]
    fn dedup_on_base_scan_emits_survivor_id_in() {
        let query = parse_query("* | dedup src_ip").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("WHERE id IN (") && sql.contains("argMin(id, timestamp) FROM stage_0"),
            "dedup over the base scan must select survivors via argMin(id, timestamp), got:\n{sql}"
        );
        assert!(
            sql.contains("GROUP BY src_ip"),
            "survivor subquery must group by the dedup keys, got:\n{sql}"
        );
        assert!(
            !sql.contains("LIMIT 1 BY"),
            "rewritten dedup must not carry the OOM-class full-row sort + LIMIT 1 BY, got:\n{sql}"
        );
    }

    /// Multi-key dedup groups the survivor subquery by every key.
    #[test]
    fn dedup_multi_key_groups_by_all_keys() {
        let query = parse_query("error | dedup src_ip, user").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("GROUP BY src_ip, \"user\"") && sql.contains("argMin(id, timestamp)"),
            "multi-key dedup must group survivors by all keys, got:\n{sql}"
        );
    }

    /// Guard 1: an upstream include-mode projection that pruned `id` would make
    /// the IN-subquery UNKNOWN_IDENTIFIER — keep the legacy shape.
    #[test]
    fn dedup_after_id_pruning_projection_falls_back() {
        for q in [
            "* | fields src_ip, user | dedup src_ip",
            "* | table src_ip, user | dedup src_ip",
        ] {
            let query = parse_query(q).unwrap();
            let sql = ClickHouseSqlGenerator::new()
                .generate(&query, &time_range())
                .unwrap();
            assert!(
                sql.contains("LIMIT 1 BY src_ip") && !sql.contains("argMin("),
                "dedup after id-pruning projection must keep the legacy shape for {q}, got:\n{sql}"
            );
        }
    }

    /// Guard 2: an upstream `eval id=…` shadows the physical row id — survivor
    /// selection on the reassigned value would keep the wrong rows.
    #[test]
    fn dedup_after_eval_id_shadowing_falls_back() {
        let query = parse_query("* | eval id=user | dedup src_ip").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("LIMIT 1 BY src_ip") && !sql.contains("argMin("),
            "dedup after `eval id=…` must keep the legacy shape, got:\n{sql}"
        );
    }

    /// Guard 3: the rewrite scans its source CTE twice, so any non-base source
    /// stage — nondeterministic (`head N` with no ORDER BY) or otherwise —
    /// keeps the legacy single-scan shape.
    #[test]
    fn dedup_after_upstream_command_falls_back() {
        for q in [
            "* | head 100 | dedup src_ip",
            "error | where status=\"failure\" | dedup src_ip",
            "* | sort -timestamp | dedup src_ip",
        ] {
            let query = parse_query(q).unwrap();
            let sql = ClickHouseSqlGenerator::new()
                .generate(&query, &time_range())
                .unwrap();
            assert!(
                sql.contains("LIMIT 1 BY src_ip") && !sql.contains("argMin("),
                "dedup with a non-base source must keep the legacy shape for {q}, got:\n{sql}"
            );
        }
    }

    /// Guard 3 (requery variant): a downstream requery command (tree/asset/
    /// cloud) injects `ORDER BY … LIMIT` into stage_0 — a bounded top-N samples
    /// tie rows nondeterministically per scan, so the dual-scan rewrite must
    /// not fire even though dedup's source IS stage_0.
    #[test]
    fn dedup_with_requery_command_falls_back() {
        let query = parse_query("* | dedup src_host | tree process").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("LIMIT 1 BY src_host") && !sql.contains("argMin("),
            "dedup over a LIMITed requery base scan must keep the legacy shape, got:\n{sql}"
        );
    }

    /// Subsearch pipelines route through `generate_command_sql` (no stage
    /// context) — the rewrite stays off there; only the main pipeline's
    /// base-scan dedup rewrites.
    #[test]
    fn dedup_inside_subsearch_falls_back() {
        let query = parse_query("error | append [error | dedup src_ip]").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("LIMIT 1 BY src_ip") && !sql.contains("argMin("),
            "subsearch dedup must keep the legacy shape, got:\n{sql}"
        );
    }

    /// Spans/metrics profiles have no `id`/`timestamp` core columns — the
    /// survivor-id shape can't apply; the legacy shape is preserved.
    #[test]
    fn dedup_on_spans_dataset_falls_back() {
        let query = parse_query("* | dedup service_name").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .with_dataset(otel::Dataset::Spans)
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("LIMIT 1 BY service_name") && !sql.contains("argMin(id"),
            "spans dedup must keep the legacy shape (no id row identity), got:\n{sql}"
        );
    }

    /// OCSF: dedup keys resolve through the active profile (src_ip → the
    /// promoted endpoint column); `id` is a physical ocsf_logs column, so the
    /// survivor-id rewrite still fires.
    #[test]
    fn dedup_ocsf_resolves_keys_and_rewrites() {
        use crate::schema::OcsfProfile;
        let query = parse_query("* | dedup src_ip").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("argMin(id, timestamp)") && sql.contains("WHERE id IN ("),
            "OCSF dedup over the base scan must rewrite, got:\n{sql}"
        );
        assert!(
            !sql.contains("GROUP BY src_ip"),
            "OCSF dedup key must resolve through the profile, not stay a raw UDM name, got:\n{sql}"
        );
    }

    /// Documented ordering behavior (finding 2.7 guard 4): the rewritten dedup
    /// stage carries NO ORDER BY — the survivor SET is unchanged (per-key
    /// oldest), but which of them a downstream bare `head N` picks follows
    /// stream order, not the legacy shape's `<keys>, timestamp` sort order.
    /// This artifact-order change is accepted; a terminal dedup still gets the
    /// outer `ORDER BY timestamp DESC` like every non-ordering pipeline.
    #[test]
    fn dedup_then_head_keeps_rewrite_without_stage_ordering() {
        let query = parse_query("* | dedup src_ip | head 5").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("argMin(id, timestamp)"),
            "downstream head must not disable the rewrite (guards are about the SOURCE), got:\n{sql}"
        );
        // The dedup stage itself is sort-free — reintroducing the legacy
        // `ORDER BY <keys>, timestamp` would resurrect the wide-row sort the
        // rewrite exists to remove.
        assert!(
            !sql.contains("ORDER BY src_ip"),
            "rewritten dedup stage must not sort by the dedup keys, got:\n{sql}"
        );
    }

    // ── resolve_identity bounded ASOF build side (NAN-1638, finding 2.8) ───
    //
    // The bare-table ASOF join materialized ALL of identity_observations into
    // the join build side (62.8M rows on Saturn incl. S3 cold tier) —
    // MEMORY_LIMIT_EXCEEDED 3/3 at the production 3GiB cap; the max-age filter
    // in the outer WHERE ran only after the join. The build side is now
    // bounded to `observed_at BETWEEN query_start − max_age AND query_end`,
    // which covers every observation an in-window event can accept.

    /// Default max_age (24h): the build side must be bounded to
    /// [window_start − 24h, window_end].
    #[test]
    fn resolve_identity_bounds_build_side_to_window_plus_max_age() {
        let query = parse_query("src_ip=\"10.0.0.1\" | resolve_identity src_ip").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains(
                "ASOF LEFT JOIN (\n    SELECT * FROM identity_observations\n    WHERE observed_at BETWEEN '2023-12-31 00:00:00.000000' AND '2024-01-02 00:00:00.000000'\n  ) AS i"
            ),
            "build side must be bounded to window_start − max_age .. window_end, got:\n{sql}"
        );
        // The outer max-age semantics are unchanged: the per-event staleness
        // filter and the no-match ('none') branch both survive — the bound
        // only shrinks the join build side.
        assert!(
            sql.contains("i.observed_at IS NULL")
                && sql.contains("INTERVAL 86400 SECOND"),
            "outer max-age WHERE + none-branch must be preserved, got:\n{sql}"
        );
    }

    /// A user-supplied max_age drives the lower bound.
    #[test]
    fn resolve_identity_bound_respects_custom_max_age() {
        let query = parse_query("* | resolve_identity src_ip max_age=1h").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("WHERE observed_at BETWEEN '2023-12-31 23:00:00.000000' AND '2024-01-02 00:00:00.000000'"),
            "custom max_age must widen the lower bound by exactly max_age, got:\n{sql}"
        );
    }

    /// Reverse lookups (user/hostname → IP) get the same bound.
    #[test]
    fn resolve_identity_reverse_lookup_is_bounded_too() {
        let query = parse_query("* | resolve_identity user").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("SELECT * FROM identity_observations\n    WHERE observed_at BETWEEN"),
            "reverse lookup build side must be bounded, got:\n{sql}"
        );
    }

    /// Guard (skeptic amendment): `bin timestamp span=X` floors event
    /// timestamps up to one span BEFORE the window start, so the
    /// window-derived bound could cut observations those rewritten timestamps
    /// still accept — the join must stay unbounded. Conservative choice over
    /// widening the bound by accumulated spans (spans can chain/alias through
    /// multiple stages, and eval rewrites are unboundable anyway).
    #[test]
    fn resolve_identity_after_bin_timestamp_stays_unbounded() {
        for q in [
            "* | bin timestamp span=1h | resolve_identity src_ip",
            "* | bin _time span=30m | resolve_identity src_ip",
            "* | bin span=1h field=x as timestamp | resolve_identity src_ip",
        ] {
            let query = parse_query(q).unwrap();
            let sql = ClickHouseSqlGenerator::new()
                .generate(&query, &time_range())
                .unwrap();
            assert!(
                sql.contains("ASOF LEFT JOIN identity_observations AS i"),
                "timestamp-rewriting bin must keep the unbounded join for {q}, got:\n{sql}"
            );
            assert!(
                !sql.contains("WHERE observed_at BETWEEN"),
                "no build-side bound may be emitted after a timestamp rewrite for {q}, got:\n{sql}"
            );
        }
    }

    /// A field-less `bin span=X` writes `time_bucket` and leaves `timestamp`
    /// intact — the bound still applies.
    #[test]
    fn resolve_identity_after_fieldless_bin_stays_bounded() {
        let query = parse_query("* | bin span=1h | resolve_identity src_ip").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("time_bucket") && sql.contains("WHERE observed_at BETWEEN"),
            "field-less bin does not rewrite timestamp — bound must apply, got:\n{sql}"
        );
    }

    /// Any upstream reassignment of `timestamp` — eval/rename/rex named
    /// capture/stats alias (upstream-computed set) or a `table … as timestamp`
    /// re-alias (dedicated flag) — moves row timestamps to values no
    /// window-derived bound can cover; the join must stay unbounded for all.
    #[test]
    fn resolve_identity_after_timestamp_reassignment_stays_unbounded() {
        for q in [
            "* | eval timestamp=now() | resolve_identity src_ip",
            "* | rename observed_time as timestamp | resolve_identity src_ip",
            "* | rex field=message \"(?<timestamp>\\\\d+)\" | resolve_identity src_ip",
            "* | stats max(observed_time) as timestamp by src_ip | resolve_identity src_ip",
            "* | table first_seen as timestamp, src_ip, id | resolve_identity src_ip",
        ] {
            let query = parse_query(q).unwrap();
            let sql = ClickHouseSqlGenerator::new()
                .generate(&query, &time_range())
                .unwrap();
            assert!(
                sql.contains("ASOF LEFT JOIN identity_observations AS i")
                    && !sql.contains("WHERE observed_at BETWEEN"),
                "timestamp reassignment must keep the unbounded join for {q}, got:\n{sql}"
            );
        }
    }

    /// Direct `generate_command_sql` callers (subsearch nesting, prevalence
    /// re-embedding) run outside `generate_with_options` — no generation time
    /// range exists, so the legacy unbounded shape is kept.
    #[test]
    fn resolve_identity_without_generation_window_stays_unbounded() {
        let gen = ClickHouseSqlGenerator::new();
        let cmd = Command::ResolveIdentity {
            field: "src_ip".to_string(),
            max_age: std::time::Duration::from_secs(24 * 3600),
        };
        let sql = gen.generate_command_sql("stage_0", &cmd).unwrap();
        assert!(
            sql.contains("ASOF LEFT JOIN identity_observations AS i")
                && !sql.contains("WHERE observed_at BETWEEN"),
            "no-window generation must keep the unbounded join, got:\n{sql}"
        );
    }


    /// A pathological max_age (the parser accepts up to u64::MAX seconds)
    /// must degrade to the legacy unbounded join — never panic codegen
    /// (chrono::Duration::seconds panics past ~i64::MAX/1000 seconds).
    #[test]
    fn resolve_identity_pathological_max_age_degrades_to_unbounded() {
        let gen = ClickHouseSqlGenerator::new();
        let query = crate::query::ast::Query::Piped {
            source: Box::new(crate::query::ast::Query::Search(SearchExpr::Keyword(
                "*".to_string(),
            ))),
            command: Command::ResolveIdentity {
                field: "src_ip".to_string(),
                max_age: std::time::Duration::from_secs(u64::MAX),
            },
        };
        let sql = gen.generate(&query, &time_range()).unwrap();
        assert!(
            sql.contains("ASOF LEFT JOIN identity_observations AS i")
                && !sql.contains("WHERE observed_at BETWEEN"),
            "overflow-class max_age must fall back to the unbounded join, got:\n{sql}"
        );
    }

    /// NAN-1640: an anchored prefix regex on a text-indexed String column emits
    /// an implied `iLike '%tok%'` guard in front of the startsWith — no skip
    /// index serves startsWith (text-index analysis yields `tokens: []`, full
    /// column read; Saturn: 19.97GiB → 25.71MiB read_bytes with the guard).
    /// `startsWith(x, lit) ⇒ x iLike '%lit%'`, so results are identical.
    #[test]
    fn anchored_prefix_regex_emits_text_index_guard() {
        let sql = ClickHouseSqlGenerator::new()
            .generate(
                &parse_query("message=/^powershell.*/").unwrap(),
                &time_range(),
            )
            .unwrap();
        let where_clause = where_slice(&sql);
        assert!(
            where_clause.contains(
                "lower(message) iLike '%powershell%' AND startsWith(lower(message), 'powershell')"
            ),
            "prefix regex must carry the index-servable iLike guard, got:\n{where_clause}"
        );
    }

    /// NAN-1640: same guard for the anchored-suffix (endsWith) lowering.
    #[test]
    fn anchored_suffix_regex_emits_text_index_guard() {
        let sql = ClickHouseSqlGenerator::new()
            .generate(
                &parse_query("command_line=/.*sekurlsa$/").unwrap(),
                &time_range(),
            )
            .unwrap();
        let where_clause = where_slice(&sql);
        assert!(
            where_clause.contains(
                "lower(command_line) iLike '%sekurlsa%' AND endsWith(lower(command_line), 'sekurlsa')"
            ),
            "suffix regex must carry the index-servable iLike guard, got:\n{where_clause}"
        );
    }

    /// NAN-1640: literals whose tokens all fail the NAN-1416 bar (≥6 chars,
    /// lettered) emit NO guard — short/unlettered tokens make the text-index
    /// probe cost more than it saves; the safe failure mode is the unchanged
    /// bare endsWith/startsWith shape.
    #[test]
    fn anchored_suffix_regex_below_guard_bar_stays_bare() {
        let sql = ClickHouseSqlGenerator::new()
            .generate(
                &parse_query(r"file_path=/.*\.exe$/").unwrap(),
                &time_range(),
            )
            .unwrap();
        let where_clause = where_slice(&sql);
        assert!(
            where_clause.contains("endsWith(lower(file_path), '.exe')"),
            "short-literal suffix must keep the bare endsWith, got:\n{where_clause}"
        );
        assert!(
            !where_clause.contains("iLike '%exe%'"),
            "3-char token fails the NAN-1416 bar — no guard, got:\n{where_clause}"
        );
    }

    /// NAN-1640: negation drops the guard (BloomGuard precedent) —
    /// `guard AND NOT startsWith` ≢ `NOT startsWith`; a guard ANDed under
    /// negation would silently drop non-matching rows.
    #[test]
    fn negated_anchored_prefix_regex_has_no_guard() {
        let sql = ClickHouseSqlGenerator::new()
            .generate(
                &parse_query("message!=/^powershell.*/").unwrap(),
                &time_range(),
            )
            .unwrap();
        let where_clause = where_slice(&sql);
        assert!(
            where_clause.contains("NOT startsWith(lower(message), 'powershell')"),
            "negated prefix regex must stay the bare NOT startsWith, got:\n{where_clause}"
        );
        assert!(
            !where_clause.contains("iLike '%powershell%'"),
            "negation must drop the guard, got:\n{where_clause}"
        );
    }

    /// NAN-1640: ext/JSON targets have no `lower(col)` text index to serve the
    /// guard — the anchored lowering stays bare there (skip_tostring=false).
    #[test]
    fn anchored_prefix_regex_on_ext_field_has_no_guard() {
        let sql = ClickHouseSqlGenerator::new()
            .generate(
                &parse_query("integrity_level=/^powershell.*/").unwrap(),
                &time_range(),
            )
            .unwrap();
        let where_clause = where_slice(&sql);
        assert!(
            where_clause.contains("startsWith("),
            "ext-field prefix regex must keep the startsWith lowering, got:\n{where_clause}"
        );
        assert!(
            !where_clause.contains("iLike '%powershell%'"),
            "non-text-indexed target must not emit the guard, got:\n{where_clause}"
        );
    }

    /// NAN-1640: where-pipe regex targets are toString-wrapped CTE
    /// intermediates — no index to serve a guard, deliberately bare
    /// (where-pipe form selection is finding 2.1 / Batch 1).
    #[test]
    fn where_pipe_anchored_prefix_regex_has_no_guard() {
        let sql = ClickHouseSqlGenerator::new()
            .generate(
                &parse_query("error | where message=/^powershell.*/").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            sql.contains("startsWith("),
            "where-pipe prefix regex must keep the startsWith lowering, got:\n{sql}"
        );
        assert!(
            !sql.contains("iLike '%powershell%'"),
            "where-pipe target must not emit the guard, got:\n{sql}"
        );
    }

    // ── NAN-1642: eventstats / anomaly map-scalar attach ──────────────────
    // Whole-partition window functions (`agg(x) OVER (PARTITION BY k)` /
    // `OVER ()`) buffered the entire partition and OOM'd (Code 241) at
    // production scale; per-group constants now come from a scalar Map built
    // with bounded GROUP BY memory and attached per row via a lookup on the
    // null-canonicalized key. These tests pin the emitted shapes.

    #[test]
    fn eventstats_grouped_emits_map_scalar_attach_not_window() {
        let query = parse_query("error | eventstats avg(bytes_out) as ab by user").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("mapFromArrays(groupArray(__nano_k), groupArray(__nano_v))"),
            "grouped eventstats must build a per-group scalar map, got:\n{sql}"
        );
        // Null-canonicalized key on BOTH the map-build side (GROUP BY) and
        // the per-row lookup side, so NULL BY-keys receive their group's
        // aggregate instead of the Map default (0).
        let canonical_key = "coalesce(toString(\"user\"), '\\0__null__')";
        assert!(
            sql.contains(&format!("{} AS __nano_k", canonical_key))
                && sql.contains(&format!("__nano_es[{}]", canonical_key)),
            "canonicalized key must appear on build and lookup sides, got:\n{sql}"
        );
        assert!(
            sql.contains("toFloat64(avg(bytes_out))") && sql.contains("AS ab"),
            "aggregate + user alias must be preserved, got:\n{sql}"
        );
        assert!(
            !sql.contains("OVER ("),
            "no whole-partition window may remain in eventstats SQL, got:\n{sql}"
        );
    }

    #[test]
    fn eventstats_multiple_aggs_share_one_tuple_valued_map() {
        let query = parse_query(
            "error | eventstats avg(bytes_out) as ab, stdev(bytes_out) as sb by user",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        // One map, tuple values — the stage source is scanned once for the
        // constants regardless of aggregation count.
        assert_eq!(
            sql.matches("mapFromArrays").count(),
            1,
            "multiple aggregations must share a single map, got:\n{sql}"
        );
        assert!(
            sql.contains("tuple(toFloat64(avg(bytes_out)), toFloat64(stddevPop(bytes_out)))"),
            "map value must be a tuple of all aggregates, got:\n{sql}"
        );
        assert!(
            sql.contains(".1 AS ab") && sql.contains(".2 AS sb"),
            "attach must project tuple elements under the user aliases, got:\n{sql}"
        );
    }

    #[test]
    fn eventstats_ungrouped_uses_plain_scalar_no_map() {
        let query = parse_query("error | eventstats count() as c, median(bytes_out) as m").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            !sql.contains("mapFromArrays") && !sql.contains("OVER ("),
            "no `by` clause = single global group: plain scalar, no map/window, got:\n{sql}"
        );
        assert!(
            sql.contains("WITH (SELECT tuple(toFloat64(count()), toFloat64(median(bytes_out))) FROM stage_0) AS __nano_es"),
            "global aggregates must come from one scalar tuple subquery, got:\n{sql}"
        );
        assert!(
            sql.contains("__nano_es.1 AS c") && sql.contains("__nano_es.2 AS m"),
            "scalar tuple elements must attach under the user aliases, got:\n{sql}"
        );
    }

    #[test]
    fn eventstats_multikey_by_canonicalizes_via_tuple_rendering() {
        let query = parse_query("error | eventstats count() as c by user, src_ip").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        // toString(tuple(...)) quote-delimits components (unambiguous for any
        // content, incl embedded NULs) and renders NULL elements as a bare
        // NULL token — same expression on the build and lookup sides.
        assert!(
            sql.contains("toString(tuple(\"user\", src_ip)) AS __nano_k")
                && sql.contains("__nano_es[toString(tuple(\"user\", src_ip))]"),
            "multi-key BY must canonicalize via tuple rendering on both sides, got:\n{sql}"
        );
        assert!(!sql.contains("OVER ("), "no window may remain, got:\n{sql}");
    }

    #[test]
    fn eventstats_null_key_ext_field_is_canonicalized() {
        // `by ext.*` keys are NULL for rows without the key — the sentinel
        // canonicalization must group them together (NAN-1642 acceptance:
        // NULL-key rows receive their group's aggregate, not zero).
        let query = parse_query("error | eventstats avg(bytes_out) as ab by ext.provider").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("coalesce(toString(\"ext.provider\"), '\\0__null__')"),
            "ext.* BY-key must be null-canonicalized, got:\n{sql}"
        );
    }

    #[test]
    fn eventstats_dc_keeps_exact_distinct_forms() {
        let grouped = ClickHouseSqlGenerator::new()
            .generate(
                &parse_query("error | eventstats dc(src_ip) as d by user").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            grouped.contains("toFloat64(uniqExact(src_ip))"),
            "grouped dc() must stay uniqExact, got:\n{grouped}"
        );
        let global = ClickHouseSqlGenerator::new()
            .generate(
                &parse_query("error | eventstats dc(src_ip) as d").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            global.contains("toFloat64(count(DISTINCT src_ip))"),
            "ungrouped dc() must stay count(DISTINCT), got:\n{global}"
        );
    }

    #[test]
    fn anomaly_zscore_grouped_attaches_stats_from_map_not_window() {
        let query = parse_query("error | anomaly bytes_out by user").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("mapFromArrays")
                && sql.contains("tuple(toFloat64(avg(bytes_out)), toFloat64(stddevPop(bytes_out)))"),
            "grouped z-score constants must come from a per-group map, got:\n{sql}"
        );
        assert!(
            sql.contains("__nano_stats[coalesce(toString(\"user\"), '\\0__null__')].1 as avg_val")
                && sql.contains(".2 as stddev_val"),
            "avg_val/stddev_val column names must be preserved, got:\n{sql}"
        );
        // Scoring math and output contract unchanged.
        assert!(
            sql.contains("abs(bytes_out - avg_val) / nullIf(stddev_val, 0) as anomaly_score")
                && sql.contains("WHERE is_anomaly = 1")
                && sql.contains("ORDER BY anomaly_score DESC"),
            "z-score math / filter / ordering must be unchanged, got:\n{sql}"
        );
        assert!(!sql.contains("OVER ("), "no window may remain, got:\n{sql}");
    }

    #[test]
    fn anomaly_zscore_ungrouped_uses_scalar_tuple() {
        let query = parse_query("error | anomaly bytes_out").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains(
                "WITH (SELECT tuple(toFloat64(avg(bytes_out)), toFloat64(stddevPop(bytes_out))) FROM stage_0) AS __nano_stats"
            ) && sql.contains("__nano_stats.1 as avg_val"),
            "ungrouped z-score must use a plain scalar tuple, got:\n{sql}"
        );
        assert!(
            !sql.contains("mapFromArrays") && !sql.contains("OVER ("),
            "no map and no window for the global group, got:\n{sql}"
        );
    }

    #[test]
    fn anomaly_mad_grouped_builds_median_then_mad_maps() {
        let query = parse_query("error | anomaly bytes_out by user method=mad").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        // Two bounded GROUP BY passes: median map, then MAD map referencing it.
        assert!(
            sql.contains("toFloat64(quantile(0.5)(bytes_out)) AS __nano_v"),
            "median map must aggregate quantile(0.5) per group, got:\n{sql}"
        );
        assert!(
            sql.contains("quantile(0.5)(abs(bytes_out - __nano_med[__nano_k]))"),
            "MAD map must reference the median map per group, got:\n{sql}"
        );
        assert!(
            sql.contains("as median_val") && sql.contains("as mad_val")
                && sql.contains("abs(bytes_out - median_val) / nullIf(mad_val * 1.4826, 0) as anomaly_score"),
            "median_val/mad_val names and MAD math must be unchanged, got:\n{sql}"
        );
        assert!(!sql.contains("OVER ("), "no window may remain, got:\n{sql}");
    }

    #[test]
    fn anomaly_categorical_keeps_pair_dedup_but_stats_from_pair_counts() {
        let query = parse_query("error | anomaly process_name by user").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        // The fine-grained (by, field) pair windows for _anomaly_count / _rn
        // dedup are retained — they are not the OOM-class coarse partition.
        assert!(
            sql.contains("count() OVER (PARTITION BY \"user\", process_name) as _anomaly_count")
                && sql.contains("row_number() OVER (PARTITION BY \"user\", process_name"),
            "pair-count window + dedup must be preserved, got:\n{sql}"
        );
        // The coarse per-BY-group stats windows are replaced by a bounded
        // pair-count GROUP BY feeding the map.
        assert!(
            !sql.contains("avg(_anomaly_count) OVER") && !sql.contains("stddevPop(_anomaly_count) OVER"),
            "whole-BY-partition stats windows must be gone, got:\n{sql}"
        );
        assert!(
            sql.contains("count() AS __nano_cnt")
                && sql.contains("tuple(toFloat64(avg(__nano_cnt)), toFloat64(stddevPop(__nano_cnt)))"),
            "stats must aggregate the pair counts via GROUP BY, got:\n{sql}"
        );
    }

    #[test]
    fn anomaly_aggregation_first_uses_scalar_tuple_over_agg_source() {
        let query = parse_query("error | anomaly count() by user").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("tuple(toFloat64(avg(_agg_value)), toFloat64(stddevPop(_agg_value)))"),
            "aggregation-first stats must come from a scalar tuple over the grouped source, got:\n{sql}"
        );
        assert!(
            !sql.contains("OVER ()"),
            "whole-set windows must be gone from the aggregation-first path, got:\n{sql}"
        );
        // This path scores every group — no is_anomaly filter, ordering kept.
        assert!(
            !sql.contains("WHERE is_anomaly = 1") && sql.contains("ORDER BY anomaly_score DESC"),
            "aggregation-first path must keep score-all semantics, got:\n{sql}"
        );
    }
