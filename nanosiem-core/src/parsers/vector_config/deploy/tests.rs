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
    assert!(
        !blocks.is_empty(),
        "expected ≥1 VRL block in pipeline config"
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
        "pipeline VRL failed to compile:\n{}",
        failures.join("\n----\n")
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

/// NAN-2361: a shared internal writer without forwarding metadata used to put
/// every event in one hard-coded 5k-EPS `unknown` throttle bucket. Keep the
/// finite client fence configurable, and retain a separately configurable
/// aggregate fallback when the key is unavailable.
#[test]
fn base_config_rate_limit_does_not_create_a_global_unknown_bucket() {
    let base = include_str!("../../../../../config/vector/00-base.toml");
    assert!(
        base.contains("threshold = ${VECTOR_RATE_LIMIT_PER_CLIENT_EPS:-500000}"),
        "the identified-client ingest fence must remain capacity-configurable"
    );
    assert!(
        base.contains("inputs = [\"rate_limit_route.identified\"]")
            && base.contains("threshold = ${VECTOR_RATE_LIMIT_UNIDENTIFIED_EPS:-500000}")
            && base.contains("inputs = [\"rate_limit\", \"rate_limit_unidentified\"]",),
        "unidentified shared ingest must retain a separately sized finite fence"
    );
    assert!(
        !base.contains("threshold = 5000"),
        "the retired global 5k-EPS choke point must not return"
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

/// NAN-2361: the generic Base Event row must carry `class_uid = 0`, keep
/// source-native data under `unmapped`, and never copy vendor fields into
/// the canonical root.
#[test]
fn generic_ocsf_prepare_emits_base_event() {
    let block = VectorConfigManager::GENERIC_OCSF_PREPARE_BLOCK;
    assert!(block.contains("\"class_uid\": 0"), "must set class_uid = 0");
    assert!(
        block.contains("unmapped = { \"raw_event\": raw_json"),
        "must preserve the raw record below canonical unmapped"
    );
    assert!(
        block.contains("unmapped.trace_id = otlp_trace_id")
            && block.contains("unmapped.span_id = otlp_span_id"),
        "generic OTLP logs must preserve queryable trace correlation"
    );
    assert!(
        !block.contains("ocsf_event = ."),
        "must not leak source-native fields"
    );
    assert!(
        block.contains("inputs = [\"generic_parser\"]"),
        "must fork off the generic_parser fall-through"
    );
}

#[test]
fn lake_pipeline_has_one_durable_terminal_and_keeps_parser_failures() {
    let lake = VectorConfigManager::pipeline_config_content_for(true, true);
    assert!(!lake.contains("[sinks.clickhouse_logs]"), "{lake}");
    assert!(!lake.contains("[sinks.clickhouse_parser_health]"), "{lake}");
    assert!(
        lake.contains("inputs = [\"generic_parser\", \"db_parsers_combined\"]"),
        "parser failures must become canonical Base Events in lake mode: {lake}"
    );
    assert!(lake.contains("[transforms.generic_ocsf_prepare]"), "{lake}");

    let legacy = VectorConfigManager::pipeline_config_content_for(true, false);
    assert!(legacy.contains("[sinks.clickhouse_logs]"), "{legacy}");
    assert!(
        legacy.contains("[sinks.clickhouse_parser_health]"),
        "{legacy}"
    );
    assert!(
        legacy.contains("inputs = [\"generic_parser\"]"),
        "legacy OCSF keeps its existing parser-failure route: {legacy}"
    );
}

#[test]
fn generic_ocsf_prepare_executes_to_a_strict_ocsf_1_9_event() {
    use vrl::compiler::runtime::Runtime;
    use vrl::compiler::state::RuntimeState;
    use vrl::compiler::{compile, TargetValue, TimeZone};
    use vrl::value::{Secrets, Value};

    let blocks = extract_vrl_blocks(VectorConfigManager::GENERIC_OCSF_PREPARE_BLOCK);
    let program = compile(blocks[0], &vrl::stdlib::all())
        .expect("generic OCSF prepare compiles")
        .program;
    let input = serde_json::json!({
        "created_at": "2026-08-12T01:15:37.282Z",
        "actor": {"login": "source-user"},
        "message": "source event",
        "metadata": {
            "original_source_type": "GitHub_Public_Events",
            "parser_type": "generic"
        },
        "source_type": "github_public_events",
        "trace_id": "AABBCCDDEEFF00112233445566778899",
        "span_id": "AABBCCDDEEFF0011"
    });
    let mut target = TargetValue {
        value: Value::from(input),
        metadata: Value::Object(Default::default()),
        secrets: Secrets::new(),
    };
    Runtime::new(RuntimeState::default())
        .resolve(&mut target, &program, &TimeZone::Local)
        .expect("generic OCSF prepare executes");
    let output: serde_json::Value = target.value.try_into().expect("VRL output is JSON");
    let mut event = output["event"].clone();
    let metadata = event["metadata"]
        .as_object_mut()
        .expect("canonical metadata object");
    metadata.insert(
        "log_source".to_string(),
        serde_json::json!("github_public_events"),
    );
    metadata.insert("tenant_uid".to_string(), serde_json::json!("tenant-a"));
    metadata.insert("uid".to_string(), serde_json::json!("generic-1"));

    let validation = crate::parsers::validate_ocsf_event(&event);
    assert!(validation.valid, "{:?}", validation.errors);
    assert!(
        event.get("actor").is_none(),
        "source actor must not leak into root"
    );
    let raw: serde_json::Value = serde_json::from_str(
        event["unmapped"]["raw_event"]
            .as_str()
            .expect("encoded source record"),
    )
    .expect("source record remains lossless JSON");
    assert_eq!(raw["actor"]["login"], "source-user");
    assert_eq!(
        event["unmapped"]["trace_id"],
        "aabbccddeeff00112233445566778899"
    );
    assert_eq!(event["unmapped"]["span_id"], "aabbccddeeff0011");
    assert_eq!(event["time"], 1_786_497_337_282_i64);
    assert_eq!(event["severity"], "Unknown");
    assert_eq!(event["severity_id"], 0);
    assert_eq!(output["source_type"], "github_public_events");
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

    // OCSF: enabled log parsers' forks + generic; disabled + enrichment excluded.
    let inputs = VectorConfigManager::ocsf_sink_inputs_for(true, &parsers);
    assert_eq!(
        inputs,
        vec![
            "\"apache_ocsf_prepare\"".to_string(),
            "\"sysmon_json_ocsf_prepare\"".to_string(),
            "\"generic_ocsf_prepare\"".to_string(),
        ],
        "OCSF sink must fork every enabled log parser + the generic lane, \
             excluding disabled and enrichment parsers"
    );

    // The rendered sink wires exactly those inputs into the ocsf_logs sink.
    let content = VectorConfigManager::clickhouse_ocsf_sink_content(&inputs);
    assert!(
        content.contains("[sinks.clickhouse_ocsf_logs]"),
        "{content}"
    );
    assert!(
            content.contains(
                "inputs = [\"apache_ocsf_prepare\", \"sysmon_json_ocsf_prepare\", \"generic_ocsf_prepare\"]"
            ),
            "{content}"
        );
}

#[test]
fn lake_ocsf_sink_writes_only_canonical_parquet_roots() {
    use vrl::compiler::compile;

    let inputs = vec![
        "\"apache_ocsf_prepare\"".to_string(),
        "\"generic_ocsf_prepare\"".to_string(),
    ];
    let content = VectorConfigManager::lake_ocsf_sink_content(&inputs, true);
    assert!(content.contains("[sinks.ocsf_parquet_bronze]"), "{content}");
    assert!(content.contains("codec = \"parquet\""), "{content}");
    assert!(content.contains("algorithm = \"zstd\""), "{content}");
    assert!(
        content.contains("level = ${VECTOR_LAKE_BRONZE_ZSTD_LEVEL:-6}"),
        "transient Bronze compression must remain an explicit deployer capacity setting: {content}"
    );
    assert!(
        content.contains("timeout_secs = ${VECTOR_LAKE_BATCH_TIMEOUT_SECS:-1}"),
        "low-rate lake events must not inherit a minute-long visibility floor: {content}"
    );
    assert!(
        content.contains("max_events = ${VECTOR_LAKE_BATCH_MAX_EVENTS:-10000}"),
        "Vector's batch bound must preserve the durable-ACK latency default: {content}"
    );
    // NAN-3523: the sink buffer is bounded by bytes (events may be 4 MiB
    // each), stays in memory so the source ACK follows the PUT, and blocks.
    let buffer = content
        .split("[sinks.ocsf_parquet_bronze.buffer]\n")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .expect("bronze sink buffer section");
    assert!(buffer.contains("type = \"memory\"\n"), "{buffer}");
    assert!(
        buffer.contains("max_size = ${VECTOR_LAKE_BUFFER_MAX_BYTES:-67108864}\n"),
        "{buffer}"
    );
    assert!(
        !buffer.contains("max_events"),
        "max_size and max_events are exclusive: {buffer}"
    );
    assert!(buffer.contains("when_full = \"block\"\n"), "{buffer}");
    assert!(
        content.contains(crate::parsers::tenant_bundle::bronze_buffer_bytes::BRONZE_BUFFER_BYTES),
        "the generator and the zero-nan3523 base upgrade carry the same section: {buffer}"
    );
    assert!(content.contains("NANO_LAKE_ACCESS_KEY_ID"), "{content}");
    assert!(
        content.contains("metadata.version = \"1.9.0\""),
        "{content}"
    );
    assert!(
        content.contains(
            "key_prefix = \"bronze-v2/{{ _nano_bronze_partition }}tenant_id={{ %tenant_id }}/\""
        ),
        "bronze handoff may fan out only by its bounded deterministic publisher partition: {content}"
    );
    assert!(
        content.contains("bronze_shards = ${NANO_LAKE_BRONZE_SHARDS:-1}")
            && content.contains("if bronze_shards < 1 || bronze_shards > 128 { abort }")
            && content.contains("._nano_bronze_partition = if bronze_shards > 1 {")
            && content.contains("bronze_shard = mod!(bronze_hash_value, bronze_shards)")
            && content.contains("except_fields = [\"_nano_bronze_partition\"]")
            && !content.contains("%bronze_partition"),
        "the generated sink must route on an event helper stripped before Parquet encoding: {content}"
    );
    assert!(
        !content.contains("key_prefix = \"bronze/tenant_id="),
        "legacy high-cardinality bronze layout must stay retired: {content}"
    );
    assert!(content.contains(".raw_data = raw_data"), "{content}");
    assert!(
        content.contains(".raw_data_size = length(raw_data)"),
        "{content}"
    );
    assert!(content.contains(
        "if tenant_id == \"\" { tenant_id = downcase(get_env_var(\"NANO_TENANT_ID\") ?? \"\") }"
    ));
    assert!(content.contains("event = .event\n"), "{content}");
    assert!(content.contains("del(._nano_parser_id)"), "{content}");
    assert!(
        !content.contains("[sinks.clickhouse_ocsf_logs]"),
        "{content}"
    );

    let workload_role = VectorConfigManager::lake_ocsf_sink_content(&inputs, false);
    assert!(
        workload_role.contains("Authentication is supplied by the pod/instance workload role"),
        "{workload_role}"
    );
    assert!(
        !workload_role.contains("auth.access_key_id"),
        "{workload_role}"
    );

    let blocks = extract_vrl_blocks(&content);
    assert_eq!(blocks.len(), 1, "{content}");
    let compile_source = blocks[0].replace("${NANO_LAKE_BRONZE_SHARDS:-1}", "1");
    if let Err(diagnostics) = compile(&compile_source, &vrl::stdlib::all()) {
        panic!("lake OCSF storage preparation VRL failed: {diagnostics:?}");
    }
}

/// NAN-3492: the bronze sink acks end to end, so `/ingest` answers a POST
/// only after its batch's PUT. The compose files pinned the batch timeout at
/// 5 s after the generated sink moved to 1 s (NAN-2432), which held one
/// sequential sender to one bronze object (one POST) per 5 s on every
/// self-hosted lean install. Their default must match the generated sink.
#[test]
fn compose_vector_lake_batch_timeout_matches_generated_sink_default() {
    let sink = VectorConfigManager::lake_ocsf_sink_content(&["\"x\"".to_string()], true);
    assert!(
        sink.contains("timeout_secs = ${VECTOR_LAKE_BATCH_TIMEOUT_SECS:-1}"),
        "{sink}"
    );
    // Read at runtime, not include_str!: the public open-core export ships only
    // docker-compose.opensource.yml, and a compile-time include of the private
    // root compose would break the mirror's build. The open compose is required.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut composes = Vec::new();
    for (name, required) in [
        ("docker-compose.opensource.yml", true),
        ("docker-compose.yml", false),
    ] {
        match std::fs::read_to_string(root.join(name)) {
            Ok(text) => composes.push((name, text)),
            Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("read {name}: {error}"),
        }
    }
    for (name, compose) in &composes {
        let pins = compose
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("VECTOR_LAKE_BATCH_TIMEOUT_SECS:"))
            .collect::<Vec<_>>();
        assert!(
            !pins.is_empty(),
            "{name} no longer sets VECTOR_LAKE_BATCH_TIMEOUT_SECS"
        );
        for pin in pins {
            assert_eq!(
                pin, "VECTOR_LAKE_BATCH_TIMEOUT_SECS: ${VECTOR_LAKE_BATCH_TIMEOUT_SECS:-1}",
                "{name}: a longer bronze batch timeout delays every acked /ingest POST"
            );
        }
    }
}

/// The partition helper is consumed by Vector's S3 key template and stripped
/// by the sink encoder before Parquet serialization. Execute the generated
/// transform because compile-only checks cannot prove template visibility.
#[test]
fn lake_ocsf_sink_executes_shard_partition_into_stripped_event_helper() {
    use vrl::compiler::runtime::Runtime;
    use vrl::compiler::state::RuntimeState;
    use vrl::compiler::{compile, TargetValue, TimeZone};
    use vrl::value::{ObjectMap, Secrets, Value};

    let content = VectorConfigManager::lake_ocsf_sink_content(
        &["\"generic_ocsf_prepare\"".to_string()],
        true,
    );
    let block = extract_vrl_blocks(&content)
        .into_iter()
        .next()
        .expect("lake OCSF storage preparation block");
    let shard_expression = "${NANO_LAKE_BRONZE_SHARDS:-1}";

    let resolve_partition = |shards: i64| {
        let program_source = block.replace(shard_expression, &shards.to_string());
        let program = compile(&program_source, &vrl::stdlib::all())
            .expect("lake OCSF storage preparation compiles")
            .program;
        let input = serde_json::json!({
            "source_type": "windows_sysmon",
            "event": {
                "class_uid": 1007,
                "metadata": {"uid": "nan2361-shard-contract"}
            }
        });
        let mut metadata = ObjectMap::new();
        metadata.insert("tenant_id".into(), Value::from("tenant-a"));
        let mut target = TargetValue {
            value: Value::from(input),
            metadata: Value::Object(metadata),
            secrets: Secrets::new(),
        };
        Runtime::new(RuntimeState::default())
            .resolve(&mut target, &program, &TimeZone::Local)
            .expect("lake OCSF storage preparation executes");
        target
            .value
            .get(vrl::path!("_nano_bronze_partition"))
            .and_then(|value| value.as_str().map(|partition| partition.into_owned()))
            .expect("Bronze partition event helper")
    };

    assert_eq!(resolve_partition(4), "shard=0/");
    assert_eq!(resolve_partition(1), "");
    assert!(
        block.ends_with(crate::parsers::lake_bronze_row::LAKE_BRONZE_ROW_VRL),
        "NAN-3339: the storage stage ends with the fixed bronze row contract: {block}"
    );

    assert!(
        compile(
            &block.replace(shard_expression, "not-a-count"),
            &vrl::stdlib::all()
        )
        .is_err(),
        "an invalid explicit shard count must fail Vector config compilation"
    );
}

#[test]
fn parser_health_combiner_bypasses_sampling_and_covers_ocsf_successes() {
    let mut sampled = log_test_parser("limacharlie", true);
    sampled.sampling_ratio = Some(0.1);
    let disabled = log_test_parser("disabled_src", false);

    let udm = VectorConfigManager::combiner_config_content_for(
        &[sampled.clone(), disabled.clone()],
        false,
    );
    assert!(
        udm.contains("inputs = [\"limacharlie_sample\"]"),
        "persisted UDM stream must retain configured sampling: {udm}"
    );
    assert!(
        udm.contains("[transforms.db_parser_health]")
            && udm.contains("inputs = [\"limacharlie_output\"]"),
        "health must observe the unsampled output and exclude disabled parsers: {udm}"
    );
    assert!(!udm.contains("disabled_src_output"), "{udm}");

    let ocsf = VectorConfigManager::combiner_config_content_for(&[sampled, disabled], true);
    assert!(
        ocsf.contains("inputs = [\"limacharlie_output\", \"limacharlie_ocsf_prepare\"]"),
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
            && pipeline
                .contains("table = \"${CLICKHOUSE_PARSER_HEALTH_TABLE:-parser_health_ingest}\""),
        "the pre-sampling health branch must terminate in the Null-engine ingress: {pipeline}"
    );
}

/// NAN-1149: the dynamically-generated enrichment lane must produce a valid,
/// backpressure-safe topology — the normalize VRL compiles, the per-table
/// sink uses `drop_newest` + acks off (never `block`; NAN-1114), and the
/// dead-letter unions the normalize `.dropped` outputs.
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
        lane.contains("[sinks.clickhouse_user_registry]")
            && lane.contains("table = \"user_registry\""),
        "missing per-target_table sink"
    );
    assert!(
        lane.contains("when_full = \"drop_newest\""),
        "enrichment sink must be non-blocking (NAN-1114)"
    );
    assert!(
        lane.contains("enabled = false"),
        "enrichment sink acknowledgements must be off (NAN-1114)"
    );
    assert!(
        lane.contains("enrichment_normalize_identity.dropped"),
        "dead-letter must union the normalize .dropped output"
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

#[test]
fn lake_enrichment_lane_is_durable_coordinator_backed_and_clickhouse_free() {
    let lane = VectorConfigManager::enrichment_lane_config_for_backend(&[], true);
    let parsed: toml::Table = toml::from_str(&lane).expect("lake enrichment TOML must parse");
    assert!(parsed["sinks"].get("lake_identity_directory").is_some());
    assert!(parsed["sinks"].get("lake_ip_context").is_some());
    assert!(!lane.contains("type = \"clickhouse\""));
    assert!(lane.contains("type = \"disk\""));
    assert!(lane.contains("when_full = \"block\""));
    assert!(lane.contains("acknowledgements.enabled = true"));
    assert!(
        super::enrichment_lane_backpressure_violations(&lane).is_empty(),
        "dedicated :8090 enrichment source must not backpressure shared logs"
    );
}

/// NAN-1151: two sources of the SAME kind (ad + entra, both identity) each
/// get their own per-source normalize transform — the unlock route-by-kind
/// couldn't express — yet share the one `user_registry` sink (keyed by
/// target_table). Proves the per-source generator + the `enrichment_router`
/// input names line up.
#[test]
fn generate_enrichment_lane_is_per_source_not_per_kind() {
    let mut ad = enrichment_test_parser(
        "identity",
        "user_registry",
        ". = { \"external_id\": to_string(.id) ?? \"\" }",
    );
    ad.enrich_source = Some("ad".to_string());
    ad.name = "ad_identity".to_string();
    let mut entra = enrichment_test_parser(
        "identity",
        "user_registry",
        ". = { \"external_id\": to_string(.id) ?? \"\" }",
    );
    entra.enrich_source = Some("entra".to_string());
    entra.name = "entra_identity".to_string();

    let lane = VectorConfigManager::generate_enrichment_lane(&[&ad, &entra]);

    // One normalize transform per source, each consuming its own route.
    assert!(
        lane.contains("[transforms.enrichment_normalize_ad]"),
        "missing ad normalize:\n{lane}"
    );
    assert!(lane.contains("inputs = [\"enrichment_router.ad\"]"));
    assert!(
        lane.contains("[transforms.enrichment_normalize_entra]"),
        "missing entra normalize"
    );
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
    // Per-source routes key by `.source` only; the one `.kind` condition is
    // the NAN-3483 unrouted-identity catch-all.
    for line in per_source.lines().filter(|l| l.contains(" = '")) {
        if line.starts_with("unrouted_identity = ") || line.starts_with("identity_directory = ") {
            continue;
        }
        assert!(
            !line.contains("downcase(to_string(.kind)"),
            "per-source route must not key by .kind: {line}"
        );
    }

    let fallback = enrichment_router_block(&[], "\"auth_check\"");
    // NAN-3483: the legacy `identity` route (the AD normalizer) only takes AD
    // or untagged records now; other identity sources have their own routes.
    assert!(
            fallback.contains("identity = 'downcase(to_string(.source_type) ?? \"\") == \"nano_enrich\" && downcase(to_string(.kind) ?? \"\") == \"identity\" && includes([\"ad\", \"\"], downcase(to_string(.source) ?? \"\"))'"),
            "empty parser list must fall back to legacy per-kind routes:\n{fallback}"
        );
    assert!(
        fallback.contains("ip_context = 'downcase(to_string(.source_type) ?? \"\") == \"nano_enrich\" && downcase(to_string(.kind) ?? \"\") == \"ip_context\"'"),
        "{fallback}"
    );
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

    // Empty → the committed static lane plus the built-in identity
    // normalizers (NAN-3483).
    let fallback = VectorConfigManager::enrichment_lane_config(&[]);
    assert_eq!(fallback, VectorConfigManager::static_enrichment_lane(false));
    assert!(fallback.starts_with(
        &VectorConfigManager::enrichment_lane_content()
            [..VectorConfigManager::enrichment_lane_content()
                .find("[sinks.clickhouse_ip_enrichments]")
                .unwrap()]
    ));
    // Disabled-only → also static (no enabled parsers to generate from).
    let mut disabled = parser;
    disabled.enabled = false;
    assert_eq!(VectorConfigManager::enrichment_lane_config(&[disabled]), fallback);
}

// =============================================================================
// NAN-3483: every identity provider has a normalizer by default
// =============================================================================

/// Route keys of the `[transforms.enrichment_router.route]` table.
fn nan3483_route_keys(router: &str) -> std::collections::BTreeSet<String> {
    let doc: toml::Table = toml::from_str(router).expect("router block must parse");
    doc["transforms"]["enrichment_router"]["route"]
        .as_table()
        .expect("route table")
        .keys()
        .cloned()
        .collect()
}

/// `enrichment_router.<route>` inputs the lane's transforms consume.
fn nan3483_consumed_routes(lane: &str) -> std::collections::BTreeSet<String> {
    let doc: toml::Table = toml::from_str(lane).expect("lane must parse");
    let mut out = std::collections::BTreeSet::new();
    for (_, t) in doc["transforms"].as_table().expect("transforms") {
        for input in t["inputs"].as_array().expect("inputs") {
            if let Some(route) = input.as_str().unwrap().strip_prefix("enrichment_router.") {
                out.insert(route.to_string());
            }
        }
    }
    out
}

/// Every component a sink or transform names as an input exists in the lane
/// (or is a router route), so Vector loads it.
fn nan3483_assert_inputs_resolve(lane: &str, routes: &std::collections::BTreeSet<String>) {
    let doc: toml::Table = toml::from_str(lane).expect("lane must parse");
    let transforms: std::collections::BTreeSet<String> =
        doc["transforms"].as_table().unwrap().keys().cloned().collect();
    for (kind, table) in [("transforms", &doc["transforms"]), ("sinks", &doc["sinks"])] {
        for (name, def) in table.as_table().unwrap() {
            for input in def["inputs"].as_array().unwrap() {
                let input = input.as_str().unwrap();
                let ok = match input.strip_prefix("enrichment_router.") {
                    Some(route) => routes.contains(route),
                    None => transforms.contains(input.strip_suffix(".dropped").unwrap_or(input)),
                };
                assert!(ok, "{kind}.{name} input {input:?} does not resolve:\n{lane}");
            }
        }
    }
}

fn nan3483_assert_vrl_compiles(lane: &str) {
    let fns = vrl::stdlib::all();
    for (idx, block) in extract_vrl_blocks(lane).iter().enumerate() {
        if let Err(diags) = vrl::compiler::compile(block, &fns) {
            panic!(
                "lane VRL block #{idx} failed to compile:\n{}",
                vrl::diagnostic::Formatter::new(block, diags)
            );
        }
    }
}

/// The CT106 failure: no enrichment parser imported, so the static lane sent
/// Okta records to the AD normalizer. The static lane (both backends) now
/// carries a normalizer per provider source, each on its own router route,
/// all feeding the directory sink, plus the unrouted dead-letter.
#[test]
fn nan3483_static_lane_has_a_normalizer_per_identity_source() {
    let router = crate::parsers::vector_config::router::enrichment_router_block(&[], "\"x\"");
    let routes = nan3483_route_keys(&router);
    for lake in [false, true] {
        let lane = VectorConfigManager::enrichment_lane_config_for_backend(&[], lake);
        let consumed = nan3483_consumed_routes(&lane);
        for source in ["okta", "entra", "google", "workday"] {
            assert!(
                lane.contains(&format!("[transforms.enrichment_normalize_{source}]")),
                "lake={lake}: no {source} normalizer:\n{lane}"
            );
            assert!(consumed.contains(source), "lake={lake}: {source} route not consumed");
            assert!(routes.contains(source), "router has no {source} route:\n{router}");
        }
        // AD keeps the legacy transform on the legacy `identity` route.
        assert!(lane.contains("[transforms.enrichment_normalize_ad]"));
        assert!(consumed.contains("identity"));
        assert!(consumed.contains("unrouted_identity"));
        assert!(routes.contains("unrouted_identity"));
        nan3483_assert_inputs_resolve(&lane, &routes);
        nan3483_assert_vrl_compiles(&lane);

        let doc: toml::Table = toml::from_str(&lane).unwrap();
        let sink = if lake { "lake_identity_directory" } else { "clickhouse_user_registry" };
        // NAN-3767: on the lake the normalizers feed the coordinator-lines
        // transform, which (with the runner's envelope) feeds the sink.
        let fed = if lake {
            let sink_inputs: Vec<&str> = doc["sinks"][sink]["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            assert_eq!(sink_inputs, ["enrichment_identity_envelope", "enrichment_identity_lines"]);
            assert_eq!(
                doc["sinks"][sink]["uri"].as_str().unwrap(),
                "${NANO_LAKE_ENRICHMENT_COORDINATOR_URL:-http://127.0.0.1:9}/v1/identity/directory/ingest"
            );
            assert_eq!(doc["sinks"][sink]["buffer"]["type"].as_str(), Some("memory"));
            &doc["transforms"]["enrichment_identity_lines"]
        } else {
            &doc["sinks"][sink]
        };
        let inputs: Vec<&str> = fed["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for t in [
            "enrichment_normalize_ad",
            "enrichment_normalize_entra",
            "enrichment_normalize_google",
            "enrichment_normalize_okta",
            "enrichment_normalize_workday",
        ] {
            assert!(inputs.contains(&t), "lake={lake}: {sink} misses {t}: {inputs:?}");
        }
        assert!(
            !inputs.contains(&"enrichment_normalize_unrouted_identity"),
            "the unrouted transform must never reach the directory"
        );
        let dead: Vec<&str> = doc["transforms"]["enrichment_dead_letter_report"]["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for t in ["enrichment_normalize_okta.dropped", "enrichment_normalize_unrouted_identity.dropped"] {
            assert!(dead.contains(&t), "lake={lake}: dead-letter misses {t}: {dead:?}");
        }
        // Dead letters are reported on the collector-error channel, not a
        // blackhole.
        assert!(!lane.contains("type = \"blackhole\""), "lake={lake}: dead letters went to a blackhole");
        let dl = &doc["sinks"]["enrichment_dead_letter"];
        assert_eq!(dl["inputs"].as_array().unwrap()[0].as_str(), Some("enrichment_dead_letter_report"));
        if lake {
            assert!(!lane.contains("type = \"clickhouse\""), "lake lane must stay ClickHouse-free");
            assert_eq!(dl["type"].as_str(), Some("http"));
            assert!(dl["uri"].as_str().unwrap().ends_with("}/v1/collector-errors/batch"));
        } else {
            assert_eq!(dl["type"].as_str(), Some("clickhouse"));
        }
        assert!(
            super::enrichment_lane_backpressure_violations(&lane).is_empty(),
            "lake={lake}: the dead-letter report must not backpressure ingest"
        );
    }
}

/// The committed static AD transform is the parsers-repo `ad_identity` body;
/// the built-in AD normalizer must stay the same VRL.
#[test]
fn nan3483_static_ad_transform_matches_builtin_ad() {
    let lane = VectorConfigManager::enrichment_lane_content();
    let start = lane.find("[transforms.enrichment_normalize_ad]").unwrap();
    let ad = extract_vrl_blocks(&lane[start..])[0];
    let builtin = crate::identity::normalizers::builtin_identity_normalizer("ad").unwrap();
    assert_eq!(ad.trim(), builtin.normalize_vrl.trim());
}

/// Generated lane with only AD imported: Okta (and the rest) still get their
/// built-in normalizer, and the router emits a route for each.
#[test]
fn nan3483_generated_lane_adds_builtins_for_uncovered_sources() {
    let mut ad = enrichment_test_parser("identity", "user_registry", crate::identity::normalizers::builtin_identity_normalizer("ad").unwrap().normalize_vrl);
    ad.enrich_source = Some("ad".to_string());
    ad.name = "ad_identity".to_string();
    let lane = VectorConfigManager::enrichment_lane_config(&[ad.clone()]);
    let router = crate::parsers::vector_config::router::enrichment_router_block(&[&ad], "\"x\"");
    let routes = nan3483_route_keys(&router);
    for source in ["ad", "okta", "entra", "google", "workday", "unrouted_identity"] {
        assert!(routes.contains(source), "router misses {source}:\n{router}");
    }
    assert_eq!(lane.matches("[transforms.enrichment_normalize_ad]").count(), 1);
    assert!(lane.contains("[transforms.enrichment_normalize_okta]"));
    nan3483_assert_inputs_resolve(&lane, &routes);
    nan3483_assert_vrl_compiles(&lane);
    super::assert_enrichment_lane_topology(&lane).expect("generated lane topology");
}

/// An imported, enabled okta parser overrides the built-in one: exactly one
/// okta transform, carrying the imported VRL.
#[test]
fn nan3483_imported_parser_overrides_the_builtin() {
    let marker = "# imported okta override";
    let vrl = format!(
        "{marker}\n{}",
        crate::identity::normalizers::builtin_identity_normalizer("okta").unwrap().normalize_vrl
    );
    let mut okta = enrichment_test_parser("identity", "user_registry", &vrl);
    okta.enrich_source = Some("okta".to_string());
    okta.name = "okta_identity".to_string();
    let lane = VectorConfigManager::enrichment_lane_config(&[okta]);
    assert_eq!(lane.matches("[transforms.enrichment_normalize_okta]").count(), 1);
    assert!(lane.contains(marker), "imported VRL must win:\n{lane}");
}

/// Identity records whose source has no normalizer go to the unrouted
/// transform, which logs the source and aborts (dead-letters).
#[test]
fn nan3483_unrouted_identity_dead_letters_with_the_source() {
    let router = crate::parsers::vector_config::router::enrichment_router_block(&[], "\"x\"");
    assert!(
        router.contains("unrouted_identity = 'downcase(to_string(.source_type) ?? \"\") == \"nano_enrich\" && downcase(to_string(.kind) ?? \"\") == \"identity\" && !includes([\"\", \"ad\", \"entra\", \"google\", \"okta\", \"workday\"], downcase(to_string(.source) ?? \"\"))'"),
        "{router}"
    );
    let lane = VectorConfigManager::static_enrichment_lane(true);
    let start = lane.find("[transforms.enrichment_normalize_unrouted_identity]").unwrap();
    let vrl = extract_vrl_blocks(&lane[start..])[0];
    let program = crate::parsers::CompiledNormalizer::compile(vrl).unwrap();
    let err = program
        .run(&serde_json::json!({"kind": "identity", "source": "onelogin", "id": "x"}))
        .unwrap_err();
    assert!(err.contains("no normalizer for source 'onelogin'"), "{err}");
}

/// The router and the lane pick the generated/static branch on the same test,
/// so an enabled parser without an `enrich_source` still yields a lane whose
/// every router input resolves.
#[test]
fn nan3483_sourceless_enabled_parser_keeps_router_and_lane_aligned() {
    let mut p = enrichment_test_parser("identity", "user_registry", ". = {}");
    p.enrich_source = None;
    let lane = VectorConfigManager::enrichment_lane_config(&[p.clone()]);
    let router = crate::parsers::vector_config::router::enrichment_router_block(&[&p], "\"x\"");
    nan3483_assert_inputs_resolve(&lane, &nan3483_route_keys(&router));
}

#[test]
fn nan3483_reserved_enrich_source_is_rejected() {
    let mut p = enrichment_test_parser(
        "identity",
        "user_registry",
        crate::identity::normalizers::builtin_identity_normalizer("okta").unwrap().normalize_vrl,
    );
    p.enrich_source = Some("unrouted_identity".to_string());
    let lane = VectorConfigManager::enrichment_lane_config(&[p.clone()]);
    let err = VectorConfigManager::guard_enrichment_lane(&[p], &lane).unwrap_err();
    assert!(err.to_string().contains("reserved"), "{err}");
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
    assert_eq!(
        blocks.len(),
        1,
        "expected exactly one VRL block in 02-hec-source.toml"
    );
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

/// NAN-1128 / NAN-1114: the push enrichment lane shares the `http_ingest`
/// / `vector_native` / `splunk_hec_ingest` upstream with the logs lane
/// under the one-key model. A sink that *blocks* when its ClickHouse target
/// stalls (`buffer.when_full = "block"`), or that waits on end-to-end
/// `acknowledgements.enabled = true`, would backpressure that shared source
/// and take *log* ingestion down with it — the same silent-halt class as
/// the dict-FAILED outage in NAN-1120. So every sink whose input chain can
/// reach a shared ingest source MUST stay non-blocking (`drop_newest` /
/// `drop_oldest`) with sink acks off. Only a source with its own
/// backpressure domain — the future dedicated enrichment lane (`:8090`,
/// not yet present) — may back a blocking/acking sink; add it to
/// `DEDICATED_ENRICHMENT_SOURCES` when it ships.
///
/// The lint parses the *shipped* topology — the binary-embedded pipeline
/// (`pipeline_config_content`) and enrichment lane (`enrichment_lane_content`)
/// plus the static base sources and the bootstrap router/combiner — so a
/// regression is caught at `cargo test` time, never on a live Vector reload.
#[test]
fn shared_ingest_source_sinks_must_not_backpressure() {
    // The committed static enrichment lane must be backpressure-safe in the
    // shipped topology. Logic lives in the shared guard so the same check
    // runs at deploy time (write_enrichment_config) on the generated lane.
    let violations = super::enrichment_lane_backpressure_violations(
        VectorConfigManager::enrichment_lane_content(),
    );
    assert!(
        violations.is_empty(),
        "shared-ingest-source backpressure lint failed:\n  {}",
        violations.join("\n  "),
    );
}

/// Positive coverage: a candidate enrichment lane whose user_registry sink
/// BLOCKS and is accidentally wired to the shared log router MUST be flagged.
/// The real enrichment router now has its own :8090 source/backpressure domain.
#[test]
fn backpressure_guard_flags_a_blocking_enrichment_sink() {
    let bad = r#"
[transforms.enrichment_normalize_ad]
type = "remap"
inputs = ["source_router.generic"]
source = '. = {}'

[sinks.clickhouse_user_registry]
type = "clickhouse"
inputs = ["enrichment_normalize_ad"]

[sinks.clickhouse_user_registry.buffer]
type = "memory"
when_full = "block"

[sinks.clickhouse_user_registry.acknowledgements]
enabled = true
"#;
    let violations = super::enrichment_lane_backpressure_violations(bad);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("clickhouse_user_registry")),
        "a blocking + acking user_registry sink reaching the shared ingest must be flagged, got {violations:?}"
    );
}

// ---- NAN-1197: enrichment-lane injection guards --------------------------

#[test]
fn ch_table_ident_accepts_valid_rejects_breakouts() {
    for ok in [
        "user_registry",
        "ip_enrichments",
        "nanosiem.user_registry",
        "_t",
    ] {
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
    assert!(
        assert_enrichment_lane_topology(exfil).is_err(),
        "http exfil sink must be rejected"
    );

    let lua = "[transforms.enrichment_normalize_ad]\ntype = \"lua\"\ninputs = []\nsource = \"x\"\n";
    assert!(
        assert_enrichment_lane_topology(lua).is_err(),
        "non-remap transform must be rejected"
    );

    let src = "[sources.evil]\ntype = \"exec\"\ncommand = [\"sh\"]\n";
    assert!(
        assert_enrichment_lane_topology(src).is_err(),
        "injected source must be rejected"
    );
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
        (
            "2026-07-29 13:36:59.002456",
            "2026-07-29T13:36:59.002456+00:00",
        ),
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
        target.value.get(vrl::path!("udm", "timestamp")).is_some(),
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

/// Extract the dollar-quoted VRL body seeded by a migration.
fn extract_dollar_quoted(content: &str, tag: &str) -> String {
    let start = content
        .find(tag)
        .unwrap_or_else(|| panic!("migration must contain the {tag} opening tag"))
        + tag.len();
    let rest = &content[start..];
    let end = rest
        .find(tag)
        .unwrap_or_else(|| panic!("migration must contain the {tag} closing tag"));
    rest[..end].to_string()
}

/// NAN-2370: the seeded OTLP parser is the ONLY thing standing between the
/// always-on OTLP listener (migration 214, gRPC :4317 / HTTP :4318) and a silent
/// discard — unclaimed `otlp_log` events fall to `source_router.generic` and
/// `placeholder_combiner` drops them with `condition = "false"`. It also ships in
/// open core, so a regression here is a data-loss path in the default install.
///
/// This guards the three defects that took bronze publication down while it was
/// being written. Each one was silent from Vector's side — the parser looked
/// perfect and every Vector metric was clean:
///
///  1. `trace` is an OCSF profile-bound attribute. Without
///     `metadata.profiles: ["trace"]` the WHOLE bronze object is rejected
///     (`strict_admission_failed`), taking co-located rows from healthy sources
///     with it.
///  2. A dot in an `unmapped` key makes Iceberg read it as a nested-struct path;
///     the additive-schema step then fails with "Cannot add column with ambiguous
///     name" on a DURABLE batch, which retries forever and stalls publication for
///     EVERY source (observed: 0 objects published, 127 queued, ingest frozen).
///  3. `to_unix_timestamp` errors on a non-timestamp, so a naive implementation
///     silently falls through to `now()` and stamps ingest time on every row.
///
/// The VRL is read from the migration (not `benchmarks/`, which is stripped from
/// the public mirror — an `include_str!` on a stripped path breaks the mirror
/// build, NAN-2169).
#[test]
fn seeded_otlp_parser_emits_admissible_ocsf_with_flat_unmapped_keys() {
    use vrl::compiler::runtime::Runtime;
    use vrl::compiler::state::RuntimeState;
    use vrl::compiler::{compile, TargetValue, TimeZone};
    use vrl::diagnostic::Formatter;
    use vrl::value::{ObjectMap, Secrets, Value};

    let migration =
        include_str!("../../../../../migrations/postgres/315_seed_otlp_log_ocsf_parser.sql");
    let program_src = extract_dollar_quoted(migration, "$otlp_vrl$");

    let fns = vrl::stdlib::all();
    let program = compile(&program_src, &fns)
        .map_err(|diagnostics| Formatter::new(&program_src, diagnostics).to_string())
        .expect("seeded OTLP parser VRL must compile")
        .program;

    // A representative post-`otlp_logs_prep` event: dotted OTLP semantic-convention
    // keys, W3C trace context, and a record timestamp that is NOT now().
    let mut resources = ObjectMap::new();
    resources.insert("service.name".into(), Value::from("web-frontend"));
    resources.insert("host.name".into(), Value::from("web-01"));
    let mut attributes = ObjectMap::new();
    attributes.insert("client.address".into(), Value::from("10.1.2.19"));
    attributes.insert("http.method".into(), Value::from("POST"));

    let mut event = ObjectMap::new();
    event.insert("message".into(), Value::from("checkout failed"));
    event.insert("severity".into(), Value::from("Error"));
    event.insert("severity_number".into(), Value::from(17));
    event.insert("timestamp".into(), Value::from("2026-08-17T19:00:00Z"));
    event.insert(
        "trace_id".into(),
        Value::from("3F7CCA2174C02EDBFE8BF4C4E2323A4F"),
    );
    event.insert("span_id".into(), Value::from("986BBCD196EFCAF8"));
    event.insert("resources".into(), Value::Object(resources));
    event.insert("attributes".into(), Value::Object(attributes));

    let mut target = TargetValue {
        value: Value::Object(event),
        metadata: Value::Object(ObjectMap::new()),
        secrets: Secrets::new(),
    };
    let mut runtime = Runtime::new(RuntimeState::default());
    runtime
        .resolve(&mut target, &program, &TimeZone::Local)
        .expect("seeded OTLP parser must not error on a representative record");

    let out = target.value;

    // (1) `trace` is emitted, so the trace profile MUST be declared or the whole
    // bronze object is rejected.
    let trace_uid = out
        .get(vrl::path!("trace", "uid"))
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .expect("trace.uid must be emitted for a record carrying trace context");
    assert_eq!(
        trace_uid, "3f7cca2174c02edbfe8bf4c4e2323a4f",
        "trace ids must be lowercased so they join the spans dataset byte-for-byte"
    );
    let profiles = out
        .get(vrl::path!("metadata", "profiles"))
        .and_then(|v| v.as_array().map(|a| a.to_vec()))
        .expect("metadata.profiles must be declared whenever `trace` is emitted");
    assert!(
        profiles
            .iter()
            .any(|p| p.as_str().is_some_and(|s| s == "trace")),
        "metadata.profiles must contain \"trace\"; without it OCSF strict admission \
         rejects the entire bronze object, not just this row"
    );

    // (2) No dotted key may reach `unmapped` — one is enough to wedge publication
    // for every source, indefinitely.
    let unmapped = out
        .get(vrl::path!("unmapped"))
        .and_then(|v| v.as_object().cloned())
        .expect("unmapped spill must be present");
    let dotted: Vec<String> = unmapped
        .keys()
        .filter(|k| k.contains('.'))
        .map(|k| k.to_string())
        .collect();
    assert!(
        dotted.is_empty(),
        "unmapped keys must not contain dots (Iceberg reads them as nested-struct \
         paths and the durable batch retries forever): {dotted:?}"
    );
    assert!(
        unmapped.contains_key("client_address") && unmapped.contains_key("service_name"),
        "dotted OTLP attributes must survive as flattened leaves, got: {:?}",
        unmapped.keys().collect::<Vec<_>>()
    );

    // (3) The record's own time must win over ingest time.
    let time_ms = out
        .get(vrl::path!("time"))
        .and_then(|v| v.as_integer())
        .expect("time must be emitted as epoch milliseconds");
    assert_eq!(
        time_ms, 1_786_993_200_000,
        "the LogRecord timestamp must win; falling back to now() silently stamps \
         ingest time on every OTLP row"
    );

    // The class must be one that can legally carry `trace` at all.
    let class_uid = out
        .get(vrl::path!("class_uid"))
        .and_then(|v| v.as_integer())
        .expect("class_uid must be emitted");
    assert!(
        class_uid == 6003 || class_uid == 4002,
        "only OCSF 4002 and 6003 define the `trace` object; class {class_uid} cannot \
         carry trace context (Base Event 0 never can)"
    );
}

// ------------------------------------------------------------------
// NAN-2612: the generic OCSF lane must keep the row's source attribution
// ------------------------------------------------------------------

/// Run the generic OCSF lane's VRL on one event, in process.
fn run_generic_ocsf_prepare(input: serde_json::Value) -> serde_json::Value {
    use vrl::compiler::runtime::Runtime;
    use vrl::compiler::state::RuntimeState;
    use vrl::compiler::{compile, TargetValue, TimeZone};
    use vrl::value::{Secrets, Value};

    let blocks = extract_vrl_blocks(VectorConfigManager::GENERIC_OCSF_PREPARE_BLOCK);
    let program = compile(blocks[0], &vrl::stdlib::all())
        .expect("generic OCSF prepare compiles")
        .program;
    let mut target = TargetValue {
        value: Value::from(input),
        metadata: Value::Object(Default::default()),
        secrets: Secrets::new(),
    };
    Runtime::new(RuntimeState::default())
        .resolve(&mut target, &program, &TimeZone::Local)
        .expect("generic OCSF prepare executes");
    target.value.try_into().expect("VRL output is JSON")
}

/// A `<parser>_output` row (every parser runtime failure, and any parser
/// output without a root `class_uid`) reaches the lake's generic lane through
/// `db_parsers_combined`. `_output` stores `.metadata` as a JSON *string*, so
/// `.metadata.original_source_type` is null there, and `to_string(null)` is
/// `""` without an error: the old `??` fallback to `.source_type` never ran and
/// every such row was stored as `unknown` (NAN-2612).
#[test]
fn generic_ocsf_prepare_keeps_the_source_of_a_parser_output_row() {
    let output = run_generic_ocsf_prepare(serde_json::json!({
        "timestamp": "2026-09-22T12:00:00Z",
        "message": "this is not json",
        "metadata": "{\"parse_failure\":true,\"parse_error\":\"function call error\",\"parser_name\":\"acme_web\"}",
        "_nano_parser_failure": true,
        "source_type": "acme-web"
    }));
    assert_eq!(output["source_type"], "acme-web", "{output}");
    assert_eq!(output["event"]["metadata"]["log_name"], "acme-web", "{output}");
}

/// The metadata string on an `_output` row is parser-authored. A parser must
/// not be able to relabel its rows as another source through it: the pinned
/// top-level `.source_type` wins.
#[test]
fn generic_ocsf_prepare_ignores_a_parser_authored_original_source_type() {
    let output = run_generic_ocsf_prepare(serde_json::json!({
        "message": "this is not json",
        "metadata": "{\"parse_failure\":true,\"original_source_type\":\"victim-src\"}",
        "source_type": "acme-web"
    }));
    assert_eq!(output["source_type"], "acme-web", "{output}");
}

/// `generic_parser` rows keep the pre-parser routing key under
/// `metadata.original_source_type` because a parse error rewrites the
/// top-level `source_type` to `parse_failure`.
#[test]
fn generic_ocsf_prepare_keeps_the_routing_key_of_a_generic_parse_failure() {
    let output = run_generic_ocsf_prepare(serde_json::json!({
        "message": "{broken",
        "metadata": {
            "parser_type": "generic",
            "original_source_type": "Acme-Web",
            "parse_failure": true
        },
        "source_type": "parse_failure"
    }));
    assert_eq!(output["source_type"], "acme-web", "{output}");
}

/// NAN-3242: an OTLP LogRecord carrying the resource `service.name` (every real
/// SDK sends it) reaches the generic lane as a class 0 Base Event. The lane
/// used to put it on `device.hostname`, a Host-profile attribute, and the
/// strict OCSF 1.9 lake refused every such row. It must now validate and carry
/// the service on `metadata.product.feature.name`.
#[test]
fn generic_ocsf_prepare_otlp_log_with_service_name_is_a_valid_ocsf_1_9_event() {
    let output = run_generic_ocsf_prepare(serde_json::json!({
        "timestamp": "2026-10-07T12:00:00Z",
        "message": "GET /checkout 200",
        "severity": "Info",
        "metadata": { "src_host": "Checkout-API", "forwarded_via": "otlp" },
        "resources": { "service.name": "Checkout-API", "host.name": "web-1" },
        "trace_id": "aabbccddeeff00112233445566778899",
        "span_id": "aabbccddeeff0011",
        "source_type": "otlp_log"
    }));
    let mut event = output["event"].clone();
    assert_eq!(event["class_uid"], 0, "{event}");
    assert!(event.get("device").is_none(), "device needs the host profile: {event}");
    assert_eq!(event["metadata"]["product"]["feature"]["name"], "Checkout-API", "{event}");
    assert_eq!(event["metadata"]["product"]["name"], "Nano Generic Source", "{event}");
    let metadata = event["metadata"].as_object_mut().unwrap();
    metadata.insert("log_source".into(), serde_json::json!("otlp_log"));
    metadata.insert("tenant_uid".into(), serde_json::json!("tenant-a"));
    metadata.insert("uid".into(), serde_json::json!("otlp-1"));
    let validation = crate::parsers::validate_ocsf_event(&event);
    assert!(validation.valid, "{:?}", validation.errors);
}

/// NAN-3242: the service mapping is OTLP-only; another parserless source that
/// happens to carry `metadata.src_host` is byte-unchanged.
#[test]
fn generic_ocsf_prepare_maps_service_name_only_for_otlp_logs() {
    let output = run_generic_ocsf_prepare(serde_json::json!({
        "message": "plain",
        "metadata": { "src_host": "edge-1" },
        "source_type": "acme-web"
    }));
    assert!(output["event"]["metadata"]["product"].get("feature").is_none(), "{output}");
    assert!(output["event"].get("device").is_none(), "{output}");
}

/// Design §10.5: `unknown` stays only for events that declared no source.
#[test]
fn generic_ocsf_prepare_labels_only_undeclared_events_unknown() {
    let output = run_generic_ocsf_prepare(serde_json::json!({
        "message": "no source",
        "metadata": { "parser_type": "generic", "original_source_type": "unknown" }
    }));
    assert_eq!(output["source_type"], "unknown", "{output}");
    let output = run_generic_ocsf_prepare(serde_json::json!({
        "message": "no source",
        "metadata": "{}"
    }));
    assert_eq!(output["source_type"], "unknown", "{output}");
}

/// The committed platform base (`config/vector`) is what a platform parser
/// bundle release packs. It must carry the generator's generic lane
/// byte-for-byte, or the fix never ships.
#[test]
fn committed_platform_base_carries_the_generated_generic_lane() {
    let lake = VectorConfigManager::pipeline_config_content_for(true, true);
    let start = lake
        .find("[transforms.generic_ocsf_prepare]")
        .expect("lake pipeline has the generic lane");
    let generated = &lake[start..];
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/vector");
    for relative in ["sources/parsers/_pipeline.toml", "backup/_pipeline.toml"] {
        let committed = std::fs::read_to_string(root.join(relative)).expect(relative);
        let at = committed
            .find("[transforms.generic_ocsf_prepare]")
            .unwrap_or_else(|| panic!("{relative} lost the generic lane"));
        assert_eq!(
            &committed[at..],
            generated,
            "{relative} drifted from GENERIC_OCSF_PREPARE_BLOCK; regenerate it"
        );
    }
}

/// NAN-2612 acceptance in the cell's pinned Vector image: a parser runtime
/// failure and a non-OCSF parser row from source `acme-web` come out of the
/// lake storage stage with `metadata.log_source = "acme-web"`; a row that
/// declared no source stays `unknown`.
///
/// Needs docker and the pinned image; opt in with
/// `NANO_VECTOR_CONTAINER_TESTS=1`. Without it the test returns early.
#[test]
fn lake_generic_lane_stamps_the_source_slug_in_the_pinned_vector() {
    const IMAGE: &str = "ghcr.io/nano-rs/vector:0.59.0-nano.7-debian@sha256:3219f912af603e68a23100fb0909d139635aab56bb253461fc794fca88c079d6";
    if std::env::var("NANO_VECTOR_CONTAINER_TESTS").as_deref() != Ok("1") {
        eprintln!("skipped: set NANO_VECTOR_CONTAINER_TESTS=1 (needs docker + {IMAGE})");
        return;
    }

    // A routed parser that errors at runtime on anything but JSON, and emits
    // no `class_uid` on success (the non-OCSF case).
    let mut parser = log_test_parser("acme_web", true);
    parser.source_type = "routed".to_string();
    parser.parser_vrl = ".parsed = parse_json!(.message)".to_string();
    let manager = VectorConfigManager::new(std::env::temp_dir());

    let stub = r#"[sources.stub_in]
type = "demo_logs"
format = "json"
count = 1

[transforms.source_router]
type = "route"
inputs = ["stub_in"]
route.acme_web = '.source_type == "acme-web"'
route.generic = '.source_type != "acme-web"'

[transforms.placeholder_combiner]
type = "filter"
inputs = ["source_router.generic"]
condition = "false"
"#;
    let condition = |slug: &str| {
        format!(
            "[[tests.outputs.conditions]]\n\
             type = \"vrl\"\n\
             source = '''\n\
             event = object!(parse_json!(string!(._nano_bronze_event)))\n\
             assert_eq!(event.metadata.log_source, \"{slug}\")\n\
             assert!(is_string(event.raw_data))\n\
             assert!(is_timestamp(.time))\n\
             '''\n"
        )
    };
    let tests = format!(
        "[[tests]]\n\
         name = \"parse failure keeps its source\"\n\
         [[tests.inputs]]\n\
         insert_at = \"acme_web_parse\"\n\
         type = \"log\"\n\
         log_fields.message = \"this is not json\"\n\
         log_fields.source_type = \"acme-web\"\n\
         [[tests.outputs]]\n\
         extract_from = \"ocsf_lake_storage_prepare\"\n\
         {}\n\
         [[tests]]\n\
         name = \"non-OCSF parser output keeps its source\"\n\
         [[tests.inputs]]\n\
         insert_at = \"acme_web_parse\"\n\
         type = \"log\"\n\
         log_fields.message = '{{\"k\":\"v\"}}'\n\
         log_fields.source_type = \"acme-web\"\n\
         [[tests.outputs]]\n\
         extract_from = \"ocsf_lake_storage_prepare\"\n\
         {}\n\
         [[tests]]\n\
         name = \"an undeclared event stays unknown\"\n\
         [[tests.inputs]]\n\
         insert_at = \"generic_parser\"\n\
         type = \"log\"\n\
         log_fields.message = \"no source\"\n\
         [[tests.outputs]]\n\
         extract_from = \"ocsf_lake_storage_prepare\"\n\
         {}\n",
        condition("acme-web"),
        condition("acme-web"),
        condition("unknown"),
    );

    // Scratch the docker daemon can see: a test runner may give the test a
    // private /tmp, so stay under the workspace target dir by default.
    let scratch = std::env::var_os("NANO_VECTOR_TEST_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"));
    std::fs::create_dir_all(&scratch).expect("scratch dir");
    let dir = tempfile::tempdir_in(&scratch).expect("tempdir");
    let files = [
        ("00-stub.toml", stub.to_string()),
        ("acme_web.toml", manager.generate_parser_config_string(&parser)),
        (
            "_combiner.toml",
            VectorConfigManager::combiner_config_content_for(std::slice::from_ref(&parser), false),
        ),
        (
            "_pipeline.toml",
            VectorConfigManager::pipeline_config_content_for(true, true),
        ),
        (
            "_ocsf_sink.toml",
            VectorConfigManager::lake_ocsf_sink_content(
                &["\"generic_ocsf_prepare\"".to_string()],
                false,
            ),
        ),
    ];
    let config = dir.path().join("config");
    std::fs::create_dir(&config).expect("config dir");
    for (name, content) in &files {
        std::fs::write(config.join(name), content).expect("write config");
    }
    // Loaded beside the config dir, like the NAN-2604 build Job's samples.
    std::fs::write(dir.path().join("tests.toml"), tests).expect("write tests");
    let output = std::process::Command::new("docker")
        .args(["run", "--rm", "--network", "none", "-v"])
        .arg(format!("{}:/work:ro", dir.path().display()))
        .args([
            "-e",
            "NANO_TENANT_ID=acme",
            "-e",
            "NANO_LAKE_BRONZE_BUCKET=placeholder",
            IMAGE,
            "--dangerously-allow-env-var-interpolation",
            "test",
            "--config-dir",
            "/work/config",
            "--config-toml",
            "/work/tests.toml",
        ])
        .output()
        .expect("docker runs");
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "vector test failed:\n{log}");
    assert_eq!(log.matches("... passed").count(), 3, "{log}");
}

/// NAN-3483, in the pinned Vector: with no enrichment parser imported (the
/// open-core default), an Okta identity record maps through the built-in Okta
/// normalizer, an untagged one still reaches AD, and an unknown source
/// dead-letters. With only AD imported (generated lane), Okta still maps.
///
/// Needs docker and the pinned image; opt in with
/// `NANO_VECTOR_CONTAINER_TESTS=1`. Without it the test returns early.
#[test]
fn nan3483_identity_sources_route_to_their_own_normalizer_in_the_pinned_vector() {
    const IMAGE: &str = "ghcr.io/nano-rs/vector:0.59.0-nano.7-debian@sha256:3219f912af603e68a23100fb0909d139635aab56bb253461fc794fca88c079d6";
    if std::env::var("NANO_VECTOR_CONTAINER_TESTS").as_deref() != Ok("1") {
        eprintln!("skipped: set NANO_VECTOR_CONTAINER_TESTS=1 (needs docker + {IMAGE})");
        return;
    }
    let record = |fields: &str| {
        format!(
            "[[tests.inputs]]\ninsert_at = \"enrichment_router\"\ntype = \"log\"\n\
             [tests.inputs.log_fields]\nsource_type = \"nano_enrich\"\nkind = \"identity\"\n{fields}\n"
        )
    };
    let expect = |from: &str, condition: &str| {
        format!(
            "[[tests.outputs]]\nextract_from = \"{from}\"\n\
             [[tests.outputs.conditions]]\ntype = \"vrl\"\nsource = '{condition}'\n"
        )
    };
    let okta = format!(
        "[[tests]]\nname = \"okta maps through the okta normalizer\"\n{}{}",
        record("source = \"okta\"\nprovider_id = \"okta-1\"\nid = \"00u1\"\nstatus = \"ACTIVE\"\n\"profile.login\" = \"dir1@example.com\""),
        expect(
            "enrichment_normalize_okta",
            ".external_id == \"00u1\" && .upn == \"dir1@example.com\" && .provider_id == \"okta-1\"",
        ),
    );
    let unknown = format!(
        "[[tests]]\nname = \"an unknown source dead-letters\"\n{}{}",
        record("source = \"onelogin\"\nid = \"x\""),
        expect(
            "enrichment_dead_letter_report",
            "contains(string!(.message), \"onelogin\") && .error_type == \"enrichment_dead_letter\" && .level == \"WARN\"",
        ),
    );
    let untagged_ad = format!(
        "[[tests]]\nname = \"an untagged record still reaches AD\"\n{}{}",
        record("external_id = \"S-1-5-21-1\""),
        expect("enrichment_normalize_ad", ".external_id == \"S-1-5-21-1\""),
    );

    let mut ad = enrichment_test_parser(
        "identity",
        "user_registry",
        crate::identity::normalizers::builtin_identity_normalizer("ad").unwrap().normalize_vrl,
    );
    ad.enrich_source = Some("ad".to_string());
    ad.name = "ad_identity".to_string();
    let stub = "[sources.stub_in]\ntype = \"demo_logs\"\nformat = \"json\"\ncount = 1\n";
    let cases = [
        (
            "static",
            crate::parsers::vector_config::router::enrichment_router_block(&[], "\"stub_in\""),
            VectorConfigManager::enrichment_lane_config_for_backend(&[], true),
            format!("{okta}{unknown}{untagged_ad}"),
            3,
        ),
        (
            "generated",
            crate::parsers::vector_config::router::enrichment_router_block(&[&ad], "\"stub_in\""),
            VectorConfigManager::enrichment_lane_config_for_backend(&[ad.clone()], true),
            format!("{okta}{unknown}"),
            2,
        ),
    ];

    let scratch = std::env::var_os("NANO_VECTOR_TEST_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../target"));
    std::fs::create_dir_all(&scratch).expect("scratch dir");
    for (label, router, lane, tests, passing) in cases {
        let dir = tempfile::tempdir_in(&scratch).expect("tempdir");
        let config = dir.path().join("config");
        std::fs::create_dir(&config).expect("config dir");
        std::fs::write(config.join("00-stub.toml"), stub).expect("write stub");
        std::fs::write(config.join("_router.toml"), &router).expect("write router");
        std::fs::write(config.join("_enrichment.toml"), &lane).expect("write lane");
        std::fs::write(dir.path().join("tests.toml"), &tests).expect("write tests");
        let output = std::process::Command::new("docker")
            .args(["run", "--rm", "--network", "none", "-v"])
            .arg(format!("{}:/work:ro", dir.path().display()))
            .args([
                "-e",
                "NANO_LAKE_ENRICHMENT_COORDINATOR_URL=http://127.0.0.1:9",
                IMAGE,
                "--dangerously-allow-env-var-interpolation",
                "test",
                "--config-dir",
                "/work/config",
                "--config-toml",
                "/work/tests.toml",
            ])
            .output()
            .expect("run docker");
        let log = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "{label}: vector test failed:\n{log}");
        assert_eq!(log.matches("... passed").count(), passing, "{label}:\n{log}");
    }
}

// ------------------------------------------------------------------
// NAN-3765: a rendered tree must never reference a missing component
// ------------------------------------------------------------------

/// Component ids declared by the static base config shipped next to the
/// dynamic tree (`config/vector/0*.toml`, `9*.toml`). Header scan rather than
/// a TOML parse: those files carry `${VAR}` interpolation outside strings.
fn static_base_components() -> std::collections::HashSet<String> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/vector");
    let mut out = std::collections::HashSet::new();
    for entry in std::fs::read_dir(&dir).expect("config/vector") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|e| e != "toml") {
            continue;
        }
        let content = std::fs::read_to_string(&path).expect("static config");
        for line in content.lines() {
            let line = line.trim();
            for kind in ["[sources.", "[transforms."] {
                if let Some(rest) = line.strip_prefix(kind) {
                    if let Some(name) = rest.strip_suffix(']') {
                        if !name.contains('.') {
                            out.insert(name.to_string());
                        }
                    }
                }
            }
        }
    }
    out
}

/// Every `inputs` entry of every transform/sink in the rendered dynamic tree
/// that resolves to neither a component in that tree nor one in the static
/// base config. Route outputs (`source_router.generic`) resolve by their
/// component prefix.
fn dangling_inputs(sources_dir: &std::path::Path) -> Vec<String> {
    fn walk(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(&path, files);
            } else if path.extension().is_some_and(|e| e == "toml") {
                files.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(sources_dir, &mut files);

    let mut declared = static_base_components();
    let mut references: Vec<(String, String)> = Vec::new();
    for file in &files {
        let raw = std::fs::read_to_string(file).expect("rendered file");
        // Vector substitutes `${VAR:-default}` before parsing TOML; mirror it.
        let content = regex::Regex::new(r"\$\{([^}]*)\}")
            .expect("regex")
            .replace_all(&raw, |caps: &regex::Captures| match caps[1].find(":-") {
                Some(pos) => caps[1][pos + 2..].to_string(),
                None => String::new(),
            })
            .into_owned();
        let doc: toml::Value = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("{} is not valid TOML: {e}", file.display()));
        for kind in ["sources", "transforms", "sinks"] {
            let Some(table) = doc.get(kind).and_then(|v| v.as_table()) else {
                continue;
            };
            for (name, def) in table {
                declared.insert(name.clone());
                for input in def
                    .get("inputs")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str())
                {
                    references.push((format!("{kind}.{name}"), input.to_string()));
                }
            }
        }
    }
    references
        .into_iter()
        .filter(|(_, input)| {
            let component = input.split('.').next().unwrap_or(input);
            !declared.contains(component)
        })
        .map(|(owner, input)| format!("{owner} -> {input}"))
        .collect()
}

fn hec_test_parser(name: &str) -> Parser {
    Parser {
        source_type: "splunk_hec".to_string(),
        match_values: Some(vec!["okta".to_string()]),
        ..log_test_parser(name, true)
    }
}

/// NAN-3765 (CT 106, publication 25): a HEC parser deployed while no HEC
/// source configuration declares `splunk_hec_route` (source disabled, absent,
/// or on default rules, so `configs/splunk_hec.toml` is not rendered). The
/// parser filter and `splunk_hec_route_unclaimed` both consumed the missing
/// route, so Vector rejected every reload and could not have booted.
#[tokio::test]
async fn hec_parser_without_hec_source_config_renders_no_dangling_input() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());

    manager
        .deploy_parsers(&[
            hec_test_parser("lab_okta_parser"),
            log_test_parser("apache", true),
        ])
        .await
        .expect("deploy");

    assert!(
        !tmp.path().join("sources/configs/splunk_hec.toml").exists(),
        "precondition: no HEC source-config route rendered"
    );
    let dangling = dangling_inputs(&tmp.path().join("sources"));
    assert!(dangling.is_empty(), "dangling inputs: {dangling:#?}");

    let router =
        std::fs::read_to_string(tmp.path().join("sources/parsers/_router.toml")).expect("router");
    // The claimed HEC stream reaches source_router only through the
    // unclaimed filter, never raw (NAN-930 double-write).
    assert!(router.contains("[transforms.splunk_hec_route]"), "{router}");
    assert!(
        router.contains("[transforms.splunk_hec_route_unclaimed]"),
        "{router}"
    );
    let source_router_inputs = router
        .split("[transforms.source_router]")
        .nth(1)
        .and_then(|rest| rest.lines().find(|l| l.trim_start().starts_with("inputs")))
        .expect("source_router inputs");
    assert!(
        source_router_inputs.contains("\"splunk_hec_route_unclaimed\"")
            && !source_router_inputs.contains("\"hec_normalize\""),
        "{source_router_inputs}"
    );
}

/// NAN-3765: with the HEC source configuration's route rendered, the
/// passthrough route must not be emitted (a duplicate component id is its own
/// reload failure) and the tree still closes.
#[tokio::test]
async fn hec_parser_with_hec_source_config_uses_its_route() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let configs = tmp.path().join("sources/configs");
    std::fs::create_dir_all(&configs).expect("configs dir");
    std::fs::write(
        configs.join("splunk_hec.toml"),
        "[transforms.splunk_hec_route]\n\
         inputs = [\"hec_normalize\"]\n\
         type = \"remap\"\n\
         source = \"\"\"\nif .source_type == \"okta\" { .source_type = \"okta\" }\n\"\"\"\n",
    )
    .expect("hec route");
    let manager = VectorConfigManager::new(tmp.path());

    manager
        .deploy_parsers(&[hec_test_parser("lab_okta_parser")])
        .await
        .expect("deploy");

    let dangling = dangling_inputs(&tmp.path().join("sources"));
    assert!(dangling.is_empty(), "dangling inputs: {dangling:#?}");
    let router =
        std::fs::read_to_string(tmp.path().join("sources/parsers/_router.toml")).expect("router");
    assert!(
        !router.contains("[transforms.splunk_hec_route]"),
        "{router}"
    );
    assert!(
        router.contains("[transforms.splunk_hec_route_unclaimed]"),
        "{router}"
    );
}

/// NAN-3765: a fetch parser bound (DISPATCH FROM) to a source configuration
/// whose route is not rendered must not get a `<route>_unclaimed` filter on
/// the missing route.
#[test]
fn unclaimed_filter_only_for_routes_feeding_source_router() {
    let bound = Parser {
        source_type: "kafka".to_string(),
        dispatch_source_config_id: Some(uuid::Uuid::new_v4()),
        dispatch_route_name: Some("kafka_audit_route".to_string()),
        ..log_test_parser("audit", true)
    };
    let (inputs, blocks) = super::super::router::build_router_inputs_with_claim_dedupe(
        vec!["vector_merge".to_string()],
        &[],
        std::slice::from_ref(&bound),
    );
    assert_eq!(inputs, vec!["vector_merge".to_string()]);
    assert!(!blocks.contains("kafka_audit_route_unclaimed"), "{blocks}");

    let (inputs, blocks) = super::super::router::build_router_inputs_with_claim_dedupe(
        vec!["vector_merge".to_string()],
        &["kafka_audit_route".to_string()],
        &[bound],
    );
    assert!(inputs.contains(&"kafka_audit_route_unclaimed".to_string()));
    assert!(
        blocks.contains("[transforms.kafka_audit_route_unclaimed]"),
        "{blocks}"
    );
}

fn nan3767_run_vrl(source: &str, input: serde_json::Value) -> Result<serde_json::Value, String> {
    use vrl::compiler::runtime::Runtime;
    use vrl::compiler::state::RuntimeState;
    use vrl::compiler::{compile, TargetValue, TimeZone};
    use vrl::value::{Secrets, Value};
    let program = compile(source, &vrl::stdlib::all()).expect("VRL compiles").program;
    let mut target = TargetValue {
        value: Value::from(input),
        metadata: Value::Object(Default::default()),
        secrets: Secrets::new(),
    };
    Runtime::new(RuntimeState::default())
        .resolve(&mut target, &program, &TimeZone::Local)
        .map_err(|e| e.to_string())?;
    Ok(target.value.try_into().expect("VRL output is JSON"))
}

/// NAN-3767: the runner's envelopes pass as coordinator lines (and nothing
/// else rides along); a record without a stage/delta op is dead-lettered.
#[test]
fn nan3767_identity_envelope_vrl_emits_coordinator_lines() {
    let row = serde_json::json!({"feed_id": "f:users", "external_id": "u1", "source_kind": "pull", "version": 7});
    let stage = nan3767_run_vrl(
        super::IDENTITY_ENVELOPE_VRL,
        serde_json::json!({"source_type": "nano_enrich", "kind": "identity_directory", "op": "stage",
            "feed_id": "f:users", "run_id": "r1", "row": row}),
    )
    .unwrap();
    assert_eq!(stage, serde_json::json!({"op": "stage", "feed_id": "f:users", "run_id": "r1", "row": row}));
    let delta = nan3767_run_vrl(
        super::IDENTITY_ENVELOPE_VRL,
        serde_json::json!({"source_type": "nano_enrich", "kind": "identity_directory", "op": "delta", "patch": true,
            "row": row, "manager_ref": {"feed_id": "f:users", "external_id": "u1", "manager_external_id": "m"}}),
    )
    .unwrap();
    assert_eq!(delta["patch"], true);
    assert_eq!(delta["manager_ref"]["manager_external_id"], "m");
    assert!(delta.get("kind").is_none() && delta.get("source_type").is_none());
    assert!(nan3767_run_vrl(super::IDENTITY_ENVELOPE_VRL, serde_json::json!({"op": "commit"})).is_err());
}

/// NAN-3767: a provider-sync / push row (the Okta built-in normalizer's
/// output) becomes a coordinator `delta` line of feed `push:<provider>`.
#[test]
fn nan3767_identity_lines_vrl_maps_normalized_rows() {
    let okta = crate::identity::normalizers::builtin_identity_normalizer("okta").unwrap();
    let normalized = nan3767_run_vrl(
        okta.normalize_vrl,
        serde_json::json!({"source_type": "nano_enrich", "kind": "identity", "source": "okta",
            "provider_id": "prov-1", "id": "00u1", "status": "ACTIVE",
            "profile": {"login": "alice@example.com", "email": "alice@example.com", "department": "Security",
                "manager": "Bob", "managerId": "bob@example.com"},
            "version": 1700000000000i64}),
    )
    .unwrap();
    let mut normalized = normalized;
    normalized["groups"] = serde_json::json!(["Admins", 3]);
    let line = nan3767_run_vrl(super::IDENTITY_LINES_VRL, normalized).unwrap();
    assert_eq!(line["op"], "delta");
    let row = &line["row"];
    assert_eq!(row["feed_id"], "push:prov-1");
    assert_eq!(row["external_id"], "00u1");
    assert_eq!(row["source_kind"], "push");
    assert_eq!(row["deleted"], false);
    assert!(row["version"].as_i64().unwrap() > 0);
    assert!(row["account_enabled"].is_boolean() && row["mfa_enabled"].is_boolean());
    assert_eq!(row["groups"], serde_json::json!(["Admins"]));
    assert_eq!(row["upn"], "alice@example.com");
    // Only coordinator IdentityRow columns (it refuses unknown fields).
    for gone in ["provider_id", "sync_hash", "last_synced_at"] {
        assert!(row.get(gone).is_none(), "{gone} leaked");
    }
    let tomb = nan3767_run_vrl(
        super::IDENTITY_LINES_VRL,
        serde_json::json!({"provider_id": "p", "external_id": "x", "account_status": "deleted"}),
    )
    .unwrap();
    assert_eq!(tomb["row"]["deleted"], true);
    assert!(nan3767_run_vrl(super::IDENTITY_LINES_VRL, serde_json::json!({"provider_id": "p"})).is_err());
}

// ------------------------------------------------------------------
// NAN-3765 follow-up: dispatch parsers waiting on their source config
// ------------------------------------------------------------------

fn dispatch_test_parser(name: &str, source_config: uuid::Uuid) -> Parser {
    Parser {
        source_type: "kafka".to_string(),
        dispatch_source_config_id: Some(source_config),
        match_values: Some(vec!["azure".to_string()]),
        ..log_test_parser(name, true)
    }
}

/// CT 106 publication 28: `nan3764_lab_azure_parser` was bound to a source
/// configuration whose route only arrived in publication 29. Resolution holds
/// the parser back, the rest of the set still renders, and the rendered tree
/// closes against the embedded static base (the publisher's own check).
#[tokio::test]
async fn parser_bound_to_undeployed_source_config_is_held_back_and_tree_closes() {
    use crate::parsers::repository::{
        apply_resolved_dispatch_routes, DispatchTarget, IngressPresence,
    };
    let hub = uuid::Uuid::new_v4();
    let targets = std::collections::HashMap::from([(
        hub,
        DispatchTarget {
            name: "nan3764 lab hub".to_string(),
            deployed: false,
        },
    )]);
    let mut parsers = vec![
        dispatch_test_parser("nan3764_lab_azure_parser", hub),
        log_test_parser("apache", true),
        hec_test_parser("lab_okta_parser"),
    ];
    let waiting = apply_resolved_dispatch_routes(
        &mut parsers,
        &targets,
        IngressPresence {
            hec: true,
            otlp: true,
        },
    );
    assert_eq!(waiting.len(), 1, "{waiting:?}");
    assert!(
        waiting[0].reason.contains("nan3764 lab hub"),
        "{}",
        waiting[0].reason
    );

    let tmp = tempfile::TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());
    manager.deploy_parsers(&parsers).await.expect("deploy");

    let sources = tmp.path().join("sources");
    assert!(
        !sources
            .join("parsers/nan3764_lab_azure_parser.toml")
            .exists(),
        "a waiting parser renders nothing"
    );
    assert!(sources.join("parsers/apache.toml").exists());
    assert_eq!(
        super::super::closure::dangling_inputs(&sources).unwrap(),
        Vec::<String>::new()
    );
    let dangling = dangling_inputs(&sources);
    assert!(dangling.is_empty(), "dangling inputs: {dangling:#?}");

    // Once the source configuration is deployed (and its route rendered), the
    // same parser renders and the tree still closes.
    let deployed = std::collections::HashMap::from([(
        hub,
        DispatchTarget {
            name: "nan3764 lab hub".to_string(),
            deployed: true,
        },
    )]);
    let mut parsers = vec![dispatch_test_parser("nan3764_lab_azure_parser", hub)];
    assert!(apply_resolved_dispatch_routes(
        &mut parsers,
        &deployed,
        IngressPresence {
            hec: true,
            otlp: true,
        },
    )
    .is_empty());
    std::fs::create_dir_all(sources.join("configs")).unwrap();
    std::fs::write(
        sources.join("configs/nan3764_lab_hub.toml"),
        "[sources.nan3764_lab_hub_source]\ntype = \"demo_logs\"\nformat = \"json\"\n\n\
         [transforms.nan3764_lab_hub_route]\ntype = \"remap\"\n\
         inputs = [\"nan3764_lab_hub_source\"]\nsource = \".\"\n",
    )
    .unwrap();
    manager.deploy_parsers(&parsers).await.expect("deploy");
    assert!(sources
        .join("parsers/nan3764_lab_azure_parser.toml")
        .exists());
    assert_eq!(
        super::super::closure::dangling_inputs(&sources).unwrap(),
        Vec::<String>::new()
    );
}

/// The publisher's closure check refuses the exact publication-28 shape.
#[tokio::test]
async fn closure_check_flags_a_filter_on_a_missing_source_config_route() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let manager = VectorConfigManager::new(tmp.path());
    let mut parser = dispatch_test_parser("nan3764_lab_azure_parser", uuid::Uuid::new_v4());
    parser.dispatch_route_name = Some("nan3764_lab_hub_route".to_string());
    manager.deploy_parsers(&[parser]).await.expect("deploy");
    let dangling = super::super::closure::dangling_inputs(&tmp.path().join("sources")).unwrap();
    assert!(
        dangling
            .iter()
            .any(|d| d.ends_with("-> nan3764_lab_hub_route")),
        "{dangling:?}"
    );
}
