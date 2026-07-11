// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser deployment to active Vector configuration.
//!
//! Handles deploying parser configs, generating combiner and pipeline configs,
//! cleaning up orphaned files, and reloading Vector.

use std::path::Path;

use tokio::fs;
use tokio::process::Command;

use super::VectorConfigError;
use super::VectorConfigManager;
use crate::parsers::types::Parser;

/// NAN-1128/1150: report any sink in the shipped topology — the static base
/// sources/router/combiner/pipeline plus the *candidate* enrichment lane TOML —
/// that backpressures a shared ingest source. A sink that blocks
/// (`buffer.when_full = "block"`) or waits on `acknowledgements.enabled = true`
/// and whose input chain reaches a shared ingest source (`http_server` /
/// `vector` / `splunk_hec`) would stall LOG ingestion when its target stalls
/// (the NAN-1120 silent-halt class). Empty result = safe.
///
/// Shared by the build-time `shared_ingest_source_sinks_must_not_backpressure`
/// test (passing the committed `enrichment_lane_content()`) and the deploy-time
/// guard in `write_enrichment_config` (passing the freshly-generated lane), so
/// the same invariant gates both `cargo test` and every live reload.
pub(super) fn enrichment_lane_backpressure_violations(candidate_enrichment_toml: &str) -> Vec<String> {
    use std::collections::{HashMap, HashSet};

    // NAN-1572: `opentelemetry` is the Vector source `type` of the OOTB OTLP
    // ingest source (`otlp_ingest`, config/vector/03-otlp-source.toml). It's a
    // shared LOG ingest source like http/vector/hec, so an enrichment-lane sink
    // that backpressures into it would stall OTLP ingestion (NAN-1120 class).
    const INGEST_SOURCE_TYPES: &[&str] = &["http_server", "vector", "splunk_hec", "opentelemetry"];
    // Sources with their own backpressure domain (none today; add the dedicated
    // enrichment `:8090` source here if it ships).
    const DEDICATED_ENRICHMENT_SOURCES: &[&str] = &[];

    // Vector substitutes `${VAR:-default}` before parsing TOML, so mirror that
    // (value after `:-`, else empty) to make the raw configs parseable.
    fn substitute_env(raw: &str) -> String {
        let re = regex::Regex::new(r"\$\{([^}]*)\}").unwrap();
        re.replace_all(raw, |caps: &regex::Captures| match caps[1].find(":-") {
            Some(pos) => caps[1][pos + 2..].to_string(),
            None => String::new(),
        })
        .into_owned()
    }

    fn input_list(def: &toml::Value) -> Vec<String> {
        def.get("inputs")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default()
    }

    // Strip the named-output suffix: "source_router.generic" -> "source_router".
    fn base(name: &str) -> String {
        name.split('.').next().unwrap_or(name).to_string()
    }

    struct SinkInfo {
        #[allow(dead_code)]
        ty: String,
        inputs: Vec<String>,
        blocks: bool,
        acks: bool,
    }

    let docs: [(&str, &str); 8] = [
        ("00-base.toml", include_str!("../../../../config/vector/00-base.toml")),
        ("01-vector-source.toml", include_str!("../../../../config/vector/01-vector-source.toml")),
        ("02-hec-source.toml", include_str!("../../../../config/vector/02-hec-source.toml")),
        ("92-metrics.toml", include_str!("../../../../config/vector/92-metrics.toml")),
        ("_router.toml", include_str!("../../../../config/vector/sources/parsers/_router.toml")),
        ("_combiner.toml", include_str!("../../../../config/vector/sources/parsers/_combiner.toml")),
        ("pipeline_config_content()", VectorConfigManager::pipeline_config_content()),
        ("candidate _enrichment.toml", candidate_enrichment_toml),
    ];

    let mut sources: HashMap<String, String> = HashMap::new();
    let mut transforms: HashMap<String, Vec<String>> = HashMap::new();
    let mut sinks: HashMap<String, SinkInfo> = HashMap::new();

    for (label, raw) in docs {
        let doc: toml::Table = match toml::from_str(&substitute_env(raw)) {
            Ok(d) => d,
            // A candidate that doesn't even parse is caught by `vector validate`
            // downstream; here we only police backpressure on what parses.
            Err(_) => return vec![format!("{label}: TOML parse failed")],
        };
        if let Some(tbl) = doc.get("sources").and_then(|v| v.as_table()) {
            for (name, def) in tbl {
                let ty = def.get("type").and_then(|v| v.as_str()).unwrap_or_default();
                sources.insert(name.clone(), ty.to_string());
            }
        }
        if let Some(tbl) = doc.get("transforms").and_then(|v| v.as_table()) {
            for (name, def) in tbl {
                transforms.insert(name.clone(), input_list(def));
            }
        }
        if let Some(tbl) = doc.get("sinks").and_then(|v| v.as_table()) {
            for (name, def) in tbl {
                let blocks = def
                    .get("buffer")
                    .and_then(|b| b.get("when_full"))
                    .and_then(|v| v.as_str())
                    == Some("block");
                let acks = def
                    .get("acknowledgements")
                    .and_then(|a| a.get("enabled"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                sinks.insert(
                    name.clone(),
                    SinkInfo {
                        ty: def.get("type").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                        inputs: input_list(def),
                        blocks,
                        acks,
                    },
                );
            }
        }
    }

    // Walk a sink's inputs back to the source terminals it can reach.
    fn reach(
        inputs: &[String],
        sources: &HashMap<String, String>,
        transforms: &HashMap<String, Vec<String>>,
        ingest_types: &[&str],
        dedicated: &[&str],
    ) -> (Vec<String>, bool) {
        let mut seen: HashSet<String> = HashSet::new();
        let mut stack: Vec<String> = inputs.iter().map(|i| base(i)).collect();
        let mut shared: Vec<String> = Vec::new();
        let mut unresolved = false;
        while let Some(node) = stack.pop() {
            if !seen.insert(node.clone()) {
                continue;
            }
            if let Some(ty) = sources.get(&node) {
                if ingest_types.contains(&ty.as_str()) && !dedicated.contains(&node.as_str()) {
                    shared.push(node);
                }
            } else if let Some(ins) = transforms.get(&node) {
                for i in ins {
                    stack.push(base(i));
                }
            } else {
                unresolved = true;
            }
        }
        shared.sort();
        shared.dedup();
        (shared, unresolved)
    }

    let mut violations: Vec<String> = Vec::new();
    for (name, sink) in &sinks {
        if !sink.blocks && !sink.acks {
            continue;
        }
        let (shared, unresolved) = reach(
            &sink.inputs,
            &sources,
            &transforms,
            INGEST_SOURCE_TYPES,
            DEDICATED_ENRICHMENT_SOURCES,
        );
        if shared.is_empty() && !unresolved {
            continue;
        }
        let mut why = Vec::new();
        if sink.blocks {
            why.push("buffer.when_full=\"block\"");
        }
        if sink.acks {
            why.push("acknowledgements.enabled=true");
        }
        let reaches = if shared.is_empty() {
            "an unresolved upstream (treated as shared)".to_string()
        } else {
            format!("shared ingest source(s): {}", shared.join(", "))
        };
        violations.push(format!(
            "sink `{name}` sets {} but reaches {reaches}",
            why.join(" + ")
        ));
    }
    violations.sort();
    violations
}

/// NAN-1197: a ClickHouse table identifier, optionally `db.table`-qualified.
/// `target_table` is interpolated raw into the generated sink's `table = "{…}"`
/// value, so anything outside this set could break out of the TOML string.
fn is_valid_ch_table_ident(s: &str) -> bool {
    fn is_ident(part: &str) -> bool {
        let mut chars = part.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    }
    match s.split_once('.') {
        Some((db, table)) => is_ident(db) && is_ident(table),
        None => is_ident(s),
    }
}

/// NAN-1197: a safe enrichment-source discriminator. `enrich_source` is
/// interpolated into the router VRL comparison literal, so restrict it to a
/// token charset that cannot terminate the string or inject VRL.
fn is_safe_enrich_source(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// NAN-1197: assert the generated enrichment lane contains only the components
/// `generate_enrichment_lane` is supposed to emit. This is the defense-in-depth
/// backstop to the per-parser source-text checks: even if a future escaping bug
/// let a value slip through, an injected `[sinks.*]` of a non-ClickHouse type
/// (http/socket/file exfil) or a non-remap transform (exec/lua) is rejected
/// here before the config is written. Only the GENERATED path calls this — the
/// committed static fallback is trusted.
fn assert_enrichment_lane_topology(toml_str: &str) -> Result<(), String> {
    let doc: toml::Table =
        toml::from_str(toml_str).map_err(|e| format!("candidate TOML parse failed: {e}"))?;

    // The lane must not introduce sources.
    if doc.contains_key("sources") {
        return Err("enrichment lane must not declare [sources]".to_string());
    }

    if let Some(transforms) = doc.get("transforms").and_then(|v| v.as_table()) {
        for (name, def) in transforms {
            if !name.starts_with("enrichment_normalize_") {
                return Err(format!("unexpected transform '{name}'"));
            }
            let ty = def.get("type").and_then(|v| v.as_str()).unwrap_or_default();
            if ty != "remap" {
                return Err(format!("transform '{name}' has unexpected type '{ty}'"));
            }
        }
    }

    if let Some(sinks) = doc.get("sinks").and_then(|v| v.as_table()) {
        for (name, def) in sinks {
            let ty = def.get("type").and_then(|v| v.as_str()).unwrap_or_default();
            let ok = (name.starts_with("clickhouse_") && ty == "clickhouse")
                || (name == "enrichment_dead_letter" && ty == "blackhole");
            if !ok {
                return Err(format!("unexpected sink '{name}' (type '{ty}')"));
            }
        }
    }

    Ok(())
}

impl VectorConfigManager {
    /// Remove a parser's config file from the parsers directory
    ///
    /// This is called when a parser is deleted to clean up its config file.
    /// The combiner and router configs should be regenerated separately via deploy_parsers.
    pub async fn remove_parser_config(&self, parser_name: &str) -> Result<(), VectorConfigError> {
        let filename = format!("{}.toml", Self::safe_name(parser_name));
        let filepath = self.parsers_dir.join(&filename);

        if filepath.exists() {
            fs::remove_file(&filepath).await?;
            tracing::info!("Removed parser config file: {}", filepath.display());
        } else {
            tracing::debug!(
                "Parser config file not found (already removed?): {}",
                filepath.display()
            );
        }

        Ok(())
    }

    /// Generate and write Vector config for all enabled parsers
    /// Each parser gets its own file, disabled parsers have their files removed
    /// Also generates the dynamic router config for routed parsers
    pub async fn deploy_parsers(&self, parsers: &[Parser]) -> Result<(), VectorConfigError> {
        // Ensure directories exist
        fs::create_dir_all(&self.parsers_dir).await?;
        fs::create_dir_all(&self.credentials_dir).await?;

        // Track which files should exist
        let mut expected_files: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // NAN-1149: enrichment parsers (kind = "enrichment") are not log sources —
        // they don't get a per-parser source TOML or a source_router route. They
        // generate the push enrichment lane (normalize + sink) instead. Split them
        // out here; the per-parser loop, combiner, and router below operate on log
        // parsers only.
        let enrichment_parsers: Vec<Parser> = parsers
            .iter()
            .filter(|p| p.kind == "enrichment")
            .cloned()
            .collect();
        let log_parsers: Vec<Parser> = parsers
            .iter()
            .filter(|p| p.kind != "enrichment")
            .cloned()
            .collect();

        for parser in &log_parsers {
            let filename = format!("{}.toml", Self::safe_name(&parser.name));
            let filepath = self.parsers_dir.join(&filename);

            if parser.enabled {
                // Write credential files if needed (GCP service account JSON, etc.)
                self.write_credential_files(parser).await?;

                // Write config for enabled parser
                let config = self.generate_parser_config(parser);
                fs::write(&filepath, &config).await?;
                expected_files.insert(filename);
                tracing::info!(
                    "Deployed parser '{}' to {}",
                    parser.name,
                    filepath.display()
                );
            } else {
                // Remove config for disabled parser if it exists
                if filepath.exists() {
                    fs::remove_file(&filepath).await?;
                    tracing::info!(
                        "Removed disabled parser '{}' from {}",
                        parser.name,
                        filepath.display()
                    );
                }
                // Clean up credential files for disabled parsers
                self.remove_credential_files(parser).await?;
            }
        }

        // Clean up orphaned parser TOML files that aren't in expected_files
        // This handles renames (e.g., "Apache" -> "Apache HTTP Server") where the old
        // file would persist as "apache.toml" alongside "apache_http_server.toml"
        let mut dir_entries = fs::read_dir(&self.parsers_dir).await?;
        while let Some(entry) = dir_entries.next_entry().await? {
            let file_name = entry.file_name().to_string_lossy().to_string();
            // Skip special files (router, combiner, pipeline, gitkeep)
            if file_name.starts_with('_') || file_name.starts_with('.') {
                continue;
            }
            if file_name.ends_with(".toml") && !expected_files.contains(&file_name) {
                fs::remove_file(entry.path()).await?;
                tracing::warn!(
                    "Removed orphaned parser config '{}' (not in expected files)",
                    file_name
                );
            }
        }

        // Write the combiner config that unions all parser outputs
        self.write_combiner_config(&log_parsers).await?;

        // Write the dynamic router config for routed parsers. Enrichment
        // parsers are passed too so the enrichment_router emits a per-source
        // route for each (NAN-1151).
        self.write_router_config(&log_parsers, &enrichment_parsers).await?;

        // NAN-1246: write the shared OCSF ingestion sink (only under
        // NANO_SCHEMA_PROFILE=ocsf) wired to every parser's generated `_ocsf_prepare`
        // fork, and drop the superseded hand-written `_ocsf.toml`. No-op under UDM.
        self.write_ocsf_sink_config(&log_parsers).await?;

        // Write the static pipeline config (generic parser, mapping, sink)
        // In distributed deployments, these must be in parsers_dir to get S3-synced
        // to Vector pods alongside the dynamic router and parser configs.
        self.write_pipeline_config().await?;

        // Write the push enrichment lane (NAN-1124/NAN-1149): when enrichment
        // parsers are deployed, the per-kind normalize transforms are generated
        // from their `normalize_vrl`; otherwise the committed static lane is kept
        // verbatim (behaviour-preserving for deployments that haven't adopted
        // dynamic enrichment parsers).
        self.write_enrichment_config(&enrichment_parsers).await?;

        let enabled_count = log_parsers.iter().filter(|p| p.enabled).count();
        tracing::info!(
            "Deployed {} parser(s) to {}",
            enabled_count,
            self.parsers_dir.display()
        );

        Ok(())
    }

    /// NAN-1246: write the shared OCSF ingestion sink, and remove the superseded
    /// hand-written `_ocsf.toml` (the apache-only Phase-6a stopgap). Under
    /// NANO_SCHEMA_PROFILE=ocsf every enabled log parser's generated
    /// `{name}_ocsf_prepare` fork feeds `nanosiem.ocsf_logs`; the sink config
    /// mirrors the UDM `clickhouse_logs` sink. Under UDM (or with no parsers) it
    /// writes nothing and clears any stale sink, so the config stays byte-identical.
    pub(super) async fn write_ocsf_sink_config(
        &self,
        log_parsers: &[Parser],
    ) -> Result<(), VectorConfigError> {
        // The Phase-6a hand-written apache-only lane is superseded by generated config.
        let legacy = self.parsers_dir.join("_ocsf.toml");
        if legacy.exists() {
            fs::remove_file(&legacy).await?;
        }

        let sink_path = self.parsers_dir.join("_ocsf_sink.toml");

        let inputs = Self::ocsf_sink_inputs(log_parsers);

        // No OCSF sink under UDM, or before any parser is deployed.
        if inputs.is_empty() {
            if sink_path.exists() {
                fs::remove_file(&sink_path).await?;
            }
            return Ok(());
        }

        fs::write(&sink_path, Self::ocsf_sink_content(&inputs)).await?;
        tracing::info!(
            "Wrote OCSF ingestion sink ({} parser fork(s)) to {}",
            inputs.len(),
            sink_path.display()
        );
        Ok(())
    }

    /// NAN-1584: compute the `clickhouse_ocsf_logs` sink inputs from the deployed
    /// parsers. Shared by the active writer ([`Self::write_ocsf_sink_config`]) and
    /// the staged writer ([`super::VectorConfigManager::write_staged_ocsf_sink_config`])
    /// so the two paths cannot byte-drift. Empty under UDM.
    pub(super) fn ocsf_sink_inputs(parsers: &[Parser]) -> Vec<String> {
        Self::ocsf_sink_inputs_for(Self::ocsf_mode(), parsers)
    }

    /// Pure variant of [`Self::ocsf_sink_inputs`] with the OCSF gate passed in
    /// explicitly, so it is testable without the env-racy `ocsf_mode` read.
    pub(super) fn ocsf_sink_inputs_for(ocsf: bool, parsers: &[Parser]) -> Vec<String> {
        if !ocsf {
            return Vec::new();
        }
        let mut v: Vec<String> = parsers
            .iter()
            .filter(|p| p.enabled && p.kind != "enrichment")
            .map(|p| format!("\"{}_ocsf_prepare\"", Self::safe_name(&p.name)))
            .collect();
        // NAN-1325: the generic Base Event lane always feeds ocsf_logs under OCSF
        // — even with zero deployed parsers — so unconfigured/unknown source types
        // are searchable (parity with the UDM `logs` unknown bucket). The
        // `generic_ocsf_prepare` transform is emitted by `full_pipeline_config_content`.
        v.push("\"generic_ocsf_prepare\"".to_string());
        v
    }

    /// NAN-1584: render the `clickhouse_ocsf_logs` sink TOML for the given inputs.
    /// Shared by the active and staged writers.
    pub(super) fn ocsf_sink_content(inputs: &[String]) -> String {
        format!(
            "# Auto-generated OCSF ingestion sink (NAN-1246)\n\
             # DO NOT EDIT - regenerated on every parser deploy.\n\
             # Each parser's generated `_ocsf_prepare` fork feeds nanosiem.ocsf_logs.\n\
             # Emitted only under NANO_SCHEMA_PROFILE=ocsf; mirrors clickhouse_logs.\n\
             # Durability ACK (NAN-1406): the server-side profile sets\n\
             # wait_for_async_insert=1, so HTTP 200 means the flush succeeded —\n\
             # a flush failure (NAN-1404 class) is a visible, retryable sink\n\
             # error instead of a silently discarded pre-ACKed batch.\n\
             # NAN-1728 (C4/W10): the OCSF ingest lane writes the ENGINE=Null\n\
             # `ocsf_logs_raw` table; a ClickHouse MV maps it into the Replicated\n\
             # `ocsf_logs`. It is deliberately NOT routed to `ocsf_logs_distributed`\n\
             # — the raw table carries the JSON `event` shape, not the mapped\n\
             # columns, so writing the wrapper would bypass the MV. Cross-shard\n\
             # retry dedup on this lane relies on the query settings below (plus the\n\
             # server-side deduplicate_blocks_in_dependent_materialized_views=1);\n\
             # this reduces but cannot fully eliminate dupes when a retry lands on a\n\
             # different shard (at-least-once on the raw lane, documented).\n\
             [sinks.clickhouse_ocsf_logs]\n\
             type = \"clickhouse\"\n\
             inputs = [{inputs}]\n\
             endpoint = \"${{CLICKHOUSE_URL:-http://clickhouse:8123}}\"\n\
             database = \"${{CLICKHOUSE_DATABASE:-nanosiem}}\"\n\
             table = \"${{CLICKHOUSE_OCSF_LOGS_TABLE:-ocsf_logs_raw}}\"\n\
             auth.strategy = \"basic\"\n\
             auth.user = \"${{CLICKHOUSE_USER:-nanosiem}}\"\n\
             auth.password = \"${{CLICKHOUSE_PASSWORD:-nanosiem}}\"\n\
             compression = \"gzip\"\n\
             date_time_best_effort = true\n\
             skip_unknown_fields = true\n\
             \n\
             # NAN-1728 (C4/W10): async_insert_deduplicate=1 for the raw lane.\n\
             [sinks.clickhouse_ocsf_logs.query_settings.async_insert_settings]\n\
             deduplicate = true\n\
             \n\
             [sinks.clickhouse_ocsf_logs.buffer]\n\
             type = \"memory\"\n\
             max_events = 100000\n\
             when_full = \"drop_newest\"\n\
             \n\
             [sinks.clickhouse_ocsf_logs.acknowledgements]\n\
             enabled = false\n\
             \n\
             [sinks.clickhouse_ocsf_logs.batch]\n\
             max_bytes = ${{VECTOR_BATCH_MAX_BYTES:-52428800}}\n\
             max_events = ${{VECTOR_BATCH_MAX_EVENTS:-50000}}\n\
             timeout_secs = ${{VECTOR_BATCH_TIMEOUT_SECS:-10}}\n\
             \n\
             [sinks.clickhouse_ocsf_logs.request]\n\
             concurrency = \"adaptive\"\n\
             timeout_secs = 120\n\
             retry_initial_backoff_secs = 1\n\
             retry_max_duration_secs = 300\n",
            inputs = inputs.join(", ")
        )
    }

    /// Write the combiner config that unions all enabled parser outputs
    pub(super) async fn write_combiner_config(
        &self,
        parsers: &[Parser],
    ) -> Result<(), VectorConfigError> {
        let combiner_path = self.parsers_dir.join("_combiner.toml");

        let enabled_parsers: Vec<_> = parsers.iter().filter(|p| p.enabled).collect();

        let mut config = String::from(
            "# Auto-generated combiner for all DB parsers\n\
             # DO NOT EDIT - changes will be overwritten\n\n",
        );

        if enabled_parsers.is_empty() {
            // No parsers enabled — use a filter that drops everything so Vector
            // has a valid input (empty inputs = [] is rejected by Vector).
            config.push_str(
                "# No enabled parsers\n\
                 [transforms.db_parsers_combined]\n\
                 type = \"filter\"\n\
                 inputs = [\"prepare_output\"]\n\
                 condition = \"false\"\n",
            );
        } else {
            // Combine all parser outputs
            let inputs: Vec<String> = enabled_parsers
                .iter()
                .map(|p| {
                    let safe = Self::safe_name(&p.name);
                    let has_sampling = p
                        .sampling_ratio
                        .map(|r| r > 0.0 && r < 1.0)
                        .unwrap_or(false);
                    if has_sampling {
                        format!("\"{}_sample\"", safe)
                    } else {
                        format!("\"{}_output\"", safe)
                    }
                })
                .collect();

            config.push_str(&format!(
                "[transforms.db_parsers_combined]\n\
                 type = \"remap\"\n\
                 inputs = [{}]\n\
                 source = '''\n. = .\n'''\n",
                inputs.join(", ")
            ));
        }

        fs::write(&combiner_path, &config).await?;
        Ok(())
    }

    /// Returns the static pipeline config content (generic parser, normalization, clickhouse mapping, sink).
    /// Shared between write_pipeline_config (deploy) and write_staged_pipeline_config (staged deploy).
    pub(super) fn pipeline_config_content() -> &'static str {
        r#"# Auto-generated static pipeline config
# DO NOT EDIT - regenerated by deploy_parsers
# Contains: generic parser, normalization, clickhouse mapping, clickhouse sink

# =============================================================================
# Generic Parser (handles unmatched source types)
# =============================================================================
[transforms.generic_parser]
type = "remap"
inputs = ["source_router.generic"]
drop_on_abort = false
drop_on_error = false
source = '''
if !is_object(.metadata) {
    .metadata = {}
}
.metadata.parser_type = "generic"

original_source_type = "unknown"
if exists(.source_type) && is_string(.source_type) {
    original_source_type = to_string!(.source_type)
}
.metadata.original_source_type = original_source_type

has_parse_error = exists(.parse_error) || exists(.metadata.parse_error)
if has_parse_error {
    parse_error = "Unknown parse error"
    if exists(.parse_error) {
        parse_error = to_string(.parse_error) ?? "Unknown parse error"
    }
    if exists(.metadata.parse_error) {
        parse_error = to_string(.metadata.parse_error) ?? parse_error
    }
    log("Parser failure for source_type=" + original_source_type + ": " + parse_error, level: "warn")
    .metadata.parse_failure = true
    .metadata.parse_error = parse_error
    .source_type = "parse_failure"
    .metadata.failure_timestamp = to_string(now())
}
'''

# =============================================================================
# Normalization - Extract UDM fields from metadata
# =============================================================================
[transforms.normalize]
type = "remap"
inputs = ["placeholder_combiner", "generic_parser"]
source = '''
.udm = {}
.udm.src_ip = .metadata.src_ip
.udm.dest_ip = .metadata.dest_ip
.udm.src_host = .metadata.src_host
.udm.dest_host = .metadata.dest_host
.udm.src_port = .metadata.src_port
.udm.dest_port = .metadata.dest_port
.udm.protocol = .metadata.protocol
.udm.src_user = .metadata.src_user
.udm.dest_user = .metadata.dest_user
.udm.user = .metadata.user
# NAN-659: prefer event_type (canonical) over action (legacy synonym).
# Plain field access is infallible in VRL, so `??` is rejected (E651) —
# use an explicit null check instead.
.udm.action = if .metadata.event_type != null { .metadata.event_type } else { .metadata.action }
.udm.status = .metadata.status
.udm.process_name = .metadata.process_name
.udm.process_id = .metadata.process_id
.udm.command_line = .metadata.command_line
.udm.file_path = .metadata.file_path
.udm.file_name = .metadata.file_name
.udm.file_hash = .metadata.file_hash

ts = .metadata.timestamp
if ts == null { ts = .timestamp }
if ts == null { ts = now() }
if is_string(ts) {
    parsed_ts, err = parse_timestamp(ts, "%+")
    if err == null { ts = parsed_ts }
}
if !is_timestamp(ts) { ts = now() }
.udm.timestamp = format_timestamp!(ts, "%+")
'''

# =============================================================================
# Deduplication - Remove duplicate events (retries, redundant forwarders)
# =============================================================================
[transforms.dedupe]
type = "dedupe"
inputs = ["normalize"]

[transforms.dedupe.fields]
match = ["message", "source_type", "timestamp"]

[transforms.dedupe.cache]
num_events = 5000

# =============================================================================
# Output Preparation
# =============================================================================
[transforms.prepare_output]
type = "remap"
inputs = ["dedupe"]
source = '''
src_type = .source_type
if src_type == null { src_type = "unknown" }

raw_message = .message
if raw_message == null { raw_message = "" }

# NAN-1556: carry OTLP-mapped fields through the `. = {...}` rebuild below.
# otlp_logs_prep (config/vector/03-otlp-source.toml) sets these at the top
# level; without capturing them here the reset would drop them on the generic
# path (the lane OTLP logs ride with no deployed parser). Null/empty for every
# non-OTLP source, so behavior for HTTP/HEC/Vector/parsers is unchanged.
otlp_severity = .severity
otlp_ext = .ext
otlp_trace_id = .trace_id
otlp_span_id = .span_id

. = {
    "timestamp": .udm.timestamp,
    "severity": otlp_severity,
    "ext": otlp_ext,
    "trace_id": otlp_trace_id,
    "span_id": otlp_span_id,
    "message": raw_message,
    "raw_content": .raw_content,
    "metadata": encode_json(.metadata),
    "source_type": src_type,
    "src_ip": .udm.src_ip,
    "dest_ip": .udm.dest_ip,
    "src_host": .udm.src_host,
    "dest_host": .udm.dest_host,
    "src_port": .udm.src_port,
    "dest_port": .udm.dest_port,
    "protocol": .udm.protocol,
    "src_user": .udm.src_user,
    "dest_user": .udm.dest_user,
    "user": .udm.user,
    "action": .udm.action,
    "status": .udm.status,
    "status_code": .udm.status_code,
    "process_name": .udm.process_name,
    "process_id": .udm.process_id,
    "process_path": .udm.process_path,
    "process_guid": .udm.process_guid,
    "process_hash": .udm.process_hash,
    "parent_command_line": .udm.parent_command_line,
    "parent_process_id": .udm.parent_process_id,
    "parent_process_path": .udm.parent_process_path,
    "command_line": .udm.command_line,
    "file_path": .udm.file_path,
    "file_name": .udm.file_name,
    "file_hash": .udm.file_hash,
    "url": .udm.url,
    "url_domain": .udm.url_domain,
    "uri_path": .udm.uri_path,
    "http_method": .udm.http_method,
    "http_user_agent": .udm.http_user_agent,
    "http_referrer": .udm.http_referrer,
    "http_content_type": .udm.http_content_type,
    "registry_path": .udm.registry_path,
    "registry_value_data": .udm.registry_value_data,
    "query": .udm.query,
    "query_type": .udm.query_type,
    "session_id": .udm.session_id,
    "duration": .udm.duration,
    "bytes_in": .udm.bytes_in,
    "bytes_out": .udm.bytes_out,
    "user_agent": .udm.user_agent
}
'''

# =============================================================================
# ClickHouse Field Mapping & Normalization
# =============================================================================
[transforms.clickhouse_mapping]
type = "remap"
inputs = ["prepare_output", "db_parsers_combined"]
source = '''
.id = uuid_v7()
if !exists(.timestamp) {
    .timestamp = format_timestamp!(now(), format: "%Y-%m-%d %H:%M:%S")
} else if is_string(.timestamp) {
    ts, err = parse_timestamp(.timestamp, "%+")
    if err == null {
        .timestamp = format_timestamp!(ts, format: "%Y-%m-%d %H:%M:%S")
    } else {
        .timestamp = format_timestamp!(now(), format: "%Y-%m-%d %H:%M:%S")
    }
} else if is_timestamp(.timestamp) {
    .timestamp = format_timestamp!(.timestamp, format: "%Y-%m-%d %H:%M:%S")
} else {
    .timestamp = format_timestamp!(now(), format: "%Y-%m-%d %H:%M:%S")
}
.message = to_string(.message) ?? ""
if is_object(.metadata) {
    .metadata = encode_json(.metadata)
} else if is_string(.metadata) {
    .metadata = to_string!(.metadata)
} else {
    .metadata = "{}"
}
.source_type = to_string(.source_type) ?? "unknown"
.namespace = to_string(.namespace) ?? "default"
.src_ip = downcase(to_string(.src_ip) ?? "")
.dest_ip = downcase(to_string(.dest_ip) ?? "")
.src_host = downcase(to_string(.src_host) ?? "")
.dest_host = downcase(to_string(.dest_host) ?? "")
.src_port = to_int(.src_port) ?? 0
.dest_port = to_int(.dest_port) ?? 0
.protocol = downcase(to_string(.protocol) ?? "")
.bytes_in = to_int(.bytes_in) ?? 0
.bytes_out = to_int(.bytes_out) ?? 0
.src_user = downcase(to_string(.src_user) ?? "")
.dest_user = to_string(.dest_user) ?? ""
.user = downcase(to_string(.user) ?? "")
# NAN-659: parsers may emit .event_type (canonical) or .action (legacy) after udm flattening.
# Both route to the action ClickHouse column (event_type is a read-only ALIAS for action).
event_type_str = to_string(.event_type) ?? ""
action_str = to_string(.action) ?? ""
if event_type_str != "" { action_str = event_type_str }
.action = downcase(action_str)
del(.event_type)
.status = to_string(.status) ?? ""
.status_code = to_int(.status_code) ?? 0
.auth_type = to_string(.auth_type) ?? ""
.auth_result = to_string(.auth_result) ?? ""
.session_id = to_string(.session_id) ?? ""
.process_name = to_string(.process_name) ?? ""
.process_id = to_int(.process_id) ?? 0
.process_path = to_string(.process_path) ?? ""
# NAN-1415: hex hash case is encoding noise - canonicalize to lowercase at
# ingest so new rows compare raw and the enrichment dicts that key on
# lower hashes join consistently. History stays mixed-case, so query codegen
# still emits the lower form - served by the migration-132 expression blooms.
# process_guid needs no line here: the logs column is MATERIALIZED from a
# lower hex expression in ClickHouse, so it is lowercase by construction.
.process_hash = downcase(to_string(.process_hash) ?? "")
cmd_val = .command_line
if cmd_val == null || cmd_val == "" { cmd_val = .process }
.command_line = to_string(cmd_val) ?? ""
pcmd_val = .parent_command_line
if pcmd_val == null || pcmd_val == "" { pcmd_val = .parent_process }
.parent_command_line = to_string(pcmd_val) ?? ""
.parent_process_name = to_string(.parent_process_name) ?? ""
.parent_process_id = to_int(.parent_process_id) ?? 0
.parent_process_path = to_string(.parent_process_path) ?? ""
.file_path = to_string(.file_path) ?? ""
.file_name = to_string(.file_name) ?? ""
.file_hash = downcase(to_string(.file_hash) ?? "")
.file_action = to_string(.file_action) ?? ""
.url = to_string(.url) ?? ""
.url_domain = to_string(.url_domain) ?? ""
.uri_path = to_string(.uri_path) ?? ""
.http_method = to_string(.http_method) ?? ""
.http_user_agent = to_string(.http_user_agent) ?? ""
.http_referrer = to_string(.http_referrer) ?? ""
.http_content_type = to_string(.http_content_type) ?? ""
.registry_path = to_string(.registry_path) ?? ""
.registry_value_data = to_string(.registry_value_data) ?? ""
.query = to_string(.query) ?? ""
.query_type = to_string(.query_type) ?? ""
.duration = to_int(.duration) ?? 0
.response_time = to_int(.response_time) ?? 0
.user_agent = to_string(.user_agent) ?? ""
.sender = to_string(.sender) ?? ""
.sender_domain = to_string(.sender_domain) ?? ""
.recipient = to_string(.recipient) ?? ""
.recipient_domain = to_string(.recipient_domain) ?? ""
.subject = to_string(.subject) ?? ""
.message_id = to_string(.message_id) ?? ""
.packets_in = to_int(.packets_in) ?? 0
.packets_out = to_int(.packets_out) ?? 0
.direction = to_string(.direction) ?? ""
.src_mac = downcase(to_string(.src_mac) ?? "")
.dest_mac = downcase(to_string(.dest_mac) ?? "")
.vlan = to_string(.vlan) ?? ""
.user_id = to_string(.user_id) ?? ""
.user_name = to_string(.user_name) ?? ""
.user_domain = downcase(to_string(.user_domain) ?? "")
.user_type = to_string(.user_type) ?? ""
.result = to_string(.result) ?? ""
.severity = to_string(.severity) ?? ""
# NAN-1556: OTLP log correlation ids (set by otlp_logs_prep, carried through
# prepare_output). Downcased to match the lower(col) convention; empty for
# non-correlated logs. Listed in explicit_columns below so they map to their
# own columns instead of being swept into ext.
.trace_id = downcase(to_string(.trace_id) ?? "")
.span_id = downcase(to_string(.span_id) ?? "")
.category = to_string(.category) ?? ""
.authentication_method = to_string(.authentication_method) ?? ""
.file_size = to_int(.file_size) ?? 0
.registry_key_name = to_string(.registry_key_name) ?? ""
.registry_value_name = to_string(.registry_value_name) ?? ""
.answer = to_string(.answer) ?? ""
.dns_answers = to_string(.dns_answers) ?? ""
.record_type = to_string(.record_type) ?? ""
.signature = to_string(.signature) ?? ""
.signature_id = to_string(.signature_id) ?? ""
.cve = to_string(.cve) ?? ""
.mitre_technique_id = to_string(.mitre_technique_id) ?? ""
.rule_id = to_string(.rule_id) ?? ""
.rule_name = to_string(.rule_name) ?? ""
.vendor = to_string(.vendor) ?? ""
.product = to_string(.product) ?? ""
.vendor_product = to_string(.vendor_product) ?? ""
.risk_entity = to_string(.risk_entity) ?? ""
.risk_score = to_float(.risk_score) ?? 0.0
.risk_level = to_string(.risk_level) ?? ""
.dvc = to_string(.dvc) ?? ""
# NAN-1646: downcase on the same lane as src_ip/dest_ip so dvc_ip can join
# LOWERCASE_NORMALIZED_FIELDS and equality hunts engage the raw bloom index.
# Only affects IPv6 hex case - IPv4 is case-free.
.dvc_ip = downcase(to_string(.dvc_ip) ?? "")
.dvc_mac = to_string(.dvc_mac) ?? ""

# Build ext JSON with all non-explicit fields
explicit_columns = [
    "id", "timestamp", "message", "metadata", "source_type", "namespace", "ingest_time", "_inserted_at",
    "src_ip", "dest_ip", "src_host", "dest_host", "src_port", "dest_port", "protocol",
    "bytes_in", "bytes_out", "packets_in", "packets_out", "direction", "src_mac", "dest_mac", "vlan",
    "user", "src_user", "dest_user", "user_id", "user_name", "user_domain", "user_type",
    "action", "status", "status_code", "result", "severity", "category",
    "trace_id", "span_id",
    "auth_type", "auth_result", "session_id", "authentication_method",
    "process_name", "process_id", "process_path", "process_hash",
    "command_line", "parent_command_line", "parent_process_name", "parent_process_id", "parent_process_path",
    "file_path", "file_name", "file_hash", "file_size", "file_action",
    "registry_path", "registry_key_name", "registry_value_name", "registry_value_data",
    "url", "url_domain", "uri_path", "http_method", "http_user_agent", "http_referrer", "http_content_type",
    "query", "query_type", "answer", "dns_answers", "record_type",
    "sender", "sender_domain", "recipient", "recipient_domain", "subject", "message_id",
    "signature", "signature_id", "cve", "mitre_technique_id", "rule_id", "rule_name", "vendor", "product", "vendor_product",
    "risk_entity", "risk_score", "risk_level",
    "dvc", "dvc_ip", "dvc_mac",
    "duration", "response_time",
    "user_agent"
]

ext_existing = .ext
if !is_object(ext_existing) {
    ext_existing = {}
}
for_each(keys(.)) -> |_idx, key| {
    if !includes(explicit_columns, key) && key != "ext" {
        val = get!(., [key])
        if val != null {
            val_str = to_string(val) ?? ""
            if val_str != "" && val_str != "0" && val_str != "0.0" {
                ext_existing = set!(ext_existing, [key], val)
            }
        }
    }
}
.ext = ext_existing

.ingest_time = format_timestamp!(now(), format: "%Y-%m-%d %H:%M:%S.%f")
'''

# =============================================================================
# ClickHouse Sink
#
# Durability ACK (NAN-1406): the server-side profile sets async_insert=1 +
# wait_for_async_insert=1, so ClickHouse's HTTP 200 means the async-insert
# FLUSH succeeded (rows durably written), not merely buffered. A flush failure
# (e.g. FAILED enrichment dict, NAN-1404) comes back as a sink error Vector
# retries and surfaces in metrics, instead of a silently discarded pre-ACKed
# batch. Measured: zero throughput cost at 5k eps; sustained-overload shedding
# unchanged (the drop_newest buffer below sheds either way, now visibly).
#
# Cluster routing contract (NAN-1728, C4/W1) — kept byte-for-byte in sync with
# config/vector/sources/parsers/_pipeline.toml. `table` is env-driven and
# defaults to the shard-LOCAL `logs`:
#   * SINGLE-SHARD (dev / Saturn / most tenants): leave CLICKHOUSE_LOGS_TABLE
#     UNSET -> writes the plain local `logs`, unchanged. No `logs_distributed`
#     wrapper exists there, so the default MUST stay `logs`.
#   * ENTERPRISE 3x2 CLUSTER: deploy/k8s/rackspace/vector.yaml sets
#     CLICKHOUSE_LOGS_TABLE=logs_distributed so writes go THROUGH the Distributed
#     wrapper (sharded by cityHash64(id), content hash not rand()), so a
#     timed-out-then-retried batch re-hashes to the SAME shard and per-shard
#     block dedup catches the duplicate; also removes per-connection shard skew.
# =============================================================================
[sinks.clickhouse_logs]
type = "clickhouse"
inputs = ["clickhouse_mapping"]

endpoint = "${CLICKHOUSE_URL:-http://clickhouse:8123}"
database = "${CLICKHOUSE_DATABASE:-nanosiem}"
table = "${CLICKHOUSE_LOGS_TABLE:-logs}"

auth.strategy = "basic"
auth.user = "${CLICKHOUSE_USER:-nanosiem}"
auth.password = "${CLICKHOUSE_PASSWORD:-nanosiem}"

compression = "gzip"
date_time_best_effort = true
skip_unknown_fields = true

# NAN-1728 (C4/W10): async-insert block dedup — `deduplicate = true` emits the
# ClickHouse query setting `async_insert_deduplicate=1` so an identical batch
# re-POSTed after an HTTP timeout is dropped, not re-inserted. Harmless on
# single-shard. The MV-cascade companion
# `deduplicate_blocks_in_dependent_materialized_views=1` is not expressible from
# the Vector clickhouse sink and lives in the server-side profile (query_limits.xml).
[sinks.clickhouse_logs.query_settings.async_insert_settings]
deduplicate = true

[sinks.clickhouse_logs.buffer]
type = "memory"
max_events = 100000
when_full = "drop_newest"

[sinks.clickhouse_logs.acknowledgements]
enabled = false

[sinks.clickhouse_logs.batch]
max_bytes = ${VECTOR_BATCH_MAX_BYTES:-52428800}
max_events = ${VECTOR_BATCH_MAX_EVENTS:-50000}
timeout_secs = ${VECTOR_BATCH_TIMEOUT_SECS:-10}

[sinks.clickhouse_logs.request]
concurrency = "adaptive"
timeout_secs = 120
retry_initial_backoff_secs = 1
retry_max_duration_secs = 300
"#
    }

    /// NAN-1325: generic OCSF **Base Event** lane. Under `NANO_SCHEMA_PROFILE=ocsf`,
    /// events from source types with NO deployed parser fall through to
    /// `generic_parser`, which sets `source_type`/metadata but never a `class_uid` —
    /// so the per-parser `_ocsf_split` (`exists(.class_uid)`) never forks them, and
    /// they reach the UDM `logs` table but never `ocsf_logs`. Since OCSF search reads
    /// `ocsf_logs`, that unconfigured/early/unknown data was silently invisible
    /// (UDM keeps it searchable in its `unknown` bucket). This transform forks off
    /// `generic_parser` and shapes a minimal Base Event (`class_uid = 0`, the raw
    /// record preserved in `event`, a `message`, `source_type`, `timestamp`) — the
    /// row shape `clickhouse_ocsf_logs` expects (mirrors `OCSF_PREPARE_VRL`). The
    /// sink wires `generic_ocsf_prepare` into its inputs. Appended only under OCSF
    /// (UDM deployments get the static config verbatim — byte-identical).
    const GENERIC_OCSF_PREPARE_BLOCK: &'static str = r#"
# =============================================================================
# Generic OCSF Base Event lane (NAN-1325) — unparsed/unknown source types still
# land searchable in ocsf_logs as a class_uid=0 Base Event. OCSF deployments only.
# =============================================================================
[transforms.generic_ocsf_prepare]
type = "remap"
inputs = ["generic_parser"]
drop_on_abort = false
drop_on_error = false
source = '''
ocsf_event = .
src_type = downcase(to_string(.metadata.original_source_type) ?? to_string(.source_type) ?? "unknown")
if src_type == "" { src_type = "unknown" }
msg = to_string(.message) ?? ""
if msg == "" { msg = encode_json(ocsf_event) }
ocsf_event.class_uid = 0
ocsf_event.message = msg

# NAN-1556: OTLP LogRecords (source_type=otlp_log) reach this generic lane with
# canonical fields already set by otlp_logs_prep (.severity, .metadata.src_host
# from resource service.name, .trace_id/.span_id). Promote them to OCSF Base
# Event keys inside `event` so the ocsf_logs MATERIALIZED columns
# (severity_id / severity / src_endpoint.hostname / time, all JSONExtract'd from
# `event`) populate. Each map is gated on presence, so non-OTLP parserless
# events are byte-unchanged (their severity/src_host are unset).
sev_str = to_string(.severity) ?? ""
if sev_str != "" {
    ocsf_event.severity = sev_str
    sl = downcase(sev_str)
    ocsf_event.severity_id = if sl == "fatal" { 6 } else if sl == "critical" { 5 } else if sl == "error" { 4 } else if sl == "warn" || sl == "warning" { 3 } else if sl == "info" || sl == "informational" || sl == "debug" || sl == "trace" { 1 } else { 0 }
}
otlp_host = to_string(.metadata.src_host) ?? ""
if otlp_host != "" {
    ocsf_event.src_endpoint.hostname = downcase(otlp_host)
}
otlp_time = to_string(.timestamp) ?? ""
if otlp_time != "" {
    ocsf_event.time = otlp_time
}

. = { "event": ocsf_event, "timestamp": format_timestamp!(now(), "%Y-%m-%d %H:%M:%S%.3f"), "source_type": src_type }
'''
"#;

    /// The pipeline config for the ACTIVE schema: the static content plus, under
    /// OCSF, the generic Base Event lane ([`Self::GENERIC_OCSF_PREPARE_BLOCK`]). UDM
    /// returns the static content unchanged (byte-identical).
    pub(super) fn full_pipeline_config_content() -> String {
        let mut content = Self::pipeline_config_content().to_string();
        if Self::ocsf_mode() {
            content.push_str(Self::GENERIC_OCSF_PREPARE_BLOCK);
        }
        content
    }

    /// Write the static pipeline config (generic parser, normalization, clickhouse mapping, sink)
    ///
    /// In distributed deployments (K8s), the base ConfigMap only has sources/auth/source_type_extract.
    /// The entire routing->parsing->normalization->sink pipeline must be in the S3-synced directory
    /// so it arrives on Vector pods alongside the dynamic router and parser configs.
    pub(super) async fn write_pipeline_config(&self) -> Result<(), VectorConfigError> {
        let pipeline_path = self.parsers_dir.join("_pipeline.toml");
        fs::write(&pipeline_path, Self::full_pipeline_config_content()).await?;
        tracing::info!(
            "Generated static pipeline config at {}",
            pipeline_path.display()
        );
        Ok(())
    }

    /// Returns the push enrichment lane config (NAN-1124): per-kind normalize
    /// transforms + dedicated ClickHouse sinks consuming the
    /// `enrichment_router.<kind>` outputs. Single source of truth is the
    /// committed `_enrichment.toml`, embedded via `include_str!` so it ships in
    /// the binary and reaches every deployment (dev/compose mounted, Rackspace
    /// GCS-synced, SaaS dynamic ConfigMap) through the same path as
    /// `_pipeline.toml`. No drift: the const IS the file.
    pub(super) fn enrichment_lane_content() -> &'static str {
        include_str!("../../../../config/vector/sources/parsers/_enrichment.toml")
    }

    /// Write the push enrichment lane config alongside the static pipeline.
    /// Must land in parsers_dir so distributed deploys sync it to Vector pods
    /// alongside the dynamic router + pipeline (NAN-1124).
    ///
    /// NAN-1149: when one or more enabled enrichment parsers are deployed, the
    /// lane is GENERATED from their `normalize_vrl` (the mapping is no longer
    /// hard-coded in the binary). With no enrichment parsers it falls back to the
    /// committed static lane verbatim — so deployments that haven't adopted
    /// dynamic enrichment parsers keep the identity lane exactly as before.
    pub(super) async fn write_enrichment_config(
        &self,
        enrichment_parsers: &[Parser],
    ) -> Result<(), VectorConfigError> {
        let enrichment_path = self.parsers_dir.join("_enrichment.toml");
        let content = Self::enrichment_lane_config(enrichment_parsers);

        // NAN-1150: deploy-time guardrails — reject a malformed enrichment lane
        // BEFORE Vector reloads, so a bad parser can never corrupt the dict and
        // halt logs ingestion (NAN-1120 class).
        Self::guard_enrichment_lane(enrichment_parsers, &content)?;

        fs::write(&enrichment_path, &content).await?;
        tracing::info!(
            "Generated push enrichment lane config at {} ({} enrichment parser(s))",
            enrichment_path.display(),
            enrichment_parsers.iter().filter(|p| p.enabled).count()
        );
        Ok(())
    }

    /// NAN-1150 deploy-time guardrails for the generated enrichment lane:
    /// (1) each enabled parser's `normalize_vrl` must pass the source-text
    /// security checks (`'''` / TOML-header / blocked-function breakout) AND
    /// compile + satisfy the `user_registry` encoding contract (NAN-1123),
    /// (2) `target_table` / `enrich_source` are interpolated into the generated
    /// TOML/VRL, so they must be safe identifiers (NAN-1197), (3) the generated
    /// lane's component topology must be exactly what the generator intended —
    /// no injected transform/sink (NAN-1197), and (4) the candidate lane TOML
    /// must not introduce a sink that backpressures the shared ingest upstream
    /// (NAN-1114/1128). Returns `ValidationFailed` with a clear, parser-named
    /// reason on the first violation.
    pub(super) fn guard_enrichment_lane(
        enrichment_parsers: &[Parser],
        candidate_toml: &str,
    ) -> Result<(), VectorConfigError> {
        let validator = crate::parsers::validator::VrlValidator::new();
        for p in enrichment_parsers.iter().filter(|p| p.enabled) {
            let vrl = p.normalize_vrl.as_deref().unwrap_or("");

            // NAN-1197: `normalize_vrl` is embedded verbatim into the lane's
            // `source = '''…'''` TOML literal. Reject a `'''` / TOML-header /
            // blocked-function breakout BEFORE it can append a sink/transform —
            // the encoding contract below only compiles + checks output shape.
            validator.check_normalize_vrl_safety(vrl).map_err(|e| {
                VectorConfigError::ValidationFailed(format!(
                    "enrichment parser '{}' rejected at deploy: unsafe normalize VRL: {e}",
                    p.name
                ))
            })?;

            // NAN-1197: `target_table` is interpolated raw into `table = "{…}"`
            // and the sink component id — require a ClickHouse identifier
            // (optionally db-qualified) so it can't break the TOML string.
            if let Some(table) = p.target_table.as_deref() {
                if !is_valid_ch_table_ident(table) {
                    return Err(VectorConfigError::ValidationFailed(format!(
                        "enrichment parser '{}' rejected at deploy: invalid target_table {table:?} \
                         (expected a ClickHouse identifier, optionally db-qualified)",
                        p.name
                    )));
                }
            }

            // NAN-1197: `enrich_source` is interpolated into the router VRL
            // comparison literal; require a safe discriminator token.
            if let Some(src) = p.enrich_source.as_deref() {
                if !src.is_empty() && !is_safe_enrich_source(src) {
                    return Err(VectorConfigError::ValidationFailed(format!(
                        "enrichment parser '{}' rejected at deploy: unsafe enrich_source {src:?}",
                        p.name
                    )));
                }
            }

            let kind = p.enrich_kind.as_deref().unwrap_or("identity");
            crate::parsers::validator::validate_enrichment_encoding_contract(kind, vrl).map_err(
                |e| {
                    VectorConfigError::ValidationFailed(format!(
                        "enrichment parser '{}' rejected at deploy: {e}",
                        p.name
                    ))
                },
            )?;
        }

        // NAN-1197: defense-in-depth — on the GENERATED path, assert the lane's
        // component topology matches exactly what `generate_enrichment_lane`
        // emits (only `enrichment_normalize_*` remaps and ClickHouse/blackhole
        // sinks). Skipped for the trusted committed static fallback (no enabled
        // parsers), whose shape is fixed at build time.
        if enrichment_parsers.iter().any(|p| p.enabled) {
            assert_enrichment_lane_topology(candidate_toml).map_err(|e| {
                VectorConfigError::ValidationFailed(format!(
                    "enrichment lane failed topology check (NAN-1197): {e}"
                ))
            })?;
        }

        let backpressure = enrichment_lane_backpressure_violations(candidate_toml);
        if !backpressure.is_empty() {
            return Err(VectorConfigError::ValidationFailed(format!(
                "enrichment lane would backpressure shared ingest (NAN-1114): {}",
                backpressure.join("; ")
            )));
        }
        Ok(())
    }

    /// The enrichment lane TOML for a set of enrichment parsers: generated
    /// per-source from the enabled ones, or the committed static lane verbatim
    /// when none are enabled (behaviour-preserving fallback). NAN-1151: shared by
    /// the active writer (`write_enrichment_config`) and the staging writer
    /// (`staging::write_staged_enrichment_config`) so the stage→promote path
    /// deploys the SAME dynamic lane as startup `deploy_to_vector` — without this
    /// the `/deploy` endpoint promoted the static lane and silently reverted
    /// per-source enrichment parsers.
    pub(super) fn enrichment_lane_config(enrichment_parsers: &[Parser]) -> String {
        let enabled: Vec<&Parser> = enrichment_parsers.iter().filter(|p| p.enabled).collect();
        if enabled.is_empty() {
            Self::enrichment_lane_content().to_string()
        } else {
            Self::generate_enrichment_lane(&enabled)
        }
    }

    /// Generate the push enrichment lane from deployed enrichment parsers
    /// (NAN-1149). One `[transforms.enrichment_normalize_<enrich_kind>]` per
    /// parser (keyed by `enrich_kind`; P1 assumes one parser per kind), each
    /// feeding a dedicated ClickHouse sink per `target_table`, plus a metered
    /// dead-letter sink unioning every normalize's `.dropped` output. The sink
    /// discipline (memory buffer + `drop_newest` + acks off) matches
    /// `clickhouse_logs` so an enrichment sink can never backpressure the shared
    /// ingest upstream (NAN-1114); the `shared_ingest_source_sinks_must_not_backpressure`
    /// lint covers this. Shape mirrors the committed `_enrichment.toml` so a
    /// single identity parser regenerates an equivalent lane.
    fn generate_enrichment_lane(parsers: &[&Parser]) -> String {
        use std::collections::BTreeMap;

        let mut out = String::from(
            "# =============================================================================\n\
             # NAN-1149: Push enrichment lane (GENERATED from deployed enrichment parsers)\n\
             # DO NOT EDIT - regenerated on every parser deploy.\n\
             # =============================================================================\n\n",
        );

        // target_table -> normalize transforms feeding its sink.
        let mut by_table: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut dropped_inputs: Vec<String> = Vec::new();
        let mut seen_sources: std::collections::HashSet<String> = std::collections::HashSet::new();

        for p in parsers {
            // NAN-1151: one normalize transform per `enrich_source`, so multiple
            // sources of the same kind (e.g. `ad` + `entra`, both identity) each
            // carry their own VRL. The route name + transform suffix go through
            // the same `enrichment_route_name` the router uses, so the
            // `enrichment_router.<source>` input always resolves. MUST key on the
            // same field the router emits routes for (`enrich_source`) — a parser
            // without one produces neither a route nor a transform here, so a
            // missing source can't strand a transform on a dangling router input.
            let source = match p.enrich_source.as_deref().filter(|s| !s.is_empty()) {
                Some(s) => s,
                None => {
                    tracing::warn!(
                        parser = %p.name,
                        "enrichment parser has no enrich_source; skipping (no lane route)"
                    );
                    continue;
                }
            };
            let route = super::router::enrichment_route_name(source);
            // Skip duplicate sources rather than emit a duplicate transform name
            // that would break the Vector reload.
            if !seen_sources.insert(route.clone()) {
                continue;
            }
            let transform = format!("enrichment_normalize_{route}");
            let vrl = p.normalize_vrl.as_deref().unwrap_or("");
            let table = p.target_table.as_deref().unwrap_or("user_registry").to_string();

            out.push_str(&format!(
                "[transforms.{transform}]\n\
                 type = \"remap\"\n\
                 inputs = [\"enrichment_router.{route}\"]\n\
                 drop_on_abort = true\n\
                 drop_on_error = true\n\
                 reroute_dropped = true\n\
                 source = '''\n{vrl}\n'''\n\n"
            ));

            by_table.entry(table).or_default().push(format!("\"{transform}\""));
            dropped_inputs.push(format!("\"{transform}.dropped\""));
        }

        for (table, inputs) in &by_table {
            // Sanitize the sink component id (a db-qualified or hyphenated
            // target_table would otherwise produce an invalid Vector component
            // name). `user_registry` is unchanged; the `table =` value stays raw.
            let sink = format!("clickhouse_{}", Self::safe_name(table));
            out.push_str(&format!(
                "[sinks.{sink}]\n\
                 type = \"clickhouse\"\n\
                 inputs = [{inputs}]\n\
                 endpoint = \"${{CLICKHOUSE_URL:-http://clickhouse:8123}}\"\n\
                 database = \"${{CLICKHOUSE_DATABASE:-nanosiem}}\"\n\
                 table = \"{table}\"\n\
                 auth.strategy = \"basic\"\n\
                 auth.user = \"${{CLICKHOUSE_USER:-nanosiem}}\"\n\
                 auth.password = \"${{CLICKHOUSE_PASSWORD:-nanosiem}}\"\n\
                 compression = \"gzip\"\n\
                 date_time_best_effort = true\n\
                 skip_unknown_fields = true\n\n\
                 [sinks.{sink}.buffer]\n\
                 type = \"memory\"\n\
                 max_events = 50000\n\
                 when_full = \"drop_newest\"\n\n\
                 [sinks.{sink}.acknowledgements]\n\
                 enabled = false\n\n\
                 [sinks.{sink}.batch]\n\
                 max_events = 1000\n\
                 timeout_secs = 5\n\n\
                 [sinks.{sink}.request]\n\
                 concurrency = \"adaptive\"\n\
                 timeout_secs = 60\n\
                 retry_initial_backoff_secs = 1\n\
                 retry_max_duration_secs = 60\n\n",
                inputs = inputs.join(", "),
            ));
        }

        out.push_str(&format!(
            "[sinks.enrichment_dead_letter]\n\
             type = \"blackhole\"\n\
             inputs = [{}]\n\
             print_interval_secs = 0\n",
            dropped_inputs.join(", ")
        ));

        out
    }

    /// Signal Vector to reload its configuration
    ///
    /// Note: If Vector is running with --watch-config, it will auto-reload when files change.
    /// This function is a fallback for deployments without --watch-config.
    pub async fn reload_vector(&self) -> Result<(), VectorConfigError> {
        // Give the filesystem a moment to sync (helps with Docker volume mounts)
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Method 1: Docker exec (for containerized Vector without --watch-config)
        let container_name = std::env::var("VECTOR_CONTAINER_NAME")
            .unwrap_or_else(|_| "nanosiem-vector".to_string());

        let docker_result = Command::new("docker")
            .args(["exec", &container_name, "pkill", "-HUP", "vector"])
            .output()
            .await;

        if let Ok(output) = docker_result {
            if output.status.success() {
                tracing::info!("Sent SIGHUP to Vector via docker exec");
                return Ok(());
            }
            // Docker exec failed - Vector might be using --watch-config or not in Docker
            tracing::debug!(
                "docker exec failed (Vector may use --watch-config or not be in Docker): {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Method 2: Direct SIGHUP (for non-containerized Vector without --watch-config)
        #[cfg(unix)]
        {
            let pkill_result = Command::new("pkill")
                .args(["-HUP", "vector"])
                .output()
                .await;

            if let Ok(output) = pkill_result {
                if output.status.success() {
                    tracing::info!("Sent SIGHUP to local Vector process");
                    return Ok(());
                }
            }
        }

        // If explicit reload methods fail, Vector should pick up changes via --watch-config
        tracing::info!("Config written - Vector will auto-reload if using --watch-config");
        Ok(())
    }

    /// Deploy parsers and reload Vector (serialized via deploy lock)
    ///
    /// Acquires the deploy mutex to prevent concurrent deploys from corrupting
    /// config or overwriting each other's backups. All config files are written
    /// atomically before a single reload signal is sent.
    pub async fn deploy_and_reload(&self, parsers: &[Parser]) -> Result<(), VectorConfigError> {
        let _guard = self.deploy_lock.lock().await;
        self.deploy_parsers(parsers).await?;
        self.reload_vector().await?;
        Ok(())
    }

    /// Render a complete parser tree without signaling a live Vector process.
    /// Used by the DB-backed publication reconciler, which renders into an
    /// isolated directory before the revision CAS makes it visible.
    pub async fn render_parsers(&self, parsers: &[Parser]) -> Result<(), VectorConfigError> {
        let _guard = self.deploy_lock.lock().await;
        self.deploy_parsers(parsers).await
    }

    /// Check if Vector is healthy by querying its internal API or checking process status.
    ///
    /// Vector exposes a health endpoint at http://localhost:8686/health when
    /// the API is enabled. Falls back to checking if the process is running.
    pub async fn check_vector_health(&self) -> bool {
        // Method 1: Check Vector's API health endpoint (requires --api flag)
        let api_url = std::env::var("VECTOR_API_URL")
            .unwrap_or_else(|_| "http://localhost:8686/health".to_string());

        if let Ok(output) = Command::new("curl")
            .args(["-sf", "--max-time", "2", &api_url])
            .output()
            .await
        {
            if output.status.success() {
                return true;
            }
        }

        // Method 2: Check if Vector process exists (Docker)
        let container_name = std::env::var("VECTOR_CONTAINER_NAME")
            .unwrap_or_else(|_| "nanosiem-vector".to_string());

        if let Ok(output) = Command::new("docker")
            .args(["exec", &container_name, "pgrep", "-x", "vector"])
            .output()
            .await
        {
            if output.status.success() {
                return true;
            }
        }

        // Method 3: Check local process
        #[cfg(unix)]
        {
            if let Ok(output) = Command::new("pgrep").args(["-x", "vector"]).output().await {
                if output.status.success() {
                    return true;
                }
            }
        }

        false
    }

    /// Deploy parsers with post-deploy health verification and auto-rollback.
    ///
    /// After reload, polls Vector health for up to 10 seconds. If Vector becomes
    /// unhealthy (crash from bad config at runtime), automatically restores the
    /// backup config and reloads.
    pub async fn deploy_and_verify(&self, parsers: &[Parser]) -> Result<(), VectorConfigError> {
        let _guard = self.deploy_lock.lock().await;

        // Backup current config before deploy
        if let Err(e) = self.backup_current().await {
            tracing::warn!(
                "Failed to backup current config (continuing — may be first deploy): {}",
                e
            );
        }

        // Write all config files
        self.deploy_parsers(parsers).await?;

        // Single reload after all files are written (fixes multi-file race)
        self.reload_vector().await?;

        // Post-deploy health polling: check every 500ms for 10 seconds
        let mut healthy = false;
        for attempt in 0..20 {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            if self.check_vector_health().await {
                healthy = true;
                tracing::debug!("Vector health check passed (attempt {})", attempt + 1);
                break;
            }
            tracing::debug!("Vector health check failed (attempt {}/20)", attempt + 1);
        }

        if !healthy {
            tracing::error!("Vector unhealthy after deploy — auto-rolling back to previous config");

            // Restore backup
            if let Err(restore_err) = self.restore_backup().await {
                tracing::error!(
                    "Auto-rollback failed: {}. Manual intervention required.",
                    restore_err
                );
                return Err(VectorConfigError::ReloadFailed(
                    "Vector unhealthy after deploy and auto-rollback failed. Check Vector logs and config manually.".to_string()
                ));
            }

            // Reload with restored config
            if let Err(reload_err) = self.reload_vector().await {
                tracing::error!("Reload after rollback failed: {}", reload_err);
            }

            // Verify rollback restored health
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            if self.check_vector_health().await {
                tracing::info!("Auto-rollback successful — Vector is healthy with previous config");
            } else {
                tracing::error!(
                    "Vector still unhealthy after rollback — manual intervention required"
                );
            }

            return Err(VectorConfigError::ReloadFailed(
                "Vector became unhealthy after config deploy. Configuration has been automatically rolled back to the previous working state.".to_string()
            ));
        }

        tracing::info!("Deploy verified — Vector is healthy with new config");
        Ok(())
    }

    /// Get the path to the parsers directory
    pub fn parsers_dir(&self) -> &Path {
        &self.parsers_dir
    }
}

#[cfg(test)]
mod tests;
