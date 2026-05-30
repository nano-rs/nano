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

    const INGEST_SOURCE_TYPES: &[&str] = &["http_server", "vector", "splunk_hec"];
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

. = {
    "timestamp": .udm.timestamp,
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
.process_hash = to_string(.process_hash) ?? ""
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
.file_hash = to_string(.file_hash) ?? ""
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
.dvc_ip = to_string(.dvc_ip) ?? ""
.dvc_mac = to_string(.dvc_mac) ?? ""

# Build ext JSON with all non-explicit fields
explicit_columns = [
    "id", "timestamp", "message", "metadata", "source_type", "namespace", "ingest_time", "_inserted_at",
    "src_ip", "dest_ip", "src_host", "dest_host", "src_port", "dest_port", "protocol",
    "bytes_in", "bytes_out", "packets_in", "packets_out", "direction", "src_mac", "dest_mac", "vlan",
    "user", "src_user", "dest_user", "user_id", "user_name", "user_domain", "user_type",
    "action", "status", "status_code", "result", "severity", "category",
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

    /// Write the static pipeline config (generic parser, normalization, clickhouse mapping, sink)
    ///
    /// In distributed deployments (K8s), the base ConfigMap only has sources/auth/source_type_extract.
    /// The entire routing->parsing->normalization->sink pipeline must be in the S3-synced directory
    /// so it arrives on Vector pods alongside the dynamic router and parser configs.
    pub(super) async fn write_pipeline_config(&self) -> Result<(), VectorConfigError> {
        let pipeline_path = self.parsers_dir.join("_pipeline.toml");
        fs::write(&pipeline_path, Self::pipeline_config_content()).await?;
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
    /// (1) each enabled parser's `normalize_vrl` must compile + satisfy the
    /// `user_registry` encoding contract (NAN-1123), and (2) the candidate lane
    /// TOML must not introduce a sink that backpressures the shared ingest
    /// upstream (NAN-1114/1128). Returns `ValidationFailed` with a clear,
    /// parser-named reason on the first violation.
    pub(super) fn guard_enrichment_lane(
        enrichment_parsers: &[Parser],
        candidate_toml: &str,
    ) -> Result<(), VectorConfigError> {
        for p in enrichment_parsers.iter().filter(|p| p.enabled) {
            let vrl = p.normalize_vrl.as_deref().unwrap_or("");
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
mod tests {
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
            source_config: serde_json::json!({}),
            parser_vrl: String::new(),
            output_fields: None,
            feed_id: None,
            credential_id: None,
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
            lane.contains("[sinks.clickhouse_user_registry]") && lane.contains("table = \"user_registry\""),
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
        assert!(!per_source.contains("downcase(to_string(.kind)"), "per-source block must not key by .kind");

        let fallback = enrichment_router_block(&[], "\"auth_check\"");
        assert!(
            fallback.contains("identity = 'downcase(to_string(.source_type) ?? \"\") == \"nano_enrich\" && downcase(to_string(.kind) ?? \"\") == \"identity\"'"),
            "empty parser list must fall back to legacy per-kind routes:\n{fallback}"
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

        // Empty → committed static lane verbatim.
        assert_eq!(
            VectorConfigManager::enrichment_lane_config(&[]),
            VectorConfigManager::enrichment_lane_content()
        );
        // Disabled-only → also static (no enabled parsers to generate from).
        let mut disabled = parser;
        disabled.enabled = false;
        assert_eq!(
            VectorConfigManager::enrichment_lane_config(&[disabled]),
            VectorConfigManager::enrichment_lane_content()
        );
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

        let content = include_str!("../../../../config/vector/02-hec-source.toml");
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
    /// BLOCKS (and reaches the shared http_ingest via enrichment_router) MUST be
    /// flagged — proving the guard isn't a silent no-op (NAN-1150).
    #[test]
    fn backpressure_guard_flags_a_blocking_enrichment_sink() {
        let bad = r#"
[transforms.enrichment_normalize_ad]
type = "remap"
inputs = ["enrichment_router.ad"]
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
            violations.iter().any(|v| v.contains("clickhouse_user_registry")),
            "a blocking + acking user_registry sink reaching the shared ingest must be flagged, got {violations:?}"
        );
    }
}
