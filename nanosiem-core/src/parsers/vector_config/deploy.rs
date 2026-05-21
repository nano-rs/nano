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

        for parser in parsers {
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
        self.write_combiner_config(parsers).await?;

        // Write the dynamic router config for routed parsers
        self.write_router_config(parsers).await?;

        // Write the static pipeline config (generic parser, mapping, sink)
        // In distributed deployments, these must be in parsers_dir to get S3-synced
        // to Vector pods alongside the dynamic router and parser configs.
        self.write_pipeline_config().await?;

        let enabled_count = parsers.iter().filter(|p| p.enabled).count();
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
}
