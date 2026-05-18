// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source Configuration service for business logic

use sqlx::PgPool;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::OnceCell;
use uuid::Uuid;

use super::creds_backend::{CredsBackend, CredsBackendError};
use super::repository::{SourceConfigRepository, SourceConfigRepositoryError};
use super::types::{
    DeploymentResult, ListParams, NewRoutingRule, NewSourceConfiguration, RoutingRule,
    SourceConfigDeployment, SourceConfiguration, SourceConfigurationWithRules, UpdateRoutingRule,
    UpdateSourceConfiguration,
};
use crate::log_telemetry::repository::is_safe_source_type;
use crate::parsers::{base_router_inputs, redact_config_snapshot, CredentialRepository};

/// Reduce a Pub/Sub subscription value to its bare name. Vector's `gcp_pubsub`
/// source builds `projects/<p>/subscriptions/<n>` itself, so a fully-qualified
/// value would be double-prefixed and rejected with InvalidArgument by gRPC.
pub(crate) fn normalize_pubsub_subscription(raw: &str) -> &str {
    raw.rsplit_once("/subscriptions/")
        .map(|(_, name)| name)
        .unwrap_or(raw)
        .trim_matches('/')
}

#[derive(Error, Debug)]
pub enum SourceConfigServiceError {
    #[error("Repository error: {0}")]
    RepositoryError(#[from] SourceConfigRepositoryError),
    #[error("Source configuration not found: {0}")]
    NotFound(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Deployment failed: {0}")]
    DeploymentFailed(String),
    #[error("Credential error: {0}")]
    CredentialError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Credentials backend error: {0}")]
    CredsBackendError(#[from] CredsBackendError),
}

#[derive(Clone)]
pub struct SourceConfigService {
    repository: SourceConfigRepository,
    credential_repo: CredentialRepository,
    vector_config_dir: PathBuf,
    /// Absolute path where Vector reads source configs at runtime.
    /// Docker: /etc/vector/sources (shared volume)
    /// K8s: /etc/vector/dynamic (S3/GCS synced)
    vector_sources_runtime_path: String,
    /// Credential storage backend, initialized lazily on first use. Detection
    /// is async (reads SA token / makes K8s API client) so it can't run in
    /// the sync constructors. `OnceCell` doesn't cache failures, so transient
    /// init errors retry on the next call.
    creds_backend: Arc<OnceCell<CredsBackend>>,
}

impl SourceConfigService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            repository: SourceConfigRepository::new(pool.clone()),
            credential_repo: CredentialRepository::new(pool),
            vector_config_dir: PathBuf::from("config/vector"),
            vector_sources_runtime_path: Self::resolve_runtime_path(),
            creds_backend: Arc::new(OnceCell::new()),
        }
    }

    pub fn with_vector_config_dir(pool: PgPool, config_dir: impl AsRef<Path>) -> Self {
        Self {
            repository: SourceConfigRepository::new(pool.clone()),
            credential_repo: CredentialRepository::new(pool),
            vector_config_dir: config_dir.as_ref().to_path_buf(),
            vector_sources_runtime_path: Self::resolve_runtime_path(),
            creds_backend: Arc::new(OnceCell::new()),
        }
    }

    /// Resolve the runtime path where Vector reads dynamic source configs.
    /// In Docker: /etc/vector/sources (shared volume mount)
    /// In K8s: /etc/vector/dynamic (S3/GCS sync destination)
    fn resolve_runtime_path() -> String {
        std::env::var("VECTOR_SOURCES_RUNTIME_PATH")
            .unwrap_or_else(|_| "/etc/vector/sources".to_string())
    }

    /// Lazily resolve the credentials backend. K8s mode is auto-detected via
    /// the SA-token file; `VECTOR_CREDS_BACKEND=disk|k8s_secret` overrides.
    async fn creds_backend(&self) -> Result<&CredsBackend, SourceConfigServiceError> {
        self.creds_backend
            .get_or_try_init(|| async {
                CredsBackend::detect(
                    self.vector_config_dir.clone(),
                    self.vector_sources_runtime_path.clone(),
                )
                .await
            })
            .await
            .map_err(SourceConfigServiceError::from)
    }

    // ========================================================================
    // Source Configuration CRUD
    // ========================================================================

    /// List source configurations
    pub async fn list(
        &self,
        params: Option<ListParams>,
    ) -> Result<Vec<SourceConfiguration>, SourceConfigServiceError> {
        Ok(self.repository.list(params).await?)
    }

    /// Get a source configuration by ID
    pub async fn get(&self, id: Uuid) -> Result<SourceConfiguration, SourceConfigServiceError> {
        Ok(self.repository.get(id).await?)
    }

    /// Get a source configuration with its routing rules
    pub async fn get_with_rules(
        &self,
        id: Uuid,
    ) -> Result<SourceConfigurationWithRules, SourceConfigServiceError> {
        Ok(self.repository.get_with_rules(id).await?)
    }

    /// Create a new source configuration
    pub async fn create(
        &self,
        request: NewSourceConfiguration,
    ) -> Result<SourceConfiguration, SourceConfigServiceError> {
        // Validate config type
        if super::types::SourceConfigType::from_str(&request.config_type).is_none() {
            return Err(SourceConfigServiceError::InvalidConfig(format!(
                "Invalid config type: {}",
                request.config_type
            )));
        }

        // Reject control chars in the name. The name is interpolated raw into
        // the leading TOML comment of the generated config (e.g.
        // `# Auto-generated Vector configuration for source: <name>`); a `\n`
        // in the name would close the comment and let the rest of the value
        // be parsed as TOML structure, bypassing the structured-emission
        // defense (NAN-689 P0).
        Self::validate_name(&request.name)?;

        // Validate the connection_config payload for the chosen driver.
        // Defense-in-depth on top of structured TOML emission (NAN-689):
        // reject scalars carrying control chars / newlines that could close
        // a TOML or VRL string if a future generator change reintroduces
        // unescaped interpolation.
        Self::validate_connection_config(&request.config_type, &request.connection_config)?;

        // Validate credential exists if specified
        if let Some(cred_id) = request.credential_id {
            self.credential_repo
                .get(cred_id)
                .await
                .map_err(|e| SourceConfigServiceError::CredentialError(e.to_string()))?;
        }

        Ok(self.repository.create(request).await?)
    }

    /// Update a source configuration
    pub async fn update(
        &self,
        id: Uuid,
        request: UpdateSourceConfiguration,
    ) -> Result<SourceConfiguration, SourceConfigServiceError> {
        // Validate config type if provided
        if let Some(ref config_type) = request.config_type {
            if super::types::SourceConfigType::from_str(config_type).is_none() {
                return Err(SourceConfigServiceError::InvalidConfig(format!(
                    "Invalid config type: {}",
                    config_type
                )));
            }
        }

        // Renames go through the same control-char gate as creates (NAN-689).
        if let Some(ref name) = request.name {
            Self::validate_name(name)?;
        }

        // Validate the connection_config payload (when present) against the
        // effective driver: prefer the patched config_type, fall back to the
        // existing one when the patch only touches connection_config (NAN-689).
        if let Some(ref conn) = request.connection_config {
            let effective_type = match request.config_type.as_deref() {
                Some(ct) => ct.to_string(),
                None => self.repository.get(id).await?.config_type,
            };
            Self::validate_connection_config(&effective_type, conn)?;
        }

        // Validate credential exists if specified
        if let Some(cred_id) = request.credential_id {
            self.credential_repo
                .get(cred_id)
                .await
                .map_err(|e| SourceConfigServiceError::CredentialError(e.to_string()))?;
        }

        Ok(self.repository.update(id, request).await?)
    }

    /// Reject control chars / newlines in a source-config name. The name lands
    /// in the leading TOML comment of the generated config — anything that
    /// closes a comment line (newline / CR) lets subsequent characters be
    /// parsed as TOML structure, which the structured-emission defense
    /// can't catch.
    fn validate_name(name: &str) -> Result<(), SourceConfigServiceError> {
        if name.is_empty() {
            return Err(SourceConfigServiceError::InvalidConfig(
                "name must not be empty".to_string(),
            ));
        }
        if let Some(c) = name.chars().find(|c| Self::is_unsafe_scalar_char(*c)) {
            return Err(SourceConfigServiceError::InvalidConfig(format!(
                "name contains disallowed control character (U+{code:04X})",
                code = c as u32,
            )));
        }
        Ok(())
    }

    /// Per-driver validation of the `connection_config` JSON payload.
    ///
    /// Two layers (NAN-689):
    /// 1. **Structural** — known fields must be the right JSON type so the
    ///    generator's `as_str()` / `as_array()` calls don't silently fall
    ///    back to defaults on malformed input (e.g. a `bootstrap_servers`
    ///    object instead of a string).
    /// 2. **Character-level** — every string scalar (in known and unknown
    ///    fields, recursively) is rejected if it contains a newline,
    ///    carriage return, NUL, or any other ASCII control char besides
    ///    tab. These are the characters that could terminate a TOML or VRL
    ///    string literal if a future generator change reintroduces
    ///    unescaped interpolation.
    ///
    /// We deliberately do NOT reject `"` or `\` — `toml::Value::String`
    /// escapes them when serialising, and rejecting would break legitimate
    /// values like `s3://bucket-with-"quote"` (rare but valid in URLs).
    fn validate_connection_config(
        config_type: &str,
        conn: &serde_json::Value,
    ) -> Result<(), SourceConfigServiceError> {
        // Top-level must be an object (or null/missing — generators tolerate
        // missing fields). Reject arrays/strings/etc. at the root.
        if !conn.is_object() && !conn.is_null() {
            return Err(SourceConfigServiceError::InvalidConfig(
                "connection_config must be a JSON object".to_string(),
            ));
        }

        // Per-driver structural checks. Unknown drivers and system-level
        // (`http`, `vector`) skip structural validation — they don't
        // generate a source block from connection_config.
        match config_type {
            "kafka" => Self::validate_kafka_conn(conn)?,
            "aws_s3" => Self::validate_aws_s3_conn(conn)?,
            "gcp_pubsub" => Self::validate_gcp_pubsub_conn(conn)?,
            "splunk_hec" => Self::validate_splunk_hec_conn(conn)?,
            _ => {}
        }

        // Universal char-safety pass over every string scalar in the payload.
        Self::validate_safe_strings(conn, "connection_config")
    }

    fn validate_kafka_conn(conn: &serde_json::Value) -> Result<(), SourceConfigServiceError> {
        Self::expect_string_if_present(conn, "bootstrap_servers")?;
        Self::expect_string_if_present(conn, "group_id")?;
        Self::expect_string_if_present(conn, "auto_offset_reset")?;
        if let Some(topics) = conn.get("topics") {
            let arr = topics.as_array().ok_or_else(|| {
                SourceConfigServiceError::InvalidConfig(
                    "kafka connection_config.topics must be an array of strings".to_string(),
                )
            })?;
            for (i, t) in arr.iter().enumerate() {
                if !t.is_string() {
                    return Err(SourceConfigServiceError::InvalidConfig(format!(
                        "kafka connection_config.topics[{i}] must be a string"
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_aws_s3_conn(conn: &serde_json::Value) -> Result<(), SourceConfigServiceError> {
        Self::expect_string_if_present(conn, "sqs_queue_url")?;
        Self::expect_string_if_present(conn, "region")?;
        Self::expect_string_if_present(conn, "compression")?;
        Self::expect_string_if_present(conn, "endpoint")?;
        Ok(())
    }

    fn validate_gcp_pubsub_conn(conn: &serde_json::Value) -> Result<(), SourceConfigServiceError> {
        Self::expect_string_if_present(conn, "project")?;
        Self::expect_string_if_present(conn, "subscription")?;
        if let Some(d) = conn.get("ack_deadline_secs") {
            if !d.is_u64() && !d.is_null() {
                return Err(SourceConfigServiceError::InvalidConfig(
                    "gcp_pubsub connection_config.ack_deadline_secs must be a non-negative integer"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    fn validate_splunk_hec_conn(conn: &serde_json::Value) -> Result<(), SourceConfigServiceError> {
        Self::expect_string_if_present(conn, "address")?;
        if let Some(tokens) = conn.get("valid_tokens") {
            let arr = tokens.as_array().ok_or_else(|| {
                SourceConfigServiceError::InvalidConfig(
                    "splunk_hec connection_config.valid_tokens must be an array of strings"
                        .to_string(),
                )
            })?;
            for (i, t) in arr.iter().enumerate() {
                if !t.is_string() {
                    return Err(SourceConfigServiceError::InvalidConfig(format!(
                        "splunk_hec connection_config.valid_tokens[{i}] must be a string"
                    )));
                }
            }
        }
        Ok(())
    }

    /// If `key` is present in `conn`, require it to be a string (not number /
    /// object / array). Missing keys are allowed — generators apply defaults.
    fn expect_string_if_present(
        conn: &serde_json::Value,
        key: &str,
    ) -> Result<(), SourceConfigServiceError> {
        if let Some(v) = conn.get(key) {
            if !v.is_string() && !v.is_null() {
                return Err(SourceConfigServiceError::InvalidConfig(format!(
                    "connection_config.{key} must be a string"
                )));
            }
        }
        Ok(())
    }

    /// Recursively walk a JSON value and reject any string scalar that
    /// contains a newline / carriage return / NUL / other ASCII control
    /// char (tab is allowed). Path is used to produce a helpful error.
    fn validate_safe_strings(
        v: &serde_json::Value,
        path: &str,
    ) -> Result<(), SourceConfigServiceError> {
        match v {
            serde_json::Value::String(s) => {
                if let Some(c) = s.chars().find(|c| Self::is_unsafe_scalar_char(*c)) {
                    return Err(SourceConfigServiceError::InvalidConfig(format!(
                        "{path} contains disallowed control character (U+{code:04X})",
                        code = c as u32,
                    )));
                }
            }
            serde_json::Value::Array(arr) => {
                for (i, item) in arr.iter().enumerate() {
                    Self::validate_safe_strings(item, &format!("{path}[{i}]"))?;
                }
            }
            serde_json::Value::Object(map) => {
                for (k, val) in map {
                    // Reject control chars in keys too — they'd produce
                    // malformed TOML headers if interpolated unquoted.
                    if k.chars().any(Self::is_unsafe_scalar_char) {
                        return Err(SourceConfigServiceError::InvalidConfig(format!(
                            "{path} contains disallowed control character in key '{k}'"
                        )));
                    }
                    Self::validate_safe_strings(val, &format!("{path}.{k}"))?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn is_unsafe_scalar_char(c: char) -> bool {
        // Newlines, CR, NUL, all other C0 controls; DEL. Tab is allowed.
        matches!(c, '\n' | '\r' | '\0' | '\x7f') || (c.is_control() && c != '\t')
    }

    /// Delete a source configuration
    pub async fn delete(&self, id: Uuid) -> Result<(), SourceConfigServiceError> {
        // Undeploy first if deployed
        let config = self.repository.get(id).await?;
        if config.deployed {
            self.undeploy(id).await?;
        }

        // Remove config file
        let config_file = self.get_config_file_path(&config.name);
        if config_file.exists() {
            tokio::fs::remove_file(&config_file).await?;
        }

        Ok(self.repository.delete(id).await?)
    }

    /// Toggle enabled status
    pub async fn toggle(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<SourceConfiguration, SourceConfigServiceError> {
        Ok(self.repository.toggle_enabled(id, enabled).await?)
    }

    // ========================================================================
    // Routing Rules
    // ========================================================================

    /// List routing rules for a source configuration
    pub async fn list_rules(
        &self,
        source_configuration_id: Uuid,
    ) -> Result<Vec<RoutingRule>, SourceConfigServiceError> {
        Ok(self.repository.list_rules(source_configuration_id).await?)
    }

    /// List routing rules for many source configurations in one query.
    ///
    /// Replaces the N+1 `list_rules` pattern in handlers that enrich a list
    /// of configs (NAN-733). Configs with no rules are omitted from the map.
    pub async fn list_rules_for_configs(
        &self,
        ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, Vec<RoutingRule>>, SourceConfigServiceError> {
        Ok(self.repository.list_rules_for_configs(ids).await?)
    }

    /// Create a routing rule
    pub async fn create_rule(
        &self,
        source_configuration_id: Uuid,
        mut request: NewRoutingRule,
    ) -> Result<RoutingRule, SourceConfigServiceError> {
        // Validate match type
        if super::types::MatchType::from_str(&request.match_type).is_none() {
            return Err(SourceConfigServiceError::InvalidConfig(format!(
                "Invalid match type: {}",
                request.match_type
            )));
        }

        // Coerce + validate match_field/match_type for the parent's
        // config_type. Pull sources collapse non-default source_type rules to
        // default; everything non-default then has its match_field run through
        // the safe-VRL-path validator.
        let parent = self.repository.get(source_configuration_id).await?;
        Self::coerce_and_validate_match(
            &parent.config_type,
            &request.match_field,
            &mut request.match_type,
        )?;

        // Reject characters in match_value / target_source_type that would
        // produce invalid VRL once interpolated into the routing transform
        // (NAN-689 follow-up). vrl_escape handles `\` and `"`; these
        // write-time checks catch the cases vrl_escape can't:
        //   - control chars / newlines in any non-default rule (bare
        //     newlines in a VRL string fail the validation gate, so this
        //     is mainly UX);
        //   - single quotes in a regex pattern (would close the VRL raw
        //     string `r'…'`, which has no escape mechanism).
        Self::validate_routing_rule_values(
            &request.match_type,
            request.match_value.as_deref(),
            &request.target_source_type,
        )?;

        Ok(self
            .repository
            .create_rule(source_configuration_id, request)
            .await?)
    }

    /// Update a routing rule
    pub async fn update_rule(
        &self,
        rule_id: Uuid,
        mut request: UpdateRoutingRule,
    ) -> Result<RoutingRule, SourceConfigServiceError> {
        // Validate match type if provided
        if let Some(ref match_type) = request.match_type {
            if super::types::MatchType::from_str(match_type).is_none() {
                return Err(SourceConfigServiceError::InvalidConfig(format!(
                    "Invalid match type: {}",
                    match_type
                )));
            }
        }

        // Coerce + validate. We need both match_field and match_type to
        // decide; if either is missing from the patch we fall back to the
        // existing rule's value. We only run this when the patch touches one
        // of those fields (otherwise the existing rule is already valid).
        if request.match_type.is_some() || request.match_field.is_some() {
            let existing = self.repository.get_rule(rule_id).await?;
            let parent = self.repository.get(existing.source_configuration_id).await?;
            let effective_field = request
                .match_field
                .as_deref()
                .unwrap_or(&existing.match_field)
                .to_string();
            // Patch the match_type in-place (or seed it from existing so the
            // helper sees the post-coercion value); same for match_field if
            // not present in the patch.
            let mut effective_type = request
                .match_type
                .clone()
                .unwrap_or_else(|| existing.match_type.clone());
            Self::coerce_and_validate_match(
                &parent.config_type,
                &effective_field,
                &mut effective_type,
            )?;
            // Mirror any coercion back into the patch so it lands in the DB.
            if effective_type != existing.match_type {
                request.match_type = Some(effective_type);
            }
        }

        // Mirror create_rule: reject characters in match_value /
        // target_source_type that would produce invalid VRL once
        // interpolated into the routing transform (NAN-689 follow-up).
        // Only run when the patch touches a relevant field; otherwise the
        // existing rule is already valid.
        let patched_match_value = request.match_value.is_some();
        let patched_target = request.target_source_type.is_some();
        let patched_match_type = request.match_type.is_some();
        if patched_match_value || patched_target || patched_match_type {
            let existing = self.repository.get_rule(rule_id).await?;
            let effective_match_type = request
                .match_type
                .as_deref()
                .unwrap_or(&existing.match_type);
            let effective_match_value: Option<&str> = request
                .match_value
                .as_deref()
                .or(existing.match_value.as_deref());
            let effective_target = request
                .target_source_type
                .as_deref()
                .unwrap_or(&existing.target_source_type);
            Self::validate_routing_rule_values(
                effective_match_type,
                effective_match_value,
                effective_target,
            )?;
        }

        Ok(self.repository.update_rule(rule_id, request).await?)
    }

    /// Reject `match_value` / `target_source_type` shapes that the routing
    /// transform generator can't safely embed in VRL (NAN-689 hardening):
    ///
    /// - **Control chars** in either value: `vrl_escape` only handles `\`
    ///   and `"`; a stray newline produces VRL like `"abc<NL>def"` which
    ///   may parse but is almost certainly a user mistake. Failing fast at
    ///   write time gives a clear error instead of a generator-time skip
    ///   or a downstream Vector-load failure.
    /// - **`'` in a regex pattern**: VRL regex literals use raw-string
    ///   syntax `r'…'` with no escape mechanism, so `'` would close the
    ///   string. The generator currently skips-and-warns; surface it
    ///   here so users get immediate feedback at create/update time.
    ///
    /// Default-typed rules don't carry an interpolated value into VRL
    /// strings (the default branch only emits `target_source_type`), so
    /// the regex check is conditional on `match_type == "regex"`.
    fn validate_routing_rule_values(
        match_type: &str,
        match_value: Option<&str>,
        target_source_type: &str,
    ) -> Result<(), SourceConfigServiceError> {
        // target_source_type is interpolated into VRL string literals AND used
        // as the value compared against `.source_type` for routing — both at
        // ClickHouse query time (rollup IN clauses, sanitized but warns) and
        // at parser routing time. Restrict to the same allow-list the rollup
        // sanitizer uses so we reject the same values everywhere.
        if !is_safe_source_type(target_source_type) {
            return Err(SourceConfigServiceError::InvalidConfig(format!(
                "target_source_type {target_source_type:?} contains characters \
                 outside [A-Za-z0-9_-] or is empty"
            )));
        }
        if let Some(c) = target_source_type
            .chars()
            .find(|c| Self::is_unsafe_scalar_char(*c))
        {
            return Err(SourceConfigServiceError::InvalidConfig(format!(
                "target_source_type contains disallowed control character (U+{code:04X})",
                code = c as u32,
            )));
        }
        if let Some(value) = match_value {
            if let Some(c) = value.chars().find(|c| Self::is_unsafe_scalar_char(*c)) {
                return Err(SourceConfigServiceError::InvalidConfig(format!(
                    "match_value contains disallowed control character (U+{code:04X})",
                    code = c as u32,
                )));
            }
            if match_type == "regex" && value.contains('\'') {
                return Err(SourceConfigServiceError::InvalidConfig(
                    "regex match_value cannot contain a single quote — VRL raw-string \
                     literals (r'…') have no escape mechanism, so the rule could not be \
                     compiled into the routing transform"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Run NAN-648 coercion then NAN-649 strict-path validation on a
    /// `(match_field, match_type)` pair belonging to a config of `config_type`.
    ///
    /// Order matters: coercion runs first, so a rule that gets demoted to
    /// `default` (because its `match_field=source_type` shape would silently
    /// fall through on a pull source) skips validation, preserving the
    /// legacy "match_field=source_type, match_type=default" shape that
    /// existed in the wild before strict validation landed.
    ///
    /// `match_type` is mutated in place when coercion fires; callers should
    /// mirror the change back into their patch.
    fn coerce_and_validate_match(
        config_type: &str,
        match_field: &str,
        match_type: &mut String,
    ) -> Result<(), SourceConfigServiceError> {
        Self::coerce_pull_source_match_type(config_type, match_field, match_type);
        Self::validate_match_field_path(match_field, match_type)
    }

    /// Strict safe-VRL-path validator for `match_field`.
    ///
    /// `match_field` is interpolated unquoted into the generated VRL transform
    /// as `.{match_field}` (e.g. `attributes.source_type` becomes
    /// `.attributes.source_type`). To prevent injection of arbitrary VRL
    /// (whitespace, operators, string literals, …) we reject anything that
    /// isn't a strict identifier-dot-identifier path:
    ///
    /// - First segment: `[A-Za-z_][A-Za-z0-9_]*`
    /// - Subsequent segments separated by single `.`s, each an identifier
    /// - No leading/trailing dot, no double dots, no whitespace, no special
    ///   characters
    ///
    /// `default`-typed rules don't reach the field-interpolation path in the
    /// generator, so the validation is skipped for them — keeps the legacy
    /// "match_field=source_type, match_type=default" shape valid even though
    /// other parts of the codebase coerce buggy rules into it.
    ///
    /// Hand-rolled (vs. a `regex` static) to avoid pulling the `regex` crate
    /// just for one path and to surface a precise error message identifying
    /// the offending segment / character.
    fn validate_match_field_path(
        match_field: &str,
        match_type: &str,
    ) -> Result<(), SourceConfigServiceError> {
        if match_type == "default" {
            return Ok(());
        }
        if match_field.is_empty() {
            return Err(SourceConfigServiceError::InvalidConfig(
                "match_field cannot be empty".to_string(),
            ));
        }
        for segment in match_field.split('.') {
            Self::validate_path_segment(match_field, segment)?;
        }
        Ok(())
    }

    /// Validate a single dot-separated segment of a VRL path.
    /// Extracted from `validate_match_field_path` so the per-segment rules
    /// live in one place: non-empty, ASCII-identifier-start, identifier-body.
    fn validate_path_segment(
        match_field: &str,
        segment: &str,
    ) -> Result<(), SourceConfigServiceError> {
        if segment.is_empty() {
            return Err(SourceConfigServiceError::InvalidConfig(format!(
                "match_field '{match_field}' is not a valid VRL path: empty segment (leading, trailing, or double dot)",
            )));
        }
        let mut chars = segment.chars();
        // Non-empty by check above.
        let first = chars.next().expect("segment non-empty");
        if !(first.is_ascii_alphabetic() || first == '_') {
            return Err(SourceConfigServiceError::InvalidConfig(format!(
                "match_field '{match_field}' is not a valid VRL path: segment '{segment}' must start with a letter or underscore",
            )));
        }
        for c in chars {
            if !(c.is_ascii_alphanumeric() || c == '_') {
                return Err(SourceConfigServiceError::InvalidConfig(format!(
                    "match_field '{match_field}' is not a valid VRL path: invalid character '{c}' in segment '{segment}'",
                )));
            }
        }
        Ok(())
    }

    /// Returns true when the (config_type, match_field) combination is the
    /// known buggy shape: a non-system-level source whose rule matches on
    /// `.source_type`. Pub/Sub / Kafka / S3 / HEC events do not carry
    /// an inbound `.source_type` field, so such rules cannot fire.
    fn is_pull_source_source_type_match(config_type: &str, match_field: &str) -> bool {
        config_type != "http" && config_type != "vector" && match_field == "source_type"
    }

    /// Coerce `match_type` to `"default"` when the rule shape would otherwise
    /// silently fall through on a pull source. No-op for system-level sources
    /// or rules that already use `match_type == "default"`.
    fn coerce_pull_source_match_type(
        config_type: &str,
        match_field: &str,
        match_type: &mut String,
    ) {
        if Self::is_pull_source_source_type_match(config_type, match_field)
            && match_type != "default"
        {
            tracing::warn!(
                config_type = %config_type,
                from = %match_type,
                "coercing routing rule match_type to default for pull source (match_field=source_type cannot match inbound events)"
            );
            *match_type = "default".to_string();
        }
    }

    /// Delete a routing rule
    pub async fn delete_rule(&self, rule_id: Uuid) -> Result<(), SourceConfigServiceError> {
        Ok(self.repository.delete_rule(rule_id).await?)
    }

    /// Reorder routing rules
    pub async fn reorder_rules(
        &self,
        source_configuration_id: Uuid,
        rule_order: Vec<Uuid>,
    ) -> Result<Vec<RoutingRule>, SourceConfigServiceError> {
        Ok(self
            .repository
            .reorder_rules(source_configuration_id, rule_order)
            .await?)
    }

    // ========================================================================
    // Deployment
    // ========================================================================

    /// For config types whose ingest source is already running OOTB
    /// (declared in `config/vector/*.toml`), returns the upstream Vector
    /// transform name that the per-config routing transform should consume
    /// from. `None` for config types that own their own ingest source.
    ///
    /// `http` / `vector` → `source_type_extract` (HTTP /ingest + Vector→Vector
    /// share the source_type_extract pipeline tail).
    /// `splunk_hec` → `hec_normalize` (`splunk_hec_ingest` on :8088 is OOTB
    /// per NAN-836; redeclaring the source would claim the same port twice
    /// and abort Vector reload).
    fn system_intermediary_source(config_type: &str) -> Option<&'static str> {
        match config_type {
            "http" | "vector" => Some("source_type_extract"),
            "splunk_hec" => Some("hec_normalize"),
            _ => None,
        }
    }

    /// Whether a system-level source config has rules worth emitting to disk.
    ///
    /// HTTP/Vector default rules are passthrough no-ops (the routing transform
    /// emits `# passthrough — keep existing .source_type`), so a config with
    /// only defaults adds nothing — we skip the file write entirely.
    ///
    /// HEC inverts this: hec_normalize already set `.source_type` from the
    /// envelope's `sourcetype`, and the user's default rule's `target` is
    /// meant to override that. Even a single default rule is meaningful.
    fn has_meaningful_routing_rules(config: &SourceConfigurationWithRules) -> bool {
        if config.config.config_type == "splunk_hec" {
            !config.routing_rules.is_empty()
        } else {
            config
                .routing_rules
                .iter()
                .any(|r| r.match_type != "default")
        }
    }

    /// Deploy a source configuration to Vector
    pub async fn deploy(&self, id: Uuid) -> Result<DeploymentResult, SourceConfigServiceError> {
        let config_with_rules = self.repository.get_with_rules(id).await?;
        let config = &config_with_rules.config;

        // System-level sources (http, vector, splunk_hec) have their ingest
        // source declared in `config/vector/*.toml` and always running. We
        // don't generate a new source block — that would collide with the
        // OOTB one — only a routing transform that consumes from the upstream
        // intermediary (source_type_extract or hec_normalize).
        if let Some(intermediary_source) = Self::system_intermediary_source(&config.config_type) {
            let has_meaningful_rules = Self::has_meaningful_routing_rules(&config_with_rules);

            // HTTP/Vector use passthrough-default semantics: default rules
            // preserve the inbound .source_type. HEC inverts this — the
            // default rule's target is authoritative, so we pass
            // system_level=false to make `generate_routing_transform` emit it
            // as an unconditional assignment.
            let routing_default_passthrough = config.config_type != "splunk_hec";

            let vector_config = if has_meaningful_rules {
                let safe_name = Self::safe_name(&config.name);
                let route_name = format!("{}_route", safe_name);
                let routing_block = Self::generate_routing_transform(
                    &config_with_rules,
                    intermediary_source,
                    &route_name,
                    routing_default_passthrough,
                );
                let config_content = format!(
                    "# Auto-generated routing rules for system-level source: {}\n\
                     # DO NOT EDIT - changes will be overwritten\n\
                     # Generated at: {}\n\n\
                     {}",
                    config.name,
                    chrono::Utc::now().to_rfc3339(),
                    routing_block
                );

                // NAN-689 acceptance criterion #3: validate before
                // mark_deployed / router-update / file write. Failure path
                // records add_deployment("failure", reason) and aborts.
                if let Err(e) = Self::validate_generated_config(&config_content) {
                    let reason = e.to_string();
                    if let Err(audit_err) = self
                        .repository
                        .add_deployment(
                            id,
                            "deploy",
                            "failure",
                            Some(&reason),
                            Some(&config_content),
                        )
                        .await
                    {
                        tracing::error!(
                            error = %audit_err,
                            "failed to record deploy-failure deployment row — \
                             validation rejection will not appear in deployment history"
                        );
                    }
                    tracing::warn!(
                        config = %config.name,
                        error = %reason,
                        "rejecting deploy: generated Vector config failed validation"
                    );
                    return Err(e);
                }

                // Write config file so Vector picks up the routing transform
                let config_file = self.get_config_file_path(&config.name);
                let configs_dir = config_file.parent().unwrap();
                tokio::fs::create_dir_all(configs_dir).await?;
                tokio::fs::write(&config_file, &config_content).await?;
                Some(config_content)
            } else {
                None
            };

            self.repository.mark_deployed(id).await?;

            // Update dynamic router — include this config's route transform in inputs
            self.update_dynamic_router().await?;

            let snapshot = vector_config.as_deref().map(redact_config_snapshot);
            let deployment = self
                .repository
                .add_deployment(id, "deploy", "success", None, snapshot.as_deref())
                .await?;

            tracing::info!(
                "Deployed {} source configuration '{}' (system-level{})",
                config.config_type,
                config.name,
                if has_meaningful_rules {
                    ", with routing rules"
                } else {
                    ""
                }
            );

            return Ok(DeploymentResult {
                success: true,
                source_configuration_id: id,
                action: "deploy".to_string(),
                message: format!(
                    "Deployed '{}' successfully (system-level {} source{})",
                    config.name,
                    config.config_type,
                    if has_meaningful_rules {
                        " with routing rules"
                    } else {
                        ""
                    }
                ),
                deployment_id: Some(deployment.id),
            });
        }

        // Generate Vector config
        let vector_config = self.generate_vector_config(&config_with_rules).await?;

        // NAN-689 acceptance criterion #3: validate the generated config
        // (TOML parse + VRL compile) before any persistence side-effect.
        // No file write, no mark_deployed, no router update if validation
        // fails — and we record the failure for audit.
        if let Err(e) = Self::validate_generated_config(&vector_config) {
            let reason = e.to_string();
            if let Err(audit_err) = self
                .repository
                .add_deployment(
                    id,
                    "deploy",
                    "failure",
                    Some(&reason),
                    Some(&vector_config),
                )
                .await
            {
                tracing::error!(
                    error = %audit_err,
                    "failed to record deploy-failure deployment row — \
                     validation rejection will not appear in deployment history"
                );
            }
            tracing::warn!(
                config = %config.name,
                error = %reason,
                "rejecting deploy: generated Vector config failed validation"
            );
            return Err(e);
        }

        // Write config file
        let config_file = self.get_config_file_path(&config.name);
        let configs_dir = config_file.parent().unwrap();
        tokio::fs::create_dir_all(configs_dir).await?;
        tokio::fs::write(&config_file, &vector_config).await?;

        // Mark as deployed BEFORE updating router, so the router query includes this config
        self.repository.mark_deployed(id).await?;

        // Update dynamic router to include this source
        self.update_dynamic_router().await?;

        // Record deployment — snapshot the redacted view so deployment history
        // never leaks SASL passwords / AWS secret keys / HEC tokens to users
        // who only hold `source_configs:view`.
        let snapshot = redact_config_snapshot(&vector_config);
        let deployment = self
            .repository
            .add_deployment(id, "deploy", "success", None, Some(&snapshot))
            .await?;

        tracing::info!(
            "Deployed source configuration '{}' to {}",
            config.name,
            config_file.display()
        );

        Ok(DeploymentResult {
            success: true,
            source_configuration_id: id,
            action: "deploy".to_string(),
            message: format!("Deployed '{}' successfully", config.name),
            deployment_id: Some(deployment.id),
        })
    }

    /// Undeploy a source configuration from Vector
    pub async fn undeploy(&self, id: Uuid) -> Result<DeploymentResult, SourceConfigServiceError> {
        let config = self.repository.get(id).await?;

        // System-level sources (http, vector, splunk_hec) — remove the
        // routing config file if it was deployed; the OOTB source itself
        // keeps running. See `system_intermediary_source` for rationale.
        if Self::system_intermediary_source(&config.config_type).is_some() {
            let config_file = self.get_config_file_path(&config.name);
            if config_file.exists() {
                tokio::fs::remove_file(&config_file).await?;
            }
            self.repository.mark_undeployed(id).await?;

            // Update dynamic router (system-level types are filtered out, but ensures
            // other deployed configs have correct inputs)
            self.update_dynamic_router().await?;

            let deployment = self
                .repository
                .add_deployment(id, "undeploy", "success", None, None)
                .await?;

            tracing::info!(
                "Undeployed {} source configuration '{}' (system-level)",
                config.config_type,
                config.name
            );

            return Ok(DeploymentResult {
                success: true,
                source_configuration_id: id,
                action: "undeploy".to_string(),
                message: format!("Undeployed '{}' successfully", config.name),
                deployment_id: Some(deployment.id),
            });
        }

        // Remove config file
        let config_file = self.get_config_file_path(&config.name);
        if config_file.exists() {
            tokio::fs::remove_file(&config_file).await?;
        }

        // Reap stored credentials for source types that materialize them (so
        // renamed/deleted configs don't accumulate orphans on disk or in the
        // Secret). Idempotent in both backends.
        if config.config_type == "gcp_pubsub" {
            let safe_name = Self::safe_name(&config.name);
            let key = format!("gcp_{}.creds", safe_name);
            self.creds_backend().await?.remove_creds(&key).await?;
        }

        // Mark as undeployed BEFORE updating router, so the router query excludes this config
        self.repository.mark_undeployed(id).await?;

        // Update dynamic router to remove this source's route
        self.update_dynamic_router().await?;

        // Record deployment
        let deployment = self
            .repository
            .add_deployment(id, "undeploy", "success", None, None)
            .await?;

        tracing::info!("Undeployed source configuration '{}'", config.name);

        Ok(DeploymentResult {
            success: true,
            source_configuration_id: id,
            action: "undeploy".to_string(),
            message: format!("Undeployed '{}' successfully", config.name),
            deployment_id: Some(deployment.id),
        })
    }

    /// Deploy all enabled source configurations
    pub async fn deploy_all(&self) -> Result<Vec<DeploymentResult>, SourceConfigServiceError> {
        let configs = self.repository.list_enabled().await?;
        let mut results = Vec::new();

        for config in configs {
            match self.deploy(config.id).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    tracing::error!(
                        "Failed to deploy source configuration '{}': {}",
                        config.name,
                        e
                    );
                    results.push(DeploymentResult {
                        success: false,
                        source_configuration_id: config.id,
                        action: "deploy".to_string(),
                        message: e.to_string(),
                        deployment_id: None,
                    });
                }
            }
        }

        Ok(results)
    }

    /// Get deployment history
    pub async fn get_deployment_history(
        &self,
        id: Uuid,
        limit: Option<i64>,
    ) -> Result<Vec<SourceConfigDeployment>, SourceConfigServiceError> {
        Ok(self.repository.get_deployments(id, limit).await?)
    }

    // ========================================================================
    // Vector Config Generation
    // ========================================================================

    /// Generate Vector TOML config for a source configuration
    async fn generate_vector_config(
        &self,
        config: &SourceConfigurationWithRules,
    ) -> Result<String, SourceConfigServiceError> {
        let safe_name = Self::safe_name(&config.config.name);
        let source_name = format!("{}_source", safe_name);
        let route_name = format!("{}_route", safe_name);

        let mut toml = format!(
            "# Auto-generated Vector configuration for source: {}\n\
             # DO NOT EDIT - changes will be overwritten\n\
             # Generated at: {}\n\n",
            config.config.name,
            chrono::Utc::now().to_rfc3339()
        );

        // Generate source block
        let source_block = self.generate_source_block(config).await?;
        toml.push_str(&source_block);
        toml.push_str("\n");

        // Generate routing transform
        let routing_block =
            Self::generate_routing_transform(config, &source_name, &route_name, false);
        toml.push_str(&routing_block);

        Ok(toml)
    }

    /// Generate the Vector source block based on config type
    async fn generate_source_block(
        &self,
        config: &SourceConfigurationWithRules,
    ) -> Result<String, SourceConfigServiceError> {
        let safe_name = Self::safe_name(&config.config.name);
        let source_name = format!("{}_source", safe_name);
        let conn = &config.config.connection_config;

        // Get credentials if needed
        let creds = if let Some(cred_id) = config.config.credential_id {
            match self.credential_repo.get_decrypted(cred_id).await {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!("Failed to get credentials for source config: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // For GCP Pub/Sub, dispatch credential storage to the active backend.
        // K8s mode PATCHes the `vector-source-credentials` Secret (mounted at
        // /etc/vector/source-creds/); Docker mode writes flat under sources/
        // (NAN-664 layout). The backend returns the absolute path Vector should
        // embed in the generated TOML.
        let gcp_creds_path = if config.config.config_type == "gcp_pubsub" {
            if let Some(ref c) = creds {
                if let Some(creds_json) = c["credentials_json"].as_str() {
                    if !creds_json.is_empty() {
                        let key = format!("gcp_{}.creds", safe_name);
                        let backend = self.creds_backend().await?;
                        Some(backend.write_creds(&key, creds_json.as_bytes()).await?)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // System-level sources have their ingest declared in `config/vector/*.toml`
        // and don't need a per-config source block. See `system_intermediary_source`.
        if Self::system_intermediary_source(&config.config.config_type).is_some() {
            return Ok(String::new());
        }

        let source_block = match config.config.config_type.as_str() {
            "kafka" => Self::generate_kafka_source(&source_name, conn, creds.as_ref()),
            "aws_s3" => Self::generate_aws_s3_source(&source_name, conn, creds.as_ref()),
            "gcp_pubsub" => {
                Self::generate_gcp_pubsub_source(&source_name, conn, gcp_creds_path.as_deref())
            }
            _ => {
                return Err(SourceConfigServiceError::InvalidConfig(format!(
                    "Unknown config type: {}",
                    config.config.config_type
                )))
            }
        };

        Ok(source_block)
    }

    /// Build the `[sources.<name>]` block for a Kafka source.
    ///
    /// Uses `toml::Table` + `toml::to_string` so user-controlled scalars from
    /// `connection_config` and credentials are emitted as properly-escaped TOML
    /// strings. Hand-rolled `format!("\"{}\"", v)` previously allowed a `"` +
    /// newline in `bootstrap_servers` etc. to terminate the string and inject
    /// new TOML tables (NAN-689).
    fn generate_kafka_source(
        source_name: &str,
        conn: &serde_json::Value,
        creds: Option<&serde_json::Value>,
    ) -> String {
        let bootstrap_servers = conn["bootstrap_servers"]
            .as_str()
            .unwrap_or("localhost:9092");
        let topics: Vec<String> = conn["topics"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_else(|| vec!["logs".to_string()]);
        let group_id = conn["group_id"].as_str().unwrap_or("nanosiem");
        let auto_offset_reset = conn["auto_offset_reset"].as_str().unwrap_or("latest");

        let mut source = toml::Table::new();
        source.insert("type".into(), "kafka".into());
        source.insert("bootstrap_servers".into(), bootstrap_servers.into());
        source.insert(
            "topics".into(),
            toml::Value::Array(topics.into_iter().map(toml::Value::String).collect()),
        );
        source.insert("group_id".into(), group_id.into());
        source.insert("auto_offset_reset".into(), auto_offset_reset.into());

        // Add SASL config from credentials
        if let Some(c) = creds {
            if let Some(mechanism) = c["sasl_mechanism"].as_str() {
                if !mechanism.is_empty() {
                    let mut sasl = toml::Table::new();
                    sasl.insert("enabled".into(), true.into());
                    sasl.insert("mechanism".into(), mechanism.into());
                    sasl.insert(
                        "username".into(),
                        c["sasl_username"].as_str().unwrap_or("").into(),
                    );
                    sasl.insert(
                        "password".into(),
                        c["sasl_password"].as_str().unwrap_or("").into(),
                    );
                    source.insert("sasl".into(), toml::Value::Table(sasl));
                }
            }
        }

        Self::wrap_source_table(source_name, source)
    }

    /// Build the `[sources.<name>]` block for an AWS S3 / SQS source.
    /// See `generate_kafka_source` for the structured-emission rationale (NAN-689).
    fn generate_aws_s3_source(
        source_name: &str,
        conn: &serde_json::Value,
        creds: Option<&serde_json::Value>,
    ) -> String {
        let sqs_queue_url = conn["sqs_queue_url"].as_str().unwrap_or("");
        let region = conn["region"].as_str().unwrap_or("us-east-1");

        let mut source = toml::Table::new();
        source.insert("type".into(), "aws_s3".into());
        source.insert("region".into(), region.into());

        // Add compression if specified
        if let Some(compression) = conn["compression"].as_str() {
            source.insert("compression".into(), compression.into());
        }
        // Add endpoint if specified (for MinIO, etc.)
        if let Some(endpoint) = conn["endpoint"].as_str() {
            if !endpoint.is_empty() {
                source.insert("endpoint".into(), endpoint.into());
            }
        }

        let mut sqs = toml::Table::new();
        sqs.insert("queue_url".into(), sqs_queue_url.into());
        sqs.insert("poll_secs".into(), toml::Value::Integer(15));
        sqs.insert("delete_message".into(), true.into());
        source.insert("sqs".into(), toml::Value::Table(sqs));

        // Add AWS credentials
        if let Some(c) = creds {
            let access_key = c["access_key_id"].as_str().unwrap_or("");
            let secret_key = c["secret_access_key"].as_str().unwrap_or("");

            if !access_key.is_empty() && !secret_key.is_empty() {
                let mut auth = toml::Table::new();
                auth.insert("access_key_id".into(), access_key.into());
                auth.insert("secret_access_key".into(), secret_key.into());
                auth.insert("region".into(), region.into());
                if let Some(role) = c["assume_role_arn"].as_str() {
                    if !role.is_empty() {
                        auth.insert("assume_role".into(), role.into());
                    }
                }
                source.insert("auth".into(), toml::Value::Table(auth));
            }
        }

        Self::wrap_source_table(source_name, source)
    }

    /// Build the `[sources.<name>]` block for a GCP Pub/Sub source.
    /// See `generate_kafka_source` for the structured-emission rationale (NAN-689).
    fn generate_gcp_pubsub_source(
        source_name: &str,
        conn: &serde_json::Value,
        credentials_path: Option<&str>,
    ) -> String {
        let project = conn["project"].as_str().unwrap_or("");
        let subscription_raw = conn["subscription"].as_str().unwrap_or("");
        let subscription = normalize_pubsub_subscription(subscription_raw);
        let ack_deadline = conn["ack_deadline_secs"].as_u64().unwrap_or(600);

        let mut source = toml::Table::new();
        source.insert("type".into(), "gcp_pubsub".into());
        source.insert("project".into(), project.into());
        source.insert("subscription".into(), subscription.into());
        source.insert(
            "ack_deadline_secs".into(),
            toml::Value::Integer(ack_deadline as i64),
        );
        if let Some(path) = credentials_path {
            source.insert("credentials_path".into(), path.into());
        }

        Self::wrap_source_table(source_name, source)
    }

    /// Pre-deploy validation gate (NAN-689 acceptance criterion #3).
    ///
    /// Runs entirely in-process — no Docker / `vector validate` subprocess
    /// dependency, so it works in test and CI environments alike. Two
    /// checks:
    ///
    /// 1. **TOML parse.** `toml::from_str::<toml::Value>` rejects any
    ///    structurally-malformed config the generator might have produced.
    ///    With the structured emission (NAN-689) this should be infallible
    ///    for clean inputs, but we keep it as a regression guard against
    ///    future generator changes.
    /// 2. **VRL compile.** Every `transforms.<name>.source` value is
    ///    handed to `vrl::compiler::compile` against the standard VRL
    ///    function set — same check used for parser pipeline VRL
    ///    (`pipeline_config_vrl_blocks_compile`). Catches embedded VRL
    ///    that would otherwise fail at Vector load time and take ingestion
    ///    down for every tenant.
    ///
    /// On failure, returns `InvalidConfig` with the diagnostic. Callers
    /// are responsible for not writing the live config and for recording
    /// `add_deployment("failure", reason)`.
    fn validate_generated_config(toml_str: &str) -> Result<(), SourceConfigServiceError> {
        // 1. Structural TOML validity.
        let parsed: toml::Value = toml::from_str(toml_str).map_err(|e| {
            SourceConfigServiceError::InvalidConfig(format!(
                "generated Vector config is not valid TOML: {e}"
            ))
        })?;

        // 2. VRL compile every transforms.<name>.source we emitted.
        let transforms = match parsed.get("transforms").and_then(|t| t.as_table()) {
            Some(t) => t,
            None => return Ok(()),
        };
        let fns = vrl::stdlib::all();
        for (name, transform) in transforms {
            // Only `remap` transforms carry user-controlled VRL via the
            // `source` attribute. Other transform types (`route`, `filter`,
            // …) take static config we don't generate from user input.
            let is_remap = transform
                .get("type")
                .and_then(|v| v.as_str())
                .map(|t| t == "remap")
                .unwrap_or(false);
            if !is_remap {
                continue;
            }
            let source = match transform.get("source").and_then(|s| s.as_str()) {
                Some(s) => s,
                None => continue,
            };
            if let Err(diagnostics) = vrl::compiler::compile(source, &fns) {
                let formatted =
                    vrl::diagnostic::Formatter::new(source, diagnostics).to_string();
                return Err(SourceConfigServiceError::InvalidConfig(format!(
                    "generated VRL for transform '{name}' failed to compile:\n{formatted}"
                )));
            }
        }

        Ok(())
    }

    /// Serialize a single-source `toml::Table` under the `[sources.<name>]`
    /// header. We build a wrapper table so the TOML serializer emits the
    /// dotted header automatically and any nested tables (sasl, sqs, auth)
    /// land under `[sources.<name>.<sub>]` with proper escaping.
    fn wrap_source_table(source_name: &str, source: toml::Table) -> String {
        let mut sources = toml::Table::new();
        sources.insert(source_name.to_string(), toml::Value::Table(source));
        let mut root = toml::Table::new();
        root.insert("sources".to_string(), toml::Value::Table(sources));
        // toml::to_string is infallible for tables built from Value::String /
        // Integer / Bool / nested Table / Array<String>. Use `expect` so a
        // future regression that introduces an unsupported value type fails
        // loudly in tests rather than silently emitting an empty source
        // block (which the validation gate would then accept).
        toml::to_string(&root).expect("source_configs TOML must serialize")
    }

    /// Generate the routing transform that applies rules.
    ///
    /// User-controlled `match_value` and `target_source_type` are interpolated
    /// into VRL string literals; VRL-escape `\` and `"` so they can't break out
    /// (NAN-689 hardening — same injection class as the source-block fix).
    /// The resulting VRL is then placed into a `toml::Value::String`, so the
    /// TOML serializer escapes for us — the previous `'''…'''` literal allowed
    /// a value containing `'''` to terminate the TOML string and inject new
    /// tables.
    ///
    /// Regex-typed rules use VRL's raw-string syntax `r'…'`, which has no
    /// escape mechanism — a `'` in the pattern would close the raw string.
    /// We skip-and-warn such rules; tightening to write-time validation is a
    /// follow-up.
    fn generate_routing_transform(
        config: &SourceConfigurationWithRules,
        source_name: &str,
        route_name: &str,
        system_level: bool,
    ) -> String {
        let mut vrl = String::from("# Apply routing rules to set source_type\n");

        // Sort rules by priority
        let mut rules: Vec<_> = config.routing_rules.iter().collect();
        rules.sort_by_key(|r| r.priority);

        let mut first = true;
        for rule in &rules {
            if rule.match_type == "default" {
                continue; // Handle default separately
            }

            // Pull sources have no inbound `.source_type` on events, so a
            // non-default rule matching on source_type can never fire — emitting
            // it would produce an always-false `if .source_type == "X"` block
            // followed by an else-fallthrough to "unknown". Skip it here and
            // fold it into the default below.
            if !system_level && rule.match_field == "source_type" {
                continue;
            }

            // `match_field` is validated at write-time to a safe VRL path
            // (`validate_match_field_path` — see create_rule/update_rule), so
            // straight string interpolation here is safe. Nested paths
            // (e.g. `attributes.source_type`) emit as `.attributes.source_type`
            // — exactly the dotted access VRL expects.
            let field = format!(".{}", rule.match_field);
            let raw_value = rule.match_value.as_deref().unwrap_or("");

            let condition = match rule.match_type.as_str() {
                "exact" => format!("{} == \"{}\"", field, Self::vrl_escape(raw_value)),
                "prefix" => {
                    format!("starts_with({}, \"{}\")", field, Self::vrl_escape(raw_value))
                }
                "suffix" => {
                    format!("ends_with({}, \"{}\")", field, Self::vrl_escape(raw_value))
                }
                "contains" => {
                    format!("contains({}, \"{}\")", field, Self::vrl_escape(raw_value))
                }
                "regex" => {
                    let pattern = if raw_value.is_empty() { ".*" } else { raw_value };
                    if pattern.contains('\'') {
                        tracing::warn!(
                            rule_id = %rule.id,
                            "skipping regex rule with single-quote in pattern (would close VRL raw string)"
                        );
                        continue;
                    }
                    format!("match({}, r'{}')", field, pattern)
                }
                _ => continue,
            };

            let target = Self::vrl_escape(&rule.target_source_type);
            if first {
                vrl.push_str(&format!(
                    "if {} {{\n    .source_type = \"{}\"\n}}",
                    condition, target
                ));
                first = false;
            } else {
                vrl.push_str(&format!(
                    " else if {} {{\n    .source_type = \"{}\"\n}}",
                    condition, target
                ));
            }
        }

        // Find default rule or use fallback.
        // System-level sources (http, vector) act as intermediaries for ALL events,
        // so unmatched events must preserve their existing source_type (passthrough).
        // Non-system sources default to "unknown" for unmatched events.
        let default_source_type: String = if system_level {
            // System-level sources MUST passthrough — a default rule with "unknown"
            // would clobber every source type not explicitly listed in the routing rules.
            "${source_type}".to_string()
        } else {
            let default_rule = rules.iter().find(|r| r.match_type == "default");
            // Fallback: when a pull-source rule was saved with the buggy shape
            // (match_field=source_type + non-default match_type), the user's
            // intent is "route everything to <target_source_type>". Use the
            // first such rule's target as the default if no explicit default
            // exists. Sorted-by-priority order is preserved from `rules`.
            let coalesced_rule = rules
                .iter()
                .find(|r| r.match_field == "source_type" && r.match_type != "default");
            Self::vrl_escape(
                default_rule
                    .or(coalesced_rule)
                    .map(|r| r.target_source_type.as_str())
                    .unwrap_or("unknown"),
            )
        };

        if !first {
            if default_source_type == "${source_type}" {
                // Passthrough: preserve existing .source_type from the event
                vrl.push_str("\n# else: passthrough — keep existing .source_type\n");
            } else {
                vrl.push_str(&format!(
                    " else {{\n    .source_type = \"{}\"\n}}\n",
                    default_source_type
                ));
            }
        } else if default_source_type == "${source_type}" {
            // Passthrough: preserve existing .source_type from the event
            vrl.push_str("# passthrough: keep existing .source_type\n");
        } else {
            vrl.push_str(&format!(".source_type = \"{}\"\n", default_source_type));
        }

        let mut transform = toml::Table::new();
        transform.insert("type".into(), "remap".into());
        transform.insert(
            "inputs".into(),
            toml::Value::Array(vec![toml::Value::String(source_name.to_string())]),
        );
        transform.insert("source".into(), toml::Value::String(vrl));

        let mut transforms = toml::Table::new();
        transforms.insert(route_name.to_string(), toml::Value::Table(transform));
        let mut root = toml::Table::new();
        root.insert("transforms".to_string(), toml::Value::Table(transforms));
        toml::to_string(&root).expect("routing transform TOML must serialize")
    }

    /// Escape a value for embedding inside a double-quoted VRL string literal:
    /// `\` → `\\`, `"` → `\"`. The surrounding TOML basic-string literal
    /// applies its own escaping on top.
    fn vrl_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for ch in s.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                _ => out.push(ch),
            }
        }
        out
    }

    /// Build the ordered `inputs = [...]` list for the source_router transform.
    ///
    /// Pure function over deployed source configs; takes a closure for the
    /// filesystem check so it stays testable without touching disk.
    /// `is_system_route_deployed_on_disk` returns true when a system-level
    /// (http/vector/splunk_hec) config has its routing TOML present — only
    /// then does it contribute a route and suppress its corresponding
    /// always-on channel from base inputs.
    fn compute_router_inputs<F>(
        deployed_configs: &[SourceConfiguration],
        is_system_route_deployed_on_disk: F,
    ) -> Vec<String>
    where
        F: Fn(&str) -> bool,
    {
        let mut source_type_extract_covered = false;
        let mut hec_normalize_covered = false;
        let mut source_config_routes: Vec<String> = Vec::new();

        for config in deployed_configs {
            // System-level configs only contribute a route to source_router
            // inputs when their routing TOML actually exists on disk. Without
            // this guard, a `mark_deployed` row whose file got skipped would
            // reference a transform that doesn't exist and abort Vector reload.
            if let Some(intermediary) = Self::system_intermediary_source(&config.config_type) {
                if !is_system_route_deployed_on_disk(&config.name) {
                    continue;
                }
                // The per-config route intermediates this always-on channel
                // (consumes from it, feeds source_router). Suppress the
                // channel from base inputs so events don't reach source_router
                // twice — once via the direct base input, once via the route.
                match intermediary {
                    "source_type_extract" => source_type_extract_covered = true,
                    "hec_normalize" => hec_normalize_covered = true,
                    _ => {}
                }
            }
            let safe_name = Self::safe_name(&config.name);
            source_config_routes.push(format!("{}_route", safe_name));
        }

        let mut router_inputs: Vec<String> =
            base_router_inputs(source_type_extract_covered, hec_normalize_covered)
                .into_iter()
                .map(String::from)
                .collect();
        router_inputs.extend(source_config_routes);
        router_inputs
    }

    /// Update the dynamic router to include all source configuration routes
    async fn update_dynamic_router(&self) -> Result<(), SourceConfigServiceError> {
        // Get all deployed source configs
        let deployed_configs = self
            .repository
            .list(Some(ListParams {
                deployed: Some(true),
                ..Default::default()
            }))
            .await?;

        let router_inputs = Self::compute_router_inputs(&deployed_configs, |name| {
            self.get_config_file_path(name).exists()
        });

        let new_inputs_line = format!(
            "inputs = [{}]",
            router_inputs
                .iter()
                .map(|s| format!("\"{}\"", s))
                .collect::<Vec<_>>()
                .join(", ")
        );

        // Read the current dynamic router config (in parsers dir for S3/GCS sync)
        let router_path = self
            .vector_config_dir
            .join("sources")
            .join("parsers")
            .join("_router.toml");
        if !router_path.exists() {
            tracing::warn!(
                "Dynamic router config not found at {}, skipping update",
                router_path.display()
            );
            return Ok(());
        }

        let current_content = tokio::fs::read_to_string(&router_path).await?;

        // Replace the inputs line in the [transforms.source_router] section.
        // Match the first inputs = [...] line that appears after the source_router header.
        // We can't rely on "source_type_extract" being present since system-level routes
        // may have already removed it.
        let mut updated = String::new();
        let mut found = false;
        let mut in_source_router = false;
        for line in current_content.lines() {
            let trimmed = line.trim();
            if trimmed == "[transforms.source_router]" {
                in_source_router = true;
                updated.push_str(line);
                updated.push('\n');
            } else if in_source_router && !found && trimmed.starts_with("inputs = [") {
                // Replace this line with the new inputs
                // Preserve leading whitespace
                let leading_ws: String = line.chars().take_while(|c| c.is_whitespace()).collect();
                updated.push_str(&format!("{}{}\n", leading_ws, new_inputs_line));
                found = true;
                in_source_router = false;
            } else {
                updated.push_str(line);
                updated.push('\n');
            }
        }

        if found {
            tokio::fs::write(&router_path, &updated).await?;
            tracing::info!("Updated dynamic router inputs: {}", new_inputs_line);
        } else {
            tracing::warn!("Could not find source_router inputs line in _router.toml");
        }

        Ok(())
    }

    /// Get the path for a source config file
    fn get_config_file_path(&self, name: &str) -> PathBuf {
        let safe_name = Self::safe_name(name);
        self.vector_config_dir
            .join("sources")
            .join("configs")
            .join(format!("{}.toml", safe_name))
    }

    /// Convert name to safe identifier
    fn safe_name(name: &str) -> String {
        name.chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect::<String>()
            .to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::{RoutingRule, SourceConfiguration, SourceConfigurationWithRules};
    use chrono::Utc;
    use uuid::Uuid;

    fn make_config(config_type: &str, rules: Vec<RoutingRule>) -> SourceConfigurationWithRules {
        let now = Utc::now();
        SourceConfigurationWithRules {
            config: SourceConfiguration {
                id: Uuid::new_v4(),
                name: "test_source".to_string(),
                description: None,
                config_type: config_type.to_string(),
                connection_config: serde_json::json!({}),
                credential_id: None,
                enabled: true,
                deployed: false,
                deployed_at: None,
                created_at: now,
                updated_at: now,
                events_24h: None,
                bytes_per_day_24h: None,
                last_event_at: None,
            },
            routing_rules: rules,
        }
    }

    fn make_rule(
        priority: i32,
        match_field: &str,
        match_type: &str,
        match_value: Option<&str>,
        target: &str,
    ) -> RoutingRule {
        RoutingRule {
            id: Uuid::new_v4(),
            source_configuration_id: Uuid::nil(),
            priority,
            match_field: match_field.to_string(),
            match_type: match_type.to_string(),
            match_value: match_value.map(|s| s.to_string()),
            target_source_type: target.to_string(),
            created_at: Utc::now(),
            fires_24h: None,
            last_fired_at: None,
        }
    }

    /// Bug shape: pull-source rule with match_field=source_type +
    /// match_type=exact must coalesce into an unconditional default assignment,
    /// not the always-false `if .source_type == X` block.
    #[test]
    fn pull_source_with_buggy_source_type_rule_coalesces_to_default() {
        let config = make_config(
            "gcp_pubsub",
            vec![make_rule(
                10,
                "source_type",
                "exact",
                Some("limacharlie_edr"),
                "limacharlie_edr",
            )],
        );

        let vrl = SourceConfigService::generate_routing_transform(
            &config, "src", "route", false,
        );

        assert!(
            vrl.contains(".source_type = \"limacharlie_edr\""),
            "expected unconditional default assignment, got:\n{}",
            vrl
        );
        assert!(
            !vrl.contains("if .source_type =="),
            "expected no tautological if-block, got:\n{}",
            vrl
        );
        assert!(
            !vrl.contains("\"unknown\""),
            "expected no fallthrough to unknown, got:\n{}",
            vrl
        );
    }

    /// Regression guard: a properly-shaped pull-source default rule still
    /// emits the unconditional assignment.
    #[test]
    fn pull_source_with_proper_default_rule_emits_unconditional() {
        let config = make_config(
            "gcp_pubsub",
            vec![make_rule(1000, "source_type", "default", None, "limacharlie_edr")],
        );

        let vrl = SourceConfigService::generate_routing_transform(
            &config, "src", "route", false,
        );

        assert!(
            vrl.contains(".source_type = \"limacharlie_edr\""),
            "expected unconditional default assignment, got:\n{}",
            vrl
        );
        assert!(
            !vrl.contains("if "),
            "expected no conditional, got:\n{}",
            vrl
        );
    }

    /// Regression guard: pull-source rules matching on a real inbound field
    /// (Kafka topic) still emit the if-block as before.
    #[test]
    fn pull_source_with_native_field_match_emits_if_block() {
        let config = make_config(
            "kafka",
            vec![
                make_rule(10, "topic", "exact", Some("audit-logs"), "aws_cloudtrail"),
                make_rule(1000, "source_type", "default", None, "unknown"),
            ],
        );

        let vrl = SourceConfigService::generate_routing_transform(
            &config, "src", "route", false,
        );

        assert!(
            vrl.contains("if .topic == \"audit-logs\""),
            "expected topic conditional, got:\n{}",
            vrl
        );
        assert!(
            vrl.contains(".source_type = \"aws_cloudtrail\""),
            "expected matched-target assignment, got:\n{}",
            vrl
        );
        assert!(
            vrl.contains(".source_type = \"unknown\""),
            "expected unknown fallthrough, got:\n{}",
            vrl
        );
    }

    /// Regression guard: HTTP (system-level) sources keep their
    /// passthrough-unmatched semantics — match_field=source_type rules are
    /// legitimate here because the X-Source-Type header populates
    /// `.source_type` upstream.
    #[test]
    fn http_source_with_source_type_rules_preserves_passthrough() {
        let config = make_config(
            "http",
            vec![make_rule(
                10,
                "source_type",
                "exact",
                Some("aws_cloudtrail_raw"),
                "aws_cloudtrail",
            )],
        );

        let vrl = SourceConfigService::generate_routing_transform(
            &config, "source_type_extract", "route", true,
        );

        assert!(
            vrl.contains("if .source_type == \"aws_cloudtrail_raw\""),
            "expected source_type if-block for system-level source, got:\n{}",
            vrl
        );
        assert!(
            vrl.contains(".source_type = \"aws_cloudtrail\""),
            "expected matched-target assignment, got:\n{}",
            vrl
        );
        assert!(
            vrl.contains("passthrough"),
            "expected passthrough comment for system-level fallthrough, got:\n{}",
            vrl
        );
        // Must NOT degrade to the "unknown" default that pull sources use
        assert!(
            !vrl.contains(".source_type = \"unknown\""),
            "system-level source must not fallthrough to unknown, got:\n{}",
            vrl
        );
    }

    // ------------------------------------------------------------------
    // Coercion helpers (unit-level, no DB required)
    // ------------------------------------------------------------------

    #[test]
    fn coerce_pull_source_buggy_shape_to_default() {
        let mut mt = "exact".to_string();
        SourceConfigService::coerce_pull_source_match_type("gcp_pubsub", "source_type", &mut mt);
        assert_eq!(mt, "default");
    }

    #[test]
    fn coerce_leaves_native_field_untouched() {
        let mut mt = "exact".to_string();
        SourceConfigService::coerce_pull_source_match_type("kafka", "topic", &mut mt);
        assert_eq!(mt, "exact");
    }

    #[test]
    fn coerce_leaves_system_level_untouched() {
        let mut mt = "exact".to_string();
        SourceConfigService::coerce_pull_source_match_type("http", "source_type", &mut mt);
        assert_eq!(mt, "exact");

        let mut mt = "exact".to_string();
        SourceConfigService::coerce_pull_source_match_type("vector", "source_type", &mut mt);
        assert_eq!(mt, "exact");
    }

    #[test]
    fn coerce_leaves_already_default_untouched() {
        let mut mt = "default".to_string();
        SourceConfigService::coerce_pull_source_match_type("gcp_pubsub", "source_type", &mut mt);
        assert_eq!(mt, "default");
    }

    // ------------------------------------------------------------------
    // Nested-path generator (NAN-649): match_field=attributes.source_type
    // emits `if .attributes.source_type == "X"`, not the buggy single-segment
    // shape that pre-NAN-649 generators silently truncated to.
    // ------------------------------------------------------------------

    #[test]
    fn pull_source_with_nested_path_match_field_emits_dotted_access() {
        let config = make_config(
            "gcp_pubsub",
            vec![
                make_rule(
                    10,
                    "attributes.source_type",
                    "exact",
                    Some("limacharlie_edr"),
                    "limacharlie_edr",
                ),
                make_rule(1000, "subscription", "default", None, "unknown"),
            ],
        );

        let vrl = SourceConfigService::generate_routing_transform(&config, "src", "route", false);

        assert!(
            vrl.contains("if .attributes.source_type == \"limacharlie_edr\""),
            "expected dotted-path conditional, got:\n{vrl}",
        );
        assert!(
            vrl.contains(".source_type = \"limacharlie_edr\""),
            "expected matched-target assignment, got:\n{vrl}",
        );
    }

    #[test]
    fn kafka_with_headers_path_match_field_emits_dotted_access() {
        let config = make_config(
            "kafka",
            vec![
                make_rule(
                    10,
                    "headers.source_type",
                    "exact",
                    Some("audit_logs"),
                    "aws_cloudtrail",
                ),
                make_rule(1000, "topic", "default", None, "unknown"),
            ],
        );

        let vrl = SourceConfigService::generate_routing_transform(&config, "src", "route", false);

        assert!(
            vrl.contains("if .headers.source_type == \"audit_logs\""),
            "expected headers.source_type conditional, got:\n{vrl}",
        );
    }

    // ------------------------------------------------------------------
    // Safe-VRL-path validation (NAN-649): rejects injection attempts on
    // match_field. Coexists with NAN-648 coercion — when coercion converts
    // the rule to default the validation no-ops.
    // ------------------------------------------------------------------

    #[test]
    fn validate_match_field_path_accepts_simple_identifier() {
        SourceConfigService::validate_match_field_path("source_type", "exact").unwrap();
        SourceConfigService::validate_match_field_path("topic", "prefix").unwrap();
        SourceConfigService::validate_match_field_path("_private", "exact").unwrap();
    }

    #[test]
    fn validate_match_field_path_accepts_nested_path() {
        SourceConfigService::validate_match_field_path("attributes.source_type", "exact").unwrap();
        SourceConfigService::validate_match_field_path("a.b.c.d", "exact").unwrap();
    }

    #[test]
    fn validate_match_field_path_rejects_injection_with_quote_and_assignment() {
        // The exact attempt called out in the Linear acceptance criteria.
        let err = SourceConfigService::validate_match_field_path(
            "X Y'; .source_type = \"hax\"",
            "exact",
        )
        .expect_err("VRL-injection must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("not a valid VRL path"),
            "expected VRL-path error, got: {msg}",
        );
    }

    #[test]
    fn validate_match_field_path_rejects_whitespace() {
        SourceConfigService::validate_match_field_path("foo bar", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path(" leading", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path("trailing ", "exact").unwrap_err();
    }

    #[test]
    fn validate_match_field_path_rejects_double_dot_and_leading_dot() {
        SourceConfigService::validate_match_field_path(".leading_dot", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path("trailing.", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path("a..b", "exact").unwrap_err();
    }

    #[test]
    fn validate_match_field_path_rejects_special_chars() {
        SourceConfigService::validate_match_field_path("foo[0]", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path("foo-bar", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path("foo+bar", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path("foo\"bar", "exact").unwrap_err();
    }

    #[test]
    fn validate_match_field_path_rejects_empty() {
        SourceConfigService::validate_match_field_path("", "exact").unwrap_err();
    }

    #[test]
    fn validate_match_field_path_skips_for_default_match_type() {
        // Default rules ignore match_field — generator never interpolates it.
        // We allow legacy/coerced match_field=source_type rules through.
        SourceConfigService::validate_match_field_path("source_type", "default").unwrap();
        SourceConfigService::validate_match_field_path("anything garbage", "default").unwrap();
    }

    #[test]
    fn validate_match_field_path_rejects_first_char_digit() {
        SourceConfigService::validate_match_field_path("0bad", "exact").unwrap_err();
        SourceConfigService::validate_match_field_path("a.0bad", "exact").unwrap_err();
    }

    #[test]
    fn coerce_and_validate_match_coerces_then_skips_validation() {
        // Pull source + match_field=source_type + non-default match_type:
        // coercion fires (match_type → "default"), validation then skips
        // (default rules don't reach the field-interpolation path).
        let mut mt = "exact".to_string();
        SourceConfigService::coerce_and_validate_match("gcp_pubsub", "source_type", &mut mt)
            .unwrap();
        assert_eq!(mt, "default");
    }

    #[test]
    fn coerce_and_validate_match_validates_when_no_coercion() {
        // Push source: coercion is a no-op, validation runs and rejects junk.
        let mut mt = "exact".to_string();
        let err = SourceConfigService::coerce_and_validate_match(
            "http",
            "foo bar; .x = \"hax\"",
            &mut mt,
        )
        .unwrap_err();
        assert!(matches!(err, SourceConfigServiceError::InvalidConfig(_)));
        // No coercion happened.
        assert_eq!(mt, "exact");
    }

    #[test]
    fn coerce_and_validate_match_passes_clean_path() {
        let mut mt = "exact".to_string();
        SourceConfigService::coerce_and_validate_match(
            "kafka",
            "attributes.source_type",
            &mut mt,
        )
        .unwrap();
        // No coercion (match_field is not "source_type"), validation passed.
        assert_eq!(mt, "exact");
    }

    // ------------------------------------------------------------------
    // NAN-689: TOML / VRL injection via connection_config and routing_rule
    // values. The structured-emission generators must round-trip a malicious
    // payload as a single string scalar — no extra TOML tables, no extra
    // VRL string boundaries crossed.
    // ------------------------------------------------------------------

    /// Recursively check the parsed TOML for a top-level `transforms` or
    /// `sinks` table — these are the keys an attacker would target to land
    /// arbitrary VRL or to redirect logs. The intended source-block output
    /// only has `sources`. Substring matching against the raw text is too
    /// coarse: a malicious payload survives as *escaped content* of a
    /// `"""…"""` string literal and produces literal `[transforms.evil]`
    /// substrings that are not actual TOML tables.
    fn parsed_has_unexpected_top_level_tables(parsed: &toml::Value) -> bool {
        let table = match parsed.as_table() {
            Some(t) => t,
            None => return true,
        };
        for (k, _) in table.iter() {
            if k != "sources" {
                return true;
            }
        }
        false
    }

    /// Kafka generator must escape a `bootstrap_servers` value that tries
    /// to terminate the TOML string and inject a `[transforms.evil]` block.
    /// After the fix the generated TOML parses cleanly as a single source —
    /// no extra tables — and the malicious string survives as content.
    #[test]
    fn kafka_generator_neutralises_bootstrap_servers_toml_injection() {
        let payload = "bs:9092\"\n[transforms.evil]\nsource = \"\"";
        let conn = serde_json::json!({ "bootstrap_servers": payload, "topics": ["logs"] });
        let out = SourceConfigService::generate_kafka_source("test", &conn, None);
        let parsed: toml::Value = toml::from_str(&out).expect("generated TOML must parse");
        assert!(
            !parsed_has_unexpected_top_level_tables(&parsed),
            "expected only [sources.<name>] tables; injection produced extras:\n{out}",
        );
        assert_eq!(
            parsed["sources"]["test"]["bootstrap_servers"].as_str().unwrap(),
            payload,
            "bootstrap_servers value must round-trip verbatim",
        );
    }

    /// AWS S3 generator: malicious region must not break out into new tables.
    #[test]
    fn aws_s3_generator_neutralises_region_toml_injection() {
        let payload = "us-east-1\"\n[transforms.evil]\nsource = \"\"";
        let conn = serde_json::json!({
            "region": payload,
            "sqs_queue_url": "https://sqs.example/q",
        });
        let out = SourceConfigService::generate_aws_s3_source("test", &conn, None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert!(!parsed_has_unexpected_top_level_tables(&parsed), "{out}");
        assert_eq!(
            parsed["sources"]["test"]["region"].as_str().unwrap(),
            payload,
        );
    }

    /// GCP Pub/Sub generator: malicious project value cannot inject tables.
    #[test]
    fn gcp_pubsub_generator_neutralises_project_toml_injection() {
        let payload = "proj\"\n[transforms.evil]\nsource = \"\"";
        let conn = serde_json::json!({ "project": payload, "subscription": "sub" });
        let out = SourceConfigService::generate_gcp_pubsub_source("test", &conn, None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert!(!parsed_has_unexpected_top_level_tables(&parsed), "{out}");
        assert_eq!(
            parsed["sources"]["test"]["project"].as_str().unwrap(),
            payload,
        );
    }

    /// Kafka credentials path: a SASL `password` containing a TOML breakout
    /// shouldn't escape the `[sources.test.sasl]` block.
    #[test]
    fn kafka_generator_neutralises_sasl_password_toml_injection() {
        let payload = "p\"\n[transforms.evil]\nsource = \"\"";
        let conn = serde_json::json!({ "bootstrap_servers": "host:9092", "topics": ["x"] });
        let creds = serde_json::json!({
            "sasl_mechanism": "PLAIN",
            "sasl_username": "u",
            "sasl_password": payload,
        });
        let out = SourceConfigService::generate_kafka_source("test", &conn, Some(&creds));
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert!(!parsed_has_unexpected_top_level_tables(&parsed), "{out}");
        assert_eq!(
            parsed["sources"]["test"]["sasl"]["password"].as_str().unwrap(),
            payload,
        );
    }

    /// Routing transform: a `target_source_type` containing `'''` would have
    /// closed the old triple-single-quoted TOML literal. With `toml::Value::String`
    /// emission it survives as escaped content.
    #[test]
    fn routing_transform_neutralises_target_triple_quote_injection() {
        let config = make_config(
            "kafka",
            vec![
                make_rule(
                    10,
                    "topic",
                    "exact",
                    Some("audit"),
                    "ok'''\n[transforms.evil]\nx = '''",
                ),
                make_rule(1000, "topic", "default", None, "unknown"),
            ],
        );
        let out =
            SourceConfigService::generate_routing_transform(&config, "src", "route", false);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        // The only transform table should be the route we generated
        let transforms = parsed.get("transforms").and_then(|t| t.as_table()).unwrap();
        assert_eq!(
            transforms.len(),
            1,
            "expected exactly one transform; injection produced extras:\n{out}",
        );
        assert!(transforms.contains_key("route"));
    }

    /// VRL escape: a `match_value` containing `"` would end the VRL string
    /// without escaping; check the embedded VRL has the escaped form.
    #[test]
    fn routing_transform_escapes_match_value_quote() {
        let config = make_config(
            "kafka",
            vec![
                make_rule(10, "topic", "exact", Some("a\"b"), "ok"),
                make_rule(1000, "topic", "default", None, "unknown"),
            ],
        );
        let out =
            SourceConfigService::generate_routing_transform(&config, "src", "route", false);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        let source = parsed["transforms"]["route"]["source"].as_str().unwrap();
        // VRL must see the escaped quote, not a bare one
        assert!(
            source.contains("\"a\\\"b\""),
            "expected escaped quote inside VRL string, got:\n{source}",
        );
    }

    /// Regex-typed rule with a `'` in the pattern would close the VRL raw
    /// string `r'…'`. Generator must skip+warn rather than emit broken VRL.
    #[test]
    fn routing_transform_skips_regex_with_single_quote() {
        let config = make_config(
            "kafka",
            vec![
                make_rule(10, "topic", "regex", Some("foo'bar"), "ok"),
                make_rule(1000, "topic", "default", None, "fallback"),
            ],
        );
        let out =
            SourceConfigService::generate_routing_transform(&config, "src", "route", false);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        let source = parsed["transforms"]["route"]["source"].as_str().unwrap();
        // Skipped — the if-block isn't emitted; only the default assignment
        assert!(
            !source.contains("match("),
            "skipped regex rule still appeared in VRL:\n{source}",
        );
        assert!(source.contains(".source_type = \"fallback\""));
    }

    // ------------------------------------------------------------------
    // NAN-689: connection_config validation at create/update.
    // ------------------------------------------------------------------

    #[test]
    fn validate_connection_config_rejects_newline_in_string_scalar() {
        let conn = serde_json::json!({
            "bootstrap_servers": "host:9092\n[transforms.evil]"
        });
        let err = SourceConfigService::validate_connection_config("kafka", &conn).unwrap_err();
        assert!(
            err.to_string().contains("control character"),
            "expected control-char error, got: {err}",
        );
    }

    #[test]
    fn validate_connection_config_rejects_carriage_return() {
        let conn = serde_json::json!({ "address": "0.0.0.0:8088\r" });
        SourceConfigService::validate_connection_config("splunk_hec", &conn).unwrap_err();
    }

    #[test]
    fn validate_connection_config_rejects_nul_byte() {
        let conn = serde_json::json!({ "project": "proj\0name" });
        SourceConfigService::validate_connection_config("gcp_pubsub", &conn).unwrap_err();
    }

    #[test]
    fn validate_connection_config_rejects_control_char_in_array_element() {
        let conn = serde_json::json!({
            "topics": ["normal", "bad\ntopic"]
        });
        let err = SourceConfigService::validate_connection_config("kafka", &conn).unwrap_err();
        assert!(
            err.to_string().contains("topics[1]"),
            "expected path-aware error, got: {err}",
        );
    }

    #[test]
    fn validate_connection_config_allows_legitimate_payload() {
        // Quotes and backslashes are fine — the toml crate escapes them on
        // emission, and rejecting them would block valid URLs / SASL passwords.
        let kafka = serde_json::json!({
            "bootstrap_servers": "broker-1.example.com:9092,broker-2.example.com:9092",
            "topics": ["audit-logs", "app-events"],
            "group_id": "nanosiem",
            "auto_offset_reset": "latest",
        });
        SourceConfigService::validate_connection_config("kafka", &kafka).unwrap();

        let s3 = serde_json::json!({
            "sqs_queue_url": "https://sqs.us-east-1.amazonaws.com/123/q",
            "region": "us-east-1",
            "compression": "gzip",
        });
        SourceConfigService::validate_connection_config("aws_s3", &s3).unwrap();

        let gcp = serde_json::json!({
            "project": "my-gcp-proj",
            "subscription": "projects/my-gcp-proj/subscriptions/my-sub",
            "ack_deadline_secs": 600,
        });
        SourceConfigService::validate_connection_config("gcp_pubsub", &gcp).unwrap();

        let hec = serde_json::json!({
            "address": "0.0.0.0:8088",
            "valid_tokens": ["00000000-0000-0000-0000-000000000000"],
        });
        SourceConfigService::validate_connection_config("splunk_hec", &hec).unwrap();
    }

    #[test]
    fn validate_connection_config_allows_quotes_and_backslashes() {
        // toml::Value::String handles escaping, so these pass through unharmed.
        let conn = serde_json::json!({
            "bootstrap_servers": "host:9092",
            "topics": ["with\"quote", "with\\backslash"]
        });
        SourceConfigService::validate_connection_config("kafka", &conn).unwrap();
    }

    #[test]
    fn validate_connection_config_rejects_kafka_topics_wrong_type() {
        // topics must be an array, not an object/string.
        let conn = serde_json::json!({ "topics": "not-an-array" });
        SourceConfigService::validate_connection_config("kafka", &conn).unwrap_err();

        let conn = serde_json::json!({ "topics": [42] });
        SourceConfigService::validate_connection_config("kafka", &conn).unwrap_err();
    }

    #[test]
    fn validate_connection_config_rejects_known_field_wrong_type() {
        let conn = serde_json::json!({ "bootstrap_servers": ["should", "be", "string"] });
        SourceConfigService::validate_connection_config("kafka", &conn).unwrap_err();

        let conn = serde_json::json!({ "address": 8088 });
        SourceConfigService::validate_connection_config("splunk_hec", &conn).unwrap_err();
    }

    #[test]
    fn validate_connection_config_allows_unknown_driver() {
        // System-level (`http`, `vector`) and unknown drivers skip
        // structural checks but still get the char-safety pass.
        let conn = serde_json::json!({ "anything": "fine" });
        SourceConfigService::validate_connection_config("http", &conn).unwrap();
        SourceConfigService::validate_connection_config("vector", &conn).unwrap();
        SourceConfigService::validate_connection_config("unknown_driver", &conn).unwrap();
    }

    #[test]
    fn validate_connection_config_rejects_root_array() {
        let conn = serde_json::json!(["nope"]);
        SourceConfigService::validate_connection_config("kafka", &conn).unwrap_err();
    }

    #[test]
    fn validate_connection_config_allows_null_root() {
        // Some legacy rows have null connection_config; generators tolerate
        // it via `.as_str().unwrap_or(...)` defaults.
        SourceConfigService::validate_connection_config("kafka", &serde_json::Value::Null).unwrap();
    }

    #[test]
    fn validate_connection_config_rejects_control_char_in_object_key() {
        let mut map = serde_json::Map::new();
        map.insert("bad\nkey".to_string(), serde_json::Value::String("v".into()));
        SourceConfigService::validate_connection_config("kafka", &serde_json::Value::Object(map))
            .unwrap_err();
    }

    // ------------------------------------------------------------------
    // NAN-689 P0: name validation. The leading TOML comment of the
    // generated config interpolates `config.name` raw — a `\n` in name
    // would close the comment and let the rest be parsed as TOML
    // structure, bypassing the structured-emission defense.
    // ------------------------------------------------------------------

    #[test]
    fn validate_name_rejects_newline() {
        SourceConfigService::validate_name("foo\n[transforms.evil]").unwrap_err();
    }

    #[test]
    fn validate_name_rejects_carriage_return() {
        SourceConfigService::validate_name("foo\r").unwrap_err();
    }

    #[test]
    fn validate_name_rejects_nul() {
        SourceConfigService::validate_name("foo\0bar").unwrap_err();
    }

    #[test]
    fn validate_name_rejects_other_control_chars() {
        SourceConfigService::validate_name("foo\x07bell").unwrap_err();
        SourceConfigService::validate_name("foo\x1bescape").unwrap_err();
        SourceConfigService::validate_name("foo\x7fdel").unwrap_err();
    }

    #[test]
    fn validate_name_allows_tab() {
        // Tab is allowed — same policy as connection_config strings.
        SourceConfigService::validate_name("foo\tbar").unwrap();
    }

    #[test]
    fn validate_name_allows_unicode_and_punctuation() {
        // Names are user-display strings; they go through `safe_name` for
        // file paths and identifiers, so the only restriction here is on
        // characters that would break the TOML comment they land in.
        SourceConfigService::validate_name("My Source [prod] (us-east-1)").unwrap();
        SourceConfigService::validate_name("источник").unwrap();
    }

    #[test]
    fn validate_name_rejects_empty() {
        SourceConfigService::validate_name("").unwrap_err();
    }

    // ------------------------------------------------------------------
    // NAN-689 P2: routing-rule write-time validation for match_value /
    // target_source_type. The generator's vrl_escape covers `\` and `"`,
    // these checks cover the cases it can't (control chars + regex `'`).
    // ------------------------------------------------------------------

    /// NAN-858: target_source_type must conform to the same allow-list the
    /// rollup IN-clause sanitizer uses. Reject the `${source_type}` sentinel
    /// at write time so it never gets persisted (and the WARN it caused on
    /// every `GET /api/source-configurations` stays gone).
    #[test]
    fn validate_routing_rule_values_rejects_passthrough_sentinel_target() {
        let err = SourceConfigService::validate_routing_rule_values(
            "default",
            None,
            "${source_type}",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("target_source_type"),
            "expected target_source_type error, got: {err}"
        );
    }

    #[test]
    fn validate_routing_rule_values_rejects_empty_target() {
        let err =
            SourceConfigService::validate_routing_rule_values("default", None, "").unwrap_err();
        assert!(err.to_string().contains("target_source_type"));
    }

    #[test]
    fn validate_routing_rule_values_rejects_dot_in_target() {
        let err = SourceConfigService::validate_routing_rule_values(
            "exact",
            Some("v"),
            "some.dotted.value",
        )
        .unwrap_err();
        assert!(err.to_string().contains("target_source_type"));
    }

    /// Counterpart: typical valid values still pass.
    #[test]
    fn validate_routing_rule_values_accepts_safe_targets() {
        for target in ["apache_access", "aws-cloudtrail", "Sysmon", "unknown", "x"] {
            SourceConfigService::validate_routing_rule_values("default", None, target)
                .unwrap_or_else(|e| {
                    panic!("expected {target:?} to be accepted, got error: {e}")
                });
        }
    }

    #[test]
    fn validate_routing_rule_values_rejects_newline_in_match_value() {
        let err = SourceConfigService::validate_routing_rule_values(
            "exact",
            Some("audit\nlogs"),
            "ok",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("match_value"),
            "expected match_value error, got: {err}",
        );
    }

    #[test]
    fn validate_routing_rule_values_rejects_newline_in_target() {
        SourceConfigService::validate_routing_rule_values(
            "exact",
            Some("audit"),
            "aws_cloudtrail\n",
        )
        .unwrap_err();
    }

    #[test]
    fn validate_routing_rule_values_rejects_single_quote_in_regex() {
        let err = SourceConfigService::validate_routing_rule_values(
            "regex",
            Some("foo'bar"),
            "ok",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("single quote"),
            "expected explicit single-quote error, got: {err}",
        );
    }

    #[test]
    fn validate_routing_rule_values_allows_single_quote_in_non_regex() {
        // Non-regex match types interpolate into `"…"` strings via
        // vrl_escape; single quotes are fine there.
        SourceConfigService::validate_routing_rule_values(
            "exact",
            Some("foo'bar"),
            "ok",
        )
        .unwrap();
    }

    #[test]
    fn validate_routing_rule_values_allows_quotes_and_backslashes_in_match_value() {
        // match_value gets vrl_escape'd before interpolation, so quotes and
        // backslashes are legitimate (e.g. matching a command_line substring
        // that contains them). target_source_type is *not* a free-form string
        // though — NAN-858 restricts it to [A-Za-z0-9_-] so the rollup IN
        // clause stays clean.
        SourceConfigService::validate_routing_rule_values(
            "exact",
            Some("a\"b\\c"),
            "safe_target",
        )
        .unwrap();
    }

    #[test]
    fn validate_routing_rule_values_allows_default_with_no_match_value() {
        SourceConfigService::validate_routing_rule_values("default", None, "unknown").unwrap();
    }

    // ------------------------------------------------------------------
    // NAN-689 acceptance criterion #3: validate_generated_config gate.
    // ------------------------------------------------------------------

    /// A well-formed kafka source-block + routing transform passes both
    /// TOML parse and VRL compile checks.
    #[test]
    fn validate_generated_config_accepts_well_formed_kafka_pipeline() {
        let conn = serde_json::json!({
            "bootstrap_servers": "broker:9092",
            "topics": ["audit-logs"],
            "group_id": "nanosiem",
            "auto_offset_reset": "latest",
        });
        let mut full = SourceConfigService::generate_kafka_source("test", &conn, None);
        full.push('\n');
        let routing = SourceConfigService::generate_routing_transform(
            &make_config(
                "kafka",
                vec![
                    make_rule(10, "topic", "exact", Some("audit-logs"), "aws_cloudtrail"),
                    make_rule(1000, "topic", "default", None, "unknown"),
                ],
            ),
            "test_source",
            "test_route",
            false,
        );
        full.push_str(&routing);

        SourceConfigService::validate_generated_config(&full)
            .expect("clean kafka pipeline must pass validation");
    }

    /// Routing transform on its own (the system-level / rewrite-rules path)
    /// also passes the gate.
    #[test]
    fn validate_generated_config_accepts_routing_transform_only() {
        let routing = SourceConfigService::generate_routing_transform(
            &make_config(
                "http",
                vec![make_rule(
                    10,
                    "source_type",
                    "exact",
                    Some("aws_cloudtrail_raw"),
                    "aws_cloudtrail",
                )],
            ),
            "source_type_extract",
            "test_route",
            true,
        );
        SourceConfigService::validate_generated_config(&routing)
            .expect("clean routing transform must pass validation");
    }

    /// Even the empty default-only case is valid VRL.
    #[test]
    fn validate_generated_config_accepts_default_only_routing_transform() {
        let routing = SourceConfigService::generate_routing_transform(
            &make_config(
                "kafka",
                vec![make_rule(1000, "topic", "default", None, "unknown")],
            ),
            "src",
            "route",
            false,
        );
        SourceConfigService::validate_generated_config(&routing)
            .expect("default-only routing must pass validation");
    }

    /// Malformed TOML (e.g. unterminated string) is rejected by the
    /// TOML-parse layer.
    #[test]
    fn validate_generated_config_rejects_malformed_toml() {
        let bad = "[sources.test]\ntype = \"kafka\nbootstrap_servers = \"x\"\n";
        let err = SourceConfigService::validate_generated_config(bad).unwrap_err();
        assert!(
            err.to_string().contains("not valid TOML"),
            "expected TOML-parse error, got: {err}",
        );
    }

    /// Malformed VRL inside a remap transform's `source` is rejected by
    /// the VRL-compile layer.
    #[test]
    fn validate_generated_config_rejects_malformed_vrl_in_remap() {
        let bad = "[transforms.bad]\n\
                   type = \"remap\"\n\
                   inputs = [\"src\"]\n\
                   source = \"this is :: not :: valid :: vrl\"\n";
        let err = SourceConfigService::validate_generated_config(bad).unwrap_err();
        assert!(
            err.to_string().contains("failed to compile"),
            "expected VRL-compile error, got: {err}",
        );
        assert!(
            err.to_string().contains("'bad'"),
            "expected transform name in error, got: {err}",
        );
    }

    /// Non-`remap` transforms (e.g. `route`, `filter`) skip the VRL
    /// compile step — they don't carry user-controlled VRL.
    #[test]
    fn validate_generated_config_skips_non_remap_transforms() {
        // A `route` transform with a `source` field that isn't VRL would
        // otherwise trip the compile check; gate skips it because type != "remap".
        let toml = "[transforms.r]\n\
                    type = \"route\"\n\
                    inputs = [\"src\"]\n\
                    source = \"not vrl, ignored\"\n\
                    [transforms.r.route]\n\
                    a = '.foo == \"x\"'\n";
        SourceConfigService::validate_generated_config(toml)
            .expect("non-remap transforms must skip VRL compile");
    }

    #[test]
    fn normalize_pubsub_subscription_strips_full_resource_path() {
        // Vector double-prefixes if we hand it the full resource name.
        let bare = normalize_pubsub_subscription(
            "projects/nano-rs/subscriptions/nanosiem-limacharlie-sub",
        );
        assert_eq!(bare, "nanosiem-limacharlie-sub");
    }

    #[test]
    fn normalize_pubsub_subscription_passes_bare_name_through() {
        let bare =
            normalize_pubsub_subscription("nanosiem-limacharlie-sub");
        assert_eq!(bare, "nanosiem-limacharlie-sub");
    }

    #[test]
    fn normalize_pubsub_subscription_handles_trailing_slash() {
        let bare = normalize_pubsub_subscription(
            "projects/nano-rs/subscriptions/foo/",
        );
        assert_eq!(bare, "foo");
    }

    #[test]
    fn normalize_pubsub_subscription_handles_empty() {
        assert_eq!(normalize_pubsub_subscription(""), "");
    }

    // Snapshot redaction itself lives in `parsers::vector_config::redaction`
    // and is unit-tested there. The wiring assertion that the source-config
    // deploy path actually invokes it is best validated end-to-end against a
    // real database (out of scope for this unit module).

    fn bare_config(name: &str, config_type: &str) -> SourceConfiguration {
        let now = Utc::now();
        SourceConfiguration {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: None,
            config_type: config_type.to_string(),
            connection_config: serde_json::json!({}),
            credential_id: None,
            enabled: true,
            deployed: true,
            deployed_at: Some(now),
            created_at: now,
            updated_at: now,
            events_24h: None,
            bytes_per_day_24h: None,
            last_event_at: None,
        }
    }

    /// Guards against the NAN-852 regression: any source-config mutation
    /// rebuilds the router inputs and `hec_normalize` must never be dropped.
    #[test]
    fn compute_router_inputs_always_contains_hec_normalize() {
        let scenarios: Vec<Vec<SourceConfiguration>> = vec![
            vec![],
            vec![bare_config("kafka_audit", "kafka")],
            vec![bare_config("http_main", "http")],
            vec![bare_config("vec_relay", "vector"), bare_config("s3_logs", "s3")],
        ];

        for configs in scenarios {
            let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true);
            assert!(
                inputs.iter().any(|s| s == "hec_normalize"),
                "hec_normalize missing from inputs for configs={:?}",
                configs.iter().map(|c| &c.name).collect::<Vec<_>>()
            );
            assert!(
                inputs.iter().any(|s| s == "vector_merge"),
                "vector_merge missing from inputs for configs={:?}",
                configs.iter().map(|c| &c.name).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn compute_router_inputs_appends_non_system_routes_after_base() {
        let configs = vec![bare_config("kafka_audit", "kafka")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| false);
        assert_eq!(
            inputs,
            vec!["source_type_extract", "vector_merge", "hec_normalize", "kafka_audit_route"]
        );
    }

    #[test]
    fn compute_router_inputs_drops_source_type_extract_when_system_route_on_disk() {
        let configs = vec![bare_config("http_main", "http")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true);
        assert_eq!(inputs, vec!["vector_merge", "hec_normalize", "http_main_route"]);
    }

    #[test]
    fn compute_router_inputs_skips_system_route_when_no_file_on_disk() {
        let configs = vec![bare_config("http_main", "http")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| false);
        assert_eq!(inputs, vec!["source_type_extract", "vector_merge", "hec_normalize"]);
    }

    #[test]
    fn system_intermediary_source_maps_http_and_vector_to_source_type_extract() {
        assert_eq!(
            SourceConfigService::system_intermediary_source("http"),
            Some("source_type_extract")
        );
        assert_eq!(
            SourceConfigService::system_intermediary_source("vector"),
            Some("source_type_extract")
        );
    }

    /// Guards NAN-853: splunk_hec deploys must route via `hec_normalize`,
    /// not declare a new `[sources.*]` on :8088 that collides with the OOTB
    /// splunk_hec_ingest source.
    #[test]
    fn system_intermediary_source_maps_splunk_hec_to_hec_normalize() {
        assert_eq!(
            SourceConfigService::system_intermediary_source("splunk_hec"),
            Some("hec_normalize")
        );
    }

    #[test]
    fn system_intermediary_source_is_none_for_owned_source_types() {
        for ty in ["kafka", "aws_s3", "gcp_pubsub", "unknown"] {
            assert_eq!(
                SourceConfigService::system_intermediary_source(ty),
                None,
                "{ty} owns its source and must not be treated as system-level"
            );
        }
    }

    /// End-to-end shape of the generated routing TOML for a splunk_hec deploy:
    /// transform-only, consumes from `hec_normalize`, no `[sources.*]` block.
    #[test]
    fn splunk_hec_routing_transform_consumes_hec_normalize_with_no_source_block() {
        let intermediary = SourceConfigService::system_intermediary_source("splunk_hec")
            .expect("splunk_hec must be system-level");
        let cfg = make_config(
            "splunk_hec",
            vec![make_rule(
                10,
                "sourcetype",
                "exact",
                Some("access_combined"),
                "apache_access",
            )],
        );

        let routing = SourceConfigService::generate_routing_transform(
            &cfg,
            intermediary,
            "splunk_hec_test_route",
            true,
        );

        assert!(
            !routing.contains("[sources."),
            "routing transform must not declare a Vector source — would collide with OOTB \
             splunk_hec_ingest on :8088. got:\n{routing}"
        );
        assert!(
            routing.contains("inputs = [\"hec_normalize\"]"),
            "routing transform must consume from hec_normalize, got:\n{routing}"
        );
        assert!(
            routing.contains("[transforms.splunk_hec_test_route]"),
            "routing transform name must be present, got:\n{routing}"
        );
    }

    /// Guards NAN-856: a splunk_hec config with only a default rule
    /// (the most common UI flow) must produce an unconditional
    /// `.source_type = "<target>"` VRL, not a passthrough that ignores
    /// the user's target.
    #[test]
    fn splunk_hec_default_only_rule_emits_unconditional_source_type_set() {
        let cfg = make_config(
            "splunk_hec",
            vec![make_rule(1000, "source_type", "default", None, "apache_access")],
        );

        // Matches what deploy() passes for splunk_hec post-NAN-856:
        // intermediary=hec_normalize, system_level=false (so default target is authoritative).
        let routing = SourceConfigService::generate_routing_transform(
            &cfg,
            "hec_normalize",
            "splunk_hec_test_route",
            false,
        );

        assert!(
            routing.contains(".source_type = \"apache_access\""),
            "user's default target must be emitted as unconditional assignment, got:\n{routing}"
        );
        assert!(
            !routing.contains("passthrough"),
            "default rule must not coalesce to passthrough for HEC, got:\n{routing}"
        );
    }

    /// Guards NAN-856 defense-in-depth: compute_router_inputs must skip
    /// system-level configs (http/vector/splunk_hec) whose routing TOML is
    /// not on disk, even if marked deployed in DB. Otherwise source_router
    /// gets an input pointing at a non-existent transform and Vector aborts.
    #[test]
    fn compute_router_inputs_skips_splunk_hec_when_no_file_on_disk() {
        let configs = vec![bare_config("hec_main", "splunk_hec")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| false);
        assert!(
            !inputs.iter().any(|s| s == "hec_main_route"),
            "splunk_hec route must not be in inputs when no file on disk, got: {inputs:?}"
        );
        // hec_normalize must still be present unconditionally.
        assert!(inputs.iter().any(|s| s == "hec_normalize"));
    }

    /// HEC with no rules at all: nothing to deploy. has_meaningful_rules
    /// must return false so deploy() skips the file write — without that, the
    /// generator would emit `.source_type = "unknown"` (the fallback when
    /// system_level=false and no default rule), wiping out hec_normalize's
    /// envelope-derived value for every HEC event.
    #[test]
    fn has_meaningful_routing_rules_false_for_splunk_hec_with_empty_rules() {
        let cfg = make_config("splunk_hec", vec![]);
        assert!(!SourceConfigService::has_meaningful_routing_rules(&cfg));
    }

    /// HEC with a single default rule: deploy() must write the file. Without
    /// this, _router.toml references splunk_hec_route while the transform
    /// itself doesn't exist on disk — Vector aborts reload. (NAN-856 root cause)
    #[test]
    fn has_meaningful_routing_rules_true_for_splunk_hec_with_default_only() {
        let cfg = make_config(
            "splunk_hec",
            vec![make_rule(1000, "source_type", "default", None, "apache_access")],
        );
        assert!(SourceConfigService::has_meaningful_routing_rules(&cfg));
    }

    /// HTTP/Vector with a default-only rule: existing behavior must be
    /// preserved — default rules are passthrough no-ops, so the file is
    /// skipped. Guards against accidental regression of the
    /// http/vector deploy semantics during NAN-856.
    #[test]
    fn has_meaningful_routing_rules_false_for_http_with_default_only() {
        let cfg = make_config(
            "http",
            vec![make_rule(1000, "source_type", "default", None, "something")],
        );
        assert!(!SourceConfigService::has_meaningful_routing_rules(&cfg));
    }

    #[test]
    fn has_meaningful_routing_rules_true_for_http_with_non_default_rule() {
        let cfg = make_config(
            "http",
            vec![make_rule(10, "host", "exact", Some("web1"), "apache_access")],
        );
        assert!(SourceConfigService::has_meaningful_routing_rules(&cfg));
    }

    /// NAN-857: when a splunk_hec route IS on disk, `hec_normalize` must be
    /// suppressed from base inputs — the route consumes hec_normalize and
    /// feeds source_router, so keeping hec_normalize as a direct base input
    /// would double-ingest every HEC event (once direct → source_type=unknown,
    /// once via the route → user-configured source_type). And — separately —
    /// splunk_hec must NOT suppress source_type_extract; HEC and HTTP are
    /// independent channels.
    #[test]
    fn compute_router_inputs_suppresses_hec_normalize_when_splunk_hec_route_on_disk() {
        let configs = vec![bare_config("hec_main", "splunk_hec")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true);
        assert_eq!(
            inputs,
            vec!["source_type_extract", "vector_merge", "hec_main_route"],
            "hec_normalize must be intermediated by the splunk_hec route, not also direct"
        );
    }

    /// Both intermediaries covered: only vector_merge + the two routes.
    #[test]
    fn compute_router_inputs_suppresses_both_intermediaries_when_both_routes_on_disk() {
        let configs = vec![
            bare_config("http_main", "http"),
            bare_config("hec_main", "splunk_hec"),
        ];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true);
        assert_eq!(
            inputs,
            vec!["vector_merge", "http_main_route", "hec_main_route"]
        );
    }
}
