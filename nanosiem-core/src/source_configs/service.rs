// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source Configuration service for business logic

use sqlx::PgPool;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::OnceCell;
use uuid::Uuid;

use super::creds_backend::{CredsBackend, CredsBackendError};
use super::repository::{RouteClaim, SourceConfigRepository, SourceConfigRepositoryError};
use super::types::{
    DeploymentResult, ListParams, NewRoutingRule, NewSourceConfiguration, RoutingRule,
    SourceConfigDeployment, SourceConfiguration, SourceConfigurationWithRules, UpdateRoutingRule,
    UpdateSourceConfiguration,
};
use crate::log_telemetry::repository::is_safe_source_type;
use crate::parsers::{
    base_router_inputs, hec_normalize_present, redact_config_snapshot, CredentialRepository,
};

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
    /// NAN-883: rejected because the target driver is single-instance and
    /// a configuration already exists (e.g. `splunk_hec` shares one OOTB
    /// listener; two would collide on the `splunk_hec_route` transform).
    /// Maps to HTTP 409 in the API layer.
    #[error("Conflict: {0}")]
    Conflict(String),
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
    /// Shared with `VectorConfigManager::deploy_lock` when wired in
    /// production so `update_dynamic_router`'s read-mutate-write of
    /// `_router.toml` is serialized against parser-deploy writes from the
    /// other service. `None` is a valid fallback for tests and unit-only
    /// callers — they don't write to `_router.toml`. NAN-948.
    deploy_lock: Option<Arc<tokio::sync::Mutex<()>>>,
}

impl SourceConfigService {
    pub fn new(pool: PgPool) -> Self {
        Self {
            repository: SourceConfigRepository::new(pool.clone()),
            credential_repo: CredentialRepository::new(pool),
            vector_config_dir: PathBuf::from("config/vector"),
            vector_sources_runtime_path: Self::resolve_runtime_path(),
            creds_backend: Arc::new(OnceCell::new()),
            deploy_lock: None,
        }
    }

    pub fn with_vector_config_dir(pool: PgPool, config_dir: impl AsRef<Path>) -> Self {
        Self {
            repository: SourceConfigRepository::new(pool.clone()),
            credential_repo: CredentialRepository::new(pool),
            vector_config_dir: config_dir.as_ref().to_path_buf(),
            vector_sources_runtime_path: Self::resolve_runtime_path(),
            creds_backend: Arc::new(OnceCell::new()),
            deploy_lock: None,
        }
    }

    /// Wire this service's `update_dynamic_router` into the same lock that
    /// the parser-deploy path uses, so the two paths can't interleave on
    /// `_router.toml`. Production callers pass `VectorConfigManager::deploy_lock()`;
    /// tests can omit. NAN-948.
    pub fn with_deploy_lock(mut self, lock: Arc<tokio::sync::Mutex<()>>) -> Self {
        self.deploy_lock = Some(lock);
        self
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

        // NAN-883: single-instance drivers (currently `splunk_hec`) share an
        // OOTB Vector listener; a second config would emit a colliding
        // routing transform. Reject the duplicate with a Conflict (409).
        //
        // This list-then-check is racy on its own — two concurrent POSTs
        // could both pass — but the partial unique index added in
        // migration 184 backstops it at the DB layer (the repository maps
        // the resulting `unique_violation` back to `Conflict`). The
        // application-level check still runs first so the typical path
        // gets a clean error without a wasted INSERT.
        if Self::is_single_instance_driver(&request.config_type) {
            let existing = self.repository.list(None).await?;
            if let Some(err) =
                Self::reject_if_duplicate_single_instance(&request.config_type, &existing)
            {
                return Err(err);
            }
        }

        // Validate credential exists if specified
        if let Some(cred_id) = request.credential_id {
            self.credential_repo
                .get(cred_id)
                .await
                .map_err(|e| SourceConfigServiceError::CredentialError(e.to_string()))?;
        }

        Ok(self.repository.create(request).await?)
    }

    /// NAN-883: drivers where only one source configuration may exist per
    /// deployment. Today: `splunk_hec` (the OOTB `splunk_hec_ingest` listener
    /// is shared, and a user config is just a routing profile over it — two
    /// would emit colliding `splunk_hec_route` transforms).
    fn is_single_instance_driver(config_type: &str) -> bool {
        matches!(config_type, "splunk_hec")
    }

    /// Pure decision helper for the single-instance check. Returns
    /// `Some(Conflict)` when `existing` already contains a row with the
    /// requested `config_type`, else `None`. Split out from `create` so it
    /// can be unit-tested without a database — the I/O is in `list` and
    /// the partial unique index (migration 184).
    fn reject_if_duplicate_single_instance(
        config_type: &str,
        existing: &[SourceConfiguration],
    ) -> Option<SourceConfigServiceError> {
        if existing.iter().any(|c| c.config_type == config_type) {
            Some(SourceConfigServiceError::Conflict(format!(
                "Only one {config_type} source configuration is supported per deployment. \
                 Edit the existing config to add routing rules."
            )))
        } else {
            None
        }
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

        // NAN-947: when a rename changes the on-disk file path, the old
        // file would otherwise linger in configs/ until the user manually
        // cleans up — and the next router scan would pick up both. We
        // snapshot the pre-update name BEFORE the DB write, then after
        // the update succeeds, compare paths and remove the stale file.
        //
        // For system-level singletons (NAN-940 — splunk_hec) the file
        // stem is pinned, so old_path == new_path and this is a no-op.
        // For Kafka / S3 / GCP / HTTP / Vector configs the stem follows
        // safe_name(name) and the path changes on rename.
        let pre_update_snapshot: Option<(String, String, PathBuf, bool)> =
            if request.name.is_some() {
                let existing = self.repository.get(id).await?;
                let old_path = self.get_config_file_path(&existing.config_type, &existing.name);
                Some((existing.config_type, existing.name, old_path, existing.deployed))
            } else {
                None
            };

        let updated = self.repository.update(id, request).await?;

        if let Some((old_type, old_name, old_path, was_deployed)) = pre_update_snapshot {
            let stem_changed = Self::rename_changes_on_disk_stem(
                &old_type,
                &old_name,
                &updated.config_type,
                &updated.name,
            );
            if stem_changed && old_path.exists() {
                let new_path = self.get_config_file_path(&updated.config_type, &updated.name);
                if let Err(err) = tokio::fs::remove_file(&old_path).await {
                    // Don't fail the update on cleanup error; just warn —
                    // the DB rename has committed and the old file is at
                    // worst a benign orphan (NAN-947 trade-off: best-effort
                    // cleanup over rollback). Operators see the warn line
                    // and can rm by hand.
                    tracing::warn!(
                        old_path = %old_path.display(),
                        new_path = %new_path.display(),
                        error = %err,
                        "failed to remove orphan TOML after source-config rename",
                    );
                } else {
                    tracing::info!(
                        old_path = %old_path.display(),
                        new_path = %new_path.display(),
                        "removed orphan TOML after source-config rename",
                    );
                }
                // Only refresh the router when the rename touched a config
                // that was actually deployed — otherwise nothing in the
                // router references either path, and refreshing would be
                // wasted I/O.
                if was_deployed {
                    if let Err(err) = self.update_dynamic_router().await {
                        tracing::warn!(
                            error = %err,
                            "failed to refresh dynamic router after source-config rename",
                        );
                    }
                }
            }
        }

        Ok(updated)
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

    /// NAN-855: post-NAN-853 a `splunk_hec` source config no longer emits its
    /// own Vector source — it consumes from the OOTB `splunk_hec_ingest`
    /// listener (`:8088`, shared `${VECTOR_AUTH_TOKEN}`). The fields below
    /// are vestigial and silently ignored at deploy time. Reject any value
    /// other than null / empty so the schema doesn't look configurable on
    /// settings that have zero effect.
    fn validate_splunk_hec_conn(conn: &serde_json::Value) -> Result<(), SourceConfigServiceError> {
        Self::reject_nonempty_vestigial_field(conn, "address")?;
        Self::reject_nonempty_vestigial_field(conn, "valid_tokens")?;
        Self::reject_nonempty_vestigial_field(conn, "permit_origin")?;
        Self::reject_nonempty_vestigial_field(conn, "tls")?;
        Ok(())
    }

    /// Reject `key` if present and non-empty. Accepts absence, JSON null,
    /// empty string, and empty array/object — those round-trip cleanly from
    /// the frontend's `connection_config: {}` and from any legacy stored
    /// payload that has been cleared.
    fn reject_nonempty_vestigial_field(
        conn: &serde_json::Value,
        key: &str,
    ) -> Result<(), SourceConfigServiceError> {
        let Some(v) = conn.get(key) else { return Ok(()) };
        let is_empty = match v {
            serde_json::Value::Null => true,
            serde_json::Value::String(s) => s.is_empty(),
            serde_json::Value::Array(a) => a.is_empty(),
            serde_json::Value::Object(o) => o.is_empty(),
            _ => false,
        };
        if is_empty {
            Ok(())
        } else {
            Err(SourceConfigServiceError::InvalidConfig(format!(
                "splunk_hec connection_config.{key} is not configurable per source — \
                 HEC is served by the platform-managed listener (:8088, shared token). \
                 Remove this field."
            )))
        }
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

    /// Maximum JSON nesting depth that `validate_safe_strings` will walk.
    ///
    /// NAN-946: admin-controlled `connection_config` payloads are arbitrary
    /// JSON, so without a cap the recursive walker can overflow the stack
    /// on a deeply-nested input. 32 is generous for legitimate shapes —
    /// every driver's connection_config today is flat or one-level deep
    /// (Kafka: `bootstrap_servers` / `topics`, HEC: empty, S3: AWS creds /
    /// regions, GCP: project / subscription / credentials). Pick a value
    /// safely past those without being close to the default Rust thread
    /// stack limit (~8 MiB / ~2-4 KiB per frame ≈ 2000 frames).
    const VALIDATE_SAFE_STRINGS_MAX_DEPTH: usize = 32;

    /// Recursively walk a JSON value and reject any string scalar that
    /// contains a newline / carriage return / NUL / other ASCII control
    /// char (tab is allowed). Path is used to produce a helpful error.
    ///
    /// NAN-946: depth is capped at `VALIDATE_SAFE_STRINGS_MAX_DEPTH` so a
    /// malicious admin payload can't overflow the runtime stack. Depth 0
    /// is the entry call; each Array/Object recursion bumps it by 1.
    fn validate_safe_strings(
        v: &serde_json::Value,
        path: &str,
    ) -> Result<(), SourceConfigServiceError> {
        Self::validate_safe_strings_inner(v, path, 0)
    }

    fn validate_safe_strings_inner(
        v: &serde_json::Value,
        path: &str,
        depth: usize,
    ) -> Result<(), SourceConfigServiceError> {
        if depth > Self::VALIDATE_SAFE_STRINGS_MAX_DEPTH {
            return Err(SourceConfigServiceError::InvalidConfig(format!(
                "{path} exceeds maximum nesting depth of {} — refusing to validate \
                 deeply-nested connection_config",
                Self::VALIDATE_SAFE_STRINGS_MAX_DEPTH
            )));
        }
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
                    Self::validate_safe_strings_inner(item, &format!("{path}[{i}]"), depth + 1)?;
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
                    Self::validate_safe_strings_inner(val, &format!("{path}.{k}"), depth + 1)?;
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
        let config_file = self.get_config_file_path(&config.config_type, &config.name);
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
    /// `.source_type`. Pub/Sub / Kafka / S3 events do not carry an inbound
    /// `.source_type` field, so such rules cannot fire.
    ///
    /// NAN-918: `splunk_hec` is excluded because `hec_normalize`
    /// (`config/vector/02-hec-source.toml`) populates `.source_type` from
    /// the inbound `.sourcetype` envelope field before this routing
    /// transform runs — so source_type rules on HEC are legitimate
    /// (matches HTTP / Vector).
    fn is_pull_source_source_type_match(config_type: &str, match_field: &str) -> bool {
        !matches!(config_type, "http" | "vector" | "splunk_hec") && match_field == "source_type"
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
    /// System-level default rules (HTTP, Vector, HEC post-NAN-918) are
    /// passthrough no-ops (the routing transform emits
    /// `# passthrough — keep existing .source_type`), so a config with
    /// only defaults adds nothing — we skip the file write entirely.
    fn has_meaningful_routing_rules(config: &SourceConfigurationWithRules) -> bool {
        config
            .routing_rules
            .iter()
            .any(|r| r.match_type != "default")
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

            // HTTP / Vector / HEC all use passthrough-default semantics
            // post-NAN-918: a default rule preserves the upstream
            // `.source_type` (set by source_type_extract for HTTP/Vector,
            // by hec_normalize for HEC). Lets imported parsers' sourcetypes
            // flow through to parser matching without per-parser routing
            // rules. Users who actually need to force `.source_type` to a
            // fixed value can write a non-default rule (e.g. regex `.*`).
            let routing_default_passthrough =
                Self::system_intermediary_source(&config.config_type).is_some();

            let vector_config = if has_meaningful_rules {
                // NAN-940: pin route_name for system-level singletons so a
                // rename of the OOTB row doesn't break parsers that hardcode
                // the transform name (e.g. HEC parsers reading from
                // `splunk_hec_route` via `parser_claimed_route`).
                let route_name = Self::config_route_name(&config.config_type, &config.name);
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
                let config_file = self.get_config_file_path(&config.config_type, &config.name);
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
        let config_file = self.get_config_file_path(&config.config_type, &config.name);
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
            let config_file = self.get_config_file_path(&config.config_type, &config.name);
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
        let config_file = self.get_config_file_path(&config.config_type, &config.name);
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

        // NAN-952: credential filenames are keyed by source-config UUID,
        // not safe_name(config.name). safe_name lowercases + replaces
        // non-alphanumerics with `_`, so e.g. "Prod-Kafka" and "prod kafka"
        // both produced `prod_kafka` — second deploy clobbered the first
        // tenant's CA. UUID is unique by construction.
        let creds_filename_stem = Self::creds_filename_stem(&config.config.id);

        // For GCP Pub/Sub, dispatch credential storage to the active backend.
        // K8s mode PATCHes the `vector-source-credentials` Secret (mounted at
        // /etc/vector/source-creds/); Docker mode writes flat under sources/
        // (NAN-664 layout). The backend returns the absolute path Vector should
        // embed in the generated TOML.
        let gcp_creds_path = if config.config.config_type == "gcp_pubsub" {
            if let Some(ref c) = creds {
                if let Some(creds_json) = c["credentials_json"].as_str() {
                    if !creds_json.is_empty() {
                        let key = format!("gcp_{}.creds", creds_filename_stem);
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

        // Kafka TLS CA cert is persisted by the same backend that handles GCP
        // creds — Vector's `tls.ca_file` wants an on-disk path, not inline PEM
        // (NAN-884 K-1). Empty / absent CA cert falls back to system CAs, which
        // is correct for Confluent Cloud + AWS MSK with public CAs.
        let kafka_ca_path = if config.config.config_type == "kafka" {
            if let Some(ref c) = creds {
                if let Some(ca_cert) = c["tls_ca_cert"].as_str() {
                    if !ca_cert.is_empty() {
                        let key = format!("kafka_{}.ca.pem", creds_filename_stem);
                        let backend = self.creds_backend().await?;
                        Some(backend.write_creds(&key, ca_cert.as_bytes()).await?)
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
            "kafka" => Self::generate_kafka_source(
                &source_name,
                &config.config.id,
                conn,
                creds.as_ref(),
                kafka_ca_path.as_deref(),
            ),
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
    ///
    /// `tls_ca_path` is the absolute path the caller wrote the credential CA
    /// PEM to via the credentials backend (or `None` when no custom CA was
    /// provided — the system CA bundle is then used). The function still
    /// decides whether to emit a `[tls]` block based on the `tls_enabled`
    /// flag on the credential JSON.
    ///
    /// `config_id` is folded into the auto-generated consumer `group_id`
    /// (`nanosiem-<base32 typeid suffix>`) when the user didn't set one
    /// explicitly. Two configs without explicit `group_id` previously
    /// collapsed onto the same broker-side consumer group and split
    /// partitions across them (NAN-884 K-3). Existing rows are backfilled
    /// to literal `"nanosiem"` by `190_kafka_default_group_id_backfill.sql`
    /// so committed offsets survive the rollout.
    fn generate_kafka_source(
        source_name: &str,
        config_id: &Uuid,
        conn: &serde_json::Value,
        creds: Option<&serde_json::Value>,
        tls_ca_path: Option<&str>,
    ) -> String {
        let bootstrap_servers = conn["bootstrap_servers"]
            .as_str()
            .unwrap_or("localhost:9092");
        let topics: Vec<String> = conn["topics"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_else(|| vec!["logs".to_string()]);
        let auto_offset_reset = conn["auto_offset_reset"].as_str().unwrap_or("latest");
        let group_id_owned: String;
        let group_id: &str = match conn["group_id"].as_str() {
            Some(explicit) => explicit,
            None => {
                group_id_owned =
                    format!("nanosiem-{}", crate::typeid::encode_suffix(config_id));
                &group_id_owned
            }
        };

        let mut source = toml::Table::new();
        source.insert("type".into(), "kafka".into());
        source.insert("bootstrap_servers".into(), bootstrap_servers.into());
        source.insert(
            "topics".into(),
            toml::Value::Array(topics.into_iter().map(toml::Value::String).collect()),
        );
        source.insert("group_id".into(), group_id.into());
        source.insert("auto_offset_reset".into(), auto_offset_reset.into());

        // Detect SASL + TLS up front so security.protocol can be chosen
        // accordingly (NAN-884 K-1 / K-2). librdkafka silently defaults to
        // PLAINTEXT when the protocol isn't set, which broke every TLS-required
        // broker (Confluent Cloud, AWS MSK, Aiven Kafka).
        let sasl_mechanism = creds
            .and_then(|c| c["sasl_mechanism"].as_str())
            .filter(|m| !m.is_empty());
        let tls_enabled = creds
            .and_then(|c| c["tls_enabled"].as_bool())
            .unwrap_or(false);

        if let Some(mechanism) = sasl_mechanism {
            let mut sasl = toml::Table::new();
            sasl.insert("enabled".into(), true.into());
            sasl.insert("mechanism".into(), mechanism.into());
            sasl.insert(
                "username".into(),
                creds
                    .and_then(|c| c["sasl_username"].as_str())
                    .unwrap_or("")
                    .into(),
            );
            sasl.insert(
                "password".into(),
                creds
                    .and_then(|c| c["sasl_password"].as_str())
                    .unwrap_or("")
                    .into(),
            );
            source.insert("sasl".into(), toml::Value::Table(sasl));
        }

        if tls_enabled {
            let mut tls = toml::Table::new();
            tls.insert("enabled".into(), true.into());
            if let Some(path) = tls_ca_path {
                tls.insert("ca_file".into(), path.into());
            }
            source.insert("tls".into(), toml::Value::Table(tls));
        }

        // Emit security.protocol whenever SASL or TLS is involved. librdkafka's
        // default is PLAINTEXT, so we only need to override when something else
        // is required — but mismatched combinations (SASL_PLAINTEXT against a
        // TLS-required broker, etc.) are exactly the silent-failure mode
        // NAN-884 is killing, so be explicit.
        let security_protocol = match (sasl_mechanism.is_some(), tls_enabled) {
            (true, true) => Some("SASL_SSL"),
            (true, false) => Some("SASL_PLAINTEXT"),
            (false, true) => Some("SSL"),
            (false, false) => None,
        };
        if let Some(proto) = security_protocol {
            let mut opts = toml::Table::new();
            opts.insert("security.protocol".into(), proto.into());
            source.insert("librdkafka_options".into(), toml::Value::Table(opts));
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
        let mut vrl = String::new();

        // Stamp the ingestion path for pull sources. NAN-201 set
        // `.metadata.forwarded_via` for http / vector_native / splunk_hec in
        // their always-on transforms (config/vector/00-base.toml,
        // 01-vector-source.toml, 02-hec-source.toml), but the per-config
        // generator missed kafka / aws_s3 / gcp_pubsub (NAN-884 K-6).
        // System-level configs route through those always-on transforms
        // already and inherit the stamp, so we skip stamping again here to
        // avoid clobbering values like `splunk_hec`.
        if !system_level {
            if let Some(forwarded_via) =
                Self::forwarded_via_for_pull_source(&config.config.config_type)
            {
                vrl.push_str(&format!(
                    "# Stamp ingestion path for downstream troubleshooting (NAN-884 K-6).\n\
                     # Matches the assignment 00-base.toml / 01-vector-source.toml /\n\
                     # 02-hec-source.toml do for the system-level sources.\n\
                     if !is_object(.metadata) {{\n    .metadata = {{}}\n}}\n\
                     .metadata.forwarded_via = \"{forwarded_via}\"\n\n",
                ));
            }
        }

        vrl.push_str("# Apply routing rules to set source_type\n");

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
            //
            // Kafka headers are the one exception: Vector decodes
            // `.headers` as `Object(String, Bytes)`, and a `Bytes == String`
            // comparison in VRL returns false unconditionally — the
            // "Header (recommended)" routing path was always-false since it
            // shipped (NAN-884 K-7). Coerce header values to string for
            // every comparison; `?? ""` keeps the rule falsy when the
            // header is missing instead of aborting the VRL program.
            let field = Self::routing_field_expression(
                &config.config.config_type,
                &rule.match_field,
            );
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
    /// filesystem check and an explicit `hec_normalize_present` bool so it
    /// stays testable without touching disk or env vars.
    /// `is_system_route_deployed_on_disk` returns true when a system-level
    /// (http/vector/splunk_hec) config has its routing TOML present — only
    /// then does it contribute a route and suppress its corresponding
    /// always-on channel from base inputs.
    fn compute_router_inputs<F>(
        deployed_configs: &[SourceConfiguration],
        is_system_route_deployed_on_disk: F,
        hec_normalize_present: bool,
    ) -> Vec<String>
    where
        F: Fn(&SourceConfiguration) -> bool,
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
                if !is_system_route_deployed_on_disk(config) {
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
            source_config_routes.push(Self::config_route_name(&config.config_type, &config.name));
        }

        let mut router_inputs: Vec<String> = base_router_inputs(
            source_type_extract_covered,
            hec_normalize_covered,
            hec_normalize_present,
        )
        .into_iter()
        .map(String::from)
        .collect();
        router_inputs.extend(source_config_routes);
        router_inputs
    }

    /// Update the dynamic router to include all source configuration routes
    async fn update_dynamic_router(&self) -> Result<(), SourceConfigServiceError> {
        // NAN-948: serialize against parser deploys that mutate the same
        // `_router.toml`. The lock is shared with `VectorConfigManager`
        // (handed in via `with_deploy_lock`). When not wired (unit tests,
        // legacy callers), proceed without locking — those paths don't
        // collide with parser deploys.
        let _deploy_guard = match &self.deploy_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };

        // Get all deployed source configs
        let deployed_configs = self
            .repository
            .list(Some(ListParams {
                deployed: Some(true),
                ..Default::default()
            }))
            .await?;

        // NAN-930: load parser-route claims so the substitution stays correct
        // across source-config redeploys. Without this, the surgical inputs
        // rewrite would put back raw route names that double-feed events into
        // both `source_router` and the per-parser filter.
        let claims = self.repository.load_route_claims().await?;
        let claim_substitutions = Self::build_claim_substitutions(&claims);

        let router_inputs = Self::compute_router_inputs(
            &deployed_configs,
            |cfg| self.get_config_file_path(&cfg.config_type, &cfg.name).exists(),
            hec_normalize_present(),
        );
        // Apply claim substitution AFTER compute_router_inputs so the
        // pure function (and its 8 unit tests) stay focused on the base-input
        // logic; this layer adds dedupe-safety on top.
        let substituted_inputs: Vec<String> = router_inputs
            .iter()
            .map(|name| {
                claim_substitutions
                    .get(name.as_str())
                    .cloned()
                    .unwrap_or_else(|| name.clone())
            })
            .collect();

        let new_inputs_line = format!(
            "inputs = [{}]",
            substituted_inputs
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

        let raw_content = tokio::fs::read_to_string(&router_path).await?;

        // NAN-930: strip then rewrite all `<route>_unclaimed` filter blocks.
        // Adding-only (the previous behavior) left stale conditions for
        // edited `match_values` and orphan blocks for renamed/deleted
        // source-configs. The clean rewrite handles both:
        //   - match_values changes propagate via build_unclaimed_blocks
        //     emitting the current condition
        //   - removed claims simply don't get re-emitted; their blocks
        //     stripped above don't return
        // Filter blocks are injected just above `[transforms.source_router]`
        // (placement is cosmetic — Vector resolves inputs file-wide).
        let current_content = Self::strip_existing_unclaimed_blocks(&raw_content);
        let claim_blocks = Self::build_unclaimed_blocks(&claims);

        // Replace the inputs line in the [transforms.source_router] section.
        // Match the first inputs = [...] line that appears after the source_router header.
        // We can't rely on "source_type_extract" being present since system-level routes
        // may have already removed it.
        let mut updated = String::new();
        let mut found = false;
        let mut in_source_router = false;
        let mut filter_block_emitted = false;
        for line in current_content.lines() {
            let trimmed = line.trim();
            if trimmed == "[transforms.source_router]" {
                // Emit unclaimed-filter blocks immediately before
                // source_router so the file reads top-down.
                if !filter_block_emitted && !claim_blocks.is_empty() {
                    updated.push_str(&claim_blocks);
                    filter_block_emitted = true;
                }
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

    /// NAN-930: build the route→substituted-route map. Any route that one or
    /// more enabled parsers claim is rewritten to `<route>_unclaimed` so the
    /// surgical inputs update keeps `source_router` consuming only the
    /// leftover stream (events no parser-filter matched).
    fn build_claim_substitutions(claims: &[RouteClaim]) -> HashMap<&str, String> {
        let mut subs: HashMap<&str, String> = HashMap::new();
        for claim in claims {
            subs.entry(claim.route.as_str())
                .or_insert_with(|| format!("{}_unclaimed", claim.route));
        }
        subs
    }

    /// NAN-930: strip all `[transforms.*_unclaimed]` filter blocks from the
    /// router file content. Pairs with `build_unclaimed_blocks` to give
    /// `update_dynamic_router` a clean rewrite (no stale conditions for
    /// changed `match_values`, no orphan blocks for renamed/deleted
    /// source-configs).
    ///
    /// Line-by-line state machine: enter "skip" mode when we see a
    /// `[transforms.<name>_unclaimed]` header, exit on the next `[` (next
    /// TOML section starts) or EOF. Comment lines that happen to mention
    /// `_unclaimed` don't trigger skip — we only match section headers
    /// (line starts with `[`, ignoring whitespace).
    pub(super) fn strip_existing_unclaimed_blocks(content: &str) -> String {
        let mut out = String::new();
        let mut in_unclaimed = false;
        for line in content.lines() {
            let trimmed = line.trim_start();
            // Section-header start. Decide whether to enter or exit skip mode.
            if trimmed.starts_with('[') {
                in_unclaimed = trimmed.starts_with("[transforms.")
                    && trimmed.contains("_unclaimed]");
                if in_unclaimed {
                    continue;
                }
            }
            if in_unclaimed {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// NAN-930: format `[transforms.<route>_unclaimed]` filter blocks for
    /// every current claim. Pair with `strip_existing_unclaimed_blocks` so
    /// `update_dynamic_router` does a clean rewrite — both renamed/deleted
    /// claims (block disappears) and changed `match_values` (condition
    /// regenerates) propagate without needing a parser redeploy. Earlier
    /// "add missing only" version left stale blocks behind and was the
    /// root cause of the NAN-930 gotchas #2 + #3.
    fn build_unclaimed_blocks(claims: &[RouteClaim]) -> String {
        // Group claimants by route so the union match_values list comes out stable.
        let mut by_route: BTreeMap<&str, Vec<&RouteClaim>> = BTreeMap::new();
        for claim in claims {
            by_route.entry(claim.route.as_str()).or_default().push(claim);
        }

        let mut out = String::new();
        for (route, claimants) in by_route {
            let filter_name = format!("{}_unclaimed", route);
            let mut values: Vec<String> = Vec::new();
            for claim in claimants {
                if claim.match_values.is_empty() {
                    values.push(claim.parser_name.clone());
                } else {
                    values.extend(claim.match_values.iter().cloned());
                }
            }
            values.sort();
            values.dedup();
            let list = values
                .iter()
                .map(|v| {
                    // Same minimal escape rule as the parser-config generator —
                    // backslashes, quotes, and embedded newlines.
                    let mut esc = String::with_capacity(v.len());
                    for ch in v.chars() {
                        match ch {
                            '\\' => esc.push_str("\\\\"),
                            '"' => esc.push_str("\\\""),
                            '\n' => esc.push_str("\\n"),
                            '\r' => esc.push_str("\\r"),
                            _ => esc.push(ch),
                        }
                    }
                    format!("\"{}\"", esc)
                })
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "[transforms.{}]\n\
                 type = \"filter\"\n\
                 inputs = [\"{}\"]\n\
                 condition = '!includes([{}], to_string(.source_type) ?? \"\")'\n\n",
                filter_name, route, list,
            ));
        }
        out
    }

    /// Build the VRL access expression for a routing-rule `match_field`.
    ///
    /// Default is a plain dotted access — `headers.source_type` becomes
    /// `.headers.source_type`. Kafka headers need a `to_string` coercion
    /// because Vector's `kafka` source decodes `.headers` as
    /// `Object(String, Bytes)` and a `Bytes == String` comparison in VRL
    /// is unconditionally false (NAN-884 K-7). `?? ""` ensures missing
    /// headers fall through cleanly rather than aborting the VRL program.
    ///
    /// GCP `attributes.*` doesn't need coercion — `gcp_pubsub` decodes
    /// `.attributes` as `Object(String, String)` already.
    fn routing_field_expression(config_type: &str, match_field: &str) -> String {
        if config_type == "kafka" && match_field.starts_with("headers.") {
            format!("(to_string(.{match_field}) ?? \"\")")
        } else {
            format!(".{match_field}")
        }
    }

    /// Map a pull-source `config_type` to the canonical
    /// `.metadata.forwarded_via` value emitted in the per-config routing
    /// transform (NAN-884 K-6). Values match NAN-201's HTTP/HEC/Vector
    /// conventions: short, lowercase, `aws_s3`/`gcp_pubsub` keep the
    /// Vector source-type spelling so detection rules can filter by it.
    /// System-level configs (http / vector / splunk_hec) are stamped in
    /// their always-on transforms and are not handled here.
    fn forwarded_via_for_pull_source(config_type: &str) -> Option<&'static str> {
        match config_type {
            "kafka" => Some("kafka"),
            "aws_s3" => Some("aws_s3"),
            "gcp_pubsub" => Some("gcp_pubsub"),
            _ => None,
        }
    }

    /// Pure helper for `update()`'s rename-cleanup branch.
    ///
    /// Returns true iff a rename actually changed the on-disk file stem,
    /// signalling that the old file is now an orphan and should be
    /// removed. For system-level singletons whose file stem is pinned
    /// (NAN-940 — splunk_hec) this returns false even when the user-facing
    /// name changes, because both stems resolve to the same singleton id.
    ///
    /// Split out so the precondition can be unit-tested without spinning
    /// up a Postgres pool. NAN-947.
    fn rename_changes_on_disk_stem(
        old_config_type: &str,
        old_name: &str,
        new_config_type: &str,
        new_name: &str,
    ) -> bool {
        Self::config_safe_stem(old_config_type, old_name)
            != Self::config_safe_stem(new_config_type, new_name)
    }

    /// Get the path for a source config file.
    ///
    /// System-level singleton drivers (today: `splunk_hec`) use a pinned
    /// stem (`splunk_hec.toml`) regardless of the user-facing `name`, so
    /// renaming the OOTB row can't strand the deployed file on disk and
    /// can't break parsers that consume from a fixed transform name. NAN-940.
    fn get_config_file_path(&self, config_type: &str, name: &str) -> PathBuf {
        let stem = Self::config_safe_stem(config_type, name);
        self.vector_config_dir
            .join("sources")
            .join("configs")
            .join(format!("{}.toml", stem))
    }

    /// Stable identifier stem for a source configuration. System-level
    /// singletons return a pinned, type-derived stem so a rename can't
    /// cascade into broken parser routing or duplicate on-disk files;
    /// everything else hashes through `safe_name` of the user-facing name.
    /// NAN-940.
    fn config_safe_stem(config_type: &str, name: &str) -> String {
        if let Some(pinned) = Self::system_singleton_stem(config_type) {
            return pinned.to_string();
        }
        Self::safe_name(name)
    }

    /// Pinned safe-name stem for system-level singleton drivers whose
    /// route-transform name downstream parsers hardcode. Returning
    /// `Some(stem)` overrides the rename-derived `safe_name` so an admin
    /// renaming the OOTB row can't break HEC routing. NAN-940.
    ///
    /// Today only `splunk_hec` is a singleton (paired with
    /// `is_single_instance_driver` and the partial unique index from
    /// migration 184). Adding a new singleton driver here also requires
    /// adding it to `is_single_instance_driver`.
    fn system_singleton_stem(config_type: &str) -> Option<&'static str> {
        match config_type {
            "splunk_hec" => Some("splunk_hec"),
            _ => None,
        }
    }

    /// Route-transform name for a source configuration's generated TOML.
    /// `<stem>_route` where `stem` is pinned for singletons (NAN-940).
    fn config_route_name(config_type: &str, name: &str) -> String {
        format!("{}_route", Self::config_safe_stem(config_type, name))
    }

    /// Stable, collision-free stem for on-disk credential filenames
    /// (Kafka CA PEM, GCP service-account JSON). NAN-952.
    ///
    /// Pre-NAN-952 these used `safe_name(config.name)`, which lowercases +
    /// replaces non-alphanumerics with `_`. Two configs named
    /// `"Prod-Kafka"` and `"prod kafka"` both resolved to `prod_kafka`,
    /// so the second deploy clobbered the first's credentials on disk.
    /// The UUID is unique by construction.
    fn creds_filename_stem(config_id: &Uuid) -> String {
        // Hyphenated UUID is 36 chars of [0-9a-f-] — filesystem-safe on
        // every target (Docker bind-mount, K8s ConfigMap-as-files,
        // K8s Secret-as-files). No further sanitization needed.
        config_id.to_string()
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
        // Narrow assertion: ensure no source_type conditional. The
        // forwarded_via stamp (NAN-884 K-6) introduces an unrelated
        // `if !is_object(.metadata)` guard which is fine here.
        assert!(
            !vrl.contains("if .source_type"),
            "expected no source_type conditional, got:\n{}",
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
    fn kafka_with_headers_path_match_field_emits_coerced_access() {
        // NAN-884 K-7: Vector's kafka source emits `.headers` as
        // `Object(String, Bytes)`; a raw `.headers.source_type == "X"`
        // comparison is `Bytes == String` and is always-false. The
        // generator must wrap header accesses in `to_string(...) ?? ""`
        // so the comparison actually fires.
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
            vrl.contains(
                "if (to_string(.headers.source_type) ?? \"\") == \"audit_logs\""
            ),
            "expected coerced headers.source_type conditional, got:\n{vrl}",
        );
        // Regression guard: the broken raw form must not slip back in.
        assert!(
            !vrl.contains("if .headers.source_type =="),
            "raw .headers access regressed (Bytes vs String always-false), got:\n{vrl}",
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
        let out = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, None, None);
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
        let out = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, Some(&creds), None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert!(!parsed_has_unexpected_top_level_tables(&parsed), "{out}");
        assert_eq!(
            parsed["sources"]["test"]["sasl"]["password"].as_str().unwrap(),
            payload,
        );
    }

    // ------------------------------------------------------------------
    // NAN-884 K-1 / K-2: TLS block + librdkafka security.protocol must
    // both make it into the generated Vector source so cloud-hosted
    // brokers (Confluent Cloud, MSK, Aiven) actually connect instead of
    // failing silently with a PLAINTEXT handshake against a TLS broker.
    // ------------------------------------------------------------------

    /// Credential with `tls_enabled = true` and a CA cert path persisted by
    /// the caller must emit `[sources.<name>.tls]` with `enabled = true` and
    /// the supplied `ca_file`.
    #[test]
    fn kafka_generator_emits_tls_block_when_credential_has_tls() {
        let conn = serde_json::json!({
            "bootstrap_servers": "broker.confluent.cloud:9092",
            "topics": ["audit"],
        });
        let creds = serde_json::json!({
            "sasl_mechanism": "SCRAM-SHA-512",
            "sasl_username": "u",
            "sasl_password": "p",
            "tls_enabled": true,
            "tls_ca_cert": "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        });
        let ca_path = "/etc/vector/source-creds/kafka_test.ca.pem";
        let out = SourceConfigService::generate_kafka_source(
            "test",
            &Uuid::nil(),
            &conn,
            Some(&creds),
            Some(ca_path),
        );
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        let tls = parsed["sources"]["test"]["tls"]
            .as_table()
            .expect("tls block must be emitted when tls_enabled");
        assert_eq!(tls["enabled"].as_bool(), Some(true));
        assert_eq!(tls["ca_file"].as_str(), Some(ca_path));
    }

    /// `tls_enabled = true` without a custom CA still emits the TLS block —
    /// Vector then trusts the system CA bundle (Confluent Cloud's public CA
    /// is in there). No `ca_file` key should appear.
    #[test]
    fn kafka_generator_tls_block_omits_ca_file_when_no_cert_supplied() {
        let conn = serde_json::json!({
            "bootstrap_servers": "broker:9092",
            "topics": ["x"],
        });
        let creds = serde_json::json!({ "tls_enabled": true });
        let out = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, Some(&creds), None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        let tls = parsed["sources"]["test"]["tls"]
            .as_table()
            .expect("tls block must be emitted");
        assert_eq!(tls["enabled"].as_bool(), Some(true));
        assert!(
            !tls.contains_key("ca_file"),
            "ca_file must be absent when no cert is provided, fall back to system CAs",
        );
    }

    /// SASL + TLS together must produce `security.protocol = "SASL_SSL"`.
    #[test]
    fn kafka_generator_emits_security_protocol_sasl_ssl() {
        let conn = serde_json::json!({ "bootstrap_servers": "h:9092", "topics": ["x"] });
        let creds = serde_json::json!({
            "sasl_mechanism": "SCRAM-SHA-256",
            "sasl_username": "u",
            "sasl_password": "p",
            "tls_enabled": true,
        });
        let out = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, Some(&creds), None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert_eq!(
            parsed["sources"]["test"]["librdkafka_options"]["security.protocol"].as_str(),
            Some("SASL_SSL"),
        );
    }

    /// SASL only (no TLS) → SASL_PLAINTEXT. Covers the local SASL_PLAINTEXT
    /// listener case in the test stand.
    #[test]
    fn kafka_generator_emits_security_protocol_sasl_plaintext() {
        let conn = serde_json::json!({ "bootstrap_servers": "h:9092", "topics": ["x"] });
        let creds = serde_json::json!({
            "sasl_mechanism": "PLAIN",
            "sasl_username": "u",
            "sasl_password": "p",
        });
        let out = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, Some(&creds), None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert_eq!(
            parsed["sources"]["test"]["librdkafka_options"]["security.protocol"].as_str(),
            Some("SASL_PLAINTEXT"),
        );
    }

    /// TLS only (no SASL) → SSL. Used by anonymous-but-TLS-required brokers.
    #[test]
    fn kafka_generator_emits_security_protocol_ssl_when_tls_only() {
        let conn = serde_json::json!({ "bootstrap_servers": "h:9093", "topics": ["x"] });
        let creds = serde_json::json!({ "tls_enabled": true });
        let out = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, Some(&creds), None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert_eq!(
            parsed["sources"]["test"]["librdkafka_options"]["security.protocol"].as_str(),
            Some("SSL"),
        );
    }

    /// Plain anonymous broker (T-1 local stand): no librdkafka_options table
    /// should appear — keeping the generated TOML minimal and letting Vector
    /// use its PLAINTEXT default.
    #[test]
    fn kafka_generator_omits_security_protocol_when_plaintext() {
        let conn = serde_json::json!({ "bootstrap_servers": "kafka:9092", "topics": ["x"] });
        let out = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, None, None);
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert!(
            parsed["sources"]["test"].get("librdkafka_options").is_none(),
            "anonymous PLAINTEXT must not emit librdkafka_options:\n{out}",
        );
        assert!(
            parsed["sources"]["test"].get("tls").is_none(),
            "anonymous PLAINTEXT must not emit tls block:\n{out}",
        );
    }

    // ------------------------------------------------------------------
    // NAN-884 K-3: consumer-group_id must be unique per source-config when
    // not explicitly set. Two implicit-group_id Kafka configs against the
    // same broker previously shared the literal "nanosiem" group and split
    // partitions across them, silently halving throughput per consumer.
    // ------------------------------------------------------------------

    /// Two different source-config ids without explicit `group_id` must
    /// produce two different generated group_ids. Format is documented as
    /// `nanosiem-<base32 typeid suffix>` so operators recognize it on the
    /// broker side.
    #[test]
    fn kafka_generator_auto_generates_unique_group_id_per_config() {
        let conn = serde_json::json!({ "bootstrap_servers": "h:9092", "topics": ["x"] });
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();

        let out_a =
            SourceConfigService::generate_kafka_source("a", &id_a, &conn, None, None);
        let out_b =
            SourceConfigService::generate_kafka_source("b", &id_b, &conn, None, None);

        let parsed_a: toml::Value = toml::from_str(&out_a).expect("a must parse");
        let parsed_b: toml::Value = toml::from_str(&out_b).expect("b must parse");

        let gid_a = parsed_a["sources"]["a"]["group_id"]
            .as_str()
            .expect("group_id must be emitted");
        let gid_b = parsed_b["sources"]["b"]["group_id"]
            .as_str()
            .expect("group_id must be emitted");

        assert_ne!(gid_a, gid_b, "two configs must get different group_ids");
        assert!(
            gid_a.starts_with("nanosiem-"),
            "auto-generated group_id must use the nanosiem- prefix, got {gid_a}",
        );
        assert_eq!(
            gid_a.len(),
            "nanosiem-".len() + 26,
            "auto-generated suffix must be a 26-char base32 typeid suffix, got {gid_a}",
        );
    }

    /// Explicit user-set `group_id` in `connection_config` always wins —
    /// even when the user picks the legacy literal "nanosiem", we must
    /// keep that value (this is the post-migration shape for already-
    /// deployed configs and preserves their committed broker offsets).
    #[test]
    fn kafka_generator_preserves_explicit_group_id() {
        let conn = serde_json::json!({
            "bootstrap_servers": "h:9092",
            "topics": ["x"],
            "group_id": "my-team-pipeline",
        });
        let out = SourceConfigService::generate_kafka_source(
            "test",
            &Uuid::new_v4(),
            &conn,
            None,
            None,
        );
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert_eq!(
            parsed["sources"]["test"]["group_id"].as_str(),
            Some("my-team-pipeline"),
        );
    }

    /// Post-migration shape: existing rows backfilled to `"nanosiem"` by
    /// `190_kafka_default_group_id_backfill.sql` must keep that value so
    /// already-deployed consumers don't restart from `auto_offset_reset`.
    #[test]
    fn kafka_generator_preserves_backfilled_nanosiem_group_id() {
        let conn = serde_json::json!({
            "bootstrap_servers": "h:9092",
            "topics": ["x"],
            "group_id": "nanosiem",
        });
        let out = SourceConfigService::generate_kafka_source(
            "test",
            &Uuid::new_v4(),
            &conn,
            None,
            None,
        );
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        assert_eq!(parsed["sources"]["test"]["group_id"].as_str(), Some("nanosiem"));
    }

    // ------------------------------------------------------------------
    // NAN-884 K-6: per-config routing transform must stamp
    // `.metadata.forwarded_via` for pull sources so downstream rows can
    // be filtered by ingestion path (NAN-201 covered HTTP / HEC / vector
    // already via the always-on transforms in config/vector/*.toml).
    // ------------------------------------------------------------------

    /// Kafka routing transform must set `.metadata.forwarded_via = "kafka"`
    /// before the source_type rules so detection rules / ad-hoc searches can
    /// filter by ingestion path the same way they do for HEC.
    #[test]
    fn routing_transform_stamps_forwarded_via_for_kafka() {
        let config = make_config(
            "kafka",
            vec![make_rule(1000, "topic", "default", None, "apache_http_server")],
        );

        let toml_out =
            SourceConfigService::generate_routing_transform(&config, "src", "route", false);
        let parsed: toml::Value = toml::from_str(&toml_out).expect("must parse");
        let vrl = parsed["transforms"]["route"]["source"]
            .as_str()
            .expect("source string");

        assert!(
            vrl.contains(".metadata.forwarded_via = \"kafka\""),
            "expected kafka forwarded_via stamp, got:\n{vrl}",
        );
        assert!(
            vrl.contains("if !is_object(.metadata)"),
            "expected metadata object guard, got:\n{vrl}",
        );
    }

    /// AWS S3 routing transform stamps `aws_s3` (same gap as Kafka — pull
    /// source with no upstream `forwarded_via`).
    #[test]
    fn routing_transform_stamps_forwarded_via_for_aws_s3() {
        let config = make_config(
            "aws_s3",
            vec![make_rule(1000, "source_type", "default", None, "aws_cloudtrail")],
        );

        let toml_out =
            SourceConfigService::generate_routing_transform(&config, "src", "route", false);
        let parsed: toml::Value = toml::from_str(&toml_out).expect("must parse");
        let vrl = parsed["transforms"]["route"]["source"]
            .as_str()
            .expect("source string");

        assert!(
            vrl.contains(".metadata.forwarded_via = \"aws_s3\""),
            "expected aws_s3 forwarded_via stamp, got:\n{vrl}",
        );
    }

    /// GCP Pub/Sub routing transform stamps `gcp_pubsub`.
    #[test]
    fn routing_transform_stamps_forwarded_via_for_gcp_pubsub() {
        let config = make_config(
            "gcp_pubsub",
            vec![make_rule(1000, "source_type", "default", None, "gcp_audit_log")],
        );

        let toml_out =
            SourceConfigService::generate_routing_transform(&config, "src", "route", false);
        let parsed: toml::Value = toml::from_str(&toml_out).expect("must parse");
        let vrl = parsed["transforms"]["route"]["source"]
            .as_str()
            .expect("source string");

        assert!(
            vrl.contains(".metadata.forwarded_via = \"gcp_pubsub\""),
            "expected gcp_pubsub forwarded_via stamp, got:\n{vrl}",
        );
    }

    /// System-level sources (http / vector / splunk_hec) MUST NOT get the
    /// per-config stamp — their always-on transforms in `config/vector/*.toml`
    /// already set `forwarded_via`, and a second assignment here would
    /// clobber the upstream value (e.g. overwrite `splunk_hec` with `http`).
    #[test]
    fn routing_transform_skips_forwarded_via_for_system_level_sources() {
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

        let toml_out = SourceConfigService::generate_routing_transform(
            &config,
            "source_type_extract",
            "route",
            true,
        );
        let parsed: toml::Value = toml::from_str(&toml_out).expect("must parse");
        let vrl = parsed["transforms"]["route"]["source"]
            .as_str()
            .expect("source string");

        assert!(
            !vrl.contains("forwarded_via"),
            "system-level routing transform must not stamp forwarded_via, got:\n{vrl}",
        );
    }

    // ------------------------------------------------------------------
    // NAN-884 K-7: Kafka header match must wrap value access in
    // `to_string(...) ?? ""`. Without the coercion the comparison is
    // `Bytes == String` and is always-false; the entire "Header
    // (recommended)" routing preset was broken since it shipped.
    // ------------------------------------------------------------------

    /// `prefix` / `suffix` / `contains` match types all take string-coerced
    /// inputs too — coercion must apply to every match type, not just
    /// `exact`.
    #[test]
    fn kafka_headers_path_match_field_is_coerced_for_all_match_types() {
        for (mt, expected_fn_call) in [
            ("prefix", "starts_with((to_string(.headers.team) ?? \"\")"),
            ("suffix", "ends_with((to_string(.headers.team) ?? \"\")"),
            ("contains", "contains((to_string(.headers.team) ?? \"\")"),
            ("regex", "match((to_string(.headers.team) ?? \"\")"),
        ] {
            let config = make_config(
                "kafka",
                vec![
                    make_rule(10, "headers.team", mt, Some("audit"), "audit_logs"),
                    make_rule(1000, "topic", "default", None, "unknown"),
                ],
            );
            let vrl =
                SourceConfigService::generate_routing_transform(&config, "src", "route", false);
            assert!(
                vrl.contains(expected_fn_call),
                "match_type={mt} must coerce header to string, got:\n{vrl}",
            );
        }
    }

    /// Non-Kafka configs do not need (and must not get) the header
    /// coercion — `gcp_pubsub` already exposes `.attributes` as
    /// `Object(String, String)`, and adding a `to_string(...) ?? ""`
    /// wrapper there would be dead weight.
    #[test]
    fn non_kafka_header_paths_are_not_coerced() {
        // gcp_pubsub commonly uses `attributes.*`; even if a rule used the
        // word "headers" the source type isn't kafka so no coercion.
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
        let vrl =
            SourceConfigService::generate_routing_transform(&config, "src", "route", false);
        assert!(
            vrl.contains("if .attributes.source_type == \"limacharlie_edr\""),
            "gcp_pubsub attributes must keep plain access, got:\n{vrl}",
        );
        assert!(
            !vrl.contains("to_string(.attributes"),
            "gcp_pubsub attributes must NOT be wrapped, got:\n{vrl}",
        );
    }

    /// Coerced VRL must still compile against the standard VRL function
    /// set — otherwise Vector rejects the generated config on deploy and
    /// the failure surfaces only in saturn logs (per
    /// `feedback_compile_test_generated_vrl`).
    #[test]
    fn routing_transform_vrl_compiles_with_kafka_header_coercion() {
        let fns = vrl::stdlib::all();
        for mt in ["exact", "prefix", "suffix", "contains", "regex"] {
            let config = make_config(
                "kafka",
                vec![
                    make_rule(10, "headers.source_type", mt, Some("sysmon"), "sysmon"),
                    make_rule(1000, "topic", "default", None, "unknown"),
                ],
            );
            let toml_out = SourceConfigService::generate_routing_transform(
                &config, "src", "route", false,
            );
            let parsed: toml::Value = toml::from_str(&toml_out).expect("must parse");
            let vrl_src = parsed["transforms"]["route"]["source"]
                .as_str()
                .expect("source string");
            if let Err(diagnostics) = vrl::compiler::compile(vrl_src, &fns) {
                let formatted =
                    vrl::diagnostic::Formatter::new(vrl_src, diagnostics).to_string();
                panic!(
                    "match_type={mt} kafka header VRL failed to compile:\n\
                     {vrl_src}\n\
                     ---\n{formatted}",
                );
            }
        }
    }

    /// Unit-level coverage for the helper itself — Kafka headers get
    /// coerced, everything else stays plain.
    #[test]
    fn routing_field_expression_picks_coerced_form_for_kafka_headers_only() {
        assert_eq!(
            SourceConfigService::routing_field_expression("kafka", "headers.source_type"),
            "(to_string(.headers.source_type) ?? \"\")",
        );
        assert_eq!(
            SourceConfigService::routing_field_expression("kafka", "headers.team_id"),
            "(to_string(.headers.team_id) ?? \"\")",
        );
        // Kafka non-headers fields stay plain.
        assert_eq!(
            SourceConfigService::routing_field_expression("kafka", "topic"),
            ".topic",
        );
        // Other config types stay plain even for `headers.*` (defensive).
        assert_eq!(
            SourceConfigService::routing_field_expression("gcp_pubsub", "attributes.source_type"),
            ".attributes.source_type",
        );
        assert_eq!(
            SourceConfigService::routing_field_expression("aws_s3", "bucket"),
            ".bucket",
        );
    }

    /// VRL compile gate (per `feedback_compile_test_generated_vrl`): the
    /// emitted metadata-object guard + forwarded_via assignment must
    /// type-check against the standard VRL function set — otherwise Vector
    /// startup fails on deploy and the failure surfaces only in saturn
    /// logs (NAN-667 E651 precedent).
    #[test]
    fn routing_transform_vrl_compiles_with_forwarded_via_stamp() {
        let fns = vrl::stdlib::all();
        for config_type in ["kafka", "aws_s3", "gcp_pubsub"] {
            let config = make_config(
                config_type,
                vec![make_rule(1000, "topic", "default", None, "apache_http_server")],
            );
            let toml_out = SourceConfigService::generate_routing_transform(
                &config, "src", "route", false,
            );
            let parsed: toml::Value = toml::from_str(&toml_out).expect("must parse");
            let vrl_src = parsed["transforms"]["route"]["source"]
                .as_str()
                .expect("source string");
            if let Err(diagnostics) = vrl::compiler::compile(vrl_src, &fns) {
                let formatted =
                    vrl::diagnostic::Formatter::new(vrl_src, diagnostics).to_string();
                panic!(
                    "routing transform VRL for {config_type} failed to compile:\n\
                     {vrl_src}\n\
                     ---\n{formatted}",
                );
            }
        }
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

        // NAN-855: post-NAN-853, HEC's connection_config is non-configurable
        // per source. Empty payloads are the valid shape; the next test below
        // (`validate_connection_config_rejects_vestigial_splunk_hec_fields`)
        // pins the rejection of populated `address` / `valid_tokens`.
        let hec_empty = serde_json::json!({});
        SourceConfigService::validate_connection_config("splunk_hec", &hec_empty).unwrap();
        let hec_nulls = serde_json::json!({
            "address": null,
            "valid_tokens": [],
            "permit_origin": [],
            "tls": {},
        });
        SourceConfigService::validate_connection_config("splunk_hec", &hec_nulls).unwrap();
    }

    /// NAN-883: lock the single-instance driver matrix. `splunk_hec` is the
    /// only driver where the OOTB listener is shared and a second user
    /// config would emit a colliding routing transform. Push drivers
    /// (http/vector) and broker pulls (kafka/aws_s3/gcp_pubsub) all support
    /// multiple instances.
    #[test]
    fn is_single_instance_driver_matrix() {
        assert!(SourceConfigService::is_single_instance_driver("splunk_hec"));
        for driver in ["http", "vector", "kafka", "aws_s3", "gcp_pubsub", "unknown"] {
            assert!(
                !SourceConfigService::is_single_instance_driver(driver),
                "{driver} must not be single-instance",
            );
        }
    }

    /// NAN-883: `reject_if_duplicate_single_instance` is the pure decision
    /// the create-path uses against the existing-configs list returned by
    /// the repository. The DB-level partial unique index (migration 184)
    /// is the race-safety backstop; this is the friendly-error path.
    #[test]
    fn reject_if_duplicate_single_instance_returns_conflict_on_match() {
        let existing = vec![
            fake_config("kafka-prod", "kafka"),
            fake_config("hec-main", "splunk_hec"),
        ];
        // Existing splunk_hec → duplicate creation must be rejected.
        let err =
            SourceConfigService::reject_if_duplicate_single_instance("splunk_hec", &existing)
                .expect("expected Conflict, got None");
        match err {
            SourceConfigServiceError::Conflict(msg) => {
                assert!(msg.contains("splunk_hec"), "msg: {msg}");
                assert!(msg.contains("Only one"), "msg: {msg}");
            }
            other => panic!("expected Conflict variant, got {other:?}"),
        }
    }

    #[test]
    fn reject_if_duplicate_single_instance_passes_with_no_existing_hec() {
        // No HEC in the list — even with other drivers present, creating a
        // HEC config must be allowed.
        let existing = vec![
            fake_config("kafka-prod", "kafka"),
            fake_config("s3-cloudtrail", "aws_s3"),
        ];
        assert!(
            SourceConfigService::reject_if_duplicate_single_instance("splunk_hec", &existing)
                .is_none()
        );
    }

    #[test]
    fn reject_if_duplicate_single_instance_passes_with_empty_existing() {
        assert!(
            SourceConfigService::reject_if_duplicate_single_instance("splunk_hec", &[]).is_none()
        );
    }

    /// Helper: build a minimal SourceConfiguration row for in-memory tests.
    fn fake_config(name: &str, config_type: &str) -> SourceConfiguration {
        SourceConfiguration {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: None,
            config_type: config_type.to_string(),
            connection_config: serde_json::json!({}),
            credential_id: None,
            enabled: false,
            deployed: false,
            deployed_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            events_24h: None,
            bytes_per_day_24h: None,
            last_event_at: None,
        }
    }

    /// NAN-855: vestigial `splunk_hec` fields (`address`, `valid_tokens`,
    /// `permit_origin`, `tls`) must be rejected when populated — they have
    /// zero effect at deploy time post-NAN-853, so accepting them would
    /// silently mislead operators into thinking they're configurable.
    #[test]
    fn validate_connection_config_rejects_vestigial_splunk_hec_fields() {
        for (field, payload) in [
            (
                "address",
                serde_json::json!({ "address": "0.0.0.0:8088" }),
            ),
            (
                "valid_tokens",
                serde_json::json!({
                    "valid_tokens": ["00000000-0000-0000-0000-000000000000"]
                }),
            ),
            (
                "permit_origin",
                serde_json::json!({ "permit_origin": ["10.0.0.0/8"] }),
            ),
            (
                "tls",
                serde_json::json!({ "tls": { "enabled": true } }),
            ),
        ] {
            let err = SourceConfigService::validate_connection_config("splunk_hec", &payload)
                .unwrap_err();
            assert!(
                err.to_string().contains(field) && err.to_string().contains("not configurable"),
                "expected rejection of vestigial `{field}`, got: {err}",
            );
        }
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
        let mut full = SourceConfigService::generate_kafka_source("test", &Uuid::nil(), &conn, None, None);
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

    /// Guards against the NAN-852 regression: when the base config defines
    /// `hec_normalize` (OOTB open-core), any source-config mutation rebuilds
    /// the router inputs and `hec_normalize` must never be dropped.
    #[test]
    fn compute_router_inputs_always_contains_hec_normalize_when_present() {
        let scenarios: Vec<Vec<SourceConfiguration>> = vec![
            vec![],
            vec![bare_config("kafka_audit", "kafka")],
            vec![bare_config("http_main", "http")],
            vec![bare_config("vec_relay", "vector"), bare_config("s3_logs", "s3")],
        ];

        for configs in scenarios {
            let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true, true);
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

    /// NAN-867: when the base config doesn't define `hec_normalize` (nano-main
    /// customer deploys), it must never appear in router inputs — Vector 0.55
    /// rejects dangling input references at startup.
    #[test]
    fn compute_router_inputs_never_contains_hec_normalize_when_absent() {
        let scenarios: Vec<Vec<SourceConfiguration>> = vec![
            vec![],
            vec![bare_config("kafka_audit", "kafka")],
            vec![bare_config("http_main", "http")],
            vec![bare_config("vec_relay", "vector"), bare_config("s3_logs", "s3")],
        ];

        for configs in scenarios {
            let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true, false);
            assert!(
                !inputs.iter().any(|s| s == "hec_normalize"),
                "hec_normalize emitted with hec_normalize_present=false for configs={:?}",
                configs.iter().map(|c| &c.name).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn compute_router_inputs_appends_non_system_routes_after_base() {
        let configs = vec![bare_config("kafka_audit", "kafka")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| false, true);
        assert_eq!(
            inputs,
            vec!["source_type_extract", "vector_merge", "hec_normalize", "kafka_audit_route"]
        );
    }

    #[test]
    fn compute_router_inputs_drops_source_type_extract_when_system_route_on_disk() {
        let configs = vec![bare_config("http_main", "http")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true, true);
        assert_eq!(inputs, vec!["vector_merge", "hec_normalize", "http_main_route"]);
    }

    #[test]
    fn compute_router_inputs_skips_system_route_when_no_file_on_disk() {
        let configs = vec![bare_config("http_main", "http")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| false, true);
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

    /// NAN-918: HEC now uses HTTP-parity passthrough-default semantics.
    /// A default rule on a HEC config preserves `.source_type` (set by
    /// hec_normalize from the envelope's sourcetype), so imported parsers
    /// with various sourcetypes route correctly without per-parser rules.
    /// Users who need "force all events to <X>" can express that with a
    /// non-default rule (e.g. regex `.*`).
    ///
    /// Supersedes the pre-NAN-918 NAN-856 "default target is authoritative"
    /// semantic — HEC was reclassified as push in NAN-883, matching HTTP/Vector.
    #[test]
    fn splunk_hec_default_only_rule_emits_passthrough() {
        let cfg = make_config(
            "splunk_hec",
            vec![make_rule(1000, "source_type", "default", None, "unknown")],
        );

        // Mirrors what deploy() passes for splunk_hec post-NAN-918:
        // intermediary=hec_normalize, system_level=true (passthrough default).
        let routing = SourceConfigService::generate_routing_transform(
            &cfg,
            "hec_normalize",
            "splunk_hec_test_route",
            true,
        );

        assert!(
            routing.contains("passthrough"),
            "default rule must coalesce to passthrough for HEC post-NAN-918, got:\n{routing}"
        );
        assert!(
            !routing.contains(".source_type = \"unknown\""),
            "stored default target must NOT be emitted as unconditional assignment, got:\n{routing}"
        );
    }

    /// Guards NAN-856 defense-in-depth: compute_router_inputs must skip
    /// system-level configs (http/vector/splunk_hec) whose routing TOML is
    /// not on disk, even if marked deployed in DB. Otherwise source_router
    /// gets an input pointing at a non-existent transform and Vector aborts.
    #[test]
    fn compute_router_inputs_skips_splunk_hec_when_no_file_on_disk() {
        let configs = vec![bare_config("hec_main", "splunk_hec")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| false, true);
        assert!(
            !inputs.iter().any(|s| s == "hec_main_route"),
            "splunk_hec route must not be in inputs when no file on disk, got: {inputs:?}"
        );
        // hec_normalize must still be present unconditionally.
        assert!(inputs.iter().any(|s| s == "hec_normalize"));
    }

    /// HEC with no rules at all: nothing to deploy. has_meaningful_rules
    /// must return false so deploy() skips the file write — hec_normalize's
    /// envelope-derived `.source_type` flows directly to parser matching.
    #[test]
    fn has_meaningful_routing_rules_false_for_splunk_hec_with_empty_rules() {
        let cfg = make_config("splunk_hec", vec![]);
        assert!(!SourceConfigService::has_meaningful_routing_rules(&cfg));
    }

    /// NAN-918: HEC default-only rules are now passthrough (HTTP-parity),
    /// so they're no-ops just like HTTP's. has_meaningful_routing_rules
    /// returns false — same as HTTP — so deploy() skips the file write.
    /// Previously (NAN-856) HEC defaults were authoritative and a
    /// default-only config DID require the file; that semantic was reverted
    /// once HEC was reclassified as push.
    #[test]
    fn has_meaningful_routing_rules_false_for_splunk_hec_with_default_only() {
        let cfg = make_config(
            "splunk_hec",
            vec![make_rule(1000, "source_type", "default", None, "unknown")],
        );
        assert!(!SourceConfigService::has_meaningful_routing_rules(&cfg));
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
    ///
    /// NAN-940: the splunk_hec route is pinned to `splunk_hec_route`
    /// regardless of the user-facing config name — `bare_config("hec_main",
    /// "splunk_hec")` resolves to the pinned route, not `hec_main_route`.
    #[test]
    fn compute_router_inputs_suppresses_hec_normalize_when_splunk_hec_route_on_disk() {
        let configs = vec![bare_config("hec_main", "splunk_hec")];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true, true);
        assert_eq!(
            inputs,
            vec!["source_type_extract", "vector_merge", "splunk_hec_route"],
            "hec_normalize must be intermediated by the splunk_hec route, not also direct"
        );
    }

    /// Both intermediaries covered: only vector_merge + the two routes.
    /// NAN-940: the splunk_hec route stays pinned even when paired with a
    /// renamed http config (which is NOT pinned — http_main → http_main_route).
    #[test]
    fn compute_router_inputs_suppresses_both_intermediaries_when_both_routes_on_disk() {
        let configs = vec![
            bare_config("http_main", "http"),
            bare_config("hec_main", "splunk_hec"),
        ];
        let inputs = SourceConfigService::compute_router_inputs(&configs, |_| true, true);
        assert_eq!(
            inputs,
            vec!["vector_merge", "http_main_route", "splunk_hec_route"]
        );
    }

    /// NAN-940 regression: a user renaming the OOTB splunk_hec config to an
    /// arbitrary string must NOT change the route-transform name. HEC
    /// parsers hardcode `splunk_hec_route` via `parser_claimed_route` —
    /// a rename-derived `<safe_name>_route` would orphan every HEC parser.
    #[test]
    fn config_route_name_pinned_for_splunk_hec_across_rename() {
        for renamed in [
            "Splunk HEC",
            "Foo",
            "My HEC",
            "internal-audit",
            "  weird   spaces  ",
        ] {
            assert_eq!(
                SourceConfigService::config_route_name("splunk_hec", renamed),
                "splunk_hec_route",
                "splunk_hec route name must be pinned regardless of user-facing name (was: {renamed})",
            );
        }

        // Non-singleton drivers still derive from the user-facing name.
        assert_eq!(
            SourceConfigService::config_route_name("kafka", "Prod-Kafka"),
            "prod_kafka_route",
        );
        assert_eq!(
            SourceConfigService::config_route_name("http", "Main"),
            "main_route",
        );
    }

    /// NAN-940: the on-disk file stem is also pinned for splunk_hec so a
    /// rename can't strand the old file on disk AND collide on the pinned
    /// transform name when the new file is written.
    #[test]
    fn config_safe_stem_pinned_for_splunk_hec_across_rename() {
        for renamed in ["Splunk HEC", "Foo", "Renamed HEC"] {
            assert_eq!(
                SourceConfigService::config_safe_stem("splunk_hec", renamed),
                "splunk_hec",
            );
        }
        // Non-singleton drivers still vary by name.
        assert_eq!(
            SourceConfigService::config_safe_stem("kafka", "Prod-Kafka"),
            "prod_kafka",
        );
    }

    // ------------------------------------------------------------------
    // NAN-930: claim-based substitution for the surgical inputs rewrite.
    // ------------------------------------------------------------------

    fn claim(route: &str, parser: &str, match_values: &[&str]) -> RouteClaim {
        RouteClaim {
            route: route.to_string(),
            parser_name: parser.to_string(),
            match_values: match_values.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Sanity: no claims → identity mapping (no substitution).
    #[test]
    fn build_claim_substitutions_is_empty_when_no_claims() {
        let subs = SourceConfigService::build_claim_substitutions(&[]);
        assert!(subs.is_empty());
    }

    /// Single claimant produces a `<route>_unclaimed` substitution.
    #[test]
    fn build_claim_substitutions_maps_route_to_unclaimed_name() {
        let claims = vec![claim("kafka_x_route", "Apache HTTP Server", &["apache_access"])];
        let subs = SourceConfigService::build_claim_substitutions(&claims);
        assert_eq!(subs.get("kafka_x_route").map(String::as_str), Some("kafka_x_route_unclaimed"));
        // Routes not in the claim list aren't substituted.
        assert!(subs.get("vector_merge").is_none());
    }

    /// Two claimants of the same route collapse to one substitution.
    #[test]
    fn build_claim_substitutions_dedupes_multiple_claimants() {
        let claims = vec![
            claim("splunk_hec_route", "apache", &["apache_access"]),
            claim("splunk_hec_route", "nginx", &["nginx"]),
        ];
        let subs = SourceConfigService::build_claim_substitutions(&claims);
        assert_eq!(subs.len(), 1);
        assert_eq!(
            subs.get("splunk_hec_route").map(String::as_str),
            Some("splunk_hec_route_unclaimed"),
        );
    }

    /// Emit a filter block with the union of match_values, negated so
    /// source_router only gets the leftover stream. Post-NAN-930 this is
    /// a clean rewrite — there is no "skip when present" branch; the
    /// strip step handles dedup at the file level.
    #[test]
    fn build_unclaimed_blocks_emits_block_with_sorted_dedup_values() {
        let claims = vec![claim("kafka_x_route", "Apache HTTP Server", &["apache_access", "apache"])];
        let blocks = SourceConfigService::build_unclaimed_blocks(&claims);
        assert!(blocks.contains("[transforms.kafka_x_route_unclaimed]"), "blocks=\n{blocks}");
        assert!(blocks.contains("type = \"filter\""));
        assert!(blocks.contains("inputs = [\"kafka_x_route\"]"));
        // Match values are sorted+deduped before negation.
        assert!(blocks.contains(r#"'!includes(["apache", "apache_access"], to_string(.source_type) ?? "")'"#),
            "blocks=\n{blocks}");
    }

    /// Empty match_values falls back to the parser name (matches what
    /// `build_hec_filter_condition` in parsers/vector_config/sources.rs does).
    #[test]
    fn build_unclaimed_blocks_falls_back_to_parser_name_when_match_values_empty() {
        let claims = vec![claim("kafka_x_route", "lone_parser", &[])];
        let blocks = SourceConfigService::build_unclaimed_blocks(&claims);
        assert!(blocks.contains(r#"["lone_parser"]"#), "blocks=\n{blocks}");
    }

    /// Strip removes a `[transforms.X_unclaimed]` block while preserving
    /// surrounding sections — handles the NAN-930 #2 case (changed
    /// match_values must regenerate the condition).
    #[test]
    fn strip_existing_unclaimed_blocks_removes_unclaimed_section() {
        let content = "[transforms.foo]\ntype = \"remap\"\n\
                       [transforms.kafka_x_route_unclaimed]\ntype = \"filter\"\ncondition = 'stale'\n\
                       [transforms.source_router]\ntype = \"route\"\n";
        let stripped = SourceConfigService::strip_existing_unclaimed_blocks(content);
        assert!(!stripped.contains("[transforms.kafka_x_route_unclaimed]"),
            "expected unclaimed section removed, got:\n{stripped}");
        assert!(!stripped.contains("'stale'"), "expected stale condition removed");
        // Other sections survive.
        assert!(stripped.contains("[transforms.foo]"));
        assert!(stripped.contains("[transforms.source_router]"));
    }

    /// Strip removes multiple unclaimed blocks — handles a deploy where
    /// several source-configs were renamed/deleted simultaneously.
    #[test]
    fn strip_existing_unclaimed_blocks_removes_multiple_blocks() {
        let content = "[transforms.a_unclaimed]\ntype = \"filter\"\n\
                       [transforms.keep_me]\ntype = \"remap\"\n\
                       [transforms.b_unclaimed]\ntype = \"filter\"\n\
                       [transforms.also_keep]\ntype = \"route\"\n";
        let stripped = SourceConfigService::strip_existing_unclaimed_blocks(content);
        assert!(!stripped.contains("a_unclaimed"));
        assert!(!stripped.contains("b_unclaimed"));
        assert!(stripped.contains("[transforms.keep_me]"));
        assert!(stripped.contains("[transforms.also_keep]"));
    }

    /// Strip with no unclaimed blocks returns the content unchanged
    /// (modulo trailing newline normalization).
    #[test]
    fn strip_existing_unclaimed_blocks_is_noop_when_no_blocks() {
        let content = "[transforms.foo]\ntype = \"remap\"\n[transforms.source_router]\ntype = \"route\"\n";
        let stripped = SourceConfigService::strip_existing_unclaimed_blocks(content);
        assert!(stripped.contains("[transforms.foo]"));
        assert!(stripped.contains("[transforms.source_router]"));
        // No unclaimed mentions
        assert!(!stripped.contains("_unclaimed"));
    }

    /// Strip does NOT match comment lines that happen to mention
    /// `_unclaimed`. Only `[transforms.X_unclaimed]` headers count.
    #[test]
    fn strip_existing_unclaimed_blocks_ignores_comment_mentions() {
        let content = "# NAN-930: _unclaimed comment\n\
                       [transforms.foo]\ntype = \"remap\"\n";
        let stripped = SourceConfigService::strip_existing_unclaimed_blocks(content);
        // Comment line survives (we only strip section bodies, not comments).
        assert!(stripped.contains("# NAN-930: _unclaimed comment"));
        assert!(stripped.contains("[transforms.foo]"));
    }

    // ----------------------------------------------------------------------
    // NAN-946: validate_safe_strings depth cap. Admin-controlled JSON
    // payloads on connection_config must not be able to overflow the
    // runtime stack via deeply-nested objects/arrays.
    // ----------------------------------------------------------------------

    /// Build a JSON object nested `depth` levels deep:
    /// `{"k": {"k": {"k": ... "leaf"}}}`
    fn nested_object(depth: usize) -> serde_json::Value {
        let mut v = serde_json::Value::String("leaf".to_string());
        for _ in 0..depth {
            let mut obj = serde_json::Map::new();
            obj.insert("k".to_string(), v);
            v = serde_json::Value::Object(obj);
        }
        v
    }

    /// Build a JSON array nested `depth` levels deep: `[[[..."leaf"...]]]`.
    fn nested_array(depth: usize) -> serde_json::Value {
        let mut v = serde_json::Value::String("leaf".to_string());
        for _ in 0..depth {
            v = serde_json::Value::Array(vec![v]);
        }
        v
    }

    #[test]
    fn validate_safe_strings_accepts_realistic_connection_configs() {
        // Real Kafka shape: one-level object with arrays of strings.
        let kafka = serde_json::json!({
            "bootstrap_servers": "broker1:9092,broker2:9092",
            "topics": ["audit", "app", "infra"],
            "group_id": "nanosiem-prod",
            "sasl": {
                "mechanism": "SCRAM-SHA-512",
                "username": "nano",
            }
        });
        assert!(SourceConfigService::validate_safe_strings(&kafka, "connection_config").is_ok());

        // HEC: typically empty.
        assert!(
            SourceConfigService::validate_safe_strings(
                &serde_json::json!({}),
                "connection_config"
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_safe_strings_accepts_depth_at_the_cap() {
        // Depth == cap is fine; depth > cap is the rejection.
        let v = nested_object(SourceConfigService::VALIDATE_SAFE_STRINGS_MAX_DEPTH);
        assert!(
            SourceConfigService::validate_safe_strings(&v, "connection_config").is_ok(),
            "object at the exact cap must still validate"
        );
    }

    #[test]
    fn validate_safe_strings_rejects_object_past_depth_cap() {
        let v = nested_object(SourceConfigService::VALIDATE_SAFE_STRINGS_MAX_DEPTH + 5);
        let err = SourceConfigService::validate_safe_strings(&v, "connection_config")
            .expect_err("expected depth-cap rejection");
        let msg = err.to_string();
        assert!(
            msg.contains("nesting depth"),
            "error must mention nesting depth: {msg}"
        );
    }

    #[test]
    fn validate_safe_strings_rejects_array_past_depth_cap() {
        let v = nested_array(SourceConfigService::VALIDATE_SAFE_STRINGS_MAX_DEPTH + 5);
        let err = SourceConfigService::validate_safe_strings(&v, "connection_config")
            .expect_err("expected depth-cap rejection");
        let msg = err.to_string();
        assert!(msg.contains("nesting depth"), "error must mention nesting depth: {msg}");
    }

    // ----------------------------------------------------------------------
    // NAN-947: rename cleanup — when a non-singleton source-config is
    // renamed, the old .toml file on disk would otherwise linger as an
    // orphan. `update()` snapshots the pre-rename path, compares against
    // the post-rename path, and removes the old file if they differ.
    // ----------------------------------------------------------------------

    #[test]
    fn rename_changes_on_disk_stem_true_for_kafka_rename() {
        assert!(
            SourceConfigService::rename_changes_on_disk_stem(
                "kafka", "Prod-Kafka", "kafka", "Renamed-Kafka",
            ),
            "kafka rename must change the on-disk stem so the orphan can be cleaned up",
        );
    }

    #[test]
    fn rename_changes_on_disk_stem_false_for_splunk_hec_rename() {
        // NAN-940 pins splunk_hec's file stem regardless of name; a rename
        // does NOT change the stem, so the cleanup branch must be a no-op.
        assert!(
            !SourceConfigService::rename_changes_on_disk_stem(
                "splunk_hec", "Splunk HEC", "splunk_hec", "Renamed HEC",
            ),
            "splunk_hec rename must NOT change the on-disk stem (pinned by NAN-940)",
        );
    }

    #[test]
    fn rename_changes_on_disk_stem_false_when_name_identical() {
        assert!(!SourceConfigService::rename_changes_on_disk_stem(
            "kafka", "Audit-Kafka", "kafka", "Audit-Kafka",
        ));
    }

    #[test]
    fn rename_changes_on_disk_stem_false_when_safe_name_collides() {
        // safe_name() lowercases + replaces non-alphanumerics → both
        // "Prod-Kafka" and "prod kafka" resolve to "prod_kafka". A
        // user-visible rename between two such names is a no-op on disk,
        // so we should NOT try to delete the file that's still active.
        // (Distinct configs colliding is the M9 / NAN-952 concern, not
        // ours — but this test pins the cleanup-is-stem-based invariant.)
        assert!(!SourceConfigService::rename_changes_on_disk_stem(
            "kafka", "Prod-Kafka", "kafka", "prod kafka",
        ));
    }

    #[test]
    fn validate_safe_strings_still_rejects_control_chars_inside_nested() {
        // Depth check must not short-circuit before the control-char check
        // on the way down.
        let v = serde_json::json!({
            "outer": {
                "inner": {
                    "bad": "line\nbreak",
                }
            }
        });
        let err = SourceConfigService::validate_safe_strings(&v, "connection_config")
            .expect_err("expected control-char rejection");
        let msg = err.to_string();
        assert!(
            msg.contains("control character"),
            "error must mention control character: {msg}"
        );
    }

    // ----------------------------------------------------------------------
    // NAN-948: deploy_lock sharing. The `with_deploy_lock` builder accepts
    // an `Arc<Mutex<()>>` shared with VectorConfigManager so that
    // `update_dynamic_router`'s read-mutate-write of `_router.toml` is
    // serialized against parser deploys. The wire-up at API startup
    // (state/constructors.rs) is integration-tested via cargo build; here
    // we cover the core invariant: `VectorConfigManager::deploy_lock()`
    // hands out the same Arc on every call (clone, not new), so a downstream
    // service receives a lock that actually blocks the manager's own writes.
    // ----------------------------------------------------------------------

    #[tokio::test]
    async fn vector_config_manager_deploy_lock_is_shared_not_cloned_anew() {
        use crate::parsers::VectorConfigManager;
        let vcm = VectorConfigManager::new(std::path::PathBuf::from("/tmp/nanosiem-test"));
        let lock_a = vcm.deploy_lock();
        let lock_b = vcm.deploy_lock();
        assert!(
            std::sync::Arc::ptr_eq(&lock_a, &lock_b),
            "deploy_lock() must hand out clones of the SAME Arc, not new Arcs — otherwise the lock would not serialize across services"
        );

        // Acquiring lock_a blocks lock_b — same mutex, mutually exclusive.
        let _outer = lock_a.lock().await;
        assert!(
            lock_b.try_lock().is_err(),
            "lock acquired via one handle must block subsequent try_lock on a clone of the same Arc",
        );
    }

    // ----------------------------------------------------------------------
    // NAN-952: creds_filename_stem must be unique-per-config_id and not
    // derived from the user-facing name (where safe_name() collisions
    // would let one config's deploy overwrite another's CA / GCP JSON).
    // ----------------------------------------------------------------------

    #[test]
    fn creds_filename_stem_returns_uuid_string() {
        let id = Uuid::parse_str("30000000-0000-0000-0000-000000000003").unwrap();
        assert_eq!(
            SourceConfigService::creds_filename_stem(&id),
            "30000000-0000-0000-0000-000000000003",
        );
    }

    #[test]
    fn creds_filename_stem_differs_for_distinct_configs_even_with_same_safe_name() {
        // Two configs that would have collided under the old safe_name(name)
        // approach. Their stem must differ — that's the whole point of
        // NAN-952.
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        assert_ne!(
            SourceConfigService::creds_filename_stem(&id_a),
            SourceConfigService::creds_filename_stem(&id_b),
            "distinct UUIDs must produce distinct filename stems",
        );
    }

    #[test]
    fn creds_filename_stem_is_filesystem_safe() {
        // Hyphenated UUID is [0-9a-f-]+ — no spaces, slashes, dots, or
        // shell metachars. ConfigMap-mount-safe (K8s flattens dirs but
        // keys can't contain `/`).
        let id = Uuid::new_v4();
        let stem = SourceConfigService::creds_filename_stem(&id);
        for c in stem.chars() {
            assert!(
                c.is_ascii_hexdigit() || c == '-',
                "stem must contain only [0-9a-f-]: got '{c}' in {stem}",
            );
        }
        // 36-char canonical UUID form. Allows our `kafka_{stem}.ca.pem`
        // filename to stay under typical filesystem name limits (255).
        assert_eq!(stem.len(), 36);
    }
}
