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
    SourceConfigDeployment, SourceConfigType, SourceConfiguration, SourceConfigurationWithRules,
    UpdateRoutingRule, UpdateSourceConfiguration,
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

    /// Construct an isolated publication renderer. Credential files must be
    /// materialized inside the checksummed generation even on Kubernetes: a
    /// mutable Secret volume can lag the object-store completion marker and
    /// make Vector reload new TOML with an old credential. The normal live
    /// deployment constructor keeps its auto-detected backend.
    pub fn with_publication_vector_config_dir(
        pool: PgPool,
        config_dir: impl AsRef<Path>,
    ) -> Self {
        let config_dir = config_dir.as_ref().to_path_buf();
        let runtime_path = Self::resolve_runtime_path();
        let creds_backend = Self::publication_creds_backend(
            config_dir.clone(),
            runtime_path.clone(),
        );
        Self {
            repository: SourceConfigRepository::new(pool.clone()),
            credential_repo: CredentialRepository::new(pool),
            vector_config_dir: config_dir,
            vector_sources_runtime_path: runtime_path,
            creds_backend: Arc::new(OnceCell::new_with(Some(creds_backend))),
            deploy_lock: None,
        }
    }

    fn publication_creds_backend(config_dir: PathBuf, runtime_path: String) -> CredsBackend {
        CredsBackend::Disk {
            config_dir,
            runtime_path,
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
    /// In K8s / multi-Vector: /etc/vector/runtime/current (atomic generation pointer)
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

        // NAN-1919: a caller-supplied default_source_type is interpolated into
        // the generated routing VRL — validate it before persistence.
        Self::validate_default_source_type(request.default_source_type.as_deref())?;

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
    /// would emit colliding `splunk_hec_route` transforms) and `otlp` (the
    /// OOTB `otlp_ingest` listener on :4317/:4318 is shared the same way —
    /// two would emit colliding `otlp_route` transforms over `otlp_logs_prep`).
    fn is_single_instance_driver(config_type: &str) -> bool {
        matches!(config_type, "splunk_hec" | "otlp")
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

        // NAN-1919: a patched default_source_type is interpolated into the
        // generated routing VRL — validate it before persistence.
        Self::validate_default_source_type(request.default_source_type.as_deref())?;

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
        // Shared with the legacy log-source path (NAN-1371).
        crate::config_safety::validate_config_name(name)
            .map_err(SourceConfigServiceError::InvalidConfig)
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

    /// Recursively walk a JSON value and reject any string scalar that
    /// contains a newline / carriage return / NUL / other ASCII control
    /// char (tab is allowed). Path is used to produce a helpful error.
    ///
    /// NAN-946: depth is capped at `config_safety::MAX_CONFIG_DEPTH` so a
    /// malicious admin payload can't overflow the runtime stack. The cap is
    /// enforced by the shared validator this delegates to (below).
    fn validate_safe_strings(
        v: &serde_json::Value,
        path: &str,
    ) -> Result<(), SourceConfigServiceError> {
        // Delegates to the shared char-safety validator (NAN-1371) so this path
        // and the legacy LogSourceService source_config path can't drift. No
        // exempt keys: connection_config carries no file-written multi-line blobs.
        crate::config_safety::validate_safe_config_strings(v, path, &[])
            .map_err(SourceConfigServiceError::InvalidConfig)
    }

    fn is_unsafe_scalar_char(c: char) -> bool {
        crate::config_safety::is_unsafe_scalar_char(c)
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
    /// NAN-1919: validate a `default_source_type` scalar before it is
    /// persisted. It is interpolated into the generated routing transform's VRL
    /// string literal (`.source_type = "<value>"`) for unmatched pull-source
    /// events, so it must satisfy the same allow-list as `target_source_type`.
    /// `is_safe_source_type` restricts to `[A-Za-z0-9_-]`, which also rejects
    /// the passthrough sentinel `${source_type}` (its `$`/`{`/`}` are outside
    /// the allow-list) — that literal would otherwise collide with the
    /// generator's system-level passthrough branch and silently suppress both
    /// the default AND the "unknown" deploy warning — and any control char that
    /// could break the generated VRL. `None` / whitespace-only is allowed
    /// (falls back to "unknown" as before); validation runs on the trimmed
    /// value to mirror what the generator emits.
    fn validate_default_source_type(
        value: Option<&str>,
    ) -> Result<(), SourceConfigServiceError> {
        let Some(value) = value else {
            return Ok(());
        };
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        if !is_safe_source_type(trimmed) {
            return Err(SourceConfigServiceError::InvalidConfig(format!(
                "default_source_type {trimmed:?} contains characters \
                 outside [A-Za-z0-9_-] or is empty"
            )));
        }
        Ok(())
    }

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
    ///
    /// NAN-1572: `otlp` is excluded for the same reason — `otlp_logs_prep`
    /// (`config/vector/03-otlp-source.toml`) sets `.source_type` before the
    /// routing transform runs, so source_type rules on OTLP are legitimate.
    fn is_pull_source_source_type_match(config_type: &str, match_field: &str) -> bool {
        !matches!(config_type, "http" | "vector" | "splunk_hec" | "otlp")
            && match_field == "source_type"
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
    /// `otlp` → `otlp_logs_prep` (NAN-1572; `otlp_ingest` on :4317/:4318 is
    /// OOTB per NAN-1528. `otlp_logs_prep` tags `.source_type` and already
    /// feeds `source_router` directly as a base input — when a meaningful
    /// OTLP routing config is on disk, `base_router_inputs`'
    /// `otlp_logs_prep_covered` flag suppresses that direct input so the
    /// stream isn't double-written).
    fn system_intermediary_source(config_type: &str) -> Option<&'static str> {
        match config_type {
            "http" | "vector" => Some("source_type_extract"),
            "splunk_hec" => Some("hec_normalize"),
            "otlp" => Some("otlp_logs_prep"),
            _ => None,
        }
    }

    /// Whether a system-level source config has rules worth emitting to disk.
    ///
    /// System-level default rules (HTTP, Vector, HEC post-NAN-918) are
    /// passthrough no-ops (the routing transform emits
    /// `# passthrough — keep existing .source_type`), so a config with
    /// only defaults adds nothing — we skip the file write entirely.
    ///
    /// NAN-1572: OTLP is always treated as no-meaningful-rules (never writes an
    /// `otlp_route`). OTLP logs route to parsers via their `match_values`
    /// claiming `otlp_logs_prep` directly (`parser_claimed_route`), not via a
    /// system route. Writing an `otlp_route` over `otlp_logs_prep` would
    /// double-write parser-claimed events — `otlp_logs_prep` is both the
    /// claimed channel and the would-be system-route upstream, so the route
    /// carries the full stream into `source_router` alongside the parser
    /// pipeline (the NAN-930/NAN-1442 class). Per-source_type OTLP routing
    /// arrives with the OTLP-log envelope mapping (NAN-1556); until then OTLP
    /// stays default-passthrough and `otlp_logs_prep` remains a direct base
    /// input that the claim-dedupe filters correctly.
    fn has_meaningful_routing_rules(config: &SourceConfigurationWithRules) -> bool {
        if config.config.config_type == "otlp" {
            return false;
        }
        config
            .routing_rules
            .iter()
            .any(|r| r.match_type != "default")
    }

    /// NAN-1919: whether a pull-transport config's generated routing transform
    /// would fall back to `.source_type = "unknown"` for unmatched events.
    /// Mirrors the fallback selection in `generate_routing_transform`: it emits
    /// "unknown" only when there is no `default` rule, no source_type-coalesced
    /// rule, AND no non-empty `default_source_type` on the config. Used by
    /// `deploy` to surface a non-blocking warning.
    ///
    /// Invariant: the caller MUST exclude system-level sources (http / vector /
    /// splunk_hec / otlp). Those route through the system-intermediary path,
    /// which passes `.source_type` through unchanged and never emits "unknown";
    /// this helper ignores `system_level` and would return a wrong answer for
    /// them. `deploy` satisfies this by early-returning on the system path
    /// before reaching the warning.
    fn pull_routing_emits_unknown(config: &SourceConfigurationWithRules) -> bool {
        let has_default = config
            .routing_rules
            .iter()
            .any(|r| r.match_type == "default");
        let has_coalesced = config
            .routing_rules
            .iter()
            .any(|r| r.match_field == "source_type" && r.match_type != "default");
        let has_config_default = config
            .config
            .default_source_type
            .as_deref()
            .map(str::trim)
            .is_some_and(|s| !s.is_empty());
        !has_default && !has_coalesced && !has_config_default
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
            let vector_config = Self::render_system_source_config(
                &config_with_rules,
                intermediary_source,
            );
            if let Some(config_content) = &vector_config {
                // NAN-689 acceptance criterion #3: validate before
                // mark_deployed / router-update / file write. Failure path
                // records add_deployment("failure", reason) and aborts.
                if let Err(e) = Self::validate_generated_config(config_content) {
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
                tokio::fs::write(&config_file, config_content).await?;
            }

            if !config.deployed {
                self.repository.mark_deployed(id).await?;
            }

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
        if !config.deployed {
            self.repository.mark_deployed(id).await?;
        }

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

        // NAN-1919: non-blocking guardrail. When a pull-transport config has no
        // routing rule and no seeded default_source_type, its generated routing
        // transform stamps unmatched events with `.source_type = "unknown"`.
        // Surface a warning (log + appended to the result message) but never
        // fail the deploy — the config is still valid and running.
        let is_pull = SourceConfigType::from_str(&config.config_type)
            .map(|t| t.is_pull_source())
            .unwrap_or(false);
        let mut message = format!("Deployed '{}' successfully", config.name);
        if is_pull && Self::pull_routing_emits_unknown(&config_with_rules) {
            let warning = format!(
                "Warning: pull source '{}' has no routing rule or default source type — \
                 unmatched events will be stamped source_type=\"unknown\". Add a routing rule \
                 (or onboard a feed) to set a real default.",
                config.name
            );
            tracing::warn!(
                config = %config.name,
                config_type = %config.config_type,
                "deploy will emit source_type=\"unknown\" for unmatched events"
            );
            message.push_str(" — ");
            message.push_str(&warning);
        }

        Ok(DeploymentResult {
            success: true,
            source_configuration_id: id,
            action: "deploy".to_string(),
            message,
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
        //
        // NAN-1915: the reap key MUST match what `deploy` wrote. `deploy` keys
        // credential files by config UUID (`creds_filename_stem`, NAN-952 — so
        // `Prod-Kafka` and `prod kafka` can't collide), but this used to remove
        // a `safe_name`-keyed filename that never existed post-NAN-952. The
        // idempotent `remove_creds` then no-op'd and left the real UUID-keyed
        // key material (GCP private key / Kafka CA) orphaned forever (delete()
        // calls undeploy(), so the UUID is gone once the row is deleted). Kafka
        // CA certs also had no reap branch at all. The `publications/<gen>/`
        // snapshot copies self-heal via the generation materialize/prune once
        // `sources/` is clean.
        // Resolve the backend only for types that materialize a credential file,
        // so a creds-less undeploy (aws_s3, system types) keeps its exact prior
        // behavior and never depends on backend detection.
        match config.config_type.as_str() {
            "gcp_pubsub" => {
                self.creds_backend()
                    .await?
                    .remove_creds(&Self::gcp_creds_key(&config.id))
                    .await?;
            }
            "kafka" => {
                self.creds_backend()
                    .await?
                    .remove_creds(&Self::kafka_ca_key(&config.id))
                    .await?;
            }
            _ => {}
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

    /// Render every deployed source configuration into this service's config
    /// directory without changing deployment state or audit history. `deployed`
    /// is the runtime authority; `enabled` controls eligibility for deploy_all
    /// and does not implicitly undeploy an already-running source.
    /// The publication reconciler uses a fresh directory, so deletion is
    /// represented by absence and snapshots never inherit another pod's files.
    pub async fn render_deployed_to_vector_config(
        &self,
    ) -> Result<(), SourceConfigServiceError> {
        Self::require_canonical_router(&self.vector_config_dir)?;

        let sources = self.repository.list_deployed().await?;
        let source_ids: Vec<_> = sources.iter().map(|source| source.id).collect();
        let mut rules_by_source = self.repository.list_rules_for_configs(&source_ids).await?;
        let configs_dir = self.vector_config_dir.join("sources").join("configs");
        tokio::fs::create_dir_all(&configs_dir).await?;

        for source in sources {
            let routing_rules = rules_by_source.remove(&source.id).unwrap_or_default();
            let config_with_rules = SourceConfigurationWithRules {
                config: source,
                routing_rules,
            };
            let config = &config_with_rules.config;
            let rendered = if let Some(intermediary) =
                Self::system_intermediary_source(&config.config_type)
            {
                Self::render_system_source_config(&config_with_rules, intermediary)
            } else {
                Some(self.generate_vector_config(&config_with_rules).await?)
            };

            if let Some(rendered) = rendered {
                Self::validate_generated_config(&rendered)?;
                let path = self.get_config_file_path(&config.config_type, &config.name);
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::write(path, rendered).await?;
            }
        }

        self.update_dynamic_router().await?;
        Ok(())
    }

    fn require_canonical_router(config_dir: &Path) -> Result<(), SourceConfigServiceError> {
        let router_path = config_dir
            .join("sources")
            .join("parsers")
            .join("_router.toml");
        if !router_path.is_file() {
            return Err(SourceConfigServiceError::InvalidConfig(format!(
                "canonical parser router must be rendered before source configurations: {}",
                router_path.display()
            )));
        }
        Ok(())
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

    /// Render only the routing transform for a system-owned listener. Default
    /// rules preserve the upstream source type, matching the live deploy path.
    fn render_system_source_config(
        config: &SourceConfigurationWithRules,
        intermediary_source: &str,
    ) -> Option<String> {
        if !Self::has_meaningful_routing_rules(config) {
            return None;
        }

        let route_name = Self::config_route_name(&config.config.config_type, &config.config.name);
        let routing_block = Self::generate_routing_transform(
            config,
            intermediary_source,
            &route_name,
            true,
        );
        Some(format!(
            "# Auto-generated routing rules for system-level source: {}\n\
             # DO NOT EDIT - changes will be overwritten\n\
             # Generated at: {}\n\n\
             {}",
            config.config.name,
            chrono::Utc::now().to_rfc3339(),
            routing_block
        ))
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
            Some(
                self.credential_repo
                    .get_decrypted(cred_id)
                    .await
                    .map_err(|error| {
                        SourceConfigServiceError::CredentialError(format!(
                            "failed to load credential {cred_id} for source config: {error}"
                        ))
                    })?,
            )
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
                        let key = Self::gcp_creds_key(&config.config.id);
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
                        let key = Self::kafka_ca_key(&config.config.id);
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
            // NAN-1919: when no default/coalesced rule exists, fall back to the
            // config's seeded `default_source_type` (from the onboarded feed's
            // name) BEFORE "unknown", so unmatched pull-source events land under
            // a real source type instead of the catch-all.
            let config_default = config
                .config
                .default_source_type
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            Self::vrl_escape(
                default_rule
                    .or(coalesced_rule)
                    .map(|r| r.target_source_type.as_str())
                    .or(config_default)
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
        let mut otlp_logs_prep_covered = false;
        let mut source_config_routes: Vec<String> = Vec::new();
        // NAN-1442: at most ONE route per shared always-on channel may feed
        // `source_router`. `http` and `vector` BOTH intermediate
        // `source_type_extract` (see `system_intermediary_source`), so wiring a
        // route for each duplicates the entire post-extract stream into
        // `source_router` — every event then lands in ClickHouse twice (the
        // Saturn 2× bug). These system routes are passthrough source_type
        // normalizers; the authoritative routing is `source_router`'s
        // match_values, so collapsing duplicate-channel routes to a single
        // carrier drops no events.
        let mut covered_channels: std::collections::HashSet<&'static str> =
            std::collections::HashSet::new();

        for config in deployed_configs {
            // System-level configs only contribute a route to source_router
            // inputs when their routing TOML actually exists on disk. Without
            // this guard, a `mark_deployed` row whose file got skipped would
            // reference a transform that doesn't exist and abort Vector reload.
            if let Some(intermediary) = Self::system_intermediary_source(&config.config_type) {
                if !is_system_route_deployed_on_disk(config) {
                    continue;
                }
                // A route for this always-on channel is already wired — skip
                // this duplicate so the channel reaches `source_router` exactly
                // once (NAN-1442). Without this, two system configs sharing a
                // channel (e.g. http + vector) each feed source_router → 2×.
                if !covered_channels.insert(intermediary) {
                    continue;
                }
                // The per-config route intermediates this always-on channel
                // (consumes from it, feeds source_router). Suppress the
                // channel from base inputs so events don't reach source_router
                // twice — once via the direct base input, once via the route.
                match intermediary {
                    "source_type_extract" => source_type_extract_covered = true,
                    "hec_normalize" => hec_normalize_covered = true,
                    "otlp_logs_prep" => otlp_logs_prep_covered = true,
                    _ => {}
                }
            }
            source_config_routes.push(Self::config_route_name(&config.config_type, &config.name));
        }

        let mut router_inputs: Vec<String> = base_router_inputs(
            source_type_extract_covered,
            hec_normalize_covered,
            hec_normalize_present,
            otlp_logs_prep_covered,
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
        let deployed_configs = self.repository.list_deployed().await?;

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
    /// Only `splunk_hec` is *pinned* here, because HEC parsers hardcode the
    /// `splunk_hec_route` transform name. `otlp` is also a single-instance
    /// driver (`is_single_instance_driver`, migration 214) but is intentionally
    /// NOT pinned: OTLP parsers claim the OOTB `otlp_logs_prep` transform
    /// directly (`parser_claimed_route`), never a config-derived `*_route`, so
    /// there's nothing for a rename to break. Adding a *pinned* singleton here
    /// also requires adding it to `is_single_instance_driver`.
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

    /// `CredsBackend` key for a `gcp_pubsub` source config's service-account
    /// JSON. NAN-1915: `deploy` (write) and `undeploy` (remove) MUST derive the
    /// key from this single helper — they used to inline two `format!`s that
    /// drifted (deploy keyed by UUID per NAN-952, undeploy still keyed by
    /// `safe_name`), so the removal silently no-op'd and orphaned the key
    /// material forever.
    fn gcp_creds_key(config_id: &Uuid) -> String {
        format!("gcp_{}.creds", Self::creds_filename_stem(config_id))
    }

    /// `CredsBackend` key for a `kafka` source config's TLS CA cert. Same
    /// deploy/undeploy key-parity contract as [`Self::gcp_creds_key`] (NAN-1915).
    fn kafka_ca_key(config_id: &Uuid) -> String {
        format!("kafka_{}.ca.pem", Self::creds_filename_stem(config_id))
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
mod tests;
