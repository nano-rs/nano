// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source Configuration service for business logic

use sqlx::PgPool;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::OnceCell;
use uuid::Uuid;

use super::creds_backend::{CredsBackend, CredsBackendError};
use super::{azure_event_hubs, crowdstrike_fdr, point_forward};
use super::repository::{
    SourceConfigIdentity, SourceConfigRepository, SourceConfigRepositoryError,
};
use super::types::{
    DeploymentResult, ListParams, NewRoutingRule, NewSourceConfiguration, RoutingRule,
    SourceConfigDeployment, SourceConfigType, SourceConfiguration, SourceConfigurationWithRules,
    UpdateRoutingRule, UpdateSourceConfiguration,
};
use crate::auth::CredentialUseGrant;
use crate::log_telemetry::repository::is_safe_source_type;
use crate::parsers::{
    ReloadWatch,
    redact_config_snapshot, CredentialRepository,
};

/// SQS poll interval emitted when a source config does not override it.
///
/// Was hard-coded at this value before NAN-2188; keeping it as the default
/// means every existing config emits byte-identical TOML.
pub(crate) const DEFAULT_SQS_POLL_SECS: u32 = 15;

/// Ceiling for `poll_secs` — one day, far past anything deliberate.
///
/// Generous on purpose: a long poll interval is merely useless, not dangerous.
pub(crate) const MAX_POLL_SECS: u32 = 86_400;

/// Ceiling for `client_concurrency`.
///
/// Deliberately MUCH tighter than [`MAX_POLL_SECS`], because the two knobs fail
/// differently. An absurd poll interval just stalls one queue; an absurd
/// concurrency spawns that many parallel S3 fetches against the customer's
/// account — a request storm, on their bill, that they did not ask for. A
/// shared ceiling would have let a fat-fingered `50000` straight through.
/// 1024 is far above any real tuning (Vector's own default is CPU-scaled)
/// while keeping the blast radius of a typo bounded.
pub(crate) const MAX_CLIENT_CONCURRENCY: u32 = 1_024;

/// SQS's own hard maximum for a message visibility timeout: 12 hours.
/// Anything above this is rejected by AWS, so reject it here where the error
/// can name the field rather than surfacing as a Vector runtime failure.
pub(crate) const MAX_SQS_VISIBILITY_SECS: u32 = 43_200;


/// Build an `sts:AssumeRole` session name from a nano source name (NAN-2194).
///
/// This string is what the CUSTOMER sees in their own CloudTrail for every
/// assumption we make into their account, so it should say which nano source
/// was responsible rather than leaving them with an anonymous session.
///
/// AWS constrains `RoleSessionName` to `[\w+=,.@-]{2,64}`. A name outside that
/// set does not degrade — `AssumeRole` fails outright — so a source named with
/// anything exotic would turn a logging improvement into an ingest outage.
/// Every disallowed character is therefore folded to `-`, and the result is
/// clamped to the length bound.
fn role_session_name(source_name: &str) -> String {
    const PREFIX: &str = "nano-";
    const MAX: usize = 64;

    let cleaned: String = source_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '=' | ',' | '.' | '@' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();

    let mut out = String::with_capacity(MAX);
    out.push_str(PREFIX);
    out.push_str(cleaned.trim_matches('-'));
    out.truncate(MAX);

    // A source name that sanitized to nothing leaves the bare prefix, which is
    // still >= the 2-char minimum, so the floor is satisfied by construction.
    out
}

/// Reduce a Pub/Sub subscription value to its bare name. Vector's `gcp_pubsub`
/// source builds `projects/<p>/subscriptions/<n>` itself, so a fully-qualified
/// value would be double-prefixed and rejected with InvalidArgument by gRPC.
pub(crate) fn normalize_pubsub_subscription(raw: &str) -> &str {
    raw.rsplit_once("/subscriptions/")
        .map(|(_, name)| name)
        .unwrap_or(raw)
        .trim_matches('/')
}

/// NAN-4914: what a credential rotation did to one bound source config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialRefreshOutcome {
    /// Redeployed with the new secret (nothing else changed).
    Redeployed,
    /// The saved config has undeployed edits; it keeps running with the
    /// previous secret until someone with deploy authority deploys it.
    PendingEdits,
    /// No successful deployment snapshot to compare with; not redeployed.
    NoDeployedSnapshot,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRefresh {
    pub source_configuration_id: Uuid,
    pub name: String,
    pub outcome: CredentialRefreshOutcome,
}

enum SecretOnly {
    Yes,
    PendingEdits,
    NoSnapshot,
}

/// A rendered (redacted) config with everything a credential contributes
/// masked and comment lines dropped, so two renders compare equal exactly
/// when they differ only in credential material.
pub(crate) fn normalize_for_secret_compare(redacted: &str, credential: Option<&serde_json::Value>) -> String {
    fn strings(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) if s.trim().len() >= 4 => {
                out.push(s.clone());
                out.push(s.trim().to_string());
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
            serde_json::Value::Object(m) => m.values().for_each(|x| strings(x, out)),
            _ => {}
        }
    }
    let mut values = Vec::new();
    if let Some(c) = credential {
        strings(c, &mut values);
    }
    // Longest first so a value containing another is masked whole; both the
    // raw and the TOML-escaped spelling (PEM newlines, quotes).
    let mut needles: Vec<String> = values
        .iter()
        .flat_map(|v| {
            let escaped = toml::Value::String(v.clone()).to_string();
            let escaped = escaped.trim_matches('"').to_string();
            [v.clone(), escaped]
        })
        .filter(|n| !n.is_empty())
        .collect();
    needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
    needles.dedup();
    let mut text: String = redacted
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for n in &needles {
        text = text.replace(n.as_str(), "<credential>");
    }
    text
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
    #[error("Missing permission: credentials:use")]
    CredentialUseRequired,
    /// NAN-5147: the request binds a stored credential (create, or a
    /// different credential on update) or moves a bound credential to a
    /// different connection host, which requires credential-owner permission.
    #[error("Missing permission: credentials:edit")]
    CredentialRetargetRequired,
    /// NAN-5232: the publication reconciler renders every deployed source
    /// from its saved row, so a saved render-affecting change to a deployed
    /// source (or its routing rules) is a deploy and needs `source_configs:deploy`.
    #[error("Missing permission: source_configs:deploy")]
    DeployPermissionRequired,
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
    ///
    /// `pub(crate)` because the value is embedded IN the generated TOML, which
    /// makes it a render-affecting input the publication renderer fingerprint
    /// has to cover (NAN-2304).
    pub(crate) fn resolve_runtime_path() -> String {
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

    // NAN-2067: every public read below returns a REDACTED row. These methods
    // exist to serve HTTP handlers; deploy/generation paths inside this service
    // read plaintext straight from `self.repository` (see `list_deployed` /
    // `list_enabled` in the deploy section), so masking here cannot starve
    // config generation of real credentials.

    /// List source configurations, with `connection_config` secrets masked.
    pub async fn list(
        &self,
        params: Option<ListParams>,
    ) -> Result<Vec<SourceConfiguration>, SourceConfigServiceError> {
        let mut configs: Vec<SourceConfiguration> = self
            .repository
            .list(params)
            .await?
            .into_iter()
            .map(SourceConfiguration::redacted)
            .collect();
        let ids: Vec<Uuid> = configs.iter().map(|c| c.id).collect();
        let mut statuses = self.repository.latest_deployment_status(&ids).await?;
        for config in &mut configs {
            config.last_deployment = statuses.remove(&config.id);
            if let Some(startup) = self
                .startup_quarantine_status(config, config.last_deployment.as_ref())
                .await
            {
                config.last_deployment = Some(startup);
            }
        }
        Ok(configs)
    }

    /// Get a source configuration by ID, with `connection_config` secrets masked.
    pub async fn get(&self, id: Uuid) -> Result<SourceConfiguration, SourceConfigServiceError> {
        let mut config = self.repository.get(id).await?.redacted();
        config.last_deployment = self.repository.latest_deployment_status(&[id]).await?.remove(&id);
        if let Some(startup) = self
            .startup_quarantine_status(&config, config.last_deployment.as_ref())
            .await
        {
            config.last_deployment = Some(startup);
        }
        Ok(config)
    }

    /// Get a source configuration with its routing rules, with
    /// `connection_config` secrets masked.
    pub async fn get_with_rules(
        &self,
        id: Uuid,
    ) -> Result<SourceConfigurationWithRules, SourceConfigServiceError> {
        let mut config = self.repository.get_with_rules(id).await?.redacted();
        config.config.last_deployment =
            self.repository.latest_deployment_status(&[id]).await?.remove(&id);
        if let Some(startup) = self
            .startup_quarantine_status(&config.config, config.config.last_deployment.as_ref())
            .await
        {
            config.config.last_deployment = Some(startup);
        }
        Ok(config)
    }

    /// Create a new source configuration
    pub async fn create(
        &self,
        mut request: NewSourceConfiguration,
        credential_use: CredentialUseGrant,
    ) -> Result<SourceConfiguration, SourceConfigServiceError> {
        // Authorization precedes validation and credential metadata lookup so
        // an under-scoped caller cannot probe whether a credential ID exists.
        Self::ensure_credential_use(request.credential_id, credential_use)?;
        // NAN-5147: binding a stored credential decides where it is sent;
        // that is credential-owner level, not just credentials:use.
        if request.credential_id.is_some() {
            Self::ensure_credential_retarget(credential_use)?;
        }

        // NAN-2067: a client that copied a redacted read (or a UI that echoes
        // the mask on a "save as new") would otherwise persist the literal
        // placeholder as if it were the secret. There is no stored row to
        // restore from on create, so masked keys are dropped instead.
        request.connection_config =
            crate::config_secrets::merge_config_secrets(request.connection_config, None);

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
        // NAN-4937: the UI creates every pull source unconfigured (`{}`) and
        // configures it on the next page, as aws_* / gcp_pubsub already allow.
        // An EMPTY Event Hubs config is accepted at CREATE only ("not
        // configured yet"); update validates the merged config in full, and
        // deploy still requires the hub.
        if !(request.config_type == "azure_event_hubs" && Self::is_unconfigured(&request.connection_config)) {
            Self::validate_connection_config(&request.config_type, &request.connection_config)?;
        }

        // NAN-1919: a caller-supplied default_source_type is interpolated into
        // the generated routing VRL — validate it before persistence.
        Self::validate_default_source_type(request.default_source_type.as_deref())?;

        // NAN-5152: inline initial routing rules get the same write-time
        // validation as rules added one at a time, before anything is stored.
        if let Some(rules) = request.routing_rules.as_mut() {
            for rule in rules.iter_mut() {
                Self::validate_new_routing_rule(&request.config_type, rule)?;
            }
        }

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

        // NAN-2305: UNIQUE(name) lets `prod kafka` in alongside `Prod-Kafka`;
        // both generate `sources/configs/prod_kafka.toml` and the deploy of
        // the second overwrites the first. Same list-then-insert race as the
        // check above, backstopped by migration 283's unique index.
        if let Some(err) = Self::identity_conflict(
            &request.config_type,
            &request.name,
            &self.repository.list_identities().await?,
            None,
        ) {
            return Err(err);
        }

        // Validate credential exists if specified
        if let Some(cred_id) = request.credential_id {
            self.credential_repo
                .get(cred_id)
                .await
                .map_err(|e| SourceConfigServiceError::CredentialError(e.to_string()))?;
        }

        Ok(self.repository.create(request).await?.redacted())
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

    /// NAN-2305: decide whether `name` would take a generated on-disk stem
    /// that another source configuration already holds.
    ///
    /// `source_configurations.name` is UNIQUE, but only as a raw string. The
    /// generated artifacts key off `config_safe_stem`, which lowercases the
    /// name and collapses every non-alphanumeric to `_`, so `Prod-Kafka` and
    /// `prod kafka` both resolve to `prod_kafka` — one
    /// `sources/configs/prod_kafka.toml`, one `[sources.prod_kafka_source]`
    /// block, one `prod_kafka_route` transform. Deploying the second
    /// overwrites the first's file, and every fetch parser bound to the first
    /// via `dispatch_route_name` silently starts reading the second's stream.
    ///
    /// Compares stems, not `safe_name(name)`, so the pinned singleton stem is
    /// respected in both directions: a `kafka` config named `Splunk HEC` is
    /// rejected against the OOTB `splunk_hec` row it would collide with on
    /// disk, which a name-only comparison would miss.
    ///
    /// Pure so the decision is testable without a database; the caller loads
    /// the rows and excludes the row being renamed.
    fn identity_conflict(
        config_type: &str,
        name: &str,
        existing: &[SourceConfigIdentity],
        exclude: Option<Uuid>,
    ) -> Option<SourceConfigServiceError> {
        let generated = Self::config_safe_stem(config_type, name);
        let holder = crate::vector_naming::find_identity_holder(
            &generated,
            existing
                .iter()
                .filter(|c| Some(c.id) != exclude)
                .map(|c| (Self::config_safe_stem(&c.config_type, &c.name), c.name.clone())),
        )?;
        Some(SourceConfigServiceError::InvalidConfig(
            crate::vector_naming::describe_identity_conflict(
                "source configuration",
                name,
                &generated,
                &holder,
            ),
        ))
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
    ///
    /// `deploy_authorized` is whether the caller holds `source_configs:deploy`.
    /// Without it, a change that alters the rendered Vector config of a
    /// DEPLOYED source is refused with `DeployPermissionRequired` (NAN-5232):
    /// the publication reconciler would otherwise put it live without a deploy.
    pub async fn update(
        &self,
        id: Uuid,
        mut request: UpdateSourceConfiguration,
        credential_use: CredentialUseGrant,
        deploy_authorized: bool,
    ) -> Result<SourceConfiguration, SourceConfigServiceError> {
        // A caller that explicitly supplies a credential reference must be
        // denied before any resource or credential lookup.
        Self::ensure_credential_use(request.credential_id, credential_use)?;

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

        // Load once and use this same snapshot for the credential decision,
        // secret merge, effective driver, and rename cleanup.
        let existing = self.repository.get(id).await?;
        Self::ensure_credential_use(
            request.credential_id.or(existing.credential_id),
            credential_use,
        )?;

        // Validate the connection_config payload (when present) against the
        // effective driver: prefer the patched config_type, fall back to the
        // existing one when the patch only touches connection_config (NAN-689).
        //
        // NAN-2067: reads now mask secrets, so the UI's read-modify-write
        // (SourceConfigurationDetail.tsx hydrates from GET and PUTs the whole
        // object back) would persist `***REDACTED***` over a live credential
        // and break ingestion. Merge against the stored row FIRST, so both
        // validation and the write see real material — and so a caller that
        // never read the secret cannot wipe it.
        // NAN-2150: when request.expected_updated_at is present, it is
        // forwarded unchanged to the repository's atomic UPDATE predicate. A
        // credential rotation landing after this read then makes the write fail
        // with StaleVersion instead of persisting the merged stale snapshot.
        if let Some(conn) = request.connection_config.take() {
            let merged = crate::config_secrets::merge_config_secrets(
                conn,
                Some(&existing.connection_config),
            );

            let effective_type = match request.config_type.as_deref() {
                Some(ct) => ct.to_string(),
                None => existing.config_type.clone(),
            };
            Self::validate_connection_config(&effective_type, &merged)?;

            request.connection_config = Some(merged);
        }

        // NAN-5232: compared against the merged (real-secret) payload, so a
        // read-modify-write that echoes redacted values back is not a change.
        if existing.deployed
            && !deploy_authorized
            && Self::update_changes_rendered_config(&existing, &request)
        {
            return Err(SourceConfigServiceError::DeployPermissionRequired);
        }

        // NAN-5147: a bound stored credential is presented to whatever host the
        // config points at. Binding a different credential, or moving a bound
        // one to a different broker/endpoint, needs credential-owner
        // permission, not just credentials:use.
        if request
            .credential_id
            .is_some_and(|c| existing.credential_id != Some(c))
        {
            Self::ensure_credential_retarget(credential_use)?;
        }
        if request.credential_id.or(existing.credential_id).is_some()
            && (request.connection_config.is_some() || request.config_type.is_some())
        {
            let effective_type = request
                .config_type
                .as_deref()
                .unwrap_or(&existing.config_type);
            let effective_conn = request
                .connection_config
                .as_ref()
                .unwrap_or(&existing.connection_config);
            if moves_credential_destination(
                &existing.config_type,
                &existing.connection_config,
                effective_type,
                effective_conn,
            ) {
                Self::ensure_credential_retarget(credential_use)?;
            }
        }

        // NAN-1919: a patched default_source_type is interpolated into the
        // generated routing VRL — validate it before persistence.
        Self::validate_default_source_type(request.default_source_type.as_deref())?;

        // NAN-2305: a rename (or a driver change, which can move the stem on
        // or off the pinned singleton value) must not land on a stem another
        // config already owns — the rename cleanup below would then delete the
        // OTHER config's file as a stale orphan. Only queried when the stem
        // can actually move; `id` is excluded so a rename that keeps the same
        // stem still succeeds.
        if request.name.is_some() || request.config_type.is_some() {
            let effective_type = request
                .config_type
                .as_deref()
                .unwrap_or(&existing.config_type);
            let effective_name = request.name.as_deref().unwrap_or(&existing.name);
            let all = self.repository.list_identities().await?;
            if let Some(err) =
                Self::identity_conflict(effective_type, effective_name, &all, Some(id))
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
                let old_path = self.get_config_file_path(&existing.config_type, &existing.name);
                Some((
                    existing.config_type,
                    existing.name,
                    old_path,
                    existing.deployed,
                ))
            } else {
                None
            };

        let updated = match self
            .repository
            .update_with_credential_guard(id, request, existing.credential_id)
            .await
        {
            Ok(updated) => updated,
            Err(SourceConfigRepositoryError::CredentialChanged(_)) if !credential_use.allows() => {
                return Err(SourceConfigServiceError::CredentialUseRequired);
            }
            Err(SourceConfigRepositoryError::CredentialChanged(_)) => {
                return Err(SourceConfigServiceError::Conflict(
                    "Source configuration credentials changed concurrently; retry the update"
                        .to_string(),
                ));
            }
            Err(error) => return Err(error.into()),
        };

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

        Ok(updated.redacted())
    }

    /// Whether `request` changes an input of the rendered Vector config of
    /// `existing` (NAN-5232).
    ///
    /// These are exactly the fields `render_pull_source` /
    /// `render_system_source_config` and the on-disk path read: the name (TOML
    /// header, component names, file stem), driver, connection payload, bound
    /// credential and fallback `source_type`. `description` and `enabled` are
    /// not rendered (`deployed`, not `enabled`, decides publication), so they
    /// stay edit-only. A field equal to the stored value is not a change, so
    /// the UI's whole-object PUT of an unrelated edit passes.
    ///
    /// A field list rather than a render diff: rendering a pull source
    /// materializes its live credential files, which an unauthorized
    /// candidate must not do.
    pub(crate) fn update_changes_rendered_config(
        existing: &SourceConfiguration,
        request: &UpdateSourceConfiguration,
    ) -> bool {
        fn non_empty(value: Option<&str>) -> Option<&str> {
            value.filter(|v| !v.is_empty())
        }
        request.name.as_ref().is_some_and(|v| *v != existing.name)
            || request
                .config_type
                .as_ref()
                .is_some_and(|v| *v != existing.config_type)
            || request
                .connection_config
                .as_ref()
                .is_some_and(|v| *v != existing.connection_config)
            || request
                .credential_id
                .is_some_and(|v| Some(v) != existing.credential_id)
            || request.default_source_type.as_ref().is_some_and(|v| {
                non_empty(Some(v.as_str())) != non_empty(existing.default_source_type.as_deref())
            })
    }

    /// Routing rules are rendered into a source's routing transform, so a
    /// rule change on a DEPLOYED source is a deploy (NAN-5232).
    async fn ensure_rule_change_allowed(
        &self,
        source_configuration_id: Uuid,
        deploy_authorized: bool,
    ) -> Result<(), SourceConfigServiceError> {
        if deploy_authorized {
            return Ok(());
        }
        if self.repository.get(source_configuration_id).await?.deployed {
            return Err(SourceConfigServiceError::DeployPermissionRequired);
        }
        Ok(())
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
            "aws_sqs" => Self::validate_aws_sqs_conn(conn)?,
            "crowdstrike_fdr" => crowdstrike_fdr::validate_conn(conn)?,
            "gcp_pubsub" => Self::validate_gcp_pubsub_conn(conn)?,
            "azure_event_hubs" => azure_event_hubs::validate_conn(conn)?,
            "splunk_hec" => Self::validate_splunk_hec_conn(conn)?,
            _ => {}
        }
        if point_forward::applies_to(config_type) {
            point_forward::validate_conn(config_type, conn)?;
        }

        // NAN-4936: no Vector environment-interpolation syntax in tenant values
        // (the live Vector expands `${...}` against its secret environment).
        super::isolation::reject_env_interpolation(conn, "connection_config")
            .map_err(SourceConfigServiceError::InvalidConfig)?;

        // Universal char-safety pass over every string scalar in the payload.
        Self::validate_safe_strings(conn, "connection_config")
    }

    /// `null` or `{}`: a source created before its connection is configured.
    pub(crate) fn is_unconfigured(conn: &serde_json::Value) -> bool {
        conn.is_null() || conn.as_object().is_some_and(|o| o.is_empty())
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
        // NAN-2188: reject bad tuning values HERE, with a message naming the
        // field, rather than letting the generator quietly fall back to its
        // default. A silently-ignored `poll_secs` is worse than a rejected one
        // — the operator believes they changed the ingest cadence and nothing
        // in the deployed config says otherwise.
        Self::expect_bounded_int_if_present(conn, "poll_secs", MAX_POLL_SECS)?;
        Self::expect_bounded_int_if_present(conn, "client_concurrency", MAX_CLIENT_CONCURRENCY)?;
        // NAN-4936: bounded by SQS's own 12-hour maximum.
        Self::expect_bounded_int_if_present(conn, "visibility_timeout_secs", MAX_SQS_VISIBILITY_SECS)?;
        Ok(())
    }

    /// A tuning knob must be a positive integer within [`MAX_TUNING_VALUE`].
    /// Absent and explicit null both mean "use the default" and pass.
    fn expect_bounded_int_if_present(
        conn: &serde_json::Value,
        key: &str,
        max: u32,
    ) -> Result<(), SourceConfigServiceError> {
        let Some(v) = conn.get(key) else {
            return Ok(());
        };
        if v.is_null() {
            return Ok(());
        }
        let ok = v
            .as_i64()
            .and_then(|n| u32::try_from(n).ok())
            .is_some_and(|n| n > 0 && n <= max);
        if ok {
            return Ok(());
        }
        Err(SourceConfigServiceError::InvalidConfig(format!("aws_s3 connection_config.{key} must be an integer between 1 and {max}")))
    }

    fn validate_aws_sqs_conn(conn: &serde_json::Value) -> Result<(), SourceConfigServiceError> {
        Self::expect_string_if_present(conn, "queue_url")?;
        Self::expect_string_if_present(conn, "region")?;
        Self::expect_string_if_present(conn, "endpoint")?;
        Self::expect_bounded_int_if_present(conn, "poll_secs", MAX_POLL_SECS)?;
        Self::expect_bounded_int_if_present(conn, "client_concurrency", MAX_CLIENT_CONCURRENCY)?;
        // Vector's visibility timeout must exceed the time it takes to process
        // a batch, or SQS redelivers messages that are still in flight and the
        // pipeline duplicates them. Bounded by SQS's own 12-hour maximum.
        Self::expect_bounded_int_if_present(conn, "visibility_timeout_secs", MAX_SQS_VISIBILITY_SECS)?;
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

    /// Toggle enabled status. Returns the row with secrets masked (NAN-2067).
    pub async fn toggle(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<SourceConfiguration, SourceConfigServiceError> {
        Ok(self.repository.toggle_enabled(id, enabled).await?.redacted())
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
    ///
    /// `deploy_authorized`: see [`Self::update`] — a rule on a deployed source
    /// needs `source_configs:deploy` (NAN-5232).
    pub async fn create_rule(
        &self,
        source_configuration_id: Uuid,
        mut request: NewRoutingRule,
        deploy_authorized: bool,
    ) -> Result<RoutingRule, SourceConfigServiceError> {
        // Reject an unknown match type before the parent lookup.
        Self::validate_match_type(&request.match_type)?;
        let parent = self.repository.get(source_configuration_id).await?;
        if parent.deployed && !deploy_authorized {
            return Err(SourceConfigServiceError::DeployPermissionRequired);
        }
        Self::validate_new_routing_rule(&parent.config_type, &mut request)?;

        Ok(self
            .repository
            .create_rule(source_configuration_id, request)
            .await?)
    }

    fn validate_match_type(match_type: &str) -> Result<(), SourceConfigServiceError> {
        if super::types::MatchType::from_str(match_type).is_none() {
            return Err(SourceConfigServiceError::InvalidConfig(format!(
                "Invalid match type: {}",
                match_type
            )));
        }
        Ok(())
    }

    /// Write-time validation for a new routing rule under a parent of
    /// `config_type`. Shared by [`Self::create_rule`] and the inline initial
    /// rules on [`Self::create`] (NAN-5152), since the router renderer
    /// interpolates the validated field path into generated VRL.
    pub(crate) fn validate_new_routing_rule(
        config_type: &str,
        request: &mut NewRoutingRule,
    ) -> Result<(), SourceConfigServiceError> {
        Self::validate_match_type(&request.match_type)?;

        // Coerce + validate match_field/match_type for the parent's
        // config_type. Pull sources collapse non-default source_type rules to
        // default; everything non-default then has its match_field run through
        // the safe-VRL-path validator.
        Self::coerce_and_validate_match(
            config_type,
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
        )
    }

    /// Update a routing rule
    pub async fn update_rule(
        &self,
        rule_id: Uuid,
        mut request: UpdateRoutingRule,
        deploy_authorized: bool,
    ) -> Result<RoutingRule, SourceConfigServiceError> {
        if !deploy_authorized {
            let rule = self.repository.get_rule(rule_id).await?;
            self.ensure_rule_change_allowed(rule.source_configuration_id, false)
                .await?;
        }
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
            if super::isolation::contains_env_interpolation(value) {
                return Err(SourceConfigServiceError::InvalidConfig(
                    "match_value must not contain environment-variable syntax (`${...}` or \
                     `$NAME`); Vector would expand it against its own environment"
                        .to_string(),
                ));
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
    pub async fn delete_rule(
        &self,
        rule_id: Uuid,
        deploy_authorized: bool,
    ) -> Result<(), SourceConfigServiceError> {
        if !deploy_authorized {
            let rule = self.repository.get_rule(rule_id).await?;
            self.ensure_rule_change_allowed(rule.source_configuration_id, false)
                .await?;
        }
        Ok(self.repository.delete_rule(rule_id).await?)
    }

    /// Reorder routing rules
    pub async fn reorder_rules(
        &self,
        source_configuration_id: Uuid,
        rule_order: Vec<Uuid>,
        deploy_authorized: bool,
    ) -> Result<Vec<RoutingRule>, SourceConfigServiceError> {
        self.ensure_rule_change_allowed(source_configuration_id, deploy_authorized)
            .await?;
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

    /// Deploy a source configuration to Vector and report whether Vector
    /// actually activated it (NAN-4936).
    pub async fn deploy(
        &self,
        id: Uuid,
        credential_use: CredentialUseGrant,
    ) -> Result<DeploymentResult, SourceConfigServiceError> {
        self.deploy_with(id, credential_use, true).await
    }

    /// `confirm_activation = false` skips the per-source wait on Vector's
    /// reload acknowledgement. Only the boot-time `deploy_all` passes it: it
    /// renders every source back-to-back (often before Vector is up), and a
    /// 10-45s wait per source would stall API startup. Isolation and
    /// quarantine still apply.
    async fn deploy_with(
        &self,
        id: Uuid,
        credential_use: CredentialUseGrant,
        confirm_activation: bool,
    ) -> Result<DeploymentResult, SourceConfigServiceError> {
        // NAN-4936 (codex P1): one critical section from the isolation check to
        // Vector's acknowledgement, shared with parser deploys. Without it a
        // concurrent deploy's reload could acknowledge this one, or interleave
        // its writes with ours. The lock is not reentrant: everything below
        // uses the `_locked` router helper.
        let _deploy_guard = self.lock_deploys().await;

        // NAN-4937 (codex P1): the snapshot this deploy renders. `deployed_at`
        // advances only after Vector activates it, and only if neither the
        // row nor its rules changed after this point (`stamp_deployed`).
        let rendered_at = self.repository.db_now().await?;
        let config_with_rules = self.repository.get_with_rules(id).await?;
        let config = &config_with_rules.config;

        // Re-evaluate against the current saved reference immediately before
        // any generation, credential decryption, deployment audit, or file I/O.
        Self::ensure_credential_use(config.credential_id, credential_use)?;

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
                    // NAN-2067: match the non-system failure path — never
                    // persist an unredacted snapshot into deployment history.
                    let redacted_snapshot = redact_config_snapshot(config_content);
                    if let Err(audit_err) = self
                        .repository
                        .add_deployment(
                            id,
                            "deploy",
                            "failure",
                            Some(&reason),
                            Some(&redacted_snapshot),
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
            }

            let watch = if confirm_activation {
                Some(ReloadWatch::begin(&self.vector_config_dir).await)
            } else {
                None
            };

            if let Some(config_content) = &vector_config {
                // Write config file so Vector picks up the routing transform
                let config_file = self.get_config_file_path(&config.config_type, &config.name);
                let configs_dir = config_file.parent().unwrap();
                tokio::fs::create_dir_all(configs_dir).await?;
                tokio::fs::write(&config_file, config_content).await?;
            } else if config.config_type == "splunk_hec" {
                // NAN-4902: `splunk_hec_route` is permanent (HEC parsers read
                // it). With only default rules there is nothing to route, so
                // replace any previous rules file with the passthrough rather
                // than leaving stale rules or no route at all.
                self.write_hec_passthrough_route().await?;
            }

            let rendered = self.flag_deployed(config).await?;

            // Update dynamic router — include this config's route transform in inputs
            self.update_dynamic_router_locked().await?;

            let mut activation_note: Option<String> = None;
            if let Some(watch) = watch {
                // A system listener's routing file is nano-rendered and VRL-checked;
                // a refusal is reported, never quarantined (`vector_built: true`).
                match self
                    .settle_activation(
                        &config_with_rules,
                        watch,
                        vector_config.as_deref().unwrap_or_default(),
                        true,
                    )
                    .await?
                {
                    activation::Settlement::Final(result) => return Ok(result),
                    activation::Settlement::Live { note } => activation_note = note,
                }
                self.stamp_activated(id, rendered, rendered_at).await?;
            }

            let snapshot = vector_config.as_deref().map(redact_config_snapshot);
            let deployment = self
                .repository
                .add_deployment(id, "deploy", "success", activation_note.as_deref(), snapshot.as_deref())
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
                    "Deployed '{}' successfully (system-level {} source{}){}",
                    config.name,
                    config.config_type,
                    if has_meaningful_rules {
                        " with routing rules"
                    } else {
                        ""
                    },
                    activation_note.as_deref().map(|n| format!(" ({n})")).unwrap_or_default()
                ),
                deployment_id: Some(deployment.id),
            });
        }

        // NAN-4936: a pull source must build ON ITS OWN before it may touch
        // the live topology. One that does not is quarantined (kept out,
        // recorded with Vector's reason) and the rest of the config stays live.
        // Before the live render, which overwrites the credential file in place.
        let vector_built = match self.isolate_pull_source(&config_with_rules).await? {
            activation::Isolation::Broken(reason) => {
                return self.quarantine(&config_with_rules, &reason, None).await;
            }
            activation::Isolation::Clean { vector_built } => vector_built,
        };

        // Generate Vector config
        let vector_config = self.generate_vector_config(&config_with_rules).await?;

        // NAN-689 acceptance criterion #3: validate the generated config
        // (TOML parse + VRL compile) before any persistence side-effect.
        // No file write, no mark_deployed, no router update if validation
        // fails — and we record the failure for audit.
        if let Err(e) = Self::validate_generated_config(&vector_config) {
            let reason = e.to_string();
            // NAN-2067: the success paths redact this snapshot (NAN-690) but
            // the failure path persisted the raw generated TOML — real SASL
            // password, AWS secret_access_key / session_token, HEC tokens —
            // straight into deployment history, which
            // `GET /api/source-configurations/{id}/deployments` serves to any
            // `source_configs:view` holder. Redact here too.
            let redacted_snapshot = redact_config_snapshot(&vector_config);
            if let Err(audit_err) = self
                .repository
                .add_deployment(
                    id,
                    "deploy",
                    "failure",
                    Some(&reason),
                    Some(&redacted_snapshot),
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

        // NAN-4936: baseline Vector's reload counters BEFORE the first write;
        // a `--watch-config` Vector reloads on its own.
        let watch = if confirm_activation {
            Some(ReloadWatch::begin(&self.vector_config_dir).await)
        } else {
            None
        };

        // Write config file
        let config_file = self.get_config_file_path(&config.config_type, &config.name);
        let configs_dir = config_file.parent().unwrap();
        tokio::fs::create_dir_all(configs_dir).await?;
        tokio::fs::write(&config_file, &vector_config).await?;
        self.clear_startup_quarantine(config).await;

        // `deployed = true` BEFORE updating the router, so the router query
        // includes this config; `deployed_at` waits for activation.
        let rendered = self.flag_deployed(config).await?;

        // Update dynamic router to include this source
        self.update_dynamic_router_locked().await?;

        let mut activation_note: Option<String> = None;
        if let Some(watch) = watch {
            match self
                .settle_activation(&config_with_rules, watch, &vector_config, vector_built)
                .await?
            {
                activation::Settlement::Final(result) => return Ok(result),
                activation::Settlement::Live { note } => activation_note = note,
            }
            self.stamp_activated(id, rendered, rendered_at).await?;
        }

        // Record deployment — snapshot the redacted view so deployment history
        // never leaks SASL passwords / AWS secret keys / HEC tokens to users
        // who only hold `source_configs:view`.
        let snapshot = redact_config_snapshot(&vector_config);
        let deployment = self
            .repository
            .add_deployment(id, "deploy", "success", activation_note.as_deref(), Some(&snapshot))
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
        if let Some(note) = &activation_note {
            message.push_str(&format!(" ({note})"));
        }
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
        // NAN-4936: one critical section from the first removal to Vector's
        // acknowledgement (see `deploy_with`).
        let _deploy_guard = self.lock_deploys().await;
        let config = self.repository.get(id).await?;
        let watch = ReloadWatch::begin(&self.vector_config_dir).await;

        // System-level sources (http, vector, splunk_hec) — remove the
        // routing config file if it was deployed; the OOTB source itself
        // keeps running. See `system_intermediary_source` for rationale.
        if Self::system_intermediary_source(&config.config_type).is_some() {
            if config.config_type == "splunk_hec" {
                // NAN-4902: never delete `splunk_hec_route` — deployed HEC
                // parsers read it, and a missing route makes a cold-started
                // Vector reject the whole config. Undeploying drops the routing
                // rules: the passthrough keeps `.source_type` as is, exactly
                // like `hec_normalize` feeding `source_router` directly.
                self.write_hec_passthrough_route().await?;
            } else {
                let config_file = self.get_config_file_path(&config.config_type, &config.name);
                if config_file.exists() {
                    tokio::fs::remove_file(&config_file).await?;
                }
            }
            self.repository.mark_undeployed(id).await?;

            // Update dynamic router (system-level types are filtered out, but ensures
            // other deployed configs have correct inputs)
            self.update_dynamic_router_locked().await?;

            tracing::info!(
                "Undeployed {} source configuration '{}' (system-level)",
                config.config_type,
                config.name
            );
            return self.finish_removal(id, &config.name, watch).await;
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

        self.clear_startup_quarantine(&config).await;

        // Update dynamic router to remove this source's route
        self.update_dynamic_router_locked().await?;

        tracing::info!("Undeployed source configuration '{}'", config.name);
        // NAN-4936 (codex P1): success only once Vector has loaded a topology
        // without this source; otherwise an explicit unconfirmed result.
        self.finish_removal(id, &config.name, watch).await
    }

    /// Deploy all enabled source configurations
    /// `POST /api/source-configurations/deploy-all`: deploys every enabled
    /// config and reports, per source, whether Vector actually activated it
    /// (NAN-4936, codex P1: this used to skip the acknowledgement).
    pub async fn deploy_all(
        &self,
        credential_use: CredentialUseGrant,
    ) -> Result<Vec<DeploymentResult>, SourceConfigServiceError> {
        self.deploy_all_with(credential_use, true).await
    }

    /// API boot reconciliation only: re-render every enabled config without
    /// waiting for Vector per source (Vector is often not up yet at api boot,
    /// and a 10-45s wait per source would stall startup). Isolation and
    /// quarantine still apply; the publication reconciler and the Vector
    /// container's cold-start guard cover activation.
    pub async fn reconcile_on_boot(
        &self,
        credential_use: CredentialUseGrant,
    ) -> Result<Vec<DeploymentResult>, SourceConfigServiceError> {
        self.deploy_all_with(credential_use, false).await
    }

    async fn deploy_all_with(
        &self,
        credential_use: CredentialUseGrant,
        confirm_activation: bool,
    ) -> Result<Vec<DeploymentResult>, SourceConfigServiceError> {
        let configs = self.repository.list_enabled().await?;

        // Fail closed for the current set before deploying anything. Each
        // individual deploy checks again so a credential attached after this
        // preflight still cannot be decrypted without authorization.
        for config in &configs {
            Self::ensure_credential_use(config.credential_id, credential_use)?;
        }

        let mut results = Vec::new();

        for config in configs {
            match self.deploy_with(config.id, credential_use, confirm_activation).await {
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

    /// NAN-4914: secret-only refresh of every deployed source configuration
    /// bound to `credential_id`, after the credential was rotated or rolled
    /// back, so the new secret reaches Vector now instead of on the next
    /// manual deploy.
    ///
    /// It never publishes anything but the credential change: each config is
    /// re-rendered from its saved row with the new secret and compared with
    /// its last successful deployment snapshot, both normalized so that only
    /// credential-derived values (and the generated-at comment) are ignored.
    /// A config whose saved row has pending, undeployed edits renders
    /// differently and is left alone ([`CredentialRefreshOutcome::PendingEdits`]),
    /// so rotating a credential can never activate a source-config change the
    /// caller had no authority to deploy. Only an identical-but-for-secrets
    /// config is redeployed (trusted system follow-up of the rotation,
    /// [`CredentialUseGrant::system`]). One config failing does not stop the
    /// others; an enumeration failure is an `Err` the caller must surface.
    pub async fn refresh_secrets_for_credential(
        &self,
        credential_id: Uuid,
        previous_payload: Option<&serde_json::Value>,
    ) -> Result<Vec<CredentialRefresh>, SourceConfigServiceError> {
        let bound: Vec<SourceConfiguration> = self
            .repository
            .list_deployed()
            .await?
            .into_iter()
            .filter(|c| c.credential_id == Some(credential_id))
            .collect();
        if bound.is_empty() {
            return Ok(Vec::new());
        }
        let new_payload = self
            .credential_repo
            .get_decrypted(credential_id)
            .await
            .map_err(|e| SourceConfigServiceError::CredentialError(e.to_string()))?;

        let mut out = Vec::with_capacity(bound.len());
        for config in bound {
            let outcome = match self.secret_only_change(&config, previous_payload, &new_payload).await {
                Ok(SecretOnly::Yes) => match self.deploy(config.id, CredentialUseGrant::system()).await {
                    Ok(r) if r.success => CredentialRefreshOutcome::Redeployed,
                    Ok(r) => CredentialRefreshOutcome::Failed(r.message),
                    Err(e) => CredentialRefreshOutcome::Failed(e.to_string()),
                },
                Ok(SecretOnly::PendingEdits) => CredentialRefreshOutcome::PendingEdits,
                Ok(SecretOnly::NoSnapshot) => CredentialRefreshOutcome::NoDeployedSnapshot,
                Err(e) => CredentialRefreshOutcome::Failed(e.to_string()),
            };
            if let CredentialRefreshOutcome::Failed(error) = &outcome {
                tracing::error!(source_config = %config.name, %credential_id, %error, "secret refresh after credential rotation failed");
            }
            out.push(CredentialRefresh { source_configuration_id: config.id, name: config.name, outcome });
        }
        Ok(out)
    }

    /// Whether re-rendering `config` with the new credential differs from its
    /// last successful deployment only in credential-derived values.
    async fn secret_only_change(
        &self,
        config: &SourceConfiguration,
        previous: Option<&serde_json::Value>,
        new: &serde_json::Value,
    ) -> Result<SecretOnly, SourceConfigServiceError> {
        let Some(snapshot) = self
            .repository
            .get_deployments(config.id, Some(50))
            .await?
            .into_iter()
            .find(|d| d.action == "deploy" && d.status == "success" && d.config_snapshot.is_some())
            .and_then(|d| d.config_snapshot)
        else {
            return Ok(SecretOnly::NoSnapshot);
        };
        let with_rules = self.repository.get_with_rules(config.id).await?;
        let rendered = match Self::system_intermediary_source(&config.config_type) {
            Some(intermediary) => Self::render_system_source_config(&with_rules, intermediary).unwrap_or_default(),
            None => self.generate_vector_config(&with_rules).await?,
        };
        let now = normalize_for_secret_compare(&redact_config_snapshot(&rendered), Some(new));
        let then = normalize_for_secret_compare(&snapshot, previous);
        Ok(if now == then { SecretOnly::Yes } else { SecretOnly::PendingEdits })
    }

    /// NAN-5147: require credential-owner permission (`credentials:edit`).
    fn ensure_credential_retarget(grant: CredentialUseGrant) -> Result<(), SourceConfigServiceError> {
        grant
            .ensure_retarget()
            .map_err(|_| SourceConfigServiceError::CredentialRetargetRequired)
    }

    /// Require explicit credential-use authorization only when a source
    /// configuration references stored credential material.
    fn ensure_credential_use(
        credential_id: Option<Uuid>,
        grant: CredentialUseGrant,
    ) -> Result<(), SourceConfigServiceError> {
        if credential_id.is_some() {
            grant
                .ensure()
                .map_err(|_| SourceConfigServiceError::CredentialUseRequired)?;
        }
        Ok(())
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
                // NAN-4936 (codex P1): one source Vector cannot build must not
                // poison the generation (consumers would refuse it on reload and
                // crash-loop on cold start). Run the same per-source isolation a
                // deploy runs: the pinned Vector builds it on its own where the
                // validation responder is reachable (a revoked token fails its
                // build-time token request), the in-process preflight elsewhere.
                // A failing source is left out and recorded as quarantined; it
                // stays `deployed`, so a later generation includes it again as
                // soon as it builds.
                if let activation::Isolation::Broken(reason) =
                    self.isolate_pull_source(&config_with_rules).await?
                {
                    tracing::warn!(
                        source_config = %config.name,
                        %reason,
                        "leaving a pull source out of the published Vector generation: it cannot build"
                    );
                    self.record_generation_quarantine(config.id, &reason).await;
                    continue;
                }
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

    /// Get deployment history, with secrets scrubbed from every snapshot.
    ///
    /// NAN-2067: redacting only on the write path would leave rows persisted
    /// BEFORE this fix exposed — an upgraded tenant whose deploy failed while
    /// the old code was running still has raw generated TOML (real SASL
    /// password, AWS keys, HEC tokens) in `config_snapshot`, and this endpoint
    /// serves it to any `source_configs:view` holder. Redacting at the read
    /// boundary closes the historical rows too, without a backfill migration.
    /// `redact_config_snapshot` is idempotent, so already-redacted rows are
    /// unaffected.
    pub async fn get_deployment_history(
        &self,
        id: Uuid,
        limit: Option<i64>,
    ) -> Result<Vec<SourceConfigDeployment>, SourceConfigServiceError> {
        let mut deployments = self.repository.get_deployments(id, limit).await?;
        for deployment in &mut deployments {
            if let Some(snapshot) = deployment.config_snapshot.as_deref() {
                deployment.config_snapshot = Some(redact_config_snapshot(snapshot));
            }
        }
        Ok(deployments)
    }

    // ========================================================================
    // Vector Config Generation
    // ========================================================================

    /// Generate Vector TOML config for a source configuration
    async fn generate_vector_config(
        &self,
        config: &SourceConfigurationWithRules,
    ) -> Result<String, SourceConfigServiceError> {
        self.render_pull_source(config, &activation::CredsTarget::Live).await
    }

    /// Render a pull source's config, materializing its credential files at
    /// `creds_target`. The NAN-4936 isolation check renders a CANDIDATE into
    /// its validation request instead of overwriting a working source's key
    /// material before the candidate has been proven.
    async fn render_pull_source(
        &self,
        config: &SourceConfigurationWithRules,
        creds_target: &activation::CredsTarget,
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
        let source_block = self.generate_source_block(config, creds_target).await?;
        toml.push_str(&source_block);
        toml.push_str("\n");

        // NAN-4914: queue / subscription sources start at current activity.
        // The point-forward filter sits between the source and its routing
        // transform, so the route reads from the filter.
        let route_input = match point_forward::cutoff_unix_ms(config) {
            Some(cutoff) => {
                let filter_name = format!("{safe_name}{}", point_forward::POINT_FORWARD_SUFFIX);
                toml.push_str(&point_forward::render_filter(
                    &filter_name,
                    &source_name,
                    &config.config.config_type,
                    cutoff,
                ));
                toml.push('\n');
                filter_name
            }
            None => source_name.clone(),
        };

        // Generate routing transform
        let routing_block =
            Self::generate_routing_transform(config, &route_input, &route_name, false);
        toml.push_str(&routing_block);

        // NAN-4936: tenant values (credential values included, which cannot be
        // rejected) must never expand against the live Vector's secret
        // environment; `$$` reads back as a literal `$` (Azure's `$Default`).
        Ok(super::isolation::escape_env_interpolation(&toml))
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
        Some(super::isolation::escape_env_interpolation(&format!(
            "# Auto-generated routing rules for system-level source: {}\n\
             # DO NOT EDIT - changes will be overwritten\n\
             # Generated at: {}\n\n\
             {}",
            config.config.name,
            chrono::Utc::now().to_rfc3339(),
            routing_block
        )))
    }

    /// Generate the Vector source block based on config type
    async fn generate_source_block(
        &self,
        config: &SourceConfigurationWithRules,
        creds_target: &activation::CredsTarget,
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
            match creds.as_ref() {
                // No credential attached: the operator chose ambient
                // credentials (GCE/GKE metadata server) explicitly.
                None => None,
                // A credential IS attached: it must yield a valid credentials
                // file, or generation fails closed. Silently omitting
                // `credentials_path` would switch the source to the node's
                // ambient identity (NAN-4935 review).
                Some(c) => {
                    let creds_json = crate::parsers::gcp_credentials::credentials_file_contents(c)
                        .map_err(|reason| {
                            SourceConfigServiceError::CredentialError(format!(
                                "the credential attached to GCP Pub/Sub source '{}' cannot \
                                 produce a credentials file: {reason}",
                                config.config.name
                            ))
                        })?;
                    let key = Self::gcp_creds_key(&config.config.id);
                    Some(self.write_source_creds(creds_target, &key, creds_json.as_bytes()).await?)
                }
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
                        Some(self.write_source_creds(creds_target, &key, ca_cert.as_bytes()).await?)
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
            "aws_sqs" => Self::generate_aws_sqs_source(&source_name, conn, creds.as_ref()),
            "crowdstrike_fdr" => {
                let mut block = format!("# NAN-5005: {}.\n", crowdstrike_fdr::LOOKUPS_POLICY);
                block.push_str(&Self::wrap_source_table(
                    &source_name,
                    crowdstrike_fdr::source_table(&source_name, conn, creds.as_ref())?,
                ));
                block
            }
            "gcp_pubsub" => {
                Self::generate_gcp_pubsub_source(&source_name, conn, gcp_creds_path.as_deref())
            }
            "azure_event_hubs" => Self::wrap_source_table(
                &source_name,
                azure_event_hubs::source_table(conn, creds.as_ref())?,
            ),
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
        // NAN-2188: `client_concurrency` is the first knob worth touching on a
        // high-object-count feed, and it was previously unreachable. Omitted
        // entirely when unset so Vector's own default applies — emitting a
        // guess here would silently override it for every existing deployment.
        // NAN-3604: it belongs in the `sqs` table (Vector's aws_s3
        // `sqs::Config`); the source's top level is `deny_unknown_fields`, so a
        // top-level key fails `vector validate` with "unknown field".
        if let Some(concurrency) =
            Self::positive_u32(conn, "client_concurrency", MAX_CLIENT_CONCURRENCY)
        {
            sqs.insert(
                "client_concurrency".into(),
                toml::Value::Integer(i64::from(concurrency)),
            );
        }
        // Defaults to the previously hard-coded 15, so an existing config that
        // does not set it emits byte-identical TOML. `poll_secs` governs
        // empty-queue backoff, NOT throughput — with a backlog Vector keeps
        // polling — so the reason to lower it is ingest LATENCY on a quiet
        // queue, where 15s is the floor on noticing a new object.
        sqs.insert(
            "poll_secs".into(),
            toml::Value::Integer(i64::from(
                Self::positive_u32(conn, "poll_secs", MAX_POLL_SECS).unwrap_or(DEFAULT_SQS_POLL_SECS),
            )),
        );
        // NAN-4936: lives in the `sqs` table (Vector's aws_s3 `sqs::Config`),
        // like `client_concurrency`. Emitted only when set (codex P2): an
        // existing source keeps Vector's 300s, because a shorter timeout than
        // one object takes to process redelivers it and duplicates its events.
        // New sources get 60 from the UI form (a notification in flight across
        // a Vector restart then comes back after 60s instead of ~300s).
        if let Some(visibility) =
            Self::positive_u32(conn, "visibility_timeout_secs", MAX_SQS_VISIBILITY_SECS)
        {
            sqs.insert(
                "visibility_timeout_secs".into(),
                toml::Value::Integer(i64::from(visibility)),
            );
        }
        sqs.insert("delete_message".into(), true.into());
        source.insert("sqs".into(), toml::Value::Table(sqs));

        if let Some(auth) = Self::aws_auth_table(creds, region, source_name) {
            source.insert("auth".into(), toml::Value::Table(auth));
        }

        Self::wrap_source_table(source_name, source)
    }

    /// Read a positive integer tuning knob from a connection config.
    ///
    /// Returns `None` for absent, null, non-numeric, zero, negative, or
    /// above the caller's `max` — every one of which means "no usable value",
    /// so the caller falls back to its default rather than emitting something
    /// Vector will reject at load. Validation (`validate_aws_s3_conn`) rejects
    /// these at write time with a real error; this is the belt-and-braces read
    /// side, since connection configs predate the validator and can also be
    /// written by other paths.
    fn positive_u32(conn: &serde_json::Value, key: &str, max: u32) -> Option<u32> {
        let n = conn.get(key)?.as_i64()?;
        u32::try_from(n).ok().filter(|v| *v > 0 && *v <= max)
    }

    /// Build the `[sources.<name>.auth]` table shared by the AWS sources.
    ///
    /// Returns `None` when the credential carries nothing we can act on, which
    /// is the load-bearing case: with no `auth` block Vector falls through to
    /// the AWS SDK provider chain — EC2 instance profile, EKS IRSA, ECS task
    /// role. That is how a keyless deployment consumes a queue in its OWN
    /// account, and `CredentialPicker` already advertises it as
    /// "None (use environment / IAM role)".
    ///
    /// NAN-2186: `assume_role` used to be nested INSIDE the both-static-keys
    /// branch, so the one posture a security-conscious customer actually wants
    /// — ambient identity assuming a role in ANOTHER account — could not be
    /// expressed at all. You had to hand over the long-lived access key you
    /// were trying to avoid. The four postures are now independent:
    ///
    /// | static keys | assume_role | result                                  |
    /// |-------------|-------------|-----------------------------------------|
    /// | no          | no          | no auth block → ambient identity        |
    /// | yes         | no          | static keys (unchanged)                 |
    /// | yes         | yes         | static keys chain into the role         |
    /// | no          | yes         | ambient identity assumes the role (NEW) |
    ///
    /// `external_id` accompanies `assume_role` and is what makes the
    /// cross-account grant safe for a MANAGED deployment: it is AWS's
    /// prescribed defense against the confused-deputy problem. Without it, a
    /// tenant's role ARN leaking plus a system that can be induced to assume an
    /// arbitrary ARN is a cross-tenant access path. It is meaningless without a
    /// role, so it is only emitted alongside one.
    pub(crate) fn aws_auth_table(
        creds: Option<&serde_json::Value>,
        region: &str,
        source_name: &str,
    ) -> Option<toml::Table> {
        let c = creds?;
        let field = |k: &str| c[k].as_str().unwrap_or("").trim().to_string();

        let access_key = field("access_key_id");
        let secret_key = field("secret_access_key");
        let assume_role = field("assume_role_arn");
        let external_id = field("external_id");

        // A half-filled key pair is a misconfiguration, not a credential —
        // emitting one field alone yields a Vector config that fails at
        // runtime. Treat it as absent and let the role (or ambient identity)
        // carry the request.
        let has_static_keys = !access_key.is_empty() && !secret_key.is_empty();
        let has_role = !assume_role.is_empty();

        if !has_static_keys && !has_role {
            return None;
        }

        let mut auth = toml::Table::new();
        if has_static_keys {
            auth.insert("access_key_id".into(), access_key.into());
            auth.insert("secret_access_key".into(), secret_key.into());
        }
        if has_role {
            auth.insert("assume_role".into(), assume_role.into());
            if !external_id.is_empty() {
                auth.insert("external_id".into(), external_id.into());
            }
            // NAN-2194: the RoleSessionName lands in the CUSTOMER's CloudTrail.
            // Without one, every assumption we make into their account is
            // indistinguishable from any other caller — a bad answer when their
            // security team asks who touched their data. Naming the source makes
            // their audit trail legible without them having to ask us.
            auth.insert("session_name".into(), role_session_name(source_name).into());
        }
        auth.insert("region".into(), region.into());
        Some(auth)
    }

    /// Build the `[sources.<name>]` block for an AWS SQS source (NAN-2187).
    ///
    /// Distinct from [`Self::generate_aws_s3_source`] despite the shared
    /// transport: there, SQS carries S3 `ObjectCreated` NOTIFICATIONS and the
    /// log is the S3 object Vector then fetches. Here the message body IS the
    /// log, so there is no bucket, no object fetch, and routing keys are
    /// message attributes rather than bucket/key.
    ///
    /// Auth and the tuning knobs come from the shared helpers, so a
    /// cross-account role (NAN-2186) and concurrency limits (NAN-2188) work
    /// identically on both AWS drivers.
    fn generate_aws_sqs_source(
        source_name: &str,
        conn: &serde_json::Value,
        creds: Option<&serde_json::Value>,
    ) -> String {
        let queue_url = conn["queue_url"].as_str().unwrap_or("");
        let region = conn["region"].as_str().unwrap_or("us-east-1");

        let mut source = toml::Table::new();
        source.insert("type".into(), "aws_sqs".into());
        source.insert("region".into(), region.into());
        source.insert("queue_url".into(), queue_url.into());

        if let Some(endpoint) = conn["endpoint"].as_str() {
            if !endpoint.is_empty() {
                source.insert("endpoint".into(), endpoint.into());
            }
        }

        source.insert(
            "poll_secs".into(),
            toml::Value::Integer(i64::from(
                Self::positive_u32(conn, "poll_secs", MAX_POLL_SECS)
                    .unwrap_or(DEFAULT_SQS_POLL_SECS),
            )),
        );

        // Top level is correct here, unlike aws_s3 (where it sits under `sqs`):
        // Vector's `AwsSqsConfig` declares `client_concurrency` directly.
        if let Some(concurrency) =
            Self::positive_u32(conn, "client_concurrency", MAX_CLIENT_CONCURRENCY)
        {
            source.insert(
                "client_concurrency".into(),
                toml::Value::Integer(i64::from(concurrency)),
            );
        }

        // Omitted unless set: Vector inherits the queue's own configured
        // timeout, which is what an operator who has not thought about it
        // wants. Overriding with a guess would silently change redelivery
        // behaviour on an existing queue.
        if let Some(visibility) =
            Self::positive_u32(conn, "visibility_timeout_secs", MAX_SQS_VISIBILITY_SECS)
        {
            source.insert(
                "visibility_timeout_secs".into(),
                toml::Value::Integer(i64::from(visibility)),
            );
        }

        if let Some(auth) = Self::aws_auth_table(creds, region, source_name) {
            source.insert("auth".into(), toml::Value::Table(auth));
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
    pub(crate) fn validate_generated_config(toml_str: &str) -> Result<(), SourceConfigServiceError> {
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
        // NAN-4912 P3: generated remaps compile against the event-parser
        // allowlist, like every other parser path.
        let fns = crate::parsers::vrl_functions::parser_vrl_functions();
        for (name, transform) in transforms {
            // Only `remap` transforms carry user-controlled VRL via the
            // `source` attribute. Other transform types (`route`, `filter`,
            // …) take static config we don't generate from user input.
            // NAN-4914: the generated point-forward `filter` carries a VRL
            // `condition` string; compile it too.
            let source_key = match transform.get("type").and_then(|v| v.as_str()) {
                Some("remap") => "source",
                Some("filter") => "condition",
                _ => continue,
            };
            let source = match transform.get(source_key).and_then(|s| s.as_str()) {
                Some(s) => s,
                None => continue,
            };
            // NAN-3494: guarded compile (size/nesting cap, large stack).
            if let Err(error) = crate::parsers::vrl_guard::compile(source, &fns) {
                let formatted = error.render(source);
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
        let header_len = vrl.len();

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
                    // NAN-5005: an FDR feed is CrowdStrike Falcon telemetry;
                    // without a rule it goes to the Falcon parser.
                    .or((config.config.config_type == "crowdstrike_fdr")
                        .then_some(crowdstrike_fdr::FDR_DEFAULT_SOURCE_TYPE))
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

        // NAN-4907: on the shared HTTP / HEC listeners a source-bound ingest
        // token decides the source (`source_type_extract` / `hec_normalize`
        // set it from the token's route key). Routing rules match on event
        // fields a sender controls, so they apply only to events without a
        // source-bound credential: multiplex credentials (route `*`) and the
        // static install-token fallback.
        if system_level && !first {
            let rules_vrl = vrl.split_off(header_len);
            vrl.push_str(
                "# NAN-4907: a source-bound ingest token already decided the source.\n\
                 nano_token_route = to_string(%nano_credential_name) ?? \"\"\n\
                 if nano_token_route == \"\" || nano_token_route == \"*\" {\n",
            );
            vrl.push_str(&rules_vrl);
            if !vrl.ends_with('\n') {
                vrl.push('\n');
            }
            vrl.push_str("}\n");
        }

        // NAN-3764: stash the routed source type in event metadata like the
        // system ingress (`00-base.toml`) does. An OCSF parser replaces the
        // event root (`. = {...}`), wiping `.source_type`; `ocsf_prepare`
        // reads `%source_type` back, so without this every dispatch-bound
        // pull source's OCSF rows were stored as `unknown`. System-level
        // sources feed the router, which sets it itself.
        if !system_level {
            vrl.push_str("%source_type = .source_type\n");
        }

        // NAN-3764: an Event Hubs message is usually an Azure Monitor batch,
        // `{"records": [...]}`. Split it into one event per record so the lane
        // sees one record in `.message`. Runs LAST: the rules above routed the
        // whole message, and every record inherits that `.source_type`.
        if !system_level && config.config.config_type == "azure_event_hubs" {
            vrl.push('\n');
            vrl.push_str(azure_event_hubs::AZURE_RECORDS_SPLIT_VRL);
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
        // One VRL string-literal escape for every generator (NAN-5033).
        crate::parsers::vrl_safety::vrl_string_body(s)
    }

    /// Update the dynamic router to include all source configuration routes
    async fn update_dynamic_router(&self) -> Result<(), SourceConfigServiceError> {
        // NAN-948: serialize against parser deploys that mutate the same
        // `_router.toml`. The lock is shared with `VectorConfigManager`
        // (handed in via `with_deploy_lock`). When not wired (unit tests,
        // legacy callers), proceed without locking — those paths don't
        // collide with parser deploys.
        let _deploy_guard = self.lock_deploys().await;
        self.update_dynamic_router_locked().await
    }

    /// The shared deploy lock (`None` when not wired: unit tests). Owned, so a
    /// caller can hold it across a whole deploy. NOT reentrant: while holding
    /// it, use only `_locked` helpers.
    /// NAN-4937: set `deployed = true` (first deploy only) without touching
    /// `deployed_at`. Returns the `updated_at` the later stamp must still
    /// find, or `None` when the row changed after it was rendered (then the
    /// stamp is skipped and the UI keeps showing pending changes).
    async fn flag_deployed(
        &self,
        config: &SourceConfiguration,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, SourceConfigServiceError> {
        if config.deployed {
            return Ok(Some(config.updated_at));
        }
        Ok(self.repository.set_deployed_flag(config.id, config.updated_at).await?)
    }

    /// NAN-4937: Vector activated the deploy: advance `deployed_at`, unless the
    /// row or its rules changed after `rendered_at` (a concurrent save is
    /// still pending, so the UI must keep saying so). A failed router write or
    /// a refused/unconfirmed activation never reaches here.
    async fn stamp_activated(
        &self,
        id: Uuid,
        rendered: Option<chrono::DateTime<chrono::Utc>>,
        rendered_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), SourceConfigServiceError> {
        let stamped = match rendered {
            Some(updated_at) => self.repository.stamp_deployed(id, updated_at, rendered_at).await?,
            None => false,
        };
        if !stamped {
            tracing::info!(
                source_configuration_id = %id,
                "activated, but the configuration changed after it was rendered: deployed_at kept, changes stay pending"
            );
        }
        Ok(())
    }

    pub(super) async fn lock_deploys(&self) -> Option<crate::parsers::VectorDeployGuard> {
        // NAN-4953: with the cross-process config-dir lock the Vector
        // entrypoint's migration takes.
        match &self.deploy_lock {
            Some(lock) => Some(
                crate::parsers::VectorDeployGuard::acquire(Arc::clone(lock), &self.vector_config_dir)
                    .await,
            ),
            None => None,
        }
    }

    /// [`Self::update_dynamic_router`] for a caller that already holds the
    /// deploy lock (NAN-4936).
    ///
    /// NAN-4956: a source-config change now re-renders the WHOLE parser tree
    /// (router, claims, parser filters) from the database and the files on
    /// disk, through the same writer every parser deploy uses. It used to be
    /// a surgical rewrite of the first `inputs = [...]` line after
    /// `[transforms.source_router]` plus the `<route>_unclaimed` blocks, so:
    /// * `enrichment_router`, which carries the SAME inputs, kept naming a
    ///   removed `<config>_route`;
    /// * claims came from every enabled parser bound to an existing config,
    ///   deployed or not, so a parser bound to the removed route kept its
    ///   `<route>_unclaimed` block and its own `_filter` on the route.
    /// Either way Vector refused every reload until something rewrote the tree
    /// (~5 min in the NAN-4937 runs). The full render prunes routes that no
    /// longer exist (`VectorConfigManager::without_unroutable_parsers`), and a
    /// config that deploys again brings its bound parsers back.
    pub(super) async fn update_dynamic_router_locked(&self) -> Result<(), SourceConfigServiceError> {
        let pool = self.repository.pool();
        let mut parsers = crate::parsers::list_effective_deployed_parsers(pool)
            .await
            .map_err(SourceConfigRepositoryError::from)?;
        crate::parsers::resolve_parser_dispatch_routes_lenient(pool, &mut parsers)
            .await
            .map_err(SourceConfigRepositoryError::from)?;
        crate::parsers::VectorConfigManager::new(&self.vector_config_dir)
            .deploy_parsers(&parsers)
            .await
            .map_err(|e| {
                SourceConfigServiceError::DeploymentFailed(format!(
                    "could not re-render the parser tree for the source-configuration change: {e}"
                ))
            })?;
        Ok(())
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
        // NAN-3764: Event Hubs application properties are producer-set and
        // typed (string, number, bool, ...); an absent one must simply not
        // match, and a non-string one must compare as its string form.
        if (config_type == "kafka" && match_field.starts_with("headers."))
            || (config_type == "azure_event_hubs" && match_field.starts_with("properties."))
        {
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
            "aws_sqs" => Some("aws_sqs"),
            "crowdstrike_fdr" => Some("crowdstrike_fdr"),
            "gcp_pubsub" => Some("gcp_pubsub"),
            "azure_event_hubs" => Some("azure_event_hubs"),
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
    fn configs_dir(&self) -> PathBuf {
        self.vector_config_dir.join("sources").join("configs")
    }

    /// NAN-4902: write the permanent `splunk_hec_route` passthrough (atomic).
    async fn write_hec_passthrough_route(&self) -> Result<(), SourceConfigServiceError> {
        let dir = self.configs_dir();
        tokio::task::spawn_blocking(move || {
            crate::parsers::vector_hec_route::write_passthrough_route(&dir)
        })
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))??;
        Ok(())
    }

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
    /// Delegates to [`crate::vector_naming::safe_name`].
    ///
    /// The transformation used to be inlined here and again in
    /// `parsers::vector_config`. `log_sources` health now needs it too, to
    /// attribute collector errors back to a source via `vector.component_id` —
    /// and a third copy that could drift from this one would silently break
    /// that attribution (NAN-2196). One definition, delegated to.
    fn safe_name(name: &str) -> String {
        crate::vector_naming::safe_name(name)
    }
}

mod activation;
pub use activation::{QUARANTINED_STATUS, QUARANTINE_UNCONFIRMED_STATUS, UNCONFIRMED_STATUS};

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "service/pull_start_tests.rs"]
mod pull_start_tests;

#[cfg(test)]
#[path = "service/create_routing_validation_tests.rs"]
mod create_routing_validation_tests;

#[cfg(test)]
#[path = "service/credential_retarget_tests.rs"]
mod credential_retarget_tests;

#[cfg(test)]
#[path = "service/crowdstrike_fdr_render_tests.rs"]
mod crowdstrike_fdr_render_tests;

/// NAN-5147: the hosts a stored credential is presented to, per driver, as
/// `(field, normalized value)`. Kafka: the broker list (order-, case- and
/// whitespace-insensitive). AWS S3/SQS: the custom endpoint and queue URL
/// origins (scheme, host, port). GCP Pub/Sub: a custom endpoint. Azure Event
/// Hubs: the namespace and checkpoint storage account. System-level drivers
/// (`http`, `vector`, `splunk_hec`, `otlp`) dial nothing. `None` for a driver
/// not listed here, which callers treat as a move (fail closed).
fn connection_destination(
    config_type: &str,
    conn: &serde_json::Value,
) -> Option<Vec<(&'static str, String)>> {
    fn origin(raw: &str) -> String {
        let raw = raw.trim();
        if raw.is_empty() {
            return String::new();
        }
        match url::Url::parse(raw) {
            Ok(u) => format!(
                "{}://{}:{}",
                u.scheme(),
                u.host_str().unwrap_or_default().to_ascii_lowercase(),
                u.port_or_known_default().map(|p| p.to_string()).unwrap_or_default()
            ),
            Err(_) => raw.to_ascii_lowercase(),
        }
    }
    let field = |key: &str| conn.get(key).and_then(|v| v.as_str()).unwrap_or("");
    let lower = |key: &str| field(key).trim().trim_end_matches('.').to_ascii_lowercase();
    use super::types::SourceConfigType as T;
    // Exhaustive over the enum so a new driver must decide its host fields.
    Some(match T::from_str(config_type)? {
        T::Kafka => {
            let mut servers: Vec<String> = field("bootstrap_servers")
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            servers.sort();
            servers.dedup();
            vec![("bootstrap_servers", servers.join(","))]
        }
        T::AwsS3 => vec![
            ("endpoint", origin(field("endpoint"))),
            ("sqs_queue_url", origin(field("sqs_queue_url"))),
        ],
        T::AwsSqs => vec![
            ("endpoint", origin(field("endpoint"))),
            ("queue_url", origin(field("queue_url"))),
        ],
        // The keys go to the queue (its origin names the region) and to S3 in
        // the same region; `region` alone can retarget S3, so it counts too.
        T::CrowdstrikeFdr => vec![
            ("endpoint", origin(field("endpoint"))),
            ("queue_url", origin(field("queue_url"))),
            ("region", lower("region")),
        ],
        T::GcpPubSub => vec![("endpoint", origin(field("endpoint")))],
        T::AzureEventHubs => vec![
            (
                "namespace",
                azure_event_hubs::azure_namespace_host(field("namespace"))
                    .unwrap_or_else(|| lower("namespace")),
            ),
            ("checkpoint_account", lower("checkpoint_account")),
        ],
        T::Http | T::Vector | T::SplunkHec | T::Otlp => Vec::new(),
    })
}

/// NAN-5147: whether an update sends a bound credential somewhere new: a
/// driver change, an unknown driver, or any changed host field (including
/// first setting one that was empty).
fn moves_credential_destination(
    old_type: &str,
    old_conn: &serde_json::Value,
    new_type: &str,
    new_conn: &serde_json::Value,
) -> bool {
    let canonical = |t: &str| {
        super::types::SourceConfigType::from_str(t).map_or_else(|| t.to_string(), |c| c.as_str().to_string())
    };
    if canonical(old_type) != canonical(new_type) {
        return true;
    }
    match (
        connection_destination(old_type, old_conn),
        connection_destination(new_type, new_conn),
    ) {
        (Some(old), Some(new)) => old != new,
        _ => true,
    }
}
