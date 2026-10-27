// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recorded coordinator activation, delivered through the existing credential
//! exchange. Absence performs no catalog I/O and constructs no new authority.
use super::{
    hosted::{HostedCatalogPolicy, HostedExportTarget},
    lifecycle::{
        metadata::{MetadataDeleteAuthority, MetadataDeleteRequest, MetadataGc},
        CatalogReadFence, RestLifecycleBackend, TenantCatalog,
    },
    schema::SchemaContract,
    ExportTable,
};
use crate::{
    iceberg::CatalogConfig,
    part_ingest::{
        platform_tls::{PlatformCatalogClient, PlatformTrust},
        r2_put::R2PartStore,
        s3_store::{S3Location, S3ObjectStore},
    },
    parts::{
        part_log::{load_log, ObjectStore},
        provenance::TenantKeySet,
    },
};
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};
pub(crate) mod platform_io;
mod recovery;
mod serving;
pub(crate) use recovery::attachment_error_class;

/// The attach step that was running when attach failed or timed out
/// (NAN-4543). Each tag is fixed and value-free: degraded-lane logs carry the
/// stage and an error class, never the error text, a key or a URL.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum AttachStage {
    #[default]
    ControlNew,
    VerifyMaintenance,
    SourceStore,
    PartLogLoad,
    PartSchema,
    CatalogConfig,
    ServingBackend,
    Uninstall,
    CustodyLock,
    FenceCloseAndDrain,
    InstallationMarker,
}
impl AttachStage {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ControlNew => "control_new",
            Self::VerifyMaintenance => "verify_maintenance",
            Self::SourceStore => "source_store",
            Self::PartLogLoad => "part_log_load",
            Self::PartSchema => "part_schema",
            Self::CatalogConfig => "catalog_config",
            Self::ServingBackend => "serving_backend",
            Self::Uninstall => "uninstall",
            Self::CustodyLock => "custody_lock",
            Self::FenceCloseAndDrain => "fence_close_and_drain",
            Self::InstallationMarker => "installation_marker",
        }
    }
}
/// Shared with the caller so a timed-out attach still names its stage.
#[derive(Default)]
pub(crate) struct AttachProgress(std::sync::Mutex<AttachStage>);
impl AttachProgress {
    fn enter(&self, stage: AttachStage) {
        *self.0.lock().expect("attach progress") = stage;
    }
    pub(crate) fn stage(&self) -> AttachStage {
        *self.0.lock().expect("attach progress")
    }
}
/// A non-success platform control response. Only the status is kept; the
/// body is never read into an error.
#[derive(Debug, thiserror::Error)]
#[error("catalog control refused: HTTP {0}")]
pub(crate) struct ControlRefused(pub u16);
/// Total attach budget (the cell keeps ingesting when it is exceeded).
const ATTACH_DEADLINE: Duration = Duration::from_secs(120);

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CatalogAuthority {
    PlatformV2,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogActivation {
    pub authority: CatalogAuthority,
    pub tenant_id: String,
    pub account_id: String,
    pub bucket: String,
    pub activation_id: uuid::Uuid,
    pub installation_sha256: String,
    pub control_token: String,
    pub expires_at: i64,
    pub metadata_permission: String,
    #[serde(default)]
    pub uninstall: bool,
    pub metadata: S3Location,
}
/// NAN-4614: R2 Data Catalog refuses (400 `InvalidLocation`) a table location
/// outside its managed `__r2_data_catalog/` area. The platform records the
/// agent table location and its metadata prefix here, one exact prefix per
/// tenant; exported parquet stays under `lake/parts/v1/...`.
pub(crate) fn platform_metadata_prefix(tenant: &str) -> String {
    format!("__r2_data_catalog/agent/v2/tenant={tenant}/agent/")
}
/// The pre-NAN-4614 prefix, kept by a recorded installation until its next
/// writer rotation (which always records `platform_metadata_prefix`).
pub(crate) fn legacy_platform_metadata_prefix(tenant: &str) -> String {
    format!("lake/agent-catalog/v2/tenant={tenant}/agent/")
}
/// Exactly this tenant's current or legacy platform metadata prefix.
pub(crate) fn is_platform_metadata_prefix(tenant: &str, prefix: &str) -> bool {
    prefix == platform_metadata_prefix(tenant) || prefix == legacy_platform_metadata_prefix(tenant)
}
impl CatalogActivation {
    pub fn validate(&self, tenant: &str) -> Result<()> {
        crate::parts::format::validate_tenant_uuid(tenant)?;
        ensure!(
            self.tenant_id == tenant
                && self.bucket == format!("nano-shared-r2-{tenant}")
                && self.metadata.bucket == self.bucket
                && is_platform_metadata_prefix(tenant, &self.metadata.prefix),
            "catalog activation belongs to another tenant"
        );
        ensure!(
            self.account_id.len() == 32
                && self.account_id.bytes().all(|b| b.is_ascii_hexdigit())
                && self.installation_sha256.len() == 64
                && self
                    .installation_sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit())
                && !self.activation_id.is_nil(),
            "catalog installation is unverified"
        );
        ensure!(
            self.metadata.endpoint
                == format!("https://{}.r2.cloudflarestorage.com", self.account_id)
                && self.metadata.session_token.is_some()
                && self.control_token.len() >= 32
                && self.metadata_permission == "object-read-only"
                && self.expires_at > chrono::Utc::now().timestamp_millis(),
            "catalog activation credential is invalid"
        );
        Ok(())
    }
}

pub struct ActivatedCatalog {
    pub catalog: Arc<TenantCatalog>,
    control: Arc<Control>,
    metadata: Arc<S3ObjectStore>,
    /// The export source and the attach-time log reader: the same split
    /// `lake_part` / `lake_part_log` routing ingest uses, refreshed with
    /// ingest's credentials (they expire at the exchange TTL).
    parts: Arc<R2PartStore>,
    record: CatalogActivation,
    activation_id: uuid::Uuid,
}
impl ActivatedCatalog {
    pub fn credential_expires_at_ms(&self) -> i64 {
        self.record.expires_at
    }
    pub async fn report_attachment(&self, health: Option<&Value>) -> Result<()> {
        let health = health.context("catalog GC custody is unattached")?;
        ensure!(
            health["custody_attached"] == true && health["gc_attached"] == true,
            "catalog GC custody is unattached"
        );
        self.control
            .call_with("writer_attached", health.clone())
            .await?;
        Ok(())
    }
    /// Refresh only the same installation. Adding/removing/replacing custody
    /// requires an ingest restart, so GC never sees half an installation.
    pub fn refresh(&self, next: Option<&CatalogActivation>) -> Result<()> {
        let next = next.context("catalog custody withdrawn; restart required")?;
        next.validate(&self.control.tenant)?;
        ensure!(
            !next.uninstall
                && next.activation_id == self.activation_id
                && next.installation_sha256 == self.record.installation_sha256
                && next.account_id == self.record.account_id
                && next.authority == self.record.authority
                && next.control_token == self.record.control_token
                && next.metadata.access_key_id == self.record.metadata.access_key_id
                && next.metadata.secret_access_key == self.record.metadata.secret_access_key
                && next.metadata.session_token == self.record.metadata.session_token,
            "catalog custody replaced; restart required"
        );
        self.metadata.replace(&next.metadata)?;
        *self
            .control
            .token
            .write()
            .expect("catalog control credential") = next.control_token.clone();
        Ok(())
    }
    /// Swap in the refreshed `lake_part` / `lake_part_log` pair ingest just
    /// accepted. The tenant bucket and endpoint must not change.
    pub(crate) fn refresh_parts(&self, part: &S3Location, log: &S3Location) -> Result<()> {
        ensure!(
            part.bucket == self.record.bucket
                && log.bucket == self.record.bucket
                && part.prefix.is_empty()
                && log.prefix.is_empty()
                && part.endpoint == self.record.metadata.endpoint
                && log.endpoint == self.record.metadata.endpoint,
            "catalog source belongs to another tenant"
        );
        self.parts.replace_split(part, log)
    }
}
struct Control {
    tenant: String,
    bucket: String,
    activation: uuid::Uuid,
    endpoint: String,
    tls: Arc<PlatformCatalogClient>,
    token: RwLock<String>,
    metadata_io: Arc<platform_io::PlatformMetadataFactory>,
}
impl Control {
    fn new(record: &CatalogActivation, tenant: &str, work: &Path, control_url: &str, cell_id: &str, trust: PlatformTrust) -> Result<Self> {
        record.validate(tenant)?;
        ensure!(!cell_id.is_empty() && cell_id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'), "invalid catalog cell identity");
        let endpoint = format!(
            "{}/v1/lake/cells/{cell_id}/agent-catalog",
            control_url.trim_end_matches('/')
        );
        let tls = Arc::new(PlatformCatalogClient::new(&endpoint, Duration::from_secs(130), trust)?);
        let metadata_io = Arc::new(platform_io::PlatformMetadataFactory::new(
            tenant,
            &record.bucket,
            &record.metadata.prefix,
            &endpoint,
            record.activation_id,
            record.control_token.clone(),
            tls.clone(),
            work,
        )?);
        Ok(Self {
            tenant: tenant.into(),
            bucket: record.bucket.clone(),
            activation: record.activation_id,
            tls,
            metadata_io,
            endpoint,
            token: RwLock::new(record.control_token.clone()),
        })
    }
    async fn call(&self, op: &str) -> Result<Value> {
        self.call_with(op, Value::Null).await
    }
    async fn call_with(&self, op: &str, details: Value) -> Result<Value> {
        let token = self
            .token
            .read()
            .expect("catalog control credential")
            .clone();
        let response=self.tls.client().post(&self.endpoint).bearer_auth(token)
            .json(&json!({"op":op,"tenant_id":self.tenant,"activation_id":self.activation,"details":details})).send().await?;
        if !response.status().is_success() {
            return Err(ControlRefused(response.status().as_u16()).into());
        }
        let body: Value = response.json().await?;
        ensure!(
            body["tenant_id"] == self.tenant
                && body["activation_id"] == self.activation.to_string()
                && body["verified"] == true,
            "catalog control binding differs"
        );
        Ok(body)
    }
}
#[async_trait::async_trait]
impl HostedCatalogPolicy for Control {
    async fn verify_manual_maintenance(&self, _table: &iceberg::TableIdent) -> Result<()> {
        self.metadata_io.replay().await?;
        self.call("verify_maintenance").await?;
        Ok(())
    }
}
#[async_trait::async_trait]
impl CatalogReadFence for Control {
    fn tenant_id(&self) -> &str {
        &self.tenant
    }
    fn bucket(&self) -> &str {
        &self.bucket
    }
    async fn close_and_drain(&self) -> Result<()> {
        self.call("close_and_drain").await?;
        Ok(())
    }
    async fn invalidate_results(&self) -> Result<()> {
        self.call("invalidate_results").await?;
        Ok(())
    }
    async fn reopen(&self) -> Result<()> {
        self.call("writer_reopen").await?;
        Ok(())
    }
}
struct MetadataAuthority {
    tenant: String,
    prefix: String,
    store_root: String,
    store: Arc<S3ObjectStore>,
    control: Arc<Control>,
    table: String,
}
#[async_trait::async_trait]
impl MetadataDeleteAuthority for MetadataAuthority {
    fn tenant_id(&self) -> &str {
        &self.tenant
    }
    fn metadata_prefix(&self) -> &str {
        &self.prefix
    }
    async fn inventory(&self) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut cursor = None;
        loop {
            let relative = self
                .prefix
                .strip_prefix(&self.store_root)
                .context("metadata scope differs")?;
            let page = self
                .store
                .list_page_after(relative, cursor.as_deref(), 1000)
                .await?;
            if page.is_empty() {
                break;
            }
            for file in &page {
                let leaf = file
                    .key
                    .strip_prefix(relative)
                    .context("foreign metadata object")?;
                ensure!(
                    !leaf.contains('/') && (leaf.ends_with(".avro") || leaf.ends_with(".json")),
                    "foreign metadata object"
                );
                keys.push(format!("{}{}", self.store_root, file.key));
            }
            ensure!(
                keys.len() <= 1_000_000,
                "catalog metadata inventory exceeds bound"
            );
            let last = page.last().unwrap().key.clone();
            ensure!(
                cursor.as_ref().is_none_or(|old| old < &last),
                "catalog metadata cursor did not advance"
            );
            cursor = Some(last);
        }
        Ok(keys)
    }
    async fn retire(&self, request: &MetadataDeleteRequest) -> Result<MetadataDeleteRequest> {
        ensure!(
            request.tenant_id == self.tenant
                && request.metadata_prefix == self.prefix
                && request.bucket == format!("nano-shared-r2-{}", self.tenant),
            "foreign metadata retirement"
        );
        let leaf = request
            .key
            .strip_prefix(&self.prefix)
            .context("foreign metadata key")?;
        ensure!(
            !leaf.contains('/')
                && (leaf.ends_with(".avro") || leaf.ends_with(".json"))
                && request.key != request.current_metadata,
            "invalid metadata retirement"
        );
        let key = request
            .key
            .strip_prefix(&self.store_root)
            .context("foreign metadata key")?;
        let response = self
            .control
            .call_with(
                "retire_metadata",
                json!({"table":self.table,"file":leaf,
            "current_metadata":request.current_metadata,"table_uuid":request.table_uuid}),
            )
            .await?;
        let receipt: MetadataDeleteRequest = serde_json::from_value(response["result"].clone())?;
        ensure!(receipt == *request, "metadata retirement receipt differs");
        ensure!(
            self.store.object_size(key).await?.is_none(),
            "metadata retirement not acknowledged"
        );
        Ok(request.clone())
    }
}

#[derive(Default)]
pub(crate) struct IngestCatalog {
    runtime: Option<Arc<ActivatedCatalog>>,
    activation_id: Option<uuid::Uuid>,
    recovery: Option<Arc<recovery::CatalogRecovery>>,
    degraded: bool,
    /// (stage, class) of a failed startup attach; value-free.
    #[cfg_attr(not(test), allow(dead_code))]
    failure: Option<(&'static str, &'static str)>,
}
impl IngestCatalog {
    pub(crate) fn runtime(&self) -> Option<&Arc<ActivatedCatalog>> { self.runtime.as_ref() }
    pub(crate) fn mark_degraded(&mut self) { self.degraded = true; }
    /// `writer_attached` acknowledged: recovery restarts of this
    /// installation no longer count against its back-off.
    pub(crate) fn mark_attached(&self) {
        if let (Some(recovery), false) = (&self.recovery, self.degraded) { recovery.clear(); }
    }
    pub(crate) fn recovery(&self) -> Option<Arc<recovery::CatalogRecovery>> {
        self.recovery.as_ref().filter(|_| self.degraded).cloned()
    }
    pub(crate) fn refresh(&self, next: Option<&CatalogActivation>) -> Result<()> {
        if let Some(runtime) = &self.runtime { runtime.refresh(next)?; }
        // A failed attachment is stable degraded state, not a reason to
        // respawn every credential refresh. A changed installation restarts
        // once to rebuild custody with the new authority.
        ensure!(self.activation_id == next.map(|r| r.activation_id), "catalog custody changed; restart to attach");
        if let Some(recovery) = &self.recovery { recovery.refresh(next)?; }
        Ok(())
    }
    /// Keep the attached export source on ingest's current part credentials.
    pub(crate) fn refresh_parts(&self, parts: Option<(&S3Location, &S3Location)>) -> Result<()> {
        let Some(runtime) = &self.runtime else { return Ok(()) };
        let (part, log) = parts.context("catalog part credentials withdrawn; restart required")?;
        runtime.refresh_parts(part, log)
    }
}

/// The cell startup path. A valid installed lane may fail remote attachment;
/// ingestion continues with erasure and physical GC held. A bounded background
/// probe requests a fresh startup once the platform verifies this installation.
/// Foreign credentials are still rejected before any IO.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn attach_for_ingest(
    cfg: &mut crate::part_ingest::IngestConfig,
    record: Option<&CatalogActivation>,
    work: &Path,
    source: &S3Location,
    log: &S3Location,
    keys: TenantKeySet,
    control_url: &str,
    cell_id: &str,
) -> Result<IngestCatalog> {
    attach_for_ingest_with(cfg, record, work, source, log, keys, control_url, cell_id, PlatformTrust::default()).await
}

#[allow(clippy::too_many_arguments)]
async fn attach_for_ingest_with(
    cfg: &mut crate::part_ingest::IngestConfig,
    record: Option<&CatalogActivation>,
    work: &Path,
    source: &S3Location,
    log: &S3Location,
    keys: TenantKeySet,
    control_url: &str,
    cell_id: &str,
    trust: PlatformTrust,
) -> Result<IngestCatalog> {
    let Some(record) = record else { return Ok(IngestCatalog::default()) };
    record.validate(&cfg.tenant_id)?;
    ensure!(source.bucket == record.bucket && log.bucket == record.bucket
        && source.prefix.is_empty() && log.prefix.is_empty()
        && source.endpoint == record.metadata.endpoint && log.endpoint == record.metadata.endpoint,
        "catalog source belongs to another tenant");
    let recovery = Some(Arc::new(recovery::CatalogRecovery::new(record, &cfg.tenant_id, work, control_url, cell_id, trust.clone())?));
    let progress = AttachProgress::default();
    let attached = tokio::time::timeout(ATTACH_DEADLINE,
        attach_inner(record, &cfg.tenant_id, work, source, log, keys, control_url, cell_id, trust, &progress)).await;
    match attached {
        Ok(Ok(runtime)) => {
            // The back-off is cleared only once the platform acknowledged
            // the attachment ([`IngestCatalog::mark_attached`]); a failing
            // `writer_attached` must not reset it every process life.
            cfg.catalog = runtime.as_ref().map(|r| r.catalog.clone());
            Ok(IngestCatalog { runtime, activation_id: Some(record.activation_id), recovery, degraded: false, failure: None })
        }
        outcome => {
            let error = match outcome { Ok(Err(error)) => error, Err(error) => error.into(), Ok(Ok(_)) => unreachable!() };
            let (stage, class) = (progress.stage().as_str(), attachment_error_class(&error));
            cfg.catalog_attachment_failure = Some("catalog_attach_failed");
            tracing::error!(tenant = %cfg.tenant_id, reason = "catalog_attach_failed", stage, error_class = class, "agent lane degraded; ingest continues, erasure and GC held");
            Ok(IngestCatalog { runtime: None, activation_id: Some(record.activation_id), recovery, degraded: true, failure: Some((stage, class)) })
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn attach(
    record: Option<&CatalogActivation>,
    tenant: &str,
    work: &Path,
    source: &S3Location,
    log: &S3Location,
    keys: TenantKeySet,
    control_url: &str,
    cell_id: &str,
) -> Result<Option<Arc<ActivatedCatalog>>> {
    let Some(record) = record else {
        return Ok(None);
    };
    attach_inner(record, tenant, work, source, log, keys, control_url, cell_id, PlatformTrust::default(), &AttachProgress::default()).await
}

#[allow(clippy::too_many_arguments)]
async fn attach_inner(
    record: &CatalogActivation,
    tenant: &str,
    work: &Path,
    source: &S3Location,
    log: &S3Location,
    keys: TenantKeySet,
    control_url: &str,
    cell_id: &str,
    trust: PlatformTrust,
    progress: &AttachProgress,
) -> Result<Option<Arc<ActivatedCatalog>>> {
    progress.enter(AttachStage::ControlNew);
    record.validate(tenant)?;
    ensure!(
        source.bucket == record.bucket
            && source.prefix.is_empty()
            && source.endpoint == record.metadata.endpoint,
        "catalog source belongs to another tenant"
    );
    ensure!(
        log.bucket == record.bucket
            && log.prefix.is_empty()
            && log.endpoint == record.metadata.endpoint,
        "catalog log belongs to another tenant"
    );
    // Legacy grants must be revoked by platform preflight. Do not retain an
    // old projected provider credential when starting the platform-only path.
    let stale_token = work.join("catalog-token");
    match std::fs::symlink_metadata(&stale_token) {
        Ok(_) => {
            std::fs::remove_file(&stale_token)?;
            std::fs::File::open(work)?.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let control = Arc::new(Control::new(record, tenant, work, control_url, cell_id, trust)?);
    progress.enter(AttachStage::VerifyMaintenance);
    control
        .verify_manual_maintenance(&iceberg::TableIdent::from_strs(["agent", "events_v1"])?)
        .await?;
    // NAN-4543: the platform scopes `lake_part` to `parts/` +
    // `log/checkpoints/` (+ finding receipts) and `lake_part_log` to exactly
    // `log/entries/`. A store on either credential alone is a 403 for half of
    // `load_log` (it LISTs checkpoints first). Read through the same per-key
    // router ingest uses; the export source shares it so both stay on the
    // credentials ingest refreshes.
    progress.enter(AttachStage::SourceStore);
    let parts = Arc::new(R2PartStore::new_split(source, log, tenant, &work.join("part-reads"))?);
    progress.enter(AttachStage::PartLogLoad);
    let live = load_log(parts.as_ref(), tenant).await?;
    progress.enter(AttachStage::PartSchema);
    let arrow = live
        .schema()
        .context("catalog activation requires a committed part schema")?
        .to_arrow()?;
    let schema = iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(&arrow)?;
    progress.enter(AttachStage::CatalogConfig);
    let metadata = Arc::new(S3ObjectStore::new(&record.metadata)?);
    // Catalog calls terminate at the platform control route. Only the scoped
    // control capability is held in memory; no CF bearer is projected to disk,
    // FileIO, environment or a child process.
    std::fs::create_dir_all(work)?;
    let config = CatalogConfig {
        uri: format!("{}/{}/{}", control.endpoint, tenant, record.activation_id),
        warehouse: format!("{}_{}", record.account_id, record.bucket),
        credential: None,
        token_file: None,
        oauth_scope: None,
        oauth_audience: None,
        oauth_server_uri: None,
        realm: None,
        allow_anonymous: false,
        s3_endpoint: record.metadata.endpoint.clone(),
        s3_region: record.metadata.region.clone(),
        s3_access_key: record.metadata.access_key_id.clone(),
        s3_secret_key: record.metadata.secret_access_key.clone(),
        s3_session_token: record.metadata.session_token.clone(),
        s3_path_style_access: true,
        s3_default_credentials: false,
        vended_credentials: false,
    };
    progress.enter(AttachStage::ServingBackend);
    // NAN-4614: verified data files survive a cut-off attempt and are not
    // read again for the fresh serving epoch. Inside `work`: uninstall
    // removes them with the planner checkpoints.
    let target = Arc::new(
        HostedExportTarget::new(tenant.into(), parts.clone(), keys, record.bucket.clone())?
            .with_verified_files(work.join("verified-files")),
    );
    let factory = Arc::new(BackendFactory {
        record: record.clone(),
        control: control.clone(),
        metadata: metadata.clone(),
        config,
        target,
        schema,
    });
    let backend = Arc::new(serving::FreshServingBackend::new(
        factory,
        work.join("serving"),
    )?);
    if record.uninstall {
        progress.enter(AttachStage::Uninstall);
        backend.uninstall().await?;
        // Clear planner checkpoints before acknowledgment, so a later install
        // cannot mistake dropped catalog contents for an already exported lake.
        std::fs::remove_dir_all(work)?;
        control.call("writer_uninstalled").await?;
        return Ok(None);
    }
    progress.enter(AttachStage::CustodyLock);
    let catalog = Arc::new(TenantCatalog::new(tenant, work.join("custody"), backend)?);
    let installation = work.join("installation-id");
    if std::fs::read_to_string(&installation).ok().as_deref()
        != Some(&record.activation_id.to_string())
    {
        // Rotation must publish a new serving epoch even when the committed
        // part set and the writer's durable checkpoint did not change.
        progress.enter(AttachStage::FenceCloseAndDrain);
        catalog.fence_installation().await?;
        progress.enter(AttachStage::InstallationMarker);
        write_private(&installation, record.activation_id.to_string().as_bytes())?;
    }
    Ok(Some(Arc::new(ActivatedCatalog {
        catalog,
        control,
        metadata,
        parts,
        record: record.clone(),
        activation_id: record.activation_id,
    })))
}
struct BackendFactory {
    record: CatalogActivation,
    control: Arc<Control>,
    metadata: Arc<S3ObjectStore>,
    config: CatalogConfig,
    target: Arc<HostedExportTarget>,
    schema: iceberg::spec::Schema,
}
impl BackendFactory {
    fn build(&self, dataset: &str) -> Result<Arc<RestLifecycleBackend>> {
        ensure!(
            dataset == "events"
                || (dataset.starts_with("events_")
                    && dataset.len() == 39
                    && dataset[7..].bytes().all(|b| b.is_ascii_hexdigit())),
            "invalid serving epoch"
        );
        let tenant = &self.record.tenant_id;
        let root = format!(
            "s3://{}/{}{dataset}_v1",
            self.record.bucket, self.record.metadata.prefix
        );
        let authority = Arc::new(MetadataAuthority {
            tenant: tenant.clone(),
            prefix: format!("{root}/metadata/"),
            store_root: format!(
                "s3://{}/{}",
                self.record.bucket, self.record.metadata.prefix
            ),
            store: self.metadata.clone(),
            control: self.control.clone(),
            table: format!("{dataset}_v1"),
        });
        let gc = Arc::new(MetadataGc::new(tenant, &root, authority)?);
        let table = ExportTable {
            tenant_id: tenant.clone(),
            namespace: "agent".into(),
            dataset: dataset.into(),
            location: root,
            data_prefix: self.target.data_prefix(),
            contract: SchemaContract {
                version: 1,
                ocsf_version: crate::iceberg::OCSF_VERSION.into(),
                schema: self.schema.clone(),
            },
            max_files: 100000,
        };
        Ok(Arc::new(
            RestLifecycleBackend::new(
                self.config.clone(),
                table,
                self.target.clone(),
                self.control.clone(),
                self.control.clone(),
                gc,
            )?
            .with_platform_auth(
                self.control.tls.clone(),
                self.record.control_token.clone(),
                self.control.metadata_io.clone(),
            ),
        ))
    }
}
#[async_trait::async_trait]
impl serving::ServingFactory for BackendFactory {
    fn tenant_id(&self) -> &str {
        &self.record.tenant_id
    }
    fn bucket(&self) -> &str {
        &self.record.bucket
    }
    fn build(&self, dataset: &str) -> Result<Arc<dyn serving::ServingTable>> {
        Ok(BackendFactory::build(self, dataset)?)
    }
    fn retain_verified(&self, live: &[crate::parts::part_log::PartRef]) -> Result<()> {
        self.target.retain_verified(live)
    }
    async fn close(&self) -> Result<()> {
        self.control.close_and_drain().await
    }
    async fn publish(&self, details: Value) -> Result<()> {
        self.control.call_with("publish_serving", details).await?;
        Ok(())
    }
    async fn retire_registry(&self) -> Result<()> {
        self.control.call("uninstall_serving").await?;
        Ok(())
    }
    async fn list_epochs(&self) -> Result<std::collections::BTreeSet<String>> {
        BackendFactory::build(self, "events")?.list_serving_epochs().await
    }
    async fn invalidate(&self) -> Result<()> {
        self.control.call("invalidate_results").await?;
        Ok(())
    }
    async fn reopen(&self) -> Result<()> {
        self.control.reopen().await
    }
}
fn write_private(path: &PathBuf, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("catalog token has no parent")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const TENANT: &str = "0199c110-0011-7000-8000-000000000001";
    pub(super) fn record() -> CatalogActivation {
        CatalogActivation {
            authority: CatalogAuthority::PlatformV2,
            tenant_id: TENANT.into(),
            account_id: "a".repeat(32),
            bucket: format!("nano-shared-r2-{TENANT}"),
            activation_id: uuid::Uuid::new_v4(),
            installation_sha256: "b".repeat(64),
            control_token: "private-tenant-control-fixture-token".into(),
            expires_at: chrono::Utc::now().timestamp_millis() + 600000,
            metadata_permission: "object-read-only".into(),
            uninstall: false,
            metadata: S3Location {
                endpoint: format!("https://{}.r2.cloudflarestorage.com", "a".repeat(32)),
                region: "auto".into(),
                bucket: format!("nano-shared-r2-{TENANT}"),
                prefix: format!("__r2_data_catalog/agent/v2/tenant={TENANT}/agent/"),
                access_key_id: "test".into(),
                secret_access_key: "test".into(),
                session_token: Some("test".into()),
            },
        }
    }
    /// NAN-4614: the recorded prefix is exactly this tenant's R2-managed one
    /// or its legacy one; nothing wider, narrower or foreign.
    #[test]
    fn platform_metadata_prefix_is_exactly_this_tenants() {
        const OTHER: &str = "0199c110-0011-7000-8000-000000000002";
        let with = |prefix: String| {
            let mut r = record();
            r.metadata.prefix = prefix;
            r
        };
        with(format!("__r2_data_catalog/agent/v2/tenant={TENANT}/agent/"))
            .validate(TENANT)
            .unwrap();
        with(format!("lake/agent-catalog/v2/tenant={TENANT}/agent/"))
            .validate(TENANT)
            .unwrap();
        for refused in [
            format!("__r2_data_catalog/agent/v2/tenant={OTHER}/agent/"),
            format!("lake/agent-catalog/v2/tenant={OTHER}/agent/"),
            "__r2_data_catalog/".to_string(),
            "__r2_data_catalog/agent/v2/".to_string(),
            format!("__r2_data_catalog/agent/v2/tenant={TENANT}/"),
            format!("__r2_data_catalog/agent/v2/tenant={TENANT}/agent"),
            format!("__r2_data_catalog/agent/v2/tenant={TENANT}/agent/x/"),
            format!("__r2_data_catalog/{TENANT}/agent/"),
            format!("lake/parts/v1/tenant={TENANT}/parts/"),
        ] {
            assert!(with(refused.clone()).validate(TENANT).is_err(), "{refused}");
            assert!(!is_platform_metadata_prefix(TENANT, &refused), "{refused}");
        }
    }
    #[test]
    fn cell_feature_lean_agent_catalog_custody_v1_is_backed() {
        record().validate(TENANT).unwrap();
        assert!(record()
            .validate("0199c110-0011-7000-8000-000000000002")
            .is_err());
        let mut r = record();
        r.metadata.prefix.clear();
        assert!(r.validate(TENANT).is_err());
        let mut r = record();
        r.metadata.bucket = "foreign".into();
        assert!(r.validate(TENANT).is_err());
        let mut r = record();
        r.expires_at = 0;
        assert!(r.validate(TENANT).is_err());
        let mut r = record();
        r.installation_sha256.clear();
        assert!(r.validate(TENANT).is_err());
        let mut r = record();
        r.metadata.session_token = None;
        assert!(r.validate(TENANT).is_err());
    }
    #[test]
    fn cell_feature_lean_agent_catalog_platform_v2_is_backed() {
        let r = record();
        let mut wire = json!({"authority":"platform_v2","tenant_id":r.tenant_id,"account_id":r.account_id,
            "bucket":r.bucket,"activation_id":r.activation_id,"installation_sha256":r.installation_sha256,
            "control_token":r.control_token,"expires_at":r.expires_at,"metadata_permission":"object-read-only","metadata":{
                "endpoint":r.metadata.endpoint,"region":r.metadata.region,"bucket":r.metadata.bucket,"prefix":r.metadata.prefix,
                "access_key_id":r.metadata.access_key_id,"secret_access_key":r.metadata.secret_access_key,"session_token":r.metadata.session_token}});
        let parsed: CatalogActivation = serde_json::from_value(wire.clone()).unwrap();
        parsed.validate(TENANT).unwrap();
        wire["catalog_token"] = json!("legacy-account-wide-write-grant");
        assert!(serde_json::from_value::<CatalogActivation>(wire.clone()).is_err());
        wire.as_object_mut().unwrap().remove("catalog_token");
        wire["authority"] = json!("tenant_v1");
        assert!(serde_json::from_value::<CatalogActivation>(wire).is_err());
    }
    #[tokio::test]
    async fn activated_constructor_refuses_foreign_source_account_before_io() {
        let record = record();
        let directory = tempfile::tempdir().unwrap();
        let work = directory.path().join("must-not-exist");
        let mut source = record.metadata.clone();
        source.prefix.clear();
        let log = source.clone();
        source.endpoint = format!("https://{}.r2.cloudflarestorage.com", "c".repeat(32));
        assert!(attach(
            Some(&record),
            TENANT,
            &work,
            &source,
            &log,
            TenantKeySet::default(),
            "invalid",
            "invalid"
        )
        .await
        .is_err());
        assert!(!work.exists());
    }
    #[tokio::test]
    async fn absent_installation_is_the_unchanged_constructor_path_without_io() {
        let directory = tempfile::tempdir().unwrap();
        let work = directory.path().join("must-not-exist");
        let location = record().metadata;
        // Deliberately unusable network settings and tenant: None must return
        // before validation, construction, file creation, or any remote call.
        assert!(attach(
            None,
            "unactivated",
            &work,
            &location,
            &location,
            TenantKeySet::default(),
            "invalid",
            "invalid"
        )
        .await
        .unwrap()
        .is_none());
        assert!(!work.exists());
        let old =
            serde_json::to_value(crate::part_ingest::ingest::IngestHealth::default()).unwrap();
        assert!(old.get("agent_catalog").is_none());
    }
}

#[cfg(test)]
#[path = "activation/trust_tests.rs"]
mod trust_tests;
