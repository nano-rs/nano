// SPDX-License-Identifier: AGPL-3.0-or-later
//! Explicit hosted coordinator deployment config. No ambient token or Redis fallback.
//!
//! Two deployment kinds are accepted:
//! * `isolated_test`: the original probe/test coordinator; free endpoint, no region.
//! * `hosted_regional` (NAN-2667/NAN-2668): the regional coordinator Worker
//!   the platform deploys (`nano-jobs-<cc>` on `jobs-<cc>.nano.rs`). It must name a
//!   registered lake `application_region`, and its endpoint must be exactly that
//!   region's coordinator endpoint from the region contract.
use super::{
    job_coordinator_client::{
        HostedAssignment, HostedCoordinatorClient, HostedCoordinatorPolicy, HostedCoordinatorRole,
    },
    job_coordinator_transport::HostedCoordinatorTransport,
    job_signing::DurableJobSigningKey,
    jobs::DurableJobStoreError,
    tenant::SearchTenantScope,
};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedCoordinatorDeployment {
    schema_version: u32,
    deployment_kind: HostedCoordinatorDeploymentKind,
    /// Required for `hosted_regional`, forbidden for `isolated_test`.
    #[serde(default)]
    application_region: Option<String>,
    /// NAN-3891: a spec region's rendered placement (from the region spec),
    /// beside `application_region`; absent for legacy/table regions.
    #[serde(default)]
    region_placement: Option<serde_json::Value>,
    tenant_id: Uuid,
    worker_assignment_revision: u64,
    endpoint: String,
    epoch: String,
    policy: HostedCoordinatorPolicy,
    authority: DeploymentAuthority,
    token_file: PathBuf,
}
/// Which hosted coordinator a deployment config selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostedCoordinatorDeploymentKind {
    /// Isolated probe/test coordinator; the endpoint is operator-supplied.
    IsolatedTest,
    /// The region's platform coordinator (`nano-jobs-<cc>`, the platform#1405).
    HostedRegional,
}

/// How a hosted producer config relates to the current worker registry
/// (NAN-2903, tenant offboarding). See `HostedCoordinatorDeployment::routing_under`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedProducerRouting {
    /// The tenant is routed at this config's worker revision: attest it.
    Routed,
    /// The registry no longer names the tenant: skip it and do not attest it.
    Offboarded,
}

/// Most hosted producer configs one process loads (NAN-3531: raised from 32
/// when configs became a live directory; a scan over it keeps the previous set).
pub const MAX_HOSTED_PRODUCER_CONFIGS: usize = 1024;

/// Parse `NANO_SHARED_HOSTED_JOB_CONFIG_FILES` (a JSON array of gen1 tenants'
/// hosted producer config paths) for a startup that attests them.
///
/// An empty list is admitted only when the registry has at least one
/// lean-lake cell route: cell tenants use a tenant-pinned in-memory store and
/// need no gen1 producer, so a cluster whose gen1 tenants are all torn down
/// still boots. An empty list with no cell routes stays a misconfiguration.
/// A non-empty list is returned for the caller's strict per-file validation.
pub fn hosted_producer_config_paths(
    raw: &str,
    registry: &super::SharedLakeWorkerRegistry,
) -> Result<Vec<PathBuf>, DurableJobStoreError> {
    let paths: Vec<PathBuf> = serde_json::from_str(raw).map_err(|_| invalid())?;
    if paths.len() > MAX_HOSTED_PRODUCER_CONFIGS {
        return Err(invalid());
    }
    if paths.is_empty() {
        let cell_routes = registry.cell_route_count();
        if cell_routes == 0 {
            return Err(invalid());
        }
        tracing::info!(
            cell_routes,
            "no gen1 hosted producer configs; booting for lean-lake cell tenants only"
        );
    }
    Ok(paths)
}

/// One producer config that passed per-file validation and should be
/// attested (NAN-3531).
pub struct HostedProducerCandidate {
    pub path: PathBuf,
    pub tenant: Uuid,
    pub config: HostedCoordinatorDeployment,
    pub scope: SearchTenantScope,
    pub assignment: HostedAssignment,
    /// Identity of the config bytes and its bearer (NAN-3531 N2a): a live
    /// reload re-attests a tenant only when this changes.
    pub fingerprint: ProducerFingerprint,
}

/// SHA-256 over a producer config's bytes and its bearer token's bytes (or a
/// fixed marker when the token is unreadable). Never the token itself.
pub type ProducerFingerprint = [u8; 32];

/// The outcome of [`select_hosted_producer_configs`]: configs to attest, and
/// tenants whose config was readable but is refused (revision mismatch or an
/// invalid expected context), with that config's fingerprint.
#[derive(Default)]
pub struct HostedProducerSelection {
    pub candidates: Vec<HostedProducerCandidate>,
    pub failed: std::collections::BTreeMap<Uuid, ProducerFingerprint>,
}

/// Whether `select_hosted_producer_configs` keeps producers of tenants that
/// currently hold a lean-lake cell route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellRoutedProducers {
    /// Keep them (search: a cell tenant's hosted client is optional job control).
    Attest,
    /// Skip them unattested (api/jobs factory: `resolve_exact` serves a cell
    /// tenant from a tenant-pinned in-memory store and never uses its producer).
    Skip,
}

/// Count one hosted producer config skipped at startup; `reason` is a fixed label.
pub fn record_hosted_producer_skip(reason: &'static str) {
    metrics::counter!("nanosiem_hosted_producer_config_skipped_total", "reason" => reason)
        .increment(1);
}

/// Per-tenant validation of the producer configs named by
/// [`hosted_producer_config_paths`] (NAN-3531).
///
/// A file that fails to read or parse, a routed tenant whose worker revision
/// disagrees with the registry, or an invalid expected context is logged and
/// SKIPPED: that tenant gets no hosted producer (gen1 search then fails closed
/// with "no configured hosted coordinator") while every other tenant still
/// boots. Offboarded tenants are skipped as before (NAN-2903).
///
/// A tenant named by two files is still a process-level error: it is a
/// deployment bug and there is no safe way to pick which file to trust.
/// Duplicates are detected across every parsed file, before any routing skip.
pub fn select_hosted_producer_configs(
    paths: Vec<PathBuf>,
    registry: &super::SharedLakeWorkerRegistry,
    cell_routed: CellRoutedProducers,
) -> Result<HostedProducerSelection, DurableJobStoreError> {
    let mut seen = std::collections::HashSet::new();
    let mut parsed = Vec::with_capacity(paths.len());
    for path in paths {
        match HostedCoordinatorDeployment::from_file_fingerprinted(&path) {
            Ok((config, fingerprint)) => {
                if !seen.insert(config.tenant_id) {
                    tracing::error!(tenant = %config.tenant_id, path = %path.display(),
                        "two hosted producer configs name the same tenant; refusing the producer set");
                    return Err(invalid());
                }
                parsed.push((path, config, fingerprint));
            }
            Err(error) => {
                tracing::error!(path = %path.display(), error = %error,
                    "skipping unreadable or invalid hosted producer config; its tenant gets no hosted producer");
                record_hosted_producer_skip("invalid_file");
            }
        }
    }
    let mut selection = HostedProducerSelection::default();
    for (path, config, fingerprint) in parsed {
        let tenant = config.tenant_id;
        match config.routing_under(registry) {
            Ok(HostedProducerRouting::Offboarded) => {
                tracing::warn!(tenant = %tenant, path = %path.display(),
                    "skipping hosted producer config for a tenant the worker registry no longer routes (offboarded)");
                record_hosted_producer_skip("offboarded");
                continue;
            }
            Ok(HostedProducerRouting::Routed) => {}
            Err(error) => {
                tracing::error!(tenant = %tenant, path = %path.display(), error = %error,
                    "skipping hosted producer config whose worker revision disagrees with the registry; tenant gets no hosted producer");
                record_hosted_producer_skip("revision_mismatch");
                selection.failed.insert(tenant, fingerprint);
                continue;
            }
        }
        if cell_routed == CellRoutedProducers::Skip && registry.cell_route(tenant).is_some() {
            tracing::info!(tenant = %tenant, path = %path.display(),
                "skipping hosted producer config for a lean-lake cell-routed tenant; it is served without a hosted producer");
            record_hosted_producer_skip("cell_routed");
            continue;
        }
        match config.expected_context() {
            Ok((scope, assignment)) => selection.candidates.push(HostedProducerCandidate {
                path,
                tenant,
                config,
                scope,
                assignment,
                fingerprint,
            }),
            Err(error) => {
                tracing::error!(tenant = %tenant, path = %path.display(), error = %error,
                    "skipping hosted producer config with an invalid expected context; tenant gets no hosted producer");
                record_hosted_producer_skip("invalid_context");
                selection.failed.insert(tenant, fingerprint);
            }
        }
    }
    Ok(selection)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedGenerationInventory {
    pub generation_ids: std::collections::BTreeSet<String>,
    pub inventory_revision: u64,
    pub observed_at: i64,
    pub tenant: String,
    pub epoch: String,
    pub cohort: String,
    pub role: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentAuthority {
    entitlement_revision: i64,
    retention_revision: i64,
    retention_days: u16,
    irreversible_event_time_floor_micros: i64,
}
impl std::fmt::Debug for HostedCoordinatorDeployment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostedCoordinatorDeployment")
            .finish_non_exhaustive()
    }
}
/// The region contract's coordinator endpoint. The region table is
/// enterprise-only, so an open-core build refuses every regional config.
#[cfg(feature = "enterprise")]
fn regional_coordinator_endpoint(
    application_region: &str,
    placement: Option<&serde_json::Value>,
) -> Option<String> {
    crate::enterprise_shared_region::resolve_lake_region(application_region, placement)
        .ok()
        .map(|region| region.hosted_coordinator_endpoint())
}
#[cfg(not(feature = "enterprise"))]
fn regional_coordinator_endpoint(_: &str, _: Option<&serde_json::Value>) -> Option<String> {
    None
}
fn invalid() -> DurableJobStoreError {
    DurableJobStoreError::Invalid("hosted coordinator deployment configuration rejected".into())
}
impl HostedCoordinatorDeployment {
    /// Maintenance uses the same private principal without loading a signing key.
    pub async fn generation_inventory(
        &self,
        retire: Option<(&str, u64)>,
    ) -> Result<HostedGenerationInventory, DurableJobStoreError> {
        let token = zeroize::Zeroizing::new(private_file(&self.token_file, 256)?);
        let token = std::str::from_utf8(&token)
            .map_err(|_| invalid())?
            .trim_end_matches('\n');
        let transport =
            HostedCoordinatorTransport::new(&self.endpoint, token).map_err(|_| invalid())?;
        let command = match retire {
            None => serde_json::json!({"op":"generation-pins:list","epoch":self.epoch}),
            Some((id, revision)) => {
                serde_json::json!({"op":"generation-pins:retire","epoch":self.epoch,
                "generation_id":id,"inventory_revision":revision})
            }
        };
        let value = transport.execute(&command).await.map_err(|_| invalid())?;
        let inventory: HostedGenerationInventory =
            serde_json::from_value(value).map_err(|_| invalid())?;
        let cohort = format!(
            "reader_{}_r{}",
            self.tenant_id.simple(),
            self.worker_assignment_revision
        );
        if inventory.tenant != self.tenant_id.to_string()
            || inventory.epoch != self.epoch
            || inventory.cohort != cohort
            || inventory.role != "runner"
            || inventory.inventory_revision == 0
            || inventory.inventory_revision > 9_007_199_254_740_991
            || retire.is_some_and(|(_, revision)| inventory.inventory_revision <= revision)
            || inventory.generation_ids.len() > 1000
            || inventory.generation_ids.iter().any(|id| {
                id.is_empty()
                    || id.len() > 128
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            })
        {
            return Err(invalid());
        }
        Ok(inventory)
    }

    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }
    pub fn deployment_kind(&self) -> HostedCoordinatorDeploymentKind {
        self.deployment_kind
    }
    /// The lake application region of a `hosted_regional` coordinator.
    pub fn application_region(&self) -> Option<&str> {
        self.application_region.as_deref()
    }
    pub fn max_execution_failures(&self) -> u32 {
        self.policy.max_execution_failures
    }
    /// Deployer expectation only. Search compares this with request-resolved
    /// PostgreSQL authority; runners compare it with PostgreSQL at boot.
    pub fn expected_context(
        &self,
    ) -> Result<(SearchTenantScope, HostedAssignment), DurableJobStoreError> {
        #[cfg(feature = "enterprise")]
        let scope = SearchTenantScope::enterprise_shared_retained(
            self.tenant_id,
            self.authority.retention_revision,
            self.authority.retention_days,
            self.authority.irreversible_event_time_floor_micros,
        )
        .map_err(|_| invalid())?;
        // Open builds never configure a hosted coordinator: fail closed.
        #[cfg(not(feature = "enterprise"))]
        let scope: SearchTenantScope = Err(invalid())?;
        if self.authority.entitlement_revision <= 0 {
            return Err(invalid());
        }
        Ok((
            scope,
            HostedAssignment {
                entitlement_revision: self.authority.entitlement_revision,
                worker_revision: self.worker_assignment_revision,
            },
        ))
    }
    /// Whether this producer config is live under `registry` (NAN-2903).
    ///
    /// The worker registry is the authority on which tenants are routed. A
    /// producer config whose tenant has NO assignment belongs to a tenant that
    /// was offboarded: the platform publishes the registry revision without it
    /// before it revokes the tenant's coordinator principal and destroys its
    /// reader. Such a config is `Offboarded` and must be skipped, never
    /// attested. Attesting it would present a revoked bearer. The search
    /// and API startups would then fail for every surviving tenant because of
    /// one leftover file. A config for a ROUTED tenant whose worker revision
    /// disagrees with the registry is still a hard error: that is a live
    /// tenant with an inconsistent render, not an offboarded one.
    pub fn routing_under(
        &self,
        registry: &super::SharedLakeWorkerRegistry,
    ) -> Result<HostedProducerRouting, DurableJobStoreError> {
        if let Some(route) = registry.cell_route(self.tenant_id) {
            return if self.worker_assignment_revision == route.worker_revision {
                Ok(HostedProducerRouting::Routed)
            } else {
                Err(invalid())
            };
        }
        match registry.assignment(self.tenant_id) {
            None => Ok(HostedProducerRouting::Offboarded),
            Some(worker) if worker.expected_worker_revision == self.worker_assignment_revision => {
                Ok(HostedProducerRouting::Routed)
            }
            Some(_) => Err(invalid()),
        }
    }
    pub fn from_file(path: &Path) -> Result<Self, DurableJobStoreError> {
        Self::parse(&private_file(path, 8192)?)
    }
    /// [`Self::from_file`] plus the [`ProducerFingerprint`] of the config
    /// bytes and its bearer. An unreadable bearer still fingerprints (as a
    /// fixed marker): attestation then fails per tenant, and the bearer
    /// appearing later changes the fingerprint.
    pub fn from_file_fingerprinted(
        path: &Path,
    ) -> Result<(Self, ProducerFingerprint), DurableJobStoreError> {
        use sha2::{Digest, Sha256};
        let bytes = private_file(path, 8192)?;
        let value = Self::parse(&bytes)?;
        let mut hasher = Sha256::new();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
        match private_file(&value.token_file, 256) {
            Ok(token) => {
                let token = zeroize::Zeroizing::new(token);
                hasher.update(b"\x01token");
                hasher.update(token.as_slice());
            }
            Err(_) => hasher.update(b"\x00token-unreadable"),
        }
        Ok((value, hasher.finalize().into()))
    }
    fn parse(bytes: &[u8]) -> Result<Self, DurableJobStoreError> {
        let value: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        let region_ok = match value.deployment_kind {
            HostedCoordinatorDeploymentKind::IsolatedTest => {
                value.application_region.is_none() && value.region_placement.is_none()
            }
            HostedCoordinatorDeploymentKind::HostedRegional => value
                .application_region
                .as_deref()
                .and_then(|region| regional_coordinator_endpoint(region, value.region_placement.as_ref()))
                .is_some_and(|endpoint| value.endpoint == endpoint),
        };
        if value.schema_version != 1
            || !region_ok
            || value.tenant_id.is_nil()
            || value.worker_assignment_revision == 0
            || !value.token_file.is_absolute()
        {
            return Err(invalid());
        }
        value.expected_context()?;
        Ok(value)
    }
    pub async fn connect(
        self,
        tenant: SearchTenantScope,
        assignment: HostedAssignment,
        role: HostedCoordinatorRole,
        max_attempts: u32,
        signer: Arc<DurableJobSigningKey>,
    ) -> Result<HostedCoordinatorClient, DurableJobStoreError> {
        if (tenant, assignment) != self.expected_context()?
            || max_attempts != self.policy.max_execution_failures
        {
            return Err(invalid());
        }
        let token = zeroize::Zeroizing::new(private_file(&self.token_file, 256)?);
        let token = std::str::from_utf8(&token)
            .map_err(|_| invalid())?
            .trim_end_matches('\n');
        let transport =
            HostedCoordinatorTransport::new(&self.endpoint, token).map_err(|_| invalid())?;
        HostedCoordinatorClient::connect(
            transport,
            tenant,
            assignment,
            self.epoch,
            role,
            self.policy,
            signer,
        )
        .await
    }
}

#[cfg(unix)]
fn private_file(path: &Path, max: u64) -> Result<Vec<u8>, DurableJobStoreError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !path.is_absolute() {
        return Err(invalid());
    }
    let before = std::fs::symlink_metadata(path).map_err(|_| invalid())?;
    if !before.is_file() {
        return Err(invalid());
    }
    let file = std::fs::File::open(path).map_err(|_| invalid())?;
    let actual = file.metadata().map_err(|_| invalid())?;
    if !actual.is_file()
        || before.dev() != actual.dev()
        || before.ino() != actual.ino()
        || !matches!(actual.permissions().mode() & 0o777, 0o400 | 0o600)
        || actual.len() == 0
        || actual.len() > max
    {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.is_empty() || bytes.len() as u64 > max {
        return Err(invalid());
    }
    Ok(bytes)
}
#[cfg(not(unix))]
fn private_file(_: &Path, _: u64) -> Result<Vec<u8>, DurableJobStoreError> {
    Err(invalid())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn cell_registry(dir: &Path, routes: serde_json::Value) -> super::super::SharedLakeWorkerRegistry {
        let token = dir.join("router.token");
        std::fs::write(&token, "r".repeat(43)).unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o400)).unwrap();
        let routes_file = dir.join("routes.json");
        std::fs::write(&routes_file, routes.to_string()).unwrap();
        super::super::SharedLakeWorkerRegistry::empty_for_cells(Arc::new(
            super::super::LakeCellRouteSource::from_files(&routes_file, &token),
        ))
    }

    /// An empty producer list is admitted only when lean-lake cell routes
    /// exist (gen1 teardown); with no cell routes it stays refused.
    #[test]
    fn empty_producer_list_boots_only_with_cell_routes() {
        let dir = tempfile::tempdir().unwrap();
        let with_cells = cell_registry(dir.path(), serde_json::json!({
            Uuid::from_u128(0xa).to_string(): {"cell_origin": "http://nano-cell-cell-us-1.nano-lake-cells.svc:8790",
                "assignment_generation": 1, "part_log_writer_epoch": 1, "worker_revision": 1}
        }));
        assert_eq!(with_cells.cell_route_count(), 1);
        assert!(hosted_producer_config_paths("[]", &with_cells).unwrap().is_empty());

        // the platform's live renderer emits plain origin strings; an empty
        // producer list must still boot on those (the #4730 teardown case).
        let string_dir = tempfile::tempdir().unwrap();
        let with_string_cells = cell_registry(string_dir.path(), serde_json::json!({
            Uuid::from_u128(0xa).to_string(): "http://nano-cell-cell-us-1.nano-lake-cells.svc:8790"
        }));
        assert_eq!(with_string_cells.cell_route_count(), 1);
        assert!(hosted_producer_config_paths("[]", &with_string_cells).unwrap().is_empty());

        let no_routes_dir = tempfile::tempdir().unwrap();
        let without_cells = cell_registry(no_routes_dir.path(), serde_json::json!({}));
        assert_eq!(without_cells.cell_route_count(), 0);
        assert!(hosted_producer_config_paths("[]", &without_cells).is_err());

        // A non-empty list is returned for strict per-file validation; the
        // other bounds are unchanged.
        assert_eq!(hosted_producer_config_paths(r#"["/p/a"]"#, &without_cells).unwrap().len(), 1);
        let too_many = serde_json::to_string(&vec!["/p"; MAX_HOSTED_PRODUCER_CONFIGS + 1]).unwrap();
        assert!(hosted_producer_config_paths(&too_many, &with_cells).is_err());
        assert!(hosted_producer_config_paths("not json", &with_cells).is_err());
    }

    fn write_producer(dir: &Path, name: &str, tenant: Uuid, revision: u64) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, serde_json::to_vec(&serde_json::json!({
            "schema_version": 1, "deployment_kind": "isolated_test",
            "tenant_id": tenant, "worker_assignment_revision": revision,
            "endpoint": "https://coordinator.invalid/v1/coordinate", "epoch": "epoch1",
            "policy": {"max_execution_failures": 2, "max_lease_recoveries": 3},
            "authority": {"entitlement_revision": 1, "retention_revision": 1,
                "retention_days": 90, "irreversible_event_time_floor_micros": 0},
            "token_file": "/nonexistent/nan-3531/token"
        })).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3531: one bad producer config skips only its own tenant; the good
    /// tenant still loads. A duplicate tenant stays a process-level error.
    #[test]
    fn producer_selection_isolates_failures_per_tenant() {
        let (good, stale, gone) = (Uuid::from_u128(0xa), Uuid::from_u128(0xb), Uuid::from_u128(0xc));
        let route = |rev: u64| serde_json::json!({"cell_origin": "http://nano-cell-cell-us-1.nano-lake-cells.svc:8790",
            "assignment_generation": 1, "part_log_writer_epoch": 1, "worker_revision": rev});
        let dir = tempfile::tempdir().unwrap();
        let registry = cell_registry(dir.path(), serde_json::json!({
            good.to_string(): route(1), stale.to_string(): route(1)
        }));
        let garbage = dir.path().join("garbage");
        std::fs::write(&garbage, b"not json").unwrap();
        std::fs::set_permissions(&garbage, std::fs::Permissions::from_mode(0o600)).unwrap();
        let public = write_producer(dir.path(), "public", Uuid::from_u128(0xd), 1);
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644)).unwrap();
        let paths = vec![
            dir.path().join("missing"),
            garbage,
            public,
            write_producer(dir.path(), "stale", stale, 2),
            write_producer(dir.path(), "gone", gone, 1),
            write_producer(dir.path(), "good", good, 1),
        ];
        let kept = select_hosted_producer_configs(paths.clone(), &registry, CellRoutedProducers::Attest).unwrap();
        assert_eq!(kept.candidates.iter().map(|c| c.tenant).collect::<Vec<_>>(), vec![good]);
        assert_eq!(kept.candidates[0].assignment.worker_revision, 1);
        assert_eq!(kept.candidates[0].path, dir.path().join("good"));
        // A readable config that is refused is reported against its tenant;
        // an offboarded tenant is neither kept nor failed.
        assert_eq!(kept.failed.keys().copied().collect::<Vec<_>>(), vec![stale]);

        // The api/jobs factory never uses a cell-routed tenant's producer, so
        // it is dropped before attestation.
        assert!(select_hosted_producer_configs(paths.clone(), &registry, CellRoutedProducers::Skip)
            .unwrap()
            .candidates
            .is_empty());

        // A tenant named by two files is ambiguous: refuse the process.
        let mut duplicated = paths;
        duplicated.push(write_producer(dir.path(), "good-again", good, 1));
        assert!(select_hosted_producer_configs(duplicated, &registry, CellRoutedProducers::Attest).is_err());
    }

    #[cfg(feature = "enterprise")]
    /// A failed attestation (here: the bearer file is missing, so no network
    /// is reached) is an error the caller isolates to that tenant.
    #[tokio::test]
    async fn producer_attestation_failure_is_a_per_tenant_error() {
        let tenant = Uuid::from_u128(0xa);
        let dir = tempfile::tempdir().unwrap();
        let path = write_producer(dir.path(), "p", tenant, 1);
        let config = HostedCoordinatorDeployment::from_file(&path).unwrap();
        let (scope, assignment) = config.expected_context().unwrap();
        let master = super::super::DurableJobSigningMasterKey::from_bytes([7; 32]);
        assert!(config
            .connect(scope, assignment, HostedCoordinatorRole::Producer, 2, Arc::new(master.derive_tenant_key(tenant)))
            .await
            .is_err());
    }

    #[test]
    fn hosted_producer_routes_a_cell_tenant_without_a_gen1_assignment() {
        let tenant = Uuid::from_u128(1);
        let config: HostedCoordinatorDeployment = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "deployment_kind": "isolated_test",
            "tenant_id": tenant, "worker_assignment_revision": 3,
            "endpoint": "https://coordinator.invalid/v1/coordinate", "epoch": "epoch1",
            "policy": {"max_execution_failures": 2, "max_lease_recoveries": 3},
            "authority": {"entitlement_revision": 1, "retention_revision": 1,
                "retention_days": 90, "irreversible_event_time_floor_micros": 0},
            "token_file": "/private/token"
        })).unwrap();
        let mut route = super::super::lake_cell::LakeCellRoute::for_test(
            tenant, "http://cell.internal:8790", "/private/router-token".into(),
        );
        // The producer binds the revision committed with the cell assignment.
        route.worker_revision = 3;
        let registry = super::super::SharedLakeWorkerRegistry::empty_for_cells(
            std::sync::Arc::new(super::super::lake_cell::LakeCellRouteSource::fixed(
                super::super::lake_cell::LakeCellRoutes::from_routes_for_test([route]),
            )),
        );
        assert_eq!(config.routing_under(&registry).unwrap(), HostedProducerRouting::Routed);
        let mut stale = config;
        stale.worker_assignment_revision = 1;
        assert!(stale.routing_under(&registry).is_err());
    }
    #[cfg(feature = "enterprise")]
    #[test]
    fn private_config_rejects_public_modes_symlinks_unknown_fields_and_production_selection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        let valid = serde_json::json!({"schema_version":1,"deployment_kind":"isolated_test",
            "tenant_id":Uuid::from_u128(1),"worker_assignment_revision":1,
            "endpoint":"https://coordinator.invalid/v1/coordinate","epoch":"epoch1",
            "policy":{"max_execution_failures":2,"max_lease_recoveries":3},
            "authority":{"entitlement_revision":1,"retention_revision":1,"retention_days":90,"irreversible_event_time_floor_micros":0},
            "token_file":"/private/token"});
        std::fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(HostedCoordinatorDeployment::from_file(&path).is_ok());
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(HostedCoordinatorDeployment::from_file(&link).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(HostedCoordinatorDeployment::from_file(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        for (field, value) in [
            ("deployment_kind", serde_json::json!("production")),
            ("extra", serde_json::json!(true)),
            ("schema_version", serde_json::json!(2)),
            ("worker_assignment_revision", serde_json::json!(0)),
        ] {
            let mut bad = valid.clone();
            bad[field] = value;
            std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
            assert!(HostedCoordinatorDeployment::from_file(&path).is_err());
        }
        assert!(private_file(Path::new("relative"), 256).is_err());
        assert!(private_file(&path, 1).is_err());
    }

    /// NAN-2667/NAN-2668: the regional coordinator the platform#1405 deploys
    /// (`nano-jobs-<cc>` on `jobs-<cc>.nano.rs`) is selected by
    /// `deployment_kind: "hosted_regional"` plus the lake application region.
    /// The endpoint is derived from the region contract, never free-form.
    #[cfg(feature = "enterprise")]
    #[test]
    fn hosted_regional_mode_binds_the_region_jobs_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        let load = |value: &serde_json::Value| {
            std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            HostedCoordinatorDeployment::from_file(&path)
        };
        let config = |kind: &str, region: Option<&str>, endpoint: &str| {
            let mut value = serde_json::json!({"schema_version":1,"deployment_kind":kind,
                "tenant_id":Uuid::from_u128(1),"worker_assignment_revision":1,
                "endpoint":endpoint,"epoch":"epoch1",
                "policy":{"max_execution_failures":2,"max_lease_recoveries":3},
                "authority":{"entitlement_revision":1,"retention_revision":1,"retention_days":90,"irreversible_event_time_floor_micros":0},
                "token_file":"/private/token"});
            if let Some(region) = region {
                value["application_region"] = serde_json::json!(region);
            }
            value
        };
        let au = "https://jobs-au.nano.rs/v1/coordinate";
        let us = "https://jobs-us.nano.rs/v1/coordinate";
        let regional = load(&config("hosted_regional", Some("aus-syd-1"), au)).unwrap();
        assert_eq!(
            regional.deployment_kind(),
            HostedCoordinatorDeploymentKind::HostedRegional
        );
        assert_eq!(regional.application_region(), Some("aus-syd-1"));
        for region in ["us-east-iad-2", "us-east-iad-1"] {
            assert!(
                load(&config("hosted_regional", Some(region), us)).is_ok(),
                "{region}"
            );
        }
        // The isolated test mode is unchanged and carries no region.
        let isolated = load(&config(
            "isolated_test",
            None,
            "https://coordinator.invalid/v1/coordinate",
        ))
        .unwrap();
        assert_eq!(
            isolated.deployment_kind(),
            HostedCoordinatorDeploymentKind::IsolatedTest
        );
        assert_eq!(isolated.application_region(), None);
        for (kind, region, endpoint) in [
            // Region is required, registered and exact.
            ("hosted_regional", None, au),
            (
                "hosted_regional",
                Some("us-west-sjc-1"),
                "https://jobs-us.nano.rs/v1/coordinate",
            ),
            ("hosted_regional", Some("AUS-SYD-1"), au),
            // Endpoint must be the region's own coordinator.
            ("hosted_regional", Some("aus-syd-1"), us),
            (
                "hosted_regional",
                Some("aus-syd-1"),
                "https://jobs-au.nano.rs/v1/coordinate/",
            ),
            (
                "hosted_regional",
                Some("aus-syd-1"),
                "http://jobs-au.nano.rs/v1/coordinate",
            ),
            (
                "hosted_regional",
                Some("aus-syd-1"),
                "https://nano-jobs-au.example.workers.dev/v1/coordinate",
            ),
            // isolated_test never carries a region; unknown kinds stay refused.
            ("isolated_test", Some("aus-syd-1"), au),
            ("production", Some("aus-syd-1"), au),
            ("hosted", Some("aus-syd-1"), au),
        ] {
            assert!(
                load(&config(kind, region, endpoint)).is_err(),
                "{kind} {region:?} {endpoint}"
            );
        }
        // NAN-3891: a spec region with no table entry is accepted with its
        // rendered placement and binds its own coordinator only.
        let placement = serde_json::json!({
            "durable_object_location_hint": "apac", "r2_jurisdiction": "default",
            "r2_location_hint": "apac", "region_code": "jp",
            "source_admission_script": "nano-source-admission-jp", "spot_region": "jp-tyo-1",
            "farm_hostname": "farm.jp.nano.rs",
        });
        // (An id no other test treats as unknown: resolved regions are process-wide.)
        let us_west = "https://jobs-jp.nano.rs/v1/coordinate";
        let mut spec = config("hosted_regional", Some("jp-tyo-1"), us_west);
        spec["region_placement"] = placement.clone();
        assert!(load(&spec).is_ok());
        spec["endpoint"] = serde_json::json!(us);
        assert!(load(&spec).is_err());
        let mut legacy = config("hosted_regional", Some("us-east-iad-2"), us);
        legacy["region_placement"] = placement.clone();
        assert!(load(&legacy).is_err(), "a legacy region takes no placement");
        let mut isolated = config("isolated_test", None, "https://coordinator.invalid/v1/coordinate");
        isolated["region_placement"] = placement;
        assert!(load(&isolated).is_err());
    }
}
