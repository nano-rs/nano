// SPDX-License-Identifier: AGPL-3.0-or-later
//! The cell's platform IOC view for on-demand indicator lookups (NAN-3881).
//!
//! NAN-4168 (Dan, 2026-10-19, option 1): platform enrichment is enforced at
//! ingest only. A stamp written under a grant stays readable forever, like
//! any other column: search, detections, risk and exports read enrichment
//! leaves (`*.location.*`, `*.autonomous_system.*`, `enrichments[]`) as plain
//! columns. There is no read-time authority, revision or expiry mask. A
//! missing or revoked grant only stops new stamping.
use std::path::PathBuf;

struct CellPolicy {
    tenant: uuid::Uuid,
    path: PathBuf,
    bundle: crate::lean_platform_bundle::PlatformBundleSource,
    current: std::sync::Mutex<crate::lean_platform_bundle::TenantPlatformPolicy>,
    /// The verified bundle `current` names, kept so an on-demand IOC lookup
    /// does not re-hash the bundle per request (NAN-3881).
    opened: std::sync::Mutex<std::sync::Arc<crate::lean_platform_bundle::PlatformBundle>>,
}

static CELL_POLICY: std::sync::OnceLock<CellPolicy> = std::sync::OnceLock::new();

/// Install the sealed cell assignment's platform mounts. The bundle is
/// verified once from the jailed read-only mount; the policy is reread per
/// lookup.
pub fn configure_cell(assignment: &nanosiem_lake_cell::contract::Assignment) -> anyhow::Result<()> {
    use anyhow::{bail, ensure, Context};
    let tenant: uuid::Uuid = assignment.tenant.as_str().parse().context("cell tenant must be UUID")?;
    let bundle = crate::lean_platform_bundle::PlatformBundleSource::from_paths(
        assignment.platform_bundle_file.as_deref(), assignment.platform_bundle_dir.as_deref())?;
    let (Some(bundle), Some(path)) = (bundle, &assignment.platform_policy_file) else {
        bail!("platform IOC lookups require platform bundle and tenant policy mounts");
    };
    ensure!(path.is_absolute(), "platform paths must be absolute");
    let policy = crate::lean_platform_bundle::TenantPlatformPolicy::read_for_query(path, tenant)?;
    let verified = std::sync::Arc::new(bundle.open(&policy.bundle_sha256)?);
    let _ = CELL_POLICY.set(CellPolicy { tenant, path: path.clone(), bundle,
        current: std::sync::Mutex::new(policy), opened: std::sync::Mutex::new(verified) });
    Ok(())
}

/// Reread the cell's private policy (revocations land on the next lookup),
/// refuse a rollback, and verify + keep the bundle it names when it moved.
fn refresh_cell_policy(
    cell: &CellPolicy,
    tenant: uuid::Uuid,
) -> anyhow::Result<(crate::lean_platform_bundle::TenantPlatformPolicy, std::sync::Arc<crate::lean_platform_bundle::PlatformBundle>)> {
    let policy = crate::lean_platform_bundle::TenantPlatformPolicy::read_for_query(&cell.path, tenant)?;
    let mut current = cell.current.lock().map_err(|_| anyhow::anyhow!("cell policy lock poisoned"))?;
    policy.validate_successor(&current)?;
    let mut opened = cell.opened.lock().map_err(|_| anyhow::anyhow!("cell bundle lock poisoned"))?;
    if policy.bundle_sha256 != opened.digest() {
        let fresh = cell.bundle.open(&policy.bundle_sha256)?;
        anyhow::ensure!(fresh.digest() == policy.bundle_sha256, "platform bundle digest differs");
        *opened = std::sync::Arc::new(fresh);
    }
    *current = policy.clone();
    Ok((policy, opened.clone()))
}

/// NAN-3881: the platform baseline IOC feeds (ThreatFox, Tor exit nodes...)
/// this process's tenant is granted, exactly as ingest stamping reads them:
/// the node bundle plus the tenant's own fresh policy. `None` when the
/// process has no platform mounts (open core, a cell without a bundle).
/// Another tenant id is refused: a process only ever answers for its own.
pub fn platform_ioc_view(
    tenant: uuid::Uuid,
) -> anyhow::Result<Option<(std::sync::Arc<crate::lean_platform_bundle::PlatformBundle>, crate::lean_platform_bundle::TenantPlatformPolicy)>> {
    let Some(cell) = CELL_POLICY.get() else { return Ok(None) };
    anyhow::ensure!(!tenant.is_nil() && tenant == cell.tenant, "platform IOC view tenant differs from process tenant");
    let (policy, bundle) = refresh_cell_policy(cell, tenant)?;
    Ok(Some((bundle, policy)))
}
