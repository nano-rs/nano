// SPDX-License-Identifier: AGPL-3.0-or-later
//! Stored-enrichment projection, applied directly over a trusted event scan.
use nanosiem_core::platform_enrichment::read::ReadAuthorization;
use std::path::PathBuf;

struct CellPolicy {
    tenant: uuid::Uuid,
    path: PathBuf,
    bundle: crate::lean_platform_bundle::PlatformBundleSource,
    current: std::sync::Mutex<crate::lean_platform_bundle::TenantPlatformPolicy>,
    /// The verified bundle `current` names, kept so an on-demand IOC lookup
    /// does not re-hash the bundle per request (NAN-3881).
    opened: std::sync::Mutex<std::sync::Arc<crate::lean_platform_bundle::PlatformBundle>>,
    custom_root: Option<PathBuf>,
    custom_digest: std::sync::Mutex<Option<String>>,
}

static CELL_POLICY: std::sync::OnceLock<CellPolicy> = std::sync::OnceLock::new();

/// Install the sealed cell assignment before serving any query. The bundle is
/// verified once from the jailed read-only mount; policy is reread per dispatch.
pub fn configure_cell(assignment: &nanosiem_lake_cell::contract::Assignment) -> anyhow::Result<()> {
    use anyhow::{bail, ensure, Context};
    let tenant: uuid::Uuid = assignment.tenant.as_str().parse().context("cell tenant must be UUID")?;
    let bundle = crate::lean_platform_bundle::PlatformBundleSource::from_paths(
        assignment.platform_bundle_file.as_deref(), assignment.platform_bundle_dir.as_deref())?;
    let (Some(bundle), Some(path)) = (bundle, &assignment.platform_policy_file) else {
        bail!("production query requires platform bundle and tenant policy mounts");
    };
    ensure!(path.is_absolute(), "platform paths must be absolute");
    let policy = crate::lean_platform_bundle::TenantPlatformPolicy::read_for_query(path, tenant)?;
    let verified = std::sync::Arc::new(bundle.open(&policy.bundle_sha256)?);
    let custom_digest = assignment.custom_context_root.as_ref().map(|root| -> anyhow::Result<String> {
        let (path, digest) = crate::ip_context::current_assignment_pointer(root, assignment.tenant.as_str())?
            .context("configured custom context has no current revision")?;
        let _verified = crate::ip_context::IpContextSnapshot::open_lean(path, &digest)?;
        Ok(digest)
    }).transpose()?;
    let _ = CELL_POLICY.set(CellPolicy { tenant, path: path.clone(), bundle,
        current: std::sync::Mutex::new(policy), opened: std::sync::Mutex::new(verified),
        custom_root: assignment.custom_context_root.clone(),
        custom_digest: std::sync::Mutex::new(custom_digest) });
    Ok(())
}

fn validate_cell_custom_context() -> anyhow::Result<()> {
    use anyhow::Context;
    let Some(cell) = CELL_POLICY.get() else { return Ok(()) };
    let Some(root) = &cell.custom_root else { return Ok(()) };
    let (path, digest) = crate::ip_context::current_assignment_pointer(root, &cell.tenant.to_string())?
        .context("configured custom context has no current revision")?;
    let mut current = cell.custom_digest.lock().map_err(|_| anyhow::anyhow!("custom context lock poisoned"))?;
    if current.as_deref() != Some(digest.as_str()) {
        let _verified = crate::ip_context::IpContextSnapshot::open_lean(path, &digest)?;
        *current = Some(digest);
    }
    Ok(())
}

fn from_lean_policy(policy: &crate::lean_platform_bundle::TenantPlatformPolicy, now: chrono::DateTime<chrono::Utc>) -> ReadAuthorization {
    use nanosiem_core::platform_enrichment::{AuthorizedRevision, FeedClass, RevisionReference};
    let rights = policy.grants.iter().map(|(feed_id, grant)| {
        let (class, tier, grant_revision, entitlement_revision) = match &grant.premium {
            Some(right) => (FeedClass::Premium, right.tier.clone(), right.grant_revision, right.entitlement_revision),
            None => (FeedClass::Baseline, "included".to_string(), 1, 1),
        };
        AuthorizedRevision {
            tenant_id: policy.tenant_id,
            reference: RevisionReference { feed_id: feed_id.clone(), feed_revision: grant.feed_revision,
                tier, grant_revision, entitlement_revision },
            class, digest: policy.bundle_sha256.clone(), mapping_revision: policy.revision as i64,
            deny_epoch: 0, valid_until: grant.valid_until, evaluated_at: now,
        }
    }).collect::<Vec<_>>();
    ReadAuthorization::from_resolved(policy.tenant_id, now, &rights)
}

#[cfg(test)]
mod lean_policy_tests {
    use super::*;
    use crate::lean_platform_bundle::{PlatformGrant, TenantPlatformPolicy};
    use std::collections::BTreeMap;

    #[test]
    fn policy_revocation_and_expiry_change_query_mask_authority() {
        let now = chrono::Utc::now();
        let mut policy = TenantPlatformPolicy { tenant_id: uuid::Uuid::new_v4(), revision: 1,
            bundle_sha256: "a".repeat(64), grants: BTreeMap::from([("ipinfo_lite".into(), PlatformGrant {
                feed_revision: 2, valid_until: now + chrono::Duration::minutes(5), premium: None,
            })]) };
        let granted = from_lean_policy(&policy, now);
        assert_eq!(granted.rights_len(), 1);
        assert_ne!(granted.tuple_permission_sql("stamp"), "0");
        policy.grants.clear();
        assert_eq!(from_lean_policy(&policy, now).tuple_permission_sql("stamp"), "0");
        policy.grants.insert("ipinfo_lite".into(), PlatformGrant {
            feed_revision: 2, valid_until: now - chrono::Duration::seconds(1), premium: None,
        });
        assert_eq!(from_lean_policy(&policy, now).rights_len(), 0);
    }

    #[tokio::test]
    async fn dispatch_refuses_result_after_policy_revocation() {
        let tenant = uuid::Uuid::new_v4();
        let now = chrono::Utc::now();
        let granted = TenantPlatformPolicy { tenant_id: tenant, revision: 1,
            bundle_sha256: "a".repeat(64), grants: BTreeMap::from([("ipinfo_lite".into(), PlatformGrant {
                feed_revision: 1, valid_until: now + chrono::Duration::minutes(5), premium: None,
            })]) };
        let mut revoked = granted.clone();
        revoked.revision = 2;
        revoked.grants.clear();
        let changed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let check = changed.clone();
        let work = changed.clone();
        let result = execute(
            move || {
                let policy = if check.load(std::sync::atomic::Ordering::SeqCst) { &revoked } else { &granted };
                std::future::ready(from_lean_policy(policy, chrono::Utc::now()))
            },
            async move { work.store(true, std::sync::atomic::Ordering::SeqCst); 1u8 },
        ).await;
        assert!(result.is_err(), "an in-flight query must not return after revocation");
    }

    /// NAN-3293 live (2026-10-08 12:03:49Z, the load-test tenant): the cell's
    /// platform-bundle sidecar published a refreshed bundle mid-job. Policy
    /// revision 2 -> 3, new bundle digest, threatfox/tor_exit_nodes feed
    /// revision +1 with renewed valid_until; same grants. The durable
    /// baseline job then failed "authorization changed during execution".
    #[tokio::test]
    async fn dispatch_returns_across_a_bundle_refresh_with_unchanged_grants() {
        let tenant = uuid::Uuid::new_v4();
        let now = chrono::Utc::now();
        let grant = |feed_revision, hours| PlatformGrant {
            feed_revision, valid_until: now + chrono::Duration::hours(hours), premium: None,
        };
        let before = TenantPlatformPolicy { tenant_id: tenant, revision: 2, bundle_sha256: "a".repeat(64),
            grants: BTreeMap::from([("ipinfo_lite".into(), grant(4, 300)), ("threatfox".into(), grant(64, 23)),
                ("tor_exit_nodes".into(), grant(64, 23))]) };
        let after = TenantPlatformPolicy { revision: 3, bundle_sha256: "b".repeat(64),
            grants: BTreeMap::from([("ipinfo_lite".into(), grant(4, 300)), ("threatfox".into(), grant(65, 24)),
                ("tor_exit_nodes".into(), grant(65, 24))]), ..before.clone() };
        after.validate_successor(&before).unwrap();
        let refreshed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (check, work) = (refreshed.clone(), refreshed.clone());
        let result = execute(
            move || {
                let policy = if check.load(std::sync::atomic::Ordering::SeqCst) { &after } else { &before };
                std::future::ready(from_lean_policy(policy, chrono::Utc::now()))
            },
            async move { work.store(true, std::sync::atomic::Ordering::SeqCst); 1u8 },
        ).await;
        assert_eq!(result.unwrap(), 1, "a feed refresh under unchanged grants is not a revocation");
    }

    /// A narrowed premium grant (entitlement revision bump) or a dropped feed
    /// mid-query still fails closed.
    #[tokio::test]
    async fn dispatch_refuses_result_after_grant_narrowing() {
        use nanosiem_core::platform_enrichment::PremiumStampRight;
        let tenant = uuid::Uuid::new_v4();
        let now = chrono::Utc::now();
        let premium = |entitlement_revision| PlatformGrant {
            feed_revision: 3, valid_until: now + chrono::Duration::hours(1),
            premium: Some(PremiumStampRight { tier: "pro".into(), grant_revision: 1, entitlement_revision }),
        };
        let granted = TenantPlatformPolicy { tenant_id: tenant, revision: 1, bundle_sha256: "a".repeat(64),
            grants: BTreeMap::from([("synthient".into(), premium(1)), ("ipinfo_lite".into(), PlatformGrant {
                feed_revision: 1, valid_until: now + chrono::Duration::hours(1), premium: None })]) };
        let mut narrowed = granted.clone();
        narrowed.revision = 2;
        narrowed.grants.insert("synthient".into(), premium(2));
        let mut dropped = granted.clone();
        dropped.revision = 2;
        dropped.grants.remove("ipinfo_lite");
        for changed_to in [narrowed, dropped] {
            let granted = granted.clone();
            let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (check, work) = (flag.clone(), flag.clone());
            let result = execute(
                move || {
                    let policy = if check.load(std::sync::atomic::Ordering::SeqCst) { &changed_to } else { &granted };
                    std::future::ready(from_lean_policy(policy, chrono::Utc::now()))
                },
                async move { work.store(true, std::sync::atomic::Ordering::SeqCst); 1u8 },
            ).await;
            assert!(result.is_err(), "a narrowed grant must not return");
        }
    }
}

/// Reread the cell's private policy (revocations land on the next dispatch),
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

/// A separate execute-only, tenant-bound DB identity. Optional metadata
/// failures never weaken the caller's existing event authorization.
pub async fn resolve(tenant_id: &str) -> ReadAuthorization {
    if let Some(cell) = CELL_POLICY.get() {
        let now = chrono::Utc::now();
        let tenant = tenant_id.parse().unwrap_or(uuid::Uuid::nil());
        if tenant != cell.tenant { return ReadAuthorization::unknown(tenant, now); }
        return match refresh_cell_policy(cell, tenant) {
            Ok((policy, _)) => from_lean_policy(&policy, now),
            Err(error) => {
                tracing::warn!(%error, tenant = tenant_id, "cell policy unavailable; denying platform enrichment");
                ReadAuthorization::unknown(tenant, now)
            }
        };
    }
    if let Some(path) = std::env::var_os("NANO_LAKE_PLATFORM_POLICY_FILE") {
        let tenant = tenant_id.parse().unwrap_or(uuid::Uuid::nil());
        let now = chrono::Utc::now();
        return match crate::lean_platform_bundle::TenantPlatformPolicy::read_for_query(std::path::Path::new(&path), tenant) {
            Ok(policy) => from_lean_policy(&policy, now),
            Err(error) => {
                tracing::warn!(%error, tenant = tenant_id, "lean platform policy unavailable; denying stored platform enrichment");
                ReadAuthorization::unknown(tenant, now)
            }
        };
    }
    let authority = nanosiem_core::platform_enrichment::read::resolve_from_environment(
        tenant_id.parse().unwrap_or(uuid::Uuid::nil()),
    )
    .await;
    // One sample per worker per minute, with bounded state across tenants.
    // Monotonic elapsed time avoids clock adjustments suppressing diagnostics.
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let elapsed = START.get_or_init(std::time::Instant::now).elapsed().as_secs();
    if NEXT.fetch_update(std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed,
        |next| (elapsed >= next).then_some(elapsed.saturating_add(60))).is_ok()
    {
        tracing::info!(tenant = tenant_id, rights_len = authority.rights_len(),
            cache_identity = %authority.cache_identity(), "platform enrichment read dispatch authority");
    }
    authority
}

tokio::task_local! {
    static AUTHORIZATION: ReadAuthorization;
    /// NAN-2869: what the owner-denial probe proved about the planned source
    /// (see [`ScalarPlan`]). Unset means nothing is proven: mask every row.
    static SCALAR_PLAN: ScalarPlan;
}

/// Proofs about the location/ASN leaves of one planned source (every file of
/// it), from [`owner_denial_probe_sql`] under the current authority.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScalarPlan {
    /// No row carries a denied platform stamp owning any of the leaves:
    /// masking them is the identity.
    pub elided: bool,
    /// Bit `i` set: every non-null value of `SCALAR_MASKED_LEAVES[i]` is owned
    /// by a denied platform stamp, so the masked leaf is NULL on every row
    /// (typically rights revoked after ingest). The leaf is planned as a typed
    /// NULL without reading `enrichments`.
    pub null_leaves: u16,
    /// NAN-3800: the per-file proofs were mixed (`elided` is false). A
    /// planner that can read clean and unclean files in separate branches
    /// may use this instead of masking every file (see [`ScalarSplit`]).
    pub split: Option<std::sync::Arc<ScalarSplit>>,
}

/// NAN-3800: one selection's owner proofs, per file. Proofs are per data
/// file, but [`ScalarPlan::elided`] needs every file clean: a dozen 6-day-old
/// files with expired or denied stamps made a 7 d `stats ... by
/// src_endpoint.location.country` decode `enrichments` for all ~200 files
/// (13 s / 740 MiB idle on tenant-a, 45 s escalations under k6) where 144 h, all
/// clean, read the plain leaf (1.7 s / 20 MiB).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScalarSplit {
    /// Local paths of the data files proven clean: their masks are the
    /// identity and may be planned as plain leaf reads.
    pub clean: std::collections::BTreeSet<std::path::PathBuf>,
    /// [`ScalarPlan::null_leaves`] over the NOT-clean files only (the leaves
    /// proven NULL there), for the branch that keeps the mask.
    pub unclean_null_leaves: u16,
}

/// Plan `future` with the scalar location/ASN masks elided. The caller must
/// have proven (see `owner_denial_probe_sql`) that no row of the planned
/// source carries a denied platform stamp owning one of those leaves.
pub async fn with_scalar_masks_elided<T>(future: impl std::future::Future<Output = T>) -> T {
    SCALAR_PLAN.scope(ScalarPlan { elided: true, ..ScalarPlan::default() }, Box::pin(future)).await
}

/// Synchronous form of [`with_scalar_masks_elided`] (planner calls are sync).
pub fn plan_with_scalar_masks_elided<T>(elided: bool, plan: impl FnOnce() -> T) -> T {
    SCALAR_PLAN.sync_scope(ScalarPlan { elided, ..ScalarPlan::default() }, plan)
}

/// Plan under the proofs of `scalar` (sync; planner calls are sync).
pub fn plan_with_scalar_plan<T>(scalar: ScalarPlan, plan: impl FnOnce() -> T) -> T {
    SCALAR_PLAN.sync_scope(scalar, plan)
}

/// The planning scope's proof, without cloning its split (the hot path
/// asks per projected leaf).
fn scalar_proof() -> (bool, u16) {
    SCALAR_PLAN.try_with(|plan| (plan.elided, plan.null_leaves)).unwrap_or_default()
}

/// NAN-3800: the planning scope's per-file split, when its proofs were mixed.
pub fn scalar_split() -> Option<std::sync::Arc<ScalarSplit>> {
    SCALAR_PLAN.try_with(|plan| if plan.elided { None } else { plan.split.clone() }).ok().flatten()
}

fn scalar_masks_elided() -> bool {
    scalar_proof().0
}

/// Is `path` a scalar leaf proven NULL for every row of the planned source?
pub fn scalar_leaf_null(path: &str) -> bool {
    let (elided, null_leaves) = scalar_proof();
    !elided
        && SCALAR_MASKED_LEAVES
            .iter()
            .position(|leaf| *leaf == path)
            .is_some_and(|index| null_leaves & (1 << index) != 0)
}

/// `sensitive` and not proven NULL: the leaf needs its per-row mask (and so
/// the `enrichments` column).
pub fn needs_row_mask(path: &str) -> bool {
    sensitive(path) && !scalar_leaf_null(path)
}

/// Are all five scalar leaves of endpoint `root` proven NULL?
fn endpoint_leaves_null(root: &str) -> bool {
    SCALAR_MASKED_LEAVES.iter().filter(|leaf| leaf.starts_with(&format!("{root}."))).all(|leaf| scalar_leaf_null(leaf))
}

/// The ten leaves `scalar_masked_leaf` covers.
pub const SCALAR_MASKED_LEAVES: &[&str] = &[
    "src_endpoint.location.country", "src_endpoint.location.continent", "src_endpoint.location.provider",
    "src_endpoint.autonomous_system.number", "src_endpoint.autonomous_system.name",
    "dst_endpoint.location.country", "dst_endpoint.location.continent", "dst_endpoint.location.provider",
    "dst_endpoint.autonomous_system.number", "dst_endpoint.autonomous_system.name",
];

/// Per-file proof statement over `{probe_source:String}`: rows carrying a
/// platform stamp that owns a location/ASN leaf and that `authority` does not
/// allow, and the earliest `valid_until` among allowed owning stamps (the
/// proof expires when that stamp does).
pub fn owner_denial_probe_sql(authority: &ReadAuthorization) -> String {
    owner_denial_probe_sql_for_fields(authority, SCALAR_MASKED_LEAVES.iter().copied())
}

/// The owner probe must not reference leaves absent from this part's schema.
/// An absent leaf is already NULL, so its keep count is provably zero.
pub fn owner_denial_probe_sql_for_fields<'a>(
    authority: &ReadAuthorization,
    available: impl IntoIterator<Item = &'a str>,
) -> String {
    let available = available.into_iter().collect::<std::collections::BTreeSet<_>>();
    let allowed = authority.tuple_permission_sql("__nano_e");
    let owns = format!(
        "hasAny(tupleElement(tupleElement(__nano_e, 'data', tuple()), 'owned_fields', CAST([], 'Array(String)')), [{}])",
        SCALAR_MASKED_LEAVES.iter().map(|leaf| format!("'{leaf}'")).collect::<Vec<_>>().join(", ")
    );
    let valid_until = "parseDateTime64BestEffortOrNull(ifNull(tupleElement(tupleElement(__nano_e, 'data', tuple()), 'valid_until', ''), ''), 6, 'UTC')";
    // keep_i: rows whose masked leaf i would still hold a value (non-null and
    // not owned by a denied platform stamp). 0 proves the leaf NULL.
    let keeps = SCALAR_MASKED_LEAVES
        .iter()
        .enumerate()
        .map(|(index, leaf)| {
            if !available.contains(leaf) {
                return format!("toUInt64(0) AS keep_{index}");
            }
            let parts = leaf.split('.').collect::<Vec<_>>();
            let value = format!("tupleElement(tupleElement(`{}`, '{}'), '{}')", parts[0], parts[1], parts[2]);
            let owned = format!("has(tupleElement(tupleElement(__nano_e, 'data', tuple()), 'owned_fields', CAST([], 'Array(String)')), '{leaf}')");
            format!("countIf(isNotNull({value}) AND NOT arrayExists(__nano_e -> {PLATFORM_STAMP} AND NOT ifNull({allowed}, 0) AND {owned}, `enrichments`)) AS keep_{index}")
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "SELECT _path AS path, {keeps}, countIf(arrayExists(__nano_e -> {PLATFORM_STAMP} AND NOT ifNull({allowed}, 0) AND {owns}, `enrichments`)) AS denied, \
                min(if(empty(arrayFilter(__nano_e -> {PLATFORM_STAMP} AND {owns}, `enrichments`)), toInt64(7258118400000000), \
                    toInt64(arrayMin(arrayMap(__nano_e -> ifNull(toUnixTimestamp64Micro({valid_until}), toInt64(0)), \
                        arrayFilter(__nano_e -> {PLATFORM_STAMP} AND {owns}, `enrichments`)))))) AS expires_us \
         FROM file({{probe_source:String}}, Parquet, {{probe_schema:String}}) GROUP BY path"
    )
}

pub async fn scope<T>(
    authority: ReadAuthorization,
    future: impl std::future::Future<Output = T>,
) -> T {
    AUTHORIZATION.scope(authority, Box::pin(future)).await
}

pub fn current() -> ReadAuthorization {
    AUTHORIZATION
        .try_with(Clone::clone)
        .unwrap_or_else(|_| ReadAuthorization::unknown(uuid::Uuid::nil(), chrono::Utc::now()))
}

pub fn current_for_tenant(tenant: &str) -> ReadAuthorization {
    AUTHORIZATION.try_with(Clone::clone).unwrap_or_else(|_| {
        ReadAuthorization::unknown(
            tenant.parse().unwrap_or(uuid::Uuid::nil()),
            chrono::Utc::now(),
        )
    })
}

pub async fn validate_return(tenant: &str) -> anyhow::Result<()> {
    validate_cell_custom_context()?;
    let authority = current_for_tenant(tenant);
    let current = resolve(tenant).await;
    if !authority.may_return(&current, None) {
        anyhow::bail!("platform enrichment authorization changed during execution");
    }
    Ok(())
}

/// One dispatch snapshot per request, inherited by nested event reads and commits.
/// The resolver is a server-owned capability,
/// never part of a request. Fixtures replace only that control-metadata source.
pub async fn execute<T, R, RF>(
    resolver: R,
    work: impl std::future::Future<Output = T>,
) -> anyhow::Result<T>
where
    R: Fn() -> RF,
    RF: std::future::Future<Output = ReadAuthorization>,
{
    // NAN-3141: hold `work` once, on the heap, across the resolver awaits.
    let work = Box::pin(work);
    validate_cell_custom_context()?;
    let (authority, nested) = match AUTHORIZATION.try_with(Clone::clone) {
        Ok(authority) => (authority, true),
        Err(_) => (resolver().await, false),
    };
    let result = scope(authority.clone(), work).await;
    validate_cell_custom_context()?;
    // A nested read keeps the dispatch snapshot; the outermost `execute`
    // owns the single post-return revocation check.
    if nested {
        return Ok(result);
    }
    let current = resolver().await;
    if !authority.may_return(&current, None) {
        anyhow::bail!("platform enrichment authorization changed during execution");
    }
    Ok(result)
}

/// The provider lives in the physical tuple, including on producer-only rows.
const PLATFORM_STAMP: &str = "startsWith(ifNull(tupleElement(__nano_e, 'provider', ''), ''), 'platform/')";

fn denied_flags(authority: &ReadAuthorization) -> String {
    let allowed = authority.tuple_permission_sql("__nano_e");
    format!("arrayMap(__nano_e -> {PLATFORM_STAMP} AND NOT ifNull({allowed}, 0), `enrichments`)")
}

fn denied_stamps(authority: &ReadAuthorization) -> String {
    format!("arrayFilter((__nano_e, __nano_deny) -> __nano_deny, `enrichments`, {})", denied_flags(authority))
}

/// A bounded, flat display page shares one permission/ownership reduction
/// across every sensitive leaf instead of repeating the permission lambda.
pub fn denied_owned_fields(authority: &ReadAuthorization) -> String {
    format!("arrayFlatten(arrayMap(__nano_e -> tupleElement(tupleElement(__nano_e, 'data', tuple()), 'owned_fields', CAST([], 'Array(String)')), {}))",
        denied_stamps(authority))
}

/// Bind the denied set as a lambda argument, rather than expanding the
/// permission predicate once for each owned leaf. Identical denied expressions
/// also share ClickHouse's expression DAG across projections in the scan.
fn mask(expression: &str, original: &str, authority: &ReadAuthorization) -> String {
    // Bind the physical root too: expanding a storage-column matcher directly
    // mixes root and subcolumn reads and breaks automatic PREWHERE headers.
    format!("if(arrayExists(__nano_e -> {PLATFORM_STAMP}, `enrichments`), arrayElement(arrayMap((__nano_denied, __nano_root) -> {expression}, [{}], [{original}]), 1), {original})",
        denied_stamps(authority))
}

fn owned_leaf(path: &str, original: &str) -> String {
    format!("if(arrayExists(__nano_e -> has(tupleElement(tupleElement(__nano_e, 'data', tuple()), 'owned_fields', CAST([], 'Array(String)')), '{path}'), __nano_denied), NULL, {original})")
}

/// Rebuild in physical field order via the tuple column matcher. REPLACE
/// ignores absent members, preserving older/additive schemas and every producer
/// sibling. CAST restores the original named tuple type (including Nullable
/// leaves), without serializing or parsing any event JSON.
fn rebuilt_endpoint(root: &str) -> String {
    let path = "__nano_root";
    let mut replacements = Vec::new();
    for (parent, leaves) in [
        ("location", &["country", "continent", "provider"][..]),
        ("autonomous_system", &["number", "name"][..]),
    ] {
        let parent_path = format!("{path}.{parent}");
        let fields = leaves.iter().map(|leaf| {
            let full = format!("{parent_path}.{leaf}");
            format!("{} AS {leaf}", owned_leaf(&format!("{root}.{parent}.{leaf}"), &full))
        }).collect::<Vec<_>>().join(", ");
        replacements.push(format!("CAST(tuple({parent_path}.* REPLACE ({fields})), toTypeName({parent_path})) AS {parent}"));
    }
    format!("CAST(tuple({path}.* REPLACE ({})), toTypeName({path}))", replacements.join(", "))
}

/// [`rebuilt_endpoint`] with every owned leaf NULL (the proven-NULL form).
fn rebuilt_endpoint_nulls(root: &str) -> String {
    let path = format!("`{root}`");
    let mut replacements = Vec::new();
    for (parent, leaves) in [
        ("location", &["country", "continent", "provider"][..]),
        ("autonomous_system", &["number", "name"][..]),
    ] {
        let parent_path = format!("{path}.{parent}");
        let fields = leaves.iter().map(|leaf| format!("NULL AS {leaf}")).collect::<Vec<_>>().join(", ");
        replacements.push(format!("CAST(tuple({parent_path}.* REPLACE ({fields})), toTypeName({parent_path})) AS {parent}"));
    }
    format!("CAST(tuple({path}.* REPLACE ({})), toTypeName({path}))", replacements.join(", "))
}

pub fn root_expression(root: &str, authority: &ReadAuthorization) -> String {
    match root {
        "enrichments" => {
            // Share the same permission flags as the owned-leaf mask, including
            // when full event rows project both endpoints and enrichments.
            format!("arrayFilter((__nano_e, __nano_deny) -> NOT __nano_deny, `enrichments`, {})", denied_flags(authority))
        }
        "src_endpoint" | "dst_endpoint" if endpoint_leaves_null(root) => {
            // Every owned leaf is proven NULL: rebuild with constants, no
            // `enrichments` read.
            rebuilt_endpoint_nulls(root)
        }
        "src_endpoint" | "dst_endpoint" => {
            mask(&rebuilt_endpoint(root), &format!("`{root}`"), authority)
        }
        _ => format!("`{root}`"),
    }
}

/// Paths come from the validated physical manifest, never request SQL.
pub fn leaf_expression(path: &str, authority: &ReadAuthorization) -> String {
    let parts = path.split('.').collect::<Vec<_>>();
    if matches!(parts[0], "src_endpoint" | "dst_endpoint") && parts.len() > 1 && !sensitive(path) {
        return parts[1..].iter().fold(format!("`{}`", parts[0]), |expr, part| {
            format!("tupleElement({expr}, '{part}')")
        });
    }
    if matches!(parts[0], "src_endpoint" | "dst_endpoint") && parts.len() == 3 {
        let original = format!("tupleElement(tupleElement(`{}`, '{}'), '{}')", parts[0], parts[1], parts[2]);
        if scalar_leaf_null(path) {
            // Proven NULL on every row of the source: no `enrichments` read.
            return format!("CAST(NULL, toTypeName({original}))");
        }
        if matches!((parts[1], parts[2]),
            ("location", "country" | "continent" | "provider") | ("autonomous_system", "number" | "name"))
        {
            // One leaf needs only a scalar denial reduction, not an allocated
            // denied array for every empty row. Multi-leaf projections use
            // shared_leaf_expression below to share the denied set instead.
            let allowed = authority.tuple_permission_sql("__nano_e");
            let owns = format!("has(tupleElement(tupleElement(__nano_e, 'data', tuple()), 'owned_fields', CAST([], 'Array(String)')), '{path}')");
            return format!("if(arrayExists(__nano_e -> {PLATFORM_STAMP}, `enrichments`), if(arrayExists(__nano_e -> {PLATFORM_STAMP} AND NOT ifNull({allowed}, 0) AND {owns}, `enrichments`), NULL, {original}), {original})");
        }
        return original;
    }
    shared_leaf_expression(path, authority)
}

/// Multiple sensitive projections reuse the identical root/permission DAG.
pub fn shared_leaf_expression(path: &str, authority: &ReadAuthorization) -> String {
    let parts = path.split('.').collect::<Vec<_>>();
    let mut expression = root_expression(parts[0], authority);
    for part in &parts[1..] {
        expression = format!("tupleElement({expression}, '{part}')");
    }
    expression
}

/// A sensitive endpoint leaf that `leaf_expression` masks with one scalar
/// reduction over `enrichments` (no root rebuild). NAN-2869: projecting two
/// or more of these through the shared root rebuild re-materialized the whole
/// endpoint tuple per row and cost ~14x the CPU of the scalar form (94 vs
/// 6.5 CPU-s on a 24 h tenant1 stats query) for identical cells.
pub fn scalar_masked_leaf(path: &str) -> bool {
    let parts = path.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && matches!(parts[0], "src_endpoint" | "dst_endpoint")
        && matches!((parts[1], parts[2]), ("location", "country" | "continent" | "provider") | ("autonomous_system", "number" | "name"))
}

pub fn sensitive(path: &str) -> bool {
    if scalar_masks_elided() && scalar_masked_leaf(path) {
        return false;
    }
    path.starts_with("enrichments")
        || path.starts_with("src_endpoint.location")
        || path.starts_with("dst_endpoint.location")
        || path.starts_with("src_endpoint.autonomous_system")
        || path.starts_with("dst_endpoint.autonomous_system")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrichment_read_sql_uses_one_denied_set_and_native_tuples() {
        let authority = ReadAuthorization::unknown(uuid::Uuid::nil(), chrono::Utc::now());
        for path in ["src_endpoint", "dst_endpoint", "src_endpoint.location.country", "dst_endpoint.autonomous_system.number"] {
            let sql = leaf_expression(path, &authority);
            assert!(sql.starts_with("if(arrayExists("), "{sql}");
            assert!(sql.contains("tupleElement(__nano_e, 'provider', '')"));
            assert_eq!(sql.matches("arrayFilter(").count(), usize::from(!path.contains('.')));
            assert!(!sql.contains("JSON"), "{sql}");
            assert!(!sql.contains("toJSONString"), "{sql}");
            assert!(!sql.contains("nano_enrichment_authority"));
        }
        let root = root_expression("src_endpoint", &authority);
        assert!(root.contains("__nano_root.* REPLACE"));
        assert!(root.contains("toTypeName(__nano_root)"));
        assert_eq!(root.matches("__nano_denied)").count(), 5);
        let leaf = leaf_expression("src_endpoint.location.country", &authority);
        assert_eq!(leaf.matches("'owned_fields'").count(), 1);
        assert!(!leaf.contains("CAST(tuple("));
    }

    #[tokio::test]
    async fn nested_reads_keep_dispatch_snapshot() {
        let tenant = uuid::Uuid::new_v4();
        let dispatch = chrono::Utc::now() - chrono::Duration::hours(1);
        execute(
            || async { ReadAuthorization::unknown(tenant, dispatch) },
            async {
                assert_eq!(current().evaluated_at(), dispatch);
                execute(|| async { panic!("must not resolve again") }, async {
                    assert_eq!(current().evaluated_at(), dispatch);
                    assert_eq!(
                        root_expression("enrichments", &current())
                            .matches("arrayFilter")
                            .count(),
                        1
                    );
                })
                .await
                .unwrap();
            },
        )
        .await
        .unwrap();
    }
}

#[cfg(test)]
mod nan2869_probe_debug {
    #[test]
    #[ignore]
    fn print_probe_sql() {
        use nanosiem_core::platform_enrichment::{AuthorizedRevision, FeedClass, RevisionReference};
        let tenant: uuid::Uuid = "b464ceb9-28a6-4249-8e29-3489627ac5f6".parse().unwrap();
        let now = chrono::Utc::now();
        let revision = AuthorizedRevision {
            tenant_id: tenant,
            reference: RevisionReference { feed_id: "ipinfo_lite".into(), feed_revision: 2, tier: "included".into(), grant_revision: 1, entitlement_revision: 1 },
            class: FeedClass::Baseline, digest: "0".repeat(64), mapping_revision: 1, deny_epoch: 0,
            valid_until: now + chrono::Duration::days(30), evaluated_at: now,
        };
        let authority = nanosiem_core::platform_enrichment::read::ReadAuthorization::from_resolved(tenant, now, &[revision]);
        println!("RIGHTS {}", authority.rights_len());
        println!("SQL {}", super::owner_denial_probe_sql(&authority));
    }
}
