// SPDX-License-Identifier: AGPL-3.0-or-later

//! Node-local tenant platform policy publication for lean cells (NAN-3005).
//!
//! A lean cell's tenant processes select the shared platform bundle
//! (`platform_bundle_dir/platform-<sha256>.nanpfb`) through their own
//! `platform_policy_file` ([`TenantPlatformPolicy`]). Nothing outside the node
//! can know the digest of the bundle the node built, so the policy has to be
//! composed next to the bundle: the `platform-bundle` sidecar
//! (`lake_platform_bundle serve`) reads
//!
//! - the node's bundle receipt (`<bundle dir>/current.json`, written by the
//!   same process), and
//! - one grants file per placed tenant (`<grants dir>/<tenant UUID>.json`),
//!   rendered by the control plane from
//!   `nano_shared.platform_enrichment_read_context(<tenant>)`,
//!
//! and writes `<policy root>/<tenant UUID>/policy.json` for each tenant.
//!
//! Rules (the same as the platform's `composeTenantPlatformPolicy`, so either
//! side may compose):
//! - per tenant, never shared: a grants file whose `tenant_id` differs from its
//!   file name is refused, and a policy is only built from its own file;
//! - a grant is kept only at the revision the bundle carries for that feed,
//!   capped by the bundle's own validity for it; anything else is dropped
//!   (fail closed: the reader then denies that feed);
//! - `revision` is monotonic: same content keeps the previous revision, any
//!   change is exactly `previous + 1` (`validate_successor` on the reader);
//! - the reader's bounds (64 grants, 16 KiB).

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure, Context, Result};
use chrono::{DateTime, Utc};
use nanosiem_core::platform_enrichment::PremiumStampRight;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::lean_platform_bundle::{PlatformGrant, TenantPlatformPolicy};

/// Schema of a control-plane grants file.
pub const GRANTS_SCHEMA: &str = "nano/lake-cell-platform-grants/1";
/// Schema of the node bundle receipt (`current.json`).
pub const RECEIPT_SCHEMA: &str = "nano/platform-bundle-receipt/1";
/// The baseline tier (`platform_enrichment_grant_revisions.class = 'baseline'`).
pub const BASELINE_TIER: &str = "included";
/// Reader bounds (`TenantPlatformPolicy::read_for_query`).
pub const POLICY_MAX_BYTES: usize = 16_384;
pub const POLICY_MAX_GRANTS: usize = 64;
/// A grants file is small: at most 65 rows (`LIMIT 65` in the read context).
const GRANTS_MAX_BYTES: u64 = 64 * 1024;
const GRANTS_MAX_ROWS: usize = 65;

/// Canonical lean cell layout under the `platform-feeds` volume. `feed_dir`
/// is the volume root; the feed cache and the bundles are sibling
/// directories below it, because the feed cache refuses any file it did not
/// write in its root and the bundle publisher refuses an output inside the
/// cache (and vice versa).
pub const FEED_DIR: &str = "/var/lib/nano-platform-feeds";
pub const FEED_CACHE_ROOT: &str = "/var/lib/nano-platform-feeds/cache";
pub const BUNDLE_DIR: &str = "/var/lib/nano-platform-feeds/bundles";
/// Outside `feed_dir`: `<root>/<tenant UUID>/policy.json`.
pub const POLICY_ROOT: &str = "/var/lib/nano-platform-policy";

/// One row of `nano_shared.platform_enrichment_read_context(<tenant>)`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantRow {
    pub feed_id: String,
    pub feed_revision: i64,
    pub tier: String,
    pub grant_revision: i64,
    pub entitlement_revision: i64,
    /// Carried for audit; the lean reader has no deny-epoch field.
    #[serde(default)]
    pub deny_epoch: Option<i64>,
    pub valid_until: DateTime<Utc>,
}

/// `<grants dir>/<tenant UUID>.json`, one per placed tenant (an empty `rows`
/// still yields a policy, so the supervisor's "every placed tenant has a
/// policy" rule holds even for a tenant with no entitlement).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantGrants {
    pub schema: String,
    pub tenant_id: Uuid,
    pub rows: Vec<GrantRow>,
}

/// What the policy composer needs from the node bundle receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleSummary {
    pub sha256: String,
    pub revisions: BTreeMap<String, i64>,
    pub valid_until: BTreeMap<String, DateTime<Utc>>,
}

#[derive(Deserialize)]
struct ReceiptView {
    schema: String,
    bundle_file: String,
    bundle_sha256: String,
    revisions: BTreeMap<String, i64>,
    valid_until: BTreeMap<String, DateTime<Utc>>,
}

impl BundleSummary {
    /// Parse `current.json` bytes. The receipt must name its own bundle file
    /// and carry a validity for exactly the revisions it lists.
    pub fn from_receipt(bytes: &[u8]) -> Result<Self> {
        let view: ReceiptView = serde_json::from_slice(bytes).context("bundle receipt")?;
        ensure!(
            view.schema == RECEIPT_SCHEMA,
            "unexpected bundle receipt schema"
        );
        ensure!(
            view.bundle_file == crate::lean_platform_bundle::bundle_file_name(&view.bundle_sha256)?,
            "bundle receipt names another file"
        );
        ensure!(
            view.valid_until.keys().eq(view.revisions.keys()),
            "bundle receipt validity does not cover its revisions"
        );
        Ok(Self {
            sha256: view.bundle_sha256,
            revisions: view.revisions,
            valid_until: view.valid_until,
        })
    }

    pub fn read(bundle_dir: &Path) -> Result<Self> {
        let path = bundle_dir.join("current.json");
        let meta =
            fs::symlink_metadata(&path).with_context(|| format!("{} missing", path.display()))?;
        ensure!(
            meta.file_type().is_file() && meta.len() <= 1024 * 1024,
            "bundle receipt must be a bounded regular file"
        );
        Self::from_receipt(&fs::read(&path)?)
    }
}

fn valid_feed(feed: &str) -> bool {
    !feed.is_empty()
        && feed.len() <= 64
        && feed
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The outcome of one composition.
#[derive(Debug)]
pub struct Composed {
    pub policy: TenantPlatformPolicy,
    /// Content (anything but the revision) differs from `previous`, or there
    /// was none: the file must be (re)written.
    pub changed: bool,
    /// Entitled feeds that were not granted (revision not in this bundle,
    /// expired, or no bundle validity), sorted.
    pub dropped: Vec<String>,
}

/// Compose one tenant's policy from its own grant rows and the node bundle.
pub fn compose(
    tenant: Uuid,
    rows: &[GrantRow],
    bundle: &BundleSummary,
    previous: Option<&TenantPlatformPolicy>,
    now: DateTime<Utc>,
) -> Result<Composed> {
    ensure!(!tenant.is_nil(), "platform policy tenant must not be nil");
    ensure!(
        bundle.sha256.len() == 64
            && bundle
                .sha256
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "bundle digest must be 64 lowercase hex"
    );
    ensure!(rows.len() <= GRANTS_MAX_ROWS, "too many grant rows");
    let mut grants: BTreeMap<String, PlatformGrant> = BTreeMap::new();
    let mut dropped = Vec::new();
    for row in rows {
        ensure!(
            valid_feed(&row.feed_id) && row.feed_revision > 0,
            "malformed grant row"
        );
        let premium = if row.tier == BASELINE_TIER {
            None
        } else {
            ensure!(
                !row.tier.is_empty() && row.grant_revision > 0 && row.entitlement_revision > 0,
                "malformed premium grant row"
            );
            Some(PremiumStampRight {
                tier: row.tier.clone(),
                grant_revision: row.grant_revision,
                entitlement_revision: row.entitlement_revision,
            })
        };
        // The read context lists every entitled revision of a feed: only the
        // one this bundle carries is kept, the first such row.
        if grants.contains_key(&row.feed_id) {
            continue;
        }
        let (Some(revision), Some(bundle_until)) = (
            bundle.revisions.get(&row.feed_id),
            bundle.valid_until.get(&row.feed_id),
        ) else {
            dropped.push(row.feed_id.clone());
            continue;
        };
        if *revision != row.feed_revision {
            dropped.push(row.feed_id.clone());
            continue;
        }
        let until = row.valid_until.min(*bundle_until);
        if until <= now {
            dropped.push(row.feed_id.clone());
            continue;
        }
        grants.insert(
            row.feed_id.clone(),
            PlatformGrant {
                feed_revision: row.feed_revision,
                valid_until: until,
                premium,
            },
        );
    }
    ensure!(
        grants.len() <= POLICY_MAX_GRANTS,
        "more than {POLICY_MAX_GRANTS} grants"
    );
    dropped.retain(|feed| !grants.contains_key(feed));
    dropped.sort();
    dropped.dedup();
    if let Some(previous) = previous {
        ensure!(
            previous.tenant_id == tenant,
            "previous policy belongs to another tenant"
        );
        ensure!(
            previous.revision > 0,
            "previous policy has no valid revision"
        );
    }
    let draft = TenantPlatformPolicy {
        tenant_id: tenant,
        revision: previous.map_or(1, |p| p.revision),
        bundle_sha256: bundle.sha256.clone(),
        grants,
    };
    let changed = match previous {
        None => true,
        Some(previous) => {
            let mut same = previous.clone();
            same.revision = draft.revision;
            same.fingerprint()? != draft.fingerprint()?
        }
    };
    let mut policy = draft;
    if changed {
        if let Some(previous) = previous {
            policy.revision = previous
                .revision
                .checked_add(1)
                .context("policy revision overflow")?;
            ensure!(
                policy.revision <= i64::MAX as u64,
                "policy revision overflow"
            );
        }
    }
    ensure!(
        serde_json::to_vec(&policy)?.len() < POLICY_MAX_BYTES,
        "policy exceeds {POLICY_MAX_BYTES} bytes"
    );
    if let Some(previous) = previous {
        policy.validate_successor(previous)?;
    }
    Ok(Composed {
        policy,
        changed,
        dropped,
    })
}

/// Read a grants file (it may be a Secret/ConfigMap projection, so symlinks
/// are followed here: only the publisher sidecar mounts it, never a tenant).
pub fn read_grants(path: &Path) -> Result<TenantGrants> {
    let meta = fs::metadata(path)?;
    ensure!(
        meta.is_file() && meta.len() <= GRANTS_MAX_BYTES,
        "grants file must be a bounded regular file"
    );
    let grants: TenantGrants = serde_json::from_slice(&fs::read(path)?).context("grants file")?;
    ensure!(grants.schema == GRANTS_SCHEMA, "unexpected grants schema");
    let expected = path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(".json"))
        .context("grants file must be named <tenant UUID>.json")?;
    ensure!(
        expected.parse::<Uuid>().ok() == Some(grants.tenant_id)
            && expected == grants.tenant_id.to_string(),
        "grants file tenant differs from its name"
    );
    ensure!(!grants.tenant_id.is_nil(), "grants tenant must not be nil");
    Ok(grants)
}

/// The tenant grants files in a directory, by tenant. Kubernetes projection
/// entries (`..data`, `..<timestamp>`) and anything not `<uuid>.json` are
/// ignored.
pub fn grants_files(dir: &Path) -> Result<BTreeMap<Uuid, PathBuf>> {
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(dir).with_context(|| format!("grants dir {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        let Ok(tenant) = stem.parse::<Uuid>() else {
            continue;
        };
        if tenant.to_string() != stem || tenant.is_nil() {
            continue;
        }
        out.insert(tenant, entry.path());
    }
    ensure!(out.len() <= 4096, "too many tenant grants files");
    Ok(out)
}

/// `<root>/<tenant>/policy.json`.
pub fn policy_path(root: &Path, tenant: Uuid) -> PathBuf {
    root.join(tenant.to_string()).join("policy.json")
}

/// The policy a tenant directory holds now, if any.
pub fn read_current(root: &Path, tenant: Uuid) -> Result<Option<TenantPlatformPolicy>> {
    let path = policy_path(root, tenant);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(meta) => {
            ensure!(
                meta.file_type().is_file(),
                "existing policy is not a regular file"
            );
            Ok(Some(TenantPlatformPolicy::read_for_query(&path, tenant)?))
        }
    }
}

fn direct_dir(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.file_type().is_dir(),
        "{} must be a real directory",
        path.display()
    );
    Ok(())
}

/// Write `policy` as `<root>/<tenant>/policy.json`: a new 0444 inode in the
/// tenant's own directory, validated by the reader's parser, then renamed
/// over the old one. The tenant directory is created 0755 (the supervisor
/// grants it read-only to that tenant's jail only).
pub fn write_policy(root: &Path, policy: &TenantPlatformPolicy) -> Result<PathBuf> {
    direct_dir(root)?;
    let dir = root.join(policy.tenant_id.to_string());
    match fs::symlink_metadata(&dir) {
        Ok(_) => direct_dir(&dir)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o755).create(&dir)?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))?;
        }
        Err(error) => return Err(error.into()),
    }
    let bytes = serde_json::to_vec(policy)?;
    ensure!(
        bytes.len() < POLICY_MAX_BYTES,
        "policy exceeds {POLICY_MAX_BYTES} bytes"
    );
    let tmp = dir.join(format!(".policy-{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<PathBuf> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o444))?;
        // Exactly what the tenant process will accept.
        let parsed = TenantPlatformPolicy::read_for_query(&tmp, policy.tenant_id)?;
        ensure!(
            parsed.fingerprint()? == policy.fingerprint()?,
            "policy did not round-trip"
        );
        let path = dir.join("policy.json");
        fs::rename(&tmp, &path)?;
        File::open(&dir)?.sync_all()?;
        Ok(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// The outcome of publishing one tenant.
#[derive(Debug)]
pub struct Published {
    pub tenant: Uuid,
    pub revision: u64,
    pub written: bool,
    pub grants: Vec<String>,
    pub dropped: Vec<String>,
}

/// Compose and (when changed) write one tenant's policy.
pub fn publish_tenant(
    root: &Path,
    grants_path: &Path,
    tenant: Uuid,
    bundle: &BundleSummary,
    now: DateTime<Utc>,
) -> Result<Published> {
    let grants = read_grants(grants_path)?;
    if grants.tenant_id != tenant {
        bail!("grants file tenant differs from its name");
    }
    let previous = read_current(root, tenant)?;
    let composed = compose(tenant, &grants.rows, bundle, previous.as_ref(), now)?;
    if composed.changed || previous.is_none() {
        write_policy(root, &composed.policy)?;
    }
    Ok(Published {
        tenant,
        revision: composed.policy.revision,
        written: composed.changed || previous.is_none(),
        grants: composed.policy.grants.keys().cloned().collect(),
        dropped: composed.dropped,
    })
}

/// Every `bundle_sha256` a policy under `root` names.
pub fn referenced_bundles(root: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(tenant) = name.parse::<Uuid>() else {
            continue;
        };
        // An unreadable policy keeps whatever it might name: GC nothing then.
        match read_current(root, tenant) {
            Ok(Some(policy)) => out.push(policy.bundle_sha256),
            Ok(None) => {}
            Err(error) => bail!("policy of {tenant} unreadable, bundle GC skipped: {error:#}"),
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    const A: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
    const B: &str = "7a2d2f3b-6c9f-4e5d-8b4f-1f3c8d0e2a11";

    fn bundle(sha: char, now: DateTime<Utc>) -> BundleSummary {
        BundleSummary {
            sha256: sha.to_string().repeat(64),
            revisions: BTreeMap::from([
                ("ipinfo_lite".into(), 2),
                ("threatfox".into(), 4),
                ("synthient".into(), 3),
            ]),
            valid_until: BTreeMap::from([
                ("ipinfo_lite".into(), now + Duration::hours(2)),
                ("threatfox".into(), now + Duration::hours(1)),
                ("synthient".into(), now + Duration::hours(1)),
            ]),
        }
    }

    fn row(feed: &str, revision: i64, tier: &str, until: DateTime<Utc>) -> GrantRow {
        GrantRow {
            feed_id: feed.into(),
            feed_revision: revision,
            tier: tier.into(),
            grant_revision: 1,
            entitlement_revision: 1,
            deny_epoch: Some(0),
            valid_until: until,
        }
    }

    #[test]
    fn grants_follow_the_bundle_revision_and_validity() {
        let now = Utc::now();
        let tenant: Uuid = A.parse().unwrap();
        let rows = vec![
            row("ipinfo_lite", 1, BASELINE_TIER, now + Duration::days(9)), // older revision
            row("ipinfo_lite", 2, BASELINE_TIER, now + Duration::days(9)),
            row("threatfox", 5, BASELINE_TIER, now + Duration::days(9)), // bundle has 4
            row("tor_exit_nodes", 1, BASELINE_TIER, now + Duration::days(9)), // not in bundle
            row("synthient", 3, "pro", now + Duration::minutes(5)),
        ];
        let composed = compose(tenant, &rows, &bundle('a', now), None, now).unwrap();
        assert!(composed.changed);
        let p = composed.policy;
        assert_eq!(p.revision, 1);
        assert_eq!(
            p.grants.keys().collect::<Vec<_>>(),
            vec!["ipinfo_lite", "synthient"]
        );
        // Capped by the bundle's own validity, never outliving it.
        assert_eq!(
            p.grants["ipinfo_lite"].valid_until,
            now + Duration::hours(2)
        );
        assert!(
            p.grants["ipinfo_lite"].premium.is_none(),
            "baseline tier is not premium"
        );
        assert_eq!(
            p.grants["synthient"].valid_until,
            now + Duration::minutes(5)
        );
        assert_eq!(p.grants["synthient"].premium.as_ref().unwrap().tier, "pro");
        assert_eq!(composed.dropped, vec!["threatfox", "tor_exit_nodes"]);
    }

    #[test]
    fn revision_is_monotonic_and_stable() {
        let now = Utc::now();
        let tenant: Uuid = A.parse().unwrap();
        let rows = vec![row(
            "ipinfo_lite",
            2,
            BASELINE_TIER,
            now + Duration::days(1),
        )];
        let first = compose(tenant, &rows, &bundle('a', now), None, now)
            .unwrap()
            .policy;
        let same = compose(tenant, &rows, &bundle('a', now), Some(&first), now).unwrap();
        assert!(!same.changed);
        assert_eq!(same.policy.revision, 1);
        let moved = compose(tenant, &rows, &bundle('b', now), Some(&first), now).unwrap();
        assert!(moved.changed);
        assert_eq!(moved.policy.revision, 2);
        moved.policy.validate_successor(&first).unwrap();
        let revoked = compose(tenant, &[], &bundle('b', now), Some(&moved.policy), now).unwrap();
        assert_eq!(revoked.policy.revision, 3);
        assert!(revoked.policy.grants.is_empty());
    }

    #[test]
    fn another_tenants_previous_policy_or_grants_file_is_refused() {
        let now = Utc::now();
        let a: Uuid = A.parse().unwrap();
        let b: Uuid = B.parse().unwrap();
        let of_b = compose(b, &[], &bundle('a', now), None, now)
            .unwrap()
            .policy;
        assert!(compose(a, &[], &bundle('a', now), Some(&of_b), now).is_err());

        let dir = tempfile::tempdir().unwrap();
        let grants = TenantGrants {
            schema: GRANTS_SCHEMA.into(),
            tenant_id: b,
            rows: vec![],
        };
        // B's grants saved under A's name: refused, never written as A's policy.
        let path = dir.path().join(format!("{A}.json"));
        fs::write(&path, serde_json::to_vec(&grants).unwrap()).unwrap();
        let root = dir.path().join("policy");
        fs::create_dir(&root).unwrap();
        assert!(publish_tenant(&root, &path, a, &bundle('a', now), now).is_err());
        assert!(!policy_path(&root, a).exists());
    }

    #[test]
    fn publish_writes_a_reader_valid_policy_once_and_bumps_on_change() {
        use std::os::unix::fs::MetadataExt;
        let now = Utc::now();
        let a: Uuid = A.parse().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let grants_dir = dir.path().join("grants");
        let root = dir.path().join("policy");
        fs::create_dir_all(&grants_dir).unwrap();
        fs::create_dir_all(&root).unwrap();
        // Kubernetes projection debris is ignored.
        fs::create_dir(grants_dir.join("..data")).unwrap();
        fs::write(grants_dir.join("README"), b"x").unwrap();
        let grants = TenantGrants {
            schema: GRANTS_SCHEMA.into(),
            tenant_id: a,
            rows: vec![row(
                "ipinfo_lite",
                2,
                BASELINE_TIER,
                now + Duration::days(1),
            )],
        };
        fs::write(
            grants_dir.join(format!("{A}.json")),
            serde_json::to_vec(&grants).unwrap(),
        )
        .unwrap();
        let files = grants_files(&grants_dir).unwrap();
        assert_eq!(files.keys().collect::<Vec<_>>(), vec![&a]);

        let first = publish_tenant(&root, &files[&a], a, &bundle('a', now), now).unwrap();
        assert!(first.written);
        let path = policy_path(&root, a);
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_file() && meta.nlink() == 1 && meta.mode() & 0o222 == 0);
        let inode = meta.ino();
        let read = TenantPlatformPolicy::read_for_query(&path, a).unwrap();
        assert_eq!(read.grants["ipinfo_lite"].feed_revision, 2);

        let again = publish_tenant(&root, &files[&a], a, &bundle('a', now), now).unwrap();
        assert!(!again.written);
        assert_eq!(
            fs::symlink_metadata(&path).unwrap().ino(),
            inode,
            "unchanged content is not rewritten"
        );

        let moved = publish_tenant(&root, &files[&a], a, &bundle('b', now), now).unwrap();
        assert!(moved.written);
        assert_eq!(moved.revision, 2);
        assert_eq!(referenced_bundles(&root).unwrap(), vec!["b".repeat(64)]);
    }

    #[test]
    fn receipt_must_name_its_file_and_cover_its_revisions() {
        let sha = "c".repeat(64);
        let now = Utc::now();
        let good = serde_json::json!({"schema": RECEIPT_SCHEMA, "format": "NANPFB01",
            "bundle_file": format!("platform-{sha}.nanpfb"), "bundle_sha256": sha, "bundle_bytes": 10,
            "revisions": {"ipinfo_lite": 2}, "valid_until": {"ipinfo_lite": now}, "selections": []});
        let parsed = BundleSummary::from_receipt(&serde_json::to_vec(&good).unwrap()).unwrap();
        assert_eq!(parsed.revisions["ipinfo_lite"], 2);
        let mut other = good.clone();
        other["bundle_file"] = serde_json::json!("platform-x.nanpfb");
        assert!(BundleSummary::from_receipt(&serde_json::to_vec(&other).unwrap()).is_err());
        let mut uncovered = good;
        uncovered["valid_until"] = serde_json::json!({});
        assert!(BundleSummary::from_receipt(&serde_json::to_vec(&uncovered).unwrap()).is_err());
    }

    /// The lean cell layout these constants describe is the one the
    /// supervisor accepts, and the image ships the publisher behind the
    /// `lean_platform_publisher_v1` cell feature.
    #[test]
    fn cell_feature_lean_platform_publisher_v1_is_backed() {
        assert!(nanosiem_lake_cell::features::CELL_FEATURES.contains(&"lean_platform_publisher_v1"));
        let bundle = Path::new(BUNDLE_DIR);
        let cache = Path::new(FEED_CACHE_ROOT);
        assert!(bundle.starts_with(FEED_DIR) && cache.starts_with(FEED_DIR));
        assert!(!bundle.starts_with(cache) && !cache.starts_with(bundle));
        assert!(
            !Path::new(POLICY_ROOT).starts_with(FEED_DIR)
                && !Path::new(FEED_DIR).starts_with(POLICY_ROOT)
        );
    }
}
