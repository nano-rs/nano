// SPDX-License-Identifier: AGPL-3.0-or-later

//! Self-hosted platform feeds (NAN-4759 part B): the sovereign and open-core
//! consumer of the portable signed feed bundle.
//!
//! Hosted cells build their node bundle from the platform feed cache
//! (`lake_platform_bundle serve`, NAN-3005). A self-hosted install has no
//! cache and makes no runtime egress, so its bundle arrives as one portable,
//! signed file, fetched at install time or by `nano feeds update` (online, or
//! `--file` for an offline drop). This module installs a verified import into
//! the SAME layout the hosted publisher writes and the cell already reads:
//!
//! - `<bundle dir>/platform-<sha256>.nanpfb`, a NANPFB01 bundle
//!   ([`PlatformBundle::publish_verified`]) whose per-feed validity is the
//!   feed's `hard_expiry`, so the reader stops stamping a feed past it;
//! - `<bundle dir>/current.json`, the receipt ([`RECEIPT_SCHEMA`]) the policy
//!   composer reads, plus the self-hosted provenance (`source`, per-feed
//!   `produced_at`/`hard_expiry`/license) that the freshness status reads;
//! - `<policy root>/<tenant>/policy.json`, composed by
//!   [`lean_platform_policy::compose`] from the tenant's grants file. A
//!   self-hosted install's default grants file ([`ALL_BUNDLED_GRANTS_SCHEMA`])
//!   grants every bundled feed at the revision the bundle carries.
//!
//! Each tenant's ingest re-reads its policy every 30 s and rotates to the new
//! bundle without a restart (`part_ingest::cell::plan_enrichment_refresh`).
//! Expiry stops new stamping only; stamped values stay in the rows they were
//! written to and are never masked on read.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure, Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use nanosiem_core::platform_enrichment::portable::{self, KeyRing, VerifiedBundle};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::lean_platform_bundle::{bundle_file_name, PlatformBundle, PlatformBundleSource};
use crate::lean_platform_policy::{
    self as policy, BundleSummary, GrantRow, TenantGrants, BASELINE_TIER, GRANTS_SCHEMA, RECEIPT_SCHEMA,
};
pub use nanosiem_core::platform_enrichment::self_hosted::{
    status, BundleReceipt as Receipt, FeedProvenance, FeedState, FeedStatus, FeedsStatus, MAX_NOTICE_BYTES, SOURCE_EMPTY,
    SOURCE_PORTABLE, STALE_AFTER_DAYS,
};

/// A self-hosted install's default grants file: every feed the installed
/// bundle carries, at its revision, until its `hard_expiry`.
pub const ALL_BUNDLED_GRANTS_SCHEMA: &str = "nano/lake-cell-platform-grants-all-bundled/1";
/// Tolerated clock skew between the publisher and this host.
const PRODUCED_AT_SKEW: Duration = Duration::minutes(10);
const MAX_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;
const GRANTS_MAX_BYTES: u64 = 64 * 1024;

/// One feed of a verified portable bundle: the signed descriptor's terms
/// (NAN-4759 C19 `FeedEntry`).
#[derive(Clone, Debug)]
struct PortableFeed {
    pub feed_id: String,
    pub revision: i64,
    pub produced_at: DateTime<Utc>,
    pub hard_expiry: DateTime<Utc>,
    pub license_id: String,
    pub terms_revision: String,
    pub records: u64,
}

/// A verified portable bundle (C19 `NANFEED1` container): the digest of the
/// signed file, the descriptor's sequence and feeds, the payload digest (one
/// unmodified hosted NANPFB01 bundle) and the attribution notice that must
/// travel with the data. Only the verify library builds one from a file.
#[derive(Clone, Debug)]
struct PortableImport {
    pub source_sha256: String,
    pub sequence: u64,
    pub payload_sha256: String,
    pub feeds: Vec<PortableFeed>,
    pub notice: String,
    signed_descriptor: Option<portable::SignedDescriptor>,
}

/// Writes the verified payload into the bundle dir as
/// `platform-<payload sha256>.nanpfb` (sealed 0444, re-hashed while copied)
/// and returns its path: the verify library's `install_payload`.
type PlacePayload<'a> = Box<dyn FnOnce(&Path) -> Result<PathBuf> + 'a>;

/// Import the portable signed artifact through the shared verifier. The CLI
/// supplies the compiled-in production ring; callers cannot install raw NANPFB01
/// bytes through this API. Verification finishes before any directory is written.
pub fn import_file(bundle_dir: &Path, file: &Path, ring: &KeyRing, now: DateTime<Utc>) -> Result<Receipt> {
    let verified = portable::verify_file(file, ring)?;
    verified.accept_after(None, now)?;
    let d = verified.descriptor();
    ensure!(d.produced_at <= now + PRODUCED_AT_SKEW, "bundle produced in the future");
    let source = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(file)?;
    ensure!(source.metadata()?.is_file(), "portable bundle must be regular");
    let mut hash = Sha256::new();
    let cap = portable::MAX_PAYLOAD_BYTES + 16 + 65536;
    let copied = std::io::copy(&mut std::io::Read::take(source, cap + 1), &mut hash)?;
    ensure!(copied <= cap, "portable bundle exceeds its size bound");
    let import = PortableImport {
        source_sha256: hex::encode(hash.finalize()),
        sequence: d.sequence,
        payload_sha256: d.payload.sha256.clone(),
        feeds: d.feeds.iter().map(|(id, f)| PortableFeed {
            feed_id: id.clone(), revision: f.revision, produced_at: f.produced_at,
            hard_expiry: f.hard_expiry, license_id: f.license_id.clone(),
            terms_revision: f.terms_revision.clone(), records: f.row_count,
        }).collect(),
        notice: d.notice.clone(),
        signed_descriptor: Some(verified.signed().clone()),
    };
    let source = file.to_path_buf();
    let place_verified = verified.clone();
    install(bundle_dir, &import, Box::new(move |dir| Ok(place_verified.install_payload(&source, dir)?)), now, Some(&verified))
}

/// Installed descriptors were verified before the sealed receipt was written.
/// Compare their signed terms without requiring a key retired in a later release.
fn receipt_descriptor(receipt: &Receipt) -> Result<&portable::SignedDescriptor> {
    let signed = receipt.signed_descriptor.as_ref().context("installed bundle lacks a signed descriptor")?;
    let d = &signed.descriptor;
    d.validate()?;
    ensure!(d.payload.sha256 == receipt.bundle_sha256 && d.payload.bytes == receipt.bundle_bytes
        && Some(d.sequence) == receipt.sequence, "installed descriptor differs from its receipt");
    ensure!(d.feeds.iter().map(|(id, f)| (id.clone(), f.revision)).collect::<BTreeMap<_, _>>() == receipt.revisions
        && d.feeds.iter().map(|(id, f)| (id.clone(), f.hard_expiry)).collect::<BTreeMap<_, _>>() == receipt.valid_until,
        "installed descriptor feed terms differ from its receipt");
    Ok(signed)
}

/// Verify the distribution response before following its download capability.
/// Return no URL only when the exact signed descriptor is already installed.
pub fn check_current(bundle_dir: &Path, file: &Path, ring: &KeyRing) -> Result<Option<String>> {
    let meta = fs::symlink_metadata(file)?;
    ensure!(meta.file_type().is_file() && meta.len() <= 1024 * 1024, "feed response must be a bounded regular file");
    let response: serde_json::Value = serde_json::from_slice(&fs::read(file)?)?;
    let signed = portable::SignedDescriptor::from_json(&serde_json::to_vec(&response["descriptor"])?, ring)?;
    ensure!(response["bundle_sha256"].as_str() == Some(signed.descriptor.payload.sha256.as_str()), "feed response digest differs from its signed descriptor");
    let url = response["bundle_url"].as_str().context("feed response download URL missing")?;
    let parsed = reqwest::Url::parse(url)?;
    ensure!(parsed.scheme() == "https" && parsed.host_str().is_some() && parsed.username().is_empty() && parsed.password().is_none()
        && !url.chars().any(|c| c.is_control() || c.is_whitespace()), "feed download URL must be https");
    if let Some(receipt) = read_receipt(bundle_dir)?.filter(|r| r.source.as_deref() == Some(SOURCE_PORTABLE)) {
        sealed_regular(&bundle_dir.join("current.json"), 1024 * 1024)?;
        if receipt_descriptor(&receipt)?.descriptor == signed.descriptor {
            return Ok(None);
        }
    }
    Ok(Some(url.to_owned()))
}

/// Read `current.json`, checked by both the composer's parser and the
/// self-hosted one.
fn read_receipt(bundle_dir: &Path) -> Result<Option<Receipt>> {
    let receipt = Receipt::read(bundle_dir)?;
    if receipt.is_some() {
        BundleSummary::read(bundle_dir)?;
    }
    Ok(receipt)
}

fn valid_feed(feed: &str) -> bool {
    !feed.is_empty() && feed.len() <= 64 && feed.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn direct_dir(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "{} must be absolute", path.display());
    let mut current = PathBuf::from("/");
    for part in path.components().skip(1) {
        current.push(part);
        ensure!(fs::symlink_metadata(&current)?.file_type().is_dir(), "{} has a symlink or non-directory component", path.display());
    }
    Ok(())
}

fn sealed_regular(path: &Path, max: u64) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.file_type().is_file() && m.nlink() == 1 && m.len() <= max && m.mode() & 0o222 == 0,
        "{} is mutable, linked, oversized or not a regular file",
        path.display()
    );
    Ok(())
}

struct RemoveOnDrop(PathBuf);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Serialize writers of one bundle directory (the same lock file the hosted
/// publisher takes).
fn lock_dir(dir: &Path) -> Result<File> {
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join("publication.lock"))?;
    ensure!(lock.metadata()?.is_file(), "publication lock is not regular");
    ensure!(unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } == 0, "publication lock unavailable");
    Ok(lock)
}

/// Write `bytes` as a sealed 0444 file at `dir/name` (new inode, renamed in).
fn write_sealed(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let tmp = dir.join(format!(".receipt-{}.tmp", Uuid::new_v4()));
    let _cleanup = RemoveOnDrop(tmp.clone());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o444))?;
    let target = dir.join(name);
    if let Ok(meta) = fs::symlink_metadata(&target) {
        ensure!(meta.file_type().is_file(), "{} is not a regular file", target.display());
    }
    fs::rename(&tmp, &target)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Move a staged bundle to its content-addressed name. An existing file of
/// that name must be the same bundle.
fn promote(dir: &Path, tmp: &Path, digest: &str) -> Result<String> {
    let name = bundle_file_name(digest)?;
    let target = dir.join(&name);
    if fs::symlink_metadata(&target).is_ok() {
        sealed_regular(&target, MAX_BUNDLE_BYTES)?;
        PlatformBundle::open(&target, digest).context("existing bundle differs from its name")?;
        fs::remove_file(tmp)?;
    } else {
        fs::rename(tmp, &target)?;
        File::open(dir)?.sync_all()?;
    }
    Ok(name)
}

/// Ensure the bundle directory exists as a real 0755 directory (tenant jails
/// traverse it; none can write it).
pub fn ensure_bundle_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match fs::symlink_metadata(dir) {
        Ok(meta) => ensure!(meta.file_type().is_dir(), "bundle dir must be a real directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new().recursive(true).mode(0o755).create(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
        }
        Err(error) => return Err(error.into()),
    }
    direct_dir(dir)
}

/// Check a verified import's terms before anything is written.
fn validate_import(import: &PortableImport, previous: Option<&Receipt>, now: DateTime<Utc>) -> Result<()> {
    let hex = |s: &str| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    ensure!(hex(&import.source_sha256) && hex(&import.payload_sha256), "portable bundle digests must be 64 lowercase hex");
    ensure!(import.sequence > 0, "portable bundle sequence must be positive");
    ensure!(!import.feeds.is_empty() && import.feeds.len() <= 64, "portable bundle must carry 1..=64 feeds");
    ensure!(!import.notice.trim().is_empty() && import.notice.len() as u64 <= MAX_NOTICE_BYTES, "portable bundle notice is missing or oversized");
    ensure!(import.feeds.iter().any(|f| f.hard_expiry > now), "every feed of the bundle is past its hard expiry");
    let mut seen = std::collections::BTreeSet::new();
    for feed in &import.feeds {
        ensure!(valid_feed(&feed.feed_id) && seen.insert(feed.feed_id.as_str()), "invalid or repeated feed {:?}", feed.feed_id);
        // Contracted, non-redistributable data never travels in this path.
        ensure!(feed.feed_id != "synthient", "synthient is not a portable feed");
        ensure!(feed.revision > 0, "{}: revision must be positive", feed.feed_id);
        ensure!(feed.produced_at <= now + PRODUCED_AT_SKEW, "{}: produced in the future (check this host's clock)", feed.feed_id);
        ensure!(feed.produced_at < feed.hard_expiry, "{}: expires before it was produced", feed.feed_id);
        ensure!(
            !feed.license_id.is_empty() && feed.license_id.len() <= 128 && !feed.terms_revision.is_empty() && feed.terms_revision.len() <= 128,
            "{}: license or terms revision missing",
            feed.feed_id
        );
        if let Some(old) = previous.and_then(|p| p.revisions.get(&feed.feed_id)) {
            ensure!(
                feed.revision >= *old,
                "{}: revision {} is older than the installed {old} (a rollback is refused)",
                feed.feed_id,
                feed.revision
            );
        }
    }
    if let Some(old) = previous.and_then(|p| p.sequence) {
        let same = previous.is_some_and(|p| p.bundle_sha256 == import.payload_sha256);
        ensure!(
            import.sequence > old || (import.sequence == old && same),
            "bundle sequence {} is older than the installed {old} (a rollback is refused)",
            import.sequence
        );
    }
    Ok(())
}

/// The payload header must carry exactly the signed revisions and expiries,
/// so the cell's own per-feed expiry gate enforces the signed hard expiry.
fn check_payload(bundle: &PlatformBundle, import: &PortableImport) -> Result<()> {
    ensure!(!bundle.has_prefix(), "portable payload carries a premium prefix section");
    let revisions: BTreeMap<&str, i64> = import.feeds.iter().map(|f| (f.feed_id.as_str(), f.revision)).collect();
    let expiry: BTreeMap<&str, DateTime<Utc>> = import.feeds.iter().map(|f| (f.feed_id.as_str(), f.hard_expiry)).collect();
    ensure!(
        bundle.feed_revisions().iter().map(|(k, v)| (k.as_str(), *v)).eq(revisions),
        "payload feed revisions differ from the signed descriptor"
    );
    ensure!(
        bundle.feed_valid_until().iter().map(|(k, v)| (k.as_str(), *v)).eq(expiry),
        "payload feed expiry differs from the signed descriptor"
    );
    Ok(())
}

/// Install a verified portable bundle as the node bundle. `place` writes the
/// payload (the verify library's `install_payload`); it is then opened and
/// verified by the cell's own reader and checked against the signed terms.
/// Atomic: the bundle and the notice are new sealed inodes, and
/// `current.json` is renamed over the old receipt last, so a reader sees the
/// old or the new bundle, never a mix. Returns the receipt now installed.
fn install(bundle_dir: &Path, import: &PortableImport, place: PlacePayload<'_>, now: DateTime<Utc>, verified: Option<&VerifiedBundle>) -> Result<Receipt> {
    ensure_bundle_dir(bundle_dir)?;
    let _lock = lock_dir(bundle_dir)?;
    let previous = read_receipt(bundle_dir)?;
    if let Some(verified) = verified {
        if previous.as_ref().is_some_and(|p| p.source.as_deref() == Some(SOURCE_PORTABLE)) {
            sealed_regular(&bundle_dir.join("current.json"), 1024 * 1024)?;
        }
        let installed = previous.as_ref().filter(|p| p.source.as_deref() == Some(SOURCE_PORTABLE))
            .map(|p| receipt_descriptor(p).map(|signed| &signed.descriptor)).transpose()?;
        verified.accept_after(installed, now)?;
    }
    validate_import(import, previous.as_ref(), now)?;
    if let Some(previous) = &previous {
        if previous.bundle_sha256 == import.payload_sha256 && previous.source.as_deref() == Some(SOURCE_PORTABLE)
            && previous.signed_descriptor == import.signed_descriptor && previous.sequence == Some(import.sequence) {
            return Ok(previous.clone());
        }
    }
    let bundle_file = bundle_file_name(&import.payload_sha256)?;
    let placed = place(bundle_dir)?;
    ensure!(placed == bundle_dir.join(&bundle_file), "payload was placed as {}, not {bundle_file}", placed.display());
    sealed_regular(&placed, MAX_BUNDLE_BYTES)?;
    let opened = PlatformBundle::open(&placed, &import.payload_sha256)?;
    check_payload(&opened, import)?;
    let bundle_bytes = opened.bytes() as u64;
    drop(opened);
    let notice_file = format!("notice-{}.txt", import.payload_sha256);
    write_sealed(bundle_dir, &notice_file, import.notice.as_bytes())?;
    let receipt = Receipt {
        schema: RECEIPT_SCHEMA.into(),
        format: "NANPFB01".into(),
        bundle_file,
        bundle_sha256: import.payload_sha256.clone(),
        bundle_bytes,
        revisions: import.feeds.iter().map(|f| (f.feed_id.clone(), f.revision)).collect(),
        valid_until: import.feeds.iter().map(|f| (f.feed_id.clone(), f.hard_expiry)).collect(),
        source: Some(SOURCE_PORTABLE.into()),
        source_sha256: Some(import.source_sha256.clone()),
        sequence: Some(import.sequence),
        signed_descriptor: import.signed_descriptor.clone(),
        installed_at: Some(now),
        notice_file: Some(notice_file),
        feeds: import
            .feeds
            .iter()
            .map(|f| {
                (f.feed_id.clone(), FeedProvenance {
                    produced_at: f.produced_at,
                    hard_expiry: f.hard_expiry,
                    license_id: f.license_id.clone(),
                    terms_revision: f.terms_revision.clone(),
                    records: f.records,
                })
            })
            .collect(),
    };
    write_sealed(bundle_dir, "current.json", &serde_json::to_vec(&receipt)?)?;
    Ok(receipt)
}

/// Place an already verified NANPFB01 file (a test fixture, or a payload the
/// verify library extracted) under its content-addressed name: copied to a
/// new sealed inode, re-hashed, then renamed in.
#[cfg(test)]
fn place_nanpfb_file(source: &Path, sha256: &str) -> PlacePayload<'static> {
    let source = source.to_path_buf();
    let sha256 = sha256.to_string();
    Box::new(move |dir: &Path| {
        let tmp = dir.join(format!(".bundle-{}.tmp", Uuid::new_v4()));
        let _cleanup = RemoveOnDrop(tmp.clone());
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        let mut input = File::open(&source)?;
        ensure!(input.metadata()?.len() <= MAX_BUNDLE_BYTES, "payload exceeds its bound");
        std::io::copy(&mut input, &mut out)?;
        out.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o444))?;
        PlatformBundle::open(&tmp, &sha256).context("payload digest")?;
        promote(dir, &tmp, &sha256)?;
        Ok(dir.join(bundle_file_name(&sha256)?))
    })
}

/// A bundle with no feed: published only while nothing was ever installed, so
/// every tenant gets a reader-valid policy (no grant) and ingest starts,
/// stamping nothing until the first import lands.
pub fn ensure_installed_or_empty(bundle_dir: &Path, now: DateTime<Utc>) -> Result<Receipt> {
    ensure_bundle_dir(bundle_dir)?;
    let _lock = lock_dir(bundle_dir)?;
    if let Some(receipt) = read_receipt(bundle_dir)? {
        // Losing an installed file must not reset signed rollback history.
        PlatformBundleSource::Dir(bundle_dir.to_path_buf()).open(&receipt.bundle_sha256)?;
        return Ok(receipt);
    }
    let tmp = bundle_dir.join(format!(".bundle-{}.tmp", Uuid::new_v4()));
    let _tmp_cleanup = RemoveOnDrop(tmp.clone());
    let digest = PlatformBundle::publish_verified(&tmp, None, &[], None, BTreeMap::new(), BTreeMap::new())?;
    let bytes = fs::metadata(&tmp)?.len();
    let bundle_file = promote(bundle_dir, &tmp, &digest)?;
    let receipt = Receipt {
        schema: RECEIPT_SCHEMA.into(),
        format: "NANPFB01".into(),
        bundle_file,
        bundle_sha256: digest,
        bundle_bytes: bytes,
        revisions: BTreeMap::new(),
        valid_until: BTreeMap::new(),
        source: Some(SOURCE_EMPTY.into()),
        source_sha256: None,
        sequence: None,
        signed_descriptor: None,
        installed_at: Some(now),
        notice_file: None,
        feeds: BTreeMap::new(),
    };
    write_sealed(bundle_dir, "current.json", &serde_json::to_vec(&receipt)?)?;
    Ok(receipt)
}

/// A tenant grants file of either schema: the control-plane rows, or the
/// self-hosted "every bundled feed" default.
fn read_tenant_grants(path: &Path, bundle: &BundleSummary) -> Result<TenantGrants> {
    let meta = fs::metadata(path)?;
    ensure!(meta.is_file() && meta.len() <= GRANTS_MAX_BYTES, "grants file must be a bounded regular file");
    let grants: TenantGrants = serde_json::from_slice(&fs::read(path)?).context("grants file")?;
    let stem = path.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".json")).context("grants file must be named <tenant UUID>.json")?;
    ensure!(stem == grants.tenant_id.to_string() && !grants.tenant_id.is_nil(), "grants file tenant differs from its name");
    match grants.schema.as_str() {
        GRANTS_SCHEMA => Ok(grants),
        ALL_BUNDLED_GRANTS_SCHEMA => {
            ensure!(grants.rows.is_empty(), "an all-bundled grants file carries no rows");
            let rows = bundle
                .revisions
                .iter()
                .filter_map(|(feed, revision)| {
                    bundle.valid_until.get(feed).map(|until| GrantRow {
                        feed_id: feed.clone(),
                        feed_revision: *revision,
                        tier: BASELINE_TIER.into(),
                        grant_revision: 1,
                        entitlement_revision: 1,
                        deny_epoch: None,
                        valid_until: *until,
                    })
                })
                .collect();
            Ok(TenantGrants { schema: GRANTS_SCHEMA.into(), tenant_id: grants.tenant_id, rows })
        }
        other => bail!("unexpected grants schema {other:?}"),
    }
}

/// The default grants file a self-hosted install writes for each tenant.
pub fn all_bundled_grants(tenant: Uuid) -> Result<Vec<u8>> {
    ensure!(!tenant.is_nil(), "grants tenant must not be nil");
    Ok(serde_json::to_vec_pretty(&serde_json::json!({
        "schema": ALL_BUNDLED_GRANTS_SCHEMA, "tenant_id": tenant, "rows": [],
    }))?)
}

/// One tenant's outcome in a publication cycle.
#[derive(Debug, Serialize)]
pub struct TenantCycle {
    pub tenant_id: Uuid,
    pub revision: Option<u64>,
    pub written: bool,
    pub grants: Vec<String>,
    pub dropped: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CycleReport {
    pub event: &'static str,
    pub bundle_sha256: String,
    pub bundle_feeds: Vec<String>,
    pub tenants: Vec<TenantCycle>,
    pub tenant_errors: usize,
    pub gc_removed: Vec<String>,
}

/// Paths of one node's self-hosted feed layout.
#[derive(Clone, Debug)]
pub struct Layout {
    pub bundle_dir: PathBuf,
    pub policy_root: PathBuf,
    pub grants_dir: PathBuf,
}

impl Layout {
    pub fn validate(&self) -> Result<()> {
        for path in [&self.bundle_dir, &self.policy_root, &self.grants_dir] {
            ensure!(path.is_absolute(), "{} must be absolute", path.display());
        }
        ensure!(
            !self.policy_root.starts_with(&self.bundle_dir) && !self.bundle_dir.starts_with(&self.policy_root),
            "tenant policies and the shared bundle dir must not overlap"
        );
        Ok(())
    }

    /// One publication cycle: ensure a bundle exists, compose every tenant's
    /// policy from its grants file and the installed bundle, then GC bundles
    /// no policy names any more (after `gc_grace`, so a process still
    /// mapping one keeps its inode and a fresh one never opens a dead name).
    pub fn cycle(&self, now: DateTime<Utc>, unreferenced: &mut BTreeMap<String, DateTime<Utc>>, gc_grace: Duration) -> Result<CycleReport> {
        self.validate()?;
        direct_dir(&self.policy_root)?;
        let receipt = ensure_installed_or_empty(&self.bundle_dir, now)?;
        let summary = BundleSummary::read(&self.bundle_dir)?;
        ensure!(summary.sha256 == receipt.bundle_sha256, "bundle receipt changed while publishing");
        let mut tenants = Vec::new();
        for (tenant, path) in policy::grants_files(&self.grants_dir)? {
            let outcome = (|| -> Result<TenantCycle> {
                let grants = read_tenant_grants(&path, &summary)?;
                ensure!(grants.tenant_id == tenant, "grants file tenant differs from its name");
                let previous = policy::read_current(&self.policy_root, tenant)?;
                let composed = policy::compose(tenant, &grants.rows, &summary, previous.as_ref(), now)?;
                let written = composed.changed || previous.is_none();
                if written {
                    policy::write_policy(&self.policy_root, &composed.policy)?;
                }
                Ok(TenantCycle {
                    tenant_id: tenant,
                    revision: Some(composed.policy.revision),
                    written,
                    grants: composed.policy.grants.keys().cloned().collect(),
                    dropped: composed.dropped,
                    error: None,
                })
            })();
            tenants.push(outcome.unwrap_or_else(|error| TenantCycle {
                tenant_id: tenant,
                revision: None,
                written: false,
                grants: Vec::new(),
                dropped: Vec::new(),
                error: Some(format!("{error:#}")),
            }));
        }
        let tenant_errors = tenants.iter().filter(|t| t.error.is_some()).count();
        let gc_removed = self.gc(&summary.sha256, now, unreferenced, gc_grace).unwrap_or_else(|error| {
            eprintln!("{}", serde_json::json!({"event": "platform_feeds_gc_skipped", "error": format!("{error:#}")}));
            Vec::new()
        });
        Ok(CycleReport {
            event: "platform_feeds_cycle",
            bundle_feeds: summary.revisions.keys().cloned().collect(),
            bundle_sha256: summary.sha256,
            tenants,
            tenant_errors,
            gc_removed,
        })
    }

    fn gc(&self, current: &str, now: DateTime<Utc>, unreferenced: &mut BTreeMap<String, DateTime<Utc>>, grace: Duration) -> Result<Vec<String>> {
        let _lock = lock_dir(&self.bundle_dir)?;
        let mut referenced = policy::referenced_bundles(&self.policy_root)?;
        referenced.push(current.to_string());
        // Import may have replaced current.json since this cycle read it.
        // Re-read while holding the same publication lock as the importer.
        if let Some(receipt) = read_receipt(&self.bundle_dir)? {
            referenced.push(receipt.bundle_sha256);
        }
        let mut removed = Vec::new();
        let mut seen = Vec::new();
        for entry in fs::read_dir(&self.bundle_dir)? {
            let name = entry?.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(digest) = name.strip_prefix("platform-").and_then(|n| n.strip_suffix(".nanpfb")) else { continue };
            if bundle_file_name(digest).is_err() {
                continue;
            }
            seen.push(digest.to_string());
            if referenced.iter().any(|r| r == digest) {
                unreferenced.remove(digest);
                continue;
            }
            let since = *unreferenced.entry(digest.to_string()).or_insert(now);
            if now - since >= grace {
                fs::remove_file(self.bundle_dir.join(name))?;
                let notice = self.bundle_dir.join(format!("notice-{digest}.txt"));
                if fs::symlink_metadata(&notice).is_ok() {
                    fs::remove_file(notice)?;
                }
                unreferenced.remove(digest);
                removed.push(digest.to_string());
            }
        }
        unreferenced.retain(|digest, _| seen.contains(digest));
        Ok(removed)
    }

    /// Startup probe: every tenant with a grants file has a reader-valid
    /// policy whose bundle opens and verifies through the cell's own source.
    pub fn ready(&self) -> Result<()> {
        self.validate()?;
        let source = PlatformBundleSource::Dir(self.bundle_dir.clone());
        let tenants = policy::grants_files(&self.grants_dir)?;
        ensure!(!tenants.is_empty(), "no tenant grants file in {}", self.grants_dir.display());
        for tenant in tenants.into_keys() {
            let current = policy::read_current(&self.policy_root, tenant)?.with_context(|| format!("no policy for {tenant} yet"))?;
            source.open(&current.bundle_sha256).with_context(|| format!("bundle for {tenant}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrichment::IocSnapshotInput;
    use crate::lean_platform_bundle::TenantPlatformPolicy;

    const TENANT: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";

    fn ioc(feed: &str, value: &str) -> IocSnapshotInput {
        IocSnapshotInput {
            ioc_value: value.into(),
            ioc_type: "ip".into(),
            source_id: feed.into(),
            enrichment_name: feed.into(),
            threat_type: "tor_exit".into(),
            confidence_level: 100,
            ..Default::default()
        }
    }

    /// A verified portable bundle: the descriptor terms plus its NANPFB01
    /// payload (staged at `<root>/payload-<revision>.nanpfb`).
    fn import(root: &Path, revision: i64, produced: DateTime<Utc>, expiry: DateTime<Utc>) -> (PortableImport, PathBuf) {
        let staged = root.join(format!("payload-{revision}-{}.nanpfb", expiry.timestamp()));
        let feed = "tor_exit_nodes".to_string();
        let sha = PlatformBundle::publish_verified(
            &staged,
            None,
            &[ioc(&feed, "185.220.101.1")],
            None,
            BTreeMap::from([(feed.clone(), revision)]),
            BTreeMap::from([(feed.clone(), expiry)]),
        )
        .unwrap();
        let import = PortableImport {
            source_sha256: format!("{:064x}", revision),
            sequence: revision as u64,
            payload_sha256: sha,
            feeds: vec![PortableFeed {
                feed_id: feed,
                revision,
                produced_at: produced,
                hard_expiry: expiry,
                license_id: "LicenseRef-tor-bulk-exit-list-public".into(),
                terms_revision: "2026-10-01".into(),
                records: 1,
            }],
            notice: "Tor exit list: The Tor Project".into(),
            signed_descriptor: None,
        };
        (import, staged)
    }

    fn put(layout: &Layout, (import, staged): &(PortableImport, PathBuf), now: DateTime<Utc>) -> Result<Receipt> {
        install(&layout.bundle_dir, import, place_nanpfb_file(staged, &import.payload_sha256), now, None)
    }

    fn layout(root: &Path) -> Layout {
        let layout = Layout {
            bundle_dir: root.join("feeds/bundles"),
            policy_root: root.join("policy"),
            grants_dir: root.join("grants"),
        };
        fs::create_dir_all(&layout.policy_root).unwrap();
        fs::create_dir_all(&layout.grants_dir).unwrap();
        fs::write(layout.grants_dir.join(format!("{TENANT}.json")), all_bundled_grants(TENANT.parse().unwrap()).unwrap()).unwrap();
        layout
    }

    #[test]
    fn empty_then_import_rotates_the_policy_and_the_reader_stamps() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let layout = layout(&root);
        let now = Utc::now();
        let mut unref = BTreeMap::new();
        let first = layout.cycle(now, &mut unref, Duration::hours(1)).unwrap();
        assert_eq!(first.tenant_errors, 0);
        assert!(first.bundle_feeds.is_empty());
        layout.ready().unwrap();
        let tenant: Uuid = TENANT.parse().unwrap();
        let empty = policy::read_current(&layout.policy_root, tenant).unwrap().unwrap();
        assert!(empty.grants.is_empty());
        assert!(!status(&layout.bundle_dir, now).unwrap().installed);

        let receipt = put(&layout, &import(&root, 5, now - Duration::hours(1), now + Duration::days(30)), now).unwrap();
        let second = layout.cycle(now, &mut unref, Duration::hours(1)).unwrap();
        assert_eq!(second.bundle_sha256, receipt.bundle_sha256);
        let policy: TenantPlatformPolicy = policy::read_current(&layout.policy_root, tenant).unwrap().unwrap();
        assert_eq!(policy.revision, empty.revision + 1);
        assert_eq!(policy.grants.keys().collect::<Vec<_>>(), vec!["tor_exit_nodes"]);
        // The cell's own source selects and verifies the bundle the policy names.
        let bundle = PlatformBundleSource::Dir(layout.bundle_dir.clone()).open(&policy.bundle_sha256).unwrap();
        let mut event = serde_json::json!({"src_endpoint": {"ip": "185.220.101.1"}}).as_object().unwrap().clone();
        bundle.stamp(&mut event, &policy, now).unwrap();
        assert_eq!(event["enrichments"][0]["provider"], "platform/tor_exit_nodes");
        // Past hard expiry nothing new is stamped (and nothing is rewritten).
        let mut later = serde_json::json!({"src_endpoint": {"ip": "185.220.101.1"}}).as_object().unwrap().clone();
        bundle.stamp(&mut later, &policy, now + Duration::days(31)).unwrap();
        assert!(later.get("enrichments").is_none());

        let st = status(&layout.bundle_dir, now).unwrap();
        assert!(st.installed);
        assert_eq!(st.feeds[0].state, FeedState::Fresh);
        assert_eq!(st.feeds[0].age_seconds, Some(3600));
        assert!(st.notice.unwrap().contains("Tor"));
        assert_eq!(status(&layout.bundle_dir, now + Duration::days(8)).unwrap().feeds[0].state, FeedState::Stale);
        assert_eq!(status(&layout.bundle_dir, now + Duration::days(31)).unwrap().feeds[0].state, FeedState::Expired);

        // The empty placeholder is GC'd once unreferenced past the grace.
        let third = layout.cycle(now + Duration::hours(2), &mut unref, Duration::hours(1)).unwrap();
        assert_eq!(third.gc_removed, vec![empty.bundle_sha256.clone()]);
        layout.ready().unwrap();
    }

    #[test]
    fn rollback_expired_and_malformed_imports_are_refused_before_any_write() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let layout = layout(&root);
        let now = Utc::now();
        let fresh = |revision| import(&root, revision, now - Duration::hours(1), now + Duration::days(30));
        let installed = put(&layout, &fresh(5), now).unwrap();
        // Same bundle again: a no-op.
        assert_eq!(put(&layout, &fresh(5), now).unwrap(), installed);
        for (bad, why) in [
            (fresh(4), "older"),
            (import(&root, 6, now - Duration::days(40), now - Duration::days(1)), "hard expiry"),
            (import(&root, 6, now + Duration::hours(1), now + Duration::days(30)), "future"),
        ] {
            let error = format!("{:#}", put(&layout, &bad, now).unwrap_err());
            assert!(error.contains(why), "{error}");
        }
        // Terms that disagree with the payload header, a premium feed, or
        // no notice: refused, and nothing changes.
        let mut wrong_revision = fresh(6);
        wrong_revision.0.feeds[0].revision = 7;
        assert!(format!("{:#}", put(&layout, &wrong_revision, now).unwrap_err()).contains("revisions differ"));
        let mut wrong_expiry = fresh(6);
        wrong_expiry.0.feeds[0].hard_expiry += Duration::days(1);
        assert!(format!("{:#}", put(&layout, &wrong_expiry, now).unwrap_err()).contains("expiry differs"));
        let mut premium = fresh(6);
        premium.0.feeds[0].feed_id = "synthient".into();
        assert!(put(&layout, &premium, now).is_err());
        let mut no_notice = fresh(6);
        no_notice.0.notice = " ".into();
        assert!(put(&layout, &no_notice, now).is_err());
        let mut misplaced = fresh(6);
        let other = fresh(8);
        misplaced.0.payload_sha256 = other.0.payload_sha256.clone();
        assert!(install(&layout.bundle_dir, &misplaced.0, place_nanpfb_file(&misplaced.1, &fresh(6).0.payload_sha256), now, None).is_err());
        assert_eq!(Receipt::read(&layout.bundle_dir).unwrap().unwrap().bundle_sha256, installed.bundle_sha256);
    }

    #[test]
    fn each_tenant_stamps_only_its_own_grants() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let layout = layout(&root);
        let now = Utc::now();
        put(&layout, &import(&root, 5, now - Duration::hours(1), now + Duration::hours(20)), now).unwrap();
        let other: Uuid = "7a2d2f3b-6c9f-4e5d-8b4f-1f3c8d0e2a11".parse().unwrap();
        fs::write(layout.grants_dir.join(format!("{other}.json")), serde_json::to_vec(&serde_json::json!({
            "schema": GRANTS_SCHEMA, "tenant_id": other, "rows": [],
        })).unwrap()).unwrap();
        let report = layout.cycle(now, &mut BTreeMap::new(), Duration::hours(1)).unwrap();
        assert_eq!(report.tenant_errors, 0);
        let granted = policy::read_current(&layout.policy_root, TENANT.parse().unwrap()).unwrap().unwrap();
        let denied = policy::read_current(&layout.policy_root, other).unwrap().unwrap();
        let bundle = PlatformBundleSource::Dir(layout.bundle_dir.clone()).open(&granted.bundle_sha256).unwrap();
        for (policy, permitted) in [(&granted, true), (&denied, false)] {
            let mut event = serde_json::json!({"src_endpoint": {"ip": "185.220.101.1"}}).as_object().unwrap().clone();
            bundle.stamp(&mut event, policy, now).unwrap();
            assert_eq!(event.contains_key("enrichments"), permitted);
        }
        assert!(TenantPlatformPolicy::read_for_query(&layout.policy_root.join(TENANT).join("policy.json"), other).is_err());
    }

    #[test]
    fn gc_rechecks_current_receipt_after_concurrent_import() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let layout = layout(&root);
        let now = Utc::now();
        let before = ensure_installed_or_empty(&layout.bundle_dir, now).unwrap();
        let installed = put(&layout, &import(&root, 5, now - Duration::hours(1), now + Duration::hours(20)), now).unwrap();
        // A serve cycle captured the old receipt before import committed. It
        // must not collect the newly current payload before policy rotation.
        let mut unreferenced = BTreeMap::from([(installed.bundle_sha256.clone(), now - Duration::hours(2))]);
        let removed = layout.gc(&before.bundle_sha256, now, &mut unreferenced, Duration::hours(1)).unwrap();
        assert!(!removed.contains(&installed.bundle_sha256));
        PlatformBundleSource::Dir(layout.bundle_dir.clone()).open(&installed.bundle_sha256).unwrap();
    }

    #[test]
    fn missing_payload_never_resets_rollback_history() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let layout = layout(&root);
        let now = Utc::now();
        let installed = put(&layout, &import(&root, 5, now - Duration::hours(1), now + Duration::hours(20)), now).unwrap();
        fs::remove_file(layout.bundle_dir.join(&installed.bundle_file)).unwrap();
        assert!(ensure_installed_or_empty(&layout.bundle_dir, now).is_err());
        assert_eq!(Receipt::read(&layout.bundle_dir).unwrap().unwrap(), installed);
    }

    #[test]
    fn an_all_bundled_file_with_rows_or_another_tenant_name_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let layout = layout(&root);
        let other = "7a2d2f3b-6c9f-4e5d-8b4f-1f3c8d0e2a11";
        fs::write(layout.grants_dir.join(format!("{other}.json")), all_bundled_grants(TENANT.parse().unwrap()).unwrap()).unwrap();
        let report = layout.cycle(Utc::now(), &mut BTreeMap::new(), Duration::hours(1)).unwrap();
        assert_eq!(report.tenant_errors, 1);
        assert!(policy::read_current(&layout.policy_root, other.parse().unwrap()).unwrap().is_none());
    }
}
