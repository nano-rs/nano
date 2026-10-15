// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prune superseded content-addressed IOC snapshots (NAN-2361 leak fix,
//! enrichment lane), mirroring `risk_sidecar_prune`.
//!
//! Every IOC publication writes a NEW whole-set Parquet snapshot
//! (`<sha256>.parquet`) and atomically advances the worker pin. Nothing ever
//! removed the superseded snapshots, so the shared local runtime volume that
//! also hosts serving generations grew without bound. This module deletes a
//! snapshot only when ALL of the following hold; when in doubt it keeps the
//! file:
//!
//! - it is not the CURRENT pin, which for the IOC lane is also the active
//!   worker generation: `worker.json` -> `ioc_snapshot.data` is both what the
//!   worker loads and what the next publication merges from;
//! - it is not the rollback snapshot: the newest superseded snapshot is
//!   always retained, mirroring the active-plus-rollback retention in
//!   `risk_sidecar_prune` and `identity_directory::prune_snapshots`;
//! - it is not pinned by a durable job's archived event config (those strip
//!   `ioc_snapshot` by construction, exactly as they strip `risk_snapshot` —
//!   see `config::archive_event_config` — but the scan is kept as a fence);
//! - it is older than an operator-controlled grace window, following the
//!   `prune_hot_tail_archives` grace-plus-pin pattern.
//!
//! Any failure to build the complete protected set aborts the prune and
//! retains everything: keeping garbage is recoverable, deleting a pinned
//! snapshot breaks enrichment or rollback and is not.

use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Mirrors the deletion cap in `prune_hot_tail_archives`.
const MAX_DELETIONS_PER_RUN: u64 = 10_000;

/// Active pin plus exactly one rollback snapshot, mirroring
/// `risk_sidecar_prune`'s active-and-rollback retention.
const ROLLBACK_SNAPSHOTS_RETAINED: usize = 1;

#[derive(Debug, Clone)]
pub struct IocSnapshotPruneInputs {
    /// Directory holding the content-addressed IOC snapshots.
    pub snapshot_dir: PathBuf,
    /// The active worker configuration (`worker.json`); its
    /// `ioc_snapshot.data` entry is the CURRENT pin.
    pub worker_config: PathBuf,
    /// Optional durable-job event-config archive root; its `configs/*.json`
    /// entries are scanned for IOC pins as a defensive fence.
    pub archived_config_root: Option<PathBuf>,
    /// Minimum age before an unreferenced snapshot may be deleted.
    pub grace: Duration,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct IocSnapshotPruneReport {
    pub scanned: u64,
    pub deleted: u64,
    pub deleted_bytes: u64,
    pub retained_referenced: u64,
    pub retained_rollback: u64,
    pub retained_grace: u64,
}

/// Delete superseded IOC snapshots in `snapshot_dir`.
///
/// `now` is injected so tests can prove the grace window without sleeping;
/// callers pass `SystemTime::now()`. Errors abort the prune before any
/// deletion, retaining every file. Callers must hold the publisher's
/// exclusive `ioc.lock` so the protected set is never computed against a
/// half-advanced pin.
pub fn prune_ioc_snapshots(
    inputs: &IocSnapshotPruneInputs,
    now: SystemTime,
) -> Result<IocSnapshotPruneReport> {
    if !inputs.snapshot_dir.is_absolute() || !inputs.snapshot_dir.is_dir() {
        bail!("IOC snapshot directory is not an absolute directory");
    }
    let mut protected = BTreeSet::new();

    // 1. The CURRENT pin, which is also the active worker generation. An
    //    unreadable worker config means the protected set cannot be computed,
    //    so the prune aborts before any deletion. A fresh tenant may have no
    //    IOC pin at all.
    let worker: Value = serde_json::from_slice(
        &std::fs::read(&inputs.worker_config)
            .with_context(|| format!("read worker config {}", inputs.worker_config.display()))?,
    )
    .context("decode worker config")?;
    protect_pin(&worker, &mut protected).context("active worker generation IOC pin")?;

    // 2. Durable-job archived configs. `archive_event_config` strips
    //    `ioc_snapshot` exactly as it strips `risk_snapshot`, so pins are
    //    structurally impossible today; this scan is a fence against older or
    //    foreign archives. An unreadable archive entry cannot silently
    //    reference IOC snapshots, so it is skipped.
    if let Some(root) = &inputs.archived_config_root {
        let configs = root.join("configs");
        if configs.is_dir() {
            for entry in std::fs::read_dir(&configs).context("read event-config archive")? {
                let path = entry?.path();
                if path.extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }
                let Ok(bytes) = std::fs::read(&path) else {
                    tracing::warn!(path = %path.display(), "unreadable archived config skipped");
                    continue;
                };
                let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
                    tracing::warn!(path = %path.display(), "undecodable archived config skipped");
                    continue;
                };
                protect_pin(&value, &mut protected)
                    .with_context(|| format!("archived config pin {}", path.display()))?;
            }
        }
    }

    // Enumerate every content-addressed snapshot. Anything else in the
    // directory (dot-prefixed temporaries, locks, stamps) is never a deletion
    // candidate.
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(&inputs.snapshot_dir).context("read IOC snapshot directory")? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !is_content_addressed_snapshot(&name) {
            continue;
        }
        let metadata = entry.metadata()?;
        entries.push((name, entry.path(), metadata.modified()?, metadata.len()));
    }

    // 3. The rollback snapshot: retain the newest superseded snapshot. The
    //    publisher advances the pin atomically, so without this the previous
    //    snapshot (still loadable by a draining worker generation, and the
    //    only rollback target) would be unprotected.
    let mut rollback_candidates = entries
        .iter()
        .filter(|(name, _, _, _)| !protected.contains(name))
        .map(|(name, _, modified, _)| (name.clone(), *modified))
        .collect::<Vec<_>>();
    rollback_candidates
        .sort_by(|left, right| right.1.cmp(&left.1).then_with(|| right.0.cmp(&left.0)));
    let rollback = rollback_candidates
        .into_iter()
        .take(ROLLBACK_SNAPSHOTS_RETAINED)
        .map(|(name, _)| name)
        .collect::<BTreeSet<_>>();

    let cutoff = now
        .checked_sub(inputs.grace)
        .context("IOC snapshot prune grace is too large")?;
    let mut report = IocSnapshotPruneReport::default();
    for (name, path, modified, bytes) in &entries {
        report.scanned += 1;
        if protected.contains(name) {
            report.retained_referenced += 1;
            tracing::debug!(file = %name, "IOC snapshot retained: referenced by a pinned generation");
            continue;
        }
        if rollback.contains(name) {
            report.retained_rollback += 1;
            tracing::debug!(file = %name, "IOC snapshot retained: rollback snapshot");
            continue;
        }
        if *modified >= cutoff {
            report.retained_grace += 1;
            tracing::debug!(file = %name, "IOC snapshot retained: inside the grace window");
            continue;
        }
        if report.deleted >= MAX_DELETIONS_PER_RUN {
            break;
        }
        std::fs::remove_file(path)
            .with_context(|| format!("delete superseded IOC snapshot {}", path.display()))?;
        report.deleted += 1;
        report.deleted_bytes = report.deleted_bytes.saturating_add(*bytes);
        tracing::debug!(file = %name, bytes, "superseded IOC snapshot deleted");
    }
    Ok(report)
}

/// Protect the snapshot a worker or archived job config pins: the basename of
/// `ioc_snapshot.data.path` plus the digest-derived name. A present but
/// malformed pin means the safe set cannot be computed, so the caller aborts
/// the prune.
fn protect_pin(config: &Value, protected: &mut BTreeSet<String>) -> Result<()> {
    let Some(snapshot) = config.get("ioc_snapshot").filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let path = snapshot
        .pointer("/data/path")
        .and_then(Value::as_str)
        .context("IOC pin has no trusted path")?;
    let name = Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .context("IOC pin has no file name")?;
    protected.insert(name.to_string());
    if let Some(digest) = snapshot
        .pointer("/data/sha256")
        .and_then(Value::as_str)
        .filter(|digest| valid_sha256(digest))
    {
        protected.insert(format!("{digest}.parquet"));
    }
    Ok(())
}

/// The publisher names snapshots `<sha256>.parquet` with no prefix; anything
/// else (`.ioc-*.parquet` temporaries, stamps, locks) never matches.
fn is_content_addressed_snapshot(name: &str) -> bool {
    name.strip_suffix(".parquet").is_some_and(valid_sha256)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const GRACE: Duration = Duration::from_secs(86_400);

    fn hex_digest(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    /// Write one content-addressed snapshot into `dir` and return its name.
    fn write_snapshot(dir: &Path, seed: &str) -> String {
        let bytes = format!("ioc-{seed}").into_bytes();
        let name = format!("{}.parquet", hex_digest(&bytes));
        std::fs::write(dir.join(&name), &bytes).unwrap();
        name
    }

    /// Age a file so it is unambiguously beyond the grace window.
    fn age_file(path: &Path, seconds_old: u64) {
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(SystemTime::now() - Duration::from_secs(seconds_old))
            .unwrap();
    }

    /// Standard fixture: worker.json pins snapshot A, a superseded snapshot B
    /// (the rollback, newer) and an older superseded snapshot C exist.
    fn fixture(dir: &Path) -> (IocSnapshotPruneInputs, String, String, String) {
        let snapshot_c = write_snapshot(dir, "c");
        let snapshot_b = write_snapshot(dir, "b");
        let snapshot_a = write_snapshot(dir, "a");

        let worker_config = dir.join("worker.json");
        std::fs::write(
            &worker_config,
            serde_json::to_vec_pretty(&json!({
                "assigned_tenant_id": "tenant-a",
                "ioc_snapshot": {
                    "snapshot_id": "ioc-current",
                    "data": {
                        "path": dir.join(&snapshot_a),
                        "sha256": snapshot_a.strip_suffix(".parquet").unwrap(),
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        // Everything predates the grace window unless a test says otherwise;
        // mtimes also decide rollback recency (B newer than C).
        age_file(&dir.join(&snapshot_a), 30 * 86_400);
        age_file(&dir.join(&snapshot_c), 30 * 86_400);
        age_file(&dir.join(&snapshot_b), 10 * 86_400);

        let inputs = IocSnapshotPruneInputs {
            snapshot_dir: dir.to_path_buf(),
            worker_config,
            archived_config_root: None,
            grace: GRACE,
        };
        (inputs, snapshot_a, snapshot_b, snapshot_c)
    }

    #[test]
    fn current_pin_is_never_deleted() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().canonicalize().unwrap();
        let (inputs, snapshot_a, _, _) = fixture(&dir);
        let report = prune_ioc_snapshots(&inputs, SystemTime::now()).unwrap();
        assert!(dir.join(&snapshot_a).is_file(), "{snapshot_a} is the current pin");
        assert_eq!(report.retained_referenced, 1);
    }

    #[test]
    fn rollback_snapshot_is_never_deleted() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().canonicalize().unwrap();
        let (inputs, _, snapshot_b, _) = fixture(&dir);
        let report = prune_ioc_snapshots(&inputs, SystemTime::now()).unwrap();
        assert!(
            dir.join(&snapshot_b).is_file(),
            "{snapshot_b} is the rollback snapshot"
        );
        assert_eq!(report.retained_rollback, 1);
    }

    #[test]
    fn old_unreferenced_snapshot_is_deleted() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().canonicalize().unwrap();
        let (inputs, _, _, snapshot_c) = fixture(&dir);
        let report = prune_ioc_snapshots(&inputs, SystemTime::now()).unwrap();
        assert!(
            !dir.join(&snapshot_c).exists(),
            "{snapshot_c} was superseded and old"
        );
        assert_eq!(report.deleted, 1);
        assert!(report.deleted_bytes > 0);
        assert_eq!(report.scanned, 3);
    }

    #[test]
    fn grace_window_is_respected() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().canonicalize().unwrap();
        let (inputs, _, snapshot_b, snapshot_c) = fixture(&dir);
        // Make every superseded snapshot recent again. One is claimed as the
        // rollback; the other must survive purely on the grace window.
        for name in [&snapshot_b, &snapshot_c] {
            let file = std::fs::File::options()
                .write(true)
                .open(dir.join(name))
                .unwrap();
            file.set_modified(SystemTime::now()).unwrap();
        }
        let report = prune_ioc_snapshots(&inputs, SystemTime::now()).unwrap();
        assert_eq!(report.deleted, 0);
        assert_eq!(report.retained_rollback, 1);
        assert_eq!(
            report.retained_grace, 1,
            "recently written superseded snapshots stay inside the grace window"
        );
        assert!(dir.join(&snapshot_c).is_file());
    }

    #[test]
    fn unreadable_worker_config_aborts_before_any_deletion() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().canonicalize().unwrap();
        let (mut inputs, _, _, snapshot_c) = fixture(&dir);
        inputs.worker_config = dir.join("missing-worker.json");
        assert!(prune_ioc_snapshots(&inputs, SystemTime::now()).is_err());
        assert!(
            dir.join(&snapshot_c).is_file(),
            "an aborted prune must not delete anything"
        );
    }

    #[test]
    fn malformed_pin_aborts_before_any_deletion() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().canonicalize().unwrap();
        let (inputs, _, _, snapshot_c) = fixture(&dir);
        std::fs::write(
            &inputs.worker_config,
            serde_json::to_vec(&json!({"ioc_snapshot": {"data": {}}})).unwrap(),
        )
        .unwrap();
        assert!(prune_ioc_snapshots(&inputs, SystemTime::now()).is_err());
        assert!(
            dir.join(&snapshot_c).is_file(),
            "an aborted prune must not delete anything"
        );
    }

    #[test]
    fn archived_config_pin_is_protected() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().canonicalize().unwrap();
        let (mut inputs, _, _, snapshot_c) = fixture(&dir);
        let archive = dir.join("archive");
        std::fs::create_dir_all(archive.join("configs")).unwrap();
        std::fs::write(
            archive.join("configs").join("pin.json"),
            serde_json::to_vec(&json!({
                "ioc_snapshot": {
                    "data": {"path": dir.join(&snapshot_c)}
                }
            }))
            .unwrap(),
        )
        .unwrap();
        inputs.archived_config_root = Some(archive);
        let report = prune_ioc_snapshots(&inputs, SystemTime::now()).unwrap();
        assert_eq!(report.deleted, 0);
        assert!(
            dir.join(&snapshot_c).is_file(),
            "a durable-job pin protects its snapshot"
        );
        assert_eq!(report.retained_referenced, 2);
    }

    #[test]
    fn missing_pin_leaves_rollback_and_grace_rules_in_charge() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().canonicalize().unwrap();
        let (inputs, snapshot_a, snapshot_b, snapshot_c) = fixture(&dir);
        // A fresh tenant has no IOC pin: nothing is "referenced", but the
        // newest snapshot is still the rollback and grace still applies.
        std::fs::write(
            &inputs.worker_config,
            serde_json::to_vec(&json!({"assigned_tenant_id": "tenant-a"})).unwrap(),
        )
        .unwrap();
        let report = prune_ioc_snapshots(&inputs, SystemTime::now()).unwrap();
        assert_eq!(report.retained_referenced, 0);
        assert_eq!(report.retained_rollback, 1);
        assert!(dir.join(&snapshot_b).is_file(), "{snapshot_b} is newest, kept");
        assert_eq!(report.deleted, 2);
        assert!(!dir.join(&snapshot_a).exists());
        assert!(!dir.join(&snapshot_c).exists());
    }

    #[test]
    fn classification_only_matches_content_addressed_names() {
        assert!(is_content_addressed_snapshot(&format!(
            "{}.parquet",
            "a".repeat(64)
        )));
        assert!(is_content_addressed_snapshot(&format!(
            "{}.parquet",
            "0".repeat(64)
        )));
        assert!(!is_content_addressed_snapshot(&format!(
            "{}.json",
            "a".repeat(64)
        )));
        assert!(!is_content_addressed_snapshot("nothex.parquet"));
        assert!(!is_content_addressed_snapshot(&format!(
            ".ioc-{}.parquet",
            "a".repeat(60)
        )));
        assert!(!is_content_addressed_snapshot(&format!(
            "{}.parquet",
            "A".repeat(64)
        )));
        assert!(!is_content_addressed_snapshot(".ioc-snapshot-prune-abcd.stamp"));
    }
}
