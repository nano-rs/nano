// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reclamation of durable query-result artifacts.
//!
//! `commit_s3`/`commit_local` publish result pages under
//! `{result_root}/tenant-{sha256}/job-{id}/attempt-{n}/`, but nothing ever
//! deleted them: the Redis job RECORDS expire on a TTL while the object-store
//! artifacts remained forever — write-only storage growing at the durable
//! export rate. This sweep reclaims artifacts whose job has become
//! unreferenceable, and only those.
//!
//! Safety rule (conservative by construction): an artifact is deleted only
//! when BOTH hold —
//! 1. the metadata service reports NO remaining reference for the job — no
//!    job record (a live record, even in a terminal state, still serves
//!    result pages to an analyst mid-export), no admission/active index
//!    membership, no durable queue entry, no runner lease; and
//! 2. the newest object in the job's directory is older than the operator's
//!    results-retention window.
//! Anything unparseable, unaged, or errored is retained. Preferring kept
//! garbage over a deleted reachable result is the design, not an accident.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nanosiem_core::search::RedisJobStore;

/// Default operator retention for durable query results. Comfortably above
/// the 24h durable job-record TTL, so a record always expires long before its
/// artifact becomes eligible.
pub const DEFAULT_RESULT_RETENTION_DAYS: u64 = 7;

/// Answers "is any live reference to this job's result left?". `Some(reason)`
/// means the artifact MUST be retained; `Err` means the answer is unknown and
/// the artifact is retained too.
pub trait JobReachability {
    fn job_reference(&self, job_id: &str) -> impl Future<Output = Result<Option<String>>> + Send;
}

impl JobReachability for RedisJobStore {
    fn job_reference(&self, job_id: &str) -> impl Future<Output = Result<Option<String>>> + Send {
        async move {
            let reference = self
                .durable_result_reference(job_id)
                .await
                .map_err(|error| anyhow::anyhow!("durable job store verdict failed: {error}"))?;
            Ok(reference.map(|reference| reference.as_str().to_string()))
        }
    }
}

/// Counters from one durable query-result GC sweep. Every retained job is
/// attributed to a reason so a missing export is explainable from the log,
/// never a silent disappearance.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct ResultGcReport {
    pub jobs_scanned: usize,
    pub jobs_reclaimed: usize,
    pub objects_reclaimed: u64,
    pub bytes_reclaimed: u64,
    pub jobs_retained_referenced: usize,
    pub jobs_retained_within_window: usize,
    pub jobs_retained_unparseable: usize,
    pub jobs_retained_error: usize,
}

/// One job directory's inventory: every object beneath it plus the newest
/// modification time observed across those objects.
struct JobArtifact {
    job_id: String,
    /// Object identifiers (paths or keys) with their sizes; manifests are
    /// deleted first so a partially swept directory cannot pass verification.
    objects: Vec<(String, u64)>,
    newest: Option<DateTime<Utc>>,
    /// True when any object's modification time could not be determined. An
    /// unaged object poisons the whole job: without proof every object is old
    /// enough, the directory is retained.
    age_unknown: bool,
}

enum GcDecision {
    Reclaim,
    RetainReferenced(String),
    RetainWithinWindow,
    RetainError(String),
}

async fn judge<R: JobReachability + Sync>(
    artifact: &JobArtifact,
    reachability: &R,
    retention: Duration,
    now: DateTime<Utc>,
) -> GcDecision {
    let newest = match (artifact.age_unknown, artifact.newest) {
        (false, Some(newest)) => newest,
        // Some (or all) objects exposed no age: without proof the artifact is
        // old enough, it is retained.
        _ => {
            return GcDecision::RetainError("object modification time unavailable".to_string());
        }
    };
    let age = now.signed_duration_since(newest);
    let retention = match chrono::Duration::from_std(retention) {
        Ok(window) => window,
        Err(_) => return GcDecision::RetainError("retention window overflowed".to_string()),
    };
    if age < retention {
        return GcDecision::RetainWithinWindow;
    }
    match reachability.job_reference(&artifact.job_id).await {
        Ok(Some(reason)) => GcDecision::RetainReferenced(reason),
        Ok(None) => GcDecision::Reclaim,
        Err(error) => GcDecision::RetainError(format!("{error:#}")),
    }
}

fn valid_job_id(job_id: &str) -> bool {
    !job_id.is_empty()
        && job_id.len() <= 128
        && job_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !job_id.bytes().all(|byte| byte == b'.')
}

/// Convert an object store timestamp into the sweep's chrono clock domain.
fn object_time(timestamp: opendal::raw::Timestamp) -> DateTime<Utc> {
    DateTime::<Utc>::from(std::time::SystemTime::from(timestamp))
}

fn tenant_prefix_filter(tenant_id: Option<&str>) -> Option<String> {
    tenant_id.map(|tenant| format!("tenant-{}", super::sha256(tenant.as_bytes())))
}

/// NAN-2596: the result root shares the tenant bucket with the platform's
/// `tenants/` parser bundles. Refuse the whole job if any key is reserved.
fn guard_reclaim_keys(objects: &[(String, u64)]) -> Result<()> {
    for (key, _) in objects {
        nanosiem_core::r2_prefix_guard::assert_deletable(key)?;
    }
    Ok(())
}

/// Sort object identifiers so every `manifest.json` deletes before any data
/// page: a half-deleted directory then fails manifest verification closed
/// instead of serving truncated pages.
fn manifest_first(objects: &mut [(String, u64)]) {
    objects.sort_by_key(|(path, _)| {
        (
            !Path::new(path)
                .file_name()
                .is_some_and(|name| name == "manifest.json"),
            path.clone(),
        )
    });
}

/// Sweep one durable-result root. Dispatches on the same URI scheme as
/// `commit_result`: `s3://` roots use the deployment-owned result operator,
/// anything else is a local directory (optionally `file://`-prefixed).
pub async fn sweep_result_root<R: JobReachability + Sync>(
    result_root: &str,
    tenant_id: Option<&str>,
    reachability: &R,
    retention: Duration,
    now: DateTime<Utc>,
) -> Result<ResultGcReport> {
    if let Some(tenant) = tenant_id {
        if tenant.is_empty() || tenant.len() > 512 || tenant.chars().any(char::is_control) {
            bail!("results GC tenant filter is invalid");
        }
    }
    let report = if result_root.starts_with("s3://") {
        crate::shared_mode::require_serialized_writer_authority(
            "durable_query_result_retention_delete",
        )?;
        sweep_s3_root(result_root, tenant_id, reachability, retention, now).await?
    } else {
        sweep_local_root(result_root, tenant_id, reachability, retention, now).await?
    };
    tracing::info!(
        jobs_scanned = report.jobs_scanned,
        jobs_reclaimed = report.jobs_reclaimed,
        objects_reclaimed = report.objects_reclaimed,
        bytes_reclaimed = report.bytes_reclaimed,
        jobs_retained_referenced = report.jobs_retained_referenced,
        jobs_retained_within_window = report.jobs_retained_within_window,
        jobs_retained_unparseable = report.jobs_retained_unparseable,
        jobs_retained_error = report.jobs_retained_error,
        "durable query-result GC sweep finished"
    );
    Ok(report)
}

async fn sweep_local_root<R: JobReachability + Sync>(
    result_root: &str,
    tenant_id: Option<&str>,
    reachability: &R,
    retention: Duration,
    now: DateTime<Utc>,
) -> Result<ResultGcReport> {
    let root = result_root.strip_prefix("file://").unwrap_or(result_root);
    if root.is_empty() {
        bail!("local result root is empty");
    }
    let root = PathBuf::from(root);
    let mut report = ResultGcReport::default();
    if !root.exists() {
        return Ok(report);
    }
    let tenant_filter = tenant_prefix_filter(tenant_id);
    for tenant_entry in std::fs::read_dir(&root).context("list result root")? {
        let tenant_entry = tenant_entry?;
        let tenant_name = tenant_entry.file_name().to_string_lossy().to_string();
        if !tenant_entry.file_type()?.is_dir() || !tenant_name.starts_with("tenant-") {
            continue;
        }
        if tenant_filter
            .as_deref()
            .is_some_and(|filter| filter != tenant_name)
        {
            continue;
        }
        for job_entry in std::fs::read_dir(tenant_entry.path())? {
            let job_entry = job_entry?;
            let job_name = job_entry.file_name().to_string_lossy().to_string();
            if !job_entry.file_type()?.is_dir() {
                continue;
            }
            report.jobs_scanned = report.jobs_scanned.saturating_add(1);
            let Some(job_id) = job_name.strip_prefix("job-").filter(|id| valid_job_id(id)) else {
                report.jobs_retained_unparseable =
                    report.jobs_retained_unparseable.saturating_add(1);
                tracing::warn!(
                    directory = %job_entry.path().display(),
                    "durable query-result GC retained a directory it does not recognize"
                );
                continue;
            };
            let artifact = match collect_local_job(&job_entry.path(), job_id) {
                Ok(artifact) => artifact,
                Err(error) => {
                    report.jobs_retained_error = report.jobs_retained_error.saturating_add(1);
                    tracing::warn!(job_id, error = %format!("{error:#}"),
                        "durable query-result GC retained an unreadable job directory");
                    continue;
                }
            };
            match judge(&artifact, reachability, retention, now).await {
                GcDecision::Reclaim => match delete_local_job(&job_entry.path(), &artifact) {
                    Ok((objects, bytes)) => {
                        report.jobs_reclaimed = report.jobs_reclaimed.saturating_add(1);
                        report.objects_reclaimed = report.objects_reclaimed.saturating_add(objects);
                        report.bytes_reclaimed = report.bytes_reclaimed.saturating_add(bytes);
                        tracing::info!(
                            job_id,
                            objects,
                            bytes,
                            "durable query-result GC reclaimed an unreferenced job artifact"
                        );
                    }
                    Err(error) => {
                        report.jobs_retained_error = report.jobs_retained_error.saturating_add(1);
                        tracing::warn!(job_id, error = %format!("{error:#}"),
                            "durable query-result GC failed mid-delete; the next sweep finishes");
                    }
                },
                GcDecision::RetainReferenced(reason) => {
                    report.jobs_retained_referenced =
                        report.jobs_retained_referenced.saturating_add(1);
                    tracing::debug!(job_id, reference = %reason,
                        "durable query-result GC retained a still-referenced job artifact");
                }
                GcDecision::RetainWithinWindow => {
                    report.jobs_retained_within_window =
                        report.jobs_retained_within_window.saturating_add(1);
                }
                GcDecision::RetainError(error) => {
                    report.jobs_retained_error = report.jobs_retained_error.saturating_add(1);
                    tracing::warn!(job_id, error = %error,
                        "durable query-result GC retained a job artifact it could not judge");
                }
            }
        }
    }
    Ok(report)
}

fn collect_local_job(job_dir: &Path, job_id: &str) -> Result<JobArtifact> {
    let mut objects = Vec::new();
    let mut newest: Option<DateTime<Utc>> = None;
    let mut pending = vec![job_dir.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
                continue;
            }
            let metadata = entry.metadata()?;
            let modified: DateTime<Utc> = metadata
                .modified()
                .context("object modification time unavailable")?
                .into();
            newest = Some(newest.map_or(modified, |current| current.max(modified)));
            objects.push((entry.path().to_string_lossy().to_string(), metadata.len()));
        }
    }
    Ok(JobArtifact {
        job_id: job_id.to_string(),
        objects,
        newest,
        age_unknown: false,
    })
}

fn delete_local_job(job_dir: &Path, artifact: &JobArtifact) -> Result<(u64, u64)> {
    let mut objects = artifact.objects.clone();
    manifest_first(&mut objects);
    let mut deleted_objects = 0_u64;
    let mut deleted_bytes = 0_u64;
    for (path, bytes) in &objects {
        std::fs::remove_file(path).with_context(|| format!("delete result object {path}"))?;
        deleted_objects += 1;
        deleted_bytes = deleted_bytes.saturating_add(*bytes);
    }
    // Only after every object is gone: drop the now-empty directory tree.
    std::fs::remove_dir_all(job_dir)
        .with_context(|| format!("remove result directory {}", job_dir.display()))?;
    Ok((deleted_objects, deleted_bytes))
}

async fn sweep_s3_root<R: JobReachability + Sync>(
    result_root: &str,
    tenant_id: Option<&str>,
    reachability: &R,
    retention: Duration,
    now: DateTime<Utc>,
) -> Result<ResultGcReport> {
    let (bucket, root_prefix) = super::parse_s3_root(result_root)?;
    let operator = super::result_s3_operator(bucket)?;
    let list_prefix = match tenant_prefix_filter(tenant_id) {
        Some(tenant) => format!("{}/", super::join_object_prefix(root_prefix, &tenant)),
        None => {
            if root_prefix.is_empty() {
                String::new()
            } else {
                format!("{root_prefix}/")
            }
        }
    };
    let entries = operator
        .list_with(&list_prefix)
        .recursive(true)
        .await
        .context("list durable query-result objects")?;
    // Group objects by their tenant-*/job-* directory.
    let mut jobs: BTreeMap<String, JobArtifact> = BTreeMap::new();
    let mut report = ResultGcReport::default();
    let mut unparseable = std::collections::BTreeSet::new();
    for entry in entries {
        if entry.metadata().mode().is_dir() {
            continue;
        }
        let key = entry.path().to_string();
        let relative = key
            .strip_prefix(&list_prefix)
            .unwrap_or(&key)
            .trim_start_matches('/');
        // Expect tenant-{sha}/job-{id}/... (or job-{id}/... when the listing
        // is already tenant-scoped).
        let mut components = relative.split('/');
        let first = components.next().unwrap_or_default().to_string();
        let (tenant_dir, job_dir) = if first.starts_with("tenant-") {
            (first, components.next().unwrap_or_default().to_string())
        } else if tenant_id.is_some() && first.starts_with("job-") {
            (String::new(), first)
        } else {
            unparseable.insert(relative.to_string());
            continue;
        };
        let Some(job_id) = job_dir.strip_prefix("job-").filter(|id| valid_job_id(id)) else {
            unparseable.insert(format!("{tenant_dir}/{job_dir}"));
            continue;
        };
        let group_key = format!("{tenant_dir}/{job_dir}");
        let (bytes, modified) = match (
            entry.metadata().last_modified(),
            entry.metadata().content_length(),
        ) {
            (Some(modified), bytes) => (bytes, Some(object_time(modified))),
            (None, _) => match operator.stat(&key).await {
                Ok(stat) => (stat.content_length(), stat.last_modified().map(object_time)),
                Err(_) => (0, None),
            },
        };
        let artifact = jobs.entry(group_key).or_insert_with(|| JobArtifact {
            job_id: job_id.to_string(),
            objects: Vec::new(),
            newest: None,
            age_unknown: false,
        });
        artifact.objects.push((key, bytes));
        match modified {
            Some(modified) => {
                artifact.newest = Some(
                    artifact
                        .newest
                        .map_or(modified, |current| current.max(modified)),
                );
            }
            None => artifact.age_unknown = true,
        }
    }
    report.jobs_retained_unparseable = unparseable.len();
    for path in &unparseable {
        tracing::warn!(prefix = %path,
            "durable query-result GC retained an object prefix it does not recognize");
    }
    report.jobs_scanned = jobs.len().saturating_add(unparseable.len());
    for artifact in jobs.values() {
        match judge(artifact, reachability, retention, now).await {
            GcDecision::Reclaim => {
                let mut objects = artifact.objects.clone();
                manifest_first(&mut objects);
                if let Err(error) = guard_reclaim_keys(&objects) {
                    tracing::error!(job_id = %artifact.job_id, error = %error,
                        "durable query-result GC refused a reserved key; the job is retained");
                    report.jobs_retained_unparseable = report.jobs_retained_unparseable.saturating_add(1);
                    continue;
                }
                let mut failed = false;
                let mut deleted_objects = 0_u64;
                let mut deleted_bytes = 0_u64;
                for (key, bytes) in &objects {
                    match operator.delete(key).await {
                        Ok(()) => {
                            deleted_objects += 1;
                            deleted_bytes = deleted_bytes.saturating_add(*bytes);
                        }
                        Err(error) => {
                            failed = true;
                            tracing::warn!(job_id = %artifact.job_id, key = %key, error = %error,
                                "durable query-result GC failed mid-delete; the next sweep finishes");
                            break;
                        }
                    }
                }
                report.objects_reclaimed = report.objects_reclaimed.saturating_add(deleted_objects);
                report.bytes_reclaimed = report.bytes_reclaimed.saturating_add(deleted_bytes);
                if failed {
                    report.jobs_retained_error = report.jobs_retained_error.saturating_add(1);
                } else {
                    report.jobs_reclaimed = report.jobs_reclaimed.saturating_add(1);
                    tracing::info!(job_id = %artifact.job_id, objects = deleted_objects,
                        bytes = deleted_bytes,
                        "durable query-result GC reclaimed an unreferenced job artifact");
                }
            }
            GcDecision::RetainReferenced(reason) => {
                report.jobs_retained_referenced = report.jobs_retained_referenced.saturating_add(1);
                tracing::debug!(job_id = %artifact.job_id, reference = %reason,
                    "durable query-result GC retained a still-referenced job artifact");
            }
            GcDecision::RetainWithinWindow => {
                report.jobs_retained_within_window =
                    report.jobs_retained_within_window.saturating_add(1);
            }
            GcDecision::RetainError(error) => {
                report.jobs_retained_error = report.jobs_retained_error.saturating_add(1);
                tracing::warn!(job_id = %artifact.job_id, error = %error,
                    "durable query-result GC retained a job artifact it could not judge");
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs::{File, FileTimes};
    use std::time::SystemTime;

    /// Deterministic reachability oracle: job_id -> Some(reason) (referenced),
    /// None (unreferenced). Unknown jobs report an error, which the sweep must
    /// treat as "retain".
    struct FakeReachability(HashMap<String, Option<String>>);

    impl JobReachability for FakeReachability {
        fn job_reference(
            &self,
            job_id: &str,
        ) -> impl Future<Output = Result<Option<String>>> + Send {
            let verdict = self.0.get(job_id).cloned();
            async move { verdict.context("reachability oracle has no verdict for this job") }
        }
    }

    const RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

    fn write_job_dir(root: &Path, tenant: &str, job_id: &str, age: Duration) -> PathBuf {
        let dir = root
            .join(format!("tenant-{}", crate::job::sha256(tenant.as_bytes())))
            .join(format!("job-{job_id}"))
            .join("attempt-1");
        std::fs::create_dir_all(&dir).unwrap();
        let stamp = SystemTime::now() - age;
        for name in ["manifest.json", "part-000000.parquet"] {
            let path = dir.join(name);
            std::fs::write(&path, b"artifact-bytes").unwrap();
            File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_times(FileTimes::new().set_modified(stamp))
                .unwrap();
        }
        dir
    }

    fn job_dir_exists(root: &Path, tenant: &str, job_id: &str) -> bool {
        root.join(format!("tenant-{}", crate::job::sha256(tenant.as_bytes())))
            .join(format!("job-{job_id}"))
            .exists()
    }

    #[tokio::test]
    async fn referenced_job_results_survive_even_past_the_window() {
        let root = tempfile::tempdir().unwrap();
        write_job_dir(
            root.path(),
            "tenant-a",
            "job-live",
            Duration::from_secs(30 * 86_400),
        );
        let reachability = FakeReachability(HashMap::from([(
            "job-live".to_string(),
            Some("job_record".to_string()),
        )]));
        let report = sweep_result_root(
            root.path().to_str().unwrap(),
            None,
            &reachability,
            RETENTION,
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(report.jobs_reclaimed, 0);
        assert_eq!(report.jobs_retained_referenced, 1);
        assert!(job_dir_exists(root.path(), "tenant-a", "job-live"));
    }

    #[tokio::test]
    async fn expired_unreferenced_results_are_reclaimed_past_the_window() {
        let root = tempfile::tempdir().unwrap();
        write_job_dir(
            root.path(),
            "tenant-a",
            "job-gone",
            Duration::from_secs(30 * 86_400),
        );
        let reachability = FakeReachability(HashMap::from([("job-gone".to_string(), None)]));
        let report = sweep_result_root(
            root.path().to_str().unwrap(),
            None,
            &reachability,
            RETENTION,
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(report.jobs_reclaimed, 1);
        assert_eq!(report.objects_reclaimed, 2);
        assert!(report.bytes_reclaimed > 0);
        assert!(!job_dir_exists(root.path(), "tenant-a", "job-gone"));
    }

    #[tokio::test]
    async fn the_retention_window_is_respected_for_unreferenced_results() {
        let root = tempfile::tempdir().unwrap();
        // Unreferenced, but written just now: the window protects it.
        write_job_dir(root.path(), "tenant-a", "job-fresh", Duration::ZERO);
        let reachability = FakeReachability(HashMap::from([("job-fresh".to_string(), None)]));
        let report = sweep_result_root(
            root.path().to_str().unwrap(),
            None,
            &reachability,
            RETENTION,
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(report.jobs_reclaimed, 0);
        assert_eq!(report.jobs_retained_within_window, 1);
        assert!(job_dir_exists(root.path(), "tenant-a", "job-fresh"));
    }

    #[tokio::test]
    async fn one_new_object_in_an_old_directory_protects_the_whole_job() {
        let root = tempfile::tempdir().unwrap();
        let dir = write_job_dir(
            root.path(),
            "tenant-a",
            "job-mixed",
            Duration::from_secs(30 * 86_400),
        );
        // A retried attempt just wrote a fresh page next to old ones.
        std::fs::write(dir.join("part-000001.parquet"), b"fresh").unwrap();
        let reachability = FakeReachability(HashMap::from([("job-mixed".to_string(), None)]));
        let report = sweep_result_root(
            root.path().to_str().unwrap(),
            None,
            &reachability,
            RETENTION,
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(report.jobs_reclaimed, 0);
        assert_eq!(report.jobs_retained_within_window, 1);
        assert!(job_dir_exists(root.path(), "tenant-a", "job-mixed"));
    }

    #[tokio::test]
    async fn unrecognized_directories_and_oracle_errors_are_never_deleted() {
        let root = tempfile::tempdir().unwrap();
        // A directory the layout does not describe.
        let stray = root
            .path()
            .join(format!(
                "tenant-{}",
                crate::job::sha256("tenant-a".as_bytes())
            ))
            .join("not-a-job-dir");
        std::fs::create_dir_all(&stray).unwrap();
        std::fs::write(stray.join("file.bin"), b"keep-me").unwrap();
        // An old job the oracle cannot answer for.
        write_job_dir(
            root.path(),
            "tenant-a",
            "job-unknown",
            Duration::from_secs(30 * 86_400),
        );
        let reachability = FakeReachability(HashMap::new());
        let report = sweep_result_root(
            root.path().to_str().unwrap(),
            None,
            &reachability,
            RETENTION,
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(report.jobs_reclaimed, 0);
        assert_eq!(report.jobs_retained_unparseable, 1);
        assert_eq!(report.jobs_retained_error, 1);
        assert!(stray.join("file.bin").exists());
        assert!(job_dir_exists(root.path(), "tenant-a", "job-unknown"));
    }

    #[tokio::test]
    async fn tenant_filter_scopes_the_sweep_to_one_tenant() {
        let root = tempfile::tempdir().unwrap();
        write_job_dir(
            root.path(),
            "tenant-a",
            "job-a",
            Duration::from_secs(30 * 86_400),
        );
        write_job_dir(
            root.path(),
            "tenant-b",
            "job-b",
            Duration::from_secs(30 * 86_400),
        );
        let reachability = FakeReachability(HashMap::from([
            ("job-a".to_string(), None),
            ("job-b".to_string(), None),
        ]));
        let report = sweep_result_root(
            root.path().to_str().unwrap(),
            Some("tenant-a"),
            &reachability,
            RETENTION,
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(report.jobs_reclaimed, 1);
        assert!(!job_dir_exists(root.path(), "tenant-a", "job-a"));
        assert!(
            job_dir_exists(root.path(), "tenant-b", "job-b"),
            "another tenant's results must never be touched"
        );
    }

    #[test]
    fn reserved_tenants_keys_are_never_reclaimed() {
        let bundle = "tenants/u/parser-bundles/a.tar.gz".to_string();
        let error = guard_reclaim_keys(&[
            ("query-results-v1/tenant-a/job-1/manifest.json".to_string(), 1),
            (bundle, 1),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("platform-owned"), "{error:#}");
        assert!(guard_reclaim_keys(&[("query-results-v1/tenant-a/job-1/manifest.json".to_string(), 1)]).is_ok());
    }

    #[test]
    fn manifests_delete_before_data_pages() {
        let mut objects = vec![
            (
                "tenant-x/job-1/attempt-1/part-000000.parquet".to_string(),
                10,
            ),
            ("tenant-x/job-1/attempt-1/manifest.json".to_string(), 1),
            (
                "tenant-x/job-1/attempt-2/part-000000.parquet".to_string(),
                10,
            ),
            ("tenant-x/job-1/attempt-2/manifest.json".to_string(), 1),
        ];
        manifest_first(&mut objects);
        assert!(objects[0].0.ends_with("attempt-1/manifest.json"));
        assert!(objects[1].0.ends_with("attempt-2/manifest.json"));
    }
}
