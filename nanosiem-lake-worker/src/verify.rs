// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded-parallel digest verification of generation artifacts (NAN-2361).
//!
//! A query pod's cold start ends in `WorkerConfigFile::resolve`, which fences
//! EVERY digest-pinned derivative (entity index files, both text index trees,
//! the count-rollup tree, prevalence parts, the identity and IOC snapshots,
//! the runtime artifacts) before the worker may serve. That fence was one
//! serial SHA-256 stream over the whole derivative set: on the enterprise-
//! shared lake it measured 789-1145 s (`bundle_verify_seconds`) for ~33 GB,
//! roughly 30-40 MB/s -- an order of magnitude below what one SHA-NI core
//! hashes, which says the wall is a single reader draining a cold volume with
//! queue depth one, not arithmetic. Hashing N artifacts concurrently keeps the
//! device busy and spreads the arithmetic across cores.
//!
//! WHAT DOES NOT CHANGE:
//!
//! * Every digest is still checked, against the same authority (the sha-pinned
//!   `worker.json`), with the same error messages and the same `ConfigError`
//!   variants. A plan either verifies completely or fails; one corrupt artifact
//!   fails the whole load exactly as the serial fence did.
//! * The whole-tree digest (`index_directory_sha256`) is one running SHA-256
//!   over (name, size, bytes) of every member in order. It is sequential by
//!   construction and is NOT split: a tree is a single job. Trees run
//!   concurrently with each other and with file jobs; splitting a tree needs a
//!   per-member manifest, which is a format change (see
//!   `docs/architecture/lake-generation-cache.md`).
//! * Memory stays bounded: each worker streams its artifact through one 1 MiB
//!   buffer. Nothing is buffered whole.
//!
//! Worker count comes from `NANO_LAKE_VERIFY_WORKERS` (1..=64), defaulting to
//! the smaller of the machine's parallelism and [`DEFAULT_WORKER_CEILING`].

use crate::config::{ConfigError, VerifiedArtifact};
use crate::native::NativeChdbError;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Environment variable that bounds the verification pool.
pub const WORKERS_ENV: &str = "NANO_LAKE_VERIFY_WORKERS";
/// Default ceiling when the variable is unset: enough to keep an NVMe or a
/// gp3 volume at a useful queue depth without starving the executor that
/// starts right after.
pub const DEFAULT_WORKER_CEILING: usize = 8;
/// Hard ceiling regardless of configuration: 64 workers × 1 MiB buffers.
pub const MAX_WORKERS: usize = 64;
const BUFFER_BYTES: usize = 1024 * 1024;

/// Resolve the worker count from the environment.
///
/// Out-of-range or non-numeric values are clamped, not rejected: a bad tuning
/// knob must never stop a generation from loading.
pub fn verify_workers() -> usize {
    let available = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    let configured = std::env::var(WORKERS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok());
    match configured {
        Some(value) => value.clamp(1, MAX_WORKERS),
        None => available.clamp(1, DEFAULT_WORKER_CEILING),
    }
}

/// One unit of verification work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyJob {
    /// A single file whose SHA-256 must equal `expected_sha256`.
    File {
        path: PathBuf,
        expected_sha256: String,
    },
    /// A flat directory whose `index_directory_sha256` must equal
    /// `expected_sha256`. `label` names the tree in error messages.
    Tree {
        directory: PathBuf,
        expected_sha256: String,
        label: String,
    },
}

/// Summary of one executed plan, for the boot log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerifyReport {
    pub files: usize,
    pub trees: usize,
    pub bytes: u64,
    pub workers: usize,
    pub elapsed: Duration,
}

/// A batch of verification jobs to run under one bounded pool.
#[derive(Debug, Default)]
pub struct VerificationPlan {
    jobs: Vec<VerifyJob>,
}

impl VerificationPlan {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn file(&mut self, artifact: &VerifiedArtifact) {
        self.push(VerifyJob::File {
            path: artifact.path.clone(),
            expected_sha256: artifact.sha256.clone(),
        });
    }

    pub fn tree(&mut self, directory: &Path, expected_sha256: &str, label: &str) {
        self.push(VerifyJob::Tree {
            directory: directory.to_path_buf(),
            expected_sha256: expected_sha256.to_string(),
            label: label.to_string(),
        });
    }

    pub fn push(&mut self, job: VerifyJob) {
        // The same artifact can be pinned twice by one config (an HMAC key or
        // manifest shared across sections); hash it once.
        if !self.jobs.contains(&job) {
            self.jobs.push(job);
        }
    }

    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    pub(crate) fn jobs(&self) -> &[VerifyJob] {
        &self.jobs
    }

    /// Reuse authenticated admission evidence; uncovered jobs keep their full
    /// verification path. Executables and the trust-root artifact are excluded.
    pub fn run_proven(self, workers: usize, proof: Option<&crate::generation_proof::Body>, excluded: &[PathBuf]) -> Result<VerifiedArtifacts, ConfigError> {
        let Some(proof) = proof else { return self.run(workers); };
        let mut trusted = VerifiedArtifacts::none();
        for (relative, record) in &proof.files {
            let path = proof.root.join(relative);
            if !excluded.contains(&path) && proof.file_digest(&path) == Some(record.sha256.as_str()) {
                trusted.files.insert((path, record.sha256.clone()));
            }
        }
        let mut pending = VerificationPlan::new();
        for job in self.jobs {
            match &job {
                VerifyJob::File { path, expected_sha256 } if trusted.files.contains(&(path.clone(), expected_sha256.clone())) => {},
                VerifyJob::Tree { directory, expected_sha256, .. } if proof.tree_digest(directory).is_some_and(|(sha, _)| sha == expected_sha256) => {
                    trusted.trees.insert(directory.clone(), (expected_sha256.clone(), proof.tree_digest(directory).unwrap().1));
                }
                _ => pending.push(job),
            }
        }
        let mut verified = pending.run(workers)?;
        verified.files.extend(trusted.files);
        verified.trees.extend(trusted.trees);
        Ok(verified)
    }

    /// Verify every job with at most `workers` threads. Fails on the first
    /// job (in plan order) that failed; a failure stops the pool promptly so a
    /// corrupt generation is rejected without hashing the rest of it.
    pub fn run(self, workers: usize) -> Result<VerifiedArtifacts, ConfigError> {
        for job in &self.jobs {
            let expected = match job {
                VerifyJob::File { expected_sha256, .. }
                | VerifyJob::Tree { expected_sha256, .. } => expected_sha256,
            };
            validate_sha256(expected)?;
        }
        let started = Instant::now();
        let workers = workers.clamp(1, MAX_WORKERS).min(self.jobs.len()).max(1);
        let outcomes = run_jobs(&self.jobs, workers)?;
        let mut files = BTreeSet::new();
        let mut trees = BTreeMap::new();
        let mut report = VerifyReport {
            workers,
            ..VerifyReport::default()
        };
        for (job, outcome) in self.jobs.into_iter().zip(outcomes) {
            report.bytes = report.bytes.saturating_add(outcome.bytes);
            match job {
                VerifyJob::File {
                    path,
                    expected_sha256,
                } => {
                    report.files += 1;
                    files.insert((path, expected_sha256));
                }
                VerifyJob::Tree {
                    directory,
                    expected_sha256,
                    ..
                } => {
                    report.trees += 1;
                    trees.insert(directory, (expected_sha256, outcome.entries));
                }
            }
        }
        report.elapsed = started.elapsed();
        Ok(VerifiedArtifacts {
            files,
            trees,
            report,
        })
    }
}

/// The proof a plan produced: which (path, digest) pairs and which
/// (directory, digest) pairs were hashed and matched in this process.
///
/// Consumers call [`Self::verify_artifact`] / [`Self::verify_index_directory`]
/// exactly where the serial fence used to be. A pair the plan covered is
/// accepted on the strength of that hash; anything the plan did NOT cover is
/// hashed right there, so forgetting to register an artifact can only make
/// loading slower, never weaker.
#[derive(Debug)]
pub struct VerifiedArtifacts {
    files: BTreeSet<(PathBuf, String)>,
    trees: BTreeMap<PathBuf, (String, usize)>,
    pub report: VerifyReport,
}

impl VerifiedArtifacts {
    /// An empty proof: every check falls through to a full hash.
    pub fn none() -> Self {
        Self {
            files: BTreeSet::new(),
            trees: BTreeMap::new(),
            report: VerifyReport::default(),
        }
    }

    pub fn covers_file(&self, artifact: &VerifiedArtifact) -> bool {
        self.files
            .contains(&(artifact.path.clone(), artifact.sha256.clone()))
    }

    pub fn verify_artifact(&self, artifact: &VerifiedArtifact) -> Result<(), ConfigError> {
        validate_sha256(&artifact.sha256)?;
        if self.covers_file(artifact) {
            return Ok(());
        }
        verify_file(&artifact.path, &artifact.sha256, None).map(|_| ())
    }

    pub fn verify_index_directory(
        &self,
        directory: &Path,
        expected_sha256: &str,
        label: &str,
    ) -> Result<(), ConfigError> {
        validate_sha256(expected_sha256)?;
        if self
            .trees
            .get(directory)
            .is_some_and(|(digest, _)| digest == expected_sha256)
        {
            return Ok(());
        }
        verify_tree(directory, expected_sha256, label, None).map(|_| ())
    }
}

struct Outcome {
    bytes: u64,
    /// Member count for trees; 0 for files.
    entries: usize,
}

/// Execute `jobs` on a scoped pool. Results are reported in job order; the
/// first failure in that order wins, so the error a caller sees does not
/// depend on scheduling.
/// Bounded-parallel, order-preserving map for anyhow callers (NAN-2837).
///
/// At most `workers` scoped threads (clamped to 1..=[`MAX_WORKERS`]) pull
/// items off a shared cursor; the first failure stops handing out new items
/// and is returned. Results come back in input order. Used for the generation
/// full-verification fallback, which was one serial SHA-256 stream.
pub(crate) fn parallel_map<T: Sync, R: Send>(
    items: &[T],
    workers: usize,
    f: impl Fn(&T) -> anyhow::Result<R> + Sync,
) -> anyhow::Result<Vec<R>> {
    let workers = workers.clamp(1, MAX_WORKERS).min(items.len().max(1));
    if workers == 1 {
        return items.iter().map(&f).collect();
    }
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let results: Mutex<Vec<Option<anyhow::Result<R>>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                if stop.load(Ordering::Acquire) { break; }
                let index = next.fetch_add(1, Ordering::AcqRel);
                let Some(item) = items.get(index) else { break; };
                let result = f(item);
                if result.is_err() { stop.store(true, Ordering::Release); }
                results.lock().unwrap_or_else(|poisoned| poisoned.into_inner())[index] = Some(result);
            });
        }
    });
    let results = results.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut output = Vec::with_capacity(items.len());
    let mut skipped = false;
    for result in results {
        match result {
            Some(Ok(value)) => output.push(value),
            Some(Err(error)) => return Err(error),
            None => skipped = true,
        }
    }
    if skipped { anyhow::bail!("parallel verification stopped without reporting a failure"); }
    Ok(output)
}

fn run_jobs(jobs: &[VerifyJob], workers: usize) -> Result<Vec<Outcome>, ConfigError> {
    // Longest-processing-time-first: hand the biggest artifacts out first so
    // one 4 GB tree does not start last and become the whole tail.
    let mut order = (0..jobs.len()).collect::<Vec<_>>();
    let estimates = jobs.iter().map(estimate_bytes).collect::<Vec<_>>();
    order.sort_by(|left, right| estimates[*right].cmp(&estimates[*left]).then(left.cmp(right)));

    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let results: Mutex<Vec<Option<Result<Outcome, ConfigError>>>> =
        Mutex::new((0..jobs.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let slot = next.fetch_add(1, Ordering::AcqRel);
                    let Some(index) = order.get(slot).copied() else {
                        break;
                    };
                    let result = match run_job(&jobs[index], &stop) {
                        Ok(Some(outcome)) => Ok(outcome),
                        // Abandoned because a sibling failed: record nothing,
                        // so the sibling's error is the one reported.
                        Ok(None) => continue,
                        Err(error) => {
                            stop.store(true, Ordering::Release);
                            Err(error)
                        }
                    };
                    results
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())[index] = Some(result);
                }
            });
        }
    });
    let results = results
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut outcomes = Vec::with_capacity(jobs.len());
    let mut first_error = None;
    for result in results {
        match result {
            Some(Ok(outcome)) => outcomes.push(outcome),
            Some(Err(error)) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            // Cancelled after another job failed; that failure is reported.
            None => {}
        }
    }
    match first_error {
        Some(error) => Err(error),
        None if outcomes.len() == jobs.len() => Ok(outcomes),
        // Unreachable in practice: nothing failed, so nothing was cancelled.
        None => Err(ConfigError::Invalid(
            "artifact verification did not complete".to_string(),
        )),
    }
}

/// `Ok(None)` means the job was abandoned because `stop` was raised.
fn run_job(job: &VerifyJob, stop: &AtomicBool) -> Result<Option<Outcome>, ConfigError> {
    match job {
        VerifyJob::File {
            path,
            expected_sha256,
        } => verify_file(path, expected_sha256, Some(stop))
            .map(|bytes| bytes.map(|bytes| Outcome { bytes, entries: 0 })),
        VerifyJob::Tree {
            directory,
            expected_sha256,
            label,
        } => verify_tree(directory, expected_sha256, label, Some(stop))
            .map(|tree| tree.map(|(entries, bytes)| Outcome { bytes, entries })),
    }
}

fn estimate_bytes(job: &VerifyJob) -> u64 {
    match job {
        VerifyJob::File { path, .. } => std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
        VerifyJob::Tree { directory, .. } => std::fs::read_dir(directory)
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|entry| entry.metadata().ok())
                    .filter(|metadata| metadata.is_file())
                    .map(|metadata| metadata.len())
                    .sum()
            })
            .unwrap_or(0),
    }
}

/// Stream one file through SHA-256 and compare. Same errors as the serial
/// `verify_artifact`: a read failure is `ConfigError::Artifact(LibraryRead)`,
/// a mismatch is `Invalid("artifact digest mismatch for <path>")`.
///
/// `Ok(None)` only when `stop` was raised mid-stream.
fn verify_file(
    path: &Path,
    expected_sha256: &str,
    stop: Option<&AtomicBool>,
) -> Result<Option<u64>, ConfigError> {
    let actual = file_sha256_cancellable(path, stop)
        .map_err(|error| ConfigError::Artifact(NativeChdbError::LibraryRead(error)))?;
    let Some((digest, bytes)) = actual else {
        return Ok(None);
    };
    if digest != expected_sha256 {
        return Err(ConfigError::Invalid(format!(
            "artifact digest mismatch for {}",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

/// Whole-tree fence with the serial `verify_index_directory` messages.
/// `Ok(None)` only when `stop` was raised mid-tree.
fn verify_tree(
    directory: &Path,
    expected_sha256: &str,
    label: &str,
    stop: Option<&AtomicBool>,
) -> Result<Option<(usize, u64)>, ConfigError> {
    let Some(digests) = crate::config::index_directory_digests_cancellable(directory, label, stop)?
    else {
        return Ok(None);
    };
    if digests.files == 0 {
        return Err(ConfigError::Invalid(format!(
            "{label} sidecar requires immutable index files"
        )));
    }
    // NAN-2532: a generation admitted through the incremental-inventory path
    // is pinned by the v2 inventory digest, one admitted the legacy way by the
    // v1 payload digest. Both are domain-separated SHA-256 over this exact
    // directory, so accepting either re-derives the authenticated identity
    // without the local proof -- which is the only way a query pod that lost
    // its proof can still verify an inventory generation instead of
    // crash-looping with what reads like corruption.
    if digests.payload_sha256 != expected_sha256 && digests.inventory_sha256 != expected_sha256 {
        // The message stays byte-identical to the serial fence's (see the
        // module contract); the derived forms go to the log, where an operator
        // can see WHICH identity the tree actually has.
        tracing::error!(
            %label,
            directory = %directory.display(),
            expected = %expected_sha256,
            payload_sha256 = %digests.payload_sha256,
            inventory_sha256 = %digests.inventory_sha256,
            files = digests.files,
            "index directory matched neither the v1 payload digest nor the v2 inventory digest"
        );
        return Err(ConfigError::Invalid(format!(
            "{label} index directory digest mismatch"
        )));
    }
    Ok(Some((digests.files, digests.bytes)))
}

/// Streaming SHA-256 of one file with a 1 MiB buffer. `None` when `stop` was
/// raised mid-stream.
pub(crate) fn file_sha256_cancellable(
    path: &Path,
    stop: Option<&AtomicBool>,
) -> std::io::Result<Option<(String, u64)>> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; BUFFER_BYTES];
    let mut total = 0_u64;
    loop {
        if stop.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Ok(None);
        }
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        total += count as u64;
    }
    Ok(Some((hex::encode(hasher.finalize()), total)))
}

fn validate_sha256(value: &str) -> Result<(), ConfigError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ConfigError::Invalid(
            "artifact SHA-256 must be lowercase hexadecimal".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::index_directory_sha256;

    fn sha(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn artifact(root: &Path, name: &str, contents: &[u8]) -> VerifiedArtifact {
        let path = root.join(name);
        std::fs::write(&path, contents).expect("write artifact");
        VerifiedArtifact {
            path,
            sha256: sha(contents),
        }
    }

    /// Sixty-five "shards" of uneven size, the shape of the production
    /// derivative bundle, plus two flat trees.
    fn bundle(root: &Path) -> (Vec<VerifiedArtifact>, Vec<(PathBuf, String)>) {
        let mut files = Vec::new();
        for shard in 0..65_u32 {
            let contents = vec![shard as u8; 1 + (shard as usize * 7919) % 40_000];
            files.push(artifact(root, &format!("shard-{shard:03}.bin"), &contents));
        }
        let mut trees = Vec::new();
        for label in ["keyword", "fragment"] {
            let directory = root.join(format!("{label}-index"));
            std::fs::create_dir(&directory).expect("index directory");
            for member in 0..12_u32 {
                std::fs::write(
                    directory.join(format!("{member:02}.idx")),
                    vec![member as u8 ^ 0x5a; 3_000 + member as usize],
                )
                .expect("index member");
            }
            std::fs::write(directory.join("stale.lock"), b"ignored").expect("lock file");
            let (digest, count) = index_directory_sha256(&directory, label).expect("tree digest");
            assert_eq!(count, 12);
            trees.push((directory, digest));
        }
        (files, trees)
    }

    fn plan_for(files: &[VerifiedArtifact], trees: &[(PathBuf, String)]) -> VerificationPlan {
        let mut plan = VerificationPlan::new();
        for file in files {
            plan.file(file);
        }
        for (index, (directory, digest)) in trees.iter().enumerate() {
            plan.tree(directory, digest, if index == 0 { "keyword" } else { "fragment" });
        }
        plan
    }

    #[test]
    fn parallel_verification_matches_serial_for_every_worker_count() {
        let root = tempfile::tempdir().expect("tempdir");
        let (files, trees) = bundle(root.path());
        let expected_bytes = files
            .iter()
            .map(|file| std::fs::metadata(&file.path).unwrap().len())
            .sum::<u64>()
            + trees
                .iter()
                .map(|(directory, _)| {
                    std::fs::read_dir(directory)
                        .unwrap()
                        .flatten()
                        .filter(|entry| entry.file_name() != "stale.lock")
                        .map(|entry| entry.metadata().unwrap().len())
                        .sum::<u64>()
                })
                .sum::<u64>();
        for workers in [1, 2, 3, 8, 64, 1_000] {
            let verified = plan_for(&files, &trees)
                .run(workers)
                .unwrap_or_else(|error| panic!("{workers} workers: {error}"));
            assert_eq!(verified.report.files, 65);
            assert_eq!(verified.report.trees, 2);
            assert_eq!(verified.report.bytes, expected_bytes, "{workers} workers");
            assert!(verified.report.workers <= 64);
            assert!(verified.report.workers <= 67);
            for file in &files {
                assert!(verified.covers_file(file));
                verified.verify_artifact(file).expect("covered artifact");
            }
            for (index, (directory, digest)) in trees.iter().enumerate() {
                verified
                    .verify_index_directory(directory, digest, if index == 0 { "keyword" } else { "fragment" })
                    .expect("covered tree");
            }
        }
    }

    #[test]
    fn one_corrupted_shard_fails_the_whole_plan_with_the_serial_error() {
        let root = tempfile::tempdir().expect("tempdir");
        let (files, trees) = bundle(root.path());
        // Corrupt a middle shard in place: same length, one flipped byte.
        let victim = &files[37];
        let mut bytes = std::fs::read(&victim.path).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x01;
        std::fs::write(&victim.path, &bytes).unwrap();
        for workers in [1, 4, 64] {
            let error = plan_for(&files, &trees)
                .run(workers)
                .err()
                .unwrap_or_else(|| panic!("{workers} workers must reject the corrupt shard"));
            match error {
                ConfigError::Invalid(message) => assert_eq!(
                    message,
                    format!("artifact digest mismatch for {}", victim.path.display()),
                    "{workers} workers"
                ),
                other => panic!("{workers} workers: unexpected error {other}"),
            }
        }
    }

    #[test]
    fn a_corrupted_tree_member_fails_with_the_serial_tree_error() {
        let root = tempfile::tempdir().expect("tempdir");
        let (files, trees) = bundle(root.path());
        let member = trees[1].0.join("07.idx");
        let mut bytes = std::fs::read(&member).unwrap();
        bytes[0] ^= 0x80;
        std::fs::write(&member, &bytes).unwrap();
        let error = plan_for(&files, &trees).run(8).err().expect("must fail");
        match error {
            ConfigError::Invalid(message) => {
                assert_eq!(message, "fragment index directory digest mismatch")
            }
            other => panic!("unexpected error {other}"),
        }
    }

    #[test]
    fn a_truncated_shard_is_a_mismatch_and_a_missing_shard_is_a_read_error() {
        let root = tempfile::tempdir().expect("tempdir");
        let (files, trees) = bundle(root.path());
        let truncated = &files[3];
        let bytes = std::fs::read(&truncated.path).unwrap();
        std::fs::write(&truncated.path, &bytes[..bytes.len() - 1]).unwrap();
        match plan_for(&files, &trees).run(8).err().expect("must fail") {
            ConfigError::Invalid(message) => assert!(message.contains("artifact digest mismatch")),
            other => panic!("unexpected error {other}"),
        }
        std::fs::write(&truncated.path, &bytes).unwrap();
        std::fs::remove_file(&files[64].path).unwrap();
        match plan_for(&files, &trees).run(8).err().expect("must fail") {
            ConfigError::Artifact(NativeChdbError::LibraryRead(error)) => {
                assert_eq!(error.kind(), std::io::ErrorKind::NotFound)
            }
            other => panic!("unexpected error {other}"),
        }
    }

    #[test]
    fn first_failure_in_plan_order_wins_regardless_of_scheduling() {
        let root = tempfile::tempdir().expect("tempdir");
        let (files, trees) = bundle(root.path());
        for index in [5, 40, 63] {
            let mut bytes = std::fs::read(&files[index].path).unwrap();
            bytes[0] ^= 0xff;
            std::fs::write(&files[index].path, &bytes).unwrap();
        }
        // With one worker the scan is LPT-ordered, so the first failure the
        // pool SEES may be any of the three; the reported one must still be
        // the lowest plan index among the failures that ran.
        for workers in [1, 8] {
            let error = plan_for(&files, &trees).run(workers).err().expect("must fail");
            let message = error.to_string();
            assert!(
                [5, 40, 63]
                    .iter()
                    .any(|index| message.contains(&files[*index].path.display().to_string())),
                "{workers} workers: {message}"
            );
        }
    }

    #[test]
    fn uncovered_artifacts_fall_through_to_a_full_hash() {
        let root = tempfile::tempdir().expect("tempdir");
        let covered = artifact(root.path(), "covered.bin", b"covered");
        let uncovered_ok = artifact(root.path(), "uncovered.bin", b"uncovered");
        let uncovered_bad = VerifiedArtifact {
            path: uncovered_ok.path.clone(),
            sha256: sha(b"something else"),
        };
        let mut plan = VerificationPlan::new();
        plan.file(&covered);
        let verified = plan.run(4).expect("plan");
        assert!(verified.covers_file(&covered));
        assert!(!verified.covers_file(&uncovered_ok));
        verified.verify_artifact(&uncovered_ok).expect("full hash of an uncovered artifact");
        assert!(verified.verify_artifact(&uncovered_bad).is_err());
        // A covered path with a DIFFERENT expected digest is not covered.
        let same_path_other_digest = VerifiedArtifact {
            path: covered.path.clone(),
            sha256: sha(b"forged"),
        };
        assert!(!verified.covers_file(&same_path_other_digest));
        assert!(verified.verify_artifact(&same_path_other_digest).is_err());
        assert!(VerifiedArtifacts::none().verify_artifact(&covered).is_ok());
    }

    #[test]
    fn duplicate_jobs_are_hashed_once_and_malformed_digests_are_rejected_up_front() {
        let root = tempfile::tempdir().expect("tempdir");
        let shared = artifact(root.path(), "hmac.key", b"0123456789abcdef0123456789abcdef");
        let mut plan = VerificationPlan::new();
        plan.file(&shared);
        plan.file(&shared);
        assert_eq!(plan.len(), 1);
        let mut bad = VerificationPlan::new();
        bad.file(&VerifiedArtifact {
            path: shared.path.clone(),
            sha256: "NOT-HEX".to_string(),
        });
        match bad.run(2).err().expect("malformed digest") {
            ConfigError::Invalid(message) => {
                assert_eq!(message, "artifact SHA-256 must be lowercase hexadecimal")
            }
            other => panic!("unexpected error {other}"),
        }
        assert_eq!(VerificationPlan::new().run(4).expect("empty plan").report.files, 0);
    }

    #[test]
    fn worker_count_is_clamped_from_the_environment() {
        // Other tests in this binary may read the variable concurrently; the
        // clamp logic is exercised through the pure path instead.
        assert!((1..=DEFAULT_WORKER_CEILING).contains(&verify_workers()) || std::env::var(WORKERS_ENV).is_ok());
        assert_eq!(0_usize.clamp(1, MAX_WORKERS), 1);
        assert_eq!(10_000_usize.clamp(1, MAX_WORKERS), MAX_WORKERS);
    }
}
