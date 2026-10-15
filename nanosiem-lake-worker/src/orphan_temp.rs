// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded cleanup for local publication temporaries left by an ungraceful
//! process exit.
//!
//! These helpers deliberately know only the exact `tempfile` namespaces used
//! by snapshot hydration, prevalence publication, and IOC publication. Final
//! paths have disjoint names. Callers must hold the existing exclusive writer
//! lock for the entire sweep.
//!
//! Liveness (NAN-2830). Most temporaries are only proven abandoned by age:
//! nothing but the writer lock excludes their writer, so a young one is
//! retained for [`DEFAULT_ORPHAN_TEMP_GRACE`]. A prevalence builder's candidate
//! directory lives INSIDE a final derivatives tree, where the bundle inventory
//! refuses every hidden entry, so a 24-hour retention after a pod kill blocked
//! generation publishing outright (and cost a full rebuild first). The builder
//! therefore holds a [`BuilderTempLease`] (an exclusive flock on the directory
//! itself) for its whole life, and the sweep reclaims such a directory as soon
//! as that lease is free, whatever its age. A kernel releases the flock when
//! the builder dies, SIGKILL included.

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub const DEFAULT_ORPHAN_TEMP_GRACE: Duration = Duration::from_secs(86_400);

/// `tempfile` prefix of the prevalence builder's candidate directory, created
/// beside the final `prevalence-snapshot-v2` inside a derivatives tree. Its
/// part-job files (`.prevalence-part-jobs-*.json`) and `parts/` live inside it.
pub const PREVALENCE_BUILDER_TEMP_PREFIX: &str = ".prevalence-snapshot-";

/// Exclusive flock a builder holds on its own temp directory while it may
/// still write there. Released explicitly (LOCK_UN) on drop, and by the kernel
/// when the process dies.
#[derive(Debug)]
pub struct BuilderTempLease(std::fs::File);

impl BuilderTempLease {
    /// Take the lease on a directory this process just created.
    pub fn acquire(directory: &Path) -> Result<Self> {
        match Self::try_acquire(directory)? {
            Some(lease) => Ok(lease),
            None => bail!(
                "builder temporary {} is already leased by another builder",
                directory.display()
            ),
        }
    }

    /// `Ok(None)` when a live builder holds the lease.
    fn try_acquire(directory: &Path) -> Result<Option<Self>> {
        let file = std::fs::File::open(directory)
            .with_context(|| format!("open builder temporary {}", directory.display()))?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Some(Self(file))),
            Err(error) if error.kind() == fs2::lock_contended_error().kind() => Ok(None),
            Err(error) => Err(error)
                .with_context(|| format!("lease builder temporary {}", directory.display())),
        }
    }
}

impl Drop for BuilderTempLease {
    fn drop(&mut self) {
        // Explicit LOCK_UN: a copy of this descriptor in a forked-but-not-yet-
        // exec'd child must not keep a finished builder looking live (NAN-2822).
        let _ = FileExt::unlock(&self.0);
    }
}

const MAX_PARENT_ENTRIES: u64 = 4_096;
const MAX_SWEEP_DIRECTORY_ENTRIES: u64 = 65_536;
const MAX_GENERATION_DIRECTORIES: u64 = 1_024;
const MAX_CANDIDATES_PER_SWEEP: usize = 16;
const MAX_CANDIDATE_TREE_ENTRIES: u64 = 125_000;
const MAX_DELETIONS_PER_SWEEP: usize = 4;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OrphanTempSweepReport {
    pub scanned_entries: u64,
    pub matched_candidates: u64,
    pub deleted: u64,
    pub deleted_files: u64,
    pub deleted_bytes: u64,
    pub retained_young: u64,
    /// Builder temporaries whose builder still holds its lease.
    pub retained_live: u64,
    pub retained_unsafe: u64,
    pub retained_delete_limit: u64,
    pub delete_errors: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateKind {
    Directory,
    File,
}

/// What proves a candidate's writer is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Liveness {
    /// Nothing but age: every entry must be older than the grace cutoff.
    AgeGrace,
    /// The writer's [`BuilderTempLease`] is free, at any age.
    BuilderLease,
}

#[derive(Debug)]
struct Candidate {
    path: PathBuf,
    kind: CandidateKind,
    liveness: Liveness,
}

#[derive(Debug)]
struct EligibleCandidate {
    candidate: Candidate,
    files: u64,
    bytes: u64,
    /// Held from validation through deletion for `Liveness::BuilderLease`.
    lease: Option<BuilderTempLease>,
}

#[derive(Debug)]
enum CandidateDisposition {
    Eligible {
        files: u64,
        bytes: u64,
        lease: Option<BuilderTempLease>,
    },
    Young,
    Live,
    Unsafe,
}

/// Sweep snapshot-hydration and prevalence-publication temporaries beneath a
/// generation cache. The generation manager's `.generation-manager.lock`
/// must be held by the caller.
pub fn sweep_generation_orphan_temporaries(
    generations_root: &Path,
    now: SystemTime,
    grace: Duration,
) -> Result<OrphanTempSweepReport> {
    require_absolute_directory(generations_root, "generation cache")?;
    let cutoff = now
        .checked_sub(grace)
        .context("orphan temporary grace is too large")?;
    let mut report = OrphanTempSweepReport::default();
    let mut candidates = Vec::new();
    let mut generation_count = 0_u64;

    for generation in bounded_read_dir(generations_root, &mut report)? {
        let name = generation.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let file_type = generation.file_type()?;
        if exact_tempfile_name(name, ".generation-handover-", "") {
            push_candidate(
                &mut candidates,
                &mut report,
                Candidate {
                    path: generation.path(),
                    kind: CandidateKind::Directory,
                    liveness: Liveness::AgeGrace,
                },
            )?;
            continue;
        }

        if !file_type.is_dir() || !valid_generation_name(name) {
            continue;
        }
        generation_count += 1;
        if generation_count > MAX_GENERATION_DIRECTORIES {
            bail!(
                "generation cache exceeds bounded directory count of {MAX_GENERATION_DIRECTORIES}"
            );
        }
        for entry in bounded_read_dir(&generation.path(), &mut report)? {
            let entry_name = entry.file_name();
            let Some(entry_name) = entry_name.to_str() else {
                continue;
            };
            if exact_tempfile_name(entry_name, ".lake-snapshot-", "") {
                push_candidate(
                    &mut candidates,
                    &mut report,
                    Candidate {
                        path: entry.path(),
                        kind: CandidateKind::Directory,
                        liveness: Liveness::AgeGrace,
                    },
                )?;
                continue;
            }
            if !entry.file_type()?.is_dir() || !valid_derivative_name(entry_name) {
                continue;
            }
            for prevalence in bounded_read_dir(&entry.path(), &mut report)? {
                let prevalence_name = prevalence.file_name();
                let Some(prevalence_name) = prevalence_name.to_str() else {
                    continue;
                };
                if exact_tempfile_name(prevalence_name, PREVALENCE_BUILDER_TEMP_PREFIX, "") {
                    push_candidate(
                        &mut candidates,
                        &mut report,
                        Candidate {
                            path: prevalence.path(),
                            kind: CandidateKind::Directory,
                            liveness: Liveness::BuilderLease,
                        },
                    )?;
                }
            }
        }
    }

    delete_eligible_candidates(candidates, cutoff, &mut report)?;
    Ok(report)
}

/// Sweep IOC Parquet temporaries in the snapshot directory. The caller must
/// hold the publisher's exclusive `ioc.lock` (and its outer generation lock,
/// when the publication path acquires both).
pub fn sweep_ioc_orphan_temporaries(
    snapshot_dir: &Path,
    now: SystemTime,
    grace: Duration,
) -> Result<OrphanTempSweepReport> {
    require_absolute_directory(snapshot_dir, "IOC snapshot cache")?;
    let cutoff = now
        .checked_sub(grace)
        .context("orphan temporary grace is too large")?;
    let mut report = OrphanTempSweepReport::default();
    let mut candidates = Vec::new();
    for entry in bounded_read_dir(snapshot_dir, &mut report)? {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if exact_ioc_tempfile_name(name) {
            push_candidate(
                &mut candidates,
                &mut report,
                Candidate {
                    path: entry.path(),
                    kind: CandidateKind::File,
                    liveness: Liveness::AgeGrace,
                },
            )?;
        }
    }
    delete_eligible_candidates(candidates, cutoff, &mut report)?;
    Ok(report)
}

/// Build-start gate for a prevalence build inside `derivatives` (NAN-2830).
/// The caller must hold the generation manager's lock.
///
/// Every hidden top-level entry of a derivatives tree makes the bundle
/// inventory refuse the whole generation, so discovering one only at publish
/// time wastes the build that precedes it. Reclaim abandoned prevalence
/// builder temporaries (free lease, any age), then return `Err` if any hidden
/// entry survives: an unknown one, or a builder that is still alive (two
/// builders in one tree break the generation-lock invariant). The reclaim has
/// already happened when the error is returned; a caller that never publishes
/// bundles may downgrade the error to a warning.
pub fn prepare_prevalence_build_parent(derivatives: &Path) -> Result<OrphanTempSweepReport> {
    require_absolute_directory(derivatives, "derivatives tree")?;
    let mut report = OrphanTempSweepReport::default();
    let mut candidates = Vec::new();
    for entry in bounded_read_dir(derivatives, &mut report)? {
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| exact_tempfile_name(name, PREVALENCE_BUILDER_TEMP_PREFIX, ""))
        {
            push_candidate(
                &mut candidates,
                &mut report,
                Candidate {
                    path: entry.path(),
                    kind: CandidateKind::Directory,
                    liveness: Liveness::BuilderLease,
                },
            )?;
        }
    }
    delete_eligible_candidates(candidates, SystemTime::now(), &mut report)?;
    let mut residue = Vec::new();
    for entry in bounded_read_dir(derivatives, &mut report)? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            residue.push(name);
        }
    }
    if !residue.is_empty() {
        residue.sort();
        bail!(
            "derivatives tree {} holds hidden entries {residue:?} that the generation bundle \
             inventory would refuse (after reclaiming abandoned prevalence builder \
             temporaries: {report:?}); refusing to start the prevalence build",
            derivatives.display()
        );
    }
    Ok(report)
}

fn require_absolute_directory(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        bail!("{label} is not absolute");
    }
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("{label} is not a non-symlink directory");
    }
    Ok(())
}

fn bounded_read_dir(
    directory: &Path,
    report: &mut OrphanTempSweepReport,
) -> Result<Vec<std::fs::DirEntry>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(directory)
        .with_context(|| format!("read orphan temporary parent {}", directory.display()))?
    {
        report.scanned_entries = report.scanned_entries.saturating_add(1);
        if report.scanned_entries > MAX_SWEEP_DIRECTORY_ENTRIES {
            bail!(
                "orphan temporary sweep exceeds bounded directory-entry count of {MAX_SWEEP_DIRECTORY_ENTRIES}"
            );
        }
        if entries.len() >= MAX_PARENT_ENTRIES as usize {
            bail!(
                "orphan temporary parent {} exceeds bounded entry count of {MAX_PARENT_ENTRIES}",
                directory.display()
            );
        }
        entries.push(entry?);
    }
    Ok(entries)
}

fn push_candidate(
    candidates: &mut Vec<Candidate>,
    report: &mut OrphanTempSweepReport,
    candidate: Candidate,
) -> Result<()> {
    report.matched_candidates = report.matched_candidates.saturating_add(1);
    if candidates.len() >= MAX_CANDIDATES_PER_SWEEP {
        bail!(
            "orphan temporary sweep exceeds bounded candidate count of {MAX_CANDIDATES_PER_SWEEP}"
        );
    }
    candidates.push(candidate);
    Ok(())
}

fn delete_eligible_candidates(
    candidates: Vec<Candidate>,
    cutoff: SystemTime,
    report: &mut OrphanTempSweepReport,
) -> Result<()> {
    // Finish the complete bounded validation pass before deleting anything.
    // A read/metadata error therefore retains every candidate.
    let mut eligible = Vec::new();
    for candidate in candidates {
        match inspect_candidate(&candidate, cutoff)? {
            CandidateDisposition::Eligible {
                files,
                bytes,
                lease,
            } => eligible.push(EligibleCandidate {
                candidate,
                files,
                bytes,
                lease,
            }),
            CandidateDisposition::Young => {
                report.retained_young = report.retained_young.saturating_add(1)
            }
            CandidateDisposition::Live => {
                report.retained_live = report.retained_live.saturating_add(1)
            }
            CandidateDisposition::Unsafe => {
                report.retained_unsafe = report.retained_unsafe.saturating_add(1)
            }
        }
    }
    eligible.sort_by(|left, right| left.candidate.path.cmp(&right.candidate.path));
    report.retained_delete_limit = eligible.len().saturating_sub(MAX_DELETIONS_PER_SWEEP) as u64;

    for planned in eligible.into_iter().take(MAX_DELETIONS_PER_SWEEP) {
        // Revalidate immediately before removal. The application lock excludes
        // writers; this second check also fails safe against foreign mutation.
        // A builder lease taken during validation is still held (`lease`).
        match inspect_candidate_with(&planned.candidate, cutoff, planned.lease.is_some()) {
            Ok(CandidateDisposition::Eligible { files, bytes, .. })
                if files == planned.files && bytes == planned.bytes => {}
            Ok(CandidateDisposition::Young) => {
                report.retained_young = report.retained_young.saturating_add(1);
                continue;
            }
            Ok(CandidateDisposition::Live) => {
                report.retained_live = report.retained_live.saturating_add(1);
                continue;
            }
            Ok(CandidateDisposition::Eligible { .. })
            | Ok(CandidateDisposition::Unsafe)
            | Err(_) => {
                report.retained_unsafe = report.retained_unsafe.saturating_add(1);
                report.delete_errors = report.delete_errors.saturating_add(1);
                continue;
            }
        }
        let result = match planned.candidate.kind {
            CandidateKind::Directory => std::fs::remove_dir_all(&planned.candidate.path),
            CandidateKind::File => std::fs::remove_file(&planned.candidate.path),
        };
        if let Err(error) = result {
            tracing::warn!(
                path = %planned.candidate.path.display(),
                error = %error,
                "orphan temporary retained after bounded delete failure"
            );
            report.delete_errors = report.delete_errors.saturating_add(1);
            continue;
        }
        report.deleted = report.deleted.saturating_add(1);
        report.deleted_files = report.deleted_files.saturating_add(planned.files);
        report.deleted_bytes = report.deleted_bytes.saturating_add(planned.bytes);
    }
    Ok(())
}

fn inspect_candidate(candidate: &Candidate, cutoff: SystemTime) -> Result<CandidateDisposition> {
    inspect_candidate_with(candidate, cutoff, false)
}

/// `lease_held`: this sweep already holds the candidate's builder lease (a
/// second flock through a new descriptor would contend with our own).
fn inspect_candidate_with(
    candidate: &Candidate,
    cutoff: SystemTime,
    lease_held: bool,
) -> Result<CandidateDisposition> {
    let metadata = std::fs::symlink_metadata(&candidate.path)
        .with_context(|| format!("inspect orphan temporary {}", candidate.path.display()))?;
    let file_type = metadata.file_type();
    if file_type.is_symlink()
        || match candidate.kind {
            CandidateKind::Directory => !file_type.is_dir(),
            CandidateKind::File => !file_type.is_file(),
        }
    {
        return Ok(CandidateDisposition::Unsafe);
    }
    let mut lease = None;
    let age_gated = match candidate.liveness {
        Liveness::AgeGrace => true,
        Liveness::BuilderLease => {
            if !lease_held {
                match BuilderTempLease::try_acquire(&candidate.path) {
                    Ok(Some(acquired)) => lease = Some(acquired),
                    Ok(None) => return Ok(CandidateDisposition::Live),
                    Err(_) => return Ok(CandidateDisposition::Unsafe),
                }
            }
            false
        }
    };
    if age_gated && metadata.modified()? >= cutoff {
        return Ok(CandidateDisposition::Young);
    }
    if candidate.kind == CandidateKind::File {
        return Ok(CandidateDisposition::Eligible {
            files: 1,
            bytes: metadata.len(),
            lease,
        });
    }

    let mut stack = vec![candidate.path.clone()];
    let mut entries = 0_u64;
    let mut files = 0_u64;
    let mut bytes = 0_u64;
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory)
            .with_context(|| format!("inspect orphan temporary tree {}", directory.display()))?
        {
            entries = entries.saturating_add(1);
            if entries > MAX_CANDIDATE_TREE_ENTRIES {
                bail!(
                    "orphan temporary {} exceeds bounded tree entry count of {MAX_CANDIDATE_TREE_ENTRIES}",
                    candidate.path.display()
                );
            }
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() || (!file_type.is_file() && !file_type.is_dir()) {
                return Ok(CandidateDisposition::Unsafe);
            }
            if age_gated && metadata.modified()? >= cutoff {
                return Ok(CandidateDisposition::Young);
            }
            if file_type.is_dir() {
                stack.push(entry.path());
            } else {
                files = files.saturating_add(1);
                bytes = bytes.saturating_add(metadata.len());
            }
        }
    }
    Ok(CandidateDisposition::Eligible {
        files,
        bytes,
        lease,
    })
}

fn exact_tempfile_name(name: &str, prefix: &str, suffix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .is_some_and(|random| {
            random.len() == 6 && random.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

fn exact_ioc_tempfile_name(name: &str) -> bool {
    let Some(identity) = name
        .strip_prefix(".ioc-")
        .and_then(|value| value.strip_suffix(".parquet"))
    else {
        return false;
    };
    uuid::Uuid::parse_str(identity)
        .is_ok_and(|uuid| uuid.get_version_num() == 7 && uuid.to_string() == identity)
}

fn valid_generation_name(name: &str) -> bool {
    let Some(identity) = name.strip_prefix("snapshot-") else {
        return false;
    };
    let Some((snapshot_id, digest)) = identity.split_once('-') else {
        return false;
    };
    snapshot_id
        .parse::<i64>()
        .is_ok_and(|snapshot_id| snapshot_id > 0)
        && digest.len() == 16
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_derivative_name(name: &str) -> bool {
    name.strip_prefix("derivatives-v1-").is_some_and(|digest| {
        digest.len() == 16
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn old_now() -> SystemTime {
        SystemTime::now() + DEFAULT_ORPHAN_TEMP_GRACE + Duration::from_secs(5)
    }

    fn generation(root: &Path) -> PathBuf {
        let generation = root.join("snapshot-123-aabbccddeeff0011");
        std::fs::create_dir_all(&generation).unwrap();
        generation
    }

    #[test]
    fn generation_sweep_deletes_only_exact_old_tempfile_directories() {
        let root = tempfile::tempdir().unwrap();
        let generation = generation(root.path());
        let lake = generation.join(".lake-snapshot-Ab12z9");
        let invalid_lake = generation.join(".lake-snapshot-too-long");
        let final_snapshot = generation.join("snapshot");
        let derivatives = generation.join("derivatives-v1-aaaaaaaaaaaaaaaa");
        let prevalence = derivatives.join(".prevalence-snapshot-Zz90Qq");
        let final_prevalence = derivatives.join("prevalence-snapshot-v2");
        for directory in [
            &lake,
            &invalid_lake,
            &final_snapshot,
            &prevalence,
            &final_prevalence,
        ] {
            std::fs::create_dir_all(directory).unwrap();
            std::fs::write(directory.join("proof"), b"bytes").unwrap();
        }

        let report =
            sweep_generation_orphan_temporaries(root.path(), old_now(), DEFAULT_ORPHAN_TEMP_GRACE)
                .unwrap();
        assert_eq!(report.deleted, 2);
        assert_eq!(report.deleted_files, 2);
        assert!(!lake.exists());
        assert!(!prevalence.exists());
        assert!(invalid_lake.join("proof").is_file());
        assert!(final_snapshot.join("proof").is_file());
        assert!(final_prevalence.join("proof").is_file());
    }

    #[test]
    fn generation_sweep_retains_young_and_non_regular_trees() {
        let root = tempfile::tempdir().unwrap();
        let generation = generation(root.path());
        let young = generation.join(".lake-snapshot-Ab12z9");
        let unsafe_tree = generation.join(".lake-snapshot-Cd34xY");
        std::fs::create_dir_all(&young).unwrap();
        std::fs::create_dir_all(&unsafe_tree).unwrap();
        let young_proof = young.join("proof");
        std::fs::write(&young_proof, b"young").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&young_proof)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_secs(600))
            .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/tmp", unsafe_tree.join("foreign-link")).unwrap();

        let report =
            sweep_generation_orphan_temporaries(root.path(), old_now(), DEFAULT_ORPHAN_TEMP_GRACE)
                .unwrap();
        assert_eq!(report.deleted, 0);
        assert_eq!(report.retained_young, 1);
        #[cfg(unix)]
        assert_eq!(report.retained_unsafe, 1);
        assert!(young.exists());
        assert!(unsafe_tree.exists());
    }

    #[test]
    fn generation_sweep_fails_closed_before_deleting_too_many_candidates() {
        let root = tempfile::tempdir().unwrap();
        let generation = generation(root.path());
        for index in 0..=MAX_CANDIDATES_PER_SWEEP {
            let candidate = generation.join(format!(".lake-snapshot-A{index:05}"));
            std::fs::create_dir_all(candidate).unwrap();
        }
        assert!(sweep_generation_orphan_temporaries(
            root.path(),
            old_now(),
            DEFAULT_ORPHAN_TEMP_GRACE,
        )
        .is_err());
        assert_eq!(
            std::fs::read_dir(&generation)
                .unwrap()
                .filter_map(Result::ok)
                .count(),
            MAX_CANDIDATES_PER_SWEEP + 1
        );
    }

    /// The 2026-09-25 tree: a builder killed mid-run left its candidate, with
    /// part-job files and `parts/`, beside the final prevalence tree.
    fn killed_builder_tree(root: &Path) -> (PathBuf, PathBuf) {
        let derivatives = generation(root).join("derivatives-v1-aaaaaaaaaaaaaaaa");
        std::fs::create_dir_all(derivatives.join("prevalence-snapshot-v2")).unwrap();
        std::fs::write(
            derivatives.join("prevalence-snapshot-v2/manifest.json"),
            b"{}",
        )
        .unwrap();
        let orphan = derivatives.join(".prevalence-snapshot-I1QXkS");
        std::fs::create_dir_all(orphan.join("parts")).unwrap();
        std::fs::write(orphan.join(".prevalence-part-jobs-Ab12Cd.json"), b"[]").unwrap();
        std::fs::write(orphan.join("parts/object-0000.parquet"), b"part").unwrap();
        (derivatives, orphan)
    }

    /// NAN-2830 repro: the boot sweep runs minutes after the pod kill, so the
    /// orphan is young. It used to be retained for the 24-hour grace
    /// (`matched_candidates: 1, deleted: 0`), blocking the next publish.
    #[test]
    fn generation_sweep_reclaims_young_prevalence_temp_of_a_dead_builder() {
        let root = tempfile::tempdir().unwrap();
        let (_, orphan) = killed_builder_tree(root.path());
        // The builder held its lease and then died: the kernel dropped it.
        drop(BuilderTempLease::acquire(&orphan).unwrap());

        let report = sweep_generation_orphan_temporaries(
            root.path(),
            SystemTime::now(),
            DEFAULT_ORPHAN_TEMP_GRACE,
        )
        .unwrap();
        assert_eq!(report.matched_candidates, 1);
        assert_eq!(report.retained_young, 0);
        assert_eq!(report.deleted, 1);
        assert_eq!(report.deleted_files, 2);
        assert!(!orphan.exists());
    }

    #[test]
    fn generation_sweep_retains_prevalence_temp_of_a_live_builder_at_any_age() {
        let root = tempfile::tempdir().unwrap();
        let (_, live) = killed_builder_tree(root.path());
        let lease = BuilderTempLease::acquire(&live).unwrap();

        let report =
            sweep_generation_orphan_temporaries(root.path(), old_now(), DEFAULT_ORPHAN_TEMP_GRACE)
                .unwrap();
        assert_eq!(report.deleted, 0);
        assert_eq!(report.retained_live, 1);
        assert!(live.join("parts/object-0000.parquet").is_file());

        drop(lease);
        let report = sweep_generation_orphan_temporaries(
            root.path(),
            SystemTime::now(),
            DEFAULT_ORPHAN_TEMP_GRACE,
        )
        .unwrap();
        assert_eq!(report.deleted, 1);
        assert!(!live.exists());
    }

    #[test]
    fn young_age_gated_temporaries_are_still_retained() {
        // Only lease-proven builder temporaries skip the grace.
        let root = tempfile::tempdir().unwrap();
        let lake = generation(root.path()).join(".lake-snapshot-Ab12z9");
        std::fs::create_dir_all(&lake).unwrap();
        std::fs::write(lake.join("proof"), b"bytes").unwrap();
        let report = sweep_generation_orphan_temporaries(
            root.path(),
            SystemTime::now(),
            DEFAULT_ORPHAN_TEMP_GRACE,
        )
        .unwrap();
        assert_eq!(report.retained_young, 1);
        assert!(lake.join("proof").is_file());
    }

    #[test]
    fn build_start_reclaims_a_dead_builder_temp_before_the_build() {
        let root = tempfile::tempdir().unwrap();
        let (derivatives, orphan) = killed_builder_tree(root.path());
        let report = prepare_prevalence_build_parent(&derivatives).unwrap();
        assert_eq!(report.deleted, 1);
        assert!(!orphan.exists());
        assert!(derivatives
            .join("prevalence-snapshot-v2/manifest.json")
            .is_file());
        // Idempotent on a clean tree.
        assert_eq!(
            prepare_prevalence_build_parent(&derivatives)
                .unwrap()
                .matched_candidates,
            0
        );
    }

    #[test]
    fn build_start_fails_fast_on_unknown_hidden_entries_and_live_builders() {
        let root = tempfile::tempdir().unwrap();
        let (derivatives, orphan) = killed_builder_tree(root.path());
        std::fs::write(derivatives.join(".stray"), b"unknown").unwrap();
        let error = prepare_prevalence_build_parent(&derivatives)
            .unwrap_err()
            .to_string();
        assert!(error.contains(".stray"), "{error}");
        // The dead builder's temp is reclaimed even when the gate refuses;
        // the unknown entry is never touched.
        assert!(!orphan.exists());
        assert!(derivatives.join(".stray").is_file());
        std::fs::remove_file(derivatives.join(".stray")).unwrap();

        let (_, live) = killed_builder_tree(root.path());
        let lease = BuilderTempLease::acquire(&live).unwrap();
        let error = prepare_prevalence_build_parent(&derivatives)
            .unwrap_err()
            .to_string();
        assert!(error.contains(".prevalence-snapshot-I1QXkS"), "{error}");
        assert!(live.join("parts/object-0000.parquet").is_file());
        drop(lease);
        prepare_prevalence_build_parent(&derivatives).unwrap();
        assert!(!live.exists());
    }

    #[test]
    fn builder_lease_is_exclusive_until_dropped() {
        let root = tempfile::tempdir().unwrap();
        let lease = BuilderTempLease::acquire(root.path()).unwrap();
        assert!(BuilderTempLease::acquire(root.path()).is_err());
        drop(lease);
        BuilderTempLease::acquire(root.path()).unwrap();
    }

    #[test]
    fn ioc_sweep_requires_exact_v7_regular_file_name() {
        let root = tempfile::tempdir().unwrap();
        let exact = root
            .path()
            .join(format!(".ioc-{}.parquet", uuid::Uuid::now_v7()));
        let v4 = root
            .path()
            .join(".ioc-550e8400-e29b-41d4-a716-446655440000.parquet");
        let final_snapshot = root.path().join(format!("{}.parquet", "a".repeat(64)));
        std::fs::write(&exact, b"orphan").unwrap();
        std::fs::write(&v4, b"other-version").unwrap();
        std::fs::write(&final_snapshot, b"authoritative").unwrap();

        let report =
            sweep_ioc_orphan_temporaries(root.path(), old_now(), DEFAULT_ORPHAN_TEMP_GRACE)
                .unwrap();
        assert_eq!(report.deleted, 1);
        assert_eq!(report.deleted_files, 1);
        assert!(!exact.exists());
        assert!(v4.is_file());
        assert!(final_snapshot.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn ioc_sweep_never_follows_an_exact_named_symlink() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let link = root
            .path()
            .join(format!(".ioc-{}.parquet", uuid::Uuid::now_v7()));
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();

        let report =
            sweep_ioc_orphan_temporaries(root.path(), old_now(), DEFAULT_ORPHAN_TEMP_GRACE)
                .unwrap();
        assert_eq!(report.deleted, 0);
        assert_eq!(report.retained_unsafe, 1);
        assert!(link.exists());
        assert!(outside.path().is_file());
    }
}
