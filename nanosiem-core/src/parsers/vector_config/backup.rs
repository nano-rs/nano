// SPDX-License-Identifier: AGPL-3.0-or-later

//! Backup and restore support for Vector configuration.
//!
//! Provides rollback capability by backing up the active configuration
//! before deployment and restoring it if deployment fails.
//!
//! # Why this file is written defensively
//!
//! This is the rollback path for the config that ingests logs for every
//! customer, and it only ever runs when a deploy has already gone wrong. A
//! partial write here turns a bad deploy into an outage, so every step is
//! ordered so that the thing it replaces survives until the replacement is
//! whole.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use tokio::fs;

use super::VectorConfigError;
use super::VectorConfigManager;

/// Written last inside a backup directory, and required by
/// [`VectorConfigManager::restore_backup`].
///
/// NAN-2301: `backup_current` used to delete the previous backup and then copy
/// in place, so a failure mid-copy destroyed the old rollback target and left a
/// partial one — which `restore_backup` accepted, since it treated any existing
/// directory as complete. A failed deploy could therefore restore a partial tree
/// over the active config, turning a bad deploy into a broken one.
const BACKUP_COMPLETE_MARKER: &str = ".backup-complete";

/// Identifies one backup, so a rollback can prove it is restoring the snapshot
/// taken for *this* deploy attempt.
///
/// NAN-2301 follow-up: without this, "keep the previous backup when a new one
/// fails" combined with "an absent tree records an EMPTY backup" produced a
/// config-destroying path. Fresh install records an empty backup; a later
/// legitimate tree fails to snapshot (a coherence-gate false positive, a
/// permissions blip); the stale empty backup survives; that deploy then fails
/// its reload, and the rollback restores the empty snapshot — deleting a live
/// config that was never in trouble. Restoring a snapshot nobody took for this
/// attempt is never right, so the token makes it impossible rather than
/// unlikely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupGeneration(String);

impl BackupGeneration {
    fn new() -> Self {
        Self(uuid::Uuid::new_v4().simple().to_string())
    }
}

/// A unique, dot-prefixed sibling of `target` to build a tree in before it is
/// swapped or published.
///
/// Dot-prefixed because `promote_staged` and `deploy_parsers` both skip dotfiles
/// when they prune the active tree (NAN-2296), and because `--config-dir` loads
/// `*.toml` only — so a workspace stranded by process death is inert rather than
/// something Vector tries to load. Unique per call so two processes sharing the
/// config volume cannot land on the same path.
fn sibling_workspace(target: &Path, purpose: &str) -> PathBuf {
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "tree".to_string());
    target.with_file_name(format!(
        ".{name}.{purpose}-{}",
        uuid::Uuid::new_v4().simple()
    ))
}

/// Durability is BEST-EFFORT, deliberately.
///
/// An fsync makes a snapshot survive power loss; it is an improvement on top of
/// the ordering guarantees above, not a precondition for them. Propagating an
/// fsync error would invent a brand new way for `backup_current` to fail — and a
/// failed backup is precisely how a deploy ends up with no rollback target,
/// which is the failure this whole file exists to prevent. So these warn and
/// carry on.
///
/// The concrete hazard is not hypothetical: `fs::copy` carries the source's
/// permission bits onto the copy, so a parser TOML that is mode `0444`, or one
/// owned by a different UID than the API process, cannot be reopened for
/// writing.
async fn fsync_file(path: &Path) {
    // Prefer a writable descriptor; `fsync` on a read-only one is fine on Linux
    // and macOS but not portably guaranteed, so it is the fallback rather than
    // the default.
    let file = match fs::OpenOptions::new().write(true).open(path).await {
        Ok(file) => Some(file),
        Err(_) => fs::File::open(path).await.ok(),
    };
    match file {
        Some(file) => {
            if let Err(e) = file.sync_all().await {
                tracing::warn!(
                    "Could not fsync {}: {e}. The tree is correct but not crash-durable.",
                    path.display()
                );
            }
        }
        None => tracing::warn!(
            "Could not open {} to fsync it. The tree is correct but not crash-durable.",
            path.display()
        ),
    }
}

/// fsync a directory so the *names* created in it survive a host crash, not just
/// the bytes inside the files.
///
/// A rename is only durable once the directory entry it created is on stable
/// storage. Best-effort for the same reason as [`fsync_file`]. Unix-only:
/// Windows has no equivalent, and no deployment target runs there.
#[cfg(unix)]
async fn fsync_dir(path: &Path) {
    match fs::File::open(path).await {
        Ok(dir) => {
            if let Err(e) = dir.sync_all().await {
                tracing::warn!(
                    "Could not fsync directory {}: {e}. Its entries are correct but not \
                     crash-durable.",
                    path.display()
                );
            }
        }
        Err(e) => tracing::warn!(
            "Could not open directory {} to fsync it: {e}. Its entries are correct but not \
             crash-durable.",
            path.display()
        ),
    }
}

#[cfg(not(unix))]
async fn fsync_dir(_path: &Path) {}

impl VectorConfigManager {
    /// Snapshot the active configuration as the rollback target.
    ///
    /// Built in a temporary directory and swapped in only once complete, so the
    /// previous backup survives a failure here and `restore_backup` never sees a
    /// half-written tree.
    ///
    /// An absent `parsers_dir` produces an EMPTY completed backup rather than no
    /// backup at all. That is the honest representation of "there was nothing
    /// here before": restoring it removes whatever the failed deploy promoted.
    /// Previously this returned `Ok(())` having just deleted the old backup, so
    /// the caller believed it had a rollback target when it had none.
    pub async fn backup_current(&self) -> Result<BackupGeneration, VectorConfigError> {
        let generation = BackupGeneration::new();
        let staging = sibling_workspace(&self.backup_dir, "tmp");
        if fs::try_exists(&staging).await? {
            fs::remove_dir_all(&staging).await?;
        }
        fs::create_dir_all(&staging).await?;

        // `try_exists`, not `exists`: the latter reports `false` for a metadata
        // error (permissions, a transient FS fault), which would silently
        // manufacture an "there was nothing here" empty backup over a real tree.
        if fs::try_exists(&self.parsers_dir).await? {
            self.copy_dir_recursive(&self.parsers_dir, &staging).await?;
        } else {
            tracing::info!(
                "No existing parsers directory — recording an empty rollback target so a \
                 failed deploy rolls back to nothing rather than staying live"
            );
        }

        // NAN-2301: refuse to record a snapshot that is already broken.
        //
        // A backup is only useful if restoring it produces a config Vector will
        // load. NAN-2296 proved the active tree can be POISONED — a regenerated
        // `_router.toml` beside a stale parser TOML whose `inputs` name a route
        // that no longer exists — while Vector keeps serving its last good
        // in-memory config. Snapshotting that state and later restoring it
        // re-creates the dangling input and takes the whole config down.
        //
        // On failure the previous backup is deliberately left in place: an older
        // but coherent rollback target beats a fresh incoherent one.
        if let Some(dangling) = incoherent_references(&staging).await? {
            let _ = fs::remove_dir_all(&staging).await;
            let detail = dangling.join("; ");
            tracing::error!(
                "Refusing to back up the active config: {detail}. The previous backup is kept \
                 as the rollback target. This is the NAN-2296 shape — a stale parser file \
                 pointing at a route the router no longer emits."
            );
            return Err(VectorConfigError::ValidationFailed(format!(
                "active config is not internally consistent, refusing to record it as a \
                 rollback target: {detail}"
            )));
        }

        // Marker last: everything above succeeded. Carries the generation so a
        // rollback can prove this snapshot belongs to its own deploy attempt.
        let marker = staging.join(BACKUP_COMPLETE_MARKER);
        fs::write(&marker, &generation.0).await?;
        fsync_file(&marker).await;
        // The marker's own directory entry has to be durable too, or a host
        // crash can surface a tree whose files are present and whose marker is
        // not — which `restore_backup` then refuses, silently costing a deploy
        // its rollback target.
        fsync_dir(&staging).await;

        self.swap_in_backup(&staging).await?;

        tracing::info!(
            "Backed up current config from {} to {}",
            self.parsers_dir.display(),
            self.backup_dir.display()
        );
        Ok(generation)
    }

    /// Make a finished snapshot the rollback target.
    ///
    /// NAN-2302: the previous backup is renamed ASIDE, not deleted. This used to
    /// be `remove_dir_all(backup_dir)` followed by `rename(staging, backup_dir)`
    /// — process death between the two left NO backup at all, at the exact
    /// moment a deploy was about to need one. Now the gap between the two
    /// renames holds BOTH the previous snapshot and the finished new one, so
    /// there is no instant at which the rollback target is unrecoverable.
    ///
    /// `backup_dir` is safe to replace by rename; `parsers_dir` is not (see
    /// [`Self::publish_restored_tree`]). Nothing mounts or watches the backup
    /// directory — it is read only by `restore_backup`.
    async fn swap_in_backup(&self, staging: &Path) -> Result<(), VectorConfigError> {
        let retired = sibling_workspace(&self.backup_dir, "retired");
        let had_previous = fs::try_exists(&self.backup_dir).await?;
        if had_previous {
            fs::rename(&self.backup_dir, &retired).await?;
        }
        if let Err(e) = fs::rename(staging, &self.backup_dir).await {
            // Put the old rollback target back before surfacing the error —
            // failing a backup is survivable, silently having none is not.
            if had_previous {
                let _ = fs::rename(&retired, &self.backup_dir).await;
            }
            let _ = fs::remove_dir_all(staging).await;
            return Err(e.into());
        }
        if had_previous {
            let _ = fs::remove_dir_all(&retired).await;
        }
        // A rename is only durable once the directory entry it created is.
        if let Some(parent) = self.backup_dir.parent() {
            fsync_dir(parent).await;
        }
        Ok(())
    }

    /// Restore configuration from backup.
    /// Used for rollback when deployment fails.
    ///
    /// Refuses a backup without its completion marker — an unmarked directory is
    /// either a partial write or a pre-NAN-2301 backup whose integrity is
    /// unknown, and copying it over the active tree could publish a config that
    /// was never whole.
    pub async fn restore_backup(
        &self,
        expected: &BackupGeneration,
    ) -> Result<(), VectorConfigError> {
        if !fs::try_exists(&self.backup_dir).await? {
            return Err(VectorConfigError::NoBackupAvailable);
        }
        let marker = self.backup_dir.join(BACKUP_COMPLETE_MARKER);
        if !fs::try_exists(&marker).await? {
            tracing::error!(
                "Backup at {} has no {} marker — refusing to restore an unverified tree",
                self.backup_dir.display(),
                BACKUP_COMPLETE_MARKER,
            );
            return Err(VectorConfigError::NoBackupAvailable);
        }

        // The snapshot must be the one taken for THIS attempt. A leftover from
        // an earlier deploy describes a different starting state — restoring it
        // is not a rollback, it is an unrelated overwrite, and when the leftover
        // is the empty first-install backup it deletes a live config outright.
        let found = fs::read_to_string(&marker).await?;
        if found.trim() != expected.0 {
            tracing::error!(
                "Backup at {} is generation {:?}, this deploy took {:?} — refusing to roll back \
                 to a snapshot from a different attempt",
                self.backup_dir.display(),
                found.trim(),
                expected.0,
            );
            return Err(VectorConfigError::NoBackupAvailable);
        }

        // NAN-2302: assemble the restored tree beside the active one first.
        //
        // This used to `remove_dir_all(parsers_dir)` and then copy the backup
        // in, so any copy error — or process death — left a PARTIALLY restored
        // active config. An input naming a missing component is fatal to the
        // whole Vector config (NAN-2296), so a half-restored tree is not
        // "degraded", it is a total ingest outage, produced by the code whose
        // entire job is to end one.
        //
        // Everything fallible (reading the snapshot, writing bytes, running out
        // of disk) now happens in the workspace, where failure cannot touch the
        // live config at all.
        //
        // The completion marker is excluded from the copy rather than deleted
        // afterwards. Copying it in and removing it after left it in the active
        // tree permanently whenever the process died in between: NAN-2296's
        // prune skips dotfiles, so nothing removes it, and the next
        // `backup_current` copies it straight back into the new snapshot.
        let staging = sibling_workspace(&self.parsers_dir, "restore");
        if fs::try_exists(&staging).await? {
            fs::remove_dir_all(&staging).await?;
        }
        if let Err(e) = self
            .copy_dir_filtered(&self.backup_dir, &staging, &[BACKUP_COMPLETE_MARKER])
            .await
        {
            let _ = fs::remove_dir_all(&staging).await;
            return Err(e);
        }

        let published = self.publish_restored_tree(&staging).await;
        // Best-effort: a stranded workspace is inert (dot-prefixed, outside
        // every `--config-dir`), and failing the restore over cleanup would be
        // strictly worse than leaking a directory.
        let _ = fs::remove_dir_all(&staging).await;
        published?;

        tracing::info!(
            "Restored config from backup {} to {}",
            self.backup_dir.display(),
            self.parsers_dir.display()
        );
        Ok(())
    }

    /// Move a fully assembled tree into `parsers_dir`.
    ///
    /// The active directory keeps its identity — it is NOT swapped for the
    /// workspace. `parsers_dir` is its own bind mount in the Vector container
    /// (`docker-compose.yml`: `./config/vector/sources/parsers` is mounted
    /// separately because the parent is read-only) and its own mount path in the
    /// Kubernetes pod (`deploy/k8s/rackspace/vector.yaml`). A bind mount follows
    /// the inode it was created from, so renaming the directory aside would
    /// leave Vector looking at the tree we are about to delete, and deleting it
    /// would empty Vector's config directory outright. Publishing INTO the
    /// existing directory is the only form of this that is safe here.
    ///
    /// So the visible transition is a sequence of same-directory renames: each
    /// file goes from old contents to new contents atomically, and the tree is
    /// never empty or missing at any point. Because every staged file lives in
    /// one directory on one filesystem, a cross-device or permission problem
    /// surfaces on the FIRST rename, before any active file has changed.
    async fn publish_restored_tree(&self, staged: &Path) -> Result<(), VectorConfigError> {
        fs::create_dir_all(&self.parsers_dir).await?;

        let mut restored: HashSet<OsString> = HashSet::new();
        let mut entries = fs::read_dir(staged).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let dest = self.parsers_dir.join(&name);
            if entry.file_type().await?.is_dir() && fs::try_exists(&dest).await? {
                // `rename` onto a populated directory fails; the snapshot's copy
                // is authoritative, so clear the active one first.
                fs::remove_dir_all(&dest).await?;
            }
            if let Err(e) = fs::rename(entry.path(), &dest).await {
                // The only step that can leave the active tree mixed. Say so
                // explicitly: the caller's message is about the restore failing,
                // not about what state the config was left in.
                tracing::error!(
                    "Failed to publish {} into the active config: {e}. {} files were already \
                     replaced, so {} now holds a MIX of the failed deploy and the snapshot — \
                     manual intervention required.",
                    dest.display(),
                    restored.len(),
                    self.parsers_dir.display(),
                );
                return Err(e.into());
            }
            restored.insert(name);
        }

        // Mirror the snapshot, do not overlay it. A file the snapshot does not
        // contain was added after it was taken, and leaving it behind keeps
        // exactly the stale component the rollback exists to remove (NAN-2296:
        // an input naming a route the router no longer emits is fatal to the
        // whole config).
        //
        // Dotfiles are left alone — `.gitkeep` and a concurrent workspace are
        // not ours to delete, matching `promote_staged`. The one exception is
        // our own completion marker, which a pre-NAN-2302 restore could have
        // stranded here; this heals that.
        let mut active = fs::read_dir(&self.parsers_dir).await?;
        while let Some(entry) = active.next_entry().await? {
            let name = entry.file_name();
            if restored.contains(&name) {
                continue;
            }
            let display = name.to_string_lossy();
            if display.starts_with('.') && display != BACKUP_COMPLETE_MARKER {
                continue;
            }
            if entry.file_type().await?.is_dir() {
                fs::remove_dir_all(entry.path()).await?;
            } else {
                fs::remove_file(entry.path()).await?;
            }
        }

        fsync_dir(&self.parsers_dir).await;
        Ok(())
    }

    /// Recursively copy a directory and its contents
    async fn copy_dir_recursive(&self, src: &Path, dst: &Path) -> Result<(), VectorConfigError> {
        self.copy_dir_filtered(src, dst, &[]).await
    }

    /// As [`Self::copy_dir_recursive`], skipping `skip_top` entries at the TOP
    /// level only — the completion marker belongs to the backup root and has no
    /// meaning anywhere else.
    async fn copy_dir_filtered(
        &self,
        src: &Path,
        dst: &Path,
        skip_top: &[&str],
    ) -> Result<(), VectorConfigError> {
        // Create destination directory
        fs::create_dir_all(dst).await?;

        let mut entries = fs::read_dir(src).await?;
        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name();
            if skip_top.iter().any(|s| file_name == **s) {
                continue;
            }
            let src_path = entry.path();
            let dst_path = dst.join(&file_name);

            let file_type = entry.file_type().await?;

            if file_type.is_dir() {
                // Recursively copy subdirectory
                Box::pin(self.copy_dir_filtered(&src_path, &dst_path, &[])).await?;
            } else if file_type.is_file() {
                // Copy file
                fs::copy(&src_path, &dst_path).await?;
                // NAN-2302: a snapshot whose files carry the right names and the
                // wrong bytes is worse than no snapshot, because the marker
                // makes it look trustworthy.
                fsync_file(&dst_path).await;
            }
            // Skip symlinks and other file types for security
        }

        fsync_dir(dst).await;
        Ok(())
    }

    /// Get the backup directory path
    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }
}

// ---------------------------------------------------------------------------
// Coherence gate
// ---------------------------------------------------------------------------

/// Component ids this codebase generates INTO the parser tree.
///
/// A reference to one of these is dangling even when nothing declares it,
/// because the tree — not some sibling config directory — is where they are
/// supposed to come from. Without this, deleting `_router.toml` entirely would
/// read as "the routers are external, so those references are fine".
const TREE_OWNED_ROUTERS: &[&str] = &["source_router", "enrichment_router"];

/// Files the deploy path generates whole, whose `inputs` only ever name
/// components declared inside the same tree.
///
/// `_router.toml` and the per-parser TOMLs are deliberately absent: they
/// legitimately consume components from OUTSIDE this tree (`vector_merge` and
/// `otlp_logs_prep` from the base configs, `<source>_route` from
/// `sources/configs`), which the tree cannot see and must not flag.
const GENERATED_ORCHESTRATION_FILES: &[&str] = &[
    "_combiner.toml",
    "_pipeline.toml",
    "_enrichment.toml",
    "_ocsf_sink.toml",
];

/// Vector substitutes `${VAR:-default}` before it parses the TOML, so the raw
/// files on disk are NOT valid TOML and must be substituted first.
///
/// This is not a nicety. `_pipeline.toml` contains
/// `max_bytes = ${VECTOR_BATCH_MAX_BYTES:-52428800}` — an unquoted
/// interpolation, which `toml::from_str` rejects. Before NAN-2302 the gate
/// therefore silently skipped `_pipeline.toml` on every real deployment, which
/// is also why it could not be widened into a graph check: without
/// `_pipeline.toml`'s declarations, `prepare_output` and friends look dangling.
///
/// Mirrors `deploy::enrichment_lane_backpressure_violations::substitute_env`,
/// which solved the same problem for the backpressure lint.
fn substitute_env(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) => {
                let body = &after[..end];
                // `${VAR:-default}` -> default, `${VAR}` -> empty.
                if let Some(pos) = body.find(":-") {
                    out.push_str(&body[pos + 2..]);
                }
                rest = &after[end + 1..];
            }
            None => {
                // Unterminated: leave it be and let the parse fail honestly.
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// One declared Vector component.
#[derive(Default)]
pub(super) struct Component {
    /// The declared `type`, when present.
    ty: Option<String>,
    /// Named outputs of a `route` transform.
    routes: HashSet<String>,
}

impl Component {
    /// A `route` transform, identified by its declared type OR by carrying a
    /// `route` table. The table alone is enough: no other transform type has
    /// one, and generated router files are read by other tooling that only
    /// looks at the table.
    fn is_route(&self) -> bool {
        self.ty.as_deref() == Some("route") || !self.routes.is_empty()
    }
}

/// Which components a candidate tree declares, and which it consumes.
///
/// # Scope
///
/// This covers the parser tree ONLY. Components declared in `sources/configs`
/// (`<source>_route`, `<source>_source`) and in the base configs
/// (`vector_merge`, `hec_normalize`, `otlp_logs_prep`, `source_type_extract`)
/// are not visible here and are never reported. A reference to something this
/// tree cannot see is treated as external, because the alternative — flagging it
/// — fails the backup, and a failed backup means the deploy in progress has no
/// rollback target at all. `vector validate` covers the cross-directory graph
/// during staging; this gate exists for the one thing validation cannot see,
/// which is an ACTIVE tree that has silently rotted while Vector keeps serving
/// its last good in-memory config.
#[derive(Default)]
pub(super) struct ComponentGraph {
    declared: HashMap<String, Component>,
    /// `(file, component id, input reference)`
    references: Vec<(String, String, String)>,
    /// Every `*.toml` in the tree parsed, so the declaration set is complete.
    complete: bool,
    /// Files that did not parse, for the operator-facing warning.
    unparsed: Vec<String>,
    /// `_router.toml` is absent, or present and parsed. When it is present and
    /// unreadable we know nothing about the routes and must stay quiet.
    router_readable: bool,
}

impl ComponentGraph {
    /// Build from `(file name, raw TOML)` pairs.
    pub(super) fn from_documents(docs: &[(String, String)]) -> Self {
        let mut graph = ComponentGraph {
            complete: true,
            router_readable: true,
            ..Default::default()
        };

        for (file, raw) in docs {
            let parsed: toml::Table = match toml::from_str(&substitute_env(raw)) {
                Ok(table) => table,
                Err(_) => {
                    // Deliberately NOT a refusal. `toml::from_str` is stricter
                    // than Vector's own loader (see `substitute_env`), so
                    // treating "we could not parse it" as "the config is
                    // broken" would fail backups on configs Vector loads fine.
                    // Instead the checks that need a complete declaration set
                    // switch themselves off below.
                    graph.complete = false;
                    graph.unparsed.push(file.clone());
                    if file == "_router.toml" {
                        graph.router_readable = false;
                    }
                    continue;
                }
            };

            for section in ["sources", "transforms", "sinks"] {
                let Some(table) = parsed.get(section).and_then(|v| v.as_table()) else {
                    continue;
                };
                for (id, def) in table {
                    let entry = graph.declared.entry(id.clone()).or_default();
                    if entry.ty.is_none() {
                        entry.ty = def.get("type").and_then(|t| t.as_str()).map(str::to_string);
                    }
                    if let Some(routes) = def.get("route").and_then(|r| r.as_table()) {
                        entry.routes.extend(routes.keys().cloned());
                    }
                    for input in def
                        .get("inputs")
                        .and_then(|i| i.as_array())
                        .into_iter()
                        .flatten()
                        .filter_map(|i| i.as_str())
                    {
                        graph
                            .references
                            .push((file.clone(), id.clone(), input.to_string()));
                    }
                }
            }
        }

        graph
    }

    /// Named outputs of `component`, when the tree declares it as a route.
    ///
    /// Test-facing: [`Self::dangling`] reads the routes directly. Kept as a
    /// named accessor so route extraction — which decides whether a
    /// `source_router.<x>` input is dangling — can be asserted on its own rather
    /// than only through a backup that did or did not fail.
    #[cfg(test)]
    pub(super) fn route_names(&self, component: &str) -> Option<&HashSet<String>> {
        self.declared
            .get(component)
            .filter(|c| c.is_route())
            .map(|c| &c.routes)
    }

    /// Every input reference the tree makes that nothing in the tree satisfies.
    ///
    /// Each rule is written to be silent unless the tree itself proves the
    /// reference is broken, because a false positive here costs a deploy its
    /// rollback target.
    ///
    /// Capped: the result is joined into an error that is logged AND persisted
    /// on the deployment record, and one deleted `_router.toml` dangles every
    /// parser in the tree at once. The count is reported in full; only the
    /// listing is trimmed.
    pub(super) fn dangling(&self) -> Vec<String> {
        const MAX_REPORTED: usize = 20;
        let mut problems = Vec::new();

        for (file, owner, input) in &self.references {
            // "source_router.generic" -> ("source_router", Some("generic")).
            let (base, port) = match input.split_once('.') {
                Some((base, port)) => (base, Some(port)),
                None => (input.as_str(), None),
            };

            match self.declared.get(base) {
                // A route transform's named outputs are exactly its route keys
                // (plus Vector's built-in `_unmatched`), so this is decidable
                // from the tree alone. This is the NAN-2296 shape: a stale
                // parser consuming a route the regenerated router dropped.
                Some(component) if component.is_route() => {
                    if let Some(port) = port {
                        if port != "_unmatched" && !component.routes.contains(port) {
                            problems.push(format!(
                                "{file}: {owner} consumes {input}, which {base} does not emit"
                            ));
                        }
                    }
                    // A bare reference to a route transform is also invalid, but
                    // Vector reports that one itself and flagging it here buys
                    // nothing but false-positive surface.
                }
                // A named output on a non-route component (`foo_parse.dropped`)
                // cannot be verified without knowing the transform's semantics.
                // Accept it.
                Some(_) => {}
                None => {
                    if TREE_OWNED_ROUTERS.contains(&base) {
                        // Only meaningful when we could actually read the router
                        // file: if it exists and did not parse, we cannot tell a
                        // deleted route from an unreadable one.
                        if self.router_readable {
                            problems.push(format!(
                                "{file}: {owner} consumes {input}, but the tree declares no {base}"
                            ));
                        }
                    } else if self.complete
                        && GENERATED_ORCHESTRATION_FILES.contains(&file.as_str())
                    {
                        // These files are generated whole from the tree's own
                        // contents, so an input they name and the tree does not
                        // declare is missing, not external. This is how a
                        // `_combiner.toml` still wired to a removed parser's
                        // `<name>_output` gets caught.
                        problems.push(format!(
                            "{file}: {owner} consumes {input}, which no file in the tree declares"
                        ));
                    }
                    // Anything else is a component from `sources/configs` or the
                    // base configs. Out of scope — see the type docs.
                }
            }
        }

        if problems.len() > MAX_REPORTED {
            let hidden = problems.len() - MAX_REPORTED;
            problems.truncate(MAX_REPORTED);
            problems.push(format!("and {hidden} more dangling reference(s)"));
        }
        problems
    }
}

/// Read the `*.toml` files a candidate tree contributes to Vector.
///
/// Top level only: `--config-dir` does not recurse, so a nested file is not part
/// of the config and counting its declarations would mask a real gap.
async fn read_tree_documents(tree: &Path) -> Result<Vec<(String, String)>, VectorConfigError> {
    let mut docs = Vec::new();
    let mut entries = fs::read_dir(tree).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".toml") {
            continue;
        }
        if !entry.file_type().await?.is_file() {
            continue;
        }
        docs.push((name, fs::read_to_string(entry.path()).await?));
    }
    docs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(docs)
}

/// Describe every input reference in `tree` that the tree itself does not
/// satisfy. `None` means coherent.
///
/// NAN-2302 widened this from "parser inputs starting `source_router.`" to a
/// component-graph check. The old form missed a `_combiner.toml` still wired to
/// a deleted parser's `<name>_output`, a dangling `enrichment_router.<kind>`,
/// and the OCSF sink's `<name>_ocsf_prepare` forks — all of which are, like the
/// original NAN-2296 bug, fatal to the WHOLE Vector config rather than to one
/// source.
async fn incoherent_references(tree: &Path) -> Result<Option<Vec<String>>, VectorConfigError> {
    let docs = read_tree_documents(tree).await?;
    let graph = ComponentGraph::from_documents(&docs);

    if !graph.unparsed.is_empty() {
        tracing::warn!(
            "Coherence gate running degraded: {} did not parse as TOML, so the checks that need a \
             complete declaration set are skipped for this snapshot. Not treated as a failure — \
             the parser is stricter than Vector's loader, and refusing the backup would cost this \
             deploy its rollback target.",
            graph.unparsed.join(", ")
        );
    }

    let problems = graph.dangling();
    Ok((!problems.is_empty()).then_some(problems))
}

#[cfg(test)]
mod tests;
