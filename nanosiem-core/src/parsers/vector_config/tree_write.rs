// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5611: a render that produces the tree Vector already runs changes
//! nothing on disk and sends no reload.
//!
//! Every api start re-renders the whole Vector tree (parsers, `_pipeline`,
//! `_router`, `_combiner`, `_ocsf_sink`, `_enrichment`, the source configs and
//! their credential files). Those writes used to rewrite each file in place,
//! and the boot render then wrote a new activation marker and SIGHUPed Vector,
//! so every api restart reloaded Vector (with `--watch-config`, the rewrites
//! alone are enough to trigger one).
//!
//! * [`write_if_changed`] leaves a file alone when its content is the same
//!   (the `# Generated at:` header line is ignored), and otherwise replaces it
//!   atomically: a dotfile temp in the same directory (Vector's loader skips
//!   dotfiles), created exclusively with the old file's mode, then renamed.
//!   A writer never writes through the live file in place.
//! * [`tree_fingerprint`] digests what Vector reads from the api's tree. The
//!   activation marker records the fingerprint of the tree it was written
//!   with; a reload is skipped only when the render changed nothing (the
//!   fingerprint before it equals the one after), that is the marker's
//!   fingerprint, and the marker is the one Vector is running (see
//!   `deploy::vector_runs_unchanged_tree`).

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The tree's activation marker (`sources/configs/_nano_activation.toml`)
/// carries the fingerprint, so it is not part of it.
const MARKER_FILE: &str = super::deploy::ACTIVATION_MARKER_FILE;

/// Deepest directory level walked under the tree roots (`sources/configs`
/// is level 2). Bounds a symlink loop.
const MAX_DEPTH: usize = 4;

/// Do `old` and `new` render the same file at `path`? The generators stamp a
/// `# Generated at: <now>` line in the header; it is not content.
pub(crate) fn same_render(path: &Path, old: &[u8], new: &[u8]) -> bool {
    if old == new {
        return true;
    }
    let name = path.to_string_lossy();
    super::publication::normalize_generated_metadata(&name, old.to_vec())
        == super::publication::normalize_generated_metadata(&name, new.to_vec())
}

/// Write `content` to `path` unless it already holds it. `Ok(true)` when the
/// file was (re)written.
pub(crate) async fn write_if_changed(path: &Path, content: impl AsRef<[u8]>) -> std::io::Result<bool> {
    let content = content.as_ref();
    if let Ok(old) = tokio::fs::read(path).await {
        if same_render(path, &old, content) {
            return Ok(false);
        }
    }
    replace_atomically(path, content).await?;
    Ok(true)
}

fn temp_path(path: &Path) -> std::io::Result<PathBuf> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other(format!("{} has no parent directory", path.display())))?;
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other(format!("{} has no file name", path.display())))?
        .to_string_lossy();
    Ok(dir.join(format!(".{name}.tmp-{}", uuid::Uuid::new_v4().simple())))
}

/// Replace `path` with `content`: exclusive dotfile temp with the old file's
/// mode (so a secret file is never visible with wider permissions), rename.
/// The new file belongs to this process's user and group (nano-api's, the
/// owner of the tree it writes; single-node Vector reads it as root), not
/// the old file's.
pub(crate) async fn replace_atomically(path: &Path, content: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let tmp = temp_path(path)?;
    let mode = old_mode(path).await;
    let result = async {
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if let Some(mode) = mode {
            options.mode(mode);
        }
        let mut file = options.open(&tmp).await?;
        file.write_all(content).await?;
        file.flush().await?;
        drop(file);
        #[cfg(unix)]
        if let Some(mode) = mode {
            // The umask may have narrowed it; keep exactly the old mode.
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).await?;
        }
        tokio::fs::rename(&tmp, path).await
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    result
}

#[cfg(unix)]
async fn old_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::metadata(path).await.ok().map(|m| m.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
async fn old_mode(_path: &Path) -> Option<u32> {
    None
}

/// [`write_if_changed`] for synchronous callers.
pub(crate) fn write_if_changed_sync(path: &Path, content: impl AsRef<[u8]>) -> std::io::Result<bool> {
    use std::io::Write;
    let content = content.as_ref();
    if let Ok(old) = std::fs::read(path) {
        if same_render(path, &old, content) {
            return Ok(false);
        }
    }
    let tmp = temp_path(path)?;
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).ok().map(|m| m.permissions().mode() & 0o7777)
    };
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(content)?;
        drop(file);
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        }
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map(|()| true)
}

/// Digest of what Vector reads from the api's tree at `config_dir`: every
/// non-dot file under `sources/` (configs, parsers, credential files) and
/// `credentials/`, by relative path and content (generated-at lines
/// ignored), except the activation marker. `None` when the tree cannot be
/// read (no evidence: callers reload as before).
pub(crate) async fn tree_fingerprint(config_dir: &Path) -> Option<String> {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let marker = config_dir.join("sources").join("configs").join(MARKER_FILE);
    let mut stack: Vec<(PathBuf, usize)> = vec![
        (config_dir.join("sources"), 1),
        (config_dir.join("credentials"), 1),
    ];
    while let Some((dir, depth)) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(_) => return None,
            };
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
            let path = entry.path();
            if path == marker {
                continue;
            }
            // Follows symlinks: Vector reads what they point at.
            let Ok(meta) = tokio::fs::metadata(&path).await else {
                return None;
            };
            if meta.is_dir() {
                if depth < MAX_DEPTH {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            let Ok(bytes) = tokio::fs::read(&path).await else {
                return None;
            };
            let relative = path.strip_prefix(config_dir).unwrap_or(&path).to_string_lossy().into_owned();
            let bytes = super::publication::normalize_generated_metadata(&relative, bytes);
            files.push((relative, bytes));
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hash = Sha256::new();
    for (path, bytes) in &files {
        hash.update(path.as_bytes());
        hash.update([0u8]);
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    Some(hex::encode(hash.finalize()))
}

#[cfg(test)]
#[path = "tree_write_tests.rs"]
mod tests;
