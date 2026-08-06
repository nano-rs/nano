// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-side of the Vector config generation publication (NAN-1931).
//!
//! The publisher ([`super::publication`]) materializes ready generations under
//! `<config_dir>/publications/<20-digit-zero-padded>/`. This module is the
//! consumer-facing read API the `nanosiem-api` internal HTTP endpoint serves
//! from: resolve the newest ready generation, hand out its manifest, and hand
//! out individual files by manifest-relative path.
//!
//! Path handling is the security-critical part. Every relative path is
//! validated with the same rules the publisher enforces at write time
//! ([`super::publication::validate_relative_path`] +
//! [`super::publication::is_safe_manifest_path`]), and reads additionally
//! verify — after the candidate resolves — that the canonicalized target is
//! still inside the canonicalized generation directory, so a symlink smuggled
//! into a generation cannot escape the publications root.

use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs;

use super::publication::{
    is_safe_manifest_path, normalized_relative_path, read_bounded_regular_file,
    validate_relative_path, VectorConfigPublicationError, MANIFEST_FILE, MAX_PROTOCOL_FILE_BYTES,
    MAX_SNAPSHOT_BYTES, READY_FILE,
};

#[derive(Debug, Error)]
pub enum VectorConfigDeliveryError {
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid generation number")]
    InvalidGeneration,
    #[error("invalid file path")]
    InvalidPath,
}

impl From<VectorConfigPublicationError> for VectorConfigDeliveryError {
    fn from(error: VectorConfigPublicationError) -> Self {
        match error {
            VectorConfigPublicationError::Io(io) => Self::Io(io),
            // The only publication errors reachable through the read helpers
            // used here are Io and InvalidPath.
            _ => Self::InvalidPath,
        }
    }
}

/// The directory name of a generation: 20 zero-padded digits, matching the
/// publisher's `format!("{generation:020}")` and the k8s consumer's layout.
fn generation_dir_name(generation: i64) -> Option<String> {
    if generation <= 0 {
        return None;
    }
    Some(format!("{generation:020}"))
}

/// Scan the publications root and return the highest generation number that
/// has a `.ready` marker, or `None` when nothing is published yet (fresh pod
/// before the first reconcile, or publication disabled).
pub async fn latest_ready_generation(
    publications_root: &Path,
) -> Result<Option<i64>, VectorConfigDeliveryError> {
    let mut entries = match fs::read_dir(publications_root).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut newest: Option<i64> = None;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.len() != 20 || !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let Ok(generation) = name.parse::<i64>() else {
            continue;
        };
        if generation <= 0 || newest.is_some_and(|current| current >= generation) {
            continue;
        }
        if fs::try_exists(entry.path().join(READY_FILE))
            .await
            .unwrap_or(false)
        {
            newest = Some(generation);
        }
    }
    Ok(newest)
}

/// Read the `_manifest.json` of a ready generation. Returns `Ok(None)` when
/// the generation does not exist or is not ready.
pub async fn read_manifest(
    publications_root: &Path,
    generation: i64,
) -> Result<Option<Vec<u8>>, VectorConfigDeliveryError> {
    read_generation_file(publications_root, generation, MANIFEST_FILE).await
}

/// Read one file of a ready generation by its manifest-relative path.
///
/// Returns `Ok(None)` when the generation is missing, not ready, or the file
/// does not exist; `Err(InvalidPath)` / `Err(InvalidGeneration)` when the
/// request itself is malformed (traversal attempts land here, never on disk).
pub async fn read_generation_file(
    publications_root: &Path,
    generation: i64,
    relative: &str,
) -> Result<Option<Vec<u8>>, VectorConfigDeliveryError> {
    let generation_dir = resolve_generation_dir(publications_root, generation)
        .ok_or(VectorConfigDeliveryError::InvalidGeneration)?;
    let candidate = resolve_relative(&generation_dir, relative)
        .ok_or(VectorConfigDeliveryError::InvalidPath)?;

    // Only ready generations are served: a consumer must never observe a
    // half-materialized directory (the publisher renames complete trees into
    // place, but a crashed rename cleanup could leave partial state behind).
    if !fs::try_exists(generation_dir.join(READY_FILE))
        .await
        .unwrap_or(false)
    {
        return Ok(None);
    }

    // Containment check BEFORE any bytes are read. Anchored on the canonical
    // PUBLICATIONS ROOT, not merely the generation directory, at two levels:
    //
    //   1. the generation directory must itself resolve inside the root, and
    //   2. the candidate file must resolve inside the generation directory.
    //
    // Checking only (2) — comparing the candidate against a canonicalize of the
    // generation directory — is self-referential: if the generation directory
    // is (or traverses) a symlink out of the publications tree, its canonical
    // form is already outside, and everything "under" it trivially passes. The
    // publisher never writes symlinks, so a hit at either level is tampering of
    // the API pod's own filesystem; fail closed without touching content.
    let canonical_publications_root = fs::canonicalize(publications_root).await?;
    let canonical_generation_dir = match fs::canonicalize(&generation_dir).await {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !canonical_generation_dir.starts_with(&canonical_publications_root) {
        return Err(VectorConfigDeliveryError::InvalidPath);
    }
    let canonical_file = match fs::canonicalize(&candidate).await {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !canonical_file.starts_with(&canonical_generation_dir) {
        return Err(VectorConfigDeliveryError::InvalidPath);
    }

    // Bounded, regular-file-only read. `read_bounded_regular_file` refuses
    // symlink leaves via symlink_metadata.
    let maximum = if relative.starts_with('_') || relative.starts_with('.') {
        MAX_PROTOCOL_FILE_BYTES
    } else {
        MAX_SNAPSHOT_BYTES
    };
    let Some(bytes) = read_bounded_regular_file(&candidate, maximum).await? else {
        return Ok(None);
    };

    Ok(Some(bytes))
}

fn resolve_generation_dir(publications_root: &Path, generation: i64) -> Option<PathBuf> {
    Some(publications_root.join(generation_dir_name(generation)?))
}

/// Validate a client-supplied relative path with the publisher's own rules and
/// join it under the generation directory. Returns `None` on any violation.
fn resolve_relative(generation_dir: &Path, relative: &str) -> Option<PathBuf> {
    // Reject backslashes and control characters first: on Unix a backslash is
    // NOT a path separator, so `..\..` would otherwise pass component checks
    // while meaning traversal to a Windows-side consumer or log viewer.
    if !is_safe_manifest_path(relative) {
        return None;
    }
    let path = Path::new(relative);
    if validate_relative_path(path).is_err() {
        return None;
    }
    // Require the exact canonical spelling the manifest uses. Rust's
    // `Path::components()` silently normalizes interior `./` segments away, so
    // without this round-trip "configs/./a.toml" (and "a//b", trailing "/")
    // would resolve — accept only paths that ARE their normalized form.
    if normalized_relative_path(path).as_deref() != Some(relative) {
        return None;
    }
    Some(generation_dir.join(path))
}

#[cfg(test)]
mod tests;
