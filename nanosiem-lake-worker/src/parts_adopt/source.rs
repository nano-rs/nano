// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only access to the objects being adopted.
//!
//! Adoption never writes, moves or deletes a source object. A source only
//! hands the job a local, SHA-256-verified path for one object at a time.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

use super::plan::PlannedObject;

/// A verified local copy (or in-place path) of one object.
#[derive(Debug)]
pub struct Materialized {
    pub path: PathBuf,
    /// Deleted on drop when the source made a temporary copy.
    temporary: bool,
}

impl Materialized {
    pub fn in_place(path: PathBuf) -> Self {
        Self { path, temporary: false }
    }

    pub fn temporary(path: PathBuf) -> Self {
        Self { path, temporary: true }
    }
}

impl Drop for Materialized {
    fn drop(&mut self) {
        if self.temporary {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[async_trait]
pub trait AdoptSource: Send + Sync {
    /// A local path whose bytes have the stamp's size and SHA-256.
    async fn materialize(&self, object: &PlannedObject, work_dir: &Path) -> Result<Materialized>;
}

/// Streaming SHA-256 and size of a file (1 MiB buffer).
pub fn file_sha256(path: &Path) -> Result<(String, u64)> {
    let mut file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    let mut bytes = 0_u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        bytes += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), bytes))
}

/// A read-only local mirror of the tenant bucket: the object with bucket key
/// `k` is at `root/k` (for example an `rclone copy` made with the read-only
/// reader credential, as phase 0 did). Objects are verified, never copied.
#[derive(Debug, Clone)]
pub struct BucketMirrorSource {
    root: PathBuf,
}

impl BucketMirrorSource {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

#[async_trait]
impl AdoptSource for BucketMirrorSource {
    async fn materialize(&self, object: &PlannedObject, _work_dir: &Path) -> Result<Materialized> {
        let path = self.root.join(&object.key);
        let expected = (object.stamp.sha256.clone(), object.stamp.size_bytes);
        let checked = path.clone();
        let actual = tokio::task::spawn_blocking(move || file_sha256(&checked)).await??;
        if actual != expected {
            bail!("mirrored object {} differs from its signed stamp", object.key);
        }
        Ok(Materialized::in_place(path))
    }
}
