// SPDX-License-Identifier: AGPL-3.0-or-later

//! Proofs that survive `query[T]`'s idle exit.
//!
//! `query[T]` exits when idle, so everything it proved about immutable part
//! files would otherwise be re-proved on every restart: the in-place SHA-256
//! of every cell-local data file a query touches (≈10 CPU-s per 7 days of a
//! 300 eps tenant) and the location/ASN owner-denial probe (≈40 CPU-s per
//! 7 days). Both are kept as small JSON files in the process's own state dir,
//! written atomically (temporary file + rename). A lost or corrupt file only
//! costs the re-proof: loading never fails the process.

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Most entries one memo file keeps (≈150 B each).
pub const MAX_ENTRIES: usize = 200_000;

/// Read `path` as `T`; missing, unreadable or corrupt gives `None`.
pub fn load<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice(&bytes) {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(path = %path.display(), error = %error, "ignoring an unreadable proof memo");
            None
        }
    }
}

/// Replace `path` with `value` atomically. Failures are logged, not raised:
/// the memo is an optimization, never an authority.
pub fn store<T: Serialize>(path: &Path, value: &T) {
    let result = (|| -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(value)?;
        let temporary = temporary_path(path);
        std::fs::write(&temporary, bytes)?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    })();
    if let Err(error) = result {
        tracing::warn!(path = %path.display(), error = %error, "proof memo was not persisted");
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|name| name.to_os_string()).unwrap_or_default();
    name.push(format!(".{}.tmp", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_tolerates_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memo.json");
        assert_eq!(load::<Vec<u32>>(&path), None);
        store(&path, &vec![1_u32, 2, 3]);
        assert_eq!(load::<Vec<u32>>(&path), Some(vec![1, 2, 3]));
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(load::<Vec<u32>>(&path), None);
    }
}
