// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded metadata bytes from currently verified leases. Never grants a lease,
//! establishes live membership or substitutes for signed digest verification.
use std::{
    collections::VecDeque,
    io::Read,
    path::Path,
    sync::{Arc, Mutex},
};

pub const MAX_METADATA_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
type Key = String;

#[derive(Default)]
pub struct MetadataBytesCache {
    entries: Mutex<VecDeque<(Key, Arc<Vec<u8>>)>>,
}

impl MetadataBytesCache {
    /// Call only while holding the fetcher's verified lease for this digest.
    /// The digest identifies immutable bytes across statement-private paths.
    pub fn get(&self, path: &Path, digest: &str) -> Option<Arc<Vec<u8>>> {
        let length = std::fs::metadata(path).ok()?.len();
        let key = digest.to_owned();
        {
            let mut entries = self.entries.lock().ok()?;
            if let Some(index) = entries.iter().position(|(old, _)| old == &key) {
                let entry = entries.remove(index)?;
                let value = entry.1.clone();
                entries.push_back(entry);
                return Some(value);
            }
        }
        if length > MAX_METADATA_BYTES as u64 {
            return None;
        }
        let mut bytes = vec![0; length as usize];
        std::fs::File::open(path)
            .ok()?
            .read_exact(&mut bytes)
            .ok()?;
        // Include allocated capacity and conservative container/key overhead.
        let value = Arc::new(bytes);
        let size = entry_bytes(&key, &value);
        if size > MAX_METADATA_BYTES {
            return Some(value);
        }
        let mut entries = self.entries.lock().ok()?;
        // A concurrent miss may have published the same immutable bytes.
        if let Some(index) = entries.iter().position(|(old, _)| old == &key) {
            let entry = entries.remove(index)?;
            let value = entry.1.clone();
            entries.push_back(entry);
            return Some(value);
        }
        let mut resident = entries
            .iter()
            .map(|(key, value)| entry_bytes(key, value))
            .sum::<usize>();
        while entries.len() >= MAX_ENTRIES || resident.saturating_add(size) > MAX_METADATA_BYTES {
            let (key, value) = entries.pop_front()?;
            resident = resident.saturating_sub(entry_bytes(&key, &value));
        }
        entries.push_back((key, value.clone()));
        Some(value)
    }
}

fn entry_bytes(key: &Key, value: &Vec<u8>) -> usize {
    256 + key.capacity() + value.capacity()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reuse_and_gc_replacement_never_serve_stale_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sidecar");
        std::fs::write(&path, b"first").unwrap();
        let cache = MetadataBytesCache::default();
        let first = cache.get(&path, "digest-a").unwrap();
        assert!(Arc::ptr_eq(&first, &cache.get(&path, "digest-a").unwrap()));
        std::fs::remove_file(&path).unwrap();
        assert!(cache.get(&path, "digest-a").is_none());
        std::fs::write(&path, b"other").unwrap();
        assert_eq!(&**cache.get(&path, "digest-b").unwrap(), b"other");
        assert_eq!(cache.entries.lock().unwrap().len(), 2);
    }
    #[test]
    fn byte_bound_evicts_least_recently_used() {
        let dir = tempfile::tempdir().unwrap();
        let cache = MetadataBytesCache::default();
        let paths = (0..5)
            .map(|i| dir.path().join(i.to_string()))
            .collect::<Vec<_>>();
        for path in &paths {
            std::fs::write(path, vec![0; 16 * 1024 * 1024]).unwrap();
        }
        let oldest = cache.get(&paths[0], &paths[0].display().to_string()).unwrap();
        for path in &paths[1..3] {
            cache.get(path, &path.display().to_string()).unwrap();
        }
        assert!(Arc::ptr_eq(
            &oldest,
            &cache.get(&paths[0], &paths[0].display().to_string()).unwrap()
        ));
        cache.get(&paths[3], &paths[3].display().to_string()).unwrap();
        {
            let entries = cache.entries.lock().unwrap();
            assert!(entries.iter().any(|(key, _)| key == &paths[0].display().to_string()));
            assert!(!entries.iter().any(|(key, _)| key == &paths[1].display().to_string()));
            assert!(
                entries
                    .iter()
                    .map(|(key, value)| entry_bytes(key, value))
                    .sum::<usize>()
                    <= MAX_METADATA_BYTES
            );
        }
        cache.get(&paths[4], &paths[4].display().to_string()).unwrap();
        cache.get(&paths[1], &paths[1].display().to_string()).unwrap();
        assert!(!Arc::ptr_eq(
            &oldest,
            &cache.get(&paths[0], &paths[0].display().to_string()).unwrap()
        ));
    }

    #[test]
    fn oversized_input_is_not_cached() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file()
            .set_len((MAX_METADATA_BYTES + 1) as u64)
            .unwrap();
        let cache = MetadataBytesCache::default();
        assert!(cache.get(file.path(), "digest").is_none());
        assert!(cache.entries.lock().unwrap().is_empty());
    }
}
