// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic, bounded gzip-tar I/O for parser bundles.
//!
//! The bounds mirror the tenant Worker renderer's `load_vector_bundle`
//! (`shared_worker_build_context.rs`): a bundle this module
//! accepts is one the renderer can load, and a bundle it packs is one the
//! renderer's bounds admit.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Component, Path};

use super::TenantBundleError;

/// Packed (gzip) size bound — the renderer's `packed.len() > 4 MiB` refusal.
pub const MAX_PACKED_BYTES: usize = 4 * 1024 * 1024;
/// Expanded (tar) size bound — the renderer's 32 MiB gunzip bound.
pub const MAX_EXPANDED_BYTES: usize = 32 * 1024 * 1024;
/// Member-count bound — the renderer's `members.len() > 4096` refusal.
pub const MAX_MEMBERS: usize = 4096;

/// An unpacked bundle: regular files keyed by relative path, plus the
/// directories the archive declared (or that a file implies).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BundleTree {
    pub files: BTreeMap<String, Vec<u8>>,
    pub dirs: BTreeSet<String>,
}

impl BundleTree {
    pub fn file(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    pub fn text(&self, path: &str) -> Result<&str, TenantBundleError> {
        let bytes = self
            .file(path)
            .ok_or_else(|| TenantBundleError::Base(format!("{path} is absent")))?;
        std::str::from_utf8(bytes)
            .map_err(|_| TenantBundleError::Base(format!("{path} is not UTF-8")))
    }

    /// Insert or replace a file, declaring every parent directory.
    pub fn put(&mut self, path: &str, data: Vec<u8>) {
        self.dirs.extend(parents(path));
        self.files.insert(path.to_string(), data);
    }

    /// Write the tree under `root` (which must exist and be empty).
    pub fn write_to(&self, root: &Path) -> std::io::Result<()> {
        for dir in &self.dirs {
            std::fs::create_dir_all(root.join(dir))?;
        }
        for (path, data) in &self.files {
            let target = root.join(path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(target, data)?;
        }
        Ok(())
    }
}

fn safe_relative(name: &str) -> bool {
    let path = Path::new(name);
    !name.is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn normalize_name(name: &str) -> String {
    let trimmed = name.trim_start_matches("./").trim_end_matches('/');
    trimmed.to_string()
}

/// Unpack and bound-check a gzip-tar bundle. Refuses links, devices,
/// absolute or parent-escaping names, duplicates, and anything over the
/// renderer's bounds.
pub fn unpack(packed: &[u8]) -> Result<BundleTree, TenantBundleError> {
    let invalid = |why: &str| TenantBundleError::Archive(why.to_string());
    if packed.len() > MAX_PACKED_BYTES {
        return Err(invalid("bundle exceeds the 4 MiB packed bound"));
    }
    let mut unpacked = Vec::new();
    flate2::read::GzDecoder::new(packed)
        .take(MAX_EXPANDED_BYTES as u64 + 1)
        .read_to_end(&mut unpacked)
        .map_err(|_| invalid("bundle is not valid gzip"))?;
    if unpacked.len() > MAX_EXPANDED_BYTES {
        return Err(invalid("bundle exceeds the 32 MiB expanded bound"));
    }
    let mut archive = tar::Archive::new(std::io::Cursor::new(unpacked));
    let mut tree = BundleTree::default();
    let mut members = 0usize;
    for entry in archive
        .entries()
        .map_err(|_| invalid("bundle is not a valid tar"))?
    {
        let mut entry = entry.map_err(|_| invalid("bundle is not a valid tar"))?;
        members += 1;
        if members > MAX_MEMBERS {
            return Err(invalid("bundle has more than 4096 members"));
        }
        let raw = entry
            .path()
            .map_err(|_| invalid("bundle member name is not a path"))?
            .to_str()
            .ok_or_else(|| invalid("bundle member name is not UTF-8"))?
            .to_string();
        if !safe_relative(&raw) {
            return Err(invalid("bundle member escapes the bundle root"));
        }
        let name = normalize_name(&raw);
        if name.is_empty() {
            continue; // the archive's own "." entry
        }
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            if tree.files.contains_key(&name) || !tree.dirs.insert(name) {
                return Err(invalid("bundle declares a member twice"));
            }
        } else if kind.is_file() {
            let mut data = Vec::new();
            entry
                .read_to_end(&mut data)
                .map_err(|_| invalid("bundle member is truncated"))?;
            if tree.dirs.contains(&name) || tree.files.insert(name, data).is_some() {
                return Err(invalid("bundle declares a member twice"));
            }
        } else {
            return Err(invalid("bundle carries a link or special file"));
        }
    }
    if tree.files.is_empty() {
        return Err(invalid("bundle is empty"));
    }
    // Declare implied parents so `pack` round-trips a tree that omitted them.
    let implied: Vec<String> = tree.files.keys().flat_map(|path| parents(path)).collect();
    tree.dirs.extend(implied);
    Ok(tree)
}

fn parents(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Path::new(path).parent();
    while let Some(dir) = current {
        if dir.as_os_str().is_empty() {
            break;
        }
        out.push(dir.to_string_lossy().into_owned());
        current = dir.parent();
    }
    out
}

/// Pack a tree into a deterministic gzip-tar: members sorted by path
/// component (directories before their contents), uid/gid 0, empty owner
/// names, mtime 0, mode 0755/0644, gzip mtime 0 and no file name. The same
/// tree always yields the same bytes for a given builder binary.
pub fn pack(tree: &BundleTree) -> Result<Vec<u8>, TenantBundleError> {
    let mut members: Vec<(&str, Option<&[u8]>)> = tree
        .dirs
        .iter()
        .map(|dir| (dir.as_str(), None))
        .chain(
            tree.files
                .iter()
                .map(|(path, data)| (path.as_str(), Some(data.as_slice()))),
        )
        .collect();
    members.sort_by(|a, b| a.0.split('/').cmp(b.0.split('/')));
    if members.len() > MAX_MEMBERS {
        return Err(TenantBundleError::Archive(
            "bundle has more than 4096 members".into(),
        ));
    }
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in members {
        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        // `new_gnu` zero-fills the owner names; set them explicitly anyway so
        // the determinism does not rest on a constructor default.
        header
            .set_username("")
            .and_then(|_| header.set_groupname(""))
            .map_err(|e| TenantBundleError::Archive(e.to_string()))?;
        let io = |e: std::io::Error| TenantBundleError::Archive(e.to_string());
        match data {
            None => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(0o755);
                header.set_size(0);
                builder
                    .append_data(&mut header, format!("{path}/"), std::io::empty())
                    .map_err(io)?;
            }
            Some(data) => {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_mode(0o644);
                header.set_size(data.len() as u64);
                builder.append_data(&mut header, path, data).map_err(io)?;
            }
        }
    }
    let tar_bytes = builder
        .into_inner()
        .map_err(|e| TenantBundleError::Archive(e.to_string()))?;
    if tar_bytes.len() > MAX_EXPANDED_BYTES {
        return Err(TenantBundleError::Archive(
            "bundle exceeds the 32 MiB expanded bound".into(),
        ));
    }
    let mut encoder = flate2::GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::new(), flate2::Compression::best());
    encoder
        .write_all(&tar_bytes)
        .map_err(|e| TenantBundleError::Archive(e.to_string()))?;
    let packed = encoder
        .finish()
        .map_err(|e| TenantBundleError::Archive(e.to_string()))?;
    if packed.len() > MAX_PACKED_BYTES {
        return Err(TenantBundleError::Archive(
            "bundle exceeds the 4 MiB packed bound".into(),
        ));
    }
    Ok(packed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> BundleTree {
        let mut tree = BundleTree::default();
        tree.put("00-base.toml", b"a = 1\n".to_vec());
        tree.put("sources/parsers/_router.toml", b"r = 1\n".to_vec());
        tree.dirs.insert("certs".into());
        tree
    }

    #[test]
    fn pack_is_deterministic_and_round_trips() {
        let a = pack(&tree()).unwrap();
        let b = pack(&tree()).unwrap();
        assert_eq!(a, b, "same tree must pack to the same bytes");
        let back = unpack(&a).unwrap();
        assert_eq!(back, tree());
    }

    #[test]
    fn put_declares_every_parent_directory() {
        let t = tree();
        assert!(t.dirs.contains("sources"));
        assert!(t.dirs.contains("sources/parsers"));
    }

    #[test]
    fn unpack_refuses_escape_and_links() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_link_name("/etc/passwd").unwrap();
        builder
            .append_data(&mut header, "evil.toml", std::io::empty())
            .unwrap();
        let tar_bytes = builder.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_bytes).unwrap();
        let err = unpack(&gz.finish().unwrap()).unwrap_err();
        assert!(err.to_string().contains("link"), "{err}");
    }
}
