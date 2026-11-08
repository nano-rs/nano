// SPDX-License-Identifier: AGPL-3.0-or-later
//! The content payload: a deterministic gzip'd tar of one repository tree
//! (NAN-4955).
//!
//! The app packs the upstream files in path order with fixed metadata
//! (mode 0644, mtime 0, uid/gid 0, no names), so the same commit always
//! produces byte-identical payload bytes. The consumer unpacks with bounds and
//! refuses anything that is not a plain file at a clean relative path.
//!
//! File ids are git blob SHA-1s (`sha1("blob <len>\0" ++ bytes)`), exactly the
//! `sha` the GitHub tree API reports. An install that synced from GitHub
//! before keeps the same per-file ids, so switching the source to nano's
//! bundle never flags unchanged content as `upstream_changed`.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use sha1::Digest as _;
use sha2::Sha256;

/// Most files one channel tree may carry.
pub const MAX_FILES: usize = 20_000;
/// Most uncompressed bytes one channel tree may carry.
pub const MAX_TREE_BYTES: u64 = 128 * 1024 * 1024;
/// Largest single file. MITRE ATT&CK v19.1's reviewed STIX JSON is about
/// 53 MB. Reserve one eighth of the signed payload for tar/gzip framing and
/// worst-case compression expansion, so an incompressible file at this bound
/// still fits the container instead of passing tree validation and failing at
/// the signing boundary.
pub const MAX_FILE_BYTES: u64 =
    super::contract::MAX_PAYLOAD_BYTES - super::contract::MAX_PAYLOAD_BYTES / 8;
/// Longest relative path.
pub const MAX_PATH_LEN: usize = 512;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TreeError {
    #[error("content tree: {0}")]
    Invalid(String),
    #[error("content tree exceeds its bounds: {0}")]
    TooLarge(&'static str),
}

/// A verified file tree: relative path -> bytes, in path order.
pub type Files = BTreeMap<String, Vec<u8>>;

/// Summary of a tree, as signed in the descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeSummary {
    pub files: u64,
    pub bytes: u64,
    pub sha256: String,
}

/// Git blob SHA-1 of `bytes` (lowercase hex).
pub fn git_blob_sha1(bytes: &[u8]) -> String {
    let mut h = sha1::Sha1::new();
    h.update(format!("blob {}\0", bytes.len()).as_bytes());
    h.update(bytes);
    hex::encode(h.finalize())
}

/// The signed tree digest: SHA-256 over `path \0 git-blob-sha1 \n` lines in
/// path order.
pub fn summarize(files: &Files) -> TreeSummary {
    let mut h = Sha256::new();
    let mut bytes = 0u64;
    for (path, content) in files {
        sha2::Digest::update(&mut h, path.as_bytes());
        sha2::Digest::update(&mut h, b"\0");
        sha2::Digest::update(&mut h, git_blob_sha1(content).as_bytes());
        sha2::Digest::update(&mut h, b"\n");
        bytes += content.len() as u64;
    }
    TreeSummary {
        files: files.len() as u64,
        bytes,
        sha256: hex::encode(sha2::Digest::finalize(h)),
    }
}

/// A clean relative path: UTF-8, `/`-separated, no empty, `.` or `..`
/// component, no leading `/`, no backslash or control character, bounded.
pub fn path_ok(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_LEN
        && !path.starts_with('/')
        && !path.chars().any(|c| c == '\\' || c.is_control())
        && path.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

fn check_bounds(files: &Files) -> Result<(), TreeError> {
    if files.len() > MAX_FILES {
        return Err(TreeError::TooLarge("file count"));
    }
    let mut total = 0u64;
    for (path, content) in files {
        if !path_ok(path) {
            return Err(TreeError::Invalid(format!("unsafe path {path:?}")));
        }
        if content.len() as u64 > MAX_FILE_BYTES {
            return Err(TreeError::TooLarge("file size"));
        }
        total += content.len() as u64;
    }
    if total > MAX_TREE_BYTES {
        return Err(TreeError::TooLarge("tree size"));
    }
    Ok(())
}

/// Pack `files` into the deterministic payload (gzip'd tar).
pub fn pack(files: &Files) -> Result<Vec<u8>, TreeError> {
    check_bounds(files)?;
    let gz = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::new(9));
    let mut builder = tar::Builder::new(gz);
    builder.mode(tar::HeaderMode::Deterministic);
    for (path, content) in files {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_size(content.len() as u64);
        builder
            .append_data(&mut header, path, content.as_slice())
            .map_err(|e| TreeError::Invalid(format!("packing {path}: {e}")))?;
    }
    let gz = builder
        .into_inner()
        .map_err(|e| TreeError::Invalid(format!("packing: {e}")))?;
    gz.finish().map_err(|e| TreeError::Invalid(format!("packing: {e}")))
}

/// Unpack a payload produced by [`pack`]. Bounded before anything is
/// buffered past a cap; refuses links, devices, unsafe or duplicate paths.
pub fn unpack(payload: &[u8]) -> Result<Files, TreeError> {
    let decoder = flate2::read::GzDecoder::new(payload);
    // Tar framing adds 512-byte headers per file; allow for it.
    let cap = MAX_TREE_BYTES + (MAX_FILES as u64 + 16) * 1536;
    let mut archive = tar::Archive::new(decoder.take(cap + 1));
    let mut files = Files::new();
    let mut total = 0u64;
    let entries = archive
        .entries()
        .map_err(|e| TreeError::Invalid(format!("archive: {e}")))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| TreeError::Invalid(format!("archive entry: {e}")))?;
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        if !kind.is_file() {
            return Err(TreeError::Invalid(format!("non-regular entry ({kind:?})")));
        }
        let path = String::from_utf8(entry.path_bytes().into_owned())
            .map_err(|_| TreeError::Invalid("non-UTF-8 path".into()))?;
        if !path_ok(&path) {
            return Err(TreeError::Invalid(format!("unsafe path {path:?}")));
        }
        let size = entry.header().size().map_err(|_| TreeError::Invalid("entry size".into()))?;
        if size > MAX_FILE_BYTES {
            return Err(TreeError::TooLarge("file size"));
        }
        total += size;
        if total > MAX_TREE_BYTES {
            return Err(TreeError::TooLarge("tree size"));
        }
        if files.len() >= MAX_FILES {
            return Err(TreeError::TooLarge("file count"));
        }
        let mut content = Vec::with_capacity(size as usize);
        (&mut entry)
            .take(size + 1)
            .read_to_end(&mut content)
            .map_err(|e| TreeError::Invalid(format!("reading {path}: {e}")))?;
        if content.len() as u64 != size {
            return Err(TreeError::Invalid(format!("truncated entry {path}")));
        }
        if files.insert(path.clone(), content).is_some() {
            return Err(TreeError::Invalid(format!("duplicate path {path}")));
        }
    }
    Ok(files)
}

/// Write `files` under `dir` (consumer: materialize a snapshot for code paths
/// that read a working tree). `dir` must exist; only clean relative paths are
/// written (they were checked on unpack and again here).
pub fn materialize(files: &Files, dir: &std::path::Path) -> std::io::Result<()> {
    for (path, content) in files {
        if !path_ok(path) {
            return Err(std::io::Error::other(format!("unsafe path {path:?}")));
        }
        let target = dir.join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = std::fs::File::create(&target)?;
        f.write_all(content)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tests;
