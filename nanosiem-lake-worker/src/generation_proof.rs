// SPDX-License-Identifier: AGPL-3.0-or-later
//! Authenticated evidence of admission, never an authority for a new assignment.
//!
//! The tenant entity/tail HMAC key authenticates this domain-separated envelope.
//! The owner-signed bundle remains the authority. Files are read-only after
//! admission; dev/inode/size/mtime/ctime guards detect replacement and mutation.
//! The worker UID/key holder is trusted (as it already is for signed tails).
//! Guards do not detect silent media corruption: a full scrub remains necessary
//! for that threat.
//!
//! NAN-2837: snapshot objects are hard-linked between sibling generations, so
//! a shared inode's ctime moves whenever ANY sibling links or unlinks it
//! (next-generation reuse, pruning a superseded generation) -- and in steady
//! state one link in plus one prune out leaves the link count unchanged. For
//! an inode that is or was shared (link count > 1 at mint or now), a ctime-only
//! move with unchanged (dev, inode, size, mtime, read-only mode) is therefore
//! the routine sharing, the same stat trust the snapshot hydrator applies to
//! these very files (`LocalVerificationStamp`). What it no longer catches is an
//! in-place write whose mtime was then restored, which needs the owner (the
//! trusted worker UID, which also holds the proof key) or root; a deterministic
//! 1-in-`LINK_SHARED_SAMPLE_DENOMINATOR` re-hash per load backstops it as the
//! hydrator's sample does. A never-shared inode keeps the strict ctime guard.
//! Any other guard change is re-hashed at load against the authenticated
//! digest: only the changed files, never the whole generation.
//!
//! A peer must authenticate the byte stream and mint NEW local guards; remote
//! inode numbers are never accepted on a different filesystem.
use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::{Component, Path, PathBuf}};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use nanosiem_core::flock_guard::FlockGuard;

pub const FILE_NAME: &str = "verified-generation.json";
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;
/// 1-in-N link-shared members re-hashed per proof load (NAN-2837 backstop).
pub const LINK_SHARED_SAMPLE_DENOMINATOR: u64 = 64;
const DOMAIN: &[u8] = b"nano-verified-generation-v1\0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub tenant_id: String,
    pub table_uuid: String,
    pub snapshot_id: i64,
    pub generation_id: String,
    pub signed_manifest_sha256: String,
    pub source_stamp_sha256: String,
    pub assignment_revision: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub path: PathBuf,
    pub identity: Identity,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Guard {
    dev: u64, inode: u64, bytes: u64,
    mtime: i64, mtime_ns: i64, ctime: i64, ctime_ns: i64,
}
impl Guard {
    pub fn read(path: &Path) -> Result<Self> { Ok(Self::read_linked(path)?.0) }
    /// The guard plus the inode's current link count (NAN-2837).
    pub fn read_linked(path: &Path) -> Result<(Self, u64)> {
        let m = fs::symlink_metadata(path)?;
        if !m.is_file() || m.file_type().is_symlink() || m.mode() & 0o222 != 0 {
            bail!("proof file is not an immutable regular file: {}", path.display());
        }
        Ok((Self { dev: m.dev(), inode: m.ino(), bytes: m.len(), mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(), ctime: m.ctime(), ctime_ns: m.ctime_nsec() }, m.nlink()))
    }
    fn same_bytes_identity(&self, other: &Self) -> bool {
        self.dev == other.dev && self.inode == other.inode && self.bytes == other.bytes
            && self.mtime == other.mtime && self.mtime_ns == other.mtime_ns
    }
}

/// How a file's current identity relates to the one its proof recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardDrift {
    Unchanged,
    /// Only ctime (and possibly the link count) moved on an inode that is or
    /// was hard-linked by a sibling generation: that sibling's link/unlink.
    /// A write moves mtime, a replacement moves the inode, a chmod to
    /// writable fails the read-only check.
    LinkShared,
    /// Anything else, including any ctime move on a never-shared inode.
    /// Re-hash before trusting.
    Changed,
}
impl GuardDrift {
    pub fn trusted(self) -> bool { self != Self::Changed }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRecord {
    pub sha256: String,
    pub bytes: u64,
    pub guard: Guard,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_sha256: Option<String>,
    /// Link count when the guard was minted (NAN-2837). Absent in proofs
    /// minted before it existed; those treat every ctime move as `Changed`
    /// (a one-time targeted re-hash after upgrade).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nlink: Option<u64>,
}
impl FileRecord {
    fn new(sha256: String, guard: Guard, nlink: u64, object_sha256: Option<String>) -> Self {
        Self { sha256, bytes: guard.bytes, guard, object_sha256, nlink: Some(nlink) }
    }
    pub fn drift(&self, current: &Guard, nlink: u64) -> GuardDrift {
        if current == &self.guard { GuardDrift::Unchanged }
        else if current.same_bytes_identity(&self.guard) && self.nlink.is_some_and(|recorded| recorded > 1 || nlink > 1) { GuardDrift::LinkShared }
        else { GuardDrift::Changed }
    }
    /// Current drift of `path` against this record; unreadable is `Changed`.
    pub fn drift_at(&self, path: &Path) -> GuardDrift {
        Guard::read_linked(path).map_or(GuardDrift::Changed, |(guard, nlink)| self.drift(&guard, nlink))
    }
}

/// Outcome of loading a proof: how many files needed a targeted re-hash.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Revalidation {
    pub link_shared_files: usize,
    pub sampled_files: usize,
    pub rehashed_files: usize,
    pub rehashed_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRecord {
    pub sha256: String,
    pub members: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Body {
    version: u8,
    pub identity: Identity,
    pub root: PathBuf,
    pub files: BTreeMap<String, FileRecord>,
    pub trees: BTreeMap<String, TreeRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derivative_inventory: Vec<crate::generation_bundle::DerivativeMember>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope { pub body: Body, mac: String }

pub fn key(path: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(path)?;
    let bytes = bytes.trim_ascii().to_vec();
    if bytes.len() < 32 { bail!("generation proof key is shorter than 32 bytes"); }
    Ok(bytes)
}
fn mac(key: &[u8], bytes: &[u8]) -> Result<Hmac<Sha256>> {
    if key.len() < 32 { bail!("generation proof key is shorter than 32 bytes"); }
    let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
    mac.update(DOMAIN); mac.update(bytes); Ok(mac)
}
pub fn relative(path: &Path) -> Result<&str> {
    let text = path.to_str().context("proof path is not UTF-8")?;
    if text.is_empty() || text.len() > 4096 || text.chars().any(char::is_control)
        || path.components().any(|c| !matches!(c, Component::Normal(_))) {
        bail!("unsafe generation proof path");
    }
    Ok(text)
}
/// The single definition of the v2 (inventory) tree digest.
///
/// `Body::inventory_trees` mints it from the authenticated proof; `config.rs`
/// re-derives the SAME value from disk when no local proof is available, so a
/// generation whose index members are content-store links can still be
/// verified in full after a restart. Records are (member name, size, content
/// sha256) in member-name order.
pub(crate) fn inventory_tree_sha256(records: &[(&str, u64, &str)]) -> Result<String> {
    Ok(sha(&serde_json::to_vec(&("nano-inventory-tree-v1", records))?))
}

fn checked_path(root: &Path, path: &str) -> Result<PathBuf> {
    relative(Path::new(path))?;
    let mut current = root.to_path_buf();
    // Reject symlink ancestors, including the root and its ancestors.
    for ancestor in root.ancestors() {
        if fs::symlink_metadata(ancestor)?.file_type().is_symlink() { bail!("proof root contains a symlink"); }
    }
    for part in Path::new(path).components() {
        current.push(part);
        if fs::symlink_metadata(&current)?.file_type().is_symlink() { bail!("proof path contains a symlink"); }
    }
    Ok(current)
}

impl Body {
    pub fn new(identity: Identity, root: PathBuf) -> Self {
        Self { version: 1, identity, root, files: BTreeMap::new(), trees: BTreeMap::new(), derivative_inventory: Vec::new() }
    }
    /// Caller owns private staging and supplies a digest accumulated while
    /// admitting bytes, or obtained by full verification against an authority.
    pub(crate) fn record(&mut self, relative_path: &str, staged: &Path, sha256: String) -> Result<()> {
        relative(Path::new(relative_path))?;
        if fs::symlink_metadata(staged)?.mode() & 0o222 != 0 { fs::set_permissions(staged, fs::Permissions::from_mode(0o444))?; }
        let (guard, nlink) = Guard::read_linked(staged)?;
        self.files.insert(relative_path.to_owned(), FileRecord::new(sha256, guard, nlink, None));
        Ok(())
    }
    pub fn encode(&self, key: &[u8]) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        let signature = hex::encode(mac(key, &bytes)?.finalize().into_bytes());
        let bytes = serde_json::to_vec(&Envelope { body: self.clone(), mac: signature })?;
        if bytes.len() as u64 > MAX_BYTES { bail!("generation proof exceeds its bound"); }
        Ok(bytes)
    }
    pub fn authenticate(bytes: &[u8], key: &[u8], expected: &Identity) -> Result<Self> {
        if bytes.len() as u64 > MAX_BYTES { bail!("generation proof exceeds its bound"); }
        let envelope: Envelope = serde_json::from_slice(bytes)?;
        mac(key, &serde_json::to_vec(&envelope.body)?)?.verify_slice(&hex::decode(envelope.mac)?)
            .context("generation proof authentication failed")?;
        let body = envelope.body;
        if body.version != 1 || &body.identity != expected || !body.root.is_absolute()
            || body.files.is_empty() { bail!("generation proof identity or inventory mismatch"); }
        for (path, record) in &body.files {
            relative(Path::new(path))?;
            if record.sha256.len() != 64 || hex::decode(&record.sha256)?.len() != 32 || record.bytes != record.guard.bytes {
                bail!("invalid generation proof digest or size");
            }
        }
        for member in &body.derivative_inventory {
            relative(Path::new(&member.relative_path))?;
            if member.content_id != format!("sha256:{}", member.sha256) { bail!("proof inventory content id mismatch"); }
        }
        Ok(body)
    }
    /// Authenticate a self-describing envelope, then let the caller compare
    /// assignment/snapshot authority. No fields are trusted before the MAC.
    pub fn load_at(path: &Path, key: &[u8]) -> Result<Self> {
        let m = fs::symlink_metadata(path)?;
        if !m.is_file() || m.file_type().is_symlink() || m.len() > MAX_BYTES { bail!("invalid proof file"); }
        let bytes = fs::read(path)?;
        let envelope: Envelope = serde_json::from_slice(&bytes)?;
        let mut body = Self::authenticate(&bytes, key, &envelope.body.identity)?;
        body.revalidate()?; Ok(body)
    }
    pub fn load(reference: &Reference, key: &[u8]) -> Result<Self> {
        let m = fs::symlink_metadata(&reference.path)?;
        if !m.is_file() || m.file_type().is_symlink() || m.len() > MAX_BYTES { bail!("invalid proof file"); }
        let mut body = Self::authenticate(&fs::read(&reference.path)?, key, &reference.identity)?;
        body.revalidate()?;
        Ok(body)
    }
    /// Strict check with no hashing: exact membership and every file's guard
    /// unchanged or moved only by a sibling's link/unlink (NAN-2837).
    pub fn validate_guards(&self) -> Result<()> {
        if let Some((path, _)) = self.drifted_files()?.into_iter().find(|(_, drift)| !drift.trusted()) {
            bail!("generation proof file guard changed: {path}");
        }
        Ok(())
    }
    /// NAN-2837: the load-time check. Membership and trees stay exact. A file
    /// whose guard changed is re-hashed against its AUTHENTICATED digest --
    /// only that file, with bounded parallelism -- and its guard refreshed in
    /// memory when the bytes still match. Different bytes fail the load.
    pub fn revalidate(&mut self) -> Result<Revalidation> {
        let drifted = self.drifted_files()?;
        let mut outcome = Revalidation::default();
        let mut changed = Vec::new();
        for (path, drift) in drifted {
            if drift == GuardDrift::LinkShared {
                outcome.link_shared_files += 1;
                if !self.link_shared_sample(&path) { continue; }
                outcome.sampled_files += 1;
            }
            changed.push(path);
        }
        if changed.is_empty() { return Ok(outcome); }
        let started = std::time::Instant::now();
        let targets = changed.iter().map(|path| Ok((path.clone(), self.resolved_file(path)?))).collect::<Result<Vec<_>>>()?;
        let hashed = crate::verify::parallel_map(&targets, crate::verify::verify_workers(), |(relative, file)| {
            let (before, _) = Guard::read_linked(file)?;
            let (digest, bytes) = file_sha256(file)?;
            let (after, nlink) = Guard::read_linked(file)?;
            if !before.same_bytes_identity(&after) { bail!("generation proof file changed while re-hashed: {relative}"); }
            let record = &self.files[relative];
            if digest != record.sha256 || bytes != record.bytes {
                bail!("generation proof file content changed: {relative}");
            }
            Ok((after, nlink, bytes))
        })?;
        for ((relative, _), (guard, nlink, bytes)) in targets.into_iter().zip(hashed) {
            let record = self.files.get_mut(&relative).expect("changed file is a proof member");
            record.guard = guard; record.nlink = Some(nlink);
            outcome.rehashed_files += 1; outcome.rehashed_bytes += bytes;
        }
        tracing::info!(rehashed_files = outcome.rehashed_files, rehashed_bytes = outcome.rehashed_bytes,
            sampled_files = outcome.sampled_files, link_shared_files = outcome.link_shared_files,
            seconds = started.elapsed().as_secs_f64(),
            "generation proof re-hashed only changed and sampled files against the authenticated digests");
        Ok(outcome)
    }
    /// Deterministic per-generation sample, like the hydrator's re-verify:
    /// consecutive generations sample different members.
    fn link_shared_sample(&self, path: &str) -> bool {
        let digest = Sha256::digest(format!("nan2837-link-shared:{}:{path}", self.identity.snapshot_id).as_bytes());
        u64::from_be_bytes(digest[..8].try_into().expect("8 bytes")) % LINK_SHARED_SAMPLE_DENOMINATOR == 0
    }
    /// Exact membership and tree checks, then every proof member whose guard
    /// is not exactly as minted, with how it drifted.
    fn drifted_files(&self) -> Result<Vec<(String, GuardDrift)>> {
        ensure_not_retired(&self.root)?;
        // Exact recursive membership also protects SlateDB checkpoints, whose
        // loader may discover metadata by listing rather than a config path.
        let prefixes = self.files.keys().filter_map(|path| Path::new(path).components().next())
            .map(|part| part.as_os_str().to_owned()).collect::<std::collections::BTreeSet<_>>();
        let mut inventory = std::collections::BTreeSet::new();
        fn walk(body: &Body, path: &Path, files: &mut std::collections::BTreeSet<String>) -> Result<()> {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() {
                let name = path.strip_prefix(&body.root)?.to_str().context("invalid object link")?;
                body.resolved_file(name)?;
                files.insert(name.to_owned());
                return Ok(());
            }
            if metadata.is_dir() {
                for entry in fs::read_dir(path)? { walk(body, &entry?.path(), files)?; }
            } else if metadata.is_file() {
                let name = path.strip_prefix(&body.root)?.to_str().context("invalid inventory path")?;
                let parent = path.parent().and_then(|p| p.strip_prefix(&body.root).ok()).and_then(Path::to_str).unwrap_or("");
                if path.file_name().and_then(|v| v.to_str()) == Some(FILE_NAME)
                    || name == "snapshot/local-verification.json"
                    || (body.trees.contains_key(parent) && name.ends_with(".lock")) { return Ok(()); }
                files.insert(name.to_owned());
                if files.len() > body.files.len() { bail!("proof inventory exceeds its authenticated membership"); }
            } else { bail!("proof inventory contains a non-regular file"); }
            Ok(())
        }
        for prefix in prefixes { walk(self, &self.root.join(prefix), &mut inventory)?; }
        if inventory != self.files.keys().cloned().collect() { bail!("generation proof inventory changed"); }

        for (path, record) in &self.trees {
            let directory = checked_path(&self.root, path)?;
            if self.tree_members(&directory)? != record.members { bail!("generation proof tree membership changed: {path}"); }
        }
        let mut drifted = Vec::new();
        for (path, record) in &self.files {
            // read_linked also enforces a read-only regular file, not a symlink.
            let (guard, nlink) = Guard::read_linked(&self.resolved_file(path)?)?;
            let drift = record.drift(&guard, nlink);
            if drift != GuardDrift::Unchanged { drifted.push((path.clone(), drift)); }
        }
        Ok(drifted)
    }
    fn resolved_file(&self, relative: &str) -> Result<PathBuf> {
        let record = self.files.get(relative).context("unlisted object link")?;
        if let Some(digest) = &record.object_sha256 {
            if digest != &record.sha256 || digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
                bail!("object content id differs from authenticated digest");
            }
            let link = self.root.join(relative);
            checked_path(&self.root, Path::new(relative).parent().and_then(Path::to_str).context("object parent missing")?)?;
            let objects = self.root.parent().context("generation parent absent")?.join("objects");
            let object = checked_path(&objects, digest)?;
            if fs::read_link(&link)? != object { bail!("object link differs from authenticated content id"); }
            Ok(object)
        } else { checked_path(&self.root, relative) }
    }
    pub(crate) fn record_object(&mut self, relative: &str, staged: &Path, digest: &str) -> Result<()> {
        crate::generation_proof::relative(Path::new(relative))?;
        let object = fs::read_link(staged)?;
        let (guard, nlink) = Guard::read_linked(&object)?;
        self.files.insert(relative.to_owned(), FileRecord::new(digest.into(), guard, nlink, Some(digest.into())));
        Ok(())
    }
    fn tree_members(&self, directory: &Path) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name().into_string().map_err(|_| anyhow::anyhow!("invalid filename"))?;
            if name.ends_with(".lock") && entry.file_type()?.is_file() { continue; }
            let path = entry.path();
            let relative = path.strip_prefix(&self.root)?.to_str().context("invalid tree path")?;
            self.resolved_file(relative)?;
            names.push(name);
        }
        names.sort(); Ok(names)
    }
    /// v2 tree identity is a digest of the authenticated file inventory. It
    /// deliberately never hashes concatenated payloads on admission or reuse.
    pub(crate) fn inventory_trees(&mut self, prefix: &str) -> Result<()> {
        for directory in ["keyword-sidecar/index", "fragment-sidecar/index", "count-rollup"] {
            let directory = format!("{prefix}/{directory}");
            let records: Vec<_> = self.files.iter().filter(|(path, _)| Path::new(path).parent().and_then(Path::to_str) == Some(directory.as_str()) && !path.ends_with(".lock"))
                .map(|(path, file)| (Path::new(path).file_name().unwrap().to_str().unwrap(), file.bytes, file.sha256.as_str())).collect();
            if records.is_empty() { continue; }
            let sha256 = inventory_tree_sha256(&records)?;
            let members = records.iter().map(|r| r.0.to_owned()).collect();
            self.trees.insert(directory, TreeRecord { sha256, members });
        }
        Ok(())
    }
    pub fn file_digest(&self, path: &Path) -> Option<&str> {
        let relative = path.strip_prefix(&self.root).ok()?.to_str()?;
        let record = self.files.get(relative)?;
        record.drift_at(&self.resolved_file(relative).ok()?).trusted().then_some(record.sha256.as_str())
    }
    pub fn tree_digest(&self, path: &Path) -> Option<(&str, usize)> {
        let relative = path.strip_prefix(&self.root).ok()?.to_str()?;
        let tree = self.trees.get(relative)?;
        if self.tree_members(path).ok()? != tree.members { return None; }
        for name in &tree.members { self.file_digest(&path.join(name))?; }
        Some((&tree.sha256, tree.members.len()))
    }
    pub fn save(&self, path: &Path, key: &[u8]) -> Result<()> {
        use std::io::Write;
        let mut staged = tempfile::NamedTempFile::new_in(path.parent().context("proof has no parent")?)?;
        staged.write_all(&self.encode(key)?)?;
        staged.as_file().sync_all()?;
        staged.persist(path)?;
        fs::File::open(path.parent().unwrap())?.sync_all()?;
        Ok(())
    }
}
/// A retired generation's tombstone (the path the retired gen1 hosted GC,
/// NAN-3861, wrote; a present tombstone still refuses the generation).
pub(crate) fn tombstone(root: &Path, name: &str) -> std::path::PathBuf {
    root.join(".generation-tombstones").join(name)
}

/// Durable atomic JSON write: temp file in the target directory, fsync,
/// rename, fsync the directory.
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("receipt parent missing")?;
    fs::create_dir_all(parent)?;
    let mut candidate = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(&mut candidate, value)?;
    candidate.flush()?;
    candidate.as_file().sync_all()?;
    candidate.persist(path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub(crate) fn ensure_not_retired(root: &Path) -> Result<()> {
    if let (Some(parent), Some(name)) = (root.parent(), root.file_name().and_then(|s| s.to_str())) {
        let tombstone = tombstone(parent, name);
        match fs::symlink_metadata(&tombstone) {
            Ok(_) => bail!("generation is retired: {}", root.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub fn tree_members(path: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() { bail!("proof tree contains a non-file"); }
        let name = entry.file_name().into_string().map_err(|_| anyhow::anyhow!("invalid tree filename"))?;
        if !name.ends_with(".lock") { names.push(name); }
    }
    names.sort(); Ok(names)
}

/// Receipt accumulated by the hydrator in this process, never deserialized
/// from the unsigned legacy on-disk verification ledger.
#[derive(Debug, Default)]
pub struct ReceivedFiles(pub(crate) BTreeMap<PathBuf, FileRecord>);
impl ReceivedFiles {
    pub(crate) fn record(&mut self, path: PathBuf, digest: String) -> Result<()> {
        if fs::symlink_metadata(&path)?.mode() & 0o222 != 0 { fs::set_permissions(&path, fs::Permissions::from_mode(0o444))?; }
        let (guard, nlink) = Guard::read_linked(&path)?;
        self.0.insert(path, FileRecord::new(digest, guard, nlink, None)); Ok(())
    }
}

pub fn sha(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{config::VerifiedArtifact, verify::VerificationPlan};
    pub const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
    pub fn fixture(root: &Path) -> (Body, serde_json::Value) {
        let identity = Identity { tenant_id: "tenant-a".into(), table_uuid: uuid::Uuid::from_u128(42).to_string(),
            snapshot_id: 42, generation_id: "signed-bundle-42".into(), signed_manifest_sha256: sha(b"signed bundle"),
            source_stamp_sha256: String::new(), assignment_revision: 7 };
        let mut body = Body::new(identity, root.to_path_buf());
        fs::create_dir_all(root.join("snapshot/data")).unwrap();
        fs::create_dir_all(root.join("derivatives/index")).unwrap();
        fs::write(root.join("snapshot/data/part.parquet"), b"source data").unwrap();
        fs::write(root.join("derivatives/index/0.idx"), b"index data").unwrap();
        fs::write(root.join("derivatives/manifest.json"), b"{}").unwrap();
        let stamps = crate::generation::ObjectStampManifest { metadata_location: "s3://bucket/table/metadata/v42.json".into(),
            snapshot_id: 42, table: "nano.events".into(), table_uuid: Some(body.identity.table_uuid.clone()),
            objects: vec![crate::generation::ObjectStamp { relative_path: "part.parquet".into(), source_uri: "s3://bucket/table/data/part.parquet".into(), version_id: "v1".into(), size_bytes: 11, sha256: sha(b"source data") }] };
        // Use exact written length, independent of this fixture's label.
        let mut stamps = stamps; stamps.objects[0].size_bytes = 11;
        body.identity.source_stamp_sha256 = crate::generation_bundle::object_stamp_manifest_sha256(&crate::generation_bundle::GenerationBundleObjectStampManifest::from(&stamps)).unwrap();
        fs::write(root.join("snapshot/object-stamps.json"), serde_json::to_vec(&stamps).unwrap()).unwrap();
        for path in ["snapshot/data/part.parquet", "snapshot/object-stamps.json", "derivatives/index/0.idx", "derivatives/manifest.json"] {
            body.record(path, &root.join(path), sha(&fs::read(root.join(path)).unwrap())).unwrap();
        }
        let (digest, _) = crate::config::index_directory_sha256(&root.join("derivatives/index"), "fixture").unwrap();
        body.trees.insert("derivatives/index".into(), TreeRecord { sha256: digest.clone(), members: vec!["0.idx".into()] });
        body.save(&root.join("derivatives").join(FILE_NAME), KEY).unwrap();
        // Any mutation a test makes after the fixture lands in a later tick.
        ctime_tick();
        let key_path = root.parent().unwrap().join("tenant.key"); fs::write(&key_path, KEY).unwrap();
        let artifact = |path: &str| serde_json::json!({"path": root.join(path), "sha256": body.files[path].sha256});
        let manifest = artifact("derivatives/manifest.json");
        let config = serde_json::json!({
            "schema_version":1, "generation_id":"lake-42-fixture", "assigned_tenant_id":"tenant-a",
            "generation_proof": {"path":root.join("derivatives").join(FILE_NAME), "identity":body.identity},
            "compiler":manifest, "native_library":manifest,
            "tenant":{"tenant_id":"tenant-a", "source":"s3://bucket/table", "iceberg_metadata_file_path":"metadata/v42.json", "source_manifest":manifest,
                "max_query_bytes":1000000, "max_execution_seconds":30, "threads":1, "event_contract":"ocsf-1.9", "allow_broad_npl":true, "iceberg_default_credentials":true},
            "snapshot_cache":{"object_stamp_manifest":artifact("snapshot/object-stamps.json"), "data_directory":root.join("snapshot/data"), "max_bytes":1000000, "ancestor_snapshot_ids":[42]},
            "entity_sidecar":{"manifest":manifest, "hmac_key":{"path":key_path,"sha256":sha(KEY)}, "index_files":[artifact("derivatives/index/0.idx")]},
            "keyword_sidecar":{"manifest":manifest, "index_directory":root.join("derivatives/index"), "index_tree_sha256":digest,
                "fragment_manifest":manifest, "fragment_index_directory":root.join("derivatives/index"), "fragment_index_tree_sha256":digest}
        });
        (body, config)
    }
    /// NAN-2532 blocker 2: `install_object` used `fs::rename`, which replaces
    /// the inode of `objects/<digest>`. Every retained generation that pinned
    /// that digest holds a `Guard { dev, inode, ctime, .. }` on the OLD inode
    /// and then fails `validate_guards()` -- including the generation currently
    /// serving. The window needs only a receipt-less object, which is exactly
    /// what a pod kill between the link and the receipt write leaves behind
    /// (and what a tenant key rotation produces for every object at once).
    #[test]
    fn a_crash_between_the_link_and_the_receipt_cannot_clobber_a_pinned_object() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("received");
        fs::write(&source, b"pinned derivative").unwrap();
        let digest = sha(b"pinned derivative");
        let bytes = b"pinned derivative".len() as u64;
        let object = install_object(root.path(), &source, &digest, bytes, KEY, ObjectSource::Authenticated).unwrap();
        let pinned = Guard::read(&object).unwrap();

        // The crash window: the dirent exists, the receipt does not.
        fs::remove_file(root.path().join("objects/.receipts").join(&digest)).unwrap();
        assert!(reusable_object(root.path(), &digest, bytes, KEY).is_err(), "no receipt, no reuse");

        let again = root.path().join("received-again");
        fs::write(&again, b"pinned derivative").unwrap();
        let readmitted = install_object(root.path(), &again, &digest, bytes, KEY, ObjectSource::Authenticated).unwrap();
        assert_eq!(readmitted, object);
        assert_eq!(Guard::read(&object).unwrap(), pinned, "a pinned object's inode must survive re-admission");
        assert!(reusable_object(root.path(), &digest, bytes, KEY).is_ok(), "the receipt is minted for the adopted inode");
        assert!(!again.exists(), "the staged copy is consumed");

        // An object whose bytes do not match its own name is never replaced
        // either: it may be pinned, so refuse loudly instead.
        fs::remove_file(root.path().join("objects/.receipts").join(&digest)).unwrap();
        fs::set_permissions(&object, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&object, b"silently corrupted").unwrap();
        fs::set_permissions(&object, fs::Permissions::from_mode(0o444)).unwrap();
        let third = root.path().join("received-third");
        fs::write(&third, b"pinned derivative").unwrap();
        let error = install_object(root.path(), &third, &digest, bytes, KEY, ObjectSource::Authenticated).unwrap_err();
        assert!(error.to_string().contains("refusing to replace"), "{error}");
        assert_eq!(fs::read(&object).unwrap(), b"silently corrupted");
    }

    /// NAN-2532 blocker 3: a peer handover byte is only the REMOTE proof's
    /// claim. Minting a local receipt for it would make a donor's silent
    /// corruption permanent -- every later owner-signed bundle naming that
    /// digest reuses the object and skips both the GET and the hash.
    #[test]
    fn unverified_handover_bytes_are_hashed_before_they_enter_the_content_store() {
        let root = tempfile::tempdir().unwrap();
        let claimed = sha(b"what the donor promised");
        let source = root.path().join("peer-bytes");
        fs::write(&source, b"what the donor actually sent").unwrap();
        let error = install_object(root.path(), &source, &claimed, 23, KEY, ObjectSource::Unverified).unwrap_err();
        assert!(error.to_string().contains("claimed digest"), "{error}");
        assert!(!object_path(root.path(), &claimed).unwrap().exists(), "corrupt peer bytes never reach the store");
        assert!(reusable_object(root.path(), &claimed, 23, KEY).is_err());

        let honest = root.path().join("honest-peer-bytes");
        fs::write(&honest, b"what the donor promised").unwrap();
        let bytes = b"what the donor promised".len() as u64;
        install_object(root.path(), &honest, &claimed, bytes, KEY, ObjectSource::Unverified).unwrap();
        assert!(reusable_object(root.path(), &claimed, bytes, KEY).is_ok());
    }

    /// NAN-2532 item 8: flock(2) conflicts between DISTINCT file descriptors
    /// within one process, so a blocking `lock_exclusive` turns any nesting
    /// (a collection inside a hydration) into a silent self-deadlock. The
    /// acquisition must be bounded and must report who is holding it.
    #[test]
    fn the_object_store_lock_is_exclusive_bounded_and_never_self_deadlocks() {
        let root = tempfile::tempdir().unwrap();
        let held = object_store_lock(root.path()).unwrap();

        // Same process, second descriptor: this is the nesting that used to
        // hang forever.
        assert!(try_object_store_lock(root.path()).unwrap().is_none());
        let started = std::time::Instant::now();
        let error = object_store_lock_within(root.path(), std::time::Duration::from_millis(200)).unwrap_err();
        assert!(error.to_string().contains("held by another writer"), "{error}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "acquisition must be bounded");
        // The collector nests on the same lock and must fail, not hang.
        assert!(collect_objects_within(root.path(), std::time::Duration::from_millis(200)).is_err());

        // A genuine waiter still gets the lock once the holder releases it.
        let path = root.path().to_path_buf();
        let waiter = std::thread::spawn(move || object_store_lock_within(&path, std::time::Duration::from_secs(30)));
        std::thread::sleep(std::time::Duration::from_millis(50));
        drop(held);
        let taken = waiter.join().unwrap().unwrap();
        assert!(try_object_store_lock(root.path()).unwrap().is_none());
        drop(taken);
        assert!(try_object_store_lock(root.path()).unwrap().is_some());
    }

    /// NAN-2822: a released content-store lock must not survive in a child
    /// that another thread forked while it was open.
    #[test]
    fn released_object_store_lock_is_not_held_by_concurrently_forked_children() {
        let root = tempfile::tempdir().unwrap();
        nanosiem_core::flock_guard::with_concurrent_spawns(std::time::Duration::from_secs(1), |i| {
            let held = try_object_store_lock(root.path()).unwrap();
            assert!(held.is_some(), "iteration {i}: phantom holder");
        });
    }

    #[test]
    fn object_receipt_and_restored_timestamp_mutations_cannot_authorize_reuse() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("received"); fs::write(&source, b"original").unwrap();
        let digest = sha(b"original");
        let object = install_object(root.path(), &source, &digest, 8, KEY, ObjectSource::Authenticated).unwrap();
        ctime_tick();
        assert!(reusable_object(root.path(), &digest, 8, KEY).is_ok());
        assert!(reusable_object(root.path(), &digest, 9, KEY).is_err());
        assert!(reusable_object(root.path(), &digest, 8, b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").is_err());
        let modified = fs::metadata(&object).unwrap().modified().unwrap();
        fs::set_permissions(&object, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&object, b"modified").unwrap();
        fs::File::open(&object).unwrap().set_times(fs::FileTimes::new().set_modified(modified)).unwrap();
        fs::set_permissions(&object, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(reusable_object(root.path(), &digest, 8, KEY).is_err());
    }

    fn load(proof: &Body) -> Result<Body> {
        Body::load(&Reference { path: proof.root.join("derivatives").join(FILE_NAME), identity: proof.identity.clone() }, KEY)
    }
    fn tamper_in_place(path: &Path, bytes: &[u8], restore_mtime: bool) {
        let modified = fs::metadata(path).unwrap().modified().unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(path, bytes).unwrap();
        if restore_mtime { fs::File::open(path).unwrap().set_times(fs::FileTimes::new().set_modified(modified)).unwrap(); }
        fs::set_permissions(path, fs::Permissions::from_mode(0o444)).unwrap();
    }
    /// NAN-3866: return once every LATER inode change is guaranteed a
    /// ctime/mtime newer than any stamp taken BEFORE this call. The kernel
    /// stamps inodes from the coarse clock (one jiffy, 1-10 ms), so a tamper
    /// in the same tick as the mint leaves the guard byte-identical -- a
    /// test-ordering artifact (a real tamper lands ticks later), not a hole a
    /// sleep can close under load. Waits on the clock itself: no fixed sleep.
    fn ctime_tick() {
        fn clock(id: libc::clockid_t) -> (i64, i64) {
            let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            // SAFETY: valid out-pointer; both clock ids exist on Linux.
            assert_eq!(unsafe { libc::clock_gettime(id, &mut now) }, 0);
            (now.tv_sec, now.tv_nsec)
        }
        // Fine-grained "now" bounds every earlier stamp, coarse or fine.
        let floor = clock(libc::CLOCK_REALTIME);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while clock(libc::CLOCK_REALTIME_COARSE) <= floor {
            assert!(std::time::Instant::now() < deadline, "coarse clock never advanced");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// NAN-2837 repro (tenant1 2026-09-25): the next generation's hydration
    /// hard-links this generation's snapshot objects, and pruning a superseded
    /// generation unlinks them. Either moves the SHARED inode's ctime, which
    /// voided the whole proof ("generation proof file guard changed:
    /// snapshot/data/tail/.../pack-....parquet") and forced a 23-min full
    /// re-hash of 28 GB. Steady state (one link in, one prune out) even leaves
    /// the link count where it was minted.
    #[test]
    fn sibling_generation_link_churn_never_voids_the_proof() {
        let root = tempfile::tempdir().unwrap(); let (proof, _) = fixture(&root.path().join("generation"));
        let object = proof.root.join("snapshot/data/part.parquet");
        // The superseded generation already shares the inode when it is pruned.
        let superseded = root.path().join("superseded-part.parquet");
        ctime_tick(); fs::hard_link(&object, &superseded).unwrap();
        ctime_tick(); let next = root.path().join("next-generation-part.parquet"); fs::hard_link(&object, &next).unwrap();
        ctime_tick(); fs::remove_file(&superseded).unwrap();
        assert_eq!(fs::metadata(&object).unwrap().nlink(), 2);
        assert_ne!(Guard::read(&object).unwrap(), proof.files["snapshot/data/part.parquet"].guard, "the churn moved ctime");

        proof.validate_guards().unwrap();
        assert_eq!(proof.file_digest(&object), Some(proof.files["snapshot/data/part.parquet"].sha256.as_str()));
        let mut loaded = load(&proof).unwrap();
        let outcome = loaded.revalidate().unwrap();
        assert_eq!(outcome.link_shared_files, 1);
        assert_eq!(outcome.rehashed_files, outcome.sampled_files, "only the deterministic sample is re-hashed");

        // Steady state after the next prune too: shared-at-mint, now unshared.
        ctime_tick(); fs::remove_file(&next).unwrap();
        load(&proof).unwrap();
    }

    /// NAN-2837: tolerating link churn must not tolerate changed bytes, and
    /// every other guard change costs a re-hash of that ONE file, not the
    /// generation.
    #[test]
    fn changed_files_are_rehashed_individually_and_tampering_still_fails() {
        // A write to a shared inode moves mtime: re-hashed, then rejected.
        let root = tempfile::tempdir().unwrap(); let (proof, _) = fixture(&root.path().join("generation"));
        let object = proof.root.join("snapshot/data/part.parquet");
        fs::hard_link(&object, root.path().join("sibling")).unwrap();
        ctime_tick(); tamper_in_place(&object, b"tamper data", false);
        assert!(proof.validate_guards().is_err());
        assert!(load(&proof).unwrap_err().to_string().contains("content changed"));

        // A never-shared inode keeps the strict ctime guard: a chmod-only
        // change is re-hashed (that file alone) and then trusted...
        let root = tempfile::tempdir().unwrap(); let (proof, _) = fixture(&root.path().join("generation"));
        let index = proof.root.join("derivatives/index/0.idx");
        ctime_tick(); fs::set_permissions(&index, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(proof.validate_guards().is_err(), "strict check still sees the change");
        let mut loaded = load(&proof).unwrap();
        assert_eq!(loaded.revalidate().unwrap().rehashed_files, 0, "load refreshed the guard in memory");
        let outcome = { let mut again = Body::authenticate(&fs::read(proof.root.join("derivatives").join(FILE_NAME)).unwrap(), KEY, &proof.identity).unwrap(); again.revalidate().unwrap() };
        assert_eq!((outcome.rehashed_files, outcome.rehashed_bytes), (1, 10), "exactly the changed file");
        // ...but a write with a restored mtime is caught by ctime and the re-hash.
        ctime_tick(); tamper_in_place(&index, b"tamperdata", true);
        assert!(load(&proof).unwrap_err().to_string().contains("content changed"));

        // Replacement: identical bytes are re-admitted, different bytes are not.
        let root = tempfile::tempdir().unwrap(); let (proof, _) = fixture(&root.path().join("generation"));
        let index = proof.root.join("derivatives/index/0.idx");
        fs::remove_file(&index).unwrap(); fs::write(&index, b"index data").unwrap(); fs::set_permissions(&index, fs::Permissions::from_mode(0o444)).unwrap();
        load(&proof).unwrap();
        fs::remove_file(&index).unwrap(); fs::write(&index, b"index DATA").unwrap(); fs::set_permissions(&index, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(load(&proof).is_err());
        // A writable file is never trusted, shared or not.
        let root = tempfile::tempdir().unwrap(); let (proof, _) = fixture(&root.path().join("generation"));
        let object = proof.root.join("snapshot/data/part.parquet");
        fs::hard_link(&object, root.path().join("sibling")).unwrap();
        fs::set_permissions(&object, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(proof.validate_guards().is_err()); assert!(load(&proof).is_err());
    }

    #[test]
    fn every_identity_field_and_transformed_manifest_is_authenticated() {
        let root = tempfile::tempdir().unwrap(); let (proof, _) = fixture(&root.path().join("generation"));
        let encoded = proof.encode(KEY).unwrap();
        for field in ["tenant_id", "table_uuid", "snapshot_id", "generation_id", "signed_manifest_sha256", "source_stamp_sha256", "assignment_revision"] {
            let mut value = serde_json::to_value(&proof.identity).unwrap();
            value[field] = if value[field].is_number() { serde_json::json!(999) } else { serde_json::json!("different") };
            let expected = serde_json::from_value(value).unwrap();
            assert!(Body::authenticate(&encoded, KEY, &expected).is_err(), "{field}");
            let mut envelope: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
            envelope["body"]["identity"][field] = serde_json::to_value(&expected).unwrap()[field].clone();
            assert!(Body::authenticate(&serde_json::to_vec(&envelope).unwrap(), KEY, &expected).is_err(), "forged {field}");
        }
        let mut envelope: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        envelope["body"]["files"]["derivatives/manifest.json"]["sha256"] = serde_json::json!(sha(b"forged"));
        assert!(Body::authenticate(&serde_json::to_vec(&envelope).unwrap(), KEY, &proof.identity).is_err());
        assert!(Body::authenticate(&encoded, b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", &proof.identity).is_err());
    }
    #[test]
    fn mutation_replacement_symlink_and_membership_invalidate_guards() {
        for attack in ["write", "restored-mtime", "replace", "symlink", "extra", "checkpoint-extra", "writable"] {
            let root = tempfile::tempdir().unwrap(); let (proof, _) = fixture(&root.path().join("generation"));
            let path = proof.root.join("derivatives/index/0.idx");
            match attack {
                "write" => { fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(); fs::write(&path, b"tamperdata").unwrap(); fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap(); }
                "restored-mtime" => { let modified = fs::metadata(&path).unwrap().modified().unwrap(); fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(); fs::write(&path, b"tamperdata").unwrap(); fs::File::open(&path).unwrap().set_times(fs::FileTimes::new().set_modified(modified)).unwrap(); fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap(); }
                "checkpoint-extra" => { fs::create_dir_all(proof.root.join("derivatives/checkpoint/manifest")).unwrap(); fs::write(proof.root.join("derivatives/checkpoint/manifest/new.manifest"), b"injected checkpoint").unwrap(); }
                "replace" => { fs::remove_file(&path).unwrap(); fs::write(&path, b"index data").unwrap(); fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap(); }
                "symlink" => { fs::remove_file(&path).unwrap(); std::os::unix::fs::symlink("../manifest.json", &path).unwrap(); }
                "extra" => fs::write(proof.root.join("derivatives/index/extra.idx"), b"extra").unwrap(),
                _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            }
            assert!(proof.validate_guards().is_err(), "{attack}");
        }
    }
    #[test]
    fn proof_skips_payload_hashing_and_fallback_detects_tampering() {
        let root = tempfile::tempdir().unwrap(); let (proof, _) = fixture(&root.path().join("generation"));
        let path = proof.root.join("derivatives/index/0.idx");
        let artifact = VerifiedArtifact { path: path.clone(), sha256: sha(b"index data") };
        let plan = || { let mut plan = VerificationPlan::new(); plan.file(&artifact); plan };
        assert_eq!(plan().run_proven(1, Some(&proof), &[]).unwrap().report.bytes, 0);
        assert_eq!(plan().run_proven(1, None, &[]).unwrap().report.bytes, 10);
        assert_eq!(plan().run_proven(1, Some(&proof), &[path.clone()]).unwrap().report.bytes, 10, "runtime exclusion");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(); fs::write(&path, b"tamperdata").unwrap();
        assert!(plan().run_proven(1, Some(&proof), &[]).is_err());
        assert!(plan().run_proven(1, None, &[]).is_err());
    }
}

#[cfg(test)]
mod benchmark {
    use super::*;
    #[test]
    #[ignore = "offline NAN-2469 native fixture benchmark; requires NANO_CHDB_LIBRARY_PATH/_SHA256"]
    fn nan2469_admission_hash_bytes() {
        use crate::{native::NativeChdb, config::VerifiedArtifact, verify::VerificationPlan};
        use std::time::Instant;
        let runtime = NativeChdb::load_verified(std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(), &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap()).unwrap();
        std::mem::forget(runtime.clone());
        let connection = runtime.connect(&[]).unwrap();
        let root = tempfile::tempdir().unwrap();
        let schema: serde_json::Value = serde_json::from_str(include_str!("../tests/fixtures/nan2469-live-tail-read-schema.json")).unwrap();
        let schema = schema["read_schema"].as_str().unwrap();
        let input = root.path().join("event.jsonl");
        fs::write(&input, serde_json::json!({"time":"2026-08-10 12:00:00", "message":"admission proof fixture ".repeat(160), "user":{"name":"jsmith"}, "src_endpoint":{"ip":"8.8.8.8"}}).to_string()).unwrap();
        let identity = Identity { tenant_id:"tenant-a".into(), table_uuid:uuid::Uuid::from_u128(42).to_string(), snapshot_id:42,
            generation_id:"nan2469-fixture".into(), signed_manifest_sha256:sha(b"fixture bundle"), source_stamp_sha256:sha(b"fixture stamps"), assignment_revision:7 };
        let mut proof = Body::new(identity, root.path().to_path_buf());
        let mut artifacts = Vec::new();
        let mut admitted_bytes = 0;
        for part in 0..4 {
            let path = root.path().join(format!("part-{part}.parquet"));
            connection.query_with_params("INSERT INTO FUNCTION file({output:String}, Parquet) SELECT e.* REPLACE(concat(message, toString(n.number)) AS message) FROM file({input:String}, JSONEachRow, {schema:String}) AS e CROSS JOIN numbers(5000) AS n SETTINGS output_format_parquet_compression_method='none'", "JSONEachRow",
                &[("output", path.to_str().unwrap()), ("input", input.to_str().unwrap()), ("schema", schema)]).unwrap();
            // Model receive/extract: one digest as bytes are admitted. Fixture
            // generation is not counted as admission or verification work.
            let bytes = fs::read(&path).unwrap(); admitted_bytes += bytes.len() as u64;
            let digest = sha(&bytes); proof.record(path.file_name().unwrap().to_str().unwrap(), &path, digest.clone()).unwrap();
            artifacts.push(VerifiedArtifact { path, sha256:digest });
        }
        let plan = || { let mut plan = VerificationPlan::new(); for artifact in &artifacts { plan.file(artifact); } plan };
        let before_start = Instant::now();
        let before_rehash: u64 = (0..3).map(|_| plan().run(4).unwrap().report.bytes).sum();
        let before_seconds = before_start.elapsed().as_secs_f64();
        let after_start = Instant::now();
        let after_rehash: u64 = (0..3).map(|_| { proof.validate_guards().unwrap(); plan().run_proven(4, Some(&proof), &[]).unwrap().report.bytes }).sum();
        assert_eq!(before_rehash, admitted_bytes * 3); assert_eq!(after_rehash, 0);
        println!("NAN2531_BENCH {{\"fixture\":\"NAN-2469 live-tail read schema\",\"admitted_bytes\":{admitted_bytes},\"before_rehash_bytes\":{before_rehash},\"after_rehash_bytes\":{after_rehash},\"before_sha_bytes_per_GB_admitted\":4000000000,\"after_sha_bytes_per_GB_admitted\":1000000000,\"before_rehash_seconds\":{before_seconds},\"after_guard_seconds\":{}}}", after_start.elapsed().as_secs_f64());
    }
}

/// How long a writer waits for the content-store lock before it gives up.
pub const OBJECT_STORE_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

fn open_object_store_lock(root: &Path) -> Result<fs::File> {
    fs::create_dir_all(root)?;
    Ok(fs::OpenOptions::new().create(true).truncate(false).read(true).write(true).open(root.join(".objects.lock"))?)
}

/// Take the content-store lock without blocking. `Ok(None)` means another
/// holder has it right now.
pub fn try_object_store_lock(root: &Path) -> Result<Option<FlockGuard>> {
    let file = open_object_store_lock(root)?;
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => Ok(Some(FlockGuard::adopt(file))),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        // fs2 maps EWOULDBLOCK to its own kind on some targets.
        Err(error) if error.raw_os_error() == Some(libc::EWOULDBLOCK) || error.raw_os_error() == Some(libc::EAGAIN) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// One writer/collector at a time; readers only inspect immutable objects.
///
/// NAN-2532: this is deliberately NOT `lock_exclusive`. flock(2) conflicts
/// between distinct file descriptors *within one process*, so a blocking
/// acquisition turns any nesting (a collection inside a hydration, a hydration
/// inside a collection) into a silent self-deadlock that looks like a hung
/// pod. Bounded try-and-back-off surfaces it as an operator-legible error
/// instead, and the caller retries on the next reconcile.
/// The guard releases with an explicit LOCK_UN. Holders live in processes that
/// spawn children (the generation manager), and a close-only release leaves the
/// lock in a concurrently forked child until its exec, so an immediate re-try
/// sees a phantom holder (NAN-2822: the backoff hid it, direct `try_` did not).
pub fn object_store_lock(root: &Path) -> Result<FlockGuard> {
    object_store_lock_within(root, OBJECT_STORE_LOCK_TIMEOUT)
}

pub(crate) fn object_store_lock_within(root: &Path, timeout: std::time::Duration) -> Result<FlockGuard> {
    let deadline = std::time::Instant::now() + timeout;
    let mut backoff = std::time::Duration::from_millis(5);
    loop {
        if let Some(file) = try_object_store_lock(root)? { return Ok(file); }
        if std::time::Instant::now() >= deadline {
            bail!("derivative content store lock at {} is held by another writer", root.display());
        }
        std::thread::sleep(backoff.min(std::time::Duration::from_millis(500)));
        backoff *= 2;
    }
}

/// `object_store_lock` for async callers: never parks a runtime worker thread
/// and never holds a blocking flock attempt across an await point.
pub async fn object_store_lock_async(root: &Path) -> Result<FlockGuard> {
    let deadline = std::time::Instant::now() + OBJECT_STORE_LOCK_TIMEOUT;
    let mut backoff = std::time::Duration::from_millis(10);
    loop {
        if let Some(file) = try_object_store_lock(root)? { return Ok(file); }
        if std::time::Instant::now() >= deadline {
            bail!("derivative content store lock at {} is held by another writer", root.display());
        }
        tokio::time::sleep(backoff.min(std::time::Duration::from_millis(500))).await;
        backoff *= 2;
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectReceipt { digest: String, guard: Guard, mac: String }
fn object_mac(key: &[u8], digest: &str, guard: &Guard) -> Result<Hmac<Sha256>> {
    mac(key, &serde_json::to_vec(&("nano-derivative-object-v1", digest, guard))?)
}
pub(crate) fn object_path(root: &Path, digest: &str) -> Result<PathBuf> {
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) { bail!("invalid object digest"); }
    Ok(root.join("objects").join(digest))
}
pub(crate) fn reusable_object(root: &Path, digest: &str, bytes: u64, key: &[u8]) -> Result<PathBuf> {
    let path = object_path(root, digest)?;
    let receipt_path = root.join("objects/.receipts").join(digest);
    if fs::symlink_metadata(&receipt_path)?.len() > 4096 { bail!("object receipt exceeds bound"); }
    let receipt: ObjectReceipt = serde_json::from_slice(&fs::read(receipt_path)?)?;
    object_mac(key, &receipt.digest, &receipt.guard)?.verify_slice(&hex::decode(receipt.mac)?)?;
    if receipt.digest != digest || receipt.guard.bytes != bytes || Guard::read(&checked_path(&root.join("objects"), digest)?)? != receipt.guard {
        bail!("immutable object guard changed");
    }
    Ok(path)
}
/// Where the bytes about to enter the content store came from, which decides
/// whether `install_object` may take the caller's digest on trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjectSource {
    /// Owner-signed transport: `read_to`/the archive extractor already
    /// authenticated these exact bytes against the signed manifest.
    Authenticated,
    /// Peer handover: `digest` is only the *remote* proof's claim. A donor's
    /// silent corruption would otherwise be minted a local receipt and reused
    /// by every later owner-signed bundle naming that digest, forever.
    Unverified,
}

pub(crate) fn file_sha256(path: &Path) -> Result<(String, u64)> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
        total += count as u64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

/// Admit `source` into `objects/<digest>` and mint its receipt.
///
/// Callers hold the content-store lock. The object path is never renamed over:
/// retained generations pin an object by (dev, inode, ctime) and replacing the
/// inode would fail `validate_guards()` for every one of them, including the
/// generation currently serving.
pub(crate) fn install_object(root: &Path, source: &Path, digest: &str, bytes: u64, key: &[u8], provenance: ObjectSource) -> Result<PathBuf> {
    if provenance == ObjectSource::Unverified {
        let (actual, actual_bytes) = file_sha256(source)?;
        if actual != digest || actual_bytes != bytes {
            bail!("unverified object content differs from its claimed digest");
        }
    }
    if let Ok(path) = reusable_object(root, digest, bytes, key) { fs::remove_file(source)?; return Ok(path); }
    let path = object_path(root, digest)?;
    fs::create_dir_all(root.join("objects/.receipts"))?;
    fs::set_permissions(source, fs::Permissions::from_mode(0o444))?;
    // hard_link is the only atomic no-clobber publish std offers: it fails
    // with AlreadyExists rather than replacing the inode behind a live pin.
    match fs::hard_link(source, &path) {
        Ok(()) => { fs::remove_file(source)?; }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // A receipt-less object is on disk: a pod kill between the link
            // and the receipt write, or a tenant key rotation that invalidated
            // every receipt at once. Adopt the bytes already there -- they may
            // be pinned by a retained generation -- but only after proving
            // they are the content this digest names.
            let (actual, actual_bytes) = file_sha256(&path)
                .with_context(|| format!("re-hash existing content object {digest}"))?;
            if actual != digest || actual_bytes != bytes {
                bail!("existing content object {digest} does not match its own digest; refusing to replace a possibly pinned object");
            }
            if fs::symlink_metadata(&path)?.mode() & 0o222 != 0 {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o444))?;
            }
            fs::remove_file(source)?;
        }
        Err(error) => return Err(error).context("link derivative object into the content store"),
    }
    let guard = Guard::read(&path)?;
    if guard.bytes != bytes { bail!("object extent differs from signed inventory"); }
    let mac = hex::encode(object_mac(key, digest, &guard)?.finalize().into_bytes());
    write_json(&root.join("objects/.receipts").join(digest), &ObjectReceipt { digest: digest.into(), guard, mac })?;
    fs::File::open(root.join("objects"))?.sync_all()?;
    Ok(path)
}

/// Called only after generation retirement has honored rollback, durable-job
/// and peer pins. Unauthenticated state can retain objects, never authorize a
/// deletion: every remaining generation/staging link is scanned conservatively.
pub fn collect_objects(root: &Path) -> Result<u64> {
    collect_objects_within(root, OBJECT_STORE_LOCK_TIMEOUT)
}

pub(crate) fn collect_objects_within(root: &Path, timeout: std::time::Duration) -> Result<u64> {
    let _lock = object_store_lock_within(root, timeout)?;
    let objects = root.join("objects");
    if !objects.exists() { return Ok(0); }
    let mut retained = std::collections::BTreeSet::new();
    fn scan(path: &Path, objects: &Path, retained: &mut std::collections::BTreeSet<String>) -> Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?; let path = entry.path();
            if path == objects { continue; }
            if entry.file_type()?.is_symlink() {
                let target = fs::read_link(&path)?;
                if target.parent() == Some(objects) { retained.insert(target.file_name().unwrap().to_string_lossy().into_owned()); }
            } else if entry.file_type()?.is_dir() { scan(&path, objects, retained)?; }
            else if entry.file_name() == FILE_NAME {
                if entry.metadata()?.len() > MAX_BYTES { bail!("retained proof exceeds collection bound"); }
                let envelope: Envelope = serde_json::from_slice(&fs::read(&path)?)?;
                retained.extend(envelope.body.derivative_inventory.into_iter().map(|m| m.sha256));
            }
        }
        Ok(())
    }
    scan(root, &objects, &mut retained)?;
    let mut removed = 0;
    for entry in fs::read_dir(&objects)? {
        let entry = entry?; let name = entry.file_name().to_string_lossy().into_owned();
        if name.len() == 64 && entry.file_type()?.is_file() && !retained.contains(&name) {
            fs::remove_file(entry.path())?;
            match fs::remove_file(objects.join(".receipts").join(&name)) { Ok(()) => {}, Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}, Err(e) => return Err(e.into()) }
            removed += 1;
        }
    }
    Ok(removed)
}
