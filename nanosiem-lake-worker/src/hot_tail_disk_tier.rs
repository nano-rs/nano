// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2694: the encrypted, persistent DISK tier of the serving hot tail.
//!
//! The RAM (tmpfs) tier in [`crate::hot_tail_cache`] keeps the newest signed
//! tail objects in plaintext so chDB can read them directly. When the tail
//! outgrows it, the next-newest objects are kept here, on a per-replica
//! PersistentVolume, so a long publication stall never makes older tail
//! events unsearchable and a restarted reader does not re-download them.
//!
//! The reader runs on shared, Spot-reclaimed nodes, so plaintext tenant bytes
//! must NEVER reach this volume:
//!
//! - Every object is sealed with AES-256-GCM in 1 MiB chunks as it is written.
//!   Plaintext exists only in memory (the chunk buffer) and, at query time, in
//!   the tmpfs staging area (see [`crate::hot_tail_slow_path`]).
//! - The key is a per-tenant 32-byte data key that the platform keeps in a
//!   Kubernetes Secret (mounted from tmpfs by the kubelet). The reader reads
//!   it once at start into zeroizing memory and never writes or logs it.
//!   Deleting the Secret crypto-shreds every byte on the volume.
//! - Each file has a random 32-byte salt; its AEAD key is
//!   `HMAC-SHA256(tenant_key, "file" || salt)`, so chunk nonces (the chunk
//!   index) never repeat under one key. Every chunk's associated data binds
//!   the file header, the signed object identity (SHA-256, byte length,
//!   ETag), the chunk index and a last-chunk flag, so chunks cannot be
//!   reordered, truncated, spliced between files or relabelled.
//! - Admission hashes the plaintext while sealing and persists the file only
//!   when the length and SHA-256 match the signed manifest. Decryption hashes
//!   the plaintext again and refuses (and evicts) an object whose digest
//!   differs, BEFORE any byte is handed to chDB.
//! - Opening the tier runs a self-test that seals a random canary, scans the
//!   sealed bytes for it and refuses to start if the canary is visible. There
//!   is no configuration that disables encryption.
//!
//! A marker binds the volume to the tenant scope and the key fingerprint. A
//! different tenant, a rotated key or an unknown format purges the volume
//! before anything is served. After a restart the surviving objects are
//! addressed only through identities of the CURRENT signed manifest (see
//! [`DiskTier::retain_only`]); anything else is deleted.

use crate::generation::HotTailObject;
use aes_gcm::aead::{Aead, OsRng, Payload};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// The only accepted value of `NANO_LAKE_HOT_TAIL_DISK_CACHE_ENCRYPTION`.
pub const DISK_TIER_ENCRYPTION: &str = "aes-256-gcm-tenant-key-v1";

const MAGIC: &[u8; 8] = b"NHTDSK01";
const SALT_BYTES: usize = 32;
const HEADER_BYTES: usize = MAGIC.len() + SALT_BYTES + 4 + 8;
pub(crate) const CHUNK_BYTES: usize = 1024 * 1024;
const TAG_BYTES: usize = 16;
const OBJECT_SUFFIX: &str = ".nhtd";
const MARKER_FILE: &str = "tier.json";
const MARKER_FORMAT: u32 = 1;
const SELF_TEST_CANARY_PREFIX: &str = "NANO-HOT-TAIL-DISK-TIER-PLAINTEXT-CANARY-";

type HmacSha256 = Hmac<Sha256>;

/// The platform-held per-tenant data key. Never `Debug`-printed, never
/// written anywhere by the reader, zeroized when dropped.
pub struct DiskTierKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for DiskTierKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DiskTierKey(<redacted>)")
    }
}

impl DiskTierKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Read a 32-byte key encoded as 64 lowercase/uppercase hex characters or
    /// as standard base64. Anything else is refused: a short or empty key
    /// would silently weaken every object on the volume.
    pub fn from_file(path: &Path) -> Result<Self> {
        let raw = Zeroizing::new(
            std::fs::read(path)
                .with_context(|| format!("read hot-tail disk-tier key {}", path.display()))?,
        );
        let text = std::str::from_utf8(&raw)
            .context("hot-tail disk-tier key is not UTF-8 text")?
            .trim();
        let decoded = Zeroizing::new(if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
            hex::decode(text).context("hot-tail disk-tier key hex is invalid")?
        } else {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .context("hot-tail disk-tier key must be 32 bytes as hex or base64")?
        });
        let bytes: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("hot-tail disk-tier key must decode to exactly 32 bytes"))?;
        if bytes.iter().all(|byte| *byte == 0) {
            bail!("hot-tail disk-tier key is all zeroes");
        }
        Ok(Self::from_bytes(bytes))
    }

    fn derive(&self, label: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
        derive_key(&self.0, label, parts)
    }
}

fn derive_key(key: &[u8; 32], label: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(b"nano.hot-tail.disk-tier.v1\0");
    mac.update(label);
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// Deployment contract for the disk tier. All four variables are set
/// together or not at all; there is no unencrypted mode.
#[derive(Clone, Debug)]
pub struct DiskTierSettings {
    pub directory: PathBuf,
    pub max_bytes: u64,
    pub key_file: PathBuf,
}

impl DiskTierSettings {
    pub fn from_env() -> Result<Option<Self>> {
        let directory = non_empty_env("NANO_LAKE_HOT_TAIL_DISK_CACHE_DIR");
        let max_bytes = non_empty_env("NANO_LAKE_HOT_TAIL_DISK_CACHE_BYTES");
        let key_file = non_empty_env("NANO_LAKE_HOT_TAIL_DISK_CACHE_KEY_FILE");
        let encryption = non_empty_env("NANO_LAKE_HOT_TAIL_DISK_CACHE_ENCRYPTION");
        Self::parse(directory, max_bytes, key_file, encryption)
    }

    fn parse(
        directory: Option<String>,
        max_bytes: Option<String>,
        key_file: Option<String>,
        encryption: Option<String>,
    ) -> Result<Option<Self>> {
        match (directory, max_bytes, key_file, encryption) {
            (None, None, None, None) => Ok(None),
            (Some(directory), Some(max_bytes), Some(key_file), Some(encryption)) => {
                if encryption != DISK_TIER_ENCRYPTION {
                    bail!(
                        "NANO_LAKE_HOT_TAIL_DISK_CACHE_ENCRYPTION must be {DISK_TIER_ENCRYPTION}; \
                         the disk tier never runs unencrypted"
                    );
                }
                let directory = PathBuf::from(directory);
                let key_file = PathBuf::from(key_file);
                if !directory.is_absolute() || !key_file.is_absolute() {
                    bail!("hot-tail disk-tier directory and key file must be absolute paths");
                }
                let max_bytes = max_bytes
                    .parse::<u64>()
                    .ok()
                    .filter(|bytes| *bytes > 0)
                    .context("NANO_LAKE_HOT_TAIL_DISK_CACHE_BYTES must be positive")?;
                Ok(Some(Self {
                    directory,
                    max_bytes,
                    key_file,
                }))
            }
            (_, _, None, _) | (_, _, _, None) => bail!(
                "the hot-tail disk tier refuses to run unencrypted: set \
                 NANO_LAKE_HOT_TAIL_DISK_CACHE_KEY_FILE and \
                 NANO_LAKE_HOT_TAIL_DISK_CACHE_ENCRYPTION={DISK_TIER_ENCRYPTION}"
            ),
            _ => bail!(
                "NANO_LAKE_HOT_TAIL_DISK_CACHE_DIR, NANO_LAKE_HOT_TAIL_DISK_CACHE_BYTES, \
                 NANO_LAKE_HOT_TAIL_DISK_CACHE_KEY_FILE and \
                 NANO_LAKE_HOT_TAIL_DISK_CACHE_ENCRYPTION must be set together"
            ),
        }
    }

    /// `scope` is the immutable tenant identity the tier is bound to.
    pub fn open(&self, scope: &str) -> Result<Arc<DiskTier>> {
        let key = DiskTierKey::from_file(&self.key_file)?;
        DiskTier::open(&self.directory, self.max_bytes, &key, scope)
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// The signed identity a disk-tier object is addressed and authenticated by.
#[derive(Clone, Copy, Debug)]
pub struct DiskObjectIdentity<'a> {
    pub sha256: &'a str,
    pub size_bytes: u64,
    pub etag: Option<&'a str>,
}

impl<'a> DiskObjectIdentity<'a> {
    pub fn of(object: &'a HotTailObject) -> Result<Self> {
        let sha256 = object
            .sha256
            .as_deref()
            .filter(|digest| valid_sha256(digest))
            .context("disk-tier object has no valid signed SHA-256")?;
        if object.size_bytes == 0 {
            bail!("disk-tier object has no signed byte length");
        }
        Ok(Self {
            sha256,
            size_bytes: object.size_bytes,
            etag: object.etag.as_deref(),
        })
    }

    fn aad_prefix(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(128);
        for part in [
            self.sha256.as_bytes(),
            &self.size_bytes.to_be_bytes(),
            self.etag.unwrap_or("").as_bytes(),
        ] {
            output.extend_from_slice(&(part.len() as u64).to_be_bytes());
            output.extend_from_slice(part);
        }
        output
    }
}

/// Typed "this object is not on the disk tier" so callers fall through to
/// the verified R2 read-through instead of treating it as a fault.
#[derive(Debug)]
pub struct DiskTierMiss;

impl std::fmt::Display for DiskTierMiss {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("hot-tail object is not on the disk tier")
    }
}

impl std::error::Error for DiskTierMiss {}

#[derive(Clone, Debug)]
struct DiskEntry {
    stored_bytes: u64,
    last_used: u64,
}

#[derive(Default, Debug)]
struct DiskIndex {
    entries: BTreeMap<String, DiskEntry>,
    reserved: u64,
}

impl DiskIndex {
    fn stored(&self) -> u64 {
        self.entries.values().map(|entry| entry.stored_bytes).sum()
    }
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
struct TierMarker {
    format: u32,
    encryption: String,
    scope_sha256: String,
    key_fingerprint: String,
}

pub struct DiskTier {
    root: PathBuf,
    objects: PathBuf,
    max_bytes: u64,
    tenant_key: Zeroizing<[u8; 32]>,
    index: Mutex<DiskIndex>,
    clock: AtomicU64,
}

impl std::fmt::Debug for DiskTier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiskTier")
            .field("root", &self.root)
            .field("max_bytes", &self.max_bytes)
            .finish_non_exhaustive()
    }
}

/// Ciphertext bytes of one sealed object (header + payload + one tag per chunk).
pub fn sealed_len(plaintext_bytes: u64) -> u64 {
    let chunks = plaintext_bytes.div_ceil(CHUNK_BYTES as u64).max(1);
    HEADER_BYTES as u64 + plaintext_bytes + chunks * TAG_BYTES as u64
}

impl DiskTier {
    pub fn open(root: &Path, max_bytes: u64, key: &DiskTierKey, scope: &str) -> Result<Arc<Self>> {
        if !root.is_absolute() || max_bytes == 0 || scope.is_empty() {
            bail!("hot-tail disk-tier path, byte bound or tenant scope is invalid");
        }
        create_private_dir(root)?;
        let objects = root.join("objects");
        create_private_dir(&objects)?;
        let tenant_key = key.derive(b"tenant", &[scope.as_bytes()]);
        let tier = Self {
            root: root.to_path_buf(),
            objects,
            max_bytes,
            tenant_key,
            index: Mutex::new(DiskIndex::default()),
            clock: AtomicU64::new(1),
        };
        let expected = TierMarker {
            format: MARKER_FORMAT,
            encryption: DISK_TIER_ENCRYPTION.to_string(),
            scope_sha256: hex::encode(Sha256::digest(scope.as_bytes())),
            key_fingerprint: hex::encode(*derive_key(&tier.tenant_key, b"fingerprint", &[])),
        };
        let marker_path = root.join(MARKER_FILE);
        let current = std::fs::read(&marker_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<TierMarker>(&bytes).ok());
        if current.as_ref() != Some(&expected) {
            // A different tenant, a rotated/shredded key or an unknown format:
            // nothing here can be decrypted or trusted. Remove it all first.
            let removed = purge_directory(&tier.objects)?;
            if current.is_some() || removed > 0 {
                tracing::warn!(
                    removed,
                    "hot-tail disk tier bound to another tenant, key or format; purged"
                );
            }
            write_atomically(&marker_path, &serde_json::to_vec(&expected)?)?;
        }
        tier.self_test()?;
        tier.load_index()?;
        Ok(Arc::new(tier))
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    pub fn stored_bytes(&self) -> u64 {
        self.index.lock().expect("disk-tier index").stored()
    }

    pub fn object_count(&self) -> usize {
        self.index.lock().expect("disk-tier index").entries.len()
    }

    pub fn contains(&self, identity: DiskObjectIdentity<'_>) -> bool {
        let name = self.object_name(identity);
        self.index
            .lock()
            .expect("disk-tier index")
            .entries
            .contains_key(&name)
    }

    /// Delete every object whose identity is not in `wanted`. Run against the
    /// CURRENT signed manifest after a restart and before each fill, so a
    /// surviving volume never serves an object the manifest no longer names.
    pub fn retain_only<'a>(
        &self,
        wanted: impl IntoIterator<Item = DiskObjectIdentity<'a>>,
    ) -> Result<usize> {
        let wanted: BTreeSet<String> = wanted
            .into_iter()
            .map(|identity| self.object_name(identity))
            .collect();
        let mut index = self.index.lock().expect("disk-tier index");
        let doomed: Vec<String> = index
            .entries
            .keys()
            .filter(|name| !wanted.contains(*name))
            .cloned()
            .collect();
        for name in &doomed {
            remove_if_present(&self.object_path(name))?;
            index.entries.remove(name);
        }
        Ok(doomed.len())
    }

    /// Start sealing one object. The byte bound is enforced here, before any
    /// write, and nothing is evicted implicitly: the filler decides which
    /// objects the tier holds (see [`Self::retain_only`]).
    pub fn begin(&self, identity: DiskObjectIdentity<'_>) -> Result<DiskTierWriter<'_>> {
        let name = self.object_name(identity);
        let needed = sealed_len(identity.size_bytes);
        {
            let mut index = self.index.lock().expect("disk-tier index");
            if index.stored().saturating_add(index.reserved).saturating_add(needed) > self.max_bytes {
                bail!(DiskTierFull {
                    needed,
                    stored: index.stored(),
                    max_bytes: self.max_bytes,
                });
            }
            index.reserved += needed;
        }
        let reservation = Reservation { tier: self, bytes: needed };
        let mut salt = [0_u8; SALT_BYTES];
        OsRng.fill_bytes(&mut salt);
        let header = header(&salt, identity.size_bytes);
        let file_key = derive_key(&self.tenant_key, b"file", &[&salt]);
        let cipher = Aes256Gcm::new_from_slice(&*file_key).expect("AES-256 key is 32 bytes");
        let mut temporary = tempfile::Builder::new()
            .prefix(".tmp-")
            .tempfile_in(&self.objects)
            .context("create hot-tail disk-tier temporary")?;
        temporary.write_all(&header)?;
        let mut aad_prefix = header.to_vec();
        aad_prefix.extend_from_slice(&identity.aad_prefix());
        Ok(DiskTierWriter {
            tier: self,
            name,
            expected_sha256: identity.sha256.to_string(),
            expected_bytes: identity.size_bytes,
            temporary: Some(temporary),
            cipher,
            aad_prefix,
            buffer: Zeroizing::new(Vec::with_capacity(CHUNK_BYTES)),
            chunk_index: 0,
            hasher: Sha256::new(),
            plaintext_bytes: 0,
            _reservation: reservation,
        })
    }

    /// Seal an already-local plaintext file (a RAM-tier object being demoted).
    /// The bytes are re-hashed against the signed identity while sealing.
    pub fn admit_from_file(&self, identity: DiskObjectIdentity<'_>, source: &Path) -> Result<()> {
        let mut file = File::open(source)
            .with_context(|| format!("open disk-tier source {}", source.display()))?;
        let mut writer = self.begin(identity)?;
        let mut buffer = Zeroizing::new(vec![0_u8; CHUNK_BYTES]);
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            writer.update(&buffer[..read])?;
        }
        writer.finish()
    }

    /// Decrypt one object into `destination` (a tmpfs staging file), hashing
    /// the plaintext as it goes. A digest, length or authentication failure
    /// evicts the object and returns an error; the caller must discard the
    /// destination. Returns [`DiskTierMiss`] when the object is absent.
    pub fn decrypt_into(&self, identity: DiskObjectIdentity<'_>, destination: &mut File) -> Result<()> {
        let name = self.object_name(identity);
        let path = self.object_path(&name);
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.index.lock().expect("disk-tier index").entries.remove(&name);
                return Err(anyhow::Error::new(DiskTierMiss));
            }
            Err(error) => return Err(error.into()),
        };
        match self.decrypt_stream(identity, &mut file, destination) {
            Ok(()) => {
                let tick = self.clock.fetch_add(1, Ordering::Relaxed);
                if let Some(entry) = self
                    .index
                    .lock()
                    .expect("disk-tier index")
                    .entries
                    .get_mut(&name)
                {
                    entry.last_used = tick;
                }
                Ok(())
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "hot-tail disk-tier object failed its integrity fence; evicted"
                );
                let _ = remove_if_present(&path);
                self.index.lock().expect("disk-tier index").entries.remove(&name);
                Err(error)
            }
        }
    }

    fn decrypt_stream(
        &self,
        identity: DiskObjectIdentity<'_>,
        source: &mut File,
        destination: &mut File,
    ) -> Result<()> {
        let mut header_bytes = [0_u8; HEADER_BYTES];
        source
            .read_exact(&mut header_bytes)
            .context("read disk-tier header")?;
        if &header_bytes[..MAGIC.len()] != MAGIC {
            bail!("disk-tier object has an unknown format");
        }
        let salt: [u8; SALT_BYTES] = header_bytes[MAGIC.len()..MAGIC.len() + SALT_BYTES]
            .try_into()
            .expect("salt slice");
        let chunk_bytes = u32::from_le_bytes(
            header_bytes[MAGIC.len() + SALT_BYTES..MAGIC.len() + SALT_BYTES + 4]
                .try_into()
                .expect("chunk slice"),
        ) as usize;
        let plaintext_bytes = u64::from_le_bytes(
            header_bytes[MAGIC.len() + SALT_BYTES + 4..]
                .try_into()
                .expect("length slice"),
        );
        if chunk_bytes != CHUNK_BYTES || plaintext_bytes != identity.size_bytes {
            bail!("disk-tier object header differs from its signed identity");
        }
        let file_key = derive_key(&self.tenant_key, b"file", &[&salt]);
        let cipher = Aes256Gcm::new_from_slice(&*file_key).expect("AES-256 key is 32 bytes");
        let mut aad_prefix = header_bytes.to_vec();
        aad_prefix.extend_from_slice(&identity.aad_prefix());
        let chunks = plaintext_bytes.div_ceil(CHUNK_BYTES as u64);
        let mut sealed = vec![0_u8; CHUNK_BYTES + TAG_BYTES];
        let mut hasher = Sha256::new();
        for chunk_index in 0..chunks {
            let plain_len = (plaintext_bytes - chunk_index * CHUNK_BYTES as u64)
                .min(CHUNK_BYTES as u64) as usize;
            let sealed_chunk = &mut sealed[..plain_len + TAG_BYTES];
            source
                .read_exact(sealed_chunk)
                .context("disk-tier object is truncated")?;
            let last = chunk_index + 1 == chunks;
            let plaintext = Zeroizing::new(
                cipher
                    .decrypt(
                        Nonce::from_slice(&chunk_nonce(chunk_index)),
                        Payload {
                            msg: sealed_chunk,
                            aad: &chunk_aad(&aad_prefix, chunk_index, last),
                        },
                    )
                    .map_err(|_| anyhow::anyhow!("disk-tier chunk failed authentication"))?,
            );
            hasher.update(&*plaintext);
            destination
                .write_all(&plaintext)
                .context("write staged hot-tail plaintext")?;
        }
        let mut trailing = [0_u8; 1];
        if source.read(&mut trailing)? != 0 {
            bail!("disk-tier object has trailing bytes");
        }
        if hex::encode(hasher.finalize()) != identity.sha256 {
            bail!("disk-tier object failed its signed SHA-256 fence");
        }
        Ok(())
    }

    fn object_name(&self, identity: DiskObjectIdentity<'_>) -> String {
        hex::encode(*derive_key(
            &self.tenant_key,
            b"name",
            &[
                identity.sha256.as_bytes(),
                &identity.size_bytes.to_be_bytes(),
                identity.etag.unwrap_or("").as_bytes(),
            ],
        ))
    }

    fn object_path(&self, name: &str) -> PathBuf {
        self.objects.join(format!("{name}{OBJECT_SUFFIX}"))
    }

    fn load_index(&self) -> Result<()> {
        let mut index = self.index.lock().expect("disk-tier index");
        index.entries.clear();
        for entry in std::fs::read_dir(&self.objects)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if file_type.is_symlink() || file_type.is_dir() {
                bail!("hot-tail disk tier contains an unexpected entry {}", path.display());
            }
            match name.strip_suffix(OBJECT_SUFFIX) {
                Some(stem) if stem.len() == 64 && stem.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    index.entries.insert(
                        stem.to_string(),
                        DiskEntry {
                            stored_bytes: entry.metadata()?.len(),
                            last_used: 0,
                        },
                    );
                }
                // Interrupted writes and anything unrecognized are removed:
                // they are ciphertext at worst, but never served.
                _ => remove_if_present(&path)?,
            }
        }
        // A shrunk bound after a restart: drop the least recently used.
        while index.stored() > self.max_bytes {
            let Some(name) = index
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(name, _)| name.clone())
            else {
                break;
            };
            remove_if_present(&self.object_path(&name))?;
            index.entries.remove(&name);
        }
        Ok(())
    }

    /// Refuse to run if a sealed object would expose plaintext on the volume.
    fn self_test(&self) -> Result<()> {
        let mut nonce = [0_u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let canary = format!("{SELF_TEST_CANARY_PREFIX}{}", hex::encode(nonce)).repeat(64);
        let digest = hex::encode(Sha256::digest(canary.as_bytes()));
        let identity = DiskObjectIdentity {
            sha256: &digest,
            size_bytes: canary.len() as u64,
            etag: Some("self-test"),
        };
        let path = self.root.join(".self-test");
        let result = (|| {
            let mut salt = [0_u8; SALT_BYTES];
            OsRng.fill_bytes(&mut salt);
            let header = header(&salt, identity.size_bytes);
            let file_key = derive_key(&self.tenant_key, b"file", &[&salt]);
            let cipher = Aes256Gcm::new_from_slice(&*file_key).expect("AES-256 key is 32 bytes");
            let mut aad_prefix = header.to_vec();
            aad_prefix.extend_from_slice(&identity.aad_prefix());
            let mut sealed = header.to_vec();
            sealed.extend(
                cipher
                    .encrypt(
                        Nonce::from_slice(&chunk_nonce(0)),
                        Payload {
                            msg: canary.as_bytes(),
                            aad: &chunk_aad(&aad_prefix, 0, true),
                        },
                    )
                    .map_err(|_| anyhow::anyhow!("disk-tier self-test seal failed"))?,
            );
            write_atomically(&path, &sealed)?;
            let on_disk = std::fs::read(&path)?;
            if contains_subslice(&on_disk, SELF_TEST_CANARY_PREFIX.as_bytes()) {
                bail!("hot-tail disk tier self-test found plaintext on the volume; refusing to start");
            }
            let mut plaintext = tempfile::tempfile()?;
            self.decrypt_stream(identity, &mut File::open(&path)?, &mut plaintext)?;
            Ok(())
        })();
        let _ = std::fs::remove_file(&path);
        result.context("hot-tail disk tier encryption self-test")
    }
}

/// Typed "the disk tier has no room" (the fill stops; nothing is evicted
/// implicitly, so newer objects are never displaced by older ones).
#[derive(Debug)]
pub struct DiskTierFull {
    pub needed: u64,
    pub stored: u64,
    pub max_bytes: u64,
}

impl std::fmt::Display for DiskTierFull {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "hot-tail disk tier needs {} more bytes with {} stored, above its {} byte bound",
            self.needed, self.stored, self.max_bytes
        )
    }
}

impl std::error::Error for DiskTierFull {}

struct Reservation<'a> {
    tier: &'a DiskTier,
    bytes: u64,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        let mut index = self.tier.index.lock().expect("disk-tier index");
        index.reserved = index.reserved.saturating_sub(self.bytes);
    }
}

/// Streaming sealer for one object. Plaintext is buffered in zeroizing memory
/// one chunk at a time; only ciphertext is written. Dropping the writer
/// without [`DiskTierWriter::finish`] deletes the partial ciphertext.
pub struct DiskTierWriter<'a> {
    tier: &'a DiskTier,
    name: String,
    expected_sha256: String,
    expected_bytes: u64,
    temporary: Option<tempfile::NamedTempFile>,
    cipher: Aes256Gcm,
    aad_prefix: Vec<u8>,
    buffer: Zeroizing<Vec<u8>>,
    chunk_index: u64,
    hasher: Sha256,
    plaintext_bytes: u64,
    _reservation: Reservation<'a>,
}

impl std::fmt::Debug for DiskTierWriter<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiskTierWriter")
            .field("expected_bytes", &self.expected_bytes)
            .field("plaintext_bytes", &self.plaintext_bytes)
            .finish_non_exhaustive()
    }
}

impl DiskTierWriter<'_> {
    pub fn update(&mut self, mut bytes: &[u8]) -> Result<()> {
        self.plaintext_bytes = self
            .plaintext_bytes
            .checked_add(bytes.len() as u64)
            .context("disk-tier byte count overflow")?;
        if self.plaintext_bytes > self.expected_bytes {
            bail!("hot-tail object exceeded its signed byte length");
        }
        self.hasher.update(bytes);
        while !bytes.is_empty() {
            let room = CHUNK_BYTES - self.buffer.len();
            let take = room.min(bytes.len());
            self.buffer.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            let sealed_through = (self.chunk_index + 1) * CHUNK_BYTES as u64;
            if self.buffer.len() == CHUNK_BYTES && sealed_through < self.expected_bytes {
                self.seal(false)?;
            }
        }
        Ok(())
    }

    fn seal(&mut self, last: bool) -> Result<()> {
        let sealed = self
            .cipher
            .encrypt(
                Nonce::from_slice(&chunk_nonce(self.chunk_index)),
                Payload {
                    msg: &self.buffer,
                    aad: &chunk_aad(&self.aad_prefix, self.chunk_index, last),
                },
            )
            .map_err(|_| anyhow::anyhow!("disk-tier chunk seal failed"))?;
        self.temporary
            .as_mut()
            .expect("writer temporary is live until finish")
            .write_all(&sealed)
            .context("write hot-tail disk-tier ciphertext")?;
        self.buffer.clear();
        self.chunk_index += 1;
        Ok(())
    }

    /// Persist only if the plaintext matched the signed length and SHA-256.
    pub fn finish(mut self) -> Result<()> {
        if self.plaintext_bytes != self.expected_bytes
            || hex::encode(std::mem::take(&mut self.hasher).finalize()) != self.expected_sha256
        {
            bail!("hot-tail object failed its signed length or SHA-256 fence; not admitted to disk");
        }
        self.seal(true)?;
        let temporary = self.temporary.take().expect("writer temporary is live until finish");
        temporary.as_file().sync_all()?;
        let path = self.tier.object_path(&self.name);
        match temporary.persist_noclobber(&path) {
            Ok(_) => {}
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.error.into()),
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
        let stored_bytes = std::fs::metadata(&path)?.len();
        let tick = self.tier.clock.fetch_add(1, Ordering::Relaxed);
        self.tier.index.lock().expect("disk-tier index").entries.insert(
            self.name.clone(),
            DiskEntry {
                stored_bytes,
                last_used: tick,
            },
        );
        Ok(())
    }
}

fn header(salt: &[u8; SALT_BYTES], plaintext_bytes: u64) -> [u8; HEADER_BYTES] {
    let mut header = [0_u8; HEADER_BYTES];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    header[MAGIC.len()..MAGIC.len() + SALT_BYTES].copy_from_slice(salt);
    header[MAGIC.len() + SALT_BYTES..MAGIC.len() + SALT_BYTES + 4]
        .copy_from_slice(&(CHUNK_BYTES as u32).to_le_bytes());
    header[MAGIC.len() + SALT_BYTES + 4..].copy_from_slice(&plaintext_bytes.to_le_bytes());
    header
}

fn chunk_nonce(chunk_index: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..8].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

fn chunk_aad(prefix: &[u8], chunk_index: u64, last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(prefix.len() + 9);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.push(u8::from(last));
    aad
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn create_private_dir(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("hot-tail disk-tier path {} is not a directory", path.display())
        }
        // An existing directory (the PV mount) is narrowed to the reader.
        Ok(_) => std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restrict {} to the reader", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .with_context(|| format!("create {}", path.display())),
        Err(error) => Err(error.into()),
    }
}

fn purge_directory(path: &Path) -> Result<usize> {
    let mut removed = 0;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
        removed += 1;
    }
    Ok(removed)
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("disk-tier file has no parent")?;
    let mut temporary = tempfile::Builder::new().prefix(".tmp-").tempfile_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("persist {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Seek;

    const SCOPE: &str = "7d7f1c2e-0000-4000-8000-000000000001";

    fn key(byte: u8) -> DiskTierKey {
        DiskTierKey::from_bytes([byte; 32])
    }

    /// Parquet-sized plaintext with a recognizable marker repeated through
    /// every chunk, spanning a chunk boundary.
    fn plaintext(marker: &str, bytes: usize) -> Vec<u8> {
        marker.as_bytes().iter().copied().cycle().take(bytes).collect()
    }

    fn object(bytes: &[u8]) -> HotTailObject {
        HotTailObject {
            source_uri: "s3://bucket/t/data/tail/o.parquet".to_string(),
            version_id: "v".to_string(),
            etag: Some("\"etag-1\"".to_string()),
            size_bytes: bytes.len() as u64,
            rows: 1,
            sha256: Some(hex::encode(Sha256::digest(bytes))),
            min_time_ms: Some(1),
            max_time_ms: Some(2),
            committed: false,
        }
    }

    fn admit(tier: &DiskTier, bytes: &[u8]) -> HotTailObject {
        let object = object(bytes);
        let mut writer = tier.begin(DiskObjectIdentity::of(&object).unwrap()).unwrap();
        // Uneven writes, as an R2 byte stream delivers them.
        for piece in bytes.chunks(333_333) {
            writer.update(piece).unwrap();
        }
        writer.finish().unwrap();
        object
    }

    fn read_back(tier: &DiskTier, object: &HotTailObject) -> Result<Vec<u8>> {
        let mut output = tempfile::tempfile().unwrap();
        tier.decrypt_into(DiskObjectIdentity::of(object).unwrap(), &mut output)?;
        output.rewind().unwrap();
        let mut bytes = Vec::new();
        output.read_to_end(&mut bytes).unwrap();
        Ok(bytes)
    }

    fn every_file_bytes(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut output = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(directory) = stack.pop() {
            for entry in std::fs::read_dir(&directory).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    stack.push(entry.path());
                } else {
                    output.push((entry.path(), std::fs::read(entry.path()).unwrap()));
                }
            }
        }
        output
    }

    #[test]
    fn no_plaintext_byte_pattern_reaches_the_volume() {
        let directory = tempfile::tempdir().unwrap();
        let tier = DiskTier::open(directory.path(), 64 << 20, &key(1), SCOPE).unwrap();
        let marker = "TENANT-SECRET-EVENT-MARKER-4b1d";
        let bytes = plaintext(marker, 2 * CHUNK_BYTES + 12_345);
        let object = admit(&tier, &bytes);
        let files = every_file_bytes(directory.path());
        assert!(files.iter().any(|(path, _)| path.extension().is_some_and(|e| e == "nhtd")));
        for (path, contents) in &files {
            assert!(
                !contains_subslice(contents, marker.as_bytes()),
                "plaintext marker found in {}",
                path.display()
            );
            assert!(!contains_subslice(contents, &bytes[..64]));
        }
        assert_eq!(read_back(&tier, &object).unwrap(), bytes);
    }

    #[test]
    fn data_is_unreadable_after_the_key_is_dropped_or_rotated() {
        let directory = tempfile::tempdir().unwrap();
        let bytes = plaintext("event", CHUNK_BYTES + 7);
        let object = {
            let tier = DiskTier::open(directory.path(), 64 << 20, &key(1), SCOPE).unwrap();
            admit(&tier, &bytes)
        };
        // Restart with the SAME key: the verified object survives.
        let tier = DiskTier::open(directory.path(), 64 << 20, &key(1), SCOPE).unwrap();
        assert!(tier.contains(DiskObjectIdentity::of(&object).unwrap()));
        assert_eq!(read_back(&tier, &object).unwrap(), bytes);
        drop(tier);
        // A shredded/rotated key cannot decrypt the old ciphertext even when
        // the files are forced back under its name: authentication fails
        // and the object is evicted instead of served.
        let old_files = every_file_bytes(&directory.path().join("objects"));
        let rotated = DiskTier::open(directory.path(), 64 << 20, &key(2), SCOPE).unwrap();
        assert_eq!(rotated.object_count(), 0, "a rotated key purges the volume");
        let name = rotated.object_name(DiskObjectIdentity::of(&object).unwrap());
        std::fs::write(rotated.object_path(&name), &old_files[0].1).unwrap();
        rotated.load_index().unwrap();
        let error = read_back(&rotated, &object).unwrap_err().to_string();
        assert!(error.contains("authentication"), "{error}");
        assert!(!rotated.contains(DiskObjectIdentity::of(&object).unwrap()));
    }

    #[test]
    fn another_tenant_scope_purges_and_cannot_read() {
        let directory = tempfile::tempdir().unwrap();
        let tier = DiskTier::open(directory.path(), 64 << 20, &key(1), SCOPE).unwrap();
        let object = admit(&tier, &plaintext("a", 4096));
        drop(tier);
        let other = DiskTier::open(directory.path(), 64 << 20, &key(1), "other-tenant").unwrap();
        assert_eq!(other.object_count(), 0);
        assert!(read_back(&other, &object).unwrap_err().downcast_ref::<DiskTierMiss>().is_some());
    }

    #[test]
    fn a_wrong_digest_is_never_admitted_and_tampering_is_refused_on_decrypt() {
        let directory = tempfile::tempdir().unwrap();
        let tier = DiskTier::open(directory.path(), 64 << 20, &key(1), SCOPE).unwrap();
        let bytes = plaintext("x", CHUNK_BYTES * 2);
        let mut forged = object(&bytes);
        forged.sha256 = Some("0".repeat(64));
        let mut writer = tier.begin(DiskObjectIdentity::of(&forged).unwrap()).unwrap();
        writer.update(&bytes).unwrap();
        assert!(writer.finish().unwrap_err().to_string().contains("SHA-256"));
        assert_eq!(tier.object_count(), 0);
        assert_eq!(tier.stored_bytes(), 0);
        assert!(every_file_bytes(&directory.path().join("objects")).is_empty());

        let object = admit(&tier, &bytes);
        let name = tier.object_name(DiskObjectIdentity::of(&object).unwrap());
        let path = tier.object_path(&name);
        let mut sealed = std::fs::read(&path).unwrap();
        let middle = sealed.len() / 2;
        sealed[middle] ^= 0x01;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, &sealed).unwrap();
        assert!(read_back(&tier, &object).is_err());
        assert!(!path.exists(), "a tampered object is evicted");
    }

    #[test]
    fn identity_binding_refuses_a_relabelled_or_truncated_object() {
        let directory = tempfile::tempdir().unwrap();
        let tier = DiskTier::open(directory.path(), 64 << 20, &key(1), SCOPE).unwrap();
        let first = admit(&tier, &plaintext("first", CHUNK_BYTES + 10));
        let second_bytes = plaintext("second", CHUNK_BYTES + 10);
        let second = object(&second_bytes);
        let first_name = tier.object_name(DiskObjectIdentity::of(&first).unwrap());
        let second_name = tier.object_name(DiskObjectIdentity::of(&second).unwrap());
        // Put the first object's ciphertext under the second's name.
        std::fs::copy(tier.object_path(&first_name), tier.object_path(&second_name)).unwrap();
        tier.load_index().unwrap();
        assert!(read_back(&tier, &second).is_err());
        // Truncate the first object by one tag.
        let path = tier.object_path(&first_name);
        let sealed = std::fs::read(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, &sealed[..sealed.len() - TAG_BYTES]).unwrap();
        assert!(read_back(&tier, &first).is_err());
    }

    #[test]
    fn the_byte_bound_is_enforced_before_any_write_and_retain_only_revalidates() {
        let directory = tempfile::tempdir().unwrap();
        let one = sealed_len(10_000);
        let tier = DiskTier::open(directory.path(), one * 2, &key(1), SCOPE).unwrap();
        let a = admit(&tier, &plaintext("a", 10_000));
        let b = admit(&tier, &plaintext("b", 10_000));
        let c = object(&plaintext("c", 10_000));
        let error = tier.begin(DiskObjectIdentity::of(&c).unwrap()).unwrap_err();
        assert!(error.downcast_ref::<DiskTierFull>().is_some(), "{error}");
        assert_eq!(tier.stored_bytes(), one * 2);
        // After a restart the current manifest names only `b`.
        drop(tier);
        let tier = DiskTier::open(directory.path(), one * 2, &key(1), SCOPE).unwrap();
        assert_eq!(tier.object_count(), 2);
        assert_eq!(
            tier.retain_only([DiskObjectIdentity::of(&b).unwrap()]).unwrap(),
            1
        );
        assert!(!tier.contains(DiskObjectIdentity::of(&a).unwrap()));
        assert!(tier.contains(DiskObjectIdentity::of(&b).unwrap()));
        assert_eq!(read_back(&tier, &b).unwrap(), plaintext("b", 10_000));
    }

    #[test]
    fn settings_refuse_to_run_unencrypted() {
        let some = |value: &str| Some(value.to_string());
        assert!(DiskTierSettings::parse(None, None, None, None).unwrap().is_none());
        for (key_file, encryption) in [
            (None, some(DISK_TIER_ENCRYPTION)),
            (some("/run/secrets/k"), None),
            (some("/run/secrets/k"), some("none")),
            (some("/run/secrets/k"), some("memory-ephemeral")),
        ] {
            let error = DiskTierSettings::parse(
                some("/var/lib/nano-hot-tail-disk"),
                some("1073741824"),
                key_file,
                encryption,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("unencrypted"), "{error}");
        }
        assert!(DiskTierSettings::parse(
            some("/var/lib/nano-hot-tail-disk"),
            some("1073741824"),
            some("/run/secrets/k"),
            some(DISK_TIER_ENCRYPTION),
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn key_files_must_hold_exactly_32_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        std::fs::write(&path, hex::encode([9_u8; 32])).unwrap();
        assert!(DiskTierKey::from_file(&path).is_ok());
        use base64::Engine as _;
        std::fs::write(&path, base64::engine::general_purpose::STANDARD.encode([9_u8; 32])).unwrap();
        assert!(DiskTierKey::from_file(&path).is_ok());
        for bad in ["", "short", &hex::encode([9_u8; 16]), &hex::encode([0_u8; 32])] {
            std::fs::write(&path, bad).unwrap();
            assert!(DiskTierKey::from_file(&path).is_err(), "{bad}");
        }
        assert_eq!(format!("{:?}", key(3)), "DiskTierKey(<redacted>)");
    }

    #[test]
    fn interrupted_writes_leave_no_trace_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let tier = DiskTier::open(directory.path(), 64 << 20, &key(1), SCOPE).unwrap();
        let bytes = plaintext("partial", CHUNK_BYTES * 3);
        let object = object(&bytes);
        let mut writer = tier.begin(DiskObjectIdentity::of(&object).unwrap()).unwrap();
        writer.update(&bytes[..CHUNK_BYTES * 2]).unwrap();
        drop(writer);
        assert_eq!(tier.stored_bytes(), 0);
        assert!(every_file_bytes(&directory.path().join("objects")).is_empty());
    }
}
