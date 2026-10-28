// SPDX-License-Identifier: AGPL-3.0-or-later
//! Portable signed enrichment feed bundle (NAN-4759 / sovereign C19).
//!
//! Hosted cells load platform feeds from a `.nanpfb` (`NANPFB01`) node bundle
//! built from signed R2 manifests. Those manifests bind the bucket and the
//! publisher fencing epoch, so they cannot be re-hosted. This module defines
//! the location-independent artifact that sovereign and open-core installs
//! fetch online or import from a file:
//!
//! ```text
//! offset 0   8 bytes   magic "NANFEED1"
//! offset 8   u64 LE    descriptor length L (1..=64 KiB)
//! offset 16  L bytes   SignedDescriptor JSON
//! 16 + L     N bytes   payload: one unmodified NANPFB01 platform bundle,
//!                      N == descriptor.payload.bytes, sha256 == payload.sha256
//! EOF        exactly at 16 + L + N
//! ```
//!
//! The descriptor names no bucket, path, endpoint, epoch or tenant. Its
//! signature (Ed25519 over a domain-separated canonical JSON encoding) covers
//! the payload digest, every feed's license terms and expiry, and the NOTICE
//! text, so the same bytes verify from R2, a CDN, a USB stick or a customer
//! mirror. Trust comes only from [`KeyRing::production`], a compiled-in key
//! list: rotation adds a key in one release, signs with it in the next and
//! drops the old one later. There is no environment or config override.
//!
//! A consumer installs a bundle by:
//! 1. [`verify_file`] (signature, structure, licenses, NOTICE, payload hash
//!    and NANPFB01 header consistency, streamed — never fully buffered);
//! 2. [`VerifiedBundle::accept_after`] against the installed descriptor
//!    (refuses rollback, same-sequence substitution, per-feed revision
//!    regression and an entirely expired bundle);
//! 3. [`VerifiedBundle::install_payload`] into the cell's `platform_bundle_dir`
//!    as `platform-<sha256>.nanpfb` (0444, re-hashed while copying), then a
//!    tenant policy whose grants come from the descriptor (lake-worker
//!    `TenantPlatformPolicy::from_portable`). The cell load path is the same
//!    one hosted uses.
//!
//! Only feeds in [`PORTABLE_FEEDS`] may appear. Synthient (contracted,
//! non-redistributable) is refused by both the descriptor and payload checks.
//! Expiry stops new stamping only; values already stamped stay.

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

/// Container magic of the portable artifact.
pub const MAGIC: &[u8; 8] = b"NANFEED1";
/// `descriptor.format`.
pub const FORMAT: &str = "nano/feed-bundle";
/// `descriptor.format_version`. A new version is a new, explicitly refused
/// format for older consumers (`deny_unknown_fields` everywhere).
pub const FORMAT_VERSION: u32 = 1;
/// The only payload format: the hosted node bundle, byte for byte.
pub const PAYLOAD_FORMAT: &str = "NANPFB01";
/// Conventional file extension of the container.
pub const FILE_EXTENSION: &str = "nanfeed";
/// Signature domain; distinct from the hosted artifact-manifest domain, so a
/// signature over one can never be replayed as the other.
const DOMAIN: &[u8] = b"nano/feed-bundle/descriptor/v1\0";
const MAX_DESCRIPTOR_BYTES: u64 = 64 * 1024;
/// Same bound the cell applies to a NANPFB01 file.
pub const MAX_PAYLOAD_BYTES: u64 = 512 * 1024 * 1024;
use super::nanpfb::MAGIC as NANPFB_MAGIC;
const NANPFB_MAX_HEADER: usize = 16_384;

/// Production verification keys: `(key id, Ed25519 public key hex)`. The
/// portable descriptor is signed by the platform feed signing key under its
/// own domain. Rotate by appending, never by configuration.
const PRODUCTION_KEYS: &[(&str, &str)] = &[(
    "platform-ad038f5046fb19e51bf310e0",
    "54022ca65c169394eb131164b596d5b1265670289959604405be7da64dcdc516",
)];

/// Redistribution terms of a feed that may leave hosted infrastructure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortableFeedTerms {
    pub feed_id: &'static str,
    /// SPDX identifier, or `LicenseRef-*` when the source has no SPDX license.
    pub license_id: &'static str,
    /// Attribution that must travel with the data.
    pub notice: &'static str,
    /// Upper bound of `hard_expiry - upstream_at` (the hosted manifest bound).
    pub max_validity_seconds: i64,
}

/// The closed set of portable feeds. Anything else (notably Synthient) is
/// refused.
pub const PORTABLE_FEEDS: [PortableFeedTerms; 3] = [
    PortableFeedTerms {
        feed_id: "ipinfo_lite",
        license_id: "CC-BY-SA-4.0",
        notice: "IP geolocation and ASN data: IPinfo Lite by IPinfo (https://ipinfo.io), \
licensed under the Creative Commons Attribution-ShareAlike 4.0 International License \
(CC BY-SA 4.0, https://creativecommons.org/licenses/by-sa/4.0/). The IPinfo Lite MMDB is \
redistributed unmodified inside this bundle.",
        max_validity_seconds: 14 * 86_400,
    },
    PortableFeedTerms {
        feed_id: "threatfox",
        license_id: "CC0-1.0",
        notice: "Threat indicators: ThreatFox by abuse.ch (https://threatfox.abuse.ch), \
released under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/).",
        max_validity_seconds: 86_400,
    },
    PortableFeedTerms {
        feed_id: "tor_exit_nodes",
        license_id: "LicenseRef-tor-bulk-exit-list-public",
        notice: "Tor exit addresses: The Tor Project bulk exit list \
(https://check.torproject.org/torbulkexitlist), public data.",
        max_validity_seconds: 86_400,
    },
];

pub fn portable_terms(feed_id: &str) -> Option<&'static PortableFeedTerms> {
    PORTABLE_FEEDS.iter().find(|t| t.feed_id == feed_id)
}

/// The exact NOTICE a bundle carrying `feeds` must ship (sorted feed order).
pub fn notice_for<'a>(feeds: impl IntoIterator<Item = &'a str>) -> Result<String> {
    let mut ids: Vec<&str> = feeds.into_iter().collect();
    ids.sort_unstable();
    ids.dedup();
    let mut out = String::from(
        "NOTICE: nano enrichment feed bundle. Third-party data, redistributed under the \
terms below.\n",
    );
    for id in ids {
        let terms = portable_terms(id).ok_or(BundleError::Invalid("feed is not portable"))?;
        out.push_str(&format!(
            "\n[{}] {}\n{}\n",
            terms.feed_id, terms.license_id, terms.notice
        ));
    }
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("invalid feed bundle: {0}")]
    Invalid(&'static str),
    #[error("feed bundle signer is not trusted")]
    UntrustedSigner,
    #[error("feed bundle signature is invalid")]
    BadSignature,
    #[error("feed bundle payload differs from its descriptor: {0}")]
    PayloadMismatch(&'static str),
    #[error("feed bundle is older than the installed bundle: {0}")]
    Rollback(&'static str),
    #[error("every feed in the bundle has expired")]
    Expired,
    #[error("feed bundle io: {0}")]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, BundleError>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    /// Always [`PAYLOAD_FORMAT`].
    pub format: String,
    /// Lowercase hex SHA-256 of the payload bytes; also the cell file name
    /// `platform-<sha256>.nanpfb` and the tenant policy `bundle_sha256`.
    pub sha256: String,
    pub bytes: u64,
}

/// One feed's provenance and terms. Mirrors the hosted signed manifest it was
/// built from, minus every location field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedEntry {
    /// Hosted feed revision; equals the NANPFB01 header `feed_revisions`.
    pub revision: i64,
    /// Fixed per feed by [`PORTABLE_FEEDS`].
    pub license_id: String,
    /// Reviewed terms revision the hosted publisher recorded.
    pub terms_revision: String,
    /// Upstream snapshot time.
    pub upstream_at: DateTime<Utc>,
    /// When the hosted publisher fetched and validated the feed.
    pub produced_at: DateTime<Utc>,
    /// After this instant the feed must not stamp new events; equals the
    /// NANPFB01 header `feed_valid_until`.
    pub hard_expiry: DateTime<Utc>,
    pub row_count: u64,
    /// SHA-256 of the hosted source artifact (MMDB or packed feed).
    pub source_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub format: String,
    pub format_version: u32,
    /// Strictly increasing per publication (the hosted publisher uses the
    /// bundle `produced_at` in Unix milliseconds). Consumers refuse rollback.
    pub sequence: u64,
    pub produced_at: DateTime<Utc>,
    pub payload: Payload,
    pub feeds: BTreeMap<String, FeedEntry>,
    /// Exactly [`notice_for`] the feed set; installers write it beside the
    /// bundle and surfaces that show the data show it.
    pub notice: String,
    pub signer_key_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDescriptor {
    pub descriptor: Descriptor,
    /// Lowercase hex Ed25519 signature over `DOMAIN || canonical(descriptor)`.
    pub signature: String,
}

/// Freshness of one installed feed, for operator/UI display.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FeedFreshness {
    pub feed_id: String,
    pub revision: i64,
    pub upstream_at: DateTime<Utc>,
    pub hard_expiry: DateTime<Utc>,
    pub age_seconds: i64,
    pub expired: bool,
}

/// Trusted verification keys.
#[derive(Clone, Debug)]
pub struct KeyRing(BTreeMap<String, VerifyingKey>);
impl KeyRing {
    /// The compiled-in production ring. No override exists.
    pub fn production() -> Self {
        Self::from_hex(PRODUCTION_KEYS).expect("compiled-in feed bundle keys are valid")
    }
    pub fn from_hex(keys: &[(&str, &str)]) -> Result<Self> {
        let mut ring = BTreeMap::new();
        for (id, hex_key) in keys {
            let bytes: [u8; 32] = hex::decode(hex_key)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or(BundleError::Invalid("verification key"))?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| BundleError::Invalid("verification key"))?;
            if !key_id_ok(id) || ring.insert((*id).to_owned(), key).is_some() {
                return Err(BundleError::Invalid("verification key id"));
            }
        }
        if ring.is_empty() {
            return Err(BundleError::Invalid("empty key ring"));
        }
        Ok(Self(ring))
    }
    pub fn contains(&self, id: &str, key: &VerifyingKey) -> bool {
        self.0.get(id) == Some(key)
    }
}

fn key_id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn sha_ok(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Descriptor {
    fn canonical(&self) -> Result<Vec<u8>> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(
            serde_json::to_vec(self).map_err(|_| BundleError::Invalid("descriptor encoding"))?,
        );
        Ok(bytes)
    }

    /// Sign as `key_id`. The descriptor must already be structurally valid.
    pub fn sign(mut self, key_id: &str, key: &SigningKey) -> Result<SignedDescriptor> {
        self.signer_key_id = key_id.to_owned();
        self.validate()?;
        let signature = hex::encode(key.sign(&self.canonical()?).to_bytes());
        Ok(SignedDescriptor {
            descriptor: self,
            signature,
        })
    }

    /// Structural, license and NOTICE validation (no signature, no clock).
    pub fn validate(&self) -> Result<()> {
        let bad = BundleError::Invalid;
        if self.format != FORMAT || self.format_version != FORMAT_VERSION {
            return Err(bad("unsupported format"));
        }
        if self.sequence == 0 || self.sequence > i64::MAX as u64 {
            return Err(bad("sequence"));
        }
        if self.payload.format != PAYLOAD_FORMAT
            || !sha_ok(&self.payload.sha256)
            || !(16..=MAX_PAYLOAD_BYTES).contains(&self.payload.bytes)
        {
            return Err(bad("payload"));
        }
        if self.feeds.is_empty() || self.feeds.len() > PORTABLE_FEEDS.len() {
            return Err(bad("feed set"));
        }
        if !key_id_ok(&self.signer_key_id) {
            return Err(bad("signer key id"));
        }
        for (id, feed) in &self.feeds {
            let terms = portable_terms(id).ok_or(bad("feed is not portable"))?;
            let terms_ok = !feed.terms_revision.is_empty()
                && feed.terms_revision.len() <= 128
                && feed.terms_revision.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
                });
            let max_expiry = feed
                .upstream_at
                .checked_add_signed(Duration::seconds(terms.max_validity_seconds));
            if feed.license_id != terms.license_id
                || !terms_ok
                || feed.revision <= 0
                || feed.upstream_at > feed.produced_at
                || feed.produced_at > self.produced_at
                || feed.hard_expiry <= feed.produced_at
                || max_expiry.is_none_or(|limit| feed.hard_expiry > limit)
                || feed.row_count > 10_000_000
                || (feed.row_count == 0 && id != "threatfox")
                || !sha_ok(&feed.source_sha256)
            {
                return Err(bad("feed entry"));
            }
        }
        if self.notice != notice_for(self.feeds.keys().map(String::as_str))? {
            return Err(bad("notice"));
        }
        Ok(())
    }

    pub fn freshness(&self, now: DateTime<Utc>) -> Vec<FeedFreshness> {
        self.feeds
            .iter()
            .map(|(id, f)| FeedFreshness {
                feed_id: id.clone(),
                revision: f.revision,
                upstream_at: f.upstream_at,
                hard_expiry: f.hard_expiry,
                age_seconds: (now - f.upstream_at).num_seconds().max(0),
                expired: f.hard_expiry <= now,
            })
            .collect()
    }
}

impl SignedDescriptor {
    /// Verify signature against `ring`, then structure. Returns the descriptor.
    pub fn verify(&self, ring: &KeyRing) -> Result<&Descriptor> {
        let d = &self.descriptor;
        let key = ring
            .0
            .get(&d.signer_key_id)
            .ok_or(BundleError::UntrustedSigner)?;
        let raw: [u8; 64] = hex::decode(&self.signature)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(BundleError::BadSignature)?;
        if self.signature != hex::encode(raw) {
            return Err(BundleError::BadSignature);
        }
        key.verify_strict(&d.canonical()?, &Signature::from_bytes(&raw))
            .map_err(|_| BundleError::BadSignature)?;
        d.validate()?;
        Ok(d)
    }

    /// Parse and verify a standalone descriptor (the distribution
    /// `current.json`), bounded.
    pub fn from_json(bytes: &[u8], ring: &KeyRing) -> Result<Self> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_DESCRIPTOR_BYTES {
            return Err(BundleError::Invalid("descriptor size"));
        }
        let signed: Self =
            serde_json::from_slice(bytes).map_err(|_| BundleError::Invalid("descriptor json"))?;
        signed.verify(ring)?;
        Ok(signed)
    }
}

/// A container whose signature, descriptor and payload all verified.
/// Its signed state is immutable outside this module:
///
/// ```compile_fail
/// use nanosiem_core::platform_enrichment::portable::VerifiedBundle;
/// fn replace_digest(mut verified: VerifiedBundle) {
///     verified.signed.descriptor.payload.sha256 = "../outside".into();
/// }
/// ```
#[derive(Clone, Debug)]
pub struct VerifiedBundle {
    signed: SignedDescriptor,
    payload_offset: u64,
}

impl VerifiedBundle {
    /// The verified descriptor and signature, for persisting installed state.
    pub fn signed(&self) -> &SignedDescriptor {
        &self.signed
    }

    pub fn descriptor(&self) -> &Descriptor {
        &self.signed.descriptor
    }

    /// Install policy: refuse a bundle that is older than, or a substitute
    /// for, the installed one, that regresses any feed revision, or whose
    /// feeds have all expired. A partly expired bundle installs; its expired
    /// feeds simply stamp nothing new.
    pub fn accept_after(&self, installed: Option<&Descriptor>, now: DateTime<Utc>) -> Result<()> {
        let d = self.descriptor();
        if d.feeds.values().all(|f| f.hard_expiry <= now) {
            return Err(BundleError::Expired);
        }
        if let Some(prev) = installed {
            if d.sequence < prev.sequence {
                return Err(BundleError::Rollback("sequence"));
            }
            if d.sequence == prev.sequence && d != prev {
                return Err(BundleError::Rollback("same sequence, different content"));
            }
            for (id, old) in &prev.feeds {
                if d.feeds
                    .get(id)
                    .is_some_and(|new| new.revision < old.revision)
                {
                    return Err(BundleError::Rollback("feed revision"));
                }
            }
        }
        Ok(())
    }

    /// Copy the payload of the verified container at `source` into `dir` as
    /// `platform-<sha256>.nanpfb` (read-only, single link, fsynced), hashing
    /// the bytes actually written. Idempotent when the same file exists.
    #[cfg(unix)]
    pub fn install_payload(&self, source: &Path, dir: &Path) -> Result<PathBuf> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let payload = &self.descriptor().payload;
        let target = dir.join(format!("platform-{}.nanpfb", payload.sha256));
        match open_regular(&target) {
            Ok(file) => {
                let meta = file.metadata()?;
                if meta.nlink() != 1 || meta.mode() & 0o222 != 0 {
                    return Err(BundleError::Invalid(
                        "existing payload is not a sealed file",
                    ));
                }
                let (digest, len) = hash_stream(file, MAX_PAYLOAD_BYTES + 1)?;
                if digest != payload.sha256 || len != payload.bytes {
                    return Err(BundleError::PayloadMismatch("existing payload"));
                }
                return Ok(target);
            }
            Err(BundleError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut file = open_regular(source)?;
        file.seek(SeekFrom::Start(self.payload_offset))?;
        let mut staged = tempfile::NamedTempFile::new_in(dir)?;
        let mut hasher = Sha256::new();
        let mut remaining = payload.bytes;
        let mut buffer = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let want = remaining.min(buffer.len() as u64) as usize;
            let n = file.read(&mut buffer[..want])?;
            if n == 0 {
                return Err(BundleError::PayloadMismatch("truncated while installing"));
            }
            hasher.update(&buffer[..n]);
            staged.as_file_mut().write_all(&buffer[..n])?;
            remaining -= n as u64;
        }
        if hex::encode(hasher.finalize()) != payload.sha256 {
            return Err(BundleError::PayloadMismatch("changed while installing"));
        }
        staged.as_file().sync_all()?;
        staged
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o444))?;
        staged.as_file().sync_all()?;
        staged
            .persist_noclobber(&target)
            .map_err(|e| BundleError::Io(e.error))?;
        File::open(dir)?.sync_all()?;
        Ok(target)
    }
}

fn open_regular(path: &Path) -> Result<File> {
    #[cfg(not(unix))]
    {
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.file_type().is_file() {
            return Err(BundleError::Invalid("not a regular file"));
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(BundleError::Invalid("not a regular file"));
    }
    Ok(file)
}

fn hash_stream(mut reader: impl Read, cap: u64) -> Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > cap {
            return Err(BundleError::Invalid("size bound"));
        }
        hasher.update(&buffer[..n]);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

/// The NANPFB01 header must state exactly the signed feed set, revisions and
/// expiries, carry no prefix (premium) section, and account for every byte.
fn check_payload_header(prefix: &[u8], d: &Descriptor) -> Result<()> {
    let bad = BundleError::PayloadMismatch;
    if prefix.len() < 16 || &prefix[..8] != NANPFB_MAGIC {
        return Err(bad("payload magic"));
    }
    let len = u64::from_le_bytes(prefix[8..16].try_into().expect("8 bytes")) as usize;
    if len == 0 || len > NANPFB_MAX_HEADER || prefix.len() < 16 + len {
        return Err(bad("payload header length"));
    }
    let h: super::nanpfb::Header =
        serde_json::from_slice(&prefix[16..16 + len]).map_err(|_| bad("payload header"))?;
    let revisions: BTreeMap<&str, i64> = d
        .feeds
        .iter()
        .map(|(k, f)| (k.as_str(), f.revision))
        .collect();
    let expiries: BTreeMap<&str, DateTime<Utc>> = d
        .feeds
        .iter()
        .map(|(k, f)| (k.as_str(), f.hard_expiry))
        .collect();
    if h.feed_revisions
        .iter()
        .map(|(k, v)| (k.as_str(), *v))
        .ne(revisions)
    {
        return Err(bad("feed revisions"));
    }
    if h.feed_valid_until
        .iter()
        .map(|(k, v)| (k.as_str(), *v))
        .ne(expiries)
    {
        return Err(bad("feed expiries"));
    }
    if h.prefix_len != 0 || h.prefix_rows != 0 {
        return Err(bad("premium prefix section"));
    }
    if (h.mmdb_len > 0) != d.feeds.contains_key("ipinfo_lite") {
        return Err(bad("ipinfo section"));
    }
    let total = (16 + len as u64)
        .checked_add(h.mmdb_len as u64)
        .and_then(|t| t.checked_add(h.ioc_len as u64));
    if total != Some(d.payload.bytes) {
        return Err(bad("payload length"));
    }
    Ok(())
}

/// Read the container header from `reader` (positioned at 0). Returns the
/// signed descriptor (unverified) and the payload offset.
fn read_head(reader: &mut impl Read) -> Result<(SignedDescriptor, u64)> {
    let mut head = [0u8; 16];
    reader
        .read_exact(&mut head)
        .map_err(|_| BundleError::Invalid("truncated header"))?;
    if &head[..8] != MAGIC {
        return Err(BundleError::Invalid("magic"));
    }
    let len = u64::from_le_bytes(head[8..16].try_into().expect("8 bytes"));
    if len == 0 || len > MAX_DESCRIPTOR_BYTES {
        return Err(BundleError::Invalid("descriptor length"));
    }
    let mut json = vec![0u8; len as usize];
    reader
        .read_exact(&mut json)
        .map_err(|_| BundleError::Invalid("truncated descriptor"))?;
    let signed =
        serde_json::from_slice(&json).map_err(|_| BundleError::Invalid("descriptor json"))?;
    Ok((signed, 16 + len))
}

/// Verify a container from any reader: signature first, then the payload is
/// streamed once (hash, exact length, header consistency, EOF).
pub fn verify_reader(mut reader: impl Read, ring: &KeyRing) -> Result<VerifiedBundle> {
    let (signed, payload_offset) = read_head(&mut reader)?;
    let d = signed.verify(ring)?.clone();
    let mut hasher = Sha256::new();
    const HEAD: usize = 16 + NANPFB_MAX_HEADER;
    let mut head = Vec::with_capacity(HEAD);
    let mut buffer = vec![0u8; 64 * 1024];
    let mut seen = 0u64;
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        seen += n as u64;
        if seen > d.payload.bytes {
            return Err(BundleError::PayloadMismatch("trailing bytes"));
        }
        let take = n.min(HEAD - head.len());
        head.extend_from_slice(&buffer[..take]);
        hasher.update(&buffer[..n]);
    }
    if seen != d.payload.bytes {
        return Err(BundleError::PayloadMismatch("payload length"));
    }
    if hex::encode(hasher.finalize()) != d.payload.sha256 {
        return Err(BundleError::PayloadMismatch("payload digest"));
    }
    check_payload_header(&head, &d)?;
    Ok(VerifiedBundle {
        signed,
        payload_offset,
    })
}

/// Verify a container file (regular file, not a symlink).
pub fn verify_file(path: &Path, ring: &KeyRing) -> Result<VerifiedBundle> {
    let file = open_regular(path)?;
    if file.metadata()?.len() > MAX_PAYLOAD_BYTES + 16 + MAX_DESCRIPTOR_BYTES {
        return Err(BundleError::Invalid("container size"));
    }
    verify_reader(std::io::BufReader::with_capacity(64 * 1024, file), ring)
}

/// Publisher side: wrap an existing NANPFB01 `payload` file into a signed
/// container at `out` (written to a sibling temp file, fsynced, renamed),
/// then re-verify the written file against `ring`. `ring` must contain the
/// signing key, so a release can never be signed by a key consumers lack.
#[allow(clippy::too_many_arguments)]
pub fn seal(
    payload: &Path,
    feeds: BTreeMap<String, FeedEntry>,
    sequence: u64,
    produced_at: DateTime<Utc>,
    key_id: &str,
    key: &SigningKey,
    ring: &KeyRing,
    out: &Path,
) -> Result<SignedDescriptor> {
    if !ring.contains(key_id, &key.verifying_key()) {
        return Err(BundleError::UntrustedSigner);
    }
    let (sha256, bytes) = hash_stream(open_regular(payload)?, MAX_PAYLOAD_BYTES)?;
    let notice = notice_for(feeds.keys().map(String::as_str))?;
    let signed = Descriptor {
        format: FORMAT.into(),
        format_version: FORMAT_VERSION,
        sequence,
        produced_at,
        payload: Payload {
            format: PAYLOAD_FORMAT.into(),
            sha256,
            bytes,
        },
        feeds,
        notice,
        signer_key_id: String::new(),
    }
    .sign(key_id, key)?;
    let json = serde_json::to_vec(&signed).map_err(|_| BundleError::Invalid("descriptor json"))?;
    if json.len() as u64 > MAX_DESCRIPTOR_BYTES {
        return Err(BundleError::Invalid("descriptor size"));
    }
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    {
        let file = staged.as_file_mut();
        file.write_all(MAGIC)?;
        file.write_all(&(json.len() as u64).to_le_bytes())?;
        file.write_all(&json)?;
        let mut source = open_regular(payload)?;
        let copied = std::io::copy(&mut (&mut source).take(bytes + 1), file)?;
        if copied != bytes {
            return Err(BundleError::PayloadMismatch(
                "payload changed while sealing",
            ));
        }
        file.sync_all()?;
    }
    let verified = verify_file(staged.path(), ring)?;
    if verified.signed != signed {
        return Err(BundleError::PayloadMismatch("sealed container differs"));
    }
    staged.persist(out).map_err(|e| BundleError::Io(e.error))?;
    File::open(parent)?.sync_all()?;
    Ok(signed)
}

#[cfg(feature = "enterprise")]
impl FeedEntry {
    /// Project a verified hosted manifest onto its portable entry. The
    /// manifest's bucket, object key and fencing epoch are dropped.
    pub fn from_hosted_manifest(m: &super::publisher::Manifest) -> Result<(String, Self)> {
        let terms =
            portable_terms(&m.feed_id).ok_or(BundleError::Invalid("feed is not portable"))?;
        Ok((
            m.feed_id.clone(),
            Self {
                revision: m.revision,
                license_id: terms.license_id.into(),
                terms_revision: m.license_revision.clone(),
                upstream_at: m.upstream_at,
                produced_at: m.fetched_at,
                hard_expiry: m.valid_until,
                row_count: m.row_count,
                source_sha256: m.digest.clone(),
            },
        ))
    }
}

#[cfg(test)]
#[path = "portable_tests.rs"]
mod tests;
