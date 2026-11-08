// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signed content bundle contract (`NANCONT1`, NAN-4955), a sibling of the
//! platform feed bundle (`NANFEED1`, NAN-4759) built from the same pieces.
//!
//! ```text
//! offset 0   8 bytes   magic "NANCONT1"
//! offset 8   u64 LE    descriptor length L (1..=64 KiB)
//! offset 16  L bytes   SignedContentDescriptor JSON
//! 16 + L     N bytes   payload: the deterministic gzip'd tar of the channel
//!                      tree (see `tree`), N == payload.bytes,
//!                      sha256 == payload.sha256
//! EOF        exactly at 16 + L + N
//! ```
//!
//! The descriptor names the channel, its upstream commit, the payload digest
//! and the tree digest, and nothing about where the bytes are stored, so the
//! same file verifies from R2, a mirror or a USB stick. The signature is
//! Ed25519 over `DOMAIN || canonical JSON`; the domain differs from the feed
//! bundle's, so neither signature can be replayed as the other even though
//! both may be made by the same platform key.
//!
//! Trust comes only from [`content_key_ring`], a compiled-in list. Release
//! images trust the production list only. The owned acceptance run uses an
//! explicitly non-shippable debug cfg whose roots are absent from the public
//! mirror; the build script rejects that cfg in every release profile.

#[cfg(all(nano_content_acceptance, not(debug_assertions)))]
compile_error!("nano_content_acceptance is forbidden in release builds");

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::channels::{self, Route};
use super::tree::{self, Files, TreeSummary};
use crate::platform_enrichment::portable::KeyRing;

pub const MAGIC: &[u8; 8] = b"NANCONT1";
pub const FORMAT: &str = "nano/content-bundle";
pub const FORMAT_VERSION: u32 = 1;
pub const PAYLOAD_FORMAT: &str = "tar+gzip";
pub const FILE_EXTENSION: &str = "nancontent";
const DOMAIN: &[u8] = b"nano/content-bundle/descriptor/v1\0";
pub const MAX_DESCRIPTOR_BYTES: u64 = 64 * 1024;
pub const MAX_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_CONTAINER_BYTES: u64 = MAX_PAYLOAD_BYTES + 16 + MAX_DESCRIPTOR_BYTES;
/// HTTP admission includes a small framing allowance while the staged bundle
/// itself remains capped at [`MAX_CONTAINER_BYTES`]. Edge proxies must admit
/// at least this many bytes so the application can return its audited 413.
pub const MAX_IMPORT_HTTP_BYTES: u64 = MAX_CONTAINER_BYTES + 64 * 1024;
/// Validity of a published descriptor. The app re-seals an unchanged
/// payload under a fresh descriptor well before this (weekly), so an online
/// install that is handed an old descriptor is being frozen on stale content.
pub const VALIDITY: Duration = Duration::days(30);

/// Production content signing keys: `(key id, Ed25519 public key hex)`.
///
/// NAN-4955 proposal (pending Dan): the platform feed key that every shipped
/// install already trusts for `NANFEED1`, used here under the content domain.
/// Rotate by appending, never by configuration.
const CONTENT_PRODUCTION_KEYS: &[(&str, &str)] = &[(
    "platform-ad038f5046fb19e51bf310e0",
    "54022ca65c169394eb131164b596d5b1265670289959604405be7da64dcdc516",
)];

/// The compiled-in trust ring for content bundles.
pub fn content_key_ring() -> KeyRing {
    #[cfg(nano_content_acceptance)]
    {
        let all: Vec<(&str, &str)> = CONTENT_PRODUCTION_KEYS
            .iter()
            .chain(super::content_acceptance_root::KEYS.iter())
            .copied()
            .collect();
        KeyRing::from_hex(&all).expect("compiled-in content keys are valid")
    }
    #[cfg(not(nano_content_acceptance))]
    {
        KeyRing::from_hex(CONTENT_PRODUCTION_KEYS).expect("compiled-in content keys are valid")
    }
}

/// The production entries only (the app signs production bundles only with
/// a key in this list).
pub fn production_key_ring() -> KeyRing {
    KeyRing::from_hex(CONTENT_PRODUCTION_KEYS).expect("compiled-in content keys are valid")
}

/// `production` or `production+acceptance` (status display).
pub fn trust_label() -> &'static str {
    if cfg!(nano_content_acceptance) {
        "production+acceptance"
    } else {
        "production"
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ContentError {
    #[error("invalid content bundle: {0}")]
    Invalid(String),
    #[error("content bundle signer is not trusted")]
    UntrustedSigner,
    #[error("content bundle signature is invalid")]
    BadSignature,
    #[error("content bundle payload differs from its descriptor: {0}")]
    PayloadMismatch(&'static str),
    #[error("content bundle is older than the installed one: {0}")]
    Rollback(&'static str),
    #[error("content bundle expired at {0}")]
    Expired(DateTime<Utc>),
    #[error(transparent)]
    Tree(#[from] tree::TreeError),
}

pub type Result<T> = std::result::Result<T, ContentError>;

fn invalid(m: &str) -> ContentError {
    ContentError::Invalid(m.to_string())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// Upstream git commit SHA-1 (40 hex). Empty for non-git channels.
    pub commit: String,
    pub committed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ContentPayload {
    pub format: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ContentTree {
    pub files: u64,
    pub bytes: u64,
    /// SHA-256 over `path \0 git-blob-sha1 \n` in path order.
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ContentDescriptor {
    pub format: String,
    pub format_version: u32,
    pub channel: String,
    /// `owner/repo` (empty for non-git channels); must equal the registry.
    pub repo: String,
    pub branch: String,
    pub route: Route,
    /// Strictly increasing per channel (the app uses produced_at ms).
    pub sequence: u64,
    pub produced_at: DateTime<Utc>,
    pub hard_expiry: DateTime<Utc>,
    pub upstream: Upstream,
    pub payload: ContentPayload,
    pub tree: ContentTree,
    pub signer_key_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedContentDescriptor {
    pub descriptor: ContentDescriptor,
    /// Lowercase hex Ed25519 signature over `DOMAIN || canonical(descriptor)`.
    pub signature: String,
}

fn sha_ok(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
fn commit_ok(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
fn key_id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

impl ContentDescriptor {
    fn canonical(&self) -> Result<Vec<u8>> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| invalid("descriptor encoding"))?);
        Ok(bytes)
    }

    pub fn sign(mut self, key_id: &str, key: &SigningKey) -> Result<SignedContentDescriptor> {
        self.signer_key_id = key_id.to_owned();
        self.validate()?;
        let signature = hex::encode(key.sign(&self.canonical()?).to_bytes());
        Ok(SignedContentDescriptor { descriptor: self, signature })
    }

    /// Structural validation (no signature, no clock): the channel must be a
    /// registry entry and every field must agree with it.
    pub fn validate(&self) -> Result<()> {
        if self.format != FORMAT || self.format_version != FORMAT_VERSION {
            return Err(invalid("unsupported format"));
        }
        let channel = channels::by_id(&self.channel).ok_or_else(|| invalid("unknown channel"))?;
        if self.repo != channel.repo || self.branch != channel.branch || self.route != channel.route {
            return Err(invalid("channel fields differ from the registry"));
        }
        if self.sequence == 0 || self.sequence > i64::MAX as u64 {
            return Err(invalid("sequence"));
        }
        if self.hard_expiry <= self.produced_at || self.hard_expiry > self.produced_at + VALIDITY {
            return Err(invalid("hard expiry"));
        }
        let git = !channel.repo.is_empty();
        if (git && !commit_ok(&self.upstream.commit)) || (!git && !self.upstream.commit.is_empty()) {
            return Err(invalid("upstream commit"));
        }
        if self.upstream.committed_at > self.produced_at + Duration::minutes(10) {
            return Err(invalid("upstream time"));
        }
        if self.payload.format != PAYLOAD_FORMAT
            || !sha_ok(&self.payload.sha256)
            || !(20..=MAX_PAYLOAD_BYTES).contains(&self.payload.bytes)
        {
            return Err(invalid("payload"));
        }
        if !sha_ok(&self.tree.sha256)
            || self.tree.files == 0
            || self.tree.files > tree::MAX_FILES as u64
            || self.tree.bytes > tree::MAX_TREE_BYTES
        {
            return Err(invalid("tree"));
        }
        if !key_id_ok(&self.signer_key_id) {
            return Err(invalid("signer key id"));
        }
        Ok(())
    }
}

impl SignedContentDescriptor {
    /// Verify the signature against `ring`, then the structure.
    pub fn verify(&self, ring: &KeyRing) -> Result<&ContentDescriptor> {
        let d = &self.descriptor;
        let key = ring.key(&d.signer_key_id).ok_or(ContentError::UntrustedSigner)?;
        let raw: [u8; 64] = hex::decode(&self.signature)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(ContentError::BadSignature)?;
        if self.signature != hex::encode(raw) {
            return Err(ContentError::BadSignature);
        }
        key.verify_strict(&d.canonical()?, &Signature::from_bytes(&raw))
            .map_err(|_| ContentError::BadSignature)?;
        d.validate()?;
        Ok(d)
    }

    /// Parse and verify a standalone descriptor (`current.json`), bounded.
    pub fn from_json(bytes: &[u8], ring: &KeyRing) -> Result<Self> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_DESCRIPTOR_BYTES {
            return Err(invalid("descriptor size"));
        }
        let signed: Self = serde_json::from_slice(bytes).map_err(|_| invalid("descriptor json"))?;
        signed.verify(ring)?;
        Ok(signed)
    }
}

/// A container whose signature, payload digest and tree all verified, with
/// its unpacked files. Immutable outside this module.
#[derive(Debug, Clone)]
pub struct VerifiedContent {
    signed: SignedContentDescriptor,
    files: Files,
}

impl VerifiedContent {
    pub fn signed(&self) -> &SignedContentDescriptor {
        &self.signed
    }
    pub fn descriptor(&self) -> &ContentDescriptor {
        &self.signed.descriptor
    }
    pub fn files(&self) -> &Files {
        &self.files
    }

    /// Install policy against the installed descriptor of the same channel:
    /// refuses rollback, same-sequence substitution and (online) an expired
    /// descriptor. `allow_expired` is the offline import, where an air-gapped
    /// site legitimately imports late; rollback is refused either way.
    pub fn accept_after(
        &self,
        installed: Option<&ContentDescriptor>,
        now: DateTime<Utc>,
        allow_expired: bool,
    ) -> Result<()> {
        let d = self.descriptor();
        if !allow_expired && d.hard_expiry <= now {
            return Err(ContentError::Expired(d.hard_expiry));
        }
        if let Some(prev) = installed {
            if prev.channel != d.channel {
                return Err(invalid("bundle is for another channel"));
            }
            if d.sequence < prev.sequence {
                return Err(ContentError::Rollback("sequence"));
            }
            if d.sequence == prev.sequence && d != prev {
                return Err(ContentError::Rollback("same sequence, different content"));
            }
        }
        Ok(())
    }
}

/// Verify a whole container held in memory (content bundles are small and
/// bounded): magic, descriptor signature and structure, payload length and
/// digest, EOF, then unpack and check the tree digest and counts.
pub fn verify_bytes(bytes: &[u8], ring: &KeyRing) -> Result<VerifiedContent> {
    if bytes.len() as u64 > MAX_CONTAINER_BYTES {
        return Err(invalid("container size"));
    }
    if bytes.len() < 16 || &bytes[..8] != MAGIC {
        return Err(invalid("magic"));
    }
    let len = u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes"));
    if len == 0 || len > MAX_DESCRIPTOR_BYTES || (bytes.len() as u64) < 16 + len {
        return Err(invalid("descriptor length"));
    }
    let head = 16 + len as usize;
    let signed: SignedContentDescriptor =
        serde_json::from_slice(&bytes[16..head]).map_err(|_| invalid("descriptor json"))?;
    let d = signed.verify(ring)?.clone();
    let payload = &bytes[head..];
    if payload.len() as u64 != d.payload.bytes {
        return Err(ContentError::PayloadMismatch("payload length"));
    }
    if hex::encode(Sha256::digest(payload)) != d.payload.sha256 {
        return Err(ContentError::PayloadMismatch("payload digest"));
    }
    let files = tree::unpack(payload)?;
    let summary = tree::summarize(&files);
    if summary.files != d.tree.files || summary.bytes != d.tree.bytes || summary.sha256 != d.tree.sha256 {
        return Err(ContentError::PayloadMismatch("tree digest"));
    }
    Ok(VerifiedContent { signed, files })
}

/// Rebuild the verified view of an INSTALLED snapshot (its signature was
/// verified at install) from the stored descriptor and files, re-checking the
/// structure and the tree digest. Used to retry an apply that failed after
/// the snapshot committed, without downloading again (NAN-4955 review).
pub fn reverify_installed(signed: SignedContentDescriptor, files: Files) -> Result<VerifiedContent> {
    signed.descriptor.validate()?;
    let summary = tree::summarize(&files);
    let d = &signed.descriptor;
    if summary.files != d.tree.files || summary.bytes != d.tree.bytes || summary.sha256 != d.tree.sha256 {
        return Err(ContentError::PayloadMismatch("installed tree differs from its descriptor"));
    }
    Ok(VerifiedContent { signed, files })
}

/// What the signing side knows about a channel publication.
#[derive(Debug, Clone)]
pub struct SealInput<'a> {
    pub channel: &'a str,
    pub sequence: u64,
    pub produced_at: DateTime<Utc>,
    pub upstream: Upstream,
}

/// Signing side (the app, and test fixtures): sign `payload` (from [`tree::pack`]) for `input.channel` and
/// return the container bytes, re-verified against `ring`. `ring` must hold
/// the signing key, so nothing is ever published that consumers cannot
/// verify.
pub fn seal(
    input: SealInput<'_>,
    payload: &[u8],
    summary: &TreeSummary,
    key_id: &str,
    key: &SigningKey,
    ring: &KeyRing,
) -> Result<(SignedContentDescriptor, Vec<u8>)> {
    if !ring.contains(key_id, &key.verifying_key()) {
        return Err(ContentError::UntrustedSigner);
    }
    let channel = channels::by_id(input.channel).ok_or_else(|| invalid("unknown channel"))?;
    let signed = ContentDescriptor {
        format: FORMAT.into(),
        format_version: FORMAT_VERSION,
        channel: channel.id.into(),
        repo: channel.repo.into(),
        branch: channel.branch.into(),
        route: channel.route,
        sequence: input.sequence,
        produced_at: input.produced_at,
        hard_expiry: input.produced_at + VALIDITY,
        upstream: input.upstream,
        payload: ContentPayload {
            format: PAYLOAD_FORMAT.into(),
            sha256: hex::encode(Sha256::digest(payload)),
            bytes: payload.len() as u64,
        },
        tree: ContentTree {
            files: summary.files,
            bytes: summary.bytes,
            sha256: summary.sha256.clone(),
        },
        signer_key_id: String::new(),
    }
    .sign(key_id, key)?;
    let json = serde_json::to_vec(&signed).map_err(|_| invalid("descriptor json"))?;
    if json.len() as u64 > MAX_DESCRIPTOR_BYTES {
        return Err(invalid("descriptor size"));
    }
    let mut out = Vec::with_capacity(16 + json.len() + payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(json.len() as u64).to_le_bytes());
    out.extend_from_slice(&json);
    out.extend_from_slice(payload);
    let verified = verify_bytes(&out, ring)?;
    if verified.signed != signed {
        return Err(ContentError::PayloadMismatch("sealed container differs"));
    }
    Ok((signed, out))
}

/// Per-file git blob ids of a verified tree (what `GitHubClient` reports as
/// `TreeEntry.sha`).
pub fn blob_ids(files: &Files) -> BTreeMap<String, String> {
    files.iter().map(|(p, c)| (p.clone(), tree::git_blob_sha1(c))).collect()
}

#[cfg(test)]
#[path = "contract_tests.rs"]
mod tests;

/// Fixture signing for the consumer tests.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    pub(crate) use super::tests::{ring, sample_files};
    pub fn sealed(channel: &str, sequence: u64, produced_at: DateTime<Utc>) -> (SignedContentDescriptor, Vec<u8>) {
        super::tests::sealed(channel, sequence, produced_at, &sample_files())
    }
}
