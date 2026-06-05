// SPDX-License-Identifier: AGPL-3.0-or-later

//! Air-gapped signed bundle format + Ed25519 verification foundation (NAN-1202).
//!
//! Air-gapped nano deployments cannot reach the internet to pull parsers,
//! IP-enrichment databases (IPinfo Lite, ~400MB), IOC feeds, or license
//! refreshes. Instead an operator carries a **signed bundle** across the
//! gap on physical media. This module defines that bundle format and the
//! verification routine that every consumer (WS2 parsers, WS3 enrichment,
//! WS4 license) MUST run before trusting a payload.
//!
//! # Bundle layout
//!
//! A bundle is a gzip-compressed tar archive (`.tar.gz`) containing:
//!
//! ```text
//!   manifest.json   -- the [`BundleManifest`], canonically serialized (see below)
//!   manifest.sig    -- detached Ed25519 signature (64 raw bytes) over the
//!                       canonical manifest bytes
//!   <payload files> -- one entry per [`FileEntry`] in the manifest, each at
//!                       its declared `path`
//! ```
//!
//! `manifest.json` and `manifest.sig` MUST be the FIRST two entries in the
//! tar stream, in that order, so that verification can complete before any
//! (potentially huge) payload is read. The verifier enforces this ordering.
//!
//! # Canonical manifest serialization (THE SIGNING RULE)
//!
//! The signature is computed over the **canonical bytes** of the manifest,
//! NOT over whatever happens to be written to `manifest.json`. Both the
//! signer (WS1, TypeScript) and the verifier (this module) MUST produce the
//! identical byte sequence. The canonical form is:
//!
//! 1. Serialize [`BundleManifest`] to JSON with **lexicographically sorted
//!    object keys at every level**.
//! 2. **No insignificant whitespace**: no spaces after `:` or `,`, no
//!    newlines, no trailing newline. (Compact form.)
//! 3. UTF-8 encoding.
//! 4. Field semantics that must match exactly:
//!    - `bundle_type`   : snake_case string (`parsers`/`ip_enrichment`/`ioc`/`license`).
//!    - `schema_version`: integer.
//!    - `content_version`: string (caller-defined, e.g. a date or semver).
//!    - `generated_at`  : RFC3339 / ISO-8601 string, exactly as emitted.
//!    - `generator`     : free-form producer string.
//!    - `files`: array, **order preserved as given** (the array order is part
//!      of the signed content; do not sort entries). Each `FileEntry` =
//!      `{ "bytes": <u64>, "path": <string>, "sha256": <lowercase hex> }`.
//!
//! In Rust this canonical form is produced by [`BundleManifest::canonical_bytes`],
//! which uses `serde_json` with `BTreeMap`-backed sorting. The matching TS rule
//! is: `JSON.stringify` with recursively sorted keys and no spacing —
//! equivalently `json-stable-stringify` / `canonicalize`. See WS1.
//!
//! `sha256` values are lowercase hex of the raw payload bytes.
//!
//! # Embedded public key
//!
//! Verification uses a **build-time embedded** Ed25519 public key
//! ([`AIRGAP_BUNDLE_PUBLIC_KEY`]). The committed source carries only a clearly
//! marked **placeholder** generated for development/tests. In production the
//! real key is injected at build time by `build.rs` via the
//! `AIRGAP_BUNDLE_PUBLIC_KEY_HEX` environment variable (see the const's doc
//! comment for the exact mechanism). A consumer may also supply its own key via
//! [`verify_bundle_with_key`].
//!
//! # Streaming
//!
//! The IPinfo payload is ~400MB; verification must not buffer it in memory.
//! [`verify_bundle`] reads `manifest.json` + `manifest.sig` (both tiny, and
//! both bounded — see [`MAX_MANIFEST_BYTES`] / the signature cap — so a
//! malicious tar header cannot OOM the verifier before the signature is
//! checked), verifies the signature, then returns a [`VerifiedBundle`] that
//! lets the caller stream each payload **one at a time** out of the still-open
//! tar reader. As each payload is streamed, its SHA-256 is computed
//! incrementally and checked against the manifest at end-of-file — so a
//! tampered payload is caught without ever holding the whole file in RAM. See
//! [`VerifiedBundle::next_payload`] and [`VerifiedPayload`].
//!
//! # TOCTOU — payload bytes are UNTRUSTED until EOF
//!
//! A verified *signature* attests only to the *manifest*. The payload bytes
//! flowing out of a [`VerifiedPayload`] are **untrusted** until the payload has
//! been read fully to EOF (or [`VerifiedPayload::verify_to_end`] returns `Ok`),
//! at which point — and only then — the SHA-256 and declared length are
//! enforced. A truncated, tampered, or substituted payload is detected at that
//! final EOF check, *after* the bytes have already passed through the reader.
//!
//! Therefore consumers **MUST** stream each payload to a temporary / staging
//! location (a temp file, a scratch table, a `.tmp` path) and only
//! commit/rename/swap it into the live destination **after** the checksum is
//! confirmed (the `Read` reaches EOF without error / `verify_to_end` is `Ok`).
//! **Never write straight to the live path**: doing so leaves a window where a
//! tampered or partial payload is observable at the real destination before the
//! checksum has a chance to reject it.

use std::collections::BTreeMap;
use std::io::{self, Read};

use ed25519_dalek::{Signature, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::Archive;
use thiserror::Error;

// Build-time injected production public key, generated by `build.rs` into
// `${OUT_DIR}/airgap_pubkey.rs`. Defines:
//
//   pub(crate) const AIRGAP_BUNDLE_PUBLIC_KEY_INJECTED: Option<[u8; 32]>;
//
// `Some([..])` when the build set `AIRGAP_BUNDLE_PUBLIC_KEY_HEX`, else `None`.
include!(concat!(env!("OUT_DIR"), "/airgap_pubkey.rs"));

/// Bundle schema version this build understands. Bumped when the manifest
/// shape or signing rule changes incompatibly. The verifier rejects any
/// manifest whose `schema_version` differs.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Upper bound on the in-memory read of `manifest.json`. The manifest is parsed
/// and used to derive the signed canonical bytes BEFORE the signature is
/// checked, so this read happens on pre-authentication, attacker-controlled
/// input. A tiny gzip bundle can declare a multi-GB tar entry; we therefore
/// never trust the tar header's declared size and instead cap the actual read
/// via `take()`. 4 MiB is far larger than any legitimate manifest (kilobytes).
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

/// Upper bound on the in-memory read of `manifest.sig`. A detached Ed25519
/// signature is exactly [`SIGNATURE_LENGTH`] (64) bytes; we cap the read small
/// so a malicious header cannot induce a large allocation before the signature
/// length is even validated.
const MAX_SIGNATURE_BYTES: u64 = 256;

/// Canonical tar entry name for the manifest.
pub const MANIFEST_ENTRY: &str = "manifest.json";
/// Canonical tar entry name for the detached signature.
pub const SIGNATURE_ENTRY: &str = "manifest.sig";

/// Embedded Ed25519 **public** key used to verify air-gap bundles.
///
/// This is the **effective** key for this build: it is the production key
/// injected at build time when present, otherwise the reproducible DEV
/// placeholder ([`DEV_PLACEHOLDER_PUBLIC_KEY`]).
///
/// ⚠️ When no key is injected this equals the PLACEHOLDER — DEV/TEST ONLY,
/// whose private half anyone can derive from the seed `[0x01; 32]`. It does NOT
/// correspond to any production signing key, and [`verify_bundle`] refuses to
/// trust it in a release build (see that function's production-key guard).
///
/// ## Production key injection
///
/// For a production (enterprise) build, set `AIRGAP_BUNDLE_PUBLIC_KEY_HEX` to
/// the 64-char hex encoding of the real 32-byte public key. `build.rs` decodes
/// it (failing the build on malformed input) and emits an injected const that
/// is `include!`-ed here; this const then resolves to the injected key:
///
/// ```text
///   AIRGAP_BUNDLE_PUBLIC_KEY_HEX=<64 hex chars> cargo build --release --features enterprise
/// ```
///
/// The matching PRIVATE signing seed lives ONLY in the offline nano-main signer
/// / key-store used by WS1's bundle builder and is never committed or present in
/// any build environment.
pub const AIRGAP_BUNDLE_PUBLIC_KEY: [u8; PUBLIC_KEY_LENGTH] = match AIRGAP_BUNDLE_PUBLIC_KEY_INJECTED
{
    Some(key) => key,
    None => DEV_PLACEHOLDER_PUBLIC_KEY,
};

/// The dev/test placeholder public key bytes. Kept as a separate named const so
/// tests can reference it explicitly and so the production override only has to
/// touch [`AIRGAP_BUNDLE_PUBLIC_KEY`].
///
/// Corresponds to the deterministic dev signing seed
/// `[0x01; 32]` (see `tests::dev_signing_key`). Anyone can reproduce the
/// keypair from that seed — which is exactly why it must never sign prod data.
const DEV_PLACEHOLDER_PUBLIC_KEY: [u8; PUBLIC_KEY_LENGTH] = [
    0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95, 0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d, 0x72,
    0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b, 0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
];

/// The kind of payload a bundle carries. Serialized as snake_case strings so
/// the manifest is stable and language-neutral.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BundleType {
    /// VRL parser definitions sourced from the parsers repo.
    Parsers,
    /// IP enrichment database (e.g. IPinfo Lite MMDB) — the large payload.
    IpEnrichment,
    /// Indicator-of-compromise feed snapshot (ThreatFox / Tor / etc.).
    Ioc,
    /// Offline license token refresh.
    License,
    /// Detection rule definitions sourced from the rules repo (nano native
    /// `rule_format: "nanosiem"`). Each payload's raw bytes are a rule
    /// definition at its repo-relative path.
    Rules,
    /// Playbook definitions sourced from the playbooks repo (markdown/yaml).
    /// Each payload's raw bytes are a playbook definition at its repo-relative
    /// path.
    Playbooks,
}

/// One payload file declared in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    /// Path of the file inside the tar archive (and its logical name).
    pub path: String,
    /// Lowercase hex SHA-256 of the raw file bytes.
    pub sha256: String,
    /// Size of the file in bytes.
    pub bytes: u64,
}

/// The bundle manifest: describes the payload, its provenance, and the
/// per-file checksums. Signed (in [canonical form](BundleManifest::canonical_bytes))
/// by the offline signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    /// What kind of payload this bundle carries.
    pub bundle_type: BundleType,
    /// Manifest schema version (see [`SUPPORTED_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Caller-defined content version (e.g. feed date, parser pack version).
    pub content_version: String,
    /// RFC3339 / ISO-8601 timestamp of when the bundle was generated.
    pub generated_at: String,
    /// Free-form identifier of the producer (tool + version).
    pub generator: String,
    /// Payload files, in signed order (order is part of the signed content).
    pub files: Vec<FileEntry>,
}

impl BundleManifest {
    /// Produce the **canonical signing bytes** for this manifest.
    ///
    /// See the module doc for the exact rule. This is compact JSON with
    /// lexicographically sorted keys at every level and no insignificant
    /// whitespace. The `files` array order is preserved (entries are NOT
    /// sorted — array order is meaningful and signed).
    ///
    /// Both the signer (WS1/TS) and verifier MUST byte-match this output.
    ///
    /// # Cross-language invariant: ASCII-only key sort
    ///
    /// The canonical key ordering is **byte-wise lexicographic over UTF-8**
    /// (Rust `BTreeMap<String, _>`). This matches JavaScript's
    /// `Array.prototype.sort()` string comparison (UTF-16 code-unit order)
    /// **only because every object key in this schema is pure ASCII** (e.g.
    /// `bundle_type`, `sha256`). For ASCII, byte order == code-unit order ==
    /// code-point order, so the two languages agree. If a future field name
    /// ever contains a non-ASCII character, this invariant breaks and the TS
    /// signer and Rust verifier could disagree — keep all field names ASCII.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BundleError> {
        // Round-trip through serde_json::Value, then re-serialize with sorted
        // keys. `serde_json::Value::Object` is backed by a map that, with the
        // `preserve_order` feature OFF, sorts keys — but we don't control that
        // feature flag globally, so sort explicitly via BTreeMap to be safe and
        // deterministic regardless of build config.
        let value = serde_json::to_value(self)
            .map_err(|e| BundleError::Serialization(e.to_string()))?;
        let canonical = canonicalize_json(&value);
        serde_json::to_vec(&canonical).map_err(|e| BundleError::Serialization(e.to_string()))
    }

    fn validate_schema(&self) -> Result<(), BundleError> {
        if self.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(BundleError::UnsupportedSchemaVersion {
                found: self.schema_version,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }
        Ok(())
    }
}

/// Recursively rewrite a `serde_json::Value` so that every object's keys are
/// sorted lexicographically. Arrays keep their order. Scalars pass through.
///
/// `serde_json::to_vec` over this value (with default compact formatting)
/// yields the canonical bytes: sorted keys, no insignificant whitespace.
fn canonicalize_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            // BTreeMap sorts keys lexicographically (byte order of UTF-8),
            // matching JS string comparison of ASCII keys used here.
            let sorted: BTreeMap<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize_json(v)))
                .collect();
            serde_json::to_value(sorted).unwrap_or(serde_json::Value::Null)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonicalize_json).collect())
        }
        other => other.clone(),
    }
}

/// Errors that can occur while verifying or consuming an air-gap bundle.
#[derive(Debug, Error)]
pub enum BundleError {
    /// The archive could not be parsed (bad gzip/tar, missing required
    /// entries, wrong entry ordering, truncated stream, etc.).
    #[error("malformed bundle archive: {0}")]
    MalformedArchive(String),

    /// The manifest JSON could not be parsed/serialized.
    #[error("manifest serialization error: {0}")]
    Serialization(String),

    /// `schema_version` is not understood by this build.
    #[error("unsupported bundle schema_version {found} (this build supports {supported})")]
    UnsupportedSchemaVersion { found: u32, supported: u32 },

    /// The embedded/provided public key bytes are not a valid Ed25519 key, or
    /// the signature bytes are not a well-formed 64-byte signature.
    #[error("invalid or wrong verification key / signature encoding: {0}")]
    InvalidKey(String),

    /// The signature did not verify against the public key over the canonical
    /// manifest bytes. The bundle is untrusted (tampered manifest, wrong
    /// signing key, or corruption).
    #[error("bundle signature verification failed (untrusted or wrong key)")]
    BadSignature,

    /// A payload file's SHA-256 did not match the manifest, or a declared file
    /// was missing / had the wrong size.
    #[error("checksum mismatch for payload '{path}': manifest={expected}, actual={actual}")]
    ChecksumMismatch {
        path: String,
        expected: String,
        actual: String,
    },

    /// A payload entry in the archive was not declared in the manifest, or a
    /// declared payload was absent from the archive.
    #[error("payload set mismatch: {0}")]
    PayloadSetMismatch(String),

    /// Underlying I/O failure while reading the archive.
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<io::Error> for BundleError {
    fn from(e: io::Error) -> Self {
        BundleError::Io(e.to_string())
    }
}

/// Verify a bundle byte stream against the **embedded** public key.
///
/// `reader` is the raw `.tar.gz` byte stream (file, network body, etc.). On
/// success returns a [`VerifiedBundle`] whose payloads can be streamed out one
/// at a time; the signature is already verified at this point and each payload
/// is checksum-verified as it is streamed.
///
/// See [`verify_bundle_with_key`] to supply a non-embedded key.
///
/// # Production-key guard
///
/// The embedded [`AIRGAP_BUNDLE_PUBLIC_KEY`] ships as a reproducible DEV
/// placeholder ([`DEV_PLACEHOLDER_PUBLIC_KEY`]) whose private half anyone can
/// derive. To prevent a release artifact from silently trusting bundles signed
/// with that publicly-known key, this entry point refuses to run when the
/// embedded key is still the placeholder **and** this is not a debug build,
/// returning [`BundleError::InvalidKey`]. A production build injects the real
/// key (see the [`AIRGAP_BUNDLE_PUBLIC_KEY`] doc) and this guard then passes.
///
/// [`verify_bundle_with_key`] does NOT apply this guard — tests and consumers
/// that pin their own key go through it directly.
pub fn verify_bundle<R: Read + 'static>(reader: R) -> Result<VerifiedBundle<R>, BundleError> {
    // A release build must never trust the well-known dev placeholder key: its
    // private half is reproducible from the seed [0x01;32]. In debug builds the
    // placeholder is expected (it is what the unit tests sign with).
    if AIRGAP_BUNDLE_PUBLIC_KEY == DEV_PLACEHOLDER_PUBLIC_KEY && !cfg!(debug_assertions) {
        return Err(BundleError::InvalidKey(
            "refusing to verify with the reproducible DEV placeholder key in a release build; \
             inject the real AIRGAP_BUNDLE_PUBLIC_KEY at build time"
                .into(),
        ));
    }
    verify_bundle_with_key(reader, &AIRGAP_BUNDLE_PUBLIC_KEY)
}

/// Verify a bundle byte stream against a caller-supplied 32-byte Ed25519
/// public key. Used in tests and by consumers that pin their own key.
pub fn verify_bundle_with_key<R: Read + 'static>(
    reader: R,
    public_key_bytes: &[u8; PUBLIC_KEY_LENGTH],
) -> Result<VerifiedBundle<R>, BundleError> {
    let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|e| BundleError::InvalidKey(e.to_string()))?;

    // The `Archive` owns the reader. `Archive::entries` borrows `&mut Archive`,
    // so to keep the `Entries` iterator alive across multiple `next_payload`
    // calls we heap-pin the archive in a `Box` and extend the borrow to the
    // box's lifetime. This is sound: the box outlives the `Entries` (both are
    // dropped together inside `VerifiedBundle`, entries first), the box is never
    // moved or aliased mutably elsewhere, and we never expose the archive again.
    let mut archive: Box<Archive<GzDecoder<R>>> = Box::new(Archive::new(GzDecoder::new(reader)));
    // SAFETY: see above — the referent (the boxed Archive) lives as long as the
    // returned `VerifiedBundle`, which owns the box, and is dropped after the
    // `Entries` field.
    let archive_ref: &'static mut Archive<GzDecoder<R>> =
        unsafe { &mut *(archive.as_mut() as *mut Archive<GzDecoder<R>>) };
    let mut entries = archive_ref
        .entries()
        .map_err(|e| BundleError::MalformedArchive(e.to_string()))?;

    // --- Entry 1: manifest.json -------------------------------------------
    let mut manifest_bytes = Vec::new();
    {
        let mut first = entries
            .next()
            .ok_or_else(|| BundleError::MalformedArchive("empty archive".into()))?
            .map_err(|e| BundleError::MalformedArchive(e.to_string()))?;
        let path = entry_path(&first)?;
        if path != MANIFEST_ENTRY {
            return Err(BundleError::MalformedArchive(format!(
                "expected first entry '{MANIFEST_ENTRY}', found '{path}'"
            )));
        }
        // Bounded read: this is pre-auth, attacker-controlled input. Cap the
        // ACTUAL read via take() rather than trusting the tar header's declared
        // size, so a tiny gzip claiming a multi-GB entry can't OOM us. Read one
        // byte past the cap to detect overflow.
        first
            .by_ref()
            .take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut manifest_bytes)?;
        if manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(BundleError::MalformedArchive(format!(
                "manifest.json exceeds maximum size of {MAX_MANIFEST_BYTES} bytes"
            )));
        }
    }

    // --- Entry 2: manifest.sig --------------------------------------------
    let mut sig_bytes = Vec::new();
    {
        let mut second = entries
            .next()
            .ok_or_else(|| BundleError::MalformedArchive("missing manifest.sig".into()))?
            .map_err(|e| BundleError::MalformedArchive(e.to_string()))?;
        let path = entry_path(&second)?;
        if path != SIGNATURE_ENTRY {
            return Err(BundleError::MalformedArchive(format!(
                "expected second entry '{SIGNATURE_ENTRY}', found '{path}'"
            )));
        }
        // Bounded read: the signature is exactly SIGNATURE_LENGTH bytes; cap the
        // read tiny so a malicious header can't induce a large allocation before
        // the length is even validated.
        second
            .by_ref()
            .take(MAX_SIGNATURE_BYTES + 1)
            .read_to_end(&mut sig_bytes)?;
        if sig_bytes.len() as u64 > MAX_SIGNATURE_BYTES {
            return Err(BundleError::MalformedArchive(format!(
                "manifest.sig exceeds maximum size of {MAX_SIGNATURE_BYTES} bytes"
            )));
        }
    }

    // Parse manifest and re-derive canonical signing bytes. We sign over the
    // canonical form, NOT the raw manifest.json bytes, so that the TS signer
    // and Rust verifier agree regardless of incidental formatting.
    let manifest: BundleManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| BundleError::Serialization(e.to_string()))?;
    manifest.validate_schema()?;
    let canonical = manifest.canonical_bytes()?;

    // Parse + verify the detached signature.
    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err(BundleError::InvalidKey(format!(
            "signature must be {SIGNATURE_LENGTH} bytes, got {}",
            sig_bytes.len()
        )));
    }
    let sig_arr: [u8; SIGNATURE_LENGTH] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| BundleError::InvalidKey("signature length".into()))?;
    let signature = Signature::from_bytes(&sig_arr);
    // `verify_strict` rejects signatures using non-canonical / small-order
    // points (the "weak key" / malleability foot-gun on the permissive
    // `verify`), per the ed25519-dalek 2.x hardening guidance.
    verifying_key
        .verify_strict(&canonical, &signature)
        .map_err(|_| BundleError::BadSignature)?;

    // The signature is now trusted, so the manifest contents are authentic. But
    // an authentic manifest can still declare hostile paths (the signer could be
    // compromised, or a legitimately-signed bundle could be repurposed). Reject
    // any traversal/absolute path UP FRONT so a malicious path can never become
    // an "expected" payload name matched in `next_payload`.
    for entry in &manifest.files {
        safe_relative_path(&entry.path)?;
    }

    // Build the lookup of remaining expected payloads (manifest order).
    let remaining: Vec<FileEntry> = manifest.files.clone();

    Ok(VerifiedBundle {
        manifest,
        entries,
        remaining_idx: 0,
        expected: remaining,
        _archive: archive,
    })
}

/// Extract the path of a tar entry as a UTF-8 string.
fn entry_path<R: Read>(entry: &tar::Entry<'_, R>) -> Result<String, BundleError> {
    let p = entry
        .path()
        .map_err(|e| BundleError::MalformedArchive(e.to_string()))?;
    Ok(p.to_string_lossy().into_owned())
}

/// Reject any path that is not a safe, relative, single-segment-or-deeper path
/// that a consumer can `Path::join` onto a destination directory without
/// escaping it.
///
/// This is the anti-`Zip-Slip` / tar-traversal guard. It is applied both to
/// every [`FileEntry::path`] declared in the manifest (so a malicious manifest
/// can never make a traversal path the "expected" name) and to the actual tar
/// entry path encountered while streaming.
///
/// A path is rejected if it:
/// - is empty,
/// - contains an embedded NUL byte,
/// - is absolute (`/foo`),
/// - has a root, prefix, or drive component (`C:\`, `\\server\share`),
/// - contains any `..` (parent-dir) component,
/// - or contains a current-dir (`.`) component (defensive; not needed but
///   keeps the path strictly normalized so `join` is predictable).
fn safe_relative_path(p: &str) -> Result<(), BundleError> {
    use std::path::{Component, Path};

    if p.is_empty() {
        return Err(BundleError::MalformedArchive(
            "payload path is empty".into(),
        ));
    }
    if p.as_bytes().contains(&0) {
        return Err(BundleError::MalformedArchive(format!(
            "payload path contains a NUL byte: {p:?}"
        )));
    }

    let path = Path::new(p);
    for comp in path.components() {
        match comp {
            Component::Normal(_) => {}
            Component::CurDir => {
                return Err(BundleError::MalformedArchive(format!(
                    "payload path contains a '.' component: {p:?}"
                )));
            }
            Component::ParentDir => {
                return Err(BundleError::MalformedArchive(format!(
                    "payload path contains a '..' (traversal) component: {p:?}"
                )));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(BundleError::MalformedArchive(format!(
                    "payload path is absolute / has a root or drive prefix: {p:?}"
                )));
            }
        }
    }
    Ok(())
}

/// A bundle whose manifest signature has been verified. Payloads have NOT yet
/// been read; stream them out one at a time with [`next_payload`].
///
/// [`next_payload`]: VerifiedBundle::next_payload
pub struct VerifiedBundle<R: Read + 'static> {
    manifest: BundleManifest,
    // `entries` borrows from `_archive`. Field declaration order is also drop
    // order in Rust, so `entries` (declared first) is dropped before
    // `_archive`, upholding the borrow's validity. Do NOT reorder these fields.
    entries: tar::Entries<'static, GzDecoder<R>>,
    remaining_idx: usize,
    expected: Vec<FileEntry>,
    /// Heap-pinned owner of the tar archive that `entries` borrows from.
    /// Declared last so it is dropped after `entries`.
    _archive: Box<Archive<GzDecoder<R>>>,
}

impl<R: Read + 'static> VerifiedBundle<R> {
    /// The verified manifest (signature already checked).
    pub fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }

    /// The bundle type, for dispatch by consumers.
    pub fn bundle_type(&self) -> BundleType {
        self.manifest.bundle_type
    }

    /// Stream the next payload out of the bundle.
    ///
    /// Returns `Ok(Some(VerifiedPayload))` for each declared payload in
    /// manifest order, then `Ok(None)` once all declared payloads have been
    /// consumed (after also confirming there are no extra/undeclared trailing
    /// entries).
    ///
    /// The returned [`VerifiedPayload`] is a `Read` that yields the file bytes
    /// while incrementally hashing them; on EOF it asserts the SHA-256 matches
    /// the manifest. **You must read each payload to completion** (or call
    /// [`VerifiedPayload::verify_to_end`]) for the checksum to be enforced.
    ///
    /// Large payloads (the ~400MB IPinfo DB) are never buffered: callers
    /// `io::copy` straight from the payload to their destination (a file, an
    /// MMDB loader, the CH bulk-insert pipe), and the hash is validated on the
    /// fly.
    pub fn next_payload(&mut self) -> Result<Option<VerifiedPayload<'_, R>>, BundleError> {
        if self.remaining_idx >= self.expected.len() {
            // All declared payloads consumed. Confirm no extra entries follow.
            if let Some(extra) = self.entries.next() {
                let extra = extra.map_err(|e| BundleError::MalformedArchive(e.to_string()))?;
                let path = entry_path(&extra)?;
                return Err(BundleError::PayloadSetMismatch(format!(
                    "undeclared trailing entry '{path}'"
                )));
            }
            return Ok(None);
        }

        let expected = self.expected[self.remaining_idx].clone();
        self.remaining_idx += 1;

        let entry = self
            .entries
            .next()
            .ok_or_else(|| {
                BundleError::PayloadSetMismatch(format!(
                    "manifest declares '{}' but archive ended",
                    expected.path
                ))
            })?
            .map_err(|e| BundleError::MalformedArchive(e.to_string()))?;

        // Reject non-regular-file tar entries (symlink/hardlink/dir/char/block/
        // fifo/etc.). Even though a payload is matched by name, a symlink entry
        // whose name matches an expected path could redirect a naive extractor.
        if !entry.header().entry_type().is_file() {
            return Err(BundleError::MalformedArchive(format!(
                "payload entry '{}' is not a regular file (type {:?})",
                expected.path,
                entry.header().entry_type()
            )));
        }

        let path = entry_path(&entry)?;
        // Defense in depth: validate the ACTUAL archive path too, not just the
        // manifest's declared path. (The manifest paths were validated up front,
        // but a tampered/repacked archive could carry a hostile path that still
        // string-matches an expected name only after normalization.)
        safe_relative_path(&path)?;
        if path != expected.path {
            return Err(BundleError::PayloadSetMismatch(format!(
                "expected payload '{}' next (manifest order), found '{}'",
                expected.path, path
            )));
        }

        Ok(Some(VerifiedPayload {
            entry,
            expected,
            hasher: Sha256::new(),
            bytes_read: 0,
            finished: false,
            _gate: std::marker::PhantomData,
        }))
    }
}

/// A single payload being streamed out of a [`VerifiedBundle`].
///
/// Implements [`Read`]; bytes are hashed as they are read. When the underlying
/// entry reaches EOF the SHA-256 and byte-count are checked against the
/// manifest. If they mismatch, the `Read` call that hits EOF returns an
/// `io::Error` wrapping [`BundleError::ChecksumMismatch`].
///
/// # The bytes are UNTRUSTED until EOF
///
/// The signature attests only to the manifest, not to these bytes. Bytes
/// returned by [`read`](Read::read) before EOF are **unverified** — the
/// checksum and length are enforced only once the stream reaches EOF (or
/// [`verify_to_end`](VerifiedPayload::verify_to_end) returns `Ok`). Consumers
/// **MUST** stream to a temporary / staging location and only commit (rename /
/// swap) into the live destination after that final check succeeds. Never
/// write straight to the live path — see the module-level docs.
pub struct VerifiedPayload<'a, R: Read + 'static> {
    // The tar entry borrows the `'static`-extended archive owned by the parent
    // `VerifiedBundle`. The `'a` lifetime below (via `_gate`) ties this payload
    // to a `&'a mut VerifiedBundle`, so the borrow checker forbids advancing to
    // the next payload while this one is still held — which would otherwise
    // invalidate this entry's reader.
    entry: tar::Entry<'static, GzDecoder<R>>,
    expected: FileEntry,
    hasher: Sha256,
    bytes_read: u64,
    finished: bool,
    _gate: std::marker::PhantomData<&'a mut ()>,
}

impl<'a, R: Read + 'static> VerifiedPayload<'a, R> {
    /// The manifest entry (path, expected sha256, expected size) for this
    /// payload.
    pub fn entry(&self) -> &FileEntry {
        &self.expected
    }

    /// The logical path / name of this payload.
    ///
    /// This is a **sanitized relative path**: it has been validated by
    /// [`safe_relative_path`] (no absolute paths, no `..`/`.` components, no
    /// root/drive prefix, no NUL bytes), so it is safe to `Path::join` onto a
    /// destination directory without risk of escaping it. (Note: the bytes of
    /// the payload are still untrusted until EOF — see the type-level docs.)
    pub fn path(&self) -> &str {
        &self.expected.path
    }

    /// Drain this payload to completion, discarding the bytes, and enforce the
    /// checksum. Convenience for callers that only need to validate.
    pub fn verify_to_end(mut self) -> Result<(), BundleError> {
        let mut sink = io::sink();
        io::copy(&mut self, &mut sink)?;
        Ok(())
    }

    fn finalize(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;

        if self.bytes_read != self.expected.bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                BundleError::ChecksumMismatch {
                    path: self.expected.path.clone(),
                    expected: format!("{} bytes", self.expected.bytes),
                    actual: format!("{} bytes", self.bytes_read),
                },
            ));
        }

        let digest = std::mem::take(&mut self.hasher).finalize();
        let actual_hex = hex::encode(digest);
        if !actual_hex.eq_ignore_ascii_case(&self.expected.sha256) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                BundleError::ChecksumMismatch {
                    path: self.expected.path.clone(),
                    expected: self.expected.sha256.clone(),
                    actual: actual_hex,
                },
            ));
        }
        Ok(())
    }
}

impl<'a, R: Read + 'static> Read for VerifiedPayload<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.entry.read(buf)?;
        if n == 0 {
            // EOF for this entry — enforce checksum + size.
            self.finalize()?;
            return Ok(0);
        }
        self.hasher.update(&buf[..n]);
        self.bytes_read += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
pub mod fixtures;

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic dev/test signing key from the seed `[0x01; 32]`. Its
    /// public half MUST equal [`DEV_PLACEHOLDER_PUBLIC_KEY`] /
    /// [`AIRGAP_BUNDLE_PUBLIC_KEY`].
    fn dev_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0x01u8; 32])
    }

    /// `Result::unwrap_err` needs the `Ok` type to be `Debug`; `VerifiedBundle`
    /// deliberately isn't (it owns a tar reader). This pulls out the error
    /// without that bound.
    fn err_of<R: Read + 'static>(r: Result<VerifiedBundle<R>, BundleError>) -> BundleError {
        match r {
            Ok(_) => panic!("expected verification to fail, but it succeeded"),
            Err(e) => e,
        }
    }

    #[test]
    fn embedded_public_key_matches_dev_seed() {
        let sk = dev_signing_key();
        assert_eq!(
            sk.verifying_key().to_bytes(),
            AIRGAP_BUNDLE_PUBLIC_KEY,
            "DEV_PLACEHOLDER_PUBLIC_KEY is stale; regenerate from seed [0x01;32]"
        );
    }

    #[test]
    fn canonical_bytes_are_sorted_and_compact() {
        let m = fixtures::sample_manifest();
        let bytes = m.canonical_bytes().unwrap();
        let s = String::from_utf8(bytes).unwrap();
        // Keys sorted: bundle_type before content_version before files ...
        let bt = s.find("\"bundle_type\"").unwrap();
        let cv = s.find("\"content_version\"").unwrap();
        let files = s.find("\"files\"").unwrap();
        assert!(bt < cv && cv < files, "keys not sorted: {s}");
        // No insignificant whitespace.
        assert!(!s.contains(": "), "has space after colon: {s}");
        assert!(!s.contains(", "), "has space after comma: {s}");
        assert!(!s.ends_with('\n'));
        // FileEntry keys sorted: bytes < path < sha256.
        let b = s.find("\"bytes\"").unwrap();
        let p = s.find("\"path\"").unwrap();
        let sh = s.find("\"sha256\"").unwrap();
        assert!(b < p && p < sh);
    }

    #[test]
    fn accepts_valid_bundle() {
        let sk = dev_signing_key();
        let payloads = vec![
            ("a.txt".to_string(), b"hello".to_vec()),
            ("b.bin".to_string(), vec![0u8; 1024]),
        ];
        let bundle = fixtures::build_bundle(&sk, BundleType::Parsers, "v1", payloads.clone());

        let mut vb = verify_bundle(std::io::Cursor::new(bundle)).expect("should verify");
        assert_eq!(vb.bundle_type(), BundleType::Parsers);

        let mut got = Vec::new();
        while let Some(mut p) = vb.next_payload().unwrap() {
            let mut buf = Vec::new();
            p.read_to_end(&mut buf).unwrap();
            got.push((p.path().to_string(), buf));
        }
        assert_eq!(got, payloads);
    }

    #[test]
    fn accepts_with_explicit_key() {
        let sk = dev_signing_key();
        let pk = sk.verifying_key().to_bytes();
        let bundle = fixtures::build_bundle(
            &sk,
            BundleType::Ioc,
            "2026-06-04",
            vec![("ioc.csv".into(), b"1.2.3.4".to_vec())],
        );
        let mut vb =
            verify_bundle_with_key(std::io::Cursor::new(bundle), &pk).expect("verify with key");
        let p = vb.next_payload().unwrap().unwrap();
        p.verify_to_end().unwrap();
        assert!(vb.next_payload().unwrap().is_none());
    }

    #[test]
    fn rejects_flipped_payload_byte() {
        let sk = dev_signing_key();
        let payloads = vec![("data.bin".to_string(), vec![7u8; 64])];
        let mut bundle = fixtures::build_bundle(&sk, BundleType::IpEnrichment, "v1", payloads);

        // Flip a byte deep in the gzip stream (the payload region). We locate
        // the known payload content by searching the *uncompressed* assertion
        // path instead: rebuild with a tampered payload that doesn't match its
        // manifest checksum.
        let tampered_payloads = vec![("data.bin".to_string(), vec![7u8; 64])];
        // Build a manifest as if payload were all 7s, but ship all 8s.
        let bad = fixtures::build_bundle_with_manifest_override(
            &sk,
            BundleType::IpEnrichment,
            "v1",
            // manifest describes 7s
            tampered_payloads,
            // actual archived bytes are 8s
            vec![("data.bin".to_string(), vec![8u8; 64])],
        );
        let _ = &mut bundle;

        let mut vb = verify_bundle(std::io::Cursor::new(bad)).expect("sig still valid");
        let mut p = vb.next_payload().unwrap().unwrap();
        let mut buf = Vec::new();
        let err = p.read_to_end(&mut buf).unwrap_err();
        let inner = err.into_inner().unwrap();
        let be = inner.downcast::<BundleError>().unwrap();
        assert!(matches!(*be, BundleError::ChecksumMismatch { .. }));
    }

    #[test]
    fn rejects_bad_signature() {
        let sk = dev_signing_key();
        let mut bundle = fixtures::build_bundle(
            &sk,
            BundleType::Parsers,
            "v1",
            vec![("a".into(), b"x".to_vec())],
        );
        // Corrupt the signature bytes inside the archive by rebuilding with a
        // garbage signature.
        let bad = fixtures::build_bundle_with_bad_signature(
            BundleType::Parsers,
            "v1",
            vec![("a".into(), b"x".to_vec())],
        );
        let _ = &mut bundle;
        let err = err_of(verify_bundle(std::io::Cursor::new(bad)));
        assert!(matches!(err, BundleError::BadSignature));
    }

    #[test]
    fn rejects_signature_from_different_key() {
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[0x02u8; 32]);
        let bundle = fixtures::build_bundle(
            &attacker,
            BundleType::Parsers,
            "v1",
            vec![("a".into(), b"x".to_vec())],
        );
        // Verified against the EMBEDDED (dev seed [0x01;32]) key — must fail.
        let err = err_of(verify_bundle(std::io::Cursor::new(bundle)));
        assert!(matches!(err, BundleError::BadSignature));
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let sk = dev_signing_key();
        let bundle = fixtures::build_bundle_with_schema_version(
            &sk,
            BundleType::License,
            "v1",
            vec![("lic".into(), b"token".to_vec())],
            SUPPORTED_SCHEMA_VERSION + 99,
        );
        let err = err_of(verify_bundle(std::io::Cursor::new(bundle)));
        assert!(matches!(
            err,
            BundleError::UnsupportedSchemaVersion { .. }
        ));
    }

    #[test]
    fn rejects_malformed_archive() {
        let err = err_of(verify_bundle(std::io::Cursor::new(b"not a gzip".to_vec())));
        assert!(matches!(err, BundleError::MalformedArchive(_) | BundleError::Io(_)));
    }

    /// Golden vector: pin the exact canonical signing bytes of the sample
    /// manifest. If this ever drifts, the TS signer and Rust verifier would
    /// disagree and every legitimately-signed bundle would fail to verify.
    #[test]
    fn canonical_bytes_golden_vector() {
        let m = fixtures::sample_manifest();
        let bytes = m.canonical_bytes().unwrap();
        let expected: &[u8] = br#"{"bundle_type":"parsers","content_version":"v1","files":[{"bytes":5,"path":"a.txt","sha256":"deadbeef"}],"generated_at":"2026-06-04T00:00:00Z","generator":"nano-airgap-fixture/1","schema_version":1}"#;
        assert_eq!(
            bytes,
            expected,
            "canonical_bytes drifted from the golden vector; this breaks cross-language signing.\n got: {}",
            String::from_utf8_lossy(&bytes)
        );
    }

    #[test]
    fn safe_relative_path_rejects_traversal_and_absolute() {
        assert!(safe_relative_path("a/b/c.txt").is_ok());
        assert!(safe_relative_path("a.txt").is_ok());
        assert!(safe_relative_path("../etc/passwd").is_err());
        assert!(safe_relative_path("a/../../etc/passwd").is_err());
        assert!(safe_relative_path("/etc/passwd").is_err());
        assert!(safe_relative_path("./a.txt").is_err());
        assert!(safe_relative_path("").is_err());
        assert!(safe_relative_path("a\0b").is_err());
    }

    #[test]
    fn rejects_manifest_with_traversal_path() {
        let sk = dev_signing_key();
        let bundle = fixtures::build_bundle_with_manifest_path(
            &sk,
            BundleType::Parsers,
            "v1",
            "../../../etc/cron.d/evil",
            "evil",
            b"payload".to_vec(),
        );
        // The manifest is correctly signed, but its declared path is hostile and
        // must be rejected up front (before any payload is streamed).
        let err = err_of(verify_bundle(std::io::Cursor::new(bundle)));
        assert!(matches!(err, BundleError::MalformedArchive(_)), "got {err:?}");
    }

    #[test]
    fn rejects_symlink_payload_entry() {
        let sk = dev_signing_key();
        let bundle = fixtures::build_bundle_with_symlink_payload(
            &sk,
            BundleType::Parsers,
            "v1",
            "link.txt",
            "/etc/passwd",
        );
        // Signature is valid (manifest describes a normal file), but the actual
        // tar entry is a symlink — next_payload must reject it.
        let mut vb = verify_bundle(std::io::Cursor::new(bundle)).expect("sig valid");
        let err = match vb.next_payload() {
            Ok(_) => panic!("expected symlink payload to be rejected"),
            Err(e) => e,
        };
        assert!(matches!(err, BundleError::MalformedArchive(_)), "got {err:?}");
    }

    #[test]
    fn rejects_oversized_manifest_before_signature() {
        // Declare a manifest entry larger than the cap. The bounded read must
        // reject it before any parsing/signature work.
        let bundle =
            fixtures::build_bundle_with_oversized_manifest((MAX_MANIFEST_BYTES + 1024) as usize);
        let err = err_of(verify_bundle(std::io::Cursor::new(bundle)));
        match err {
            BundleError::MalformedArchive(m) => {
                assert!(m.contains("manifest.json exceeds"), "got {m}");
            }
            other => panic!("expected oversized-manifest rejection, got {other:?}"),
        }
    }
}
