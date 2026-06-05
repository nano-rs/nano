// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reusable air-gap bundle fixture builder.
//!
//! Mirrors exactly what the WS1 (TypeScript) signer must produce, so it serves
//! as an executable specification of the bundle format. Used by the unit tests
//! in this module and available to other crates' tests.
//!
//! ## Build order (must match the verifier's expectations)
//!
//! 1. Compute `FileEntry { path, sha256, bytes }` for each payload (in the
//!    order given — order is signed).
//! 2. Assemble the [`BundleManifest`].
//! 3. Sign [`BundleManifest::canonical_bytes`] with the Ed25519 signing key,
//!    producing a detached 64-byte signature.
//! 4. Write a gzip(tar) with entries in this exact order:
//!    `manifest.json` (the canonical bytes), then `manifest.sig` (raw 64
//!    bytes), then each payload at its `path`.
//!
//! The TS implementation should write the identical structure; the
//! `accepts_valid_bundle` test is the conformance check.

use std::io::Write;

use ed25519_dalek::{Signer, SigningKey};
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};

use super::{BundleManifest, BundleType, FileEntry, MANIFEST_ENTRY, SIGNATURE_ENTRY,
    SUPPORTED_SCHEMA_VERSION};

/// A sample manifest for unit tests (no real payloads on disk).
pub fn sample_manifest() -> BundleManifest {
    BundleManifest {
        bundle_type: BundleType::Parsers,
        schema_version: SUPPORTED_SCHEMA_VERSION,
        content_version: "v1".to_string(),
        generated_at: "2026-06-04T00:00:00Z".to_string(),
        generator: "nano-airgap-fixture/1".to_string(),
        files: vec![FileEntry {
            path: "a.txt".to_string(),
            sha256: "deadbeef".to_string(),
            bytes: 5,
        }],
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn manifest_for(
    bundle_type: BundleType,
    content_version: &str,
    payloads: &[(String, Vec<u8>)],
    schema_version: u32,
) -> BundleManifest {
    let files = payloads
        .iter()
        .map(|(path, bytes)| FileEntry {
            path: path.clone(),
            sha256: sha256_hex(bytes),
            bytes: bytes.len() as u64,
        })
        .collect();
    BundleManifest {
        bundle_type,
        schema_version,
        content_version: content_version.to_string(),
        generated_at: "2026-06-04T00:00:00Z".to_string(),
        generator: "nano-airgap-fixture/1".to_string(),
        files,
    }
}

/// Low-level: write a `.tar.gz` from explicit manifest bytes, signature bytes,
/// and a set of `(path, content)` payloads, in the canonical entry order.
fn write_targz(
    manifest_json: &[u8],
    signature: &[u8],
    payloads: &[(String, Vec<u8>)],
) -> Vec<u8> {
    let buf = Vec::new();
    let enc = GzEncoder::new(buf, Compression::fast());
    let mut tar = tar::Builder::new(enc);

    append_entry(&mut tar, MANIFEST_ENTRY, manifest_json);
    append_entry(&mut tar, SIGNATURE_ENTRY, signature);
    for (path, content) in payloads {
        append_entry(&mut tar, path, content);
    }

    let enc = tar.into_inner().expect("finish tar");
    enc.finish().expect("finish gzip")
}

fn append_entry<W: Write>(tar: &mut tar::Builder<W>, path: &str, data: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, path, data).expect("append entry");
}

/// Build a correctly-signed bundle whose **manifest** declares a payload at the
/// (possibly hostile) `manifest_path`, while the archive carries the payload
/// under a tar-legal `archive_path`. Used to exercise the up-front
/// path-traversal guard on the manifest's declared path (the `tar` crate's
/// builder refuses to *write* a `..` entry, so the hostile path can only live
/// in the manifest, which is exactly where the verifier must catch it).
pub fn build_bundle_with_manifest_path(
    signing_key: &SigningKey,
    bundle_type: BundleType,
    content_version: &str,
    manifest_path: &str,
    archive_path: &str,
    content: Vec<u8>,
) -> Vec<u8> {
    let manifest = manifest_for(
        bundle_type,
        content_version,
        &[(manifest_path.to_string(), content.clone())],
        SUPPORTED_SCHEMA_VERSION,
    );
    let canonical = manifest.canonical_bytes().expect("canonical");
    let signature = signing_key.sign(&canonical);
    write_targz(
        &canonical,
        &signature.to_bytes(),
        &[(archive_path.to_string(), content)],
    )
}

/// Build a bundle whose payload tar entry is a **symlink** (not a regular
/// file), even though the manifest declares it as a normal file with a matching
/// checksum/size. Exercises the entry-type guard in `next_payload`.
pub fn build_bundle_with_symlink_payload(
    signing_key: &SigningKey,
    bundle_type: BundleType,
    content_version: &str,
    payload_path: &str,
    link_target: &str,
) -> Vec<u8> {
    // The manifest describes a zero-byte regular file at `payload_path` (a
    // symlink carries no file data, so size 0 / sha256 of empty keeps the
    // checksum logic from being the thing that rejects it).
    let manifest = manifest_for(
        bundle_type,
        content_version,
        &[(payload_path.to_string(), Vec::new())],
        SUPPORTED_SCHEMA_VERSION,
    );
    let canonical = manifest.canonical_bytes().expect("canonical");
    let signature = signing_key.sign(&canonical);

    let buf = Vec::new();
    let enc = GzEncoder::new(buf, Compression::fast());
    let mut tar = tar::Builder::new(enc);
    append_entry(&mut tar, MANIFEST_ENTRY, &canonical);
    append_entry(&mut tar, SIGNATURE_ENTRY, &signature.to_bytes());

    // Append a symlink entry.
    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_mode(0o777);
    header.set_entry_type(tar::EntryType::Symlink);
    header
        .set_link_name(link_target)
        .expect("set link target");
    header.set_cksum();
    tar.append_data(&mut header, payload_path, std::io::empty())
        .expect("append symlink");

    let enc = tar.into_inner().expect("finish tar");
    enc.finish().expect("finish gzip")
}

/// Build a bundle whose `manifest.json` entry is larger than `size` bytes (the
/// content is meaningless padding), to exercise the bounded pre-auth read cap.
/// The signature is garbage — the size guard must fire before any signature
/// work, so this is fine.
pub fn build_bundle_with_oversized_manifest(size: usize) -> Vec<u8> {
    let padding = vec![b'{'; size];
    let garbage_sig = [0xABu8; ed25519_dalek::SIGNATURE_LENGTH];
    write_targz(&padding, &garbage_sig, &[])
}

/// Build a fully valid, correctly signed bundle. The manifest checksums match
/// the archived payloads.
pub fn build_bundle(
    signing_key: &SigningKey,
    bundle_type: BundleType,
    content_version: &str,
    payloads: Vec<(String, Vec<u8>)>,
) -> Vec<u8> {
    let manifest = manifest_for(bundle_type, content_version, &payloads, SUPPORTED_SCHEMA_VERSION);
    let canonical = manifest.canonical_bytes().expect("canonical");
    let signature = signing_key.sign(&canonical);
    write_targz(&canonical, &signature.to_bytes(), &payloads)
}

/// Build a bundle whose manifest describes `manifest_payloads` (and is correctly
/// signed over that manifest), but whose archive actually contains
/// `archived_payloads`. Used to simulate payload tampering that passes the
/// signature check but fails the per-file checksum.
pub fn build_bundle_with_manifest_override(
    signing_key: &SigningKey,
    bundle_type: BundleType,
    content_version: &str,
    manifest_payloads: Vec<(String, Vec<u8>)>,
    archived_payloads: Vec<(String, Vec<u8>)>,
) -> Vec<u8> {
    let manifest = manifest_for(
        bundle_type,
        content_version,
        &manifest_payloads,
        SUPPORTED_SCHEMA_VERSION,
    );
    let canonical = manifest.canonical_bytes().expect("canonical");
    let signature = signing_key.sign(&canonical);
    write_targz(&canonical, &signature.to_bytes(), &archived_payloads)
}

/// Build a bundle with a structurally-valid-but-wrong signature (random 64
/// bytes), to exercise the [`BadSignature`](super::BundleError::BadSignature)
/// path.
pub fn build_bundle_with_bad_signature(
    bundle_type: BundleType,
    content_version: &str,
    payloads: Vec<(String, Vec<u8>)>,
) -> Vec<u8> {
    let manifest = manifest_for(bundle_type, content_version, &payloads, SUPPORTED_SCHEMA_VERSION);
    let canonical = manifest.canonical_bytes().expect("canonical");
    let garbage = [0xABu8; ed25519_dalek::SIGNATURE_LENGTH];
    write_targz(&canonical, &garbage, &payloads)
}

/// Build a bundle declaring an arbitrary `schema_version`, to exercise the
/// unsupported-version path. Signed correctly over its (wrong-version) manifest.
pub fn build_bundle_with_schema_version(
    signing_key: &SigningKey,
    bundle_type: BundleType,
    content_version: &str,
    payloads: Vec<(String, Vec<u8>)>,
    schema_version: u32,
) -> Vec<u8> {
    let manifest = manifest_for(bundle_type, content_version, &payloads, schema_version);
    let canonical = manifest.canonical_bytes().expect("canonical");
    let signature = signing_key.sign(&canonical);
    write_targz(&canonical, &signature.to_bytes(), &payloads)
}
