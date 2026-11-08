// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fixture-signed portable bundles for the NAN-4948 consumer tests.

use std::{collections::BTreeMap, path::PathBuf};

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;

use super::nanpfb::{self, IocSnapshotInput};
use super::portable::{self, FeedEntry, KeyRing, SignedDescriptor};

pub const FIXTURE_KEY_ID: &str = "fixture-consumer-1";
const FIXTURE_SEED: [u8; 32] = [0x24; 32];

pub fn key() -> SigningKey {
    SigningKey::from_bytes(&FIXTURE_SEED)
}

pub fn ring() -> KeyRing {
    KeyRing::from_hex(&[(FIXTURE_KEY_ID, &hex::encode(key().verifying_key().as_bytes()))]).unwrap()
}

/// A signed feed entry for `feed` produced an hour before `now`.
pub fn entry(feed: &str, revision: i64, now: DateTime<Utc>, rows: u64) -> FeedEntry {
    let upstream_at = now - Duration::hours(2);
    let terms = portable::portable_terms(feed).unwrap();
    FeedEntry {
        revision,
        license_id: terms.license_id.into(),
        terms_revision: format!("{feed}-reviewed").replace('_', "-"),
        upstream_at,
        produced_at: now - Duration::hours(1),
        hard_expiry: upstream_at + Duration::hours(20),
        row_count: rows,
        source_sha256: "ab".repeat(32),
    }
}

pub fn ioc(feed: &str, ty: &str, value: &str, threat: &str) -> IocSnapshotInput {
    IocSnapshotInput {
        ioc_value: value.into(),
        ioc_type: ty.into(),
        source_id: feed.into(),
        enrichment_name: feed.into(),
        threat_type: threat.into(),
        confidence_level: 90,
        ..Default::default()
    }
}

/// A sealed container in its own temp dir.
pub struct Sealed {
    pub dir: tempfile::TempDir,
    pub path: PathBuf,
    pub signed: SignedDescriptor,
}

/// Seal `feeds` (+ optional MMDB bytes and IOC rows) at `sequence`.
pub fn seal(
    feeds: BTreeMap<String, FeedEntry>,
    mmdb: Option<&[u8]>,
    rows: &[IocSnapshotInput],
    sequence: u64,
    produced_at: DateTime<Utc>,
) -> Sealed {
    let dir = tempfile::tempdir().unwrap();
    let payload = dir.path().join("p.nanpfb");
    nanpfb::write(
        &payload,
        mmdb,
        rows,
        None,
        feeds.iter().map(|(k, f)| (k.clone(), f.revision)).collect(),
        feeds.iter().map(|(k, f)| (k.clone(), f.hard_expiry)).collect(),
    )
    .unwrap();
    let path = dir.path().join("bundle.nanfeed");
    let signed = portable::seal(
        &payload,
        feeds,
        sequence,
        produced_at,
        FIXTURE_KEY_ID,
        &key(),
        &ring(),
        &path,
    )
    .unwrap();
    Sealed { dir, path, signed }
}

/// The metadata response the distribution route returns for `signed`.
pub fn metadata(signed: &SignedDescriptor, url: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "descriptor": signed,
        "bundle_url": url,
        "bundle_sha256": signed.descriptor.payload.sha256,
        "bundle_url_expires_in": 300,
    }))
    .unwrap()
}
