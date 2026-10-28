// SPDX-License-Identifier: AGPL-3.0-or-later
//! Self-hosted platform feed status (NAN-4759 part B).
//!
//! A sovereign or open-core install keeps its node feed bundle in a local
//! bundle directory (`nanosiem_lake_worker::lean_platform_feeds` installs it).
//! `current.json` there is the hosted bundle receipt plus the self-hosted
//! provenance of each feed. This module reads it, without opening the bundle,
//! so the API can show feed age and expiry with only a read-only mount.
//!
//! Freshness never changes stored data: a feed past `hard_expiry` stops
//! stamping NEW events (the cell's reader enforces it); values already
//! stamped stay as written and are never masked on read (NAN-4168).

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

/// `current.json` schema (hosted and self-hosted alike).
pub const RECEIPT_SCHEMA: &str = "nano/platform-bundle-receipt/1";
/// `source` of a bundle installed from a portable signed import.
pub const SOURCE_PORTABLE: &str = "portable";
/// `source` of the placeholder bundle published before any import.
pub const SOURCE_EMPTY: &str = "empty";
/// A feed produced longer ago than this is reported stale. It still stamps
/// until its `hard_expiry`.
pub const STALE_AFTER_DAYS: i64 = 7;
/// Upper bound of the attribution notice that travels with the bundle.
pub const MAX_NOTICE_BYTES: u64 = 64 * 1024;
const RECEIPT_MAX_BYTES: u64 = 1024 * 1024;

/// Per-feed provenance kept in `current.json`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FeedProvenance {
    pub produced_at: DateTime<Utc>,
    pub hard_expiry: DateTime<Utc>,
    pub license_id: String,
    pub terms_revision: String,
    pub records: u64,
}

/// `current.json`: the hosted receipt fields plus self-hosted provenance
/// (absent on a hosted receipt).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BundleReceipt {
    pub schema: String,
    pub format: String,
    pub bundle_file: String,
    pub bundle_sha256: String,
    pub bundle_bytes: u64,
    pub revisions: BTreeMap<String, i64>,
    pub valid_until: BTreeMap<String, DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_sha256: Option<String>,
    /// The signed portable descriptor's sequence (strictly increasing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    /// Persist the verified signature with the atomic receipt for rollback checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_descriptor: Option<super::portable::SignedDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice_file: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub feeds: BTreeMap<String, FeedProvenance>,
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl BundleReceipt {
    /// Parse and check `current.json` bytes: it names its own bundle file and
    /// covers exactly its revisions.
    pub fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        let receipt: Self = serde_json::from_slice(bytes)?;
        anyhow::ensure!(receipt.schema == RECEIPT_SCHEMA, "unexpected bundle receipt schema");
        anyhow::ensure!(
            hex64(&receipt.bundle_sha256) && receipt.bundle_file == format!("platform-{}.nanpfb", receipt.bundle_sha256),
            "bundle receipt names another file"
        );
        anyhow::ensure!(receipt.valid_until.keys().eq(receipt.revisions.keys()), "bundle receipt validity does not cover its revisions");
        anyhow::ensure!(receipt.feeds.keys().all(|f| receipt.revisions.contains_key(f)), "bundle receipt provenance names a feed it does not carry");
        if let Some(notice) = &receipt.notice_file {
            anyhow::ensure!(notice == &format!("notice-{}.txt", receipt.bundle_sha256), "bundle receipt names another notice");
        }
        Ok(receipt)
    }

    /// `<bundle dir>/current.json`, if any. Never follows a symlink.
    pub fn read(bundle_dir: &Path) -> anyhow::Result<Option<Self>> {
        let path = bundle_dir.join("current.json");
        let meta = match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            other => other?,
        };
        anyhow::ensure!(meta.file_type().is_file() && meta.len() <= RECEIPT_MAX_BYTES, "bundle receipt must be a bounded regular file");
        Ok(Some(Self::parse(&std::fs::read(&path)?)?))
    }
}

/// Freshness of one installed feed.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedState {
    /// Stamping, produced within [`STALE_AFTER_DAYS`].
    Fresh,
    /// Still stamping, but older than [`STALE_AFTER_DAYS`]: update the bundle.
    Stale,
    /// Past `hard_expiry`: new events are no longer stamped from this feed.
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct FeedStatus {
    pub feed_id: String,
    pub name: String,
    pub revision: i64,
    pub produced_at: Option<DateTime<Utc>>,
    pub hard_expiry: DateTime<Utc>,
    pub age_seconds: Option<i64>,
    pub state: FeedState,
    pub license_id: Option<String>,
    pub terms_revision: Option<String>,
    pub records: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct FeedsStatus {
    /// This deployment keeps a local feed bundle (self-hosted).
    pub available: bool,
    /// A real feed bundle (not the empty placeholder) is installed.
    pub installed: bool,
    pub bundle_sha256: Option<String>,
    pub source: Option<String>,
    pub installed_at: Option<DateTime<Utc>>,
    pub stale_after_days: i64,
    pub feeds: Vec<FeedStatus>,
    /// Attribution that must be shown with the data (IPinfo CC BY-SA 4.0).
    pub notice: Option<String>,
}

impl FeedsStatus {
    /// No local bundle directory on this deployment (hosted, ClickHouse).
    pub fn unavailable() -> Self {
        Self {
            available: false,
            installed: false,
            bundle_sha256: None,
            source: None,
            installed_at: None,
            stale_after_days: STALE_AFTER_DAYS,
            feeds: Vec::new(),
            notice: None,
        }
    }
}

/// Product name of a platform feed id.
pub fn feed_display_name(feed: &str) -> String {
    match feed {
        "ipinfo_lite" => "IPinfo Lite",
        "threatfox" => "ThreatFox",
        "tor_exit_nodes" => "Tor exit nodes",
        "urlhaus" => "URLhaus",
        "malwarebazaar" => "MalwareBazaar",
        other => other,
    }
    .to_string()
}

/// Freshness of one feed at `now`.
pub fn feed_state(produced_at: Option<DateTime<Utc>>, hard_expiry: DateTime<Utc>, now: DateTime<Utc>) -> FeedState {
    if hard_expiry <= now {
        FeedState::Expired
    } else if produced_at.is_none_or(|at| now - at > Duration::days(STALE_AFTER_DAYS)) {
        FeedState::Stale
    } else {
        FeedState::Fresh
    }
}

/// The installed feeds of `bundle_dir` and their freshness at `now`.
pub fn status(bundle_dir: &Path, now: DateTime<Utc>) -> anyhow::Result<FeedsStatus> {
    let Some(receipt) = BundleReceipt::read(bundle_dir)? else {
        return Ok(FeedsStatus { available: true, ..FeedsStatus::unavailable() });
    };
    let notice = match &receipt.notice_file {
        Some(name) => {
            let path = bundle_dir.join(name);
            let meta = std::fs::symlink_metadata(&path)?;
            anyhow::ensure!(meta.file_type().is_file() && meta.len() <= MAX_NOTICE_BYTES, "bundle notice must be a bounded regular file");
            Some(std::fs::read_to_string(path)?)
        }
        None => None,
    };
    let feeds = receipt
        .revisions
        .iter()
        .map(|(feed, revision)| {
            let provenance = receipt.feeds.get(feed);
            let hard_expiry = receipt.valid_until[feed];
            let produced_at = provenance.map(|p| p.produced_at);
            FeedStatus {
                feed_id: feed.clone(),
                name: feed_display_name(feed),
                revision: *revision,
                produced_at,
                hard_expiry,
                age_seconds: produced_at.map(|at| (now - at).num_seconds().max(0)),
                state: feed_state(produced_at, hard_expiry, now),
                license_id: provenance.map(|p| p.license_id.clone()),
                terms_revision: provenance.map(|p| p.terms_revision.clone()),
                records: provenance.map(|p| p.records),
            }
        })
        .collect();
    Ok(FeedsStatus {
        available: true,
        installed: receipt.source.as_deref() != Some(SOURCE_EMPTY) && !receipt.revisions.is_empty(),
        bundle_sha256: Some(receipt.bundle_sha256),
        source: receipt.source,
        installed_at: receipt.installed_at,
        stale_after_days: STALE_AFTER_DAYS,
        feeds,
        notice,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_follows_age_and_hard_expiry() {
        let now = Utc::now();
        let until = now + Duration::days(30);
        assert_eq!(feed_state(Some(now - Duration::hours(1)), until, now), FeedState::Fresh);
        assert_eq!(feed_state(Some(now - Duration::days(8)), until, now), FeedState::Stale);
        assert_eq!(feed_state(None, until, now), FeedState::Stale);
        assert_eq!(feed_state(Some(now - Duration::hours(1)), now, now), FeedState::Expired);
    }

    #[test]
    fn receipt_must_name_its_own_files_and_cover_its_feeds() {
        let sha = "a".repeat(64);
        let ok = serde_json::json!({"schema": RECEIPT_SCHEMA, "format": "NANPFB01", "bundle_file": format!("platform-{sha}.nanpfb"),
            "bundle_sha256": sha, "bundle_bytes": 16, "revisions": {"threatfox": 3}, "valid_until": {"threatfox": "2030-01-01T00:00:00Z"}});
        BundleReceipt::parse(&serde_json::to_vec(&ok).unwrap()).unwrap();
        for patch in [
            serde_json::json!({"bundle_file": "platform-other.nanpfb"}),
            serde_json::json!({"valid_until": {}}),
            serde_json::json!({"notice_file": "notice-other.txt"}),
            serde_json::json!({"feeds": {"tor_exit_nodes": {"produced_at": "2026-01-01T00:00:00Z", "hard_expiry": "2030-01-01T00:00:00Z",
                "license_id": "x", "terms_revision": "1", "records": 1}}}),
        ] {
            let mut bad = ok.clone();
            for (k, v) in patch.as_object().unwrap() {
                bad[k] = v.clone();
            }
            assert!(BundleReceipt::parse(&serde_json::to_vec(&bad).unwrap()).is_err(), "{patch}");
        }
    }
}
