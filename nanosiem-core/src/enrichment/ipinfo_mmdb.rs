// SPDX-License-Identifier: AGPL-3.0-or-later

//! Immutable IPinfo Lite MMDB serving snapshots for the object-lake lane.
//!
//! The file is memory mapped so independent worker processes can share the
//! operating-system page cache. A mapped file must never be modified in place.
//! Publishers write a complete sibling file, validate it, and atomically rename
//! it over the configured path; existing readers retain the old inode until the
//! last request releases it.

use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use maxminddb::{Mmap, Reader};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::types::IpEnrichmentResult;

#[derive(Debug, Error)]
pub enum IpinfoMmdbError {
    #[error("IPinfo MMDB I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid IPinfo MMDB: {0}")]
    Database(#[from] maxminddb::MaxMindDbError),
    #[error("IPinfo MMDB SHA-256 must be 64 lowercase hexadecimal characters")]
    InvalidDigest,
    #[error("IPinfo MMDB digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error("invalid IP address: {0}")]
    InvalidIp(String),
    #[error("unsupported IPinfo Lite download path: {0}")]
    UnsupportedDownloadPath(String),
    #[error("invalid IPinfo Lite download URL: {0}")]
    InvalidDownloadUrl(#[from] url::ParseError),
}

#[derive(Debug, Deserialize)]
struct IpinfoLiteMmdbRecord {
    #[serde(default)]
    country: String,
    #[serde(default)]
    country_code: String,
    #[serde(default)]
    continent: String,
    #[serde(default)]
    continent_code: String,
    #[serde(default)]
    asn: String,
    #[serde(default)]
    as_name: String,
    #[serde(default)]
    as_domain: String,
}

/// One validated, immutable IPinfo database generation.
pub struct IpinfoMmdbSnapshot {
    reader: Reader<Mmap>,
    path: PathBuf,
    sha256: String,
}

impl std::fmt::Debug for IpinfoMmdbSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpinfoMmdbSnapshot")
            .field("path", &self.path)
            .field("sha256", &self.sha256)
            .field("database_type", &self.reader.metadata().database_type)
            .finish()
    }
}

impl IpinfoMmdbSnapshot {
    /// Open a versioned or atomically published immutable MMDB generation.
    pub fn open(
        path: impl AsRef<Path>,
        expected_sha256: Option<&str>,
    ) -> Result<Self, IpinfoMmdbError> {
        let path = path.as_ref().to_path_buf();
        let sha256 = sha256_file(&path)?;
        if let Some(expected) = expected_sha256 {
            validate_digest(expected)?;
            if expected != sha256 {
                return Err(IpinfoMmdbError::DigestMismatch {
                    expected: expected.to_string(),
                    actual: sha256,
                });
            }
        }

        // SAFETY: the serving contract requires an immutable, versioned file.
        // Sync writes a sibling temp file and renames it only after validation;
        // it never truncates or mutates the inode held by this Reader.
        let reader = unsafe { Reader::open_mmap(&path)? };
        Ok(Self {
            reader,
            path,
            sha256,
        })
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn lookup(&self, ip: &str) -> Result<Option<IpEnrichmentResult>, IpinfoMmdbError> {
        lookup_reader(&self.reader, ip)
    }

    /// Count published CIDR records once per sync, never on the request path.
    pub fn record_count(&self) -> Result<u64, IpinfoMmdbError> {
        let mut count = 0u64;
        for network in self.reader.networks(Default::default())? {
            network?;
            count = count.saturating_add(1);
        }
        Ok(count)
    }
}

/// Shared decoder for an already verified, leased platform mmap.
pub(crate) fn lookup_reader<S: AsRef<[u8]>>(
    reader: &Reader<S>,
    ip: &str,
) -> Result<Option<IpEnrichmentResult>, IpinfoMmdbError> {
    let address = ip
        .parse::<IpAddr>()
        .map_err(|_| IpinfoMmdbError::InvalidIp(ip.to_string()))?;
    let lookup = reader.lookup(address)?;
    let Some(record) = lookup.decode::<IpinfoLiteMmdbRecord>()? else {
        return Ok(None);
    };

    if record.country.is_empty() && record.asn.is_empty() {
        return Ok(None);
    }

    let optional = |value: String| (!value.is_empty()).then_some(value);
    Ok(Some(IpEnrichmentResult {
        source_id: Some("ipinfo_lite".to_string()),
        network: lookup.network().ok().map(|network| network.to_string()),
        country: optional(record.country),
        country_code: optional(record.country_code),
        continent: optional(record.continent),
        continent_code: optional(record.continent_code),
        asn: optional(record.asn),
        as_name: optional(record.as_name),
        as_domain: optional(record.as_domain),
    }))
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn validate_digest(digest: &str) -> Result<(), IpinfoMmdbError> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(IpinfoMmdbError::InvalidDigest)
    }
}

/// Change only the official IPinfo Lite format suffix and preserve the token.
pub fn derive_mmdb_download_url(configured: &str) -> Result<String, IpinfoMmdbError> {
    let mut url = url::Url::parse(configured)?;
    let path = url.path().to_string();
    let replacement = [
        "ipinfo_lite.csv.gz",
        "ipinfo_lite.json.gz",
        "ipinfo_lite.parquet",
    ]
    .iter()
    .find_map(|suffix| path.strip_suffix(suffix))
    .map(|prefix| format!("{prefix}ipinfo_lite.mmdb"));

    match replacement {
        Some(path) => url.set_path(&path),
        None if path.ends_with("ipinfo_lite.mmdb") => {}
        None => return Err(IpinfoMmdbError::UnsupportedDownloadPath(path)),
    }
    Ok(url.into())
}

/// Safe diagnostic form. Tokens and signed redirect query parameters never log.
pub fn redacted_download_url(configured: &str) -> String {
    url::Url::parse(configured)
        .map(|mut url| {
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        })
        .unwrap_or_else(|_| "<invalid-url>".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_url_becomes_mmdb_without_losing_query_configuration() {
        let actual = derive_mmdb_download_url(
            "https://ipinfo.io/data/ipinfo_lite.csv.gz?token=not-a-real-token",
        )
        .unwrap();
        assert_eq!(
            actual,
            "https://ipinfo.io/data/ipinfo_lite.mmdb?token=not-a-real-token"
        );
    }

    #[test]
    fn diagnostic_url_removes_credentials() {
        assert_eq!(
            redacted_download_url("https://ipinfo.io/data/ipinfo_lite.mmdb?token=secret#fragment"),
            "https://ipinfo.io/data/ipinfo_lite.mmdb"
        );
    }

    #[test]
    fn unsupported_product_is_not_silently_rewritten() {
        assert!(matches!(
            derive_mmdb_download_url("https://ipinfo.io/data/ipinfo_core.csv.gz?token=x"),
            Err(IpinfoMmdbError::UnsupportedDownloadPath(_))
        ));
    }

    #[test]
    fn corrupt_database_is_rejected_before_publication() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("corrupt.mmdb");
        std::fs::write(&path, b"not an mmdb").unwrap();
        assert!(matches!(
            IpinfoMmdbSnapshot::open(path, None),
            Err(IpinfoMmdbError::Database(_))
        ));
    }

    #[test]
    fn expected_digest_is_strictly_verified() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("corrupt.mmdb");
        std::fs::write(&path, b"content").unwrap();
        assert!(matches!(
            IpinfoMmdbSnapshot::open(path, Some(&"0".repeat(64))),
            Err(IpinfoMmdbError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn configured_ipinfo_lite_snapshot_serves_ipv4_and_ipv6() {
        let Ok(path) = std::env::var("NANO_TEST_IPINFO_MMDB_PATH") else {
            return;
        };
        let expected = std::env::var("NANO_TEST_IPINFO_MMDB_SHA256").ok();
        let snapshot = IpinfoMmdbSnapshot::open(path, expected.as_deref()).unwrap();

        let google = snapshot.lookup("8.8.8.8").unwrap().unwrap();
        assert_eq!(google.country_code.as_deref(), Some("US"));
        assert_eq!(google.as_domain.as_deref(), Some("google.com"));

        let cloudflare = snapshot.lookup("1.1.1.1").unwrap().unwrap();
        assert_eq!(cloudflare.asn.as_deref(), Some("AS13335"));

        let google_v6 = snapshot.lookup("2001:4860:4860::8888").unwrap().unwrap();
        assert_eq!(google_v6.as_domain.as_deref(), Some("google.com"));
        assert!(snapshot.record_count().unwrap() > 3_000_000);
    }
}
