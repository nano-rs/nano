// SPDX-License-Identifier: AGPL-3.0-or-later
//! NANPFB01 node platform bundle writer and shared wire pieces.
//!
//! Moved verbatim from `nanosiem-lake-worker::lean_platform_bundle` (NAN-4759)
//! so the hosted publisher can build the payload of the portable feed bundle
//! with the exact writer the hosted node bundle uses. The lake-worker reader
//! and `PlatformBundle::publish_verified` use these items unchanged; the
//! `hosted_bytes_pin` test in `lake_platform_bundle` pins the output bytes.

use anyhow::{ensure, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::File, io::Write, os::unix::fs::PermissionsExt, path::Path};

pub const MAGIC: &[u8; 8] = b"NANPFB01";
pub const MAX_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;

/// One platform IOC row of a NANPFB01 IOC section.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IocSnapshotInput {
    pub ioc_value: String,
    pub ioc_type: String,
    pub source_id: String,
    #[serde(default)]
    pub enrichment_name: String,
    #[serde(default = "default_true")]
    pub is_ioc: bool,
    #[serde(default)]
    pub threat_type: String,
    #[serde(default)]
    pub malware: String,
    #[serde(default)]
    pub confidence_level: i32,
    #[serde(default)]
    pub risk_score: Option<i32>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub data: Value,
    #[serde(default)]
    pub published_at_ms: i64,
    #[serde(default)]
    pub first_seen_at: Option<String>,
    #[serde(default)]
    pub last_seen_at: Option<String>,
}

impl Default for IocSnapshotInput {
    fn default() -> Self {
        Self {
            ioc_value: String::new(),
            ioc_type: String::new(),
            source_id: String::new(),
            enrichment_name: String::new(),
            is_ioc: true,
            threat_type: String::new(),
            malware: String::new(),
            confidence_level: 0,
            risk_score: None,
            tags: Vec::new(),
            data: Value::Null,
            published_at_ms: 0,
            first_seen_at: None,
            last_seen_at: None,
        }
    }
}

fn default_true() -> bool {
    true
}

pub fn valid_feed(feed: &str) -> bool {
    !feed.is_empty()
        && feed.len() <= 64
        && feed
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

pub fn le64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("validated packed slice"))
}

/// Validate the complete NANPACK1 prefix section before any binary search.
/// This repeats the cache's packed wire checks in the default cell build,
/// which does not include the enterprise cache module.
pub fn validate_prefix(bytes: &[u8], rows: u64) -> Result<()> {
    ensure!(
        bytes.len() >= 40
            && &bytes[..8] == b"NANPACK1"
            && bytes[8..12] == 2u32.to_le_bytes()
            && bytes[12..16] == 1u32.to_le_bytes(),
        "invalid prefix header"
    );
    let count = le64(&bytes[16..24]);
    let arena = le64(&bytes[24..32]);
    ensure!(
        count == rows
            && le64(&bytes[32..40]) == bytes.len() as u64
            && count.checked_mul(48).and_then(|n| n.checked_add(40)) == Some(arena)
            && arena <= bytes.len() as u64,
        "invalid prefix table length"
    );
    let mut previous: Option<(u64, [u8; 16], usize)> = None;
    let mut end = arena;
    for i in 0..count {
        let p = 40 + (i * 48) as usize;
        let r = &bytes[p..p + 48];
        let ko = le64(&r[..8]);
        let kl = le64(&r[8..16]);
        let vo = le64(&r[16..24]);
        let vl = le64(&r[24..32]);
        let tag = le64(&r[32..40]);
        let prefix = le64(&r[40..48]);
        ensure!(
            ko == end
                && matches!((tag, kl), (4, 4) | (6, 16))
                && prefix <= kl * 8
                && vo == ko + kl
                && vl == 8
                && vo.checked_add(vl).is_some_and(|n| n <= bytes.len() as u64),
            "invalid prefix row bounds"
        );
        let key = &bytes[ko as usize..vo as usize];
        ensure!(
            (prefix..kl * 8).all(|bit| key[(bit / 8) as usize] & (0x80 >> (bit % 8)) == 0),
            "prefix host bits set"
        );
        let value = &bytes[vo as usize..(vo + vl) as usize];
        ensure!(
            value[0] == 1
                && value[7] == 0
                && value[1..5].iter().all(|v| *v <= 2)
                && (value[5] <= 100 || value[5] == 255)
                && value[6] as u64 == prefix,
            "invalid prefix signals"
        );
        let mut fixed = [0u8; 16];
        fixed[..kl as usize].copy_from_slice(key);
        let sort = tag * 256 + prefix;
        if let Some((old_sort, old, old_len)) = previous {
            ensure!(
                (old_sort, &old[..old_len]) < (sort, key),
                "unsorted prefix rows"
            );
        }
        previous = Some((sort, fixed, kl as usize));
        end = vo + vl;
    }
    ensure!(end == bytes.len() as u64, "trailing prefix bytes");
    Ok(())
}

/// NANPFB01 JSON header.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub mmdb_len: usize,
    pub ioc_len: usize,
    #[serde(default)]
    pub prefix_len: usize,
    #[serde(default)]
    pub prefix_rows: u64,
    pub feed_revisions: BTreeMap<String, i64>,
    #[serde(default)]
    pub feed_valid_until: BTreeMap<String, DateTime<Utc>>,
}

/// Write one NANPFB01 bundle to `path` (staged sibling, 0444, fsynced, renamed)
/// and return its SHA-256. Publisher input is trusted platform feed data.
pub fn write(
    path: &Path,
    mmdb: Option<&[u8]>,
    rows: &[IocSnapshotInput],
    prefix: Option<(&[u8], u64)>,
    revisions: BTreeMap<String, i64>,
    valid_until: BTreeMap<String, DateTime<Utc>>,
) -> Result<String> {
    ensure!(
        valid_until.is_empty() || valid_until.keys().eq(revisions.keys()),
        "bundle validity does not cover exact revisions"
    );
    ensure!(
        revisions.len() <= 64 && revisions.iter().all(|(f, r)| valid_feed(f) && *r > 0),
        "invalid bundle revisions"
    );
    ensure!(
        mmdb.is_none_or(|v| !v.is_empty())
            && mmdb.is_some() == revisions.contains_key("ipinfo_lite"),
        "IPinfo revision and bytes differ"
    );
    ensure!(
        prefix.is_some() == revisions.contains_key("synthient"),
        "Synthient revision and bytes differ"
    );
    if let Some((bytes, count)) = prefix {
        ensure!(
            bytes.len() <= 120 * 1024 * 1024,
            "Synthient pack exceeds cap"
        );
        validate_prefix(bytes, count)?;
    }
    ensure!(rows.len() <= 5_000_000, "platform IOC rows exceed bound");
    let mut order = Vec::with_capacity(rows.len());
    let mut ioc_len = 0usize;
    for (index, row) in rows.iter().enumerate() {
        let value = row.ioc_value.trim().to_ascii_lowercase();
        ensure!(!value.is_empty(), "empty platform IOC value");
        ensure!(
            revisions.contains_key(&row.source_id) && value.len() <= 4096,
            "IOC has no platform revision or exceeds bound"
        );
        ensure!(
            !value.contains('\n') && !value.contains('\t'),
            "invalid IOC value"
        );
        let mut normalized = row.clone();
        normalized.ioc_value = value.clone();
        let size = serde_json::to_vec(&normalized)?.len();
        ensure!(size <= 16_384, "platform IOC row exceeds 16 KiB");
        ioc_len = ioc_len
            .checked_add(value.len() + 2 + size)
            .context("platform IOC length overflow")?;
        ensure!(
            ioc_len as u64 <= MAX_BUNDLE_BYTES,
            "platform IOC section exceeds bundle cap"
        );
        order.push((value, index));
    }
    order.sort_by(|(a, ai), (b, bi)| (a, &rows[*ai].source_id).cmp(&(b, &rows[*bi].source_id)));
    let header = serde_json::to_vec(&Header {
        mmdb_len: mmdb.map_or(0, <[u8]>::len),
        ioc_len,
        prefix_len: prefix.map_or(0, |(bytes, _)| bytes.len()),
        prefix_rows: prefix.map_or(0, |(_, count)| count),
        feed_revisions: revisions,
        feed_valid_until: valid_until,
    })?;
    ensure!(header.len() <= 16_384, "bundle header exceeds bound");
    let total = 16_u64
        + header.len() as u64
        + mmdb.map_or(0, |v| v.len()) as u64
        + ioc_len as u64
        + prefix.map_or(0, |(v, _)| v.len()) as u64;
    ensure!(total <= MAX_BUNDLE_BYTES, "platform bundle exceeds 512 MiB");
    fn chunk(file: &mut File, hash: &mut Sha256, bytes: &[u8]) -> Result<()> {
        file.write_all(bytes)?;
        hash.update(bytes);
        Ok(())
    }
    let parent = path.parent().context("bundle parent missing")?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    let mut hash = Sha256::new();
    let file = staged.as_file_mut();
    chunk(file, &mut hash, MAGIC)?;
    chunk(file, &mut hash, &(header.len() as u64).to_le_bytes())?;
    chunk(file, &mut hash, &header)?;
    if let Some(mmdb) = mmdb {
        chunk(file, &mut hash, mmdb)?;
    }
    for (value, index) in &order {
        let mut row = rows[*index].clone();
        row.ioc_value = value.clone();
        chunk(file, &mut hash, value.as_bytes())?;
        chunk(file, &mut hash, b"\t")?;
        let encoded = serde_json::to_vec(&row)?;
        chunk(file, &mut hash, &encoded)?;
        chunk(file, &mut hash, b"\n")?;
    }
    if let Some((packed, _)) = prefix {
        chunk(file, &mut hash, packed)?;
    }
    ensure!(
        file.metadata()?.len() == total,
        "bundle write length changed"
    );
    file.sync_all()?;
    file.set_permissions(std::fs::Permissions::from_mode(0o444))?;
    file.sync_all()?;
    let digest = hex::encode(hash.finalize());
    staged.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(digest)
}
