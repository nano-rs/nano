// SPDX-License-Identifier: AGPL-3.0-or-later
//! One immutable, node-shared mmap containing platform IPinfo and exact IOC data.
//! Tenant policy is a separate, small, process-bound projection. The publisher
//! writes a new inode and atomically changes the mounted path; readers pin an
//! inode until the next part boundary.

use anyhow::{ensure, Context, Result};
use chrono::{DateTime, Utc};
use maxminddb::Reader;
use memmap2::Mmap;
use nanosiem_core::platform_enrichment::{
    FeedClass, FeedStampV1, FreshnessAtIngest, OwnedField, PremiumStampRight, StampStatus,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    net::IpAddr,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::Arc,
};
use uuid::Uuid;

use crate::enrichment::{artifact_candidates, IocSnapshotInput};

const MAGIC: &[u8; 8] = b"NANPFB01";
const MAX_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone)]
struct MappedSection {
    map: Arc<Mmap>,
    start: usize,
    end: usize,
}
impl AsRef<[u8]> for MappedSection {
    fn as_ref(&self) -> &[u8] {
        &self.map[self.start..self.end]
    }
}

/// Authenticated upstream policy projection, mounted only into this tenant's
/// jailed ingest process. An absent or expired grant fails closed.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPlatformPolicy {
    pub tenant_id: Uuid,
    pub revision: u64,
    pub bundle_sha256: String,
    pub grants: BTreeMap<String, PlatformGrant>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformGrant {
    pub feed_revision: i64,
    pub valid_until: DateTime<Utc>,
    #[serde(default)]
    pub premium: Option<PremiumStampRight>,
}

impl TenantPlatformPolicy {
    /// Stable semantic identity: a same-revision policy replacement may not
    /// silently alter grants, even if JSON whitespace or key order changes.
    pub fn fingerprint(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(self)?)))
    }

    pub fn validate_successor(&self, previous: &Self) -> Result<()> {
        ensure!(
            self.tenant_id == previous.tenant_id && self.revision >= previous.revision,
            "platform policy tenant or revision rolled back"
        );
        if self.revision == previous.revision {
            ensure!(
                self.fingerprint()? == previous.fingerprint()?,
                "platform policy changed without revision"
            );
        }
        Ok(())
    }
    pub fn read(path: &Path, tenant: Uuid, digest: &str) -> Result<Self> {
        let policy = Self::read_for_query(path, tenant)?;
        ensure!(
            policy.bundle_sha256 == digest,
            "platform policy bundle differs"
        );
        Ok(policy)
    }

    /// Query[T] reads its private policy on every dispatch after revocations.
    pub fn read_for_query(path: &Path, tenant: Uuid) -> Result<Self> {
        ensure!(path.is_absolute(), "platform policy path must be absolute");
        let bytes = std::fs::read(path)?;
        ensure!(bytes.len() <= 16_384, "platform policy exceeds its bound");
        let policy: Self = serde_json::from_slice(&bytes)?;
        ensure!(
            policy.tenant_id == tenant && !tenant.is_nil(),
            "platform policy tenant differs from process tenant"
        );
        ensure!(
            policy.revision > 0
                && policy.revision <= i64::MAX as u64
                && policy.bundle_sha256.len() == 64
                && policy.bundle_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "platform policy bundle or revision differs"
        );
        ensure!(policy.grants.len() <= 64, "too many platform grants");
        for (feed, grant) in &policy.grants {
            ensure!(
                valid_feed(feed) && grant.feed_revision > 0,
                "invalid platform grant"
            );
            if let Some(right) = &grant.premium {
                ensure!(
                    !right.tier.is_empty()
                        && right.grant_revision > 0
                        && right.entitlement_revision > 0,
                    "invalid premium right"
                );
            }
        }
        Ok(policy)
    }

    fn grant(&self, feed: &str, now: DateTime<Utc>) -> Option<&PlatformGrant> {
        self.grants.get(feed).filter(|g| g.valid_until > now)
    }
}

#[cfg(test)]
mod policy_revision_contract_tests {
    use super::*;
    #[test]
    fn same_revision_change_and_rollback_are_refused() {
        let mut old = TenantPlatformPolicy {
            tenant_id: Uuid::new_v4(),
            revision: 7,
            bundle_sha256: "a".repeat(64),
            grants: BTreeMap::new(),
        };
        let mut changed = old.clone();
        changed.grants.insert(
            "ipinfo_lite".into(),
            PlatformGrant {
                feed_revision: 1,
                valid_until: Utc::now() + chrono::Duration::hours(1),
                premium: None,
            },
        );
        assert!(changed.validate_successor(&old).is_err());
        changed.revision = 8;
        assert!(changed.validate_successor(&old).is_ok());
        old.revision = 9;
        assert!(changed.validate_successor(&old).is_err());
        changed.tenant_id = Uuid::new_v4();
        changed.revision = 10;
        assert!(changed.validate_successor(&old).is_err());
    }
}

fn valid_feed(feed: &str) -> bool {
    !feed.is_empty()
        && feed.len() <= 64
        && feed
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn le64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("validated packed slice"))
}

/// Validate the complete NANPACK1 prefix section before any binary search.
/// This repeats the cache's packed wire checks in the default cell build,
/// which does not include the enterprise cache module.
fn validate_prefix(bytes: &[u8], rows: u64) -> Result<()> {
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

fn prefix_lookup(bytes: &[u8], address: IpAddr) -> Option<&[u8]> {
    let mut raw = [0u8; 16];
    let (tag, len) = match address {
        IpAddr::V4(ip) => {
            raw[..4].copy_from_slice(&ip.octets());
            (4u64, 4usize)
        }
        IpAddr::V6(ip) => {
            raw.copy_from_slice(&ip.octets());
            (6u64, 16usize)
        }
    };
    let mut masked = raw;
    for prefix in (0..=len * 8).rev() {
        let mut lo = 0u64;
        let mut hi = le64(&bytes[16..24]);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let p = 40 + (mid * 48) as usize;
            let row = &bytes[p..p + 48];
            let ko = le64(&row[..8]) as usize;
            let kl = le64(&row[8..16]) as usize;
            let order = (
                le64(&row[32..40]) * 256 + le64(&row[40..48]),
                &bytes[ko..ko + kl],
            )
                .cmp(&(tag * 256 + prefix as u64, &masked[..len]));
            match order {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => {
                    let vo = le64(&row[16..24]) as usize;
                    return Some(&bytes[vo..vo + 8]);
                }
            }
        }
        if prefix > 0 {
            masked[(prefix - 1) / 8] &= !(0x80 >> ((prefix - 1) % 8));
        }
    }
    None
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_multicast()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_unspecified())
        }
        IpAddr::V6(v) => {
            !(v.is_loopback()
                || v.is_unique_local()
                || v.is_unicast_link_local()
                || v.is_multicast()
                || v.is_unspecified())
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    mmdb_len: usize,
    ioc_len: usize,
    #[serde(default)]
    prefix_len: usize,
    #[serde(default)]
    prefix_rows: u64,
    feed_revisions: BTreeMap<String, i64>,
    #[serde(default)]
    feed_valid_until: BTreeMap<String, DateTime<Utc>>,
}

#[derive(Deserialize)]
struct LiteRecord {
    #[serde(default)]
    country: String,
    #[serde(default)]
    continent: String,
    #[serde(default)]
    continent_code: String,
    #[serde(default)]
    as_name: String,
    #[serde(default)]
    as_domain: String,
    #[serde(default)]
    country_code: String,
    #[serde(default)]
    asn: String,
}

/// Bundle feeds that are not exact-match IOC sections.
const NON_IOC_FEEDS: [&str; 2] = ["ipinfo_lite", "synthient"];

/// Human-readable name for a platform feed id, as the product names it.
pub fn platform_feed_display_name(feed: &str) -> String {
    match feed {
        "threatfox" => "ThreatFox".to_string(),
        "tor_exit_nodes" => "Tor exit nodes".to_string(),
        "urlhaus" => "URLhaus".to_string(),
        "malwarebazaar" => "MalwareBazaar".to_string(),
        other => other.to_string(),
    }
}

/// One granted platform IOC row with the grant that admits it.
struct GrantedIoc<'a> {
    row: IocSnapshotInput,
    grant: &'a PlatformGrant,
    source_until: Option<DateTime<Utc>>,
}

pub struct PlatformBundle {
    map: Arc<Mmap>,
    mmdb: Option<Reader<MappedSection>>,
    ioc_start: usize,
    ioc_end: usize,
    prefix_start: usize,
    prefix_end: usize,
    revisions: BTreeMap<String, i64>,
    valid_until: BTreeMap<String, DateTime<Utc>>,
    digest: String,
}

impl PlatformBundle {
    /// Publisher input is trusted platform feed data. The output is one file;
    /// readers never decode the feed into tenant-private heap maps.
    pub fn publish(
        path: &Path,
        mmdb: Option<&[u8]>,
        rows: &[IocSnapshotInput],
        revisions: BTreeMap<String, i64>,
    ) -> Result<String> {
        Self::publish_with_prefix(path, mmdb, rows, None, revisions)
    }

    pub fn publish_with_prefix(
        path: &Path,
        mmdb: Option<&[u8]>,
        rows: &[IocSnapshotInput],
        prefix: Option<(&[u8], u64)>,
        revisions: BTreeMap<String, i64>,
    ) -> Result<String> {
        Self::publish_verified(path, mmdb, rows, prefix, revisions, BTreeMap::new())
    }

    pub fn publish_verified(
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

    pub fn open(path: &Path, expected_sha256: &str) -> Result<Self> {
        ensure!(
            expected_sha256.len() == 64 && expected_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid platform bundle digest"
        );
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        ensure!(
            (16..=MAX_BUNDLE_BYTES).contains(&size),
            "invalid platform bundle size"
        );
        // Hash through the opened inode before mapping. Hashing `&map[..]`
        // faults every bundle page into this tenant's RSS, even when lookups
        // touch only a few IOC lines. The publisher keeps each inode immutable.
        let mut reader = &file;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut read_bytes = 0_u64;
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            read_bytes += n as u64;
            ensure!(
                read_bytes <= MAX_BUNDLE_BYTES,
                "platform bundle grew while hashing"
            );
            hasher.update(&buffer[..n]);
        }
        ensure!(
            read_bytes == size,
            "platform bundle size changed while hashing"
        );
        let actual = hex::encode(hasher.finalize());
        ensure!(actual == expected_sha256, "platform bundle digest mismatch");
        // SAFETY: publisher creates a complete sibling inode then renames it;
        // the mounted bundle inode is immutable while this mapping is live.
        let map = Arc::new(unsafe { Mmap::map(&file)? });
        ensure!(&map[..8] == MAGIC, "invalid platform bundle magic");
        let header_len = u64::from_le_bytes(map[8..16].try_into()?) as usize;
        ensure!(
            header_len <= 16_384 && 16 + header_len <= map.len(),
            "invalid platform bundle header"
        );
        let header: Header = serde_json::from_slice(&map[16..16 + header_len])?;
        ensure!(
            header.feed_valid_until.is_empty()
                || header
                    .feed_valid_until
                    .keys()
                    .eq(header.feed_revisions.keys()),
            "bundle validity and revisions differ"
        );
        let mmdb_start = 16 + header_len;
        let ioc_start = mmdb_start
            .checked_add(header.mmdb_len)
            .context("bundle length overflow")?;
        let ioc_end = ioc_start
            .checked_add(header.ioc_len)
            .context("bundle length overflow")?;
        let prefix_end = ioc_end
            .checked_add(header.prefix_len)
            .context("prefix length overflow")?;
        ensure!(prefix_end == map.len(), "platform bundle length mismatch");
        ensure!(
            (header.prefix_len > 0) == header.feed_revisions.contains_key("synthient"),
            "Synthient bundle section differs from revision"
        );
        if header.prefix_len > 0 {
            validate_prefix(&map[ioc_end..prefix_end], header.prefix_rows)?;
        }
        let mmdb = if header.mmdb_len == 0 {
            None
        } else {
            Some(Reader::from_source(MappedSection {
                map: map.clone(),
                start: mmdb_start,
                end: ioc_start,
            })?)
        };
        ensure!(
            mmdb.is_some() == header.feed_revisions.contains_key("ipinfo_lite"),
            "invalid IPinfo bundle section"
        );
        let lines = &map[ioc_start..ioc_end];
        ensure!(
            lines.is_empty() || lines.last() == Some(&b'\n'),
            "unterminated platform IOC section"
        );
        Ok(Self {
            map,
            mmdb,
            ioc_start,
            ioc_end,
            prefix_start: ioc_end,
            prefix_end,
            revisions: header.feed_revisions,
            valid_until: header.feed_valid_until,
            digest: actual,
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn bytes(&self) -> usize {
        self.map.len()
    }

    fn grant<'a>(
        &self,
        policy: &'a TenantPlatformPolicy,
        feed: &str,
        now: DateTime<Utc>,
    ) -> Option<&'a PlatformGrant> {
        if self
            .valid_until
            .get(feed)
            .is_some_and(|until| *until <= now)
        {
            return None;
        }
        policy.grant(feed, now)
    }

    fn lookup_ioc(&self, value: &str) -> Result<Vec<IocSnapshotInput>> {
        let bytes = &self.map[self.ioc_start..self.ioc_end];
        let mut lo = 0usize;
        let mut hi = bytes.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let start = bytes[..mid]
                .iter()
                .rposition(|b| *b == b'\n')
                .map_or(0, |n| n + 1);
            let end = bytes[mid..]
                .iter()
                .position(|b| *b == b'\n')
                .map_or(bytes.len(), |n| mid + n);
            let key_end = bytes[start..end]
                .iter()
                .position(|b| *b == b'\t')
                .context("invalid IOC row")?
                + start;
            match bytes[start..key_end].cmp(value.as_bytes()) {
                std::cmp::Ordering::Less => lo = end.saturating_add(1),
                _ => hi = start,
            }
        }
        let mut out = Vec::new();
        let mut cursor = lo;
        while cursor < bytes.len() {
            let end = bytes[cursor..]
                .iter()
                .position(|b| *b == b'\n')
                .map(|n| cursor + n)
                .context("invalid IOC row")?;
            let tab = bytes[cursor..end]
                .iter()
                .position(|b| *b == b'\t')
                .map(|n| cursor + n)
                .context("invalid IOC row")?;
            if &bytes[cursor..tab] != value.as_bytes() {
                break;
            }
            ensure!(out.len() < 64, "platform IOC match cap exceeded");
            out.push(serde_json::from_slice(&bytes[tab + 1..end])?);
            cursor = end + 1;
        }
        Ok(out)
    }

    /// Every live platform IOC row for one normalized value that this
    /// tenant's policy grants at the revision the bundle carries. The single
    /// grant/revision/expiry gate shared by ingest stamping ([`Self::stamp`])
    /// and the on-demand lookup ([`Self::lookup_indicator`]), so the two can
    /// never disagree about which baseline feeds a tenant has (NAN-3881).
    fn granted_ioc_rows<'a>(
        &self,
        policy: &'a TenantPlatformPolicy,
        value: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<GrantedIoc<'a>>> {
        let mut out = Vec::new();
        for row in self.lookup_ioc(value)? {
            if row
                .data
                .get("effective_valid_until")
                .and_then(Value::as_i64)
                .is_some_and(|until| until <= now.timestamp())
            {
                continue;
            }
            if let Some(expiry) = row.data.get("indicator_expires_at").and_then(Value::as_str) {
                let expiry =
                    DateTime::parse_from_rfc3339(expiry).context("invalid platform IOC expiry")?;
                if expiry <= now {
                    continue;
                }
            }
            let Some(grant) = self.grant(policy, &row.source_id, now) else {
                continue;
            };
            if self.revisions.get(&row.source_id) != Some(&grant.feed_revision) {
                continue;
            }
            let mut source_until = self.valid_until.get(&row.source_id).copied();
            if let Some(record_until) = row
                .data
                .get("effective_valid_until")
                .and_then(Value::as_i64)
                .and_then(|s| DateTime::from_timestamp(s, 0))
            {
                source_until = Some(source_until.map_or(record_until, |v| v.min(record_until)));
            }
            out.push(GrantedIoc { row, grant, source_until });
        }
        Ok(out)
    }

    /// The exact-match IOC feeds in this bundle (every feed but the IPinfo
    /// and Synthient sections) that `policy` grants now at the bundle's
    /// revision: the platform IOC feeds ingest stamping matches for this
    /// tenant. Sorted feed ids. Never another tenant's: the policy is the
    /// process tenant's own projection (NAN-3881).
    pub fn granted_ioc_feeds(
        &self,
        policy: &TenantPlatformPolicy,
        now: DateTime<Utc>,
    ) -> Result<Vec<String>> {
        ensure!(
            policy.bundle_sha256 == self.digest,
            "platform policy and bundle differ"
        );
        Ok(self
            .revisions
            .iter()
            .filter(|(feed, _)| !NON_IOC_FEEDS.contains(&feed.as_str()))
            .filter(|(feed, revision)| {
                self.grant(policy, feed, now)
                    .is_some_and(|grant| grant.feed_revision == **revision)
            })
            .map(|(feed, _)| feed.clone())
            .collect())
    }

    /// On-demand point lookup of one value in the platform IOC feeds this
    /// tenant is granted, through the same gate as ingest stamping. The value
    /// is normalized as ingest normalizes artifact candidates.
    pub fn lookup_indicator(
        &self,
        policy: &TenantPlatformPolicy,
        value: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<IocSnapshotInput>> {
        ensure!(
            policy.bundle_sha256 == self.digest,
            "platform policy and bundle differ"
        );
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() || value.len() > 4096 || value.contains(['\n', '\t']) {
            return Ok(Vec::new());
        }
        Ok(self
            .granted_ioc_rows(policy, &value, now)?
            .into_iter()
            .map(|granted| granted.row)
            .collect())
    }

    pub fn stamp(
        &self,
        event: &mut Map<String, Value>,
        policy: &TenantPlatformPolicy,
        now: DateTime<Utc>,
    ) -> Result<()> {
        ensure!(
            policy.bundle_sha256 == self.digest,
            "platform policy and bundle differ"
        );
        let candidates = artifact_candidates(event);
        let mut stamps = Vec::new();
        if let (Some(mmdb), Some(grant)) = (&self.mmdb, self.grant(policy, "ipinfo_lite", now)) {
            if self.revisions.get("ipinfo_lite") == Some(&grant.feed_revision) {
                for endpoint_name in ["src_endpoint", "dst_endpoint"] {
                    let ip = event
                        .get(endpoint_name)
                        .and_then(Value::as_object)
                        .and_then(|e| e.get("ip"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let Ok(address) = ip.parse::<IpAddr>() else {
                        continue;
                    };
                    if !public_ip(address) {
                        continue;
                    }
                    let Some(geo) = mmdb.lookup(address)?.decode::<LiteRecord>()? else {
                        continue;
                    };
                    let mut owned = Vec::new();
                    let endpoint = event
                        .get_mut(endpoint_name)
                        .and_then(Value::as_object_mut)
                        .context("endpoint changed shape")?;
                    if !geo.country_code.is_empty() {
                        let location = child(endpoint, "location")?;
                        if !location.contains_key("country") {
                            location.insert("country".into(), json!(geo.country_code));
                            owned.push(if endpoint_name == "src_endpoint" {
                                OwnedField::SrcCountry
                            } else {
                                OwnedField::DstCountry
                            });
                        }
                    }
                    if !geo.continent.is_empty() {
                        let location = child(endpoint, "location")?;
                        if !location.contains_key("continent") {
                            location.insert("continent".into(), json!(geo.continent));
                            owned.push(if endpoint_name == "src_endpoint" {
                                OwnedField::SrcContinent
                            } else {
                                OwnedField::DstContinent
                            });
                        }
                    }
                    if !geo.as_name.is_empty() {
                        let system = child(endpoint, "autonomous_system")?;
                        if !system.contains_key("name") {
                            system.insert("name".into(), json!(geo.as_name));
                            owned.push(if endpoint_name == "src_endpoint" {
                                OwnedField::SrcAsName
                            } else {
                                OwnedField::DstAsName
                            });
                        }
                    }
                    if let Ok(asn) = geo.asn.trim_start_matches("AS").parse::<u32>() {
                        let system = child(endpoint, "autonomous_system")?;
                        if !system.contains_key("number") {
                            system.insert("number".into(), json!(asn));
                            owned.push(if endpoint_name == "src_endpoint" {
                                OwnedField::SrcAsn
                            } else {
                                OwnedField::DstAsn
                            });
                        }
                    }
                    stamps.push(stamp_record(
                        "ipinfo_lite",
                        &format!("{endpoint_name}.ip"),
                        &ip,
                        grant,
                        self.valid_until.get("ipinfo_lite").copied(),
                        &self.digest,
                        now,
                        owned,
                        "geoip",
                        // OCSF has no dedicated leaves for these Lite attributes.
                        // Keep them on the subject-bound, authorized stamp.
                        json!({"country_name": geo.country, "continent_code": geo.continent_code,
                            "as_domain": geo.as_domain}),
                    )?);
                }
            }
        }
        if self.prefix_end > self.prefix_start {
            if let Some(grant) = self
                .grant(policy, "synthient", now)
                .filter(|g| g.premium.is_some())
            {
                if self.revisions.get("synthient") == Some(&grant.feed_revision) {
                    let packed = &self.map[self.prefix_start..self.prefix_end];
                    for endpoint_name in ["src_endpoint", "dst_endpoint"] {
                        let Some(ip) = event
                            .get(endpoint_name)
                            .and_then(Value::as_object)
                            .and_then(|e| e.get("ip"))
                            .and_then(Value::as_str)
                        else {
                            continue;
                        };
                        let Ok(address) = ip.parse::<IpAddr>() else {
                            continue;
                        };
                        if !public_ip(address) {
                            continue;
                        }
                        let Some(raw) = prefix_lookup(packed, address) else {
                            continue;
                        };
                        stamps.push(stamp_record(
                            "synthient",
                            endpoint_name,
                            ip,
                            grant,
                            self.valid_until.get("synthient").copied(),
                            &self.digest,
                            now,
                            Vec::new(),
                            "network_risk",
                            json!({
                                "vpn": (raw[1] != 0).then_some(raw[1] == 2),
                                "proxy": (raw[2] != 0).then_some(raw[2] == 2),
                                "residential_proxy": (raw[3] != 0).then_some(raw[3] == 2),
                                "bot": (raw[4] != 0).then_some(raw[4] == 2),
                                "confidence": (raw[5] != 255).then_some(raw[5]), "prefix": raw[6]
                            }),
                        )?);
                    }
                }
            }
        }
        for (field, value) in candidates {
            for GrantedIoc { row, grant, source_until } in self.granted_ioc_rows(policy, &value, now)? {
                stamps.push(stamp_record(&row.source_id, &field, &value, grant,
                    source_until, &self.digest, now, Vec::new(), "threat_intelligence", json!({
                    "matched_field": field, "ioc_type": row.ioc_type, "threat_type": row.threat_type,
                    "confidence": row.confidence_level, "risk_score": row.risk_score, "tags": row.tags,
                    "record": row.data
                }))?);
            }
        }
        if !stamps.is_empty() {
            event
                .entry("enrichments")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .context("enrichments must be array")?
                .extend(stamps);
        }
        Ok(())
    }
}

fn child<'a>(parent: &'a mut Map<String, Value>, key: &str) -> Result<&'a mut Map<String, Value>> {
    parent
        .entry(key)
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .context("endpoint child is not an object")
}

fn stamp_record(
    feed: &str,
    field: &str,
    value: &str,
    grant: &PlatformGrant,
    source_valid_until: Option<DateTime<Utc>>,
    digest: &str,
    now: DateTime<Utc>,
    owned: Vec<OwnedField>,
    kind: &str,
    extra: Value,
) -> Result<Value> {
    let stamp = FeedStampV1 {
        contract_version: 1,
        feed_id: feed.to_string(),
        feed_class: if grant.premium.is_some() {
            FeedClass::Premium
        } else {
            FeedClass::Baseline
        },
        feed_revision_id: Some(grant.feed_revision),
        payload_digest: Some(digest.to_string()),
        mapping_revision: Some(1),
        admitted_at: now,
        upstream_at: Some(now),
        valid_until: Some(
            source_valid_until.map_or(grant.valid_until, |v| v.min(grant.valid_until)),
        ),
        freshness_at_ingest: FreshnessAtIngest::Fresh,
        status: StampStatus::Match,
        reason: None,
        owned_fields: owned,
        premium: grant.premium.clone(),
    };
    stamp.validate()?;
    let mut data = serde_json::to_value(stamp)?;
    if let Some(extra) = extra.as_object() {
        data.as_object_mut().unwrap().extend(extra.clone());
    }
    Ok(
        json!({"name":field,"value":value,"provider":format!("platform/{feed}"),"type":kind,"data":data}),
    )
}

/// Apply fresh tenant rights to a row read from a signed part. This same
/// operation is available to query[T] after its route lands.
pub fn mask_event(
    event: &mut Value,
    policy: &TenantPlatformPolicy,
    now: DateTime<Utc>,
) -> Result<()> {
    let object = event.as_object_mut().context("OCSF event must be object")?;
    let Some(Value::Array(records)) = object.get_mut("enrichments") else {
        return Ok(());
    };
    let mut revoked = Vec::new();
    records.retain(|record| {
        let Some(feed) = record
            .get("provider")
            .and_then(Value::as_str)
            .and_then(|v| v.strip_prefix("platform/"))
        else {
            return true;
        };
        let data = &record["data"];
        let allowed = policy.grant(feed, now).is_some_and(|grant| {
            data["feed_revision_id"].as_i64() == Some(grant.feed_revision)
                && data["valid_until"]
                    .as_str()
                    .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                    .is_some_and(|t| t > now)
                && match &grant.premium {
                    Some(right) => {
                        data["premium"]["entitlement_revision"].as_i64()
                            == Some(right.entitlement_revision)
                            && data["premium"]["grant_revision"].as_i64()
                                == Some(right.grant_revision)
                            && data["premium"]["tier"].as_str() == Some(right.tier.as_str())
                    }
                    None => data["premium"].is_null(),
                }
        });
        if !allowed {
            if let Some(fields) = data["owned_fields"].as_array() {
                revoked.extend(fields.iter().filter_map(Value::as_str).map(str::to_string));
            }
        }
        allowed
    });
    for field in revoked {
        let mut parts = field.split('.');
        if let (Some(endpoint), Some(child), Some(leaf)) =
            (parts.next(), parts.next(), parts.next())
        {
            if let Some(map) = object
                .get_mut(endpoint)
                .and_then(Value::as_object_mut)
                .and_then(|e| e.get_mut(child))
                .and_then(Value::as_object_mut)
            {
                map.remove(leaf);
            }
        }
    }
    Ok(())
}

/// Where a cell process finds the node-shared platform bundle.
///
/// - `File`: the legacy fixed path (`platform_bundle_file`); every bundle
///   update needs a config re-render.
/// - `Dir`: a directory of content-addressed `platform-<sha256>.nanpfb`
///   files (`platform_bundle_dir`). The tenant policy is the only authority
///   that selects one: its `bundle_sha256` names the file, the file's content
///   hash must equal that name, and `TenantPlatformPolicy::validate_successor`
///   keeps the selection monotonic in the policy revision. A bundle carries
///   no signature the cell can verify on its own (its feed manifests are
///   signed by a ring the cell does not hold), so nothing is ever chosen by
///   directory listing, mtime or the bundle's unsigned header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlatformBundleSource {
    File(std::path::PathBuf),
    Dir(std::path::PathBuf),
}

/// `platform-<64 lowercase hex>.nanpfb`.
pub fn bundle_file_name(digest: &str) -> Result<String> {
    ensure!(
        digest.len() == 64 && digest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "platform bundle digest must be 64 lowercase hex"
    );
    Ok(format!("platform-{digest}.nanpfb"))
}

impl PlatformBundleSource {
    /// Exactly one of the two assignment fields, or neither.
    pub fn from_paths(file: Option<&Path>, dir: Option<&Path>) -> Result<Option<Self>> {
        match (file, dir) {
            (None, None) => Ok(None),
            (Some(file), None) => {
                ensure!(file.is_absolute(), "platform bundle file must be absolute");
                Ok(Some(Self::File(file.to_path_buf())))
            }
            (None, Some(dir)) => {
                ensure!(dir.is_absolute(), "platform bundle dir must be absolute");
                Ok(Some(Self::Dir(dir.to_path_buf())))
            }
            (Some(_), Some(_)) => anyhow::bail!("platform bundle file and dir are mutually exclusive"),
        }
    }

    /// The path the policy digest selects (not yet verified).
    pub fn path_for(&self, digest: &str) -> Result<std::path::PathBuf> {
        match self {
            Self::File(path) => Ok(path.clone()),
            Self::Dir(dir) => Ok(dir.join(bundle_file_name(digest)?)),
        }
    }

    /// Open and verify the bundle the policy names. In `Dir` mode the file
    /// must be a direct, read-only, regular (not symlinked) entry whose
    /// content hash equals its name; anything else is refused.
    pub fn open(&self, digest: &str) -> Result<PlatformBundle> {
        let path = self.path_for(digest)?;
        if let Self::Dir(_) = self {
            let meta = std::fs::symlink_metadata(&path)
                .with_context(|| format!("platform bundle {} is missing", path.display()))?;
            ensure!(meta.file_type().is_file(), "platform bundle must be a regular file, not a symlink");
            ensure!(meta.permissions().mode() & 0o222 == 0, "platform bundle inode must be read-only");
        }
        let bundle = PlatformBundle::open(&path, digest)?;
        ensure!(bundle.digest() == digest, "platform bundle digest differs from its name");
        Ok(bundle)
    }
}

#[cfg(test)]
mod bundle_source_tests {
    use super::*;

    fn publish(dir: &Path, feed_revision: i64) -> String {
        let staging = dir.join(format!(".staging-{feed_revision}"));
        let row = IocSnapshotInput {
            ioc_value: format!("10.0.0.{feed_revision}"),
            ioc_type: "ip".into(),
            source_id: "threatfox".into(),
            ..Default::default()
        };
        let digest = PlatformBundle::publish(&staging, None, &[row], BTreeMap::from([("threatfox".into(), feed_revision)])).unwrap();
        std::fs::rename(&staging, dir.join(bundle_file_name(&digest).unwrap())).unwrap();
        digest
    }

    #[test]
    fn dir_selects_exactly_the_policy_named_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let old = publish(tmp.path(), 1);
        let new = publish(tmp.path(), 2);
        std::fs::write(tmp.path().join("current.json"), b"{}").unwrap();
        let source = PlatformBundleSource::Dir(tmp.path().to_path_buf());
        assert_eq!(source.open(&old).unwrap().digest(), old);
        assert_eq!(source.open(&new).unwrap().digest(), new);
        // A digest with no file, and a non-canonical digest, are refused.
        assert!(source.open(&"0".repeat(64)).is_err());
        assert!(source.open(&new.to_ascii_uppercase()).is_err());
        assert!(source.open("../etc/passwd").is_err());
    }

    #[test]
    fn dir_refuses_content_that_does_not_match_its_name() {
        let tmp = tempfile::tempdir().unwrap();
        let real = publish(tmp.path(), 1);
        let forged = "f".repeat(64);
        std::fs::copy(tmp.path().join(bundle_file_name(&real).unwrap()), tmp.path().join(bundle_file_name(&forged).unwrap())).unwrap();
        let path = tmp.path().join(bundle_file_name(&forged).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let source = PlatformBundleSource::Dir(tmp.path().to_path_buf());
        let error = source.open(&forged).err().unwrap();
        assert!(format!("{error:#}").contains("digest mismatch"), "{error:#}");
    }

    #[test]
    fn dir_refuses_symlinks_and_writable_inodes() {
        let tmp = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let digest = publish(other.path(), 1);
        std::os::unix::fs::symlink(other.path().join(bundle_file_name(&digest).unwrap()), tmp.path().join(bundle_file_name(&digest).unwrap())).unwrap();
        let source = PlatformBundleSource::Dir(tmp.path().to_path_buf());
        assert!(source.open(&digest).is_err(), "symlinked bundle must be refused");
        let local = publish(tmp.path(), 2);
        let path = tmp.path().join(bundle_file_name(&local).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(source.open(&local).is_err(), "writable bundle must be refused");
    }

    #[test]
    fn file_and_dir_are_mutually_exclusive() {
        let p = Path::new("/feeds/platform.bundle");
        let d = Path::new("/feeds");
        assert_eq!(PlatformBundleSource::from_paths(None, None).unwrap(), None);
        assert_eq!(PlatformBundleSource::from_paths(Some(p), None).unwrap(), Some(PlatformBundleSource::File(p.into())));
        assert_eq!(PlatformBundleSource::from_paths(None, Some(d)).unwrap(), Some(PlatformBundleSource::Dir(d.into())));
        assert!(PlatformBundleSource::from_paths(Some(p), Some(d)).is_err());
        assert!(PlatformBundleSource::from_paths(None, Some(Path::new("feeds"))).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_packed_expiry_overrides_later_upstream_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle");
        let now = Utc::now();
        let row = IocSnapshotInput {
            ioc_value: "8.8.8.8".into(),
            ioc_type: "ip".into(),
            source_id: "threatfox".into(),
            data: json!({"effective_valid_until": now.timestamp() - 1,
                "indicator_expires_at": (now + chrono::Duration::days(30)).to_rfc3339()}),
            ..Default::default()
        };
        let digest = PlatformBundle::publish(
            &path,
            None,
            &[row],
            BTreeMap::from([("threatfox".into(), 1)]),
        )
        .unwrap();
        let bundle = PlatformBundle::open(&path, &digest).unwrap();
        let policy = TenantPlatformPolicy {
            tenant_id: Uuid::new_v4(),
            revision: 1,
            bundle_sha256: digest,
            grants: BTreeMap::from([(
                "threatfox".into(),
                PlatformGrant {
                    feed_revision: 1,
                    valid_until: now + chrono::Duration::hours(1),
                    premium: None,
                },
            )]),
        };
        let mut event = json!({"src_endpoint":{"ip":"8.8.8.8"}})
            .as_object()
            .unwrap()
            .clone();
        bundle.stamp(&mut event, &policy, now).unwrap();
        assert!(event.get("enrichments").is_none());
    }

    #[test]
    fn prefix_pack_is_readable_in_default_cell_build_only_with_premium_policy() {
        let dir = tempfile::tempdir().unwrap();
        let mut packed = Vec::new();
        packed.extend(b"NANPACK1");
        packed.extend(2u32.to_le_bytes());
        packed.extend(1u32.to_le_bytes());
        for n in [1u64, 88, 100] {
            packed.extend(n.to_le_bytes());
        }
        for n in [88u64, 4, 92, 8, 4, 24] {
            packed.extend(n.to_le_bytes());
        }
        packed.extend([8, 8, 8, 0]);
        packed.extend([1, 2, 1, 0, 0, 80, 24, 0]);
        let path = dir.path().join("bundle");
        let digest = PlatformBundle::publish_with_prefix(
            &path,
            None,
            &[],
            Some((&packed, 1)),
            BTreeMap::from([("synthient".into(), 3)]),
        )
        .unwrap();
        let bundle = PlatformBundle::open(&path, &digest).unwrap();
        let now = Utc::now();
        let grant = PlatformGrant {
            feed_revision: 3,
            valid_until: now + chrono::Duration::hours(1),
            premium: Some(PremiumStampRight {
                tier: "fixture".into(),
                grant_revision: 1,
                entitlement_revision: 1,
            }),
        };
        let mut policy = TenantPlatformPolicy {
            tenant_id: Uuid::new_v4(),
            revision: 1,
            bundle_sha256: digest,
            grants: BTreeMap::from([("synthient".into(), grant)]),
        };
        let mut event = json!({"src_endpoint":{"ip":"8.8.8.8"}})
            .as_object()
            .unwrap()
            .clone();
        bundle.stamp(&mut event, &policy, now).unwrap();
        assert_eq!(event["enrichments"][0]["data"]["vpn"], true);
        policy.grants.clear();
        let mut event = json!({"src_endpoint":{"ip":"8.8.8.8"}})
            .as_object()
            .unwrap()
            .clone();
        bundle.stamp(&mut event, &policy, now).unwrap();
        assert!(event.get("enrichments").is_none());
    }

    fn mmdb_bytes() -> Vec<u8> {
        fn text(s: &str) -> Vec<u8> {
            [vec![0x40 | s.len() as u8], s.as_bytes().to_vec()].concat()
        }
        fn uint(n: u64, kind: u8) -> Vec<u8> {
            let bytes = n.to_be_bytes();
            let i = bytes.iter().position(|b| *b != 0).unwrap_or(7);
            let mut out = if kind < 8 {
                vec![(kind << 5) | (8 - i) as u8]
            } else {
                vec![(8 - i) as u8, kind - 7]
            };
            out.extend(&bytes[i..]);
            out
        }
        fn map(pairs: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
            let mut out = vec![0xe0 | pairs.len() as u8];
            for (k, v) in pairs {
                out.extend(text(k));
                out.extend(v);
            }
            out
        }
        let us = map(vec![
            ("country", text("United States")),
            ("country_code", text("US")),
            ("asn", text("AS64500")),
            ("as_name", text("Fixture network")),
            ("as_domain", text("fixture.example")),
            ("continent", text("North America")),
            ("continent_code", text("NA")),
        ]);
        let ca = map(vec![
            ("country", text("Canada")),
            ("country_code", text("CA")),
            ("asn", text("AS64501")),
        ]);
        let a = 18_u32;
        let b = a + us.len() as u32;
        let mut bytes = Vec::new();
        for pointer in [1, b, a, b] {
            bytes.extend(&pointer.to_be_bytes()[1..]);
        }
        bytes.extend([0; 16]);
        bytes.extend(us);
        bytes.extend(ca);
        bytes.extend(b"\xab\xcd\xefMaxMind.com");
        bytes.extend(map(vec![
            ("node_count", uint(2, 6)),
            ("record_size", uint(24, 5)),
            ("ip_version", uint(6, 5)),
            ("database_type", text("ipinfo_lite")),
            ("languages", vec![1, 4, 0x42, b'e', b'n']),
            ("binary_format_major_version", uint(2, 5)),
            ("binary_format_minor_version", uint(0, 5)),
            ("build_epoch", uint(1_799_999_000, 9)),
            ("description", map(vec![("en", text("fixture"))])),
        ]));
        bytes
    }

    fn lite_part_fixture(dir: &Path) -> (Value, TenantPlatformPolicy, std::path::PathBuf) {
        use crate::part_ingest::schema::{decode, infer_schema};
        let bundle_path = dir.join("platform.bundle");
        let digest = PlatformBundle::publish(&bundle_path, Some(&mmdb_bytes()), &[],
            BTreeMap::from([("ipinfo_lite".into(), 1)])).unwrap();
        let policy = TenantPlatformPolicy {
            tenant_id: Uuid::nil(), revision: 1, bundle_sha256: digest.clone(),
            grants: BTreeMap::from([("ipinfo_lite".into(), PlatformGrant {
                feed_revision: 1, valid_until: Utc::now() + chrono::Duration::hours(1), premium: None,
            })]),
        };
        let enricher = crate::enrichment::BronzeIngestEnricher::disabled()
            .with_lean_platform(Arc::new(PlatformBundle::open(&bundle_path, &digest).unwrap()), policy.clone());
        let mut event = json!({"time":"2026-10-01T12:00:00Z",
            "src_endpoint":{"ip":"8.8.8.8"}, "dst_endpoint":{"ip":"8.8.8.8"}});
        enricher.enrich(&mut event, &mut enricher.initial_metrics()).unwrap();
        let schema = Arc::new(infer_schema(&[&event]).unwrap());
        let batch = decode(schema.clone(), &[&event]).unwrap();
        let path = dir.join("part.parquet");
        let mut writer = parquet::arrow::ArrowWriter::try_new(
            std::fs::File::create(&path).unwrap(), schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        (event, policy, path)
    }

    fn assert_lite_attributes(event: &Value) {
        for endpoint in ["src_endpoint", "dst_endpoint"] {
            assert_eq!(event[endpoint]["autonomous_system"]["number"], 64500);
            assert_eq!(event[endpoint]["autonomous_system"]["name"], "Fixture network");
            assert_eq!(event[endpoint]["location"]["country"], "US");
            assert_eq!(event[endpoint]["location"]["continent"], "North America");
            let stamp = event["enrichments"].as_array().unwrap().iter()
                .find(|s| s["name"] == format!("{endpoint}.ip") && s["provider"] == "platform/ipinfo_lite").unwrap();
            assert_eq!(stamp["data"]["country_name"], "United States");
            assert_eq!(stamp["data"]["continent_code"], "NA");
            assert_eq!(stamp["data"]["as_domain"], "fixture.example");
        }
    }

    #[test]
    fn all_lite_attributes_roundtrip_into_part_schema() {
        let dir = tempfile::tempdir().unwrap();
        let (event, policy, path) = lite_part_fixture(dir.path());
        assert_lite_attributes(&event);
        let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
            std::fs::File::open(path).unwrap()).unwrap();
        let types = crate::generation::schema_leaf_types(reader.schema());
        for endpoint in ["src_endpoint", "dst_endpoint"] {
            assert!(types.contains_key(&format!("{endpoint}.autonomous_system.name")));
            assert!(types.contains_key(&format!("{endpoint}.location.continent")));
        }
        for leaf in ["as_domain", "country_name", "continent_code"] {
            assert!(types.contains_key(&format!("enrichments.data.{leaf}")));
        }
        let mut writer = arrow_json::LineDelimitedWriter::new(Vec::new());
        for batch in reader.build().unwrap() { writer.write(&batch.unwrap()).unwrap(); }
        writer.finish().unwrap();
        assert_lite_attributes(&serde_json::from_slice::<Value>(&writer.into_inner()).unwrap());
        let bundle = PlatformBundle::open(&dir.path().join("platform.bundle"), &policy.bundle_sha256).unwrap();
        let mut producer = json!({"src_endpoint":{"ip":"8.8.8.8",
            "autonomous_system":{"name":"Producer network"}, "location":{"continent":"Producer continent"}}});
        bundle.stamp(producer.as_object_mut().unwrap(), &policy, Utc::now()).unwrap();
        let mut revoked = policy;
        revoked.grants.clear();
        mask_event(&mut producer, &revoked, Utc::now()).unwrap();
        assert_eq!(producer["src_endpoint"]["autonomous_system"]["name"], "Producer network");
        assert_eq!(producer["src_endpoint"]["location"]["continent"], "Producer continent");
        assert!(producer["src_endpoint"]["autonomous_system"].get("number").is_none());

    }

    #[tokio::test]
    #[ignore = "requires a digest-verified native chDB library"]
    async fn all_lite_attributes_native_search_table_stats_and_revocation() {
        use nanosiem_core::platform_enrichment::{AuthorizedRevision, RevisionReference, read::ReadAuthorization};
        let dir = tempfile::tempdir().unwrap();
        let (_, policy, path) = lite_part_fixture(dir.path());
        let now = Utc::now();
        let auth = ReadAuthorization::from_resolved(policy.tenant_id, now, &[AuthorizedRevision {
            tenant_id: policy.tenant_id, evaluated_at: now,
            valid_until: policy.grants["ipinfo_lite"].valid_until,
            reference: RevisionReference { feed_id:"ipinfo_lite".into(), feed_revision:1,
                tier:"included".into(), grant_revision:1, entitlement_revision:1 },
            class: FeedClass::Baseline, digest:"a".repeat(64), mapping_revision:1, deny_epoch:0,
        }]);
        let runtime = crate::native::NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap()).unwrap();
        std::mem::forget(runtime.clone());
        let c = runtime.connect(&[]).unwrap();
        let source = format!("file('{}', Parquet)", path.display());
        use crate::planner::{CompiledQuery, TenantQueryConfig, ObjectStoreCredentials,
            SnapshotCache, SnapshotCacheObject, SourceManifest, plan_broad_log_query};
        let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
            std::fs::File::open(&path).unwrap()).unwrap();
        let types = crate::generation::schema_leaf_types(reader.schema());
        let read_schema = crate::iceberg::clickhouse_read_schema(reader.schema()).unwrap();
        let bytes = std::fs::metadata(&path).unwrap().len();
        let object = "s3://test/events/part.parquet";
        let config = TenantQueryConfig {
            tenant_id: policy.tenant_id.to_string(), source:"https://object.test/test/events".into(),
            iceberg_metadata_file_path:"metadata/test.json".into(), max_query_bytes:10_000_000,
            max_memory_bytes:1_000_000_000, max_execution_seconds:30, threads:1,
            credentials:ObjectStoreCredentials::DefaultChain,
            snapshot_cache:Some(SnapshotCache { source_spec:path.to_str().unwrap().into(),
                objects:BTreeMap::from([(object.into(), SnapshotCacheObject {
                    version_id:"v1".into(), bytes, path:path.clone() })]), bytes,
                read_schema:Some(read_schema), bootstrap:false }),
        };
        let manifest: SourceManifest = serde_json::from_value(json!({"tenant_id":policy.tenant_id.to_string(),
            "objects":[{"event_object_key":object,"event_object_version":"v1",
                "event_object_bytes":bytes,"rows":1,"available_paths":types.keys().collect::<Vec<_>>(),
                "field_types":types}]})).unwrap();
        for endpoint in ["src_endpoint", "dst_endpoint"] {
            let leaf = format!("{endpoint}.autonomous_system.name");
            for sql in [format!("SELECT `{leaf}` AS name FROM __nano_lake_source__"),
                format!("SELECT `{leaf}` AS name, count() AS count FROM __nano_lake_source__ GROUP BY name")] {
                let compiled: CompiledQuery = serde_json::from_value(json!({"schema_version":1,
                    "profile":"ocsf","dataset":"logs","source_placeholder":"__nano_lake_source__",
                    "query_sha256":"a".repeat(64),"start":"2026-10-01T00:00:00Z",
                    "end":"2026-10-02T00:00:00Z","limit":100,"table_view":true,
                    "required_columns":[{"name":leaf,"field_type":"string"}],"sql":sql})).unwrap();
                let plan = crate::enrichment_read::scope(auth.clone(), async {
                    plan_broad_log_query(&config, &manifest, &compiled).unwrap()
                }).await;
                assert!(!plan.schema_defaults.contains(&leaf));
                let params = plan.params.iter().map(|(k,v)| (k.as_str(),v.as_str())).collect::<Vec<_>>();
                let result = c.query_with_params(&plan.sql, "JSONEachRow", &params).unwrap();
                assert_eq!(serde_json::from_slice::<Value>(&result.data).unwrap()["name"], "Fixture network");
            }
        }

        let projection = ["src_endpoint", "dst_endpoint", "enrichments"].iter()
            .map(|root| format!("{} AS {root}", crate::enrichment_read::root_expression(root, &auth)))
            .collect::<Vec<_>>().join(", ");
        let result = c.query_with_params(&format!("SELECT {projection} FROM {source}"), "JSONEachRow", &[]).unwrap();
        assert_lite_attributes(&serde_json::from_slice::<Value>(&result.data).unwrap());
        for endpoint in ["src_endpoint", "dst_endpoint"] {
            let leaf = format!("{endpoint}.autonomous_system.name");
            let expression = crate::enrichment_read::leaf_expression(&leaf, &auth);
            for sql in [format!("SELECT {expression} AS name FROM {source}"),
                format!("SELECT {expression} AS name, count() AS count FROM {source} GROUP BY name")] {
                let result = c.query_with_params(&sql, "JSONEachRow", &[]).unwrap();
                let row: Value = serde_json::from_slice(&result.data).unwrap();
                assert_eq!(row["name"], "Fixture network");
            }
            let denied = ReadAuthorization::unknown(policy.tenant_id, now);
            let expression = crate::enrichment_read::leaf_expression(&leaf, &denied);
            let result = c.query_with_params(&format!("SELECT {expression} AS name FROM {source}"), "JSONEachRow", &[]).unwrap();
            assert!(serde_json::from_slice::<Value>(&result.data).unwrap()["name"].is_null());
        }
        let denied = crate::enrichment_read::root_expression("enrichments", &ReadAuthorization::unknown(policy.tenant_id, now));
        let result = c.query_with_params(&format!("SELECT {denied} AS enrichments FROM {source}"), "JSONEachRow", &[]).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&result.data).unwrap()["enrichments"], json!([]));
    }

    #[test]
    fn one_mmap_stamps_geo_ioc_and_masks_revocation_expiry_and_other_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("platform.bundle");
        let mmdb = mmdb_bytes();
        let digest = PlatformBundle::publish(
            &path,
            Some(&mmdb),
            &[IocSnapshotInput {
                ioc_value: "8.8.8.8".into(),
                ioc_type: "ip".into(),
                source_id: "threatfox".into(),
                threat_type: "malware".into(),
                ..Default::default()
            }],
            BTreeMap::from([("ipinfo_lite".into(), 1), ("threatfox".into(), 2)]),
        )
        .unwrap();
        let bundle = PlatformBundle::open(&path, &digest).unwrap();
        assert_eq!(
            bundle.bytes(),
            std::fs::metadata(&path).unwrap().len() as usize
        );
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        let now = Utc::now();
        let grant = |revision| PlatformGrant {
            feed_revision: revision,
            valid_until: now + chrono::Duration::minutes(5),
            premium: None,
        };
        let a = TenantPlatformPolicy {
            tenant_id: tenant_a,
            revision: 1,
            bundle_sha256: digest.clone(),
            grants: BTreeMap::from([
                ("ipinfo_lite".into(), grant(1)),
                ("threatfox".into(), grant(2)),
            ]),
        };
        let b = TenantPlatformPolicy {
            tenant_id: tenant_b,
            revision: 1,
            bundle_sha256: digest.clone(),
            grants: BTreeMap::from([("ipinfo_lite".into(), grant(1))]),
        };
        let policy_path = dir.path().join("policy.json");
        std::fs::write(&policy_path, serde_json::to_vec(&a).unwrap()).unwrap();
        assert!(TenantPlatformPolicy::read(&policy_path, tenant_b, &digest).is_err());
        let mut a_event =
            json!({"src_endpoint":{"ip":"8.8.8.8"},"dst_endpoint":{"ip":"192.168.1.1"}});
        bundle
            .stamp(a_event.as_object_mut().unwrap(), &a, now)
            .unwrap();
        assert_eq!(a_event["src_endpoint"]["location"]["country"], "US");
        assert_eq!(
            a_event["src_endpoint"]["autonomous_system"]["number"],
            64500
        );
        assert_eq!(a_event["enrichments"].as_array().unwrap().len(), 2);
        assert!(a_event["dst_endpoint"].get("location").is_none());
        let mut unchanged_feed = a_event.clone();
        let mut rotated_bundle = a.clone();
        rotated_bundle.bundle_sha256 = "0".repeat(64);
        mask_event(&mut unchanged_feed, &rotated_bundle, now).unwrap();
        assert_eq!(unchanged_feed["enrichments"].as_array().unwrap().len(), 2);
        let mut b_event = json!({"src_endpoint":{"ip":"8.8.8.8"}});
        bundle
            .stamp(b_event.as_object_mut().unwrap(), &b, now)
            .unwrap();
        assert_eq!(b_event["enrichments"].as_array().unwrap().len(), 1);
        let mut revoked = a.clone();
        revoked.grants.clear();
        mask_event(&mut a_event, &revoked, now).unwrap();
        assert!(a_event["enrichments"].as_array().unwrap().is_empty());
        assert!(a_event["src_endpoint"]["location"].get("country").is_none());
        assert!(a_event["src_endpoint"]["autonomous_system"]
            .get("number")
            .is_none());
        mask_event(&mut b_event, &b, now + chrono::Duration::minutes(6)).unwrap();
        assert!(b_event["enrichments"].as_array().unwrap().is_empty());
        let restarted = PlatformBundle::open(&path, &digest).unwrap();
        assert_eq!(restarted.lookup_ioc("8.8.8.8").unwrap().len(), 1);
    }

    #[test]
    fn premium_feed_requires_tenant_grant_and_current_entitlement_to_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("platform.bundle");
        let digest = PlatformBundle::publish(
            &path,
            None,
            &[IocSnapshotInput {
                ioc_value: "bad.example".into(),
                ioc_type: "domain".into(),
                source_id: "spur".into(),
                ..Default::default()
            }],
            BTreeMap::from([("spur".into(), 3)]),
        )
        .unwrap();
        let bundle = PlatformBundle::open(&path, &digest).unwrap();
        let now = Utc::now();
        let premium = PremiumStampRight {
            tier: "premium".into(),
            grant_revision: 1,
            entitlement_revision: 7,
        };
        let policy = TenantPlatformPolicy {
            tenant_id: Uuid::new_v4(),
            revision: 1,
            bundle_sha256: digest,
            grants: BTreeMap::from([(
                "spur".into(),
                PlatformGrant {
                    feed_revision: 3,
                    valid_until: now + chrono::Duration::minutes(5),
                    premium: Some(premium),
                },
            )]),
        };
        let mut event = json!({"url":{"hostname":"bad.example"}});
        bundle
            .stamp(event.as_object_mut().unwrap(), &policy, now)
            .unwrap();
        assert_eq!(
            event["enrichments"][0]["data"]["premium"]["entitlement_revision"],
            7
        );
        let mut revoked = policy.clone();
        revoked
            .grants
            .get_mut("spur")
            .unwrap()
            .premium
            .as_mut()
            .unwrap()
            .entitlement_revision = 8;
        mask_event(&mut event, &revoked, now).unwrap();
        assert!(event["enrichments"].as_array().unwrap().is_empty());
    }

    #[test]
    fn sorted_mmap_ioc_lookup_finds_every_key_and_duplicate_without_heap_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("platform.bundle");
        let mut rows = (0..1000)
            .rev()
            .map(|i| IocSnapshotInput {
                ioc_value: format!("host-{i:04}.example"),
                ioc_type: "domain".into(),
                source_id: "threatfox".into(),
                ..Default::default()
            })
            .collect::<Vec<_>>();
        rows.push(rows[501].clone());
        let digest = PlatformBundle::publish(
            &path,
            None,
            &rows,
            BTreeMap::from([("threatfox".into(), 1)]),
        )
        .unwrap();
        let bundle = PlatformBundle::open(&path, &digest).unwrap();
        for i in 0..1000 {
            let count = bundle
                .lookup_ioc(&format!("host-{i:04}.example"))
                .unwrap()
                .len();
            assert_eq!(count, if i == 498 { 2 } else { 1 }, "key {i}");
        }
        assert!(bundle.lookup_ioc("missing.example").unwrap().is_empty());
    }

    #[test]
    #[ignore = "run explicitly for local CPU/RSS fixture measurements"]
    fn benchmark_20_and_300_eps_fixture() {
        fn cpu_micros() -> i64 {
            let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
            assert_eq!(
                unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
                0
            );
            let usage = unsafe { usage.assume_init() };
            (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1_000_000
                + usage.ru_utime.tv_usec
                + usage.ru_stime.tv_usec
        }
        fn rss_kib() -> u64 {
            let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
            let resident = statm
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse::<u64>()
                .unwrap();
            resident * unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 } / 1024
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("platform.bundle");
        let digest = PlatformBundle::publish(
            &path,
            Some(&mmdb_bytes()),
            &[IocSnapshotInput {
                ioc_value: "8.8.8.8".into(),
                ioc_type: "ip".into(),
                source_id: "threatfox".into(),
                ..Default::default()
            }],
            BTreeMap::from([("ipinfo_lite".into(), 1), ("threatfox".into(), 2)]),
        )
        .unwrap();
        let bundle = PlatformBundle::open(&path, &digest).unwrap();
        let now = Utc::now();
        let policy = TenantPlatformPolicy {
            tenant_id: Uuid::new_v4(),
            revision: 1,
            bundle_sha256: digest,
            grants: BTreeMap::from([
                (
                    "ipinfo_lite".into(),
                    PlatformGrant {
                        feed_revision: 1,
                        valid_until: now + chrono::Duration::hours(1),
                        premium: None,
                    },
                ),
                (
                    "threatfox".into(),
                    PlatformGrant {
                        feed_revision: 2,
                        valid_until: now + chrono::Duration::hours(1),
                        premium: None,
                    },
                ),
            ]),
        };
        println!("artifact_bytes={}", bundle.bytes());
        for eps in [20_u32, 300] {
            for enabled in [false, true] {
                let cpu_before = cpu_micros();
                let rss_before = rss_kib();
                let start = std::time::Instant::now();
                let mut lookup_ns = 0_u128;
                for i in 0..eps {
                    let due = start
                        + std::time::Duration::from_nanos(i as u64 * 1_000_000_000 / eps as u64);
                    if let Some(wait) = due.checked_duration_since(std::time::Instant::now()) {
                        std::thread::sleep(wait);
                    }
                    let mut event = json!({"src_endpoint":{"ip":"8.8.8.8"}});
                    if enabled {
                        let begin = std::time::Instant::now();
                        bundle
                            .stamp(event.as_object_mut().unwrap(), &policy, Utc::now())
                            .unwrap();
                        lookup_ns += begin.elapsed().as_nanos();
                    }
                    std::hint::black_box(event);
                }
                let elapsed = start.elapsed();
                println!("eps={} platform={} elapsed_ms={} cpu_us={} rss_delta_kib={} lookup_us_per_event={}",
                    eps, enabled, elapsed.as_millis(), cpu_micros() - cpu_before,
                    rss_kib() as i64 - rss_before as i64, lookup_ns / eps as u128 / 1000);
            }
        }
    }
}
