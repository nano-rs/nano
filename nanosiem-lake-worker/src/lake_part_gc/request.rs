// SPDX-License-Identifier: AGPL-3.0-or-later

//! `LakePartDeleteRequest`: the flat wire request the owner authorizes
//! (spec "LakePartDeleteRequest"; owner `lakePartDeleteRequestSchema`).

use anyhow::{bail, Result};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::parts::format::{MAX_DATA_FILES, PROVENANCE_FILE};
use crate::parts::{is_sha256_hex, sha256_hex, PartId};

/// Grace for superseded / retention deletes: the contract's 1 h floor, 7 d cap.
pub const MIN_GRACE_SECONDS: u64 = 3_600;
pub const MAX_GRACE_SECONDS: u64 = 7 * 86_400;
/// Orphan minimum upload age: 49 h (coordinator policy, above the owner's
/// 24 h floor), capped at 30 d.
pub const MIN_ORPHAN_AGE_SECONDS: u64 = 176_400;
pub const MAX_ORPHAN_AGE_SECONDS: u64 = 30 * 86_400;
/// An orphan's id must be older than the log's id memory plus this margin.
pub const ORPHAN_ID_MEMORY_MARGIN_MS: i64 = 3_600_000;
pub const RETENTION_DAYS: [u64; 4] = [30, 90, 180, 365];
pub const MAX_KEY_BYTES: usize = 1_024;
/// NAN-4567: the bronze quarantine store under a tenant's `log/` family
/// (NAN-4554, `part_ingest::quarantine_store`). The only `log/` keys a
/// delete may name, and only with [`LakePartDeleteReason::QuarantineExpired`].
pub const QUARANTINE_DIR: &str = "log/checkpoints/bronze-quarantine-v1/";
/// NAN-4567: the age a quarantine object or record must reach before it may
/// be deleted: the quarantine TTL (7 d) plus the restore's day of clock-skew
/// slack, i.e. `quarantine_store::RESTORE_HORIZON_MS`. Past it a record can
/// only describe an expired entry, so no restore ever reads it.
pub const QUARANTINE_MIN_AGE_SECONDS: u64 = 8 * 86_400;
/// Fixed part file names (owner `LAKE_PART_FILE_NAMES`, contract r2). Data
/// files and UID/entity JSON sidecars use five-digit indices, `i` <
/// `format::MAX_DATA_FILES`, matched separately.
pub const PART_FILE_NAMES: [&str; 5] = [
    "provenance.json",
    "partials/rollup.parquet",
    "partials/prevalence.parquet",
    "partials/entity_ranges.parquet",
    "partials/risk.parquet",
];

const UUID_V4: &str = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";

#[cfg(test)]
fn part_file_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // `[0-9]`, never `\d`: Rust's `\d` is Unicode-aware.
        regex::Regex::new(&format!(
            r"^lake/parts/v1/tenant=({UUID_V4})/parts/(l0|m|h|d)/([0-9]{{4}})/([0-9]{{2}})/([0-9]{{2}})/([0-9]{{2}})/([0-9]{{13}}-[0-9a-f]{{16}})/(data-([0-9]{{5}})\.parquet|tokens-([0-9]{{5}})\.nti|(?:uids|entities|locators|ranges)-([0-9]{{5}})\.json|provenance\.json|provenance\.pending\.[0-9a-f]{{64}}\.json|counts-v2\.json|counts-v2-[0-9a-f]{{16}}\.parquet|partials/rollup\.parquet|partials/prevalence\.parquet|partials/entity_ranges\.parquet|partials/risk\.parquet)$"
        ))
        .expect("part file regex")
    })
}

fn uuid_v4_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(&format!("^{UUID_V4}$")).expect("uuid regex"))
}

fn slug_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$").expect("slug regex"))
}

fn etag_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new("^\"[^\"\\x00-\\x1f\\x7f]+\"$").expect("etag regex"))
}

/// A parsed part FILE key (never a log entry, checkpoint or HEAD).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartFileKey {
    pub tenant_uuid: String,
    /// `l0`, `m`, `h` or `d`.
    pub level: String,
    /// The key's date path as a UTC hour.
    pub path_hour: DateTime<Utc>,
    pub part_id: PartId,
    pub file: String,
}

impl PartFileKey {
    /// `YYYY-MM-DD` of the date path.
    pub fn day(&self) -> String {
        self.path_hour.format("%Y-%m-%d").to_string()
    }

    pub fn is_provenance(&self) -> bool {
        self.file == PROVENANCE_FILE
    }
}

/// What a bronze quarantine key names (NAN-4567).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineKeyKind {
    /// `objects/{id}.parquet`: the kept bytes; `id` is their SHA-256.
    Object { id: String },
    /// `records/{written_ms:013}-{sha16}.json`: one immutable state record.
    Record { written_ms: i64 },
}

/// A parsed bronze quarantine key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineKey {
    pub tenant_uuid: String,
    pub kind: QuarantineKeyKind,
}

/// Parse an exact bronze quarantine object or record key; `None` for
/// anything else (every other `log/` key included).
pub fn parse_quarantine_key(key: &str) -> Option<QuarantineKey> {
    if key.len() > MAX_KEY_BYTES { return None; }
    let rest = key.strip_prefix("lake/parts/v1/tenant=")?;
    let (tenant, rest) = rest.split_at_checked(36)?;
    if !uuid_v4_regex().is_match(tenant) { return None; }
    let rest = rest.strip_prefix('/')?.strip_prefix(QUARANTINE_DIR)?;
    let kind = if let Some(name) = rest.strip_prefix("objects/") {
        let id = name.strip_suffix(".parquet")?;
        if !is_sha256_hex(id) { return None; }
        QuarantineKeyKind::Object { id: id.to_string() }
    } else {
        let name = rest.strip_prefix("records/")?;
        let bytes = name.as_bytes();
        if bytes.len() != 35 || !bytes[..13].iter().all(u8::is_ascii_digit) || bytes[13] != b'-'
            || !bytes[14..30].iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
            || &name[30..] != ".json" {
            return None;
        }
        QuarantineKeyKind::Record { written_ms: name[..13].parse().ok()? }
    };
    Some(QuarantineKey { tenant_uuid: tenant.to_string(), kind })
}

/// True for any key under a tenant's `log/` family (entries, checkpoints,
/// HEAD). Such a key is never deletable.
pub fn is_log_key(key: &str) -> bool {
    key.strip_prefix("lake/parts/v1/tenant=")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(_, rest)| rest == "log" || rest.starts_with("log/"))
}

/// Parse an exact part FILE key: UUIDv4 tenant, level, a real calendar date
/// and hour (`hh = 00` for `d`), the part-id shape, the closed file set.
pub fn parse_part_file_key(key: &str) -> Option<PartFileKey> {
    if key.len() > MAX_KEY_BYTES { return None; }
    let rest = key.strip_prefix("lake/parts/v1/tenant=")?;
    let (tenant, rest) = rest.split_once("/parts/")?;
    if !uuid_v4_regex().is_match(tenant) { return None; }
    let mut fields = rest.splitn(7, '/');
    let level = fields.next()?;
    if !matches!(level, "l0" | "m" | "h" | "d") { return None; }
    let decimal = |value: &str, width| {
        (value.len() == width && value.bytes().all(|b| b.is_ascii_digit()))
            .then(|| value.parse::<u32>().ok()).flatten()
    };
    let year = decimal(fields.next()?, 4)? as i32;
    let month = decimal(fields.next()?, 2)?;
    let day = decimal(fields.next()?, 2)?;
    let hour = decimal(fields.next()?, 2)?;
    if year < 1970 || level == "d" && hour != 0 { return None; }
    let id = fields.next()?;
    // Validate ASCII before PartId's fixed byte slicing (including hostile UTF-8).
    if !id.is_ascii() { return None; }
    let part_id = PartId::parse(id).ok()?;
    let file = fields.next()?;
    let indexed = [
        ("data-", ".parquet"), ("tokens-", ".nti"),
        ("uids-", ".json"), ("entities-", ".json"),
        ("locators-", ".json"), ("ranges-", ".json"),
    ].iter().any(|(prefix, suffix)| {
        file.strip_prefix(prefix).and_then(|s| s.strip_suffix(suffix))
            .and_then(|s| decimal(s, 5)).is_some_and(|i| (i as usize) < MAX_DATA_FILES)
    });
    let pending = file.strip_prefix("provenance.pending.")
        .and_then(|s| s.strip_suffix(".json")).is_some_and(is_sha256_hex);
    // NAN-3801: a counts-only backfill's count record and count file.
    let counts = crate::parts::count_record::is_count_file(file);
    if !indexed && !pending && !counts && !PART_FILE_NAMES.contains(&file) { return None; }
    let path_hour = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, 0, 0)?.and_utc();
    Some(PartFileKey {
        tenant_uuid: tenant.to_string(), level: level.to_string(), path_hour,
        part_id, file: file.to_string(),
    })
}

#[cfg(test)]
fn parse_part_file_key_regex(key: &str) -> Option<PartFileKey> {
    if key.len() > MAX_KEY_BYTES || is_log_key(key) {
        return None;
    }
    let caps = part_file_regex().captures(key)?;
    let (year, month, day, hour): (i32, u32, u32, u32) =
        (caps[3].parse().ok()?, caps[4].parse().ok()?, caps[5].parse().ok()?, caps[6].parse().ok()?);
    if year < 1970 || &caps[2] == "d" && hour != 0 {
        return None;
    }
    // All indexed file families: i = 0..MAX_DATA_FILES.
    let index = caps.get(9).or_else(|| caps.get(10)).or_else(|| caps.get(11));
    if index.is_some_and(|i| i.as_str().parse::<usize>().map_or(true, |i| i >= MAX_DATA_FILES)) {
        return None;
    }
    let path_hour = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, 0, 0)?.and_utc();
    Some(PartFileKey {
        tenant_uuid: caps[1].to_string(),
        level: caps[2].to_string(),
        path_hour,
        part_id: PartId::parse(&caps[7]).ok()?,
        file: caps[8].to_string(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LakePartDeleteReason {
    Superseded,
    Orphan,
    Retention,
    /// NAN-4567: an expired bronze quarantine object or record.
    QuarantineExpired,
}

impl LakePartDeleteReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Superseded => "superseded",
            Self::Orphan => "orphan",
            Self::Retention => "retention",
            Self::QuarantineExpired => "quarantine_expired",
        }
    }
}

/// Present-or-absent, never `null`: a JSON `null` is refused like the owner's
/// strict schema refuses it.
fn some<'de, D: Deserializer<'de>, T: Deserialize<'de>>(deserializer: D) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

/// One lake-part delete. Flat; the per-reason fields are present exactly
/// for their reason (see [`LakePartDeleteRequest::validate`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LakePartDeleteRequest {
    pub schema_version: u8,
    pub operation: String,
    pub tenant_id: String,
    pub tenant_uuid: String,
    pub bucket: String,
    pub key: String,
    pub strong_etag: String,
    pub content_length: u64,
    pub reason: LakePartDeleteReason,
    #[serde(default, deserialize_with = "some", skip_serializing_if = "Option::is_none")]
    pub removal_seq: Option<u64>,
    #[serde(default, deserialize_with = "some", skip_serializing_if = "Option::is_none")]
    pub removal_entry_sha256: Option<String>,
    #[serde(default, deserialize_with = "some", skip_serializing_if = "Option::is_none")]
    pub grace_seconds: Option<u64>,
    #[serde(default, deserialize_with = "some", skip_serializing_if = "Option::is_none")]
    pub orphan_min_age_seconds: Option<u64>,
    #[serde(default, deserialize_with = "some", skip_serializing_if = "Option::is_none")]
    pub retention_day: Option<String>,
    #[serde(default, deserialize_with = "some", skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u64>,
    /// NAN-4567: exactly [`QUARANTINE_MIN_AGE_SECONDS`], for
    /// [`LakePartDeleteReason::QuarantineExpired`] only.
    #[serde(default, deserialize_with = "some", skip_serializing_if = "Option::is_none")]
    pub quarantine_min_age_seconds: Option<u64>,
}

/// `nano-shared-r2-{tenant_uuid}`.
pub fn tenant_bucket(tenant_uuid: &str) -> String {
    format!("nano-shared-r2-{tenant_uuid}")
}

impl LakePartDeleteRequest {
    /// Common fields for `key`; the caller sets the reason fields.
    pub fn base(
        tenant_id: &str,
        tenant_uuid: &str,
        key: &str,
        strong_etag: &str,
        content_length: u64,
        reason: LakePartDeleteReason,
    ) -> Self {
        Self {
            schema_version: 1,
            operation: super::OPERATION.to_string(),
            tenant_id: tenant_id.to_string(),
            tenant_uuid: tenant_uuid.to_string(),
            bucket: tenant_bucket(tenant_uuid),
            key: key.to_string(),
            strong_etag: strong_etag.to_string(),
            content_length,
            reason,
            removal_seq: None,
            removal_entry_sha256: None,
            grace_seconds: None,
            orphan_min_age_seconds: None,
            retention_day: None,
            retention_days: None,
            quarantine_min_age_seconds: None,
        }
    }

    pub fn validate(&self) -> Result<()> { self.validate_with_local(false) }

    /// Local installations retain the open settings range; hosted requests
    /// continue to accept only the four owner policy tiers.
    pub(crate) fn validate_with_local(&self, trusted_local: bool) -> Result<()> {
        if self.schema_version != 1 || self.operation != super::OPERATION {
            bail!("lake part delete request has the wrong schema or operation");
        }
        if self.tenant_id.len() > 63 || !slug_regex().is_match(&self.tenant_id) {
            bail!("lake part delete tenant_id is not a tenant slug");
        }
        if !uuid_v4_regex().is_match(&self.tenant_uuid) {
            bail!("lake part delete tenant_uuid is not a lowercase UUIDv4");
        }
        if self.bucket != tenant_bucket(&self.tenant_uuid) {
            bail!("lake part delete bucket is not the tenant's shared bucket");
        }
        if !etag_regex().is_match(&self.strong_etag) || self.content_length == 0 {
            bail!("lake part delete needs an exact strong etag and a non-empty length");
        }
        if self.key.is_empty() || self.key.len() > MAX_KEY_BYTES {
            bail!("lake part delete key is empty or too long");
        }
        if self.reason == LakePartDeleteReason::QuarantineExpired {
            // NAN-4567: the one `log/` family a delete may name.
            let Some(key) = parse_quarantine_key(&self.key) else {
                bail!("quarantine delete key is not an exact bronze quarantine key");
            };
            if key.tenant_uuid != self.tenant_uuid {
                bail!("lake part delete key is outside the tenant's prefix");
            }
            if self.removal_seq.is_some()
                || self.removal_entry_sha256.is_some()
                || self.grace_seconds.is_some()
                || self.orphan_min_age_seconds.is_some()
                || self.retention_day.is_some()
                || self.retention_days.is_some()
                || self.quarantine_min_age_seconds != Some(QUARANTINE_MIN_AGE_SECONDS)
            {
                bail!("quarantine delete fields are not exactly quarantine_min_age_seconds");
            }
            return Ok(());
        }
        if self.quarantine_min_age_seconds.is_some() {
            bail!("quarantine_min_age_seconds is only for a quarantine_expired delete");
        }
        if is_log_key(&self.key) {
            bail!("part-log entries, checkpoints and HEAD are never deletable");
        }
        let Some(key) = parse_part_file_key(&self.key) else {
            bail!("lake part delete key is not an exact part file key");
        };
        if key.tenant_uuid != self.tenant_uuid {
            bail!("lake part delete key is outside the tenant's prefix");
        }
        let removal_ok = || {
            self.removal_seq.is_some_and(|seq| seq >= 1)
                && self
                    .removal_entry_sha256
                    .as_deref()
                    .is_some_and(|sha| is_sha256_hex(sha) && sha != "0".repeat(64))
                && self.grace_seconds.is_some_and(|g| (MIN_GRACE_SECONDS..=MAX_GRACE_SECONDS).contains(&g))
        };
        match self.reason {
            LakePartDeleteReason::Superseded => {
                if !removal_ok()
                    || self.orphan_min_age_seconds.is_some()
                    || self.retention_day.is_some()
                    || self.retention_days.is_some()
                {
                    bail!("superseded delete fields are not exactly removal + grace");
                }
                if key.is_provenance() {
                    bail!("a superseded part keeps its provenance until retention");
                }
            }
            LakePartDeleteReason::Orphan => {
                if self.removal_seq.is_some()
                    || self.removal_entry_sha256.is_some()
                    || self.grace_seconds.is_some()
                    || self.retention_day.is_some()
                    || self.retention_days.is_some()
                    || !self
                        .orphan_min_age_seconds
                        .is_some_and(|age| (MIN_ORPHAN_AGE_SECONDS..=MAX_ORPHAN_AGE_SECONDS).contains(&age))
                {
                    bail!("orphan delete fields are not exactly orphan_min_age_seconds");
                }
            }
            LakePartDeleteReason::QuarantineExpired => bail!("quarantine deletes are validated above"),
            LakePartDeleteReason::Retention => {
                if !removal_ok()
                    || self.orphan_min_age_seconds.is_some()
                    || !self.retention_days.is_some_and(|days| RETENTION_DAYS.contains(&days) || (trusted_local && (1..=3650).contains(&days)))
                {
                    bail!("retention delete fields are not exactly removal + grace + retention");
                }
                if self.retention_day.as_deref() != Some(key.day().as_str()) {
                    bail!("retention day is not the key's date path");
                }
            }
        }
        Ok(())
    }

    /// Keys sorted bytewise, compact, integers as bare digits (the owner's
    /// `bronzeCanonicalJson`).
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        let serde_json::Value::Object(map) = serde_json::to_value(self)? else {
            bail!("lake part delete request is not an object");
        };
        let sorted: BTreeMap<String, serde_json::Value> = map.into_iter().collect();
        Ok(serde_json::to_vec(&sorted)?)
    }

    /// SHA-256 hex of the canonical request: the owner's `identity_sha256`.
    pub fn digest(&self) -> Result<String> {
        self.digest_with_local(false)
    }

    pub(crate) fn digest_with_local(&self, trusted_local: bool) -> Result<String> {
        self.validate_with_local(trusted_local)?;
        Ok(sha256_hex(&self.canonical_json()?))
    }

    /// `lpd_{digest}`.
    pub fn permit_id(&self) -> Result<String> {
        Ok(format!("lpd_{}", self.digest()?))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const TENANT_UUID: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
    pub const PART: &str = "1790330400123-9f86d081884c7d65";

    pub fn key(file: &str) -> String {
        format!("lake/parts/v1/tenant={TENANT_UUID}/parts/l0/2026/09/25/10/{PART}/{file}")
    }

    pub fn superseded() -> LakePartDeleteRequest {
        let mut request = LakePartDeleteRequest::base(
            "tenant1",
            TENANT_UUID,
            &key("data-00000.parquet"),
            "\"etag-1\"",
            42,
            LakePartDeleteReason::Superseded,
        );
        request.removal_seq = Some(7);
        request.removal_entry_sha256 = Some("ab".repeat(32));
        request.grace_seconds = Some(3_600);
        request
    }

    #[test]
    fn digest_is_pinned() {
        let request = superseded();
        let canonical = String::from_utf8(request.canonical_json().unwrap()).unwrap();
        let expected = format!(
            concat!(
                r#"{{"bucket":"nano-shared-r2-{u}","content_length":42,"grace_seconds":3600,"#,
                r#""key":"lake/parts/v1/tenant={u}/parts/l0/2026/09/25/10/{p}/data-00000.parquet","#,
                r#""operation":"lake_part_delete","reason":"superseded","#,
                r#""removal_entry_sha256":"{s}","removal_seq":7,"schema_version":1,"#,
                r#""strong_etag":"\"etag-1\"","tenant_id":"tenant1","tenant_uuid":"{u}"}}"#
            ),
            u = TENANT_UUID,
            p = PART,
            s = "ab".repeat(32)
        );
        assert_eq!(canonical, expected);
        // Computed independently with Python:
        //   json.dumps(d, sort_keys=True, separators=(",", ":")) -> hashlib.sha256
        assert_eq!(request.digest().unwrap(), "b3b757f47f91e8b6549dadc0d4d8e0f1ed405bb9ed51543a0fcfba08fce60d83");
        assert_eq!(request.permit_id().unwrap(), format!("lpd_{}", request.digest().unwrap()));
    }

    #[test]
    fn json_round_trip_is_flat_and_strict() {
        let request = superseded();
        let json = serde_json::to_value(&request).unwrap();
        assert!(json.get("orphan_min_age_seconds").is_none());
        assert_eq!(json["removal_seq"], serde_json::json!(7));
        let back: LakePartDeleteRequest = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(back, request);
        let mut extra = json.clone();
        extra["surprise"] = serde_json::json!(1);
        assert!(serde_json::from_value::<LakePartDeleteRequest>(extra).is_err());
        let mut null = json;
        null["retention_days"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<LakePartDeleteRequest>(null).is_err());
    }

    #[test]
    fn validation_matrix() {
        superseded().validate().unwrap();
        let bad = |edit: &dyn Fn(&mut LakePartDeleteRequest)| {
            let mut request = superseded();
            edit(&mut request);
            request.validate().is_err()
        };
        assert!(bad(&|r| r.key = key("provenance.json")));
        // The staged by-reference record is GC'd with the part (contract 4.4).
        assert!(!bad(&|r| r.key = key(&format!("provenance.pending.{}.json", "ab".repeat(32)))));
        assert!(bad(&|r| r.key = key("provenance.pending.json")));
        assert!(bad(&|r| r.key = key(&format!("provenance.pending.{}.json", "AB".repeat(32)))));
        assert!(bad(&|r| r.key = format!("lake/parts/v1/tenant={TENANT_UUID}/log/entries/00000000000000000007.json")));
        assert!(bad(&|r| r.key = format!("lake/parts/v1/tenant={TENANT_UUID}/log/HEAD")));
        assert!(bad(&|r| r.key = key("data.parquet")));
        assert!(bad(&|r| r.key = key("tokens.nti")));
        assert!(bad(&|r| r.key = key("data-01000.parquet")));
        assert!(bad(&|r| r.key = key("tokens-0001.nti")));
        for family in ["uids", "entities", "locators", "ranges"] {
            for index in ["00000", "00999"] {
                assert!(!bad(&|r| r.key = key(&format!("{family}-{index}.json"))));
            }
            for suffix in ["01000.json", "0000.json", "00000.parquet", "00000.json/extra", "０００００.json"] {
                assert!(bad(&|r| r.key = key(&format!("{family}-{suffix}"))));
            }
        }
        assert!(bad(&|r| r.key = key("data-00000.parquet").replace("/2026/09/25/10/", "/2026/02/30/10/")));
        assert!(bad(&|r| r.key = key("data-00000.parquet").replace("/2026/09/25/10/", "/2026/09/25/24/")));
        assert!(bad(&|r| r.key = key("data-00000.parquet").replace("/l0/", "/d/")));
        assert!(bad(&|r| r.key = key("data-00000.parquet").replace("/2026/", "/２026/")));
        assert!(bad(&|r| r.grace_seconds = Some(3_599)));
        assert!(bad(&|r| r.grace_seconds = Some(MAX_GRACE_SECONDS + 1)));
        assert!(bad(&|r| r.removal_seq = Some(0)));
        assert!(bad(&|r| r.removal_entry_sha256 = Some("0".repeat(64))));
        assert!(bad(&|r| r.orphan_min_age_seconds = Some(MIN_ORPHAN_AGE_SECONDS)));
        assert!(bad(&|r| r.bucket = "nano-shared-r2-other".into()));
        assert!(bad(&|r| r.tenant_uuid = "6f1c1e2a-5b8e-1d4c-9a3e-0e2b7c9d1f00".into()));
        assert!(bad(&|r| r.tenant_id = "Tenant1".into()));
        assert!(bad(&|r| r.strong_etag = "W/\"weak\"".into()));
        assert!(bad(&|r| r.content_length = 0));
        let other = "7f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        assert!(bad(&|r| r.key = key("data-00000.parquet").replace(TENANT_UUID, other)));

        let mut orphan = superseded();
        orphan.reason = LakePartDeleteReason::Orphan;
        assert!(orphan.validate().is_err(), "orphan with removal fields");
        orphan.removal_seq = None;
        orphan.removal_entry_sha256 = None;
        orphan.grace_seconds = None;
        orphan.orphan_min_age_seconds = Some(MIN_ORPHAN_AGE_SECONDS - 1);
        assert!(orphan.validate().is_err(), "orphan under 49 h");
        orphan.orphan_min_age_seconds = Some(MIN_ORPHAN_AGE_SECONDS);
        orphan.validate().unwrap();
        orphan.orphan_min_age_seconds = Some(MAX_ORPHAN_AGE_SECONDS + 1);
        assert!(orphan.validate().is_err());

        let mut retention = superseded();
        retention.reason = LakePartDeleteReason::Retention;
        retention.key = key("provenance.json");
        retention.retention_days = Some(30);
        retention.retention_day = Some("2026-09-25".into());
        retention.validate().unwrap();
        retention.retention_day = Some("2026-09-24".into());
        assert!(retention.validate().is_err(), "retention day must be the date path");
        retention.retention_day = Some("2026-09-25".into());
        retention.retention_days = Some(31);
        assert!(retention.validate().is_err());
        retention.retention_days = None;
        assert!(retention.validate().is_err());
    }

    pub fn quarantine(key: &str) -> LakePartDeleteRequest {
        let mut request = LakePartDeleteRequest::base(
            "tenant1", TENANT_UUID, key, "\"etag-q\"", 42, LakePartDeleteReason::QuarantineExpired,
        );
        request.quarantine_min_age_seconds = Some(QUARANTINE_MIN_AGE_SECONDS);
        request
    }

    /// NAN-4567: a quarantine delete names exactly one bronze quarantine
    /// object or record of its own tenant, with exactly the age field.
    #[test]
    fn quarantine_validation_is_exact() {
        let root = format!("lake/parts/v1/tenant={TENANT_UUID}/{QUARANTINE_DIR}");
        assert_eq!(
            root,
            crate::part_ingest::quarantine_store::store_prefix(TENANT_UUID).unwrap(),
            "the delete layout is the store's layout"
        );
        assert_eq!(QUARANTINE_MIN_AGE_SECONDS as i64 * 1_000, crate::part_ingest::quarantine_store::RESTORE_HORIZON_MS);
        let object = format!("{root}objects/{}.parquet", "ab".repeat(32));
        let record = format!("{root}records/1790330400123-0123456789abcdef.json");
        quarantine(&object).validate().unwrap();
        quarantine(&record).validate().unwrap();
        assert_eq!(
            parse_quarantine_key(&record).unwrap().kind,
            QuarantineKeyKind::Record { written_ms: 1_790_330_400_123 }
        );
        // The canonical form carries the age; the digest is stable.
        let json = String::from_utf8(quarantine(&record).canonical_json().unwrap()).unwrap();
        assert!(json.contains(r#""quarantine_min_age_seconds":691200"#), "{json}");
        assert!(json.contains(r#""reason":"quarantine_expired""#), "{json}");
        for bad_key in [
            format!("{root}objects/{}.parquet", "AB".repeat(32)),
            format!("{root}objects/{}.json", "ab".repeat(32)),
            format!("{root}objects/{}.parquet/x", "ab".repeat(32)),
            format!("{root}records/179033040012-0123456789abcdef.json"),
            format!("{root}records/1790330400123-0123456789ABCDEF.json"),
            format!("{root}records/1790330400123_0123456789abcdef.json"),
            format!("{root}outbox/{}", "ab".repeat(32)),
            format!("lake/parts/v1/tenant={TENANT_UUID}/log/checkpoints/00000000000000000001.json"),
            format!("lake/parts/v1/tenant={TENANT_UUID}/log/HEAD"),
            key("data-00000.parquet"),
            // Another tenant's quarantine.
            format!("lake/parts/v1/tenant=7f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00/{QUARANTINE_DIR}objects/{}.parquet", "ab".repeat(32)),
        ] {
            assert!(quarantine(&bad_key).validate().is_err(), "{bad_key}");
        }
        let mut young = quarantine(&record);
        young.quarantine_min_age_seconds = Some(QUARANTINE_MIN_AGE_SECONDS - 1);
        assert!(young.validate().is_err());
        let mut absent = quarantine(&record);
        absent.quarantine_min_age_seconds = None;
        assert!(absent.validate().is_err());
        let mut mixed = quarantine(&record);
        mixed.orphan_min_age_seconds = Some(MIN_ORPHAN_AGE_SECONDS);
        assert!(mixed.validate().is_err());
        // Other reasons never carry the quarantine age, and the reason never
        // opens any other `log/` key.
        let mut stray = superseded();
        stray.quarantine_min_age_seconds = Some(QUARANTINE_MIN_AGE_SECONDS);
        assert!(stray.validate().is_err());
        let mut orphan = quarantine(&object);
        orphan.reason = LakePartDeleteReason::Orphan;
        orphan.quarantine_min_age_seconds = None;
        orphan.orphan_min_age_seconds = Some(MIN_ORPHAN_AGE_SECONDS);
        assert!(orphan.validate().is_err(), "an orphan delete never names a quarantine key");
        // Unchanged canonical form for the existing reasons.
        assert!(!String::from_utf8(superseded().canonical_json().unwrap()).unwrap().contains("quarantine"));
    }

    #[test]
    fn key_parser_is_exact() {
        let parsed = parse_part_file_key(&key("partials/risk.parquet")).unwrap();
        assert_eq!(parsed.level, "l0");
        assert_eq!(parsed.day(), "2026-09-25");
        assert_eq!(parsed.part_id.as_str(), PART);
        let day = format!("lake/parts/v1/tenant={TENANT_UUID}/parts/d/2026/09/25/00/{PART}/data-00999.parquet");
        assert!(parse_part_file_key(&day).is_some());
        assert!(parse_part_file_key(&format!("{}/x", key("data-00000.parquet"))).is_none());
        assert!(parse_part_file_key(&key("partials/other.parquet")).is_none());
        assert!(is_log_key(&format!("lake/parts/v1/tenant={TENANT_UUID}/log/checkpoints/00000000000000001024.json")));
        assert!(!is_log_key(&key("data-00000.parquet")));
    }
    #[test]
    fn direct_key_parser_matches_exact_regex_contract() {
        let mut corpus = Vec::new();
        for file in ["data-00000.parquet", "data-00999.parquet", "data-01000.parquet",
            "tokens-00001.nti", "uids-00000.json", "entities-00000.json",
            "locators-00000.json", "ranges-00000.json", "provenance.json",
            "partials/rollup.parquet", "partials/prevalence.parquet",
            "partials/entity_ranges.parquet", "partials/risk.parquet"] {
            corpus.push(key(file));
        }
        corpus.push(key(&format!("provenance.pending.{}.json", "a".repeat(64))));
        // NAN-3801 count files, and near misses.
        for file in ["counts-v2.json", "counts-v2-0123456789abcdef.parquet", "counts-v2-0123456789ABCDEF.parquet",
            "counts-v2-0123456789abcde.parquet", "counts-v2.parquet", "counts-v3.json"] {
            corpus.push(key(file));
        }
        assert!(parse_part_file_key(&key("counts-v2.json")).is_some());
        assert!(parse_part_file_key(&key("counts-v2-0123456789abcdef.parquet")).is_some());
        for base in corpus.clone() {
            for i in 0..base.len() {
                for byte in [b'/', b'X', b'0', b'-', b' ', b'\n', 0] {
                    let mut raw = base.as_bytes().to_vec(); raw[i] = byte;
                    corpus.push(String::from_utf8(raw).unwrap());
                }
            }
            corpus.extend([format!("{base}/x"), format!("{base}\n"), base.replace("2026/09/25/10", "1969/02/29/24"),
                base.replace("/parts/l0/", "/parts/d/"), base.replace(PART, "ééééééééééééééé")]);
        }
        for level in ["l0", "m", "h", "d", "x"] {
            for date in ["1970/01/01/00", "1969/12/31/00", "2024/02/29/00",
                "2025/02/29/00", "2026/13/01/00", "2026/01/00/00",
                "2026/01/01/23", "2026/01/01/24"] {
                corpus.push(format!("lake/parts/v1/tenant={TENANT_UUID}/parts/{level}/{date}/{PART}/data-00000.parquet"));
            }
        }
        for value in &corpus {
            assert_eq!(parse_part_file_key(value), parse_part_file_key_regex(value), "{value:?}");
        }
        let valid = key("data-00000.parquet");
        for (name, parser) in [("regex", parse_part_file_key_regex as fn(&str)->Option<PartFileKey>),
            ("direct", parse_part_file_key as fn(&str)->Option<PartFileKey>)] {
            let started = std::time::Instant::now();
            for _ in 0..2048 { std::hint::black_box(parser(&valid)); }
            eprintln!("KEY_PARSE implementation={name} keys=2048 elapsed_us={}", started.elapsed().as_micros());
        }
    }

}
