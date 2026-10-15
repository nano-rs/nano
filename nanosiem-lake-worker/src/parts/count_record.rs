// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3801: the owner-signed count record of one published part.
//!
//! A counts-only backfill leaves the part untouched and adds two immutable
//! files to its directory (the platform admits both names):
//!
//! - `counts-v2-{sha256[..16]}.parquet`: the part's entity counts, in the
//!   EntityRanges schema and encoding (coverage row, count rows, v2 footer
//!   hint), exactly the count namespace a full count rewrite writes;
//! - `counts-v2.json`: `{"record": CountRecord, "signature": …}` in canonical
//!   JSON, signed by the owner (`lake-part-counts:sign`) over
//!   `"nano-lake-part-counts-v2" || 0x00 || canonical(record)`. The domain
//!   differs from provenance, so neither signature verifies as the other.
//!
//! The record binds the count file (name, bytes, SHA-256) to the part's
//! signed provenance (`provenance_sha256`, rows, bounds). A reader uses it as
//! count authority only after verifying the signature with the tenant's
//! trusted keys and checking every binding against the live `PartRef`.
//! Readers that predate it never fetch it: they keep scanning, as today.

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};

use super::format::PartId;
use super::levels::Level;
use super::part_log::PartRef;
use super::provenance::{canonical_json_bytes, Ed25519Signature, FileDigest, TenantKeySet};

pub const COUNT_RECORD_FORMAT: &str = "nano.part.counts.v2";
/// Fixed name: one count record per part, created once.
pub const COUNT_RECORD_FILE: &str = "counts-v2.json";
pub const COUNT_SIGNATURE_DOMAIN: &[u8] = b"nano-lake-part-counts-v2\0";
/// The owner refuses larger records (the platform).
pub const MAX_COUNT_RECORD_BYTES: usize = 16 * 1024;
/// Stored envelope bound (record + signature).
pub const MAX_SIGNED_COUNT_RECORD_BYTES: usize = 32 * 1024;
const ALL_KINDS: u8 = (1 << super::entity_counts::KINDS.len()) - 1;

/// `counts-v2-{first 16 hex of sha256}.parquet`.
pub fn count_file_name(sha256: &str) -> Result<String> {
    ensure!(super::is_sha256_hex(sha256), "count file digest is not lowercase sha256 hex");
    Ok(format!("counts-v2-{}.parquet", &sha256[..16]))
}

/// The two count file names a part directory may hold.
pub fn is_count_file(name: &str) -> bool {
    name == COUNT_RECORD_FILE
        || name.strip_prefix("counts-v2-").and_then(|rest| rest.strip_suffix(".parquet"))
            .is_some_and(|hex| hex.len() == 16 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CountRecord {
    pub format: String,
    pub tenant_id: String,
    pub signer_key_id: String,
    pub part_id: PartId,
    pub level: Level,
    pub event_hour: i32,
    pub provenance_sha256: String,
    pub rows: u64,
    pub min_time_us: i64,
    pub max_time_us: i64,
    /// Entity kinds whose counts are complete (bit per `entity_counts::KINDS`).
    pub coverage_mask: u8,
    /// Rows of the count file (coverage row included).
    pub count_rows: u64,
    pub file: FileDigest,
    pub created_at_ms: i64,
}

impl CountRecord {
    /// The record of `part`'s counts in `file`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(part: &PartRef, tenant_id: &str, signer_key_id: &str, coverage_mask: u8, count_rows: u64,
        file: FileDigest, created_at_ms: i64) -> Result<Self> {
        let record = Self {
            format: COUNT_RECORD_FORMAT.into(), tenant_id: tenant_id.into(), signer_key_id: signer_key_id.into(),
            part_id: part.part_id.clone(), level: part.level, event_hour: part.event_hour,
            provenance_sha256: part.provenance_sha256.clone(), rows: part.rows,
            min_time_us: part.min_time_us, max_time_us: part.max_time_us,
            coverage_mask, count_rows, file, created_at_ms,
        };
        record.validate()?;
        record.binds(part, tenant_id)?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.format == COUNT_RECORD_FORMAT, "count record format is unsupported");
        ensure!(super::provenance::valid_key_id(&self.signer_key_id), "count record signer key id is malformed");
        ensure!(matches!(self.level, Level::Minute | Level::Hour | Level::Day), "count record level is not a compacted level");
        ensure!(self.level != Level::Day || self.event_hour.rem_euclid(24) == 0, "a day part's count record must name its first hour");
        ensure!(super::is_sha256_hex(&self.provenance_sha256), "count record provenance digest is malformed");
        ensure!(self.rows > 0 && self.count_rows > 0, "count record must cover rows");
        ensure!(self.min_time_us <= self.max_time_us, "count record bounds are inverted");
        ensure!(self.coverage_mask > 0 && self.coverage_mask <= ALL_KINDS, "count record coverage mask is out of range");
        ensure!(self.file.bytes > 0 && self.file.bytes <= super::format::MAX_OBJECT_BYTES, "count file size is out of range");
        ensure!(self.file.name == count_file_name(&self.file.sha256)?, "count file name does not bind its digest");
        Ok(())
    }

    /// Every binding to the live part reference and the reader's tenant.
    pub fn binds(&self, part: &PartRef, tenant_id: &str) -> Result<()> {
        ensure!(self.tenant_id == tenant_id, "count record belongs to another tenant");
        ensure!(self.part_id == part.part_id && self.level == part.level && self.event_hour == part.event_hour,
            "count record names another part");
        ensure!(self.provenance_sha256 == part.provenance_sha256, "count record binds another provenance");
        ensure!(self.rows == part.rows && self.min_time_us == part.min_time_us && self.max_time_us == part.max_time_us,
            "count record bounds differ from the signed part");
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let bytes = canonical_json_bytes(&serde_json::to_value(self)?)?;
        ensure!(bytes.len() <= MAX_COUNT_RECORD_BYTES, "count record exceeds its byte bound");
        Ok(bytes)
    }

    /// The exact message the owner signs.
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        let mut message = COUNT_SIGNATURE_DOMAIN.to_vec();
        message.extend_from_slice(&self.canonical_bytes()?);
        Ok(message)
    }
}

/// `counts-v2.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCountRecord {
    pub record: CountRecord,
    pub signature: Ed25519Signature,
}

impl SignedCountRecord {
    /// Attach an owner signature after checking it.
    pub fn assemble(record: CountRecord, signature: Ed25519Signature, keys: &TenantKeySet) -> Result<Self> {
        record.validate()?;
        ensure!(signature.key_id == record.signer_key_id, "signature key id differs from the count record's signer");
        keys.verify(&signature, &record.signing_message()?)?;
        Ok(Self { record, signature })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let bytes = canonical_json_bytes(&serde_json::to_value(self)?)?;
        ensure!(bytes.len() <= MAX_SIGNED_COUNT_RECORD_BYTES, "signed count record exceeds its byte bound");
        Ok(bytes)
    }

    /// Parse, verify and bind stored bytes to `part` of `tenant_id`.
    pub fn verify_bytes(bytes: &[u8], part: &PartRef, tenant_id: &str, keys: &TenantKeySet) -> Result<Self> {
        if bytes.len() > MAX_SIGNED_COUNT_RECORD_BYTES {
            bail!("signed count record exceeds its byte bound");
        }
        let signed: Self = serde_json::from_slice(bytes).context("count record does not parse")?;
        ensure!(signed.to_bytes()? == bytes, "count record is not in canonical form");
        signed.record.validate()?;
        signed.record.binds(part, tenant_id)?;
        ensure!(signed.signature.key_id == signed.record.signer_key_id, "signature key id differs from the count record's signer");
        keys.verify(&signed.signature, &signed.record.signing_message()?)?;
        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::provenance::{tests::{signer, TENANT}, PartSigner};

    fn part() -> PartRef {
        PartRef {
            part_id: PartId::new(1_790_000_000_000).unwrap(), level: Level::Hour, event_hour: 497_222, event_day: None,
            rows: 1_000, min_time_us: 1_790_000_000_000_000, max_time_us: 1_790_000_100_000_000,
            schema_fingerprint: String::new(), provenance_sha256: "ab".repeat(32), merkle_root: String::new(),
            sorted: true, data_bytes: 1, row_groups: 1, data_files: 1,
        }
    }

    fn file() -> FileDigest {
        let sha256 = "cd".repeat(32);
        FileDigest { name: count_file_name(&sha256).unwrap(), bytes: 4_096, sha256 }
    }

    #[test]
    fn file_names_bind_the_digest() {
        assert_eq!(count_file_name(&"0123456789abcdef".repeat(4)).unwrap(), "counts-v2-0123456789abcdef.parquet");
        assert!(count_file_name("ABC").is_err());
        for good in ["counts-v2.json", "counts-v2-0123456789abcdef.parquet"] { assert!(is_count_file(good), "{good}"); }
        for bad in ["counts-v2-0123456789ABCDEF.parquet", "counts-v2-0123456789abcde.parquet", "counts-v3.json",
            "counts-v2-0123456789abcdef.json", "counts-v2.parquet", "../counts-v2.json"] {
            assert!(!is_count_file(bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn a_signed_record_verifies_only_for_its_part_tenant_and_domain() {
        let signer = signer(7);
        let keys = signer.trusted();
        let part = part();
        let record = CountRecord::new(&part, TENANT, signer.key_id(), 0b1011, 42, file(), 1).unwrap();
        let signature = signer.sign_counts(TENANT, std::slice::from_ref(&record)).await.unwrap().remove(0);
        let signed = SignedCountRecord::assemble(record.clone(), signature.clone(), &keys).unwrap();
        let bytes = signed.to_bytes().unwrap();
        assert_eq!(SignedCountRecord::verify_bytes(&bytes, &part, TENANT, &keys).unwrap(), signed);

        // Another part, provenance, bound or tenant: refused.
        let mut other = part.clone();
        other.provenance_sha256 = "ef".repeat(32);
        assert!(SignedCountRecord::verify_bytes(&bytes, &other, TENANT, &keys).is_err());
        let mut other = part.clone();
        other.rows += 1;
        assert!(SignedCountRecord::verify_bytes(&bytes, &other, TENANT, &keys).is_err());
        assert!(SignedCountRecord::verify_bytes(&bytes, &part, "00000000-0000-4000-8000-000000000001", &keys).is_err());
        // Untrusted key, tampered body, non-canonical bytes: refused.
        assert!(SignedCountRecord::verify_bytes(&bytes, &part, TENANT, &crate::parts::provenance::tests::signer(8).trusted()).is_err());
        let tampered = String::from_utf8(bytes.clone()).unwrap().replace("\"count_rows\":42", "\"count_rows\":43");
        assert!(SignedCountRecord::verify_bytes(tampered.as_bytes(), &part, TENANT, &keys).is_err());
        let mut spaced = bytes.clone();
        spaced.insert(1, b' ');
        assert!(SignedCountRecord::verify_bytes(&spaced, &part, TENANT, &keys).is_err());
        // A provenance signature over the same bytes never verifies as counts.
        let mut provenance_message = crate::parts::provenance::PROVENANCE_SIGNATURE_DOMAIN.to_vec();
        provenance_message.extend_from_slice(&record.canonical_bytes().unwrap());
        assert!(keys.verify(&signature, &provenance_message).is_err());
    }

    #[test]
    fn invalid_records_are_refused() {
        let part = part();
        let ok = || CountRecord::new(&part, TENANT, "platform-release-test", 1, 1, file(), 1).unwrap();
        ok();
        for broken in [
            CountRecord { coverage_mask: 0, ..ok() },
            CountRecord { coverage_mask: 16, ..ok() },
            CountRecord { count_rows: 0, ..ok() },
            CountRecord { level: Level::L0, ..ok() },
            CountRecord { format: "nano.part.counts.v1".into(), ..ok() },
            CountRecord { file: FileDigest { name: "counts-v2-0000000000000000.parquet".into(), ..file() }, ..ok() },
            CountRecord { min_time_us: 2, max_time_us: 1, ..ok() },
        ] {
            assert!(broken.validate().is_err(), "{broken:?}");
        }
        assert!(CountRecord::new(&part, "00000000-0000-4000-8000-000000000001", "platform-release-test", 1, 1, file(), 1)
            .unwrap().binds(&part, TENANT).is_err());
    }
}
