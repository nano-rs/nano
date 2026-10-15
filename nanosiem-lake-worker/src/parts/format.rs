// SPDX-License-Identifier: AGPL-3.0-or-later

//! Part R2 key layout and Parquet data-file settings (contract sections 1–2).

use anyhow::{bail, Context, Result};
use arrow_schema::Schema as ArrowSchema;
use chrono::{DateTime, Datelike, Timelike, Utc};
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::{EnabledStatistics, WriterProperties};
use parquet::file::metadata::KeyValue;
use parquet::schema::types::ColumnPath;
use serde::{Deserialize, Serialize};
use std::fmt;

use super::levels::Level;
use super::{sha256_hex, DAY_US, HOUR_US};

/// Root prefix of the part model inside a tenant bucket.
pub const PARTS_ROOT: &str = "lake/parts/v1";
/// Rows per Parquet row group at every level (the default layout).
pub const ROW_GROUP_ROWS: usize = 65_536;
/// Largest row group a compaction layout may write (NAN-3156): gen1's
/// 262,144-row groups, for merged hour parts. Every signed-sidecar reader
/// (token index, entity blooms, entity locators) accepts groups up to this.
pub const MAX_ROW_GROUP_ROWS: usize = 262_144;
/// Bloom false-positive probability for entity columns.
pub const BLOOM_FPP: f64 = 0.0001;
/// Lower bound on the bloom ndv so tiny L0 parts keep a useful filter.
pub const BLOOM_MIN_NDV: u64 = 1_024;
/// `created_by` suffix written into every part.
pub const CREATED_BY: &str = "nano-part-v1";

/// Columns with Parquet bloom filters and page statistics in every part.
/// Equal to `tail_predicate::IDENTITY_PATHS`; `metadata.uid` doubles as the
/// per-part uid bloom used by dedup.
pub const BLOOM_PATHS: &[&str] = crate::tail_predicate::IDENTITY_PATHS;

/// Identity paths with rows in every part's `partials/entity_ranges.parquet`
/// (`BLOOM_PATHS` minus uid, as of NAN-3694). Readers answer a part inside
/// their window from its partial alone, so a path may only be listed here
/// once every live part carries its rows: an older part has none, and would
/// read as "never seen". There is no per-part coverage marker, so a path
/// added to `BLOOM_PATHS` later (the NAN-3694 asset identities) stays out.
pub const ENTITY_RANGE_PATHS: &[&str] = &[
    "user.name", "user.uid", "actor.user.name", "actor.user.uid",
    "src_endpoint.ip", "dst_endpoint.ip", "src_endpoint.hostname", "dst_endpoint.hostname",
    "device.hostname", "src_endpoint.mac", "dst_endpoint.mac", "process.name", "process.uid",
    "file_hash", "process_hash", "file.hashes.value",
    "process.file.hashes.value", "actor.process.file.hashes.value",
    "actor.process.name", "actor.process.uid",
];

/// The uid column path.
pub const UID_PATH: &str = "metadata.uid";
/// The event time column.
pub const TIME_COLUMN: &str = "time";
/// Sort order of every part written by ingest: `(time, metadata.uid)`.
pub const SORT_KEY: &[&str] = &[TIME_COLUMN, UID_PATH];

/// Parquet file key/value metadata keys (informational; the signed record is
/// the authority).
pub const META_PART_ID: &str = "nano.part.id";
pub const META_LEVEL: &str = "nano.part.level";
pub const META_TENANT: &str = "nano.part.tenant";
pub const META_SCHEMA: &str = "nano.part.schema_fingerprint";

/// Hard ceiling on any object the part model writes: the owner's
/// `content_length` cap. Never raised; parts split instead.
pub const MAX_OBJECT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// A part's data rolls to its next `data-NNNNN.parquet` once the current file
/// reaches this size (checked at row-group boundaries), leaving margin under
/// [`MAX_OBJECT_BYTES`] for the final row group.
pub const DATA_FILE_SPLIT_BYTES: u64 = 1024 * 1024 * 1024;
/// Most data files one part may have.
pub const MAX_DATA_FILES: usize = 1_000;
/// Part-log entries and checkpoints: one single-PUT object each, at most this.
pub const MAX_LOG_OBJECT_BYTES: usize = 4 * 1024 * 1024;

/// File names inside a part directory.
pub const PROVENANCE_FILE: &str = "provenance.json";
/// `provenance.pending.{record_sha256}.json`: the canonical, unsigned record
/// staged for by-reference owner signing, named by its content.
pub fn provenance_pending_file(record_sha256: &str) -> String {
    format!("provenance.pending.{record_sha256}.json")
}

/// `data-{index:05}.parquet`.
pub fn data_file_name(index: usize) -> String {
    format!("data-{index:05}.parquet")
}

/// `tokens-{index:05}.nti`: the token index of `data-{index:05}.parquet`.
pub fn tokens_file_name(index: usize) -> String {
    format!("tokens-{index:05}.nti")
}
pub const PARTIAL_ROLLUP_FILE: &str = "partials/rollup.parquet";
pub const PARTIAL_PREVALENCE_FILE: &str = "partials/prevalence.parquet";
pub const PARTIAL_ENTITY_RANGES_FILE: &str = "partials/entity_ranges.parquet";
pub const PARTIAL_RISK_FILE: &str = "partials/risk.parquet";

/// `{created_unix_ms:013}-{16 lowercase hex}`: unique per write attempt and
/// sortable by creation time.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PartId(String);

impl PartId {
    pub fn new(created_unix_ms: i64) -> Result<Self> {
        if !(0..=9_999_999_999_999).contains(&created_unix_ms) {
            bail!("part creation time is out of range");
        }
        let random = uuid::Uuid::new_v4();
        let suffix = hex::encode(&random.as_bytes()[..8]);
        Ok(Self(format!("{created_unix_ms:013}-{suffix}")))
    }

    pub fn parse(value: &str) -> Result<Self> {
        let valid = value.len() == 30
            && value.as_bytes()[13] == b'-'
            && value[..13].bytes().all(|b| b.is_ascii_digit())
            && value[14..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !valid {
            bail!("part id is malformed");
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn created_unix_ms(&self) -> i64 {
        self.0[..13].parse().unwrap_or_default()
    }
}

impl TryFrom<String> for PartId {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

impl From<PartId> for String {
    fn from(value: PartId) -> Self {
        value.0
    }
}

impl fmt::Display for PartId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validate an immutable tenant UUID (lowercase, hyphenated).
pub fn validate_tenant_uuid(tenant_id: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(tenant_id).context("tenant id is not a UUID")?;
    if parsed.hyphenated().to_string() != tenant_id {
        bail!("tenant id must be a lowercase hyphenated UUID");
    }
    Ok(())
}

fn tenant_root(tenant_id: &str) -> String {
    format!("{PARTS_ROOT}/tenant={tenant_id}")
}

/// Keys of one part's files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartKeys {
    pub dir: String,
}

impl PartKeys {
    /// `event_hour` is the part's event hour (hours since epoch). For a day
    /// part pass the first hour of the day.
    pub fn new(tenant_id: &str, level: Level, event_hour: i32, part_id: &PartId) -> Result<Self> {
        validate_tenant_uuid(tenant_id)?;
        let start = DateTime::<Utc>::from_timestamp(i64::from(event_hour) * 3_600, 0)
            .context("part event hour is out of range")?;
        let hour = if level == Level::Day { 0 } else { start.hour() };
        if level == Level::Day && start.hour() != 0 {
            bail!("a day part's event hour must be the first hour of its day");
        }
        Ok(Self {
            dir: format!(
                "{}/parts/{}/{:04}/{:02}/{:02}/{:02}/{}",
                tenant_root(tenant_id),
                level.code(),
                start.year(),
                start.month(),
                start.day(),
                hour,
                part_id
            ),
        })
    }

    pub fn file(&self, name: &str) -> String {
        format!("{}/{name}", self.dir)
    }

    pub fn data(&self, index: usize) -> String {
        self.file(&data_file_name(index))
    }

    pub fn tokens(&self, index: usize) -> String {
        self.file(&tokens_file_name(index))
    }

    pub fn provenance(&self) -> String {
        self.file(PROVENANCE_FILE)
    }

    pub fn provenance_pending(&self, record_sha256: &str) -> String {
        self.file(&provenance_pending_file(record_sha256))
    }
}

/// Keys of one tenant's part log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogKeys {
    root: String,
}

impl LogKeys {
    pub fn new(tenant_id: &str) -> Result<Self> {
        validate_tenant_uuid(tenant_id)?;
        Ok(Self { root: format!("{}/log", tenant_root(tenant_id)) })
    }

    pub fn entry(&self, seq: u64) -> String {
        format!("{}/entries/{seq:020}.json", self.root)
    }

    pub fn checkpoint(&self, seq: u64) -> String {
        format!("{}/checkpoints/{seq:020}.json", self.root)
    }

    pub fn checkpoints_prefix(&self) -> String {
        format!("{}/checkpoints/", self.root)
    }

    pub fn head(&self) -> String {
        format!("{}/HEAD", self.root)
    }
}

/// Prefix of the hourly Iceberg export (BYO readers; never served).
pub fn iceberg_export_prefix(tenant_id: &str) -> Result<String> {
    validate_tenant_uuid(tenant_id)?;
    Ok(format!("{}/export/iceberg", tenant_root(tenant_id)))
}

/// Parquet writer settings for a part at `level` (contract section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParquetSettings {
    pub zstd_level: i32,
    pub row_group_rows: usize,
    /// Roll to the next data file at this size (row-group boundary).
    pub max_file_bytes: u64,
}

impl ParquetSettings {
    pub fn for_level(level: Level) -> Self {
        let zstd_level = match level {
            Level::L0 => 3,
            Level::Minute => 6,
            Level::Hour | Level::Day => 9,
        };
        Self { zstd_level, row_group_rows: ROW_GROUP_ROWS, max_file_bytes: DATA_FILE_SPLIT_BYTES }
    }

    /// Opt-in compaction experiment; L0 keeps its ingest layout. Invalid or
    /// unbounded settings fail before creating output rather than silently
    /// changing a tenant's layout. The signed inventory records actual groups
    /// and file digests, so readers need no environment setting.
    pub fn compaction_layout(mut self, level: Level, value: Option<&str>) -> Result<Self> {
        let Some(value) = value else { return Ok(self) };
        if level == Level::L0 {
            return Ok(self);
        }
        let (rows, bytes) = value.split_once(':').context("compaction layout must be rows:file_bytes")?;
        let rows: usize = rows.parse().context("invalid compaction row count")?;
        let bytes: u64 = bytes.parse().context("invalid compaction file size")?;
        if ![8_192, 16_384, 32_768, ROW_GROUP_ROWS, 131_072, MAX_ROW_GROUP_ROWS].contains(&rows)
            || !(64 * 1024 * 1024..=DATA_FILE_SPLIT_BYTES).contains(&bytes)
        {
            bail!("compaction layout exceeds bounded row/file sizes");
        }
        self.row_group_rows = rows;
        self.max_file_bytes = bytes;
        Ok(self)
    }

    /// Do not fragment parts too small to fill the eight family streams.
    /// Tiny families reset dictionaries and duplicate footers and bloom filters.
    /// This is a conservative admission floor, not a storage-cost guarantee.
    pub fn for_compaction_rows(self, level: Level, rows: u64) -> Self {
        if level != Level::L0 && !Self::cluster_worthwhile(rows, self.row_group_rows) {
            Self { row_group_rows: ROW_GROUP_ROWS, max_file_bytes: DATA_FILE_SPLIT_BYTES, ..self }
        } else { self }
    }

    /// The floor is about family fragmentation, not group size: groups
    /// larger than the default share the default's floor, so a 300-eps hour
    /// (~1M rows) still takes a 262,144-row layout (as one or a few groups
    /// per family file) rather than silently reverting to the legacy layout.
    pub fn cluster_worthwhile(rows: u64, group_rows: usize) -> bool {
        rows >= (group_rows.clamp(8_192, ROW_GROUP_ROWS) as u64).saturating_mul(8)
    }

    /// Writer properties with page statistics, page index and entity blooms.
    /// `rows` sizes the bloom ndv.
    pub fn writer_properties(
        &self,
        rows: u64,
        part_id: &PartId,
        level: Level,
        tenant_id: &str,
        schema_fingerprint: &str,
    ) -> Result<WriterProperties> {
        // Blooms are allocated per row group at the configured ndv: size them
        // for one row group, not the whole part.
        let ndv = rows.min(self.row_group_rows as u64).max(BLOOM_MIN_NDV);
        let mut builder = WriterProperties::builder()
            .set_compression(Compression::ZSTD(ZstdLevel::try_new(self.zstd_level)?))
            .set_max_row_group_row_count(Some(self.row_group_rows))
            .set_statistics_enabled(EnabledStatistics::Page)
            .set_created_by(format!("{} {CREATED_BY}", parquet::file::properties::DEFAULT_CREATED_BY))
            .set_key_value_metadata(Some(vec![
                KeyValue::new(META_PART_ID.to_string(), part_id.to_string()),
                KeyValue::new(META_LEVEL.to_string(), level.code().to_string()),
                KeyValue::new(META_TENANT.to_string(), tenant_id.to_string()),
                KeyValue::new(META_SCHEMA.to_string(), schema_fingerprint.to_string()),
            ]));
        for path in BLOOM_PATHS {
            let column = ColumnPath::new(path.split('.').map(str::to_owned).collect());
            builder = builder
                .set_column_bloom_filter_enabled(column.clone(), true)
                .set_column_bloom_filter_fpp(column.clone(), BLOOM_FPP)
                .set_column_bloom_filter_ndv(column, ndv);
        }
        Ok(builder.build())
    }
}

/// `schema_fingerprint`: SHA-256 of the schema's ClickHouse read projection.
pub fn schema_fingerprint(schema: &ArrowSchema) -> Result<String> {
    Ok(sha256_hex(crate::iceberg::clickhouse_read_schema(schema)?.as_bytes()))
}

/// Inclusive time bounds of an event hour, in microseconds.
pub fn hour_bounds_us(event_hour: i32) -> (i64, i64) {
    let start = i64::from(event_hour) * HOUR_US;
    (start, start + HOUR_US - 1)
}

/// Inclusive time bounds of an event day, in microseconds.
pub fn day_bounds_us(event_day: i32) -> (i64, i64) {
    let start = i64::from(event_day) * DAY_US;
    (start, start + DAY_US - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";

    #[test]
    fn part_id_round_trips_and_rejects_garbage() {
        let id = PartId::new(1_790_330_400_123).unwrap();
        assert_eq!(id.created_unix_ms(), 1_790_330_400_123);
        assert_eq!(PartId::parse(id.as_str()).unwrap(), id);
        assert!(PartId::parse("1790330400123-XYZ").is_err());
        assert!(PartId::parse("../../etc").is_err());
    }

    #[test]
    fn keys_follow_the_contract_layout() {
        let id = PartId::parse("1790330400123-9f86d081884c7d65").unwrap();
        // 2026-09-25T10:00Z
        let hour = (1_790_330_400_i64 / 3_600) as i32;
        let keys = PartKeys::new(TENANT, Level::L0, hour, &id).unwrap();
        assert_eq!(
            keys.data(0),
            format!("lake/parts/v1/tenant={TENANT}/parts/l0/2026/09/25/10/{id}/data-00000.parquet")
        );
        let log = LogKeys::new(TENANT).unwrap();
        assert_eq!(log.entry(42), format!("lake/parts/v1/tenant={TENANT}/log/entries/00000000000000000042.json"));
        assert!(PartKeys::new("NOT-A-UUID", Level::L0, hour, &id).is_err());
        assert!(PartKeys::new(&TENANT.to_uppercase(), Level::L0, hour, &id).is_err());
        assert!(PartKeys::new(TENANT, Level::Day, hour, &id).is_err());
        let day_hour = hour - 10;
        assert!(PartKeys::new(TENANT, Level::Day, day_hour, &id).unwrap().dir.contains("/d/2026/09/25/00/"));
    }

    #[test]
    fn compaction_layout_is_opt_in_bounded_and_leaves_ingest_alone() {
        let base = ParquetSettings::for_level(Level::Hour);
        assert_eq!(base.compaction_layout(Level::Hour, None).unwrap(), base);
        let small = base.compaction_layout(Level::Hour, Some("8192:67108864")).unwrap();
        assert_eq!(small.row_group_rows, 8192);
        assert_eq!(small.max_file_bytes, 64 * 1024 * 1024);
        let l0 = ParquetSettings::for_level(Level::L0);
        assert_eq!(l0.compaction_layout(Level::L0, Some("invalid")).unwrap(), l0);
        for invalid in ["", "8192", "0:67108864", "65537:67108864", "8192:0", "8192:2147483648", "524288:268435456", "262145:268435456"] {
            assert!(base.compaction_layout(Level::Hour, Some(invalid)).is_err(), "{invalid}");
        }
        // NAN-3156: gen1's 262,144-row groups for merged parts.
        let wide = base.compaction_layout(Level::Hour, Some("262144:268435456")).unwrap();
        assert_eq!((wide.row_group_rows, wide.max_file_bytes), (MAX_ROW_GROUP_ROWS, 256 * 1024 * 1024));
        assert_eq!(base.compaction_layout(Level::Minute, Some("131072:67108864")).unwrap().row_group_rows, 131_072);
        assert_eq!(l0.compaction_layout(Level::L0, Some("262144:268435456")).unwrap(), l0, "L0 keeps its fresh ingest layout");
    }

    #[test]
    fn wide_groups_keep_the_default_fragmentation_floor() {
        // A 300-eps hour (~1.08M rows) must not fall back to the legacy
        // layout just because 8 x 262,144 rows exceeds it.
        let base = ParquetSettings::for_level(Level::Hour);
        let wide = base.compaction_layout(Level::Hour, Some("262144:268435456")).unwrap();
        assert_eq!(wide.for_compaction_rows(Level::Hour, 1_080_000), wide);
        assert_eq!(wide.for_compaction_rows(Level::Hour, 8 * 65_536), wide);
        assert_eq!(wide.for_compaction_rows(Level::Hour, 8 * 65_536 - 1), base);
        assert!(ParquetSettings::cluster_worthwhile(1_080_000, MAX_ROW_GROUP_ROWS));
        // Unchanged for the existing small layouts.
        assert!(!ParquetSettings::cluster_worthwhile(65_535, 8_192));
        assert!(ParquetSettings::cluster_worthwhile(65_536, 8_192));
        // Blooms are sized for one (now larger) group.
        let id = PartId::new(1).unwrap();
        assert!(wide.writer_properties(1_080_000, &id, Level::Hour, TENANT, "x").is_ok());
    }

    #[test]
    fn compaction_avoids_tiny_family_dictionary_and_metadata_resets() {
        let base = ParquetSettings::for_level(Level::Hour);
        let layout = base.compaction_layout(Level::Hour, Some("8192:67108864")).unwrap();
        assert_eq!(layout.clone().for_compaction_rows(Level::Hour, 65_535), base);
        assert_eq!(layout.clone().for_compaction_rows(Level::Hour, 65_536), layout);
        let l0 = ParquetSettings::for_level(Level::L0);
        assert_eq!(l0.clone().for_compaction_rows(Level::L0, 1), l0);
    }

    #[test]
    fn settings_by_level() {
        assert_eq!(ParquetSettings::for_level(Level::L0).zstd_level, 3);
        assert_eq!(ParquetSettings::for_level(Level::Day).zstd_level, 9);
        let id = PartId::new(1).unwrap();
        let props = ParquetSettings::for_level(Level::Hour)
            .writer_properties(10, &id, Level::Hour, TENANT, "x")
            .unwrap();
        let uid = ColumnPath::new(vec!["metadata".into(), "uid".into()]);
        assert!(props.bloom_filter_properties(&uid).is_some());
    }
}
