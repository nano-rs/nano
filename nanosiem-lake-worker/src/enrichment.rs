// SPDX-License-Identifier: AGPL-3.0-or-later

//! Immutable ingest enrichment for canonical OCSF source events.
//!
//! IPinfo and tenant IOC data are large serving snapshots, not PostgreSQL
//! metadata. The bronze publisher opens their SHA-fenced files once and adds
//! only standard OCSF 1.9 endpoint and `enrichments[]` attributes before the
//! event is validated and committed to Iceberg.

use anyhow::{Context, Result, bail};
use arrow_array::{ArrayRef, Int32Array, Int64Array, RecordBatch, StringArray};
use arrow_json::LineDelimitedWriter;
use arrow_schema::{DataType, Field, Schema};
use nanosiem_core::enrichment::ioc::IocLookupResult;
use nanosiem_core::enrichment::ipinfo_mmdb::{IpinfoMmdbError, IpinfoMmdbSnapshot};
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::native::file_sha256;
use crate::ip_context::IpContextSnapshot;

const MAX_IOC_SNAPSHOT_BYTES: u64 = 1_073_741_824;
const MAX_IOC_RECORDS: usize = 5_000_000;
const MAX_IOC_VALUE_BYTES: usize = 4_096;
const MAX_IOC_TEXT_BYTES: usize = 1_024;
const MAX_IOC_TAGS: usize = 64;

#[derive(Debug, Clone, Serialize, Default)]
pub struct IngestEnrichmentMetrics {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipinfo_snapshot_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ioc_snapshot_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_context_snapshot_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_admission_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_policy_revision: Option<String>,
    pub ipinfo_candidates: u64,
    pub ipinfo_hits: u64,
    pub ipinfo_enriched_endpoints: u64,
    pub ip_context_candidates: u64,
    pub ip_context_hits: u64,
    pub ip_context_enriched_endpoints: u64,
    pub ioc_candidates: u64,
    pub ioc_hits: u64,
    pub ioc_attached: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prevalence_snapshot_id: Option<String>,
    pub prevalence_candidates: u64,
    pub prevalence_hits: u64,
    pub prevalence_attached: u64,
    /// NAN-2710: what ingest prevalence did to this batch, recorded explicitly
    /// so an unstamped batch is never mistaken for an unrecorded one:
    /// `stamped`, `pending` (a hand-off is configured but no snapshot is
    /// installed yet: every row keeps the N/A sentinel), or `failed` (the
    /// stamper errored; the batch published unstamped). Absent when ingest
    /// prevalence is not configured for this publisher at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prevalence_state: Option<String>,
    /// NAN-3503: the identity directory revision stamped from, and its
    /// counters. Omitted when directory enrichment is off, so the record of
    /// an unenriched publisher is unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_revision: Option<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub identity_candidates: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub identity_hits: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub identity_attached: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Debug, Clone)]
struct IocRecord {
    ioc_type: String,
    source_id: String,
    enrichment_name: String,
    is_ioc: bool,
    threat_type: String,
    malware: String,
    confidence: i32,
    risk_score: Option<i32>,
    tags: Vec<String>,
    data: Value,
    published_at_ms: i64,
    first_seen_at: Option<String>,
    last_seen_at: Option<String>,
}

#[derive(Debug)]
pub struct IocSnapshot {
    path: PathBuf,
    sha256: String,
    records: BTreeMap<String, Vec<IocRecord>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IocSnapshotRow {
    ioc_value: String,
    ioc_type: String,
    source_id: String,
    threat_type: String,
    malware: String,
    confidence_level: i32,
    tags: String,
    #[serde(default)]
    enrichment_name: String,
    #[serde(default = "default_true")]
    is_ioc: bool,
    #[serde(default)]
    risk_score: Option<i32>,
    #[serde(default)]
    data: Option<String>,
    #[serde(default)]
    published_at_ms: i64,
    #[serde(default)]
    first_seen_at: Option<String>,
    #[serde(default)]
    last_seen_at: Option<String>,
}

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

/// Bounded source record returned to product features that need to enumerate a
/// feed (interactive `| retro feed=...` and scheduled retro-hunt candidates).
/// It intentionally omits arbitrary enrichment data and storage coordinates.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct IocSourceRecord {
    pub value: String,
    pub key_type: String,
    pub source_id: String,
    pub enrichment_name: String,
    pub confidence: i32,
    pub tags: Vec<String>,
    pub published_at_ms: i64,
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

/// Write one deterministic immutable IOC serving snapshot. Callers publish the
/// returned digest as the version and must never mutate the resulting file in
/// place. The same artifact is accepted by ingest decoration and worker lookup.
pub fn write_ioc_snapshot(path: &Path, rows: &[IocSnapshotInput]) -> Result<String> {
    if rows.len() > MAX_IOC_RECORDS {
        bail!("IOC snapshot publication exceeds {MAX_IOC_RECORDS} rows");
    }
    write_ioc_snapshot_owned(path, rows.to_vec()).map(|(digest, _)| digest)
}

/// [`write_ioc_snapshot`] taking ownership of the rows, so a publisher never
/// holds a second copy of the tenant snapshot (NAN-3882: the lean coordinator
/// runs in 256 MiB). The rows are released before the Parquet encode, and the
/// written row count is returned with the digest.
pub fn write_ioc_snapshot_owned(path: &Path, mut rows: Vec<IocSnapshotInput>) -> Result<(String, usize)> {
    if rows.len() > MAX_IOC_RECORDS {
        bail!("IOC snapshot publication exceeds {MAX_IOC_RECORDS} rows");
    }
    for row in &mut rows {
        row.ioc_value = normalize_indicator(&row.ioc_value);
        row.ioc_type = normalize_indicator(&row.ioc_type);
        row.source_id = row.source_id.trim().to_string();
        row.enrichment_name = row.enrichment_name.trim().to_string();
        if row.enrichment_name.is_empty() {
            row.enrichment_name.clone_from(&row.source_id);
        }
        row.threat_type = row.threat_type.trim().to_string();
        row.malware = row.malware.trim().to_string();
        row.tags = normalized_tag_values(&row.tags)?;
        row.data = canonical_json(std::mem::take(&mut row.data));
        row.first_seen_at = normalized_optional_text(row.first_seen_at.as_deref())?;
        row.last_seen_at = normalized_optional_text(row.last_seen_at.as_deref())?;
        validate_ioc_input(row)?;
    }
    rows.sort_by(|left, right| {
        let order = (
            &left.ioc_value,
            &left.source_id,
            &left.enrichment_name,
            left.is_ioc,
            &left.ioc_type,
            &left.threat_type,
            &left.malware,
            left.confidence_level,
            left.risk_score,
            &left.tags,
            left.published_at_ms,
        )
            .cmp(&(
                &right.ioc_value,
                &right.source_id,
                &right.enrichment_name,
                right.is_ioc,
                &right.ioc_type,
                &right.threat_type,
                &right.malware,
                right.confidence_level,
                right.risk_score,
                &right.tags,
                right.published_at_ms,
            ));
        if order == std::cmp::Ordering::Equal {
            serde_json::to_string(&left.data)
                .unwrap_or_default()
                .cmp(&serde_json::to_string(&right.data).unwrap_or_default())
        } else {
            order
        }
    });
    rows.dedup();

    let schema = std::sync::Arc::new(Schema::new(vec![
        Field::new("ioc_value", DataType::Utf8, false),
        Field::new("ioc_type", DataType::Utf8, false),
        Field::new("source_id", DataType::Utf8, false),
        Field::new("threat_type", DataType::Utf8, false),
        Field::new("malware", DataType::Utf8, false),
        Field::new("confidence_level", DataType::Int32, false),
        Field::new("tags", DataType::Utf8, false),
        Field::new("enrichment_name", DataType::Utf8, false),
        Field::new("is_ioc", DataType::Boolean, false),
        Field::new("risk_score", DataType::Int32, true),
        Field::new("data", DataType::Utf8, false),
        Field::new("published_at_ms", DataType::Int64, false),
        Field::new("first_seen_at", DataType::Utf8, true),
        Field::new("last_seen_at", DataType::Utf8, true),
    ]));
    let strings =
        |values: Vec<&str>| -> ArrayRef { std::sync::Arc::new(StringArray::from(values)) };
    let optional_strings =
        |values: Vec<Option<&str>>| -> ArrayRef { std::sync::Arc::new(StringArray::from(values)) };
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            strings(rows.iter().map(|row| row.ioc_value.as_str()).collect()),
            strings(rows.iter().map(|row| row.ioc_type.as_str()).collect()),
            strings(rows.iter().map(|row| row.source_id.as_str()).collect()),
            strings(rows.iter().map(|row| row.threat_type.as_str()).collect()),
            strings(rows.iter().map(|row| row.malware.as_str()).collect()),
            std::sync::Arc::new(Int32Array::from(
                rows.iter()
                    .map(|row| row.confidence_level)
                    .collect::<Vec<_>>(),
            )),
            strings(
                rows.iter()
                    .map(|row| row.tags.join(","))
                    .collect::<Vec<_>>()
                    .iter()
                    .map(String::as_str)
                    .collect(),
            ),
            strings(
                rows.iter()
                    .map(|row| row.enrichment_name.as_str())
                    .collect(),
            ),
            std::sync::Arc::new(arrow_array::BooleanArray::from(
                rows.iter().map(|row| row.is_ioc).collect::<Vec<_>>(),
            )),
            std::sync::Arc::new(Int32Array::from(
                rows.iter().map(|row| row.risk_score).collect::<Vec<_>>(),
            )),
            strings(
                rows.iter()
                    .map(|row| serde_json::to_string(&row.data))
                    .collect::<std::result::Result<Vec<_>, _>>()?
                    .iter()
                    .map(String::as_str)
                    .collect(),
            ),
            std::sync::Arc::new(Int64Array::from(
                rows.iter()
                    .map(|row| row.published_at_ms)
                    .collect::<Vec<_>>(),
            )),
            optional_strings(
                rows.iter()
                    .map(|row| row.first_seen_at.as_deref())
                    .collect(),
            ),
            optional_strings(rows.iter().map(|row| row.last_seen_at.as_deref()).collect()),
        ],
    )?;
    let written = rows.len();
    // The batch owns its own buffers; release the row structs before encoding.
    drop(rows);
    let output = OpenOptions::new().write(true).create_new(true).open(path)?;
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
        .build();
    let mut writer = ArrowWriter::try_new(output, schema, Some(properties))?;
    writer.write(&batch)?;
    writer.close()?;
    let metadata = std::fs::metadata(path)?;
    if metadata.len() == 0 || metadata.len() > MAX_IOC_SNAPSHOT_BYTES {
        bail!("published IOC snapshot exceeds its immutable byte contract");
    }
    Ok((file_sha256(path)?, written))
}

impl IocSnapshot {
    pub fn open(path: impl AsRef<Path>, expected_sha256: &str) -> Result<Self> {
        validate_digest(expected_sha256)?;
        let path = path.as_ref().to_path_buf();
        let metadata = std::fs::metadata(&path)
            .with_context(|| format!("inspect IOC snapshot {}", path.display()))?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_IOC_SNAPSHOT_BYTES {
            bail!("IOC snapshot must be one non-empty bounded Parquet file");
        }
        let sha256 = file_sha256(&path)?;
        if sha256 != expected_sha256 {
            bail!("IOC snapshot SHA-256 mismatch");
        }

        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&path)?)?
            .with_batch_size(8_192)
            .build()?;
        let mut records = BTreeMap::new();
        let mut observed = 0_usize;
        for batch in reader {
            let batch = batch?;
            observed = observed
                .checked_add(batch.num_rows())
                .context("IOC snapshot record count overflow")?;
            if observed > MAX_IOC_RECORDS {
                bail!("IOC snapshot exceeds its record bound");
            }
            let mut writer = LineDelimitedWriter::new(Vec::new());
            writer.write(&batch)?;
            writer.finish()?;
            for line in writer
                .into_inner()
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
            {
                let row: IocSnapshotRow = serde_json::from_slice(line)?;
                let value = normalize_indicator(&row.ioc_value);
                validate_ioc_row(&row, &value)?;
                let record = IocRecord {
                    ioc_type: normalize_indicator(&row.ioc_type),
                    source_id: row.source_id.trim().to_string(),
                    enrichment_name: if row.enrichment_name.trim().is_empty() {
                        row.source_id.trim().to_string()
                    } else {
                        row.enrichment_name.trim().to_string()
                    },
                    is_ioc: row.is_ioc,
                    threat_type: row.threat_type.trim().to_string(),
                    malware: row.malware.trim().to_string(),
                    confidence: row.confidence_level,
                    risk_score: row.risk_score,
                    tags: normalized_tags(&row.tags)?,
                    data: row
                        .data
                        .as_deref()
                        .map(serde_json::from_str)
                        .transpose()?
                        .unwrap_or(Value::Null),
                    published_at_ms: row.published_at_ms,
                    first_seen_at: normalized_optional_text(row.first_seen_at.as_deref())?,
                    last_seen_at: normalized_optional_text(row.last_seen_at.as_deref())?,
                };
                let verdicts = records.entry(value).or_insert_with(Vec::new);
                if !verdicts.iter().any(|existing| same_ioc(existing, &record)) {
                    verdicts.push(record);
                    verdicts.sort_by(|left, right| ioc_order(left).cmp(&ioc_order(right)));
                }
            }
        }
        Ok(Self {
            path,
            sha256,
            records,
        })
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lookup(&self, value: &str) -> Option<&[IocRecord]> {
        self.records
            .get(&normalize_indicator(value))
            .map(Vec::as_slice)
    }

    /// Return every immutable verdict for one normalized indicator. This is
    /// the query-time companion to ingest decoration: both paths read the same
    /// SHA-fenced snapshot instead of maintaining a second IOC database.
    ///
    /// An indicator past its per-indicator expiry is not a match here either,
    /// exactly as at ingest (NAN-3882).
    pub fn lookup_all(&self, value: &str) -> Vec<IocLookupResult> {
        let now = chrono::Utc::now();
        self.lookup(value)
            .unwrap_or_default()
            .iter()
            .filter(|record| record.is_ioc && !record_expired(&record.data, now))
            .map(|record| IocLookupResult {
                found: true,
                // NAN-2361: the HUMAN-READABLE feed name, matching the
                // ClickHouse path (`enrichment/ioc/mod.rs` builds this field
                // from `enrichment_name`). This returned the raw enrichment
                // UUID, so an attributed retro hit rendered as
                // "matched 464b19aa-0c4f-4dcf-921a-ce92fca848c5" instead of
                // "matched ThreatFox IOC Feed" — the name was already carried
                // in the snapshot, just never surfaced. `record.enrichment_name`
                // already falls back to `source_id` when a publisher omitted
                // the name, so this can never render empty.
                source_id: Some(record.enrichment_name.clone()),
                ioc_type: Some(record.ioc_type.clone()),
                threat_type: non_empty(&record.threat_type),
                malware: non_empty(&record.malware),
                confidence_level: Some(record.confidence),
                first_seen_at: record.first_seen_at.clone(),
                last_seen_at: record.last_seen_at.clone(),
                tags: record.tags.clone(),
            })
            .collect()
    }

    /// NAN-3881: the distinct indicator sources (feed / list display names)
    /// with at least one IOC row in this snapshot, sorted. A point lookup
    /// returns it beside its matches so "no match" can say how many of the
    /// tenant's own indicator sets were searched.
    pub fn ioc_sources(&self) -> Vec<String> {
        self.records
            .values()
            .flatten()
            .filter(|record| record.is_ioc)
            .map(|record| record.enrichment_name.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// [`Self::publication_rows`] consuming the snapshot and skipping one
    /// source: the coordinator replaces or deletes `source_id`, so its old
    /// rows are never materialized and nothing is cloned (NAN-3882).
    pub fn into_publication_rows_except(self, source_id: &str) -> Vec<IocSnapshotInput> {
        let mut rows = Vec::new();
        for (ioc_value, records) in self.records {
            for record in records.into_iter().filter(|record| record.source_id != source_id) {
                rows.push(IocSnapshotInput {
                    ioc_value: ioc_value.clone(),
                    ioc_type: record.ioc_type,
                    source_id: record.source_id,
                    enrichment_name: record.enrichment_name,
                    is_ioc: record.is_ioc,
                    threat_type: record.threat_type,
                    malware: record.malware,
                    confidence_level: record.confidence,
                    risk_score: record.risk_score,
                    tags: record.tags,
                    data: record.data,
                    published_at_ms: record.published_at_ms,
                    first_seen_at: record.first_seen_at,
                    last_seen_at: record.last_seen_at,
                });
            }
        }
        rows
    }

    /// Materialize the immutable snapshot back into its publication shape.
    /// This is used only by the serialized publication coordinator to replace
    /// one source without dropping every other tenant feed.
    pub fn publication_rows(&self) -> Vec<IocSnapshotInput> {
        self.records
            .iter()
            .flat_map(|(ioc_value, records)| {
                records.iter().map(|record| IocSnapshotInput {
                    ioc_value: ioc_value.clone(),
                    ioc_type: record.ioc_type.clone(),
                    source_id: record.source_id.clone(),
                    enrichment_name: record.enrichment_name.clone(),
                    is_ioc: record.is_ioc,
                    threat_type: record.threat_type.clone(),
                    malware: record.malware.clone(),
                    confidence_level: record.confidence,
                    risk_score: record.risk_score,
                    tags: record.tags.clone(),
                    data: record.data.clone(),
                    published_at_ms: record.published_at_ms,
                    first_seen_at: record.first_seen_at.clone(),
                    last_seen_at: record.last_seen_at.clone(),
                })
            })
            .collect()
    }

    /// Enumerate distinct current IOC values through positive feed/type
    /// allow-lists and the same `(published_at_ms, value)` keyset contract used
    /// by scheduled retro hunts. The resident immutable map makes this a
    /// bounded memory lookup rather than an object-store scan.
    pub fn source_records(
        &self,
        feeds: &[String],
        feed_name_contains: &[String],
        tags: &[String],
        artifact_types: &[String],
        cursor: Option<(i64, &str)>,
        limit: usize,
    ) -> Vec<IocSourceRecord> {
        let feeds = normalized_filter(feeds);
        let feed_name_contains = normalized_filter(feed_name_contains);
        let tags = normalized_filter(tags);
        let artifact_types = normalized_filter(artifact_types);
        let cursor_value = cursor.map(|(_, value)| normalize_indicator(value));
        let mut selected = BTreeMap::<String, IocSourceRecord>::new();
        for (value, records) in &self.records {
            for record in records.iter().filter(|record| record.is_ioc) {
                if !feeds.is_empty() || !feed_name_contains.is_empty() || !tags.is_empty() {
                    let source_id = record.source_id.to_ascii_lowercase();
                    let enrichment_name = record.enrichment_name.to_ascii_lowercase();
                    let source_matches = feeds.contains(&source_id)
                        || feeds.contains(&enrichment_name)
                        || feed_name_contains
                            .iter()
                            .any(|term| enrichment_name.contains(term))
                        || record
                            .tags
                            .iter()
                            .any(|tag| tags.contains(&tag.to_ascii_lowercase()));
                    if !source_matches {
                        continue;
                    }
                }
                if !artifact_types.is_empty()
                    && !artifact_types.contains(&record.ioc_type.to_ascii_lowercase())
                {
                    continue;
                }
                if let Some((cursor_ms, _)) = cursor {
                    if record.published_at_ms < cursor_ms
                        || (record.published_at_ms == cursor_ms
                            && cursor_value
                                .as_deref()
                                .is_some_and(|cursor| value.as_str() <= cursor))
                    {
                        continue;
                    }
                }
                let candidate = IocSourceRecord {
                    value: value.clone(),
                    key_type: record.ioc_type.clone(),
                    source_id: record.source_id.clone(),
                    enrichment_name: record.enrichment_name.clone(),
                    confidence: record.confidence,
                    tags: record.tags.clone(),
                    published_at_ms: record.published_at_ms,
                };
                selected
                    .entry(value.clone())
                    .and_modify(|current| {
                        if (
                            candidate.published_at_ms,
                            candidate.confidence,
                            &candidate.source_id,
                        ) > (
                            current.published_at_ms,
                            current.confidence,
                            &current.source_id,
                        ) {
                            current.clone_from(&candidate);
                        }
                    })
                    .or_insert(candidate);
            }
        }
        let mut selected = selected.into_values().collect::<Vec<_>>();
        selected.sort_by(|left, right| {
            (left.published_at_ms, &left.value).cmp(&(right.published_at_ms, &right.value))
        });
        selected.truncate(limit);
        selected
    }

    pub fn source_record_count(
        &self,
        feeds: &[String],
        feed_name_contains: &[String],
        tags: &[String],
        artifact_types: &[String],
        cursor: Option<(i64, &str)>,
    ) -> usize {
        self.source_records(
            feeds,
            feed_name_contains,
            tags,
            artifact_types,
            cursor,
            MAX_IOC_RECORDS,
        )
        .len()
    }
}

#[derive(Clone)]
pub struct BronzeIngestEnricher {
    ipinfo: Option<std::sync::Arc<IpinfoMmdbSnapshot>>,
    iocs: Option<std::sync::Arc<IocSnapshot>>,
    ip_context: Option<std::sync::Arc<IpContextSnapshot>>,
    /// NAN-3503: the tenant's merged identity directory (cell flag
    /// `identity_directory_enrich`); `None` leaves events untouched.
    identity: Option<crate::identity_enrichment::IdentityDirectoryHandle>,
    lean_platform: Option<(std::sync::Arc<crate::lean_platform_bundle::PlatformBundle>, crate::lean_platform_bundle::TenantPlatformPolicy)>,
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    pub(crate) platform: Option<std::sync::Arc<crate::platform_stamping::ShadowStamper>>,
}

impl std::fmt::Debug for BronzeIngestEnricher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BronzeIngestEnricher")
            .field("ipinfo", &self.ipinfo)
            .field("iocs", &self.iocs.as_ref().map(|s| s.path()))
            .field("ip_context", &self.ip_context.as_ref().map(|s| s.path()))
            .field("identity", &self.identity)
            .finish()
    }
}

impl BronzeIngestEnricher {
    pub fn new(
        ipinfo: Option<IpinfoMmdbSnapshot>,
        iocs: Option<IocSnapshot>,
        ip_context: Option<IpContextSnapshot>,
    ) -> Self {
        Self {
            ipinfo: ipinfo.map(std::sync::Arc::new),
            iocs: iocs.map(std::sync::Arc::new),
            ip_context: ip_context.map(std::sync::Arc::new),
            identity: None,
            lean_platform: None,
            #[cfg(all(feature = "enterprise", target_os = "linux"))]
            platform: None,
        }
    }

    /// Attach durable platform admission; each claim pins its publication mode.
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    pub fn clear_platform_objects(&self) -> Result<()> {
        if let Some(stamper) = &self.platform { stamper.clear_bindings()?; }
        Ok(())
    }
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    pub fn bind_platform_object(&self, object: &str, key: &str) -> Result<()> {
        if let Some(stamper) = &self.platform { stamper.bind_object(object, key)?; }
        Ok(())
    }

    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    pub fn with_platform(
        mut self,
        shadow: std::sync::Arc<crate::platform_stamping::ShadowStamper>,
    ) -> Self {
        self.platform = Some(shadow);
        self
    }

    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    pub fn with_platform_shadow(
        self,
        stamper: std::sync::Arc<crate::platform_stamping::ShadowStamper>,
    ) -> Self {
        self.with_platform(stamper)
    }

    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    pub fn without_platform(mut self) -> Self {
        self.platform = None;
        self
    }

    pub fn for_pending(&self, source: &Self, version: Option<i16>) -> Result<Self> {
        #[allow(unused_mut)]
        let mut result = self.clone();
        match version {
            None => {
                #[cfg(all(feature = "enterprise", target_os = "linux"))]
                {
                    result.platform = None;
                }
            }
            Some(1) => {
                #[cfg(all(feature = "enterprise", target_os = "linux"))]
                {
                    result.platform = Some(
                        source
                            .platform
                            .clone()
                            .context("platform pending recovery requires its shadow writer")?,
                    );
                }
                #[cfg(not(all(feature = "enterprise", target_os = "linux")))]
                bail!("platform pending recovery requires enterprise Linux writer");
            }
            _ => bail!("unsupported platform pending admission version"),
        }
        let _ = source;
        Ok(result)
    }

    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    pub(crate) fn matches_legacy(&self, pins: &[Option<String>; 3]) -> bool {
        let m = self.initial_metrics();
        pins == &[
            m.ipinfo_snapshot_sha256,
            m.ioc_snapshot_sha256,
            m.ip_context_snapshot_sha256,
        ]
    }

    pub fn disabled() -> Self {
        Self::new(None, None, None)
    }

    /// Stamp directory identity context (NAN-3503) from whatever directory
    /// the handle holds when each event is enriched. The handle is filled
    /// by the background refresh, so swapping a directory never rotates
    /// the enricher or cuts a part.
    pub fn with_identity_handle(
        mut self,
        handle: Option<crate::identity_enrichment::IdentityDirectoryHandle>,
    ) -> Self {
        self.identity = handle;
        self
    }

    /// A fixed directory (tests, the lab).
    pub fn with_identity(
        self,
        directory: Option<std::sync::Arc<crate::identity_enrichment::IdentityDirectory>>,
    ) -> Self {
        let handle = directory.map(|directory| crate::identity_enrichment::IdentityDirectoryHandle::with(Some(directory)));
        self.with_identity_handle(handle)
    }

    pub fn identity(&self) -> Option<std::sync::Arc<crate::identity_enrichment::IdentityDirectory>> {
        self.identity.as_ref().and_then(|handle| handle.current())
    }

    pub fn with_lean_platform(mut self, bundle: std::sync::Arc<crate::lean_platform_bundle::PlatformBundle>, policy: crate::lean_platform_bundle::TenantPlatformPolicy) -> Self {
        self.lean_platform = Some((bundle, policy));
        self
    }

    pub fn initial_metrics(&self) -> IngestEnrichmentMetrics {
        IngestEnrichmentMetrics {
            ipinfo_snapshot_sha256: self.ipinfo.as_ref().map(|value| value.sha256().to_string()),
            platform_admission_sha256: self.lean_platform.as_ref().map(|(bundle, _)| bundle.digest().to_string()),
            platform_policy_revision: self.lean_platform.as_ref().map(|(_, policy)| policy.revision.to_string()),
            ioc_snapshot_sha256: self.iocs.as_ref().map(|value| value.sha256().to_string()),
            ip_context_snapshot_sha256: self
                .ip_context
                .as_ref()
                .map(|value| value.sha256().to_string()),
            identity_revision: self.identity().map(|value| value.revision().to_string()),
            ..IngestEnrichmentMetrics::default()
        }
    }

    pub fn enrich(&self, event: &mut Value, metrics: &mut IngestEnrichmentMetrics) -> Result<()> {
        self.enrich_before_normalization(event, metrics, false)
    }

    pub(crate) fn enrich_before_normalization(
        &self,
        event: &mut Value,
        metrics: &mut IngestEnrichmentMetrics,
        platform_shadow: bool,
    ) -> Result<()> {
        let event = event
            .as_object_mut()
            .context("OCSF event must be an object before ingest enrichment")?;
        // Tenant-provided CIDR context is more specific than the public IPinfo
        // baseline and therefore gets first refusal. IPinfo then fills only
        // attributes that remain absent.
        if let Some(ip_context) = &self.ip_context {
            enrich_ip_context(event, ip_context, metrics)?;
        }
        if !platform_shadow {
            if let Some(ipinfo) = &self.ipinfo {
                enrich_ipinfo(event, ipinfo, metrics)?;
            }
        }
        if let Some(iocs) = &self.iocs {
            enrich_iocs(event, iocs, metrics)?;
        }
        if let Some(directory) = self.identity() {
            crate::identity_enrichment::enrich_identity(
                event,
                &directory,
                chrono::Utc::now().timestamp_millis(),
                metrics,
            )?;
        }
        if let Some((bundle, policy)) = &self.lean_platform {
            bundle.stamp(event, policy, chrono::Utc::now())?;
        }
        Ok(())
    }
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    pub(crate) fn restore_legacy_baseline(
        &self,
        event: &mut Value,
        metrics: &mut IngestEnrichmentMetrics,
    ) -> Result<()> {
        if let Some(ipinfo) = &self.ipinfo {
            enrich_ipinfo(
                event.as_object_mut().context("OCSF event must be object")?,
                ipinfo,
                metrics,
            )?;
        }
        Ok(())
    }
}

fn enrich_ip_context(
    event: &mut Map<String, Value>,
    snapshot: &IpContextSnapshot,
    metrics: &mut IngestEnrichmentMetrics,
) -> Result<()> {
    for endpoint_name in ["src_endpoint", "dst_endpoint"] {
        let ip = event
            .get(endpoint_name)
            .and_then(Value::as_object)
            .and_then(|endpoint| endpoint.get("ip"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let Some(ip) = ip else {
            continue;
        };
        metrics.ip_context_candidates = metrics.ip_context_candidates.saturating_add(1);
        let Some(record) = snapshot.lookup(&ip).context("lookup immutable custom IP context")?
        else {
            continue;
        };
        metrics.ip_context_hits = metrics.ip_context_hits.saturating_add(1);
        let endpoint = event
            .get_mut(endpoint_name)
            .and_then(Value::as_object_mut)
            .context("OCSF endpoint changed shape during custom IP enrichment")?;
        let mut changed = false;
        if record.country_code.is_some() || record.continent.is_some() {
            let location = object_child(endpoint, "location")?;
            let location_changed = insert_string_if_absent(
                location,
                "country",
                record.country_code.map(|value| value.to_ascii_uppercase()),
            ) | insert_string_if_absent(location, "continent", record.continent);
            if location_changed {
                insert_string_if_absent(location, "provider", record.source_id.clone());
                changed = true;
            }
        }
        let number = record
            .asn
            .as_deref()
            .map(|value| value.trim().trim_start_matches("AS"))
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value >= 0);
        if number.is_some() || record.as_name.is_some() {
            let autonomous_system = object_child(endpoint, "autonomous_system")?;
            if !autonomous_system.contains_key("number") {
                if let Some(number) = number {
                    autonomous_system.insert("number".to_string(), Value::from(number));
                    changed = true;
                }
            }
            changed |= insert_string_if_absent(autonomous_system, "name", record.as_name);
        }
        if changed {
            metrics.ip_context_enriched_endpoints =
                metrics.ip_context_enriched_endpoints.saturating_add(1);
        }
    }
    Ok(())
}

fn enrich_ipinfo(
    event: &mut Map<String, Value>,
    snapshot: &IpinfoMmdbSnapshot,
    metrics: &mut IngestEnrichmentMetrics,
) -> Result<()> {
    for endpoint_name in ["src_endpoint", "dst_endpoint"] {
        let ip = event
            .get(endpoint_name)
            .and_then(Value::as_object)
            .and_then(|endpoint| endpoint.get("ip"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let Some(ip) = ip else {
            continue;
        };
        metrics.ipinfo_candidates = metrics.ipinfo_candidates.saturating_add(1);
        if ip.parse::<IpAddr>().is_err() {
            continue;
        }
        let record = match snapshot.lookup(&ip) {
            Ok(Some(record)) => record,
            Ok(None) | Err(IpinfoMmdbError::InvalidIp(_)) => continue,
            Err(error) => return Err(error).context("lookup immutable IPinfo snapshot"),
        };
        metrics.ipinfo_hits = metrics.ipinfo_hits.saturating_add(1);
        let endpoint = event
            .get_mut(endpoint_name)
            .and_then(Value::as_object_mut)
            .context("OCSF endpoint changed shape during IPinfo enrichment")?;
        let mut changed = false;
        let country = record
            .country_code
            .as_deref()
            .map(str::to_ascii_uppercase)
            .filter(|value| !value.is_empty());
        let continent = record
            .continent
            .clone()
            .filter(|value| !value.trim().is_empty());
        if country.is_some() || continent.is_some() {
            let location = object_child(endpoint, "location")?;
            let location_changed = insert_string_if_absent(location, "country", country)
                | insert_string_if_absent(location, "continent", continent);
            if location_changed {
                insert_string_if_absent(location, "provider", Some("IPinfo Lite".to_string()));
                changed = true;
            }
        }

        let number = record
            .asn
            .as_deref()
            .map(|value| value.trim().trim_start_matches("AS"))
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value >= 0);
        let as_name = record
            .as_name
            .clone()
            .filter(|value| !value.trim().is_empty());
        if number.is_some() || as_name.is_some() {
            let autonomous_system = object_child(endpoint, "autonomous_system")?;
            if !autonomous_system.contains_key("number") {
                if let Some(number) = number {
                    autonomous_system.insert("number".to_string(), Value::from(number));
                    changed = true;
                }
            }
            changed |= insert_string_if_absent(autonomous_system, "name", as_name);
        }
        if changed {
            metrics.ipinfo_enriched_endpoints = metrics.ipinfo_enriched_endpoints.saturating_add(1);
        }
    }
    Ok(())
}

fn enrich_iocs(
    event: &mut Map<String, Value>,
    snapshot: &IocSnapshot,
    metrics: &mut IngestEnrichmentMetrics,
) -> Result<()> {
    let candidates = artifact_candidates(event);
    if candidates.is_empty() {
        return Ok(());
    }
    let now = chrono::Utc::now();
    metrics.ioc_candidates = metrics
        .ioc_candidates
        .saturating_add(candidates.len() as u64);
    let enrichments = event
        .entry("enrichments")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .context("OCSF enrichments must be an array")?;
    for (name, value) in candidates {
        let Some(records) = snapshot.lookup(&value) else {
            continue;
        };
        metrics.ioc_hits = metrics.ioc_hits.saturating_add(1);
        for record in records {
            // NAN-3038: an indicator with a passed per-indicator expiry (tenant
            // IOC lists carry it as `data.indicator_expires_at`) stops matching
            // at ingest without waiting for a republish.
            if record_expired(&record.data, now) {
                continue;
            }
            let enrichment = json!({
                "name": record.enrichment_name,
                "value": value,
                "type": if record.is_ioc { "threat_intelligence" } else { "context" },
                // NAN-3038: the human-readable source (the list / enrichment
                // name, falling back to the source id when a publisher gave
                // none); the source UUID stays in `data.source_id`.
                "provider": record.enrichment_name,
                "short_desc": if record.is_ioc { &record.threat_type } else { &record.enrichment_name },
                "data": {
                    "matched_field": name,
                    "source_id": record.source_id,
                    "ioc_type": record.ioc_type,
                    "is_ioc": record.is_ioc,
                    "threat_type": record.threat_type,
                    "malware": record.malware,
                    "confidence": record.confidence,
                    "risk_score": record.risk_score,
                    "tags": record.tags,
                    "record": record.data,
                }
            });
            if enrichments.iter().any(|existing| existing == &enrichment) {
                continue;
            }
            enrichments.push(enrichment);
            metrics.ioc_attached = metrics.ioc_attached.saturating_add(1);
        }
    }
    Ok(())
}

/// Whether an IOC record's optional `data.indicator_expires_at` (RFC 3339)
/// has passed. Absent or unparsable expiry never expires a record.
fn record_expired(data: &Value, now: chrono::DateTime<chrono::Utc>) -> bool {
    data.get("indicator_expires_at")
        .and_then(Value::as_str)
        .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
        .is_some_and(|expiry| expiry <= now)
}

/// OCSF paths carrying an IP, hash, or domain artifact, as `(path, value)`,
/// for IOC matching. Domains come from every field in
/// [`crate::ocsf_domains::DOMAIN_FIELDS`] (endpoint hostnames, URL hosts, the
/// DNS question and answers, TLS SNI, e-mail addresses and their domains).
pub(crate) fn artifact_candidates(event: &Map<String, Value>) -> Vec<(String, String)> {
    candidates(event, false)
}

/// The prevalence-indexed subset of [`artifact_candidates`]: IPs, hashes and
/// the [`crate::ocsf_domains::PREVALENCE_DOMAIN_PATHS`] domains, normalized
/// exactly as the prevalence builder normalizes them (`lower-trim-v1`). The
/// ingest stamper must never look up an artifact the builder cannot index,
/// or it stays `is_new` forever.
pub(crate) fn prevalence_artifact_candidates(event: &Map<String, Value>) -> Vec<(String, String)> {
    candidates(event, true)
}

/// OCSF fields carrying a full URL, matched against URL indicators.
const URL_STRING_PATHS: [&str; 2] = ["url.url_string", "http_request.url.url_string"];

fn candidates(event: &Map<String, Value>, prevalence_only: bool) -> Vec<(String, String)> {
    let mut values = Vec::new();
    for path in ["src_endpoint.ip", "dst_endpoint.ip"] {
        if let Some(value) = string_at(event, path) {
            values.push((path.to_string(), normalize_indicator(value)));
        }
    }
    for path in [
        "file.hashes",
        "process.file.hashes",
        "actor.process.file.hashes",
    ] {
        if let Some(hashes) = value_at(event, path).and_then(Value::as_array) {
            for hash in hashes.iter().filter_map(Value::as_object) {
                if let Some(value) = hash.get("value").and_then(Value::as_str) {
                    values.push((format!("{path}.value"), normalize_indicator(value)));
                }
            }
        }
    }
    values.extend(crate::ocsf_domains::domain_candidates(event, prevalence_only));
    // Full URLs are IOC-only (prevalence indexes no URL artifact class).
    if !prevalence_only {
        for path in URL_STRING_PATHS {
            if let Some(value) = string_at(event, path) {
                values.push((path.to_string(), normalize_indicator(value)));
            }
        }
    }
    values.retain(|(_, value)| !value.is_empty());
    values.sort();
    values.dedup();
    values
}

pub(crate) fn value_at<'a>(event: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let mut value = event.get(parts.next()?)?;
    for part in parts {
        value = value.as_object()?.get(part)?;
    }
    Some(value)
}

pub(crate) fn string_at<'a>(event: &'a Map<String, Value>, path: &str) -> Option<&'a str> {
    value_at(event, path)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn object_child<'a>(
    parent: &'a mut Map<String, Value>,
    name: &str,
) -> Result<&'a mut Map<String, Value>> {
    parent
        .entry(name.to_string())
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .with_context(|| format!("OCSF {name} enrichment target must be an object"))
}

fn insert_string_if_absent(
    target: &mut Map<String, Value>,
    name: &str,
    value: Option<String>,
) -> bool {
    if target.get(name).is_some_and(|value| !value.is_null()) {
        return false;
    }
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return false;
    };
    target.insert(name.to_string(), Value::String(value));
    true
}

fn validate_ioc_row(row: &IocSnapshotRow, normalized_value: &str) -> Result<()> {
    if normalized_value.is_empty()
        || normalized_value.len() > MAX_IOC_VALUE_BYTES
        || !(0..=100).contains(&row.confidence_level)
        || row
            .risk_score
            .is_some_and(|score| !(0..=100).contains(&score))
        || row.published_at_ms < 0
    {
        bail!("IOC snapshot row has an invalid value or confidence");
    }
    for value in [
        row.ioc_type.as_str(),
        row.source_id.as_str(),
        row.enrichment_name.as_str(),
        row.threat_type.as_str(),
        row.malware.as_str(),
    ] {
        if value.len() > MAX_IOC_TEXT_BYTES || value.chars().any(char::is_control) {
            bail!("IOC snapshot row has an invalid bounded text field");
        }
    }
    // The wire column joins valid tags with commas; bound the complete
    // string before splitting/cloning it, without rejecting 16x64-byte lists.
    if row.tags.len() > MAX_IOC_TAGS * (MAX_IOC_TEXT_BYTES + 1) - 1 {
        bail!("IOC snapshot row exceeds its joined tag bound");
    }
    if row.ioc_type.trim().is_empty() || row.source_id.trim().is_empty() {
        bail!("IOC snapshot row lacks its type or source identity");
    }
    Ok(())
}

fn validate_ioc_input(row: &IocSnapshotInput) -> Result<()> {
    if row.ioc_value.is_empty()
        || row.ioc_value.len() > MAX_IOC_VALUE_BYTES
        || row.ioc_type.is_empty()
        || row.source_id.is_empty()
        || !(0..=100).contains(&row.confidence_level)
        || row
            .risk_score
            .is_some_and(|score| !(0..=100).contains(&score))
        || row.published_at_ms < 0
    {
        bail!("IOC snapshot input has an invalid value, type, source, or confidence");
    }
    for value in [
        row.ioc_type.as_str(),
        row.source_id.as_str(),
        row.enrichment_name.as_str(),
        row.threat_type.as_str(),
        row.malware.as_str(),
    ] {
        if value.len() > MAX_IOC_TEXT_BYTES || value.chars().any(char::is_control) {
            bail!("IOC snapshot input has an invalid bounded text field");
        }
    }
    if serde_json::to_vec(&row.data)?.len() > 65_536 {
        bail!("IOC snapshot input data exceeds its per-record JSON bound");
    }
    Ok(())
}

fn normalized_tags(value: &str) -> Result<Vec<String>> {
    let tags = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if tags.len() > MAX_IOC_TAGS || tags.iter().any(|value| value.len() > MAX_IOC_TEXT_BYTES || value.chars().any(char::is_control)) {
        bail!("IOC snapshot row exceeds its tag bound");
    }
    Ok(tags)
}

fn normalized_tag_values(values: &[String]) -> Result<Vec<String>> {
    let tags = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if tags.len() > MAX_IOC_TAGS
        || tags.iter().any(|value| {
            value.len() > MAX_IOC_TEXT_BYTES
                || value.contains(',')
                || value.chars().any(char::is_control)
        })
    {
        bail!("IOC snapshot input has invalid tags");
    }
    Ok(tags)
}

fn normalized_optional_text(value: Option<&str>) -> Result<Option<String>> {
    let value = value.map(str::trim).filter(|value| !value.is_empty());
    if value.is_some_and(|value| {
        value.len() > MAX_IOC_TEXT_BYTES || value.chars().any(char::is_control)
    }) {
        bail!("IOC snapshot row has an invalid optional text field");
    }
    Ok(value.map(str::to_string))
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

fn normalize_indicator(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalized_filter(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn canonical_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_json).collect()),
        Value::Object(values) => {
            let mut entries = values.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, canonical_json(value)))
                    .collect(),
            )
        }
        value => value,
    }
}

fn same_ioc(left: &IocRecord, right: &IocRecord) -> bool {
    left.ioc_type == right.ioc_type
        && left.source_id == right.source_id
        && left.enrichment_name == right.enrichment_name
        && left.is_ioc == right.is_ioc
        && left.threat_type == right.threat_type
        && left.malware == right.malware
        && left.confidence == right.confidence
        && left.risk_score == right.risk_score
        && left.tags == right.tags
        && left.data == right.data
        && left.published_at_ms == right.published_at_ms
}

fn ioc_order(
    value: &IocRecord,
) -> (
    &str,
    &str,
    bool,
    &str,
    &str,
    &str,
    i32,
    Option<i32>,
    &[String],
    i64,
) {
    (
        &value.source_id,
        &value.enrichment_name,
        value.is_ioc,
        &value.ioc_type,
        &value.threat_type,
        &value.malware,
        value.confidence,
        value.risk_score,
        &value.tags,
        value.published_at_ms,
    )
}

fn default_true() -> bool {
    true
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("snapshot SHA-256 must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_context::{IpContextInput, IpContextStore};

    fn controlled_iocs() -> IocSnapshot {
        IocSnapshot {
            path: PathBuf::from("/immutable/iocs.parquet"),
            sha256: "a".repeat(64),
            records: BTreeMap::from([(
                "bad.example".to_string(),
                vec![IocRecord {
                    ioc_type: "domain".to_string(),
                    source_id: "tenant-feed".to_string(),
                    enrichment_name: "Tenant feed".to_string(),
                    is_ioc: true,
                    threat_type: "c2".to_string(),
                    malware: "fixture".to_string(),
                    confidence: 95,
                    risk_score: Some(95),
                    tags: vec!["controlled".to_string()],
                    data: json!({"fixture": true}),
                    published_at_ms: 1_786_742_400_000,
                    first_seen_at: Some("2026-08-01T00:00:00Z".to_string()),
                    last_seen_at: Some("2026-08-15T00:00:00Z".to_string()),
                }],
            )]),
        }
    }

    #[test]
    fn canonical_ioc_enrichment_is_idempotent() {
        let enricher = BronzeIngestEnricher::new(None, Some(controlled_iocs()), None);
        let mut event = json!({"url": {"hostname": "BAD.Example"}});
        let mut metrics = enricher.initial_metrics();
        enricher.enrich(&mut event, &mut metrics).unwrap();
        enricher.enrich(&mut event, &mut metrics).unwrap();
        assert_eq!(event["enrichments"].as_array().unwrap().len(), 1);
        assert_eq!(event["enrichments"][0]["type"], "threat_intelligence");
        assert_eq!(event["enrichments"][0]["value"], "bad.example");
        assert_eq!(metrics.ioc_hits, 2);
        assert_eq!(metrics.ioc_attached, 1);
    }

    /// NAN-3039: a domain indicator is matched on every domain-bearing OCSF
    /// field, not only URL / DNS-question hostnames.
    #[test]
    fn domain_ioc_matches_every_domain_bearing_field() {
        let enricher = BronzeIngestEnricher::new(None, Some(controlled_iocs()), None);
        for (field, mut event) in [
            ("dst_endpoint.hostname", json!({"dst_endpoint": {"hostname": "bad.example"}})),
            ("src_endpoint.hostname", json!({"src_endpoint": {"hostname": "BAD.example"}})),
            ("query.hostname", json!({"query": {"hostname": "bad.example."}})),
            ("answers.rdata", json!({"answers": [{"rdata": "good.example"}, {"rdata": "bad.example"}]})),
            ("tls.sni", json!({"tls": {"sni": "bad.example"}})),
            ("email.from", json!({"email": {"from": "Eve <eve@bad.example>"}})),
            ("email.to", json!({"email": {"to": ["ok@good.example", "x@BAD.example"]}})),
        ] {
            let mut metrics = enricher.initial_metrics();
            enricher.enrich(&mut event, &mut metrics).unwrap();
            let stamps = event["enrichments"].as_array().unwrap_or_else(|| panic!("{field}: no stamp"));
            assert_eq!(stamps.len(), 1, "{field}: {stamps:?}");
            assert_eq!(stamps[0]["value"], "bad.example", "{field}");
            assert_eq!(stamps[0]["data"]["matched_field"], field);
        }
    }

    #[test]
    fn prevalence_candidates_are_the_indexed_subset() {
        let event = json!({
            "dst_endpoint": {"hostname": "Dst.Example.", "ip": "8.8.8.8"},
            "tls": {"sni": "sni.example"},
            "email": {"from": "a@mail.example"}
        });
        let event = event.as_object().unwrap();
        let prevalence = prevalence_artifact_candidates(event);
        assert_eq!(
            prevalence,
            vec![
                ("dst_endpoint.hostname".to_string(), "dst.example.".to_string()),
                ("dst_endpoint.ip".to_string(), "8.8.8.8".to_string()),
            ]
        );
        let ioc = artifact_candidates(event);
        assert!(ioc.contains(&("tls.sni".to_string(), "sni.example".to_string())));
        let url_event = json!({"http_request": {"url": {"url_string": "HTTPS://Bad.Example/x", "hostname": "bad.example"}}});
        let url_event = url_event.as_object().unwrap();
        assert!(artifact_candidates(url_event).contains(&("http_request.url.url_string".to_string(), "https://bad.example/x".to_string())));
        assert!(prevalence_artifact_candidates(url_event).iter().all(|(path, _)| !path.ends_with("url_string")));
        assert!(ioc.contains(&("email.from".to_string(), "mail.example".to_string())));
        assert!(ioc.contains(&("dst_endpoint.hostname".to_string(), "dst.example".to_string())));
    }

    /// NAN-3038: the stamp names its source by list name, keeps the source
    /// id in `data`, and an expired indicator no longer matches.
    #[test]
    fn ioc_stamp_provider_is_the_list_name_and_expiry_is_honoured() {
        let mut snapshot = controlled_iocs();
        let enricher = BronzeIngestEnricher::new(None, Some(controlled_iocs()), None);
        let mut event = json!({"url": {"hostname": "bad.example"}});
        let mut metrics = enricher.initial_metrics();
        enricher.enrich(&mut event, &mut metrics).unwrap();
        assert_eq!(event["enrichments"][0]["provider"], "Tenant feed");
        assert_eq!(event["enrichments"][0]["data"]["source_id"], "tenant-feed");

        let record = &mut snapshot.records.get_mut("bad.example").unwrap()[0];
        record.data = json!({"indicator_expires_at": "2020-01-01T00:00:00Z"});
        let enricher = BronzeIngestEnricher::new(None, Some(snapshot), None);
        let mut event = json!({"url": {"hostname": "bad.example"}});
        let mut metrics = enricher.initial_metrics();
        enricher.enrich(&mut event, &mut metrics).unwrap();
        assert!(event.get("enrichments").and_then(Value::as_array).is_none_or(Vec::is_empty), "{event}");

        let future = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        assert!(!record_expired(&json!({"indicator_expires_at": future}), chrono::Utc::now()));
        assert!(!record_expired(&json!({"indicator_expires_at": "garbage"}), chrono::Utc::now()));
        assert!(!record_expired(&Value::Null, chrono::Utc::now()));
    }

    /// NAN-3882: hunts and the threat-intel flyout read `lookup_all`; an
    /// expired indicator is not a hit there, a never-expiring one still is.
    #[test]
    fn query_lookup_skips_expired_indicators() {
        let mut snapshot = controlled_iocs();
        assert_eq!(snapshot.lookup_all("bad.example").len(), 1);
        let future = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
        snapshot.records.get_mut("bad.example").unwrap()[0].data = json!({"indicator_expires_at": future});
        assert_eq!(snapshot.lookup_all("bad.example").len(), 1, "a future expiry still matches");
        snapshot.records.get_mut("bad.example").unwrap()[0].data =
            json!({"indicator_expires_at": "2020-01-01T00:00:00Z"});
        assert!(snapshot.lookup_all("bad.example").is_empty(), "an expired indicator must not match");
    }

    #[test]
    fn custom_cidr_context_wins_and_is_digest_reported() {
        let root = tempfile::tempdir().unwrap();
        let store = IpContextStore::new(
            root.path().join("ip-context"),
            "tenant-a".to_string(),
        )
        .unwrap();
        store
            .upsert(vec![IpContextInput {
                network: "10.20.30.0/24".to_string(),
                source_id: "cmdb".to_string(),
                country: String::new(),
                country_code: "US".to_string(),
                continent: "North America".to_string(),
                continent_code: "NA".to_string(),
                asn: "AS64512".to_string(),
                as_name: "Corp network".to_string(),
                as_domain: "corp.example".to_string(),
                updated_at: chrono::DateTime::from_timestamp_millis(1_700_000_000_000).unwrap(),
                deleted: false,
            }])
            .unwrap();
        let (path, digest) = store.assignment().unwrap().unwrap();
        let enricher = BronzeIngestEnricher::new(
            None,
            None,
            Some(IpContextSnapshot::open(path, &digest).unwrap()),
        );
        let mut event = json!({"src_endpoint": {"ip": "10.20.30.4"}});
        let mut metrics = enricher.initial_metrics();
        enricher.enrich(&mut event, &mut metrics).unwrap();
        assert_eq!(metrics.ip_context_snapshot_sha256.as_deref(), Some(digest.as_str()));
        assert_eq!(metrics.ip_context_hits, 1);
        assert_eq!(event["src_endpoint"]["location"]["provider"], "cmdb");
        assert_eq!(event["src_endpoint"]["location"]["country"], "US");
        assert_eq!(event["src_endpoint"]["autonomous_system"]["number"], 64512);
        assert_eq!(
            event["src_endpoint"]["autonomous_system"]["name"],
            "Corp network"
        );
    }

    #[test]
    fn query_lookup_uses_the_same_normalized_snapshot() {
        let snapshot = controlled_iocs();
        let hits = snapshot.lookup_all("  BAD.EXAMPLE ");
        assert_eq!(hits.len(), 1);
        // NAN-2361: `IocLookupResult.source_id` carries the HUMAN-READABLE feed
        // name, matching the ClickHouse path (`enrichment/ioc/mod.rs` fills it
        // from `enrichment_name`). It previously returned the raw source id, so
        // an attributed retro hit rendered as "matched <uuid>" instead of the
        // feed name. The fixture's source_id is "tenant-feed"; its display name
        // is "Tenant feed".
        assert_eq!(hits[0].source_id.as_deref(), Some("Tenant feed"));
        assert_eq!(hits[0].confidence_level, Some(95));
        assert_eq!(
            hits[0].first_seen_at.as_deref(),
            Some("2026-08-01T00:00:00Z")
        );
        assert!(snapshot.lookup_all("clean.example").is_empty());
    }

    #[test]
    fn maximum_ioc_list_tags_round_trip_through_snapshot_reader() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tags.parquet");
        let tags: Vec<_> = (0..16).map(|n| format!("{n:02}{}", "x".repeat(62))).collect();
        let digest = write_ioc_snapshot(&path, &[IocSnapshotInput {
            ioc_value: "evil.example".into(), ioc_type: "domain".into(), source_id: "list".into(),
            tags: tags.clone(), ..Default::default()
        }]).unwrap();
        let snapshot = IocSnapshot::open(&path, &digest).unwrap();
        assert_eq!(snapshot.publication_rows()[0].tags, tags);
    }

    #[test]
    fn published_snapshot_round_trips_through_the_serving_reader() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("iocs.parquet");
        let digest = write_ioc_snapshot(
            &path,
            &[
                IocSnapshotInput {
                    ioc_value: " BAD.Example ".to_string(),
                    ioc_type: "DOMAIN".to_string(),
                    source_id: "tenant-feed".to_string(),
                    threat_type: "c2".to_string(),
                    malware: "fixture".to_string(),
                    confidence_level: 95,
                    tags: vec!["controlled".to_string(), "controlled".to_string()],
                    first_seen_at: Some("2026-08-01T00:00:00Z".to_string()),
                    last_seen_at: Some("2026-08-15T00:00:00Z".to_string()),
                    ..IocSnapshotInput::default()
                },
                IocSnapshotInput {
                    ioc_value: "bad.example".to_string(),
                    ioc_type: "domain".to_string(),
                    source_id: "tenant-feed".to_string(),
                    threat_type: "c2".to_string(),
                    malware: "fixture".to_string(),
                    confidence_level: 95,
                    tags: vec!["controlled".to_string()],
                    first_seen_at: Some("2026-08-01T00:00:00Z".to_string()),
                    last_seen_at: Some("2026-08-15T00:00:00Z".to_string()),
                    ..IocSnapshotInput::default()
                },
            ],
        )
        .unwrap();
        let snapshot = IocSnapshot::open(&path, &digest).unwrap();
        let hits = snapshot.lookup_all("BAD.EXAMPLE");
        assert_eq!(hits.len(), 1, "normalized duplicate rows must collapse");
        assert_eq!(hits[0].ioc_type.as_deref(), Some("domain"));
        assert_eq!(hits[0].tags, vec!["controlled"]);
    }

    #[test]
    fn source_records_enforce_feed_type_cursor_and_ioc_scope() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("feed-selection.parquet");
        let row = |value: &str,
                   key_type: &str,
                   source_id: &str,
                   name: &str,
                   tags: &[&str],
                   published_at_ms: i64,
                   is_ioc: bool| IocSnapshotInput {
            ioc_value: value.to_string(),
            ioc_type: key_type.to_string(),
            source_id: source_id.to_string(),
            enrichment_name: name.to_string(),
            is_ioc,
            confidence_level: 90,
            tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
            published_at_ms,
            ..IocSnapshotInput::default()
        };
        let digest = write_ioc_snapshot(
            &path,
            &[
                row(
                    "one.example",
                    "domain",
                    "source-a",
                    "ThreatFox Daily",
                    &["apt29"],
                    100,
                    true,
                ),
                row(
                    "2.3.4.5",
                    "ip",
                    "source-a",
                    "ThreatFox Daily",
                    &["apt29"],
                    100,
                    true,
                ),
                row(
                    "two.example",
                    "domain",
                    "source-b",
                    "OTX Campaign",
                    &["apt29"],
                    200,
                    true,
                ),
                row(
                    "context.example",
                    "domain",
                    "context-source",
                    "Tenant Context",
                    &["apt29"],
                    300,
                    false,
                ),
            ],
        )
        .unwrap();
        let snapshot = IocSnapshot::open(&path, &digest).unwrap();

        let threatfox_domains = snapshot.source_records(
            &[],
            &["threatfox".to_string()],
            &[],
            &["domain".to_string()],
            None,
            100,
        );
        assert_eq!(
            threatfox_domains
                .iter()
                .map(|record| record.value.as_str())
                .collect::<Vec<_>>(),
            vec!["one.example"]
        );

        let campaign = snapshot.source_records(
            &[],
            &[],
            &["apt29".to_string()],
            &[],
            Some((100, "one.example")),
            100,
        );
        assert_eq!(
            campaign
                .iter()
                .map(|record| record.value.as_str())
                .collect::<Vec<_>>(),
            vec!["two.example"]
        );
        assert_eq!(
            snapshot.source_record_count(&["source-a".to_string()], &[], &[], &[], None,),
            2
        );
        assert!(
            campaign
                .iter()
                .all(|record| record.value != "context.example")
        );
    }

    #[test]
    fn publication_rejects_ambiguous_comma_delimited_tags() {
        let root = tempfile::tempdir().unwrap();
        let error = write_ioc_snapshot(
            &root.path().join("iocs.parquet"),
            &[IocSnapshotInput {
                ioc_value: "bad.example".to_string(),
                ioc_type: "domain".to_string(),
                source_id: "tenant-feed".to_string(),
                threat_type: String::new(),
                malware: String::new(),
                confidence_level: 95,
                tags: vec!["one,two".to_string()],
                first_seen_at: None,
                last_seen_at: None,
                ..IocSnapshotInput::default()
            }],
        )
        .expect_err("commas would corrupt the serving tag contract");
        assert!(error.to_string().contains("invalid tags"));
    }

    #[test]
    fn source_enrichment_values_win() {
        let mut endpoint = Map::from_iter([(
            "location".to_string(),
            json!({"country": "DE", "provider": "source"}),
        )]);
        let location = object_child(&mut endpoint, "location").unwrap();
        assert!(!insert_string_if_absent(
            location,
            "country",
            Some("US".to_string())
        ));
        assert_eq!(location["country"], "DE");
        assert_eq!(location["provider"], "source");
    }
}
