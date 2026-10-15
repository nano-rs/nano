// SPDX-License-Identifier: AGPL-3.0-or-later

//! Count parity: the phase-4 exit gate.
//!
//! "Every hour before T0 is covered; per-hour row counts equal the current
//! generation's." The generation's counts come from an independent source,
//! the Iceberg manifests of the generation's snapshot (`record_count` and the
//! `event_hour` partition of each live data file). The adopted counts come
//! from the verified part log: each adopted part's signed record carries
//! per-hour row counts. Neither side is derived from the other.

use anyhow::{bail, Context, Result};
use iceberg::spec::{DataContentType, DataFileFormat, Literal, ManifestContentType, PrimitiveLiteral};
use iceberg::table::Table;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::job::adopted_parts;
use super::plan::split_source_uri;
use crate::parts::part_log::ObjectStore;
use crate::parts::provenance::{PartInputs, TenantKeySet};
use crate::parts::{event_hour_of, HOUR_US};

/// The generation's per-object counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationCounts {
    pub snapshot_id: i64,
    /// Bucket key → (event hour partition, record count).
    pub objects: BTreeMap<String, ObjectCount>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectCount {
    pub event_hour: i32,
    pub rows: u64,
}

impl GenerationCounts {
    /// Read the live data files of `snapshot_id` from its Iceberg manifests.
    pub async fn from_iceberg_snapshot(table: &Table, snapshot_id: i64) -> Result<Self> {
        let snapshot = table
            .metadata()
            .snapshot_by_id(snapshot_id)
            .with_context(|| format!("snapshot {snapshot_id} is not in the table metadata"))?
            .clone();
        let manifest_list = table
            .manifest_list_reader(&snapshot)
            .load()
            .await
            .context("load the generation's Iceberg manifest list")?;
        let mut objects = BTreeMap::new();
        for descriptor in manifest_list.consume_entries() {
            if descriptor.content != ManifestContentType::Data {
                bail!("generation snapshot has a delete manifest; counts would not be exact");
            }
            let manifest = descriptor.load_manifest(table.file_io()).await?;
            for entry in manifest.entries().iter().filter(|e| e.is_alive()) {
                if entry.content_type() != DataContentType::Data || entry.file_format() != DataFileFormat::Parquet {
                    bail!("generation snapshot holds a non-Parquet or delete file");
                }
                let event_hour = match entry.data_file().partition().fields() {
                    [Some(Literal::Primitive(PrimitiveLiteral::Int(hour)))] => *hour,
                    _ => bail!("data file {} has no event_hour partition", entry.file_path()),
                };
                let (_, key) = split_source_uri(entry.file_path())?;
                let count = ObjectCount { event_hour, rows: entry.data_file().record_count() };
                if objects.insert(key.to_string(), count).is_some() {
                    bail!("data file {key} is live twice");
                }
            }
        }
        Ok(Self { snapshot_id, objects })
    }

    /// Per-hour expected rows for hours before `t0_hour`.
    pub fn hours_before(&self, t0_hour: i32) -> BTreeMap<i32, u64> {
        let mut hours = BTreeMap::new();
        for count in self.objects.values().filter(|c| c.event_hour < t0_hour) {
            *hours.entry(count.event_hour).or_default() += count.rows;
        }
        hours
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HourMismatch {
    pub event_hour: i32,
    pub expected: u64,
    pub adopted: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ParityReport {
    pub ok: bool,
    pub t0_hour: i32,
    pub first_hour: Option<i32>,
    /// Hours in `[first_hour, t0_hour)`.
    pub hours_in_range: usize,
    pub hours_with_rows: usize,
    pub hours_matched: usize,
    /// Hours with no rows on either side (covered trivially).
    pub empty_hours: usize,
    pub expected_rows: u64,
    pub adopted_rows: u64,
    pub mismatches: Vec<HourMismatch>,
    /// Generation objects before T0 with no live adopted part.
    pub missing_objects: Vec<String>,
    /// Adopted objects the generation does not hold.
    pub unexpected_objects: Vec<String>,
    /// Objects whose adopted rows differ from their Iceberg record count, or
    /// whose rows are not all in their `event_hour` partition.
    pub object_row_mismatches: Vec<String>,
    /// Adopted rows at or after T0 (shadow ingest owns those hours).
    pub adopted_hours_at_or_after_t0: Vec<i32>,
    /// Hours after the generation's newest event and before T0: neither the
    /// generation nor shadow ingest covers them.
    pub horizon_gap_hours: Vec<i32>,
    /// Adopted parts that are not `h` parts. Adoption refuses multi-hour
    /// objects (contract 8.1), so any here fails the gate.
    pub non_hour_parts: Vec<String>,
}

/// Check adopted history in the tenant's log against the generation.
pub async fn check_parity(
    store: &dyn ObjectStore,
    tenant_id: &str,
    trusted: &TenantKeySet,
    expected: &GenerationCounts,
    t0_us: i64,
    generation_max_event_hour: i32,
) -> Result<ParityReport> {
    if t0_us % HOUR_US != 0 {
        bail!("T0 must be hour aligned");
    }
    let t0_hour = event_hour_of(t0_us);
    let adopted = adopted_parts(store, tenant_id, trusted).await?;
    let mut report = ParityReport { t0_hour, ..ParityReport::default() };

    let mut adopted_hours: BTreeMap<i32, u64> = BTreeMap::new();
    let mut after_t0 = BTreeSet::new();
    for (key, part) in &adopted {
        if part.record.level != crate::parts::Level::Hour {
            report.non_hour_parts.push(key.clone());
        }
        for hour in &part.record.hours {
            if hour.event_hour >= t0_hour {
                after_t0.insert(hour.event_hour);
            }
            *adopted_hours.entry(hour.event_hour).or_default() += hour.rows;
        }
        match expected.objects.get(key) {
            None => report.unexpected_objects.push(key.clone()),
            Some(count) => {
                let PartInputs::Adopted { objects, .. } = &part.record.inputs else { unreachable!() };
                // An hour-partitioned data file holds exactly its partition hour.
                let in_partition = part.record.hours.len() == 1 && part.record.hours[0].event_hour == count.event_hour;
                if objects[0].rows != count.rows || part.record.rows != count.rows || !in_partition {
                    report.object_row_mismatches.push(key.clone());
                }
            }
        }
    }
    report.adopted_hours_at_or_after_t0 = after_t0.into_iter().collect();
    for (key, count) in &expected.objects {
        if count.event_hour < t0_hour && !adopted.contains_key(key) {
            report.missing_objects.push(key.clone());
        }
    }

    let expected_hours = expected.hours_before(t0_hour);
    let first = expected_hours.keys().next().copied().into_iter().chain(adopted_hours.keys().next().copied()).min();
    report.first_hour = first;
    if let Some(first) = first {
        for hour in first..t0_hour {
            report.hours_in_range += 1;
            let want = expected_hours.get(&hour).copied().unwrap_or(0);
            let got = adopted_hours.get(&hour).copied().unwrap_or(0);
            report.expected_rows += want;
            report.adopted_rows += got;
            match (want, got) {
                (0, 0) => report.empty_hours += 1,
                (w, g) if w == g => {
                    report.hours_with_rows += 1;
                    report.hours_matched += 1;
                }
                (w, g) => {
                    report.hours_with_rows += 1;
                    report.mismatches.push(HourMismatch { event_hour: hour, expected: w, adopted: g });
                }
            }
        }
        report.horizon_gap_hours = ((generation_max_event_hour + 1).max(first)..t0_hour).collect();
    }
    report.ok = report.mismatches.is_empty()
        && report.missing_objects.is_empty()
        && report.unexpected_objects.is_empty()
        && report.object_row_mismatches.is_empty()
        && report.adopted_hours_at_or_after_t0.is_empty()
        && report.horizon_gap_hours.is_empty()
        && report.non_hour_parts.is_empty();
    Ok(report)
}
