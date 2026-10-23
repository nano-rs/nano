// SPDX-License-Identifier: AGPL-3.0-or-later
//! Explicit audited recovery for the internal ops tenant. A fixed dry-run
//! snapshot bounds the policy; missing/invalid times ALWAYS retain a segment.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::io::Read;

pub const OPS_TENANT: &str = "eb0126d5-dbd5-4e6a-8414-7310610074ac";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BacklogSummary {
    pub segments: u64,
    pub bytes: u64,
    pub rows: u64,
    pub kept: u64,
    pub ranges: Vec<[u64; 2]>,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BacklogSkipPlan {
    pub version: u32,
    pub tenant_uuid: String,
    pub cutoff_ms: i64,
    pub first_seq: u64,
    pub through_seq: u64,
    pub summary: BacklogSummary,
    pub plan_hash: String,
    pub at: i64,
}

impl BacklogSkipPlan {
    pub fn validate(&self, tenant: &str, now_ms: i64) -> Result<()> {
        ensure!(tenant == OPS_TENANT && self.tenant_uuid == tenant, "recovery tenant is not allowlisted");
        ensure!(self.version == 1 && self.cutoff_ms > 0 && self.cutoff_ms <= now_ms - 3_600_000,
            "invalid recovery age boundary");
        ensure!(self.first_seq > 0 && self.first_seq <= self.through_seq && self.through_seq <= super::protocol::MAX_SEQ,
            "invalid recovery sequence boundary");
        ensure!(self.summary.ranges.len() <= 8192, "too many recovery ranges");
        let (mut previous, mut count) = (self.first_seq - 1, 0_u64);
        for [first, last] in &self.summary.ranges {
            ensure!(*first > previous && *first >= self.first_seq && *last >= *first && *last <= self.through_seq,
                "invalid recovery range");
            count += last - first + 1;
            previous = *last;
        }
        ensure!(count == self.summary.segments && count.checked_add(self.summary.kept) == Some(self.through_seq - self.first_seq + 1),
            "recovery counts differ from ranges");
        ensure!(crate::parts::is_sha256_hex(&self.summary.manifest_sha256), "invalid recovery manifest hash");
        ensure!(self.canonical_hash()? == self.plan_hash, "recovery plan hash differs");
        Ok(())
    }

    pub fn canonical_hash(&self) -> Result<String> {
        // Struct serialization preserves the same explicit field order as the
        // authority's canonical plan. Never hash a JSON map's incidental order.
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Payload<'a> {
            version: u32, tenant_uuid: &'a str, cutoff_ms: i64, first_seq: u64,
            through_seq: u64, summary: &'a BacklogSummary,
        }
        let payload = Payload { version: self.version, tenant_uuid: &self.tenant_uuid, cutoff_ms: self.cutoff_ms,
            first_seq: self.first_seq, through_seq: self.through_seq, summary: &self.summary };
        Ok(crate::parts::sha256_hex(&serde_json::to_vec(&payload)?))
    }

    pub fn includes(&self, seq: u64) -> bool {
        self.summary.ranges.iter().any(|[first, last]| (*first..=*last).contains(&seq))
    }
}

/// Exact row count if EVERY canonical event time is strictly older than the
/// cutoff. Reads only the top-level canonical time column (the same column
/// bronze admission uses), never envelope payload values or footer maxima.
/// Unsupported/corrupt files, nulls, empty files and mixed/recent/future rows
/// are retained. Errors contain no row content and are deliberately not logged.
pub fn old_segment_rows(bytes: &[u8], cutoff_ms: i64) -> Option<u64> {
    inspect(bytes, cutoff_ms).ok().flatten()
}

fn inspect(bytes: &[u8], cutoff_ms: i64) -> Result<Option<u64>> {
    use parquet::arrow::{arrow_reader::ParquetRecordBatchReaderBuilder, ProjectionMask};
    let bytes = if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(bytes).take(256 * 1024 * 1024 + 1).read_to_end(&mut decoded)?;
        ensure!(decoded.len() <= 256 * 1024 * 1024, "recovery decode bound");
        decoded
    } else { bytes.to_vec() };
    let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))?;
    let count = builder.metadata().file_metadata().num_rows();
    ensure!(count > 0 && count <= crate::bronze::MAX_BRONZE_ROWS as i64, "recovery row bound");
    let index = builder.schema().index_of("time")?;
    let projection = ProjectionMask::roots(builder.parquet_schema(), [index]);
    let reader = builder.with_projection(projection).with_batch_size(1024).build()?;
    let mut rows = 0;
    for batch in reader {
        let batch = batch?;
        if batch.column(0).null_count() != 0 { return Ok(None); }
        if matches!(batch.column(0).data_type(), arrow_schema::DataType::Timestamp(_, _)) {
            let (_, max) = crate::iceberg::batch_time_bounds_ms(&batch)?;
            if max >= cutoff_ms { return Ok(None); }
            rows += batch.num_rows() as u64;
            continue;
        }
        let mut writer = arrow_json::LineDelimitedWriter::new(Vec::new());
        writer.write(&batch)?;
        writer.finish()?;
        for line in writer.into_inner().split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            let row: serde_json::Value = serde_json::from_slice(line)?;
            let Some(time) = crate::iceberg::ocsf_time_millis(row.get("time")) else { return Ok(None) };
            if time >= cutoff_ms { return Ok(None); }
            rows += 1;
        }
    }
    ensure!(rows == count as u64, "recovery row count differs");
    Ok(Some(rows))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Arc;
    pub(crate) fn parquet(times: Vec<Option<i64>>) -> Vec<u8> {
        let schema = Arc::new(arrow_schema::Schema::new(vec![arrow_schema::Field::new("time", arrow_schema::DataType::Int64, true)]));
        let batch = arrow_array::RecordBatch::try_new(schema.clone(), vec![Arc::new(arrow_array::Int64Array::from(times))]).unwrap();
        let mut bytes = Vec::new();
        let mut writer = parquet::arrow::ArrowWriter::try_new(&mut bytes, schema, None).unwrap();
        writer.write(&batch).unwrap(); writer.close().unwrap(); bytes
    }
    #[test]
    fn backlog_plan_hash_matches_authority_wire_fixture() {
        let mut plan = BacklogSkipPlan { version: 1, tenant_uuid: OPS_TENANT.into(), cutoff_ms: 6_000_000,
            first_seq: 1, through_seq: 4, summary: BacklogSummary { segments: 2, bytes: 12, rows: 4, kept: 2,
                ranges: vec![[1, 1], [3, 3]], manifest_sha256: "a".repeat(64) }, at: 10_000_000,
            plan_hash: "38c5b887be94c6672fbd48253518357a1376e80dab974d2ad44de8a05ecca8c6".into() };
        plan.validate(OPS_TENANT, 10_000_000).unwrap();
        plan.summary.bytes += 1;
        assert!(plan.validate(OPS_TENANT, 10_000_000).is_err());
    }
    #[test]
    fn backlog_native_timestamp_units_keep_boundary_and_nulls() {
        for unit in [arrow_schema::TimeUnit::Second, arrow_schema::TimeUnit::Millisecond,
            arrow_schema::TimeUnit::Microsecond, arrow_schema::TimeUnit::Nanosecond] {
            let factor = match unit { arrow_schema::TimeUnit::Second => 1, arrow_schema::TimeUnit::Millisecond => 1000,
                arrow_schema::TimeUnit::Microsecond => 1_000_000, _ => 1_000_000_000 };
            let raw: arrow_array::ArrayRef = Arc::new(arrow_array::Int64Array::from(vec![Some(factor), Some(2 * factor)]));
            let data_type = arrow_schema::DataType::Timestamp(unit, None);
            let values = arrow_cast::cast(&raw, &data_type).unwrap();
            let schema = Arc::new(arrow_schema::Schema::new(vec![arrow_schema::Field::new("time", data_type, true)]));
            let batch = arrow_array::RecordBatch::try_new(schema.clone(), vec![values]).unwrap();
            let mut bytes = Vec::new();
            let mut writer = parquet::arrow::ArrowWriter::try_new(&mut bytes, schema, None).unwrap();
            writer.write(&batch).unwrap(); writer.close().unwrap();
            assert_eq!(old_segment_rows(&bytes, 2001), Some(2));
            assert_eq!(old_segment_rows(&bytes, 2000), None);
        }
    }
    #[test]
    fn backlog_age_requires_every_row_strictly_old() {
        assert_eq!(old_segment_rows(&parquet(vec![Some(1), Some(99)]), 100), Some(2));
        for times in [vec![Some(1), Some(100)], vec![Some(1), Some(101)], vec![Some(1), None], vec![]] {
            assert_eq!(old_segment_rows(&parquet(times), 100), None);
        }
        assert_eq!(old_segment_rows(b"not parquet", 100), None);
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gzip, &parquet(vec![Some(1)])).unwrap();
        assert_eq!(old_segment_rows(&gzip.finish().unwrap(), 100), Some(1));
    }
}
