// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3279: concatenate Parquet files of one schema by copying their encoded
//! column chunks, row group by row group, into a new file. No decode, no
//! re-encode and no native statement: a stepwise prevalence fold assembles
//! its per-hash-range step outputs (disjoint groups) into one state file this
//! way, and the 30-day history is the concatenation of its daily files.
//!
//! Row groups, their order and their column statistics are kept, so a reader
//! still prunes row groups by min/max (the state's `bucket` column).

use anyhow::{bail, Context, Result};
use parquet::column::writer::ColumnCloseResult;
use parquet::file::properties::WriterProperties;
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::file::writer::SerializedFileWriter;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Write `inputs` (in order) to `output` as one Parquet file. Every input
/// must have the schema of the first; otherwise nothing is kept at `output`.
pub(super) fn concat(inputs: &[PathBuf], output: &Path) -> Result<()> {
    let result = concat_inner(inputs, output);
    if result.is_err() {
        let _ = std::fs::remove_file(output);
    }
    result
}

fn concat_inner(inputs: &[PathBuf], output: &Path) -> Result<()> {
    let Some(first) = inputs.first() else {
        bail!("nothing to concatenate")
    };
    let first = SerializedFileReader::new(
        File::open(first).with_context(|| format!("open {}", first.display()))?,
    )?;
    let metadata = first.metadata().file_metadata();
    let schema = metadata.schema_descr_ptr();
    let properties = WriterProperties::builder()
        .set_key_value_metadata(metadata.key_value_metadata().cloned())
        .build();
    let mut writer = SerializedFileWriter::new(
        File::create(output)?,
        schema.root_schema_ptr(),
        Arc::new(properties),
    )?;
    for input in inputs {
        let file = File::open(input).with_context(|| format!("open {}", input.display()))?;
        let reader = SerializedFileReader::new(file.try_clone()?)?;
        let descriptor = reader.metadata().file_metadata().schema_descr();
        if descriptor.root_schema() != schema.root_schema() {
            bail!(
                "{} has another schema than the first input",
                input.display()
            );
        }
        for group in reader.metadata().row_groups() {
            let mut out = writer.next_row_group()?;
            for column in group.columns() {
                out.append_column(
                    &file,
                    ColumnCloseResult {
                        bytes_written: column.compressed_size() as u64,
                        rows_written: group.num_rows() as u64,
                        metadata: column.clone(),
                        bloom_filter: None,
                        column_index: None,
                        offset_index: None,
                    },
                )?;
            }
            out.close()?;
        }
    }
    writer.close()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::{ArrayRef, RecordBatch, StringArray, UInt64Array, UInt8Array};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use parquet::arrow::ArrowWriter;

    fn write(path: &Path, buckets: &[u8], entities: &[&str], counts: &[u64], row_group: usize) {
        let batch = RecordBatch::try_from_iter([
            (
                "bucket",
                Arc::new(UInt8Array::from(buckets.to_vec())) as ArrayRef,
            ),
            (
                "entity",
                Arc::new(StringArray::from(entities.to_vec())) as ArrayRef,
            ),
            (
                "total",
                Arc::new(UInt64Array::from(counts.to_vec())) as ArrayRef,
            ),
        ])
        .unwrap();
        let properties = WriterProperties::builder()
            .set_max_row_group_row_count(Some(row_group))
            .build();
        let mut writer = ArrowWriter::try_new(
            File::create(path).unwrap(),
            batch.schema(),
            Some(properties),
        )
        .unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
    }

    fn rows(path: &Path) -> Vec<(u8, String, u64)> {
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap())
            .unwrap()
            .build()
            .unwrap();
        let mut rows = Vec::new();
        for batch in reader {
            let batch = batch.unwrap();
            let bucket = batch
                .column(0)
                .as_any()
                .downcast_ref::<UInt8Array>()
                .unwrap();
            let entity = batch
                .column(1)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let total = batch
                .column(2)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .unwrap();
            for i in 0..batch.num_rows() {
                rows.push((bucket.value(i), entity.value(i).to_string(), total.value(i)));
            }
        }
        rows
    }

    #[test]
    fn concatenation_keeps_every_row_group_in_order_with_statistics() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b, empty, out) = (
            dir.path().join("a"),
            dir.path().join("b"),
            dir.path().join("e"),
            dir.path().join("out"),
        );
        write(&a, &[0, 0, 1], &["x", "y", "z"], &[1, 2, 3], 2);
        write(&empty, &[], &[], &[], 2);
        write(&b, &[7, 9], &["p", "q"], &[4, 5], 8);
        concat(&[a.clone(), empty.clone(), b.clone()], &out).unwrap();
        let mut expected = rows(&a);
        expected.extend(rows(&b));
        assert_eq!(rows(&out), expected);
        let reader = SerializedFileReader::new(File::open(&out).unwrap()).unwrap();
        let groups = reader.metadata().row_groups();
        assert_eq!(groups.len(), 3, "2 + 0 + 1 row groups, as written");
        // Row-group min/max survive: readers still prune by bucket.
        let stats = groups
            .iter()
            .map(|group| {
                let statistics = group.column(0).statistics().unwrap();
                match statistics {
                    parquet::file::statistics::Statistics::Int32(value) => {
                        (*value.min_opt().unwrap(), *value.max_opt().unwrap())
                    }
                    other => panic!("unexpected statistics {other:?}"),
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(stats, vec![(0, 0), (1, 1), (7, 9)]);
    }

    #[test]
    fn another_schema_is_refused_and_leaves_no_output() {
        let dir = tempfile::tempdir().unwrap();
        let (a, out) = (dir.path().join("a"), dir.path().join("out"));
        write(&a, &[0], &["x"], &[1], 2);
        let other = dir.path().join("other");
        let batch = RecordBatch::try_from_iter([(
            "bucket",
            Arc::new(UInt64Array::from(vec![1_u64])) as ArrayRef,
        )])
        .unwrap();
        let mut writer =
            ArrowWriter::try_new(File::create(&other).unwrap(), batch.schema(), None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        assert!(concat(&[a, other], &out).is_err());
        assert!(!out.exists());
        assert!(concat(&[], &out).is_err());
    }
}
