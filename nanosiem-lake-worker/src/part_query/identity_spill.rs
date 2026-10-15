// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact local identity backfill for large signed parts. Small sorted runs
//! and bounded fan-in limit the observation and merge buffers.

use anyhow::{ensure, Result};
use std::path::{Path, PathBuf};

use crate::identity_observations::{IdentityAccumulator, IDENTITY_PATH};
use crate::part_ingest::partials::{
    merge_sorted_capped, write_sorted_capped, EntityRangeRow, PartialSpillLimit,
};

pub(super) const FLAG: &str = "NANO_LAKE_IDENTITY_SPILL_BACKFILL";
pub(super) const MARKER: &[u8] = b"identity-spill-v1";
const BATCH_ROWS: usize = 512;
const FAN_IN: usize = 4;
const ACTIVE_BYTES: u64 = 1 << 30;

pub(super) fn enabled() -> bool {
    std::env::var(FLAG).as_deref() == Ok("1")
}

struct Runs {
    directory: tempfile::TempDir,
    levels: Vec<Vec<PathBuf>>,
    sequence: u64,
    bytes: u64,
    cap: u64,
    batch_rows: usize,
}

impl Runs {
    fn next(&mut self) -> PathBuf {
        self.sequence += 1;
        self.directory
            .path()
            .join(format!("{:016}.parquet", self.sequence))
    }

    fn merge(&mut self, inputs: &[PathBuf]) -> Result<PathBuf> {
        ensure!(
            inputs.len() <= FAN_IN,
            "identity spill fan-in exceeds bound"
        );
        let output = self.next();
        // Active inputs occupy at most cap; one new output at most cap:
        // the transient disk peak never exceeds 2 * cap.
        merge_sorted_capped::<EntityRangeRow>(
            &inputs.iter().map(PathBuf::as_path).collect::<Vec<_>>(),
            &output,
            self.batch_rows,
            self.cap,
        )?;
        for input in inputs {
            self.bytes -= std::fs::metadata(input)?.len();
            std::fs::remove_file(input)?;
        }
        self.bytes += std::fs::metadata(&output)?.len();
        if self.bytes > self.cap {
            return Err(PartialSpillLimit.into());
        }
        Ok(output)
    }

    fn push(&mut self, mut run: PathBuf) -> Result<()> {
        self.bytes += std::fs::metadata(&run)?.len();
        if self.bytes > self.cap {
            return Err(PartialSpillLimit.into());
        }
        let mut level = 0;
        loop {
            if level == self.levels.len() {
                self.levels.push(Vec::new());
            }
            self.levels[level].push(run);
            if self.levels[level].len() < FAN_IN {
                return Ok(());
            }
            let inputs = std::mem::take(&mut self.levels[level]);
            run = self.merge(&inputs)?;
            level += 1;
        }
    }

    fn finish(mut self, output: &Path) -> Result<()> {
        let mut pending = std::mem::take(&mut self.levels)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        while pending.len() > 1 {
            let mut next = Vec::new();
            for inputs in pending.chunks(FAN_IN) {
                next.push(if inputs.len() == 1 {
                    inputs[0].clone()
                } else {
                    self.merge(inputs)?
                });
            }
            pending = next;
        }
        ensure!(pending.len() == 1, "identity spill has no coverage run");
        std::fs::rename(&pending[0], output)?;
        Ok(())
    }
}

/// Only the caller's temporary local-cache path is written. A false answer
/// never publishes partial coverage; the caller marks this derivation version
/// unindexable and keeps the ordinary event fallback.
pub(super) fn derive(paths: &[PathBuf], output: &Path, expected_rows: u64) -> Result<bool> {
    derive_with(
        paths,
        output,
        expected_rows,
        crate::identity_observations::BACKFILL_BYTES_CAP,
        BATCH_ROWS,
        ACTIVE_BYTES,
    )
}

fn derive_with(
    paths: &[PathBuf],
    output: &Path,
    expected_rows: u64,
    cap_bytes: usize,
    batch_rows: usize,
    disk_cap: u64,
) -> Result<bool> {
    let parent = output
        .parent()
        .ok_or_else(|| anyhow::anyhow!("identity spill has no parent"))?;
    let directory = tempfile::Builder::new()
        .prefix(".identity-spill-")
        .tempdir_in(parent)?;
    let mut runs = Runs {
        directory,
        levels: Vec::new(),
        sequence: 0,
        bytes: 0,
        cap: disk_cap,
        batch_rows,
    };
    let mut covered = 0_u64;
    let result = (|| -> Result<bool> {
        super::identity::projected_batches(paths, batch_rows, |batch| {
            let mut accumulator = IdentityAccumulator::new(cap_bytes);
            accumulator.add_batch(&batch)?;
            if accumulator.overflowed() {
                return Err(PartialSpillLimit.into());
            }
            covered = covered
                .checked_add(accumulator.covered_rows())
                .ok_or_else(|| anyhow::anyhow!("identity coverage overflow"))?;
            let rows = accumulator
                .into_rows()
                .into_iter()
                .map(|(value, range)| EntityRangeRow {
                    key: (IDENTITY_PATH.to_string(), value),
                    first_time: range.first_us,
                    last_time: range.last_us,
                    events: range.events,
                })
                .collect::<Vec<_>>();
            let run = runs.next();
            write_sorted_capped(rows, &run, batch_rows, disk_cap.saturating_sub(runs.bytes))?;
            runs.push(run)?;
            Ok(true)
        })?;
        if covered != expected_rows {
            return Ok(false);
        }
        if covered == 0 {
            return Ok(false);
        }
        runs.finish(output)?;
        Ok(true)
    })();
    match result {
        Err(error)
            if error.chain().any(|cause| {
                cause.downcast_ref::<PartialSpillLimit>().is_some()
                    || cause
                        .downcast_ref::<std::io::Error>()
                        .and_then(std::io::Error::get_ref)
                        .is_some_and(|inner| inner.downcast_ref::<PartialSpillLimit>().is_some())
            }) =>
        {
            Ok(false)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_observations::BACKFILL_BYTES_CAP;

    fn data(directory: &Path) -> (PathBuf, u64) {
        use arrow_array::{
            ArrayRef, RecordBatch, StringArray, StructArray, TimestampMicrosecondArray,
        };
        use arrow_schema::{DataType, Field, Fields, Schema, TimeUnit};
        use std::sync::Arc;
        let rows = 513;
        let endpoint_fields = Fields::from(vec![
            Field::new("ip", DataType::Utf8, false),
            Field::new("hostname", DataType::Utf8, false),
        ]);
        let ips = (0..rows)
            .map(|i| format!("10.1.3.{}", i % 5))
            .collect::<Vec<_>>();
        let hosts = (0..rows)
            .map(|i| format!("host-{}.corp.local", i % 41))
            .collect::<Vec<_>>();
        let endpoint = StructArray::new(
            endpoint_fields.clone(),
            vec![
                Arc::new(StringArray::from(ips)) as ArrayRef,
                Arc::new(StringArray::from(hosts)) as ArrayRef,
            ],
            None,
        );
        let metadata_fields = Fields::from(vec![Field::new("log_source", DataType::Utf8, false)]);
        let metadata = StructArray::new(
            metadata_fields.clone(),
            vec![Arc::new(StringArray::from(
                (0..rows)
                    .map(|i| {
                        if i % 3 == 0 {
                            "windows_sysmon"
                        } else {
                            "audit"
                        }
                    })
                    .collect::<Vec<_>>(),
            ))],
            None,
        );
        let schema = Arc::new(Schema::new(vec![
            Field::new(
                "time",
                DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())),
                false,
            ),
            Field::new("src_endpoint", DataType::Struct(endpoint_fields), false),
            Field::new("metadata", DataType::Struct(metadata_fields), false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(
                    TimestampMicrosecondArray::from(
                        (0..rows)
                            .map(|i| (i as i64 % 7) * 86_400_000_000 + i as i64)
                            .collect::<Vec<_>>(),
                    )
                    .with_timezone("+00:00"),
                ),
                Arc::new(endpoint),
                Arc::new(metadata),
            ],
        )
        .unwrap();
        let path = directory.join("data.parquet");
        let mut writer = parquet::arrow::ArrowWriter::try_new(
            std::fs::File::create(&path).unwrap(),
            schema,
            None,
        )
        .unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        (path, rows as u64)
    }

    #[test]
    fn spilled_historical_index_matches_uncapped_ingest_with_bounded_fan_in() {
        let directory = tempfile::tempdir().unwrap();
        let (path, rows) = data(directory.path());
        let paths = [path];
        assert!(
            super::super::identity::derive_from_data_files(&paths, 8_192)
                .unwrap()
                .overflowed()
        );
        let expected = super::super::identity::derive_from_data_files(&paths, BACKFILL_BYTES_CAP)
            .unwrap()
            .into_rows();
        let output = directory.path().join("index.parquet");
        assert!(derive_with(&paths, &output, rows, 8_192, 8, 16 << 20).unwrap());
        use crate::part_ingest::partials::PartialRow;
        let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
            std::fs::File::open(&output).unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();
        let actual = reader
            .flat_map(|batch| EntityRangeRow::from_batch(&batch.unwrap()).unwrap())
            .map(|row| (row.key.1, row.first_time, row.last_time, row.events))
            .collect::<Vec<_>>();
        let expected = expected
            .into_iter()
            .map(|(value, range)| (value, range.first_us, range.last_us, range.events))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            2,
            "no temporary runs survive publication"
        );
    }

    #[tokio::test]
    #[ignore = "requires digest-verified native chDB"]
    async fn native_spill_lookup_matches_uncapped_index_for_120_time_and_deny_windows() {
        use super::super::identity::{plan_lookup, plan_nat, Item, LookupKind};
        use crate::executor::NativeExecutor;
        use crate::native::NativeChdb;
        use crate::part_ingest::partials::write_sorted;
        let runtime = NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        )
        .unwrap();
        // chDB owns process-global background threads. As in the other native
        // fixtures, retain its library until process exit rather than dlclose.
        std::mem::forget(runtime.clone());
        let executor = NativeExecutor::start(runtime, 1).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let (path, rows) = data(directory.path());
        let paths = [path];
        let spill = directory.path().join("spill.parquet");
        let baseline = directory.path().join("baseline.parquet");
        assert!(derive_with(&paths, &spill, rows, 8_192, 8, 16 << 20).unwrap());
        let expected = super::super::identity::derive_from_data_files(&paths, BACKFILL_BYTES_CAP)
            .unwrap()
            .into_rows()
            .into_iter()
            .map(|(value, range)| EntityRangeRow {
                key: (IDENTITY_PATH.into(), value),
                first_time: range.first_us,
                last_time: range.last_us,
                events: range.events,
            })
            .collect();
        write_sorted(expected, &baseline).unwrap();
        for i in 0..120 {
            let items = vec![Item {
                ordinal: 0,
                key: format!("10.1.3.{}", i % 6),
                reference_us: (i % 9) * 86_400_000_000 + i * 3,
            }];
            let denied = if i % 3 == 0 {
                vec!["windows_sysmon".to_string()]
            } else {
                Vec::new()
            };
            for nat in [false, true] {
                let plan = |file: &Path| {
                    if nat {
                        plan_nat(
                            file.to_str().unwrap(),
                            &items,
                            &denied,
                            " SETTINGS max_threads=1",
                        )
                    } else {
                        plan_lookup(
                            file.to_str().unwrap(),
                            LookupKind::Ip,
                            &items,
                            &denied,
                            " SETTINGS max_threads=1",
                        )
                    }
                };
                let (sql, params) = plan(&spill);
                let actual = executor.execute_sql(sql, params).await.unwrap();
                let (sql, params) = plan(&baseline);
                let expected = executor.execute_sql(sql, params).await.unwrap();
                let decode = |bytes: &[u8]| {
                    bytes
                        .split(|b| *b == b'\n')
                        .filter(|line| !line.is_empty())
                        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
                        .collect::<Vec<_>>()
                };
                assert_eq!(
                    decode(&actual.data),
                    decode(&expected.data),
                    "window {i}, NAT {nat}"
                );
            }
        }
        // Let the detached executor close its native session before the test
        // process runs chDB's global destructors.
        drop(executor);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    #[test]
    fn resource_or_coverage_refusal_never_publishes_a_partial_index() {
        let directory = tempfile::tempdir().unwrap();
        let (path, rows) = data(directory.path());
        let output = directory.path().join("index.parquet");
        assert!(!derive_with(
            &[path.clone()],
            &output,
            rows + 1,
            BACKFILL_BYTES_CAP,
            8,
            16 << 20
        )
        .unwrap());
        assert!(!output.exists());
        assert!(!derive_with(&[path], &output, rows, BACKFILL_BYTES_CAP, 8, 1).unwrap());
        assert!(!output.exists());
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            1,
            "failed runs are retired"
        );
    }
}
