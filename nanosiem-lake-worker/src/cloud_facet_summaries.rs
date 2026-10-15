// SPDX-License-Identifier: AGPL-3.0-or-later

//! Correlated Cloud/Asset facets in the existing signed entity-range partial.
//! The empty value counts ALL input rows. A reader uses the nonempty groups
//! only when that coverage equals the signed part row count. Old/mixed parts
//! and ragged time edges keep the raw path. No new provenance field or file.

use anyhow::{Context, Result};
use arrow_array::RecordBatch;
use serde_json::Value;
use std::collections::BTreeMap;

use crate::part_ingest::partials::EntityRangeRow;

pub const PATH: &str = "nano.cloud_facets.v1";
pub const FIELDS: [&str; 6] = [
    "cloud.provider",
    "api.service.name",
    "cloud.region",
    "cloud.account.uid",
    "activity_name",
    "resources.type",
];
pub const CAP_BYTES: usize = 16 * 1024 * 1024;

pub fn enabled() -> bool {
    std::env::var("NANO_LAKE_CLOUD_FACET_SUMMARIES").as_deref() == Ok("1")
}

pub fn reads_enabled() -> bool {
    std::env::var("NANO_LAKE_CLOUD_FACET_READS").as_deref() == Ok("1")
}

pub struct Accumulator {
    rows: BTreeMap<String, EntityRangeRow>,
    covered: u64,
    min_us: i64,
    max_us: i64,
    bytes: usize,
    cap: usize,
    overflowed: bool,
    asset: bool,
}

impl Accumulator {
    pub fn new(cap: usize) -> Self {
        Self {
            rows: Default::default(),
            covered: 0,
            min_us: i64::MAX,
            max_us: i64::MIN,
            bytes: 0,
            cap,
            overflowed: false,
            asset: false,
        }
    }

    pub fn asset(cap: usize) -> Self {
        Self {
            asset: true,
            ..Self::new(cap)
        }
    }

    pub fn add_batch(&mut self, batch: &RecordBatch) -> Result<()> {
        if self.overflowed {
            return Ok(());
        }
        // Project before JSON conversion: never serialize message/raw_data or
        // unrelated root columns on this ingest path.
        let roots = if self.asset {
            &[
                "metadata",
                "device",
                "src_endpoint",
                "dst_endpoint",
                "actor",
                "user",
                "class_uid",
                "status",
            ][..]
        } else {
            &[
                "class_uid",
                "metadata",
                "cloud",
                "api",
                "activity_name",
                "resources",
            ][..]
        };
        let indices = roots
            .iter()
            .filter_map(|name| batch.schema().index_of(name).ok())
            .collect::<Vec<_>>();
        let projected = batch.project(&indices)?;
        let time = batch
            .column_by_name("time")
            .context("Correlated facet batch has no time")?;
        for start in (0..batch.num_rows()).step_by(256) {
            let slice = projected.slice(start, 256.min(batch.num_rows() - start));
            let mut output = Vec::new();
            let mut writer = arrow_json::LineDelimitedWriter::new(&mut output);
            writer.write(&slice)?;
            writer.finish()?;
            for (offset, line) in output
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .enumerate()
            {
                let event: Value = serde_json::from_slice(line)?;
                let at = crate::generation::event_time_us_from_array(time.as_ref(), start + offset)
                    .context("Correlated facet event time is invalid")?;
                self.add_event(&event, at)?;
                if self.overflowed {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn add_event(&mut self, event: &Value, at: i64) -> Result<()> {
        self.covered += 1;
        self.min_us = self.min_us.min(at);
        self.max_us = self.max_us.max(at);
        if !self.asset && event.get("class_uid").and_then(Value::as_i64) != Some(6003) {
            return Ok(());
        }
        let source = leaf(event, "metadata.log_source")
            .as_str()
            .unwrap_or("")
            .to_owned();
        let fields = if self.asset {
            &crate::asset_facet_summaries::FIELDS[..]
        } else {
            &FIELDS[..]
        };
        let values = fields
            .iter()
            .map(|field| {
                if *field == "resources.type" {
                    Value::Array(
                        event
                            .get("resources")
                            .and_then(Value::as_array)
                            .map(|resources| {
                                resources
                                    .iter()
                                    .map(|resource| leaf(resource, "type"))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    )
                } else {
                    leaf(event, field)
                }
            })
            .collect::<Vec<_>>();
        let value = serde_json::to_string(&(source, values))?;
        if let Some(row) = self.rows.get_mut(&value) {
            row.first_time = row.first_time.min(at);
            row.last_time = row.last_time.max(at);
            row.events += 1;
        } else {
            // Include both owned keys, tree node and row overhead. On overflow
            // discard ALL groups and coverage; never advertise a partial exact answer.
            self.bytes = self
                .bytes
                .saturating_add(value.len().saturating_mul(2) + 256);
            if self.bytes > self.cap {
                self.rows.clear();
                self.overflowed = true;
                return Ok(());
            }
            self.rows.insert(
                value.clone(),
                EntityRangeRow {
                    key: (self.path().into(), value),
                    first_time: at,
                    last_time: at,
                    events: 1,
                },
            );
        }
        Ok(())
    }

    fn path(&self) -> &'static str {
        if self.asset {
            crate::asset_facet_summaries::PATH
        } else {
            PATH
        }
    }

    pub fn into_rows(self) -> Vec<EntityRangeRow> {
        if self.overflowed {
            return Vec::new();
        }
        let path = self.path();
        let mut rows = self.rows.into_values().collect::<Vec<_>>();
        rows.push(EntityRangeRow {
            key: (path.into(), String::new()),
            first_time: if self.covered == 0 { 0 } else { self.min_us },
            last_time: if self.covered == 0 { 0 } else { self.max_us },
            events: self.covered,
        });
        rows
    }
}

fn leaf(event: &Value, field: &str) -> Value {
    field
        .split('.')
        .try_fold(event, |value, part| value.get(part))
        .cloned()
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn correlated_groups_preserve_arrays_scope_and_non_cloud_coverage() {
        let mut accumulator = Accumulator::new(CAP_BYTES);
        let event = json!({"class_uid":6003,"metadata":{"log_source":"audit"},"cloud":{"provider":"AWS"},"resources":[{"type":"Role"},{"type":"Role"},{"type":null}]});
        accumulator.add_event(&event, 12).unwrap();
        accumulator.add_event(&event, 15).unwrap();
        accumulator
            .add_event(&json!({"class_uid":1001}), 17)
            .unwrap();
        let rows = accumulator.into_rows();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].events, 3);
        let (source, values): (String, [Value; 6]) = serde_json::from_str(&rows[0].key.1).unwrap();
        assert_eq!(source, "audit");
        assert_eq!(values[5], json!(["Role", "Role", null]));
        assert_eq!(
            (rows[0].events, rows[0].first_time, rows[0].last_time),
            (2, 12, 15)
        );
    }

    #[test]
    fn overflow_drops_coverage_and_every_group() {
        let mut accumulator = Accumulator::new(1);
        accumulator
            .add_event(&json!({"class_uid":6003}), 1)
            .unwrap();
        assert!(accumulator.into_rows().is_empty());
    }

    #[test]
    fn asset_groups_keep_overlapping_identities_null_and_empty_users() {
        let mut accumulator = Accumulator::asset(CAP_BYTES);
        let event = json!({"class_uid":3002,"status":"Failure","device":{"hostname":"host"},"src_endpoint":{"hostname":"host","ip":"10.0.0.1"},"actor":{"user":{"name":""}},"user":{"name":"fallback"},"metadata":{"log_source":"audit"}});
        accumulator.add_event(&event, 12).unwrap();
        accumulator.add_event(&event, 15).unwrap();
        accumulator
            .add_event(&json!({"class_uid":1001}), 17)
            .unwrap();
        let rows = accumulator.into_rows();
        assert!(rows
            .iter()
            .all(|row| row.key.0 == crate::asset_facet_summaries::PATH));
        assert_eq!(
            rows.iter().find(|row| row.key.1.is_empty()).unwrap().events,
            3
        );
        let groups = rows
            .iter()
            .filter(|row| !row.key.1.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups.iter().map(|row| row.events).sum::<u64>(), 3);
        assert!(groups.iter().any(|row| {
            let (_, values): (String, Vec<Value>) = serde_json::from_str(&row.key.1).unwrap();
            values[8] == "" && values[7] == "fallback" && values[0] == values[1]
        }));
        let mut overflow = Accumulator::asset(1);
        overflow.add_event(&event, 1).unwrap();
        assert!(overflow.into_rows().is_empty());
    }
}
