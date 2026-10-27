// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4664: the derived IOC indicator columns of a data file.
//!
//! The contract (column names, which leaves feed which column, the bare-term
//! routing rule) lives in [`nanosiem_core::search::lake_indicators`]; this
//! module derives the columns from a part batch for [`PartWriter`] and drops
//! them again from a read batch.
//!
//! They are file-only: the part writer appends them to the file schema it
//! writes (never to the part or tenant schema), recomputes them from the
//! stored row on every write, and every reader that turns a data file back
//! into part rows ([`strip`]) drops them. A file gets them only when every
//! indicator leaf of its schema is a string the derivation reads; otherwise
//! (or for any file written before this) it carries no marker and no
//! reader answers anything from it.
//!
//! [`PartWriter`]: crate::part_ingest::writer::PartWriter

use anyhow::{ensure, Result};
use arrow_array::builder::{ListBuilder, StringBuilder};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use nanosiem_core::search::lake_indicators::{self as contract, Kind};
use std::collections::BTreeSet;
use std::sync::Arc;

#[cfg(test)]
static WRITE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Tests: write files without the columns (the layout before NAN-4664).
#[cfg(test)]
pub fn set_write_enabled(enabled: bool) {
    WRITE.store(enabled, std::sync::atomic::Ordering::SeqCst);
}

fn write_enabled() -> bool {
    #[cfg(test)]
    return WRITE.load(std::sync::atomic::Ordering::SeqCst);
    #[cfg(not(test))]
    true
}

fn list_type() -> DataType {
    DataType::List(Arc::new(Field::new("item", DataType::Utf8, true)))
}

/// The Parquet leaf path of a kind's column (`<column>.list.item`).
pub fn leaf_path(kind: Kind) -> [String; 3] {
    [kind.column().to_string(), "list".to_string(), "item".to_string()]
}

/// What the writer derives for one part schema.
#[derive(Debug, Clone)]
pub struct Derivation {
    /// The part schema plus the indicator columns.
    pub file_schema: SchemaRef,
    /// `(dotted event path, kind)` of every indicator string leaf.
    leaves: Vec<(String, Kind)>,
}

impl Derivation {
    /// `None` (write no columns) when disabled, when the part schema already
    /// names an indicator column, or when some indicator leaf is not a
    /// string the derivation can read: such a file stays uncovered.
    pub fn for_schema(schema: &SchemaRef) -> Option<Self> {
        if !write_enabled() || schema.fields().iter().any(|field| contract::is_indicator_column(field.name())) {
            return None;
        }
        let mut leaves = Vec::new();
        for field in schema.fields() {
            if !walk(field.name(), field.data_type(), &mut leaves) {
                return None;
            }
        }
        let mut fields = schema.fields().iter().cloned().collect::<Vec<_>>();
        fields.extend(Kind::ALL.iter().map(|kind| Arc::new(Field::new(kind.column(), list_type(), true))));
        let file_schema = Arc::new(Schema::new_with_metadata(fields, schema.metadata().clone()));
        Some(Self { file_schema, leaves })
    }

    /// `batch` (of the part schema) with its indicator columns appended.
    pub fn extend(&self, batch: &RecordBatch) -> Result<RecordBatch> {
        let rows = batch.num_rows();
        let compiled = self
            .leaves
            .iter()
            .map(|(path, kind)| {
                let compiled = crate::generation::CompiledStringPath::new(batch, path);
                ensure!(compiled.is_some(), "indicator leaf {path} does not resolve in the part batch");
                Ok((compiled.expect("checked"), *kind))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut builders = Kind::ALL.map(|_| ListBuilder::new(StringBuilder::new()));
        let mut values: [BTreeSet<String>; Kind::ALL.len()] = Default::default();
        let slot = |kind: Kind| Kind::ALL.iter().position(|k| *k == kind).expect("kind");
        for row in 0..rows {
            values.iter_mut().for_each(BTreeSet::clear);
            for (compiled, kind) in &compiled {
                for value in compiled.strings(row) {
                    values[slot(*kind)].insert(contract::normalize(&value));
                }
            }
            for (builder, set) in builders.iter_mut().zip(&values) {
                for value in set {
                    builder.values().append_value(value);
                }
                builder.append(true);
            }
        }
        let mut columns = batch.columns().to_vec();
        columns.extend(builders.iter_mut().map(|builder| Arc::new(builder.finish()) as ArrayRef));
        Ok(RecordBatch::try_new(self.file_schema.clone(), columns)?)
    }
}

fn is_string(data_type: &DataType) -> bool {
    matches!(data_type, DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View)
}

/// Collect indicator string leaves under `path`; false when an indicator
/// leaf has another type, or sits under a name holding a '.' (its dotted
/// path would not resolve as nested fields): the file is then not covered.
fn walk(path: &str, data_type: &DataType, out: &mut Vec<(String, Kind)>) -> bool {
    walk_inner(path, path.contains('.'), data_type, out)
}

fn walk_inner(path: &str, ambiguous: bool, data_type: &DataType, out: &mut Vec<(String, Kind)>) -> bool {
    match data_type {
        DataType::Struct(fields) => fields.iter().all(|field| {
            walk_inner(&format!("{path}.{}", field.name()), ambiguous || field.name().contains('.'), field.data_type(), out)
        }),
        DataType::List(child) | DataType::LargeList(child) | DataType::FixedSizeList(child, _) => {
            walk_inner(path, ambiguous, child.data_type(), out)
        }
        leaf => match contract::classify(path) {
            None => true,
            Some(_) if ambiguous || !is_string(leaf) => false,
            Some(kind) => {
                out.push((path.to_string(), kind));
                true
            }
        },
    }
}

/// True when a data file's footer marks the current derivation: its
/// `nano_ioc_*` columns are ours, complete and trusted.
pub fn is_marked(metadata: &parquet::file::metadata::FileMetaData) -> bool {
    metadata.key_value_metadata().is_some_and(|entries| {
        entries.iter().any(|entry| entry.key == contract::FILE_MARKER_KEY && entry.value.as_deref() == Some(contract::VERSION))
    })
}

/// True when a data file's footer carries any indicator marker (any
/// version): its `nano_ioc_*` columns were written by a part writer, never
/// by a source (a part schema naming one is written without columns or
/// marker), so a merge drops them and re-derives.
pub fn has_any_marker(metadata: &parquet::file::metadata::FileMetaData) -> bool {
    metadata.key_value_metadata().is_some_and(|entries| entries.iter().any(|entry| entry.key == contract::FILE_MARKER_KEY))
}

/// `batch` without any indicator column (a data file whose footer carries
/// a marker, read back as part rows). Cheap: columns are reference-counted.
/// An unmarked file is never stripped: a `nano_ioc_*` column there is a
/// source field committed before the namespace was reserved.
pub fn strip(batch: RecordBatch) -> Result<RecordBatch> {
    let schema = batch.schema();
    let keep = schema
        .fields()
        .iter()
        .enumerate()
        .filter(|(_, field)| !contract::is_indicator_column(field.name()))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if keep.len() == schema.fields().len() {
        return Ok(batch);
    }
    Ok(batch.project(&keep)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::{Array, ListArray, StringArray};

    fn decode(events: &[serde_json::Value]) -> RecordBatch {
        let rows = events.iter().collect::<Vec<_>>();
        let schema = crate::part_ingest::schema::infer_schema(&rows).unwrap();
        crate::part_ingest::schema::decode(Arc::new(schema), &rows).unwrap()
    }

    fn column(batch: &RecordBatch, kind: Kind, row: usize) -> Vec<String> {
        let list = batch.column_by_name(kind.column()).unwrap().as_any().downcast_ref::<ListArray>().unwrap();
        let values = list.value(row);
        let values = values.as_any().downcast_ref::<StringArray>().unwrap();
        (0..values.len()).map(|i| values.value(i).to_string()).collect()
    }

    #[test]
    fn derives_lowercased_deduplicated_values_from_every_domain_leaf() {
        let batch = decode(&[
            serde_json::json!({
                "time": "2026-09-25T10:00:00Z", "metadata": {"uid": "a"},
                "message": "dropped from evil.example.org",
                "process": {"file": {"hashes": [{"algorithm": "SHA-256", "value": "AB"}]}},
                "dst_endpoint": {"ip": "203.0.113.77", "domain": "Update-CDN.Example", "hostname": "Other.Example"},
                "query": {"hostname": "update-cdn.example"},
                "http_request": {"url": {"hostname": "CDN.Example."}},
                "evidences": [{"query": {"hostname": "Ev.Example"}}, {"query": {"hostname": "ev.example"}}],
                "device": {"hostname": "ws-1.corp"},
            }),
            serde_json::json!({"time": "2026-09-25T10:00:01Z", "metadata": {"uid": "b"}}),
        ]);
        let derivation = Derivation::for_schema(&batch.schema()).unwrap();
        let out = derivation.extend(&batch).unwrap();
        // Spelled as stored, ASCII-lowered: no trailing-dot or IDN rewrite
        // (the SQL compares the same raw spelling).
        assert_eq!(column(&out, Kind::Domain, 0), vec!["cdn.example.", "ev.example", "update-cdn.example"]);
        assert!(column(&out, Kind::Domain, 1).is_empty());
        let stripped = strip(out).unwrap();
        assert_eq!(stripped.schema(), batch.schema());
    }

    #[test]
    fn a_non_string_indicator_leaf_or_a_source_owned_column_leaves_the_file_uncovered() {
        let batch = decode(&[serde_json::json!({"time": "2026-09-25T10:00:00Z", "metadata": {"uid": "a"}, "query": {"hostname": 7}})]);
        assert!(Derivation::for_schema(&batch.schema()).is_none());
        // A leaf no kind maps is not read, whatever its type.
        let batch = decode(&[serde_json::json!({"time": "2026-09-25T10:00:00Z", "metadata": {"uid": "a"}, "device": {"ip": 7}})]);
        assert!(Derivation::for_schema(&batch.schema()).is_some());
        let batch = decode(&[serde_json::json!({"time": "2026-09-25T10:00:00Z", "metadata": {"uid": "a"}, "nano_ioc_hashes": ["x"]})]);
        assert!(Derivation::for_schema(&batch.schema()).is_none());
    }
}
