// SPDX-License-Identifier: AGPL-3.0-or-later

//! The tenant read schema in the part model (contract section 2): additive
//! only, carried in the part log, and the target every admitted row and every
//! merge input is decoded into.

use anyhow::{bail, Context, Result};
use arrow_array::RecordBatch;
use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::{LineDelimitedWriter, ReaderBuilder};
use arrow_schema::{DataType, Field, Fields, Schema, SchemaRef, TimeUnit};
use serde_json::Value;
use std::io::Cursor;
use std::sync::Arc;

fn time_field() -> Field {
    Field::new("time", DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())), false)
}

/// Infer the Arrow shape of normalized OCSF events (time pinned to UTC µs).
pub fn infer_schema(events: &[&Value]) -> Result<Schema> {
    let mut encoded = Vec::new();
    for event in events {
        serde_json::to_writer(&mut encoded, event)?;
        encoded.push(b'\n');
    }
    let (inferred, _) = infer_json_schema_from_seekable(&mut Cursor::new(encoded), None)
        .context("infer OCSF Arrow schema")?;
    let fields = inferred
        .fields()
        .iter()
        .filter_map(|field| {
            if field.name() == "time" {
                Some(Arc::new(time_field()))
            } else if matches!(field.name().as_str(),
                "prevalence_file_hash" | "prevalence_process_hash" |
                "prevalence_dest_domain" | "prevalence_dest_ip" | "prevalence_min") {
                Some(Arc::new(Field::new(field.name(), DataType::UInt16, false)))
            } else {
                prune_null(field.as_ref()).map(Arc::new)
            }
        })
        .collect::<Vec<_>>();
    if !fields.iter().any(|f| f.name() == "time") {
        bail!("inferred OCSF schema has no time field");
    }
    Ok(Schema::new(fields))
}

/// Drop all-null inference artifacts (a leaf typed `Null`, a struct with no
/// surviving child).
fn prune_null(field: &Field) -> Option<Field> {
    match field.data_type() {
        DataType::Null => None,
        DataType::Struct(children) => {
            let kept = children.iter().filter_map(|c| prune_null(c.as_ref()).map(Arc::new)).collect::<Vec<_>>();
            (!kept.is_empty()).then(|| field.clone().with_data_type(DataType::Struct(Fields::from(kept))).with_nullable(true))
        }
        DataType::List(child) => prune_null(child.as_ref())
            .map(|c| field.clone().with_data_type(DataType::List(Arc::new(c))).with_nullable(true)),
        _ => Some(field.clone().with_nullable(true)),
    }
}

/// Merge `proposed` into `current`, adding new leaves only. An existing
/// leaf keeps its type (rows decode into it or fail closed); the result is
/// `None` when nothing was added.
pub fn additive_merge(current: &Schema, proposed: &Schema) -> Result<Option<Schema>> {
    let merged = merge_fields(current.fields(), proposed.fields())?;
    Ok(merged.map(|fields| Schema::new_with_metadata(fields, current.metadata().clone())))
}

fn merge_fields(current: &Fields, proposed: &Fields) -> Result<Option<Fields>> {
    let mut out: Vec<Arc<Field>> = current.iter().cloned().collect();
    let mut changed = false;
    for field in proposed.iter() {
        match out.iter().position(|f| f.name() == field.name()) {
            None => {
                out.push(Arc::new(field.as_ref().clone().with_nullable(true)));
                changed = true;
            }
            Some(index) => {
                let existing = out[index].clone();
                if let Some(merged) = merge_type(existing.data_type(), field.data_type())? {
                    out[index] = Arc::new(existing.as_ref().clone().with_data_type(merged));
                    changed = true;
                }
            }
        }
    }
    Ok(changed.then(|| Fields::from(out)))
}

fn merge_type(current: &DataType, proposed: &DataType) -> Result<Option<DataType>> {
    match (current, proposed) {
        (DataType::Struct(a), DataType::Struct(b)) => Ok(merge_fields(a, b)?.map(DataType::Struct)),
        (DataType::List(a), DataType::List(b)) => Ok(merge_type(a.data_type(), b.data_type())?
            .map(|t| DataType::List(Arc::new(a.as_ref().clone().with_data_type(t))))),
        (DataType::Struct(_), _) | (_, DataType::Struct(_)) | (DataType::List(_), _) | (_, DataType::List(_))
            if std::mem::discriminant(current) != std::mem::discriminant(proposed) =>
        {
            bail!("OCSF field changed shape between struct, list and scalar; schema generation required")
        }
        // Scalars keep the existing type; decoding enforces compatibility.
        _ => Ok(None),
    }
}

/// Where a row's type-drifted values go (B4, contract 5.2): the OCSF
/// `unmapped` object, as one JSON text leaf `{"<dotted path>": <raw>}`.
pub const COERCED_OBJECT: &str = "unmapped";
pub const COERCED_LEAF: &str = "nano_coerced";

/// Does `value` decode into a leaf of `data_type` without loss?
fn fits(value: &Value, data_type: &DataType) -> bool {
    use DataType as D;
    match (value, data_type) {
        (Value::Null, _) => true,
        (Value::Object(map), D::Struct(fields)) => {
            fields.iter().all(|f| map.get(f.name()).is_none_or(|child| fits(child, f.data_type())))
        }
        (_, D::Struct(_)) | (Value::Object(_), _) => false,
        (Value::Array(items), D::List(f) | D::LargeList(f)) => items.iter().all(|item| fits(item, f.data_type())),
        (_, D::List(_) | D::LargeList(_)) | (Value::Array(_), _) => false,
        (Value::Number(n), D::Int8 | D::Int16 | D::Int32 | D::Int64) => {
            let range = int_range(data_type);
            n.as_i64().map(|v| range.contains(&(v as i128))).unwrap_or_else(|| {
                n.as_u64().map(|v| range.contains(&(v as i128))).unwrap_or_else(|| {
                    n.as_f64().is_some_and(|f| f.fract() == 0.0 && range.contains(&(f as i128)))
                })
            })
        }
        (Value::Number(n), D::UInt8 | D::UInt16 | D::UInt32 | D::UInt64) => {
            let range = int_range(data_type);
            n.as_u64().map(|v| range.contains(&(v as i128))).unwrap_or_else(|| {
                n.as_f64().is_some_and(|f| f >= 0.0 && f.fract() == 0.0 && range.contains(&(f as i128)))
            })
        }
        (Value::String(text), D::Int8 | D::Int16 | D::Int32 | D::Int64 | D::UInt8 | D::UInt16 | D::UInt32 | D::UInt64) => {
            text.trim().parse::<i128>().is_ok_and(|v| int_range(data_type).contains(&v))
        }
        (Value::Number(_), D::Float16 | D::Float32 | D::Float64) => true,
        (Value::String(text), D::Float16 | D::Float32 | D::Float64) => text.trim().parse::<f64>().is_ok(),
        (Value::Bool(_), D::Boolean) => true,
        (_, D::Boolean) => false,
        // Coerce-primitive: numbers and bools decode as their text.
        (Value::String(_) | Value::Number(_) | Value::Bool(_), D::Utf8 | D::LargeUtf8 | D::Utf8View) => true,
        (Value::Bool(_), _) => false,
        (Value::String(_), D::Timestamp(_, _)) => true,
        (Value::Number(n), D::Timestamp(_, _)) => n.as_i64().is_some(),
        // Anything else is left to decode (fails closed there).
        _ => true,
    }
}

fn int_range(data_type: &DataType) -> std::ops::RangeInclusive<i128> {
    use DataType as D;
    match data_type {
        D::Int8 => i128::from(i8::MIN)..=i128::from(i8::MAX),
        D::Int16 => i128::from(i16::MIN)..=i128::from(i16::MAX),
        D::Int32 => i128::from(i32::MIN)..=i128::from(i32::MAX),
        D::UInt8 => 0..=i128::from(u8::MAX),
        D::UInt16 => 0..=i128::from(u16::MAX),
        D::UInt32 => 0..=i128::from(u32::MAX),
        D::UInt64 => 0..=i128::from(u64::MAX),
        _ => i128::from(i64::MIN)..=i128::from(i64::MAX),
    }
}

/// Type drift is never a refusal (B4): every value of `event` that does
/// not fit its existing leaf in `schema` (int↔float with a fraction,
/// scalar↔struct/list, an unparseable text for a numeric leaf) is moved out
/// of its typed column (which becomes null for this row) into
/// `unmapped.nano_coerced` as raw JSON keyed by its dotted path. Leaves the
/// schema does not have yet are untouched (additive growth handles them).
/// Returns how many values moved. `time` is never moved (callers validate
/// it first).
pub fn coerce_to_schema(event: &mut Value, schema: &Schema) -> usize {
    let Value::Object(root) = event else { return 0 };
    let mut moved = Vec::new();
    for field in schema.fields() {
        if field.name() == "time" {
            continue;
        }
        if let Some(value) = root.get_mut(field.name()) {
            collect_conflicts(value, field.data_type(), field.name(), &mut moved);
        }
    }
    let count = moved.len();
    if count > 0 {
        stash_coerced(root, schema, moved);
    }
    count
}

fn collect_conflicts(value: &mut Value, data_type: &DataType, path: &str, moved: &mut Vec<(String, Value)>) {
    // Recurse into objects so one drifted leaf does not take its siblings
    // with it.
    if let (Value::Object(map), DataType::Struct(fields)) = (&mut *value, data_type) {
        for field in fields.iter() {
            if let Some(child) = map.get_mut(field.name()) {
                collect_conflicts(child, field.data_type(), &format!("{path}.{}", field.name()), moved);
            }
        }
        return;
    }
    if !fits(value, data_type) {
        moved.push((path.to_string(), std::mem::replace(value, Value::Null)));
    }
}

fn stash_coerced(root: &mut serde_json::Map<String, Value>, schema: &Schema, moved: Vec<(String, Value)>) {
    // `unmapped` is a struct (or absent) in every OCSF tenant schema; a
    // non-object `unmapped` in the row was itself moved above.
    let unmapped_is_struct = schema
        .field_with_name(COERCED_OBJECT)
        .map_or(true, |f| matches!(f.data_type(), DataType::Struct(_)));
    let (container, key) = if unmapped_is_struct {
        let slot = root.entry(COERCED_OBJECT.to_string()).or_insert_with(|| Value::Object(Default::default()));
        if !slot.is_object() {
            *slot = Value::Object(Default::default());
        }
        (slot.as_object_mut().expect("object"), COERCED_LEAF.to_string())
    } else {
        (&mut *root, format!("{COERCED_OBJECT}_{COERCED_LEAF}"))
    };
    let mut stash = container
        .get(&key)
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str::<serde_json::Map<String, Value>>(text).ok())
        .unwrap_or_default();
    for (path, raw) in moved {
        stash.insert(path, raw);
    }
    container.insert(key, Value::String(Value::Object(stash).to_string()));
}

/// Decode normalized events into `schema`.
pub fn decode(schema: SchemaRef, events: &[&Value]) -> Result<RecordBatch> {
    let mut bytes = Vec::new();
    for event in events {
        serde_json::to_writer(&mut bytes, event)?;
        bytes.push(b'\n');
    }
    // Primitive coercion: a number or bool arriving for a Utf8 leaf decodes
    // as its text instead of failing the object.
    let batches = ReaderBuilder::new(schema.clone())
        .with_batch_size(events.len().max(1))
        .with_coerce_primitive(true)
        .build(Cursor::new(bytes))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("decode OCSF events into the part schema")?;
    Ok(arrow_select::concat::concat_batches(&schema, &batches)?)
}

/// Rows per [`decode_parallel`] chunk: big enough that per-chunk reader
/// setup is noise, small enough to spread a 10k-row admission over cores.
pub const DECODE_CHUNK_ROWS: usize = 1_024;

/// [`decode`] in row chunks on the rayon pool, concatenated in input order.
/// Fails iff any chunk fails, so it validates exactly like [`decode`].
pub fn decode_parallel(schema: SchemaRef, events: &[&Value]) -> Result<RecordBatch> {
    use rayon::prelude::*;
    if events.len() <= DECODE_CHUNK_ROWS {
        return decode(schema, events);
    }
    let batches = events
        .par_chunks(DECODE_CHUNK_ROWS)
        .map(|chunk| decode(schema.clone(), chunk))
        .collect::<Result<Vec<_>>>()?;
    Ok(arrow_select::concat::concat_batches(&schema, &batches)?)
}

/// Re-shape a batch written under an older (narrower) schema into `target`.
/// Equal schemas are a zero-copy pass; otherwise rows round-trip through
/// JSON (rare: only right after an additive schema change).
pub fn align(batch: RecordBatch, target: &SchemaRef) -> Result<RecordBatch> {
    if batch.schema().fields() == target.fields() {
        return Ok(batch);
    }
    let mut writer = LineDelimitedWriter::new(Vec::new());
    writer.write(&batch)?;
    writer.finish()?;
    let bytes = writer.into_inner();
    let batches = ReaderBuilder::new(target.clone())
        .with_batch_size(batch.num_rows().max(1))
        .build(Cursor::new(bytes))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("align part batch to the merge schema")?;
    Ok(arrow_select::concat::concat_batches(target, &batches)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn additive_merge_adds_nested_leaves_only() {
        let a = json!({"time": "2026-09-25T10:00:00Z", "metadata": {"uid": "u"}, "x": 1});
        let b = json!({"time": "2026-09-25T10:00:00Z", "metadata": {"uid": "u", "log_source": "s"}, "y": "t", "n": null});
        let current = infer_schema(&[&a]).unwrap();
        let proposed = infer_schema(&[&b]).unwrap();
        let merged = additive_merge(&current, &proposed).unwrap().unwrap();
        let mut names = merged.fields().iter().map(|f| f.name().as_str()).collect::<Vec<_>>();
        assert_eq!(names.last(), Some(&"y"), "new leaves append");
        names.sort_unstable();
        assert_eq!(names, ["metadata", "time", "x", "y"]);
        assert!(additive_merge(&merged, &proposed).unwrap().is_none());
        let batch = decode(Arc::new(merged.clone()), &[&a, &b]).unwrap();
        assert_eq!(batch.num_rows(), 2);
        let narrow = decode(Arc::new(current), &[&a]).unwrap();
        assert_eq!(align(narrow, &Arc::new(merged)).unwrap().num_rows(), 1);
    }

    #[test]
    fn a_number_for_a_string_leaf_coerces_and_a_string_for_a_number_fails() {
        let a = json!({"time": "2026-09-25T10:00:00Z", "port": "443"});
        let schema = Arc::new(infer_schema(&[&a]).unwrap());
        let b = json!({"time": "2026-09-25T10:00:00Z", "port": 443});
        assert_eq!(decode(schema, &[&a, &b]).unwrap().num_rows(), 2);
        let c = json!({"time": "2026-09-25T10:00:00Z", "n": 1});
        let numeric = Arc::new(infer_schema(&[&c]).unwrap());
        assert!(decode(numeric, &[&json!({"time": "2026-09-25T10:00:00Z", "n": "x"})]).is_err());
    }

    #[test]
    fn shape_change_fails_closed() {
        let a = infer_schema(&[&json!({"time": "2026-09-25T10:00:00Z", "x": {"a": 1}})]).unwrap();
        let b = infer_schema(&[&json!({"time": "2026-09-25T10:00:00Z", "x": "s"})]).unwrap();
        assert!(additive_merge(&a, &b).is_err());
    }

    #[test]
    fn drifted_values_move_to_unmapped_and_never_refuse() {
        let a = json!({"time": "2026-09-25T10:00:00Z", "n": 1, "obj": {"k": "v", "m": 2}, "list": [1], "unmapped": {"x": "y"}});
        let schema = infer_schema(&[&a]).unwrap();
        let mut b = json!({"time": "2026-09-25T10:00:00Z", "n": 1.5, "obj": {"k": "v", "m": {"deep": true}}, "list": "s", "new": 3});
        assert_eq!(coerce_to_schema(&mut b, &schema), 3);
        assert_eq!(b["n"], Value::Null);
        assert_eq!(b["obj"]["k"], "v", "siblings stay typed");
        assert_eq!(b["obj"]["m"], Value::Null);
        let stash: Value = serde_json::from_str(b["unmapped"]["nano_coerced"].as_str().unwrap()).unwrap();
        assert_eq!(stash, json!({"n": 1.5, "obj.m": {"deep": true}, "list": "s"}));
        let grown = additive_merge(&schema, &infer_schema(&[&b]).unwrap()).unwrap().unwrap();
        assert_eq!(decode(Arc::new(grown), &[&a, &b]).unwrap().num_rows(), 2);
        // Fitting rows are untouched, 5.0 fits an int leaf, a numeric string fits too.
        let mut c = json!({"time": "2026-09-25T10:00:00Z", "n": 5.0, "list": ["7"]});
        assert_eq!(coerce_to_schema(&mut c, &schema), 0);
        assert!(c.get("unmapped").is_none());
        // A scalar `unmapped` is itself moved.
        let mut d = json!({"time": "2026-09-25T10:00:00Z", "unmapped": "flat"});
        assert_eq!(coerce_to_schema(&mut d, &schema), 1);
        let stash: Value = serde_json::from_str(d["unmapped"]["nano_coerced"].as_str().unwrap()).unwrap();
        assert_eq!(stash, json!({"unmapped": "flat"}));
    }
}
