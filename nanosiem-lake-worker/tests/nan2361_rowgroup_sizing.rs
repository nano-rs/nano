//! Measure what Parquet row-group size costs us on the real OCSF schema.
//!
//! The event writer pins `set_max_row_group_row_count(Some(4_096))`. Against a
//! 261-column OCSF schema that is very small: dictionaries cannot amortise, RLE
//! runs stay short, and per-column-chunk metadata (stats, offsets, encodings) is
//! paid 261 times per 4k rows. Saturn stores the SAME logs at 131 B/row via
//! per-column ClickHouse codecs; the lake sits at ~250 B/row for large objects.
//!
//! This encodes identical data at several row-group sizes so the lever is a
//! measured number rather than an argument.
use std::sync::Arc;

use arrow_array::{ArrayRef, Int64Array, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;

/// Shape-alike for an OCSF row: a wide, mostly-sparse schema with a handful of
/// hot columns and a long tail of low-cardinality / empty ones.
fn wide_batch(rows: usize, columns: usize) -> RecordBatch {
    let mut fields = Vec::with_capacity(columns);
    let mut arrays: Vec<ArrayRef> = Vec::with_capacity(columns);

    fields.push(Field::new("time", DataType::Int64, false));
    let base = 1_787_000_000_000_i64;
    arrays.push(Arc::new(Int64Array::from(
        (0..rows).map(|i| base + (i as i64) * 250).collect::<Vec<_>>(),
    )) as ArrayRef);

    // A few high-cardinality columns (uids, hashes) …
    for c in 0..3 {
        fields.push(Field::new(format!("hi_{c}"), DataType::Utf8, true));
        arrays.push(Arc::new(StringArray::from(
            (0..rows)
                .map(|i| Some(format!("{c}-{:016x}", i * 2_654_435_761_u64 as usize)))
                .collect::<Vec<_>>(),
        )) as ArrayRef);
    }
    // … a few low-cardinality ones (log_source, class_name, severity) …
    let lows = ["windows_sysmon", "aws_cloudtrail", "apache_http_server"];
    for c in 0..6 {
        fields.push(Field::new(format!("low_{c}"), DataType::Utf8, true));
        arrays.push(Arc::new(StringArray::from(
            (0..rows)
                .map(|i| Some(lows[(i + c) % lows.len()].to_string()))
                .collect::<Vec<_>>(),
        )) as ArrayRef);
    }
    // … and a long sparse tail, which is what 261 OCSF columns really look like.
    for c in 0..columns.saturating_sub(10) {
        fields.push(Field::new(format!("sparse_{c}"), DataType::Utf8, true));
        arrays.push(Arc::new(StringArray::from(
            (0..rows)
                .map(|i| if i % 97 == 0 { Some(format!("v{c}")) } else { None })
                .collect::<Vec<_>>(),
        )) as ArrayRef);
    }
    RecordBatch::try_new(Arc::new(Schema::new(fields)), arrays).expect("batch")
}

fn encoded_bytes(batch: &RecordBatch, row_group: usize, level: i32) -> usize {
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(level).unwrap()))
        .set_max_row_group_row_count(Some(row_group))
        .build();
    let mut sink: Vec<u8> = Vec::new();
    {
        let mut writer =
            ArrowWriter::try_new(&mut sink, batch.schema(), Some(properties)).expect("writer");
        writer.write(batch).expect("write");
        writer.close().expect("close");
    }
    sink.len()
}

/// Same data, rows SORTED by a clustering key before encoding.
///
/// This is the lever ClickHouse gets for free: a MergeTree stores rows ordered
/// by its ORDER BY key, so equal values land adjacent and RLE / dictionary /
/// delta encodings all get long runs to work with. The lake writes in arrival
/// order, which scatters those runs. Sorting also HELPS queries -- adjacent
/// equal values make min/max row-group stats selective, so a filter can skip
/// whole row groups instead of decoding them.
fn sorted_batch(batch: &RecordBatch) -> RecordBatch {
    use arrow_select::take::take;
    // Sort by a realistic clustering key: low-cardinality source first (so equal
    // values cluster), then time within it.
    let key = batch
        .column_by_name("low_0")
        .expect("low_0")
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("utf8")
        .clone();
    let time = batch
        .column_by_name("time")
        .expect("time")
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("i64")
        .clone();
    let mut order: Vec<u32> = (0..batch.num_rows() as u32).collect();
    order.sort_by(|a, b| {
        let ka = key.value(*a as usize);
        let kb = key.value(*b as usize);
        ka.cmp(kb)
            .then_with(|| time.value(*a as usize).cmp(&time.value(*b as usize)))
    });
    let indices = arrow_array::UInt32Array::from(order);
    let columns = batch
        .columns()
        .iter()
        .map(|c| take(c.as_ref(), &indices, None).expect("take"))
        .collect::<Vec<_>>();
    RecordBatch::try_new(batch.schema(), columns).expect("sorted batch")
}

#[test]
fn sorting_and_row_groups_are_the_compression_levers() {
    let rows = 100_000;
    let batch = wide_batch(rows, 261);
    let sorted = sorted_batch(&batch);
    println!("\n  rows={rows} columns=261");
    println!("  {:<38}{:>10}{:>12}", "configuration", "B/row", "vs today");
    let today = encoded_bytes(&batch, 4_096, 6) as f64 / rows as f64;
    for (label, b, rg, lvl) in [
        ("today: arrival order, rg=4096, zstd6", &batch, 4_096usize, 6i32),
        ("rg=65536, zstd6", &batch, 65_536, 6),
        ("SORTED, rg=4096, zstd6", &sorted, 4_096, 6),
        ("SORTED, rg=65536, zstd6", &sorted, 65_536, 6),
        ("SORTED, rg=100000, zstd6", &sorted, 100_000, 6),
        ("SORTED, rg=100000, zstd9", &sorted, 100_000, 9),
    ] {
        let per = encoded_bytes(b, rg, lvl) as f64 / rows as f64;
        println!("  {label:<38}{per:>10.1}{:>11.2}x", today / per);
    }
}

#[test]
fn row_group_size_dominates_bytes_per_row_on_a_wide_schema() {
    let rows = 100_000;
    let batch = wide_batch(rows, 261);
    println!("\n  rows={rows} columns=261  (zstd-6, as the staged writer uses)");
    let mut baseline = 0f64;
    for rg in [4_096usize, 16_384, 65_536, 100_000] {
        let bytes = encoded_bytes(&batch, rg, 6);
        let per_row = bytes as f64 / rows as f64;
        if rg == 4_096 {
            baseline = per_row;
        }
        println!(
            "    row_group={rg:>7}  {:>9} bytes  {per_row:>6.1} B/row  {:>5.2}x vs 4096",
            bytes,
            baseline / per_row
        );
    }
    println!("\n  zstd level sweep at row_group=65536:");
    for level in [3, 6, 9] {
        let bytes = encoded_bytes(&batch, 65_536, level);
        println!(
            "    zstd-{level}  {:>9} bytes  {:>6.1} B/row",
            bytes,
            bytes as f64 / rows as f64
        );
    }
    // The claim under test: 4k row groups are leaving real bytes on the floor.
    let small = encoded_bytes(&batch, 4_096, 6) as f64;
    let large = encoded_bytes(&batch, 65_536, 6) as f64;
    assert!(
        large < small,
        "larger row groups must not be worse: {large} vs {small}"
    );
}
