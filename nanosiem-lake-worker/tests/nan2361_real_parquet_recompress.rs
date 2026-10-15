//! Re-encode a REAL Iceberg data file at different settings.
//!
//! The synthetic benchmark could not answer whether SORTING helps: its columns
//! are artificially independent, so ordering by one destroys arrival-order
//! locality in the others. Real logs have correlated columns (same host implies
//! same OS, same process implies same image path), which is exactly what a
//! clustering key exploits — and it is why ClickHouse's MergeTree, which stores
//! rows ordered by its ORDER BY key, reaches 13.26x on this same data while the
//! lake sits near 2x.
//!
//! Run with: NANO_REAL_PARQUET=/path/to/pack.parquet cargo test -p
//! nanosiem-lake-worker --test nan2361_real_parquet_recompress -- --nocapture
use std::fs::File;
use std::sync::Arc;

use arrow_array::{RecordBatch, StringArray, UInt32Array};
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;

fn encode(batches: &[RecordBatch], schema: arrow_schema::SchemaRef, rg: usize, lvl: i32) -> usize {
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(lvl).unwrap()))
        .set_max_row_group_row_count(Some(rg))
        .build();
    let mut sink: Vec<u8> = Vec::new();
    {
        let mut writer = ArrowWriter::try_new(&mut sink, schema, Some(properties)).expect("writer");
        for b in batches {
            writer.write(b).expect("write");
        }
        writer.close().expect("close");
    }
    sink.len()
}

/// Concatenate every batch, then reorder rows by a clustering key.
///
/// ClickHouse's 13.26x on this same data is not magic codecs alone: a MergeTree
/// stores rows ORDERED BY its key, so equal values sit adjacent and dictionary /
/// RLE / delta encodings get long runs. The lake writes in arrival order, which
/// interleaves sources and scatters those runs. Sorting also makes row-group
/// min/max stats selective, so it should HELP query pruning rather than hurt it.
fn concat_sorted(batches: &[RecordBatch], by: &str) -> RecordBatch {
    use arrow_select::concat::concat_batches;
    use arrow_select::take::take;
    let schema = batches[0].schema();
    let all = concat_batches(&schema, batches).expect("concat");
    let Some(col) = all.column_by_name(by) else {
        return all;
    };
    // Sort on the string rendering of the key column, then by time, so this
    // works for a struct/dictionary column without unpacking its type.
    let keys: Vec<String> = (0..all.num_rows())
        .map(|i| format!("{:?}", col.slice(i, 1)))
        .collect();
    let time = all.column_by_name("time").cloned();
    let mut order: Vec<u32> = (0..all.num_rows() as u32).collect();
    order.sort_by(|a, b| {
        keys[*a as usize].cmp(&keys[*b as usize]).then_with(|| {
            match &time {
                Some(t) => format!("{:?}", t.slice(*a as usize, 1))
                    .cmp(&format!("{:?}", t.slice(*b as usize, 1))),
                None => std::cmp::Ordering::Equal,
            }
        })
    });
    let indices = UInt32Array::from(order);
    let columns = all
        .columns()
        .iter()
        .map(|c| take(c.as_ref(), &indices, None).expect("take"))
        .collect::<Vec<_>>();
    RecordBatch::try_new(schema, columns).expect("sorted")
}

#[test]
fn recompress_a_real_generation_file() {
    let Ok(path) = std::env::var("NANO_REAL_PARQUET") else {
        eprintln!("set NANO_REAL_PARQUET to a real pack.parquet; skipping");
        return;
    };
    let on_disk = std::fs::metadata(&path).expect("stat").len() as f64;
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&path).expect("open"))
        .expect("builder")
        .with_batch_size(8192)
        .build()
        .expect("reader");
    let mut batches = Vec::new();
    for b in reader {
        batches.push(b.expect("batch"));
    }
    let schema = batches[0].schema();
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    println!("\n  real file: {rows} rows, {} columns", schema.fields().len());
    println!("  as shipped on disk: {:.1} B/row", on_disk / rows as f64);
    // What are we working with?
    let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
    println!("  columns: {}", names.join(", "));

    println!("\n  {:<40}{:>9}{:>11}", "configuration", "B/row", "vs shipped");
    for (label, rg, lvl) in [
        ("rg=4096  zstd6  (current writer)", 4_096usize, 6i32),
        ("rg=65536 zstd6", 65_536, 6),
        ("rg=262144 zstd6", 262_144, 6),
        ("rg=262144 zstd9", 262_144, 9),
        ("rg=262144 zstd12", 262_144, 12),
    ] {
        let bytes = encode(&batches, schema.clone(), rg, lvl) as f64;
        println!(
            "  {label:<40}{:>9.1}{:>10.2}x",
            bytes / rows as f64,
            on_disk / bytes
        );
    }

    // Now the same, but clustered.
    println!("\n  SORTED by class_uid, then time:");
    let sorted = concat_sorted(&batches, "class_uid");
    for (label, rg, lvl) in [
        ("  sorted rg=65536 zstd6", 65_536usize, 6i32),
        ("  sorted rg=262144 zstd9", 262_144, 9),
        ("  sorted rg=262144 zstd12", 262_144, 12),
    ] {
        let bytes = encode(std::slice::from_ref(&sorted), schema.clone(), rg, lvl) as f64;
        println!(
            "  {label:<40}{:>9.1}{:>10.2}x",
            bytes / rows as f64,
            on_disk / bytes
        );
    }
}

/// What the file would weigh with `message` emptied — the exact effect of the
/// parser change, measured on real data instead of waiting an hour for a clean
/// pack. Also stacks the encoding levers on top so the combined number is real.
#[test]
fn dropping_message_on_a_real_file() {
    let Ok(path) = std::env::var("NANO_REAL_PARQUET") else {
        eprintln!("set NANO_REAL_PARQUET; skipping");
        return;
    };
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&path).expect("open"))
        .expect("builder")
        .with_batch_size(8192)
        .build()
        .expect("reader");
    let mut batches = Vec::new();
    for b in reader {
        batches.push(b.expect("batch"));
    }
    let schema = batches[0].schema();
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();

    // Replace `message` with all-null, leaving every other column untouched.
    let idx = schema.index_of("message").expect("message column");
    let blanked: Vec<RecordBatch> = batches
        .iter()
        .map(|b| {
            let mut cols = b.columns().to_vec();
            cols[idx] = Arc::new(StringArray::from(vec![None::<&str>; b.num_rows()]));
            RecordBatch::try_new(b.schema(), cols).expect("blanked")
        })
        .collect();

    let base = encode(&batches, schema.clone(), 4_096, 6) as f64;
    println!("\n  {rows} rows");
    println!("  {:<44}{:>9}{:>11}", "configuration", "B/row", "vs today");
    for (label, set, rg, lvl) in [
        ("today (message duplicated, rg4096, zstd6)", &batches, 4_096usize, 6i32),
        ("message EMPTY, rg=4096 zstd6", &blanked, 4_096, 6),
        ("message EMPTY, rg=262144 zstd9", &blanked, 262_144, 9),
        ("message EMPTY, rg=262144 zstd12", &blanked, 262_144, 12),
    ] {
        let b = encode(set, schema.clone(), rg, lvl) as f64;
        println!("  {label:<44}{:>9.1}{:>10.2}x", b / rows as f64, base / b);
    }
    println!("  (Saturn, same logs: 131.0 B/row)");
}

/// Does sorting WITHIN a row group capture the benefit of a global sort?
///
/// A global sort means materialising the whole pack, which is the memory shape
/// that just OOM-looped the bronze publisher. Parquet compresses per column
/// chunk within a row group, so sorting each group's buffer independently should
/// capture most of the win at bounded memory — one row group, not one file.
/// If that holds, the packer can stay streaming.
#[test]
fn chunked_sort_versus_global_sort() {
    let Ok(path) = std::env::var("NANO_REAL_PARQUET") else {
        eprintln!("set NANO_REAL_PARQUET; skipping");
        return;
    };
    use arrow_select::concat::concat_batches;
    use arrow_select::take::take;

    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&path).expect("open"))
        .expect("b")
        .with_batch_size(8192)
        .build()
        .expect("r");
    let mut batches = Vec::new();
    for b in reader {
        batches.push(b.expect("batch"));
    }
    let schema = batches[0].schema();
    let all = concat_batches(&schema, &batches).expect("concat");
    let rows = all.num_rows();

    // Sort `slice` by class_uid then time, the clustering key under test.
    let sort_slice = |b: &RecordBatch| -> RecordBatch {
        let key = b.column_by_name("class_uid").cloned();
        let time = b.column_by_name("time").cloned();
        let mut order: Vec<u32> = (0..b.num_rows() as u32).collect();
        order.sort_by(|x, y| {
            let kx = key.as_ref().map(|c| format!("{:?}", c.slice(*x as usize, 1)));
            let ky = key.as_ref().map(|c| format!("{:?}", c.slice(*y as usize, 1)));
            kx.cmp(&ky).then_with(|| {
                let tx = time.as_ref().map(|c| format!("{:?}", c.slice(*x as usize, 1)));
                let ty = time.as_ref().map(|c| format!("{:?}", c.slice(*y as usize, 1)));
                tx.cmp(&ty)
            })
        });
        let idx = UInt32Array::from(order);
        let cols = b
            .columns()
            .iter()
            .map(|c| take(c.as_ref(), &idx, None).expect("take"))
            .collect::<Vec<_>>();
        RecordBatch::try_new(b.schema(), cols).expect("sorted")
    };

    println!("\n  {rows} rows, sorting by (class_uid, time)");
    println!("  {:<40}{:>9}{:>11}", "strategy", "B/row", "vs unsorted");
    let unsorted = encode(std::slice::from_ref(&all), schema.clone(), 262_144, 9) as f64;
    println!("  {:<40}{:>9.1}{:>10}", "unsorted (shipped today)", unsorted / rows as f64, "1.00x");

    let global = encode(std::slice::from_ref(&sort_slice(&all)), schema.clone(), 262_144, 9) as f64;
    println!("  {:<40}{:>9.1}{:>10.2}x", "GLOBAL sort (needs full materialise)", global / rows as f64, unsorted / global);

    for chunk in [65_536usize, 131_072] {
        let mut parts = Vec::new();
        let mut off = 0;
        while off < rows {
            let n = chunk.min(rows - off);
            parts.push(sort_slice(&all.slice(off, n)));
            off += n;
        }
        let bytes = encode(&parts, schema.clone(), chunk, 9) as f64;
        println!(
            "  {:<40}{:>9.1}{:>10.2}x",
            format!("CHUNKED sort, {chunk}-row buffer"),
            bytes / rows as f64,
            unsorted / bytes
        );
    }
}

/// Saturn's ORDER BY on this same data is
/// `(source_type, timestamp, src_host, src_ip, cityHash64(id))` with daily
/// partitions — a low-cardinality field FIRST, then time. It still prunes well
/// because rows stay time-ordered within each source_type.
///
/// The OCSF analog is `metadata.log_source`. This measures both halves of the
/// trade: bytes saved, and how wide each row group's time range becomes (the
/// query cost).
#[test]
fn saturn_style_clustering_key() {
    let Ok(path) = std::env::var("NANO_REAL_PARQUET") else {
        eprintln!("set NANO_REAL_PARQUET; skipping");
        return;
    };
    use arrow_select::concat::concat_batches;
    use arrow_select::take::take;
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&path).expect("open"))
        .expect("b").with_batch_size(8192).build().expect("r");
    let mut batches = Vec::new();
    for b in reader { batches.push(b.expect("batch")); }
    let schema = batches[0].schema();
    let all = concat_batches(&schema, &batches).expect("concat");
    let rows = all.num_rows();

    let key_of = |b: &RecordBatch, name: &str, i: usize| -> String {
        b.column_by_name(name).map(|c| format!("{:?}", c.slice(i, 1))).unwrap_or_default()
    };
    let sorted_by = |b: &RecordBatch, first: &str| -> RecordBatch {
        let mut order: Vec<u32> = (0..b.num_rows() as u32).collect();
        order.sort_by(|x, y| {
            key_of(b, first, *x as usize).cmp(&key_of(b, first, *y as usize))
                .then_with(|| key_of(b, "time", *x as usize).cmp(&key_of(b, "time", *y as usize)))
        });
        let idx = UInt32Array::from(order);
        let cols = b.columns().iter()
            .map(|c| take(c.as_ref(), &idx, None).expect("take")).collect::<Vec<_>>();
        RecordBatch::try_new(b.schema(), cols).expect("sorted")
    };

    let base = encode(std::slice::from_ref(&all), schema.clone(), 262_144, 9) as f64;
    println!("\n  {rows} rows   (unsorted baseline {:.1} B/row)", base / rows as f64);
    println!("  {:<34}{:>9}{:>9}", "clustering key", "B/row", "gain");
    for first in ["metadata", "class_uid", "time"] {
        if all.column_by_name(first).is_none() { continue; }
        let s = sorted_by(&all, first);
        let b = encode(std::slice::from_ref(&s), schema.clone(), 262_144, 9) as f64;
        println!("  ({:<20}, time){:>9.1}{:>8.2}x", first, b / rows as f64, base / b);
    }
}
