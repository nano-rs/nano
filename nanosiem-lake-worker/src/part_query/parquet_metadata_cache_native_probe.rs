// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4174 probe, native: does chDB 26.7's Parquet metadata cache keep
//! admitting footers once it is full (ClickHouse #115517, fixed in 26.8: an
//! SLRU admission bug freezes a full cache)? Many small wide-footer files are
//! read through `file()` with a deliberately small
//! `parquet_metadata_cache_size`, and the cache hit/miss events are diffed
//! per pass. A frozen cache shows a recently read working set that never
//! hits again after the cache filled.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=...
//! cargo test -p nanosiem-lake-worker --lib part_query::lanes::metadata_cache_probe -- --ignored --nocapture --exact \
//!   part_query::lanes::metadata_cache_probe::parquet_metadata_cache_keeps_admitting_after_it_fills
//! ```

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

const FILES: usize = 120;
const COLUMNS: usize = 160;
const ROWS: usize = 2_048;

fn write_files(dir: &Path) {
    use arrow_array::{ArrayRef, RecordBatch, StringArray};
    use arrow_schema::{DataType, Field, Schema};
    let schema = Arc::new(Schema::new((0..COLUMNS).map(|c| Field::new(format!("c{c}"), DataType::Utf8, true)).collect::<Vec<_>>()));
    let props = parquet::file::properties::WriterProperties::builder()
        // PROBE_STATS=chunk: chunk statistics only (no column index), to
        // weigh what page statistics cost a cached footer.
        .set_statistics_enabled(if std::env::var("PROBE_STATS").as_deref() == Ok("chunk") {
            parquet::file::properties::EnabledStatistics::Chunk
        } else {
            parquet::file::properties::EnabledStatistics::Page
        })
        .set_max_row_group_row_count(Some(ROWS / 2))
        .build();
    for file in 0..FILES {
        let path = dir.join(format!("data-{file:03}.parquet"));
        let mut writer = parquet::arrow::ArrowWriter::try_new(std::fs::File::create(&path).unwrap(), schema.clone(), Some(props.clone())).unwrap();
        let columns = (0..COLUMNS)
            .map(|c| Arc::new(StringArray::from_iter_values((0..ROWS).map(|r| format!("v{}-{}", (r * 31 + c + file) % 97, c)))) as ArrayRef)
            .collect::<Vec<_>>();
        writer.write(&RecordBatch::try_new(schema.clone(), columns).unwrap()).unwrap();
        writer.close().unwrap();
    }
}

fn rows(output: &[u8]) -> Vec<serde_json::Value> {
    output.split(|b| *b == b'\n').filter(|line| !line.is_empty()).map(|line| serde_json::from_slice(line).unwrap()).collect()
}

#[test]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
fn parquet_metadata_cache_keeps_admitting_after_it_fills() {
    let dir = tempfile::tempdir().unwrap();
    write_files(dir.path());
    let footer = std::fs::metadata(dir.path().join("data-000.parquet")).unwrap().len();
    let runtime = crate::native::NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let cache_bytes = std::env::var("PROBE_CACHE_BYTES").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(4 << 20);
    let cache_arg = format!("--parquet_metadata_cache_size={cache_bytes}");
    let connection = runtime.connect(&["--memory_worker_use_cgroup=0", "--memory_worker_dynamic_hard_limit=0", &cache_arg]).unwrap();
    let query = |sql: &str| rows(&connection.query_with_params(sql, "JSONEachRow", &[]).unwrap().data);
    println!("server: {:?}", query("SELECT name, value FROM system.server_settings WHERE name ILIKE '%parquet%metadata%'"));
    println!("settings: {:?}", query("SELECT name, value FROM system.settings WHERE name ILIKE '%parquet%metadata%cache%'"));
    let events = || -> BTreeMap<String, u64> {
        query("SELECT name, value FROM system.events WHERE name ILIKE '%parquet%' AND (name ILIKE '%cache%' OR name ILIKE '%metadata%')")
            .into_iter()
            .map(|row| (row["name"].as_str().unwrap().to_string(), row["value"].as_str().map_or_else(|| row["value"].as_u64().unwrap(), |v| v.parse().unwrap())))
            .collect()
    };
    let cache_size = || connection.query_with_params("SELECT metric, value FROM system.metrics WHERE metric ILIKE '%parquet%'", "JSONEachRow", &[])
        .map(|output| rows(&output.data)).unwrap_or_default();
    let pass = |label: &str, from: usize, to: usize| -> BTreeMap<String, i64> {
        let before = events();
        let sql = format!(
            "SELECT count() AS n, countIf(c3 = 'v1-3') AS m FROM file('{}/data-{{{from:03}..{to:03}}}.parquet', Parquet) WHERE c7 != 'zz' \
             SETTINGS max_threads=2, input_format_parquet_filter_push_down=1, use_parquet_metadata_cache=1",
            dir.path().display(), to = to - 1
        );
        let result = query(&sql);
        let after = events();
        let delta = after.iter().map(|(name, value)| (name.clone(), *value as i64 - *before.get(name).unwrap_or(&0) as i64)).filter(|(_, d)| *d != 0).collect::<BTreeMap<_, _>>();
        println!("{label:<28} files {from:>3}..{to:<3} result {result:?} events {delta:?}");
        delta
    };
    println!("file bytes {footer}, cache bytes {cache_bytes}, files {FILES}");
    for round in 0..3 {
        pass(&format!("A warm-set round {round}"), 0, 20);
    }
    pass("B overflow sweep", 0, FILES);
    println!("cache after sweep: {:?}", cache_size());
    let mut last = BTreeMap::new();
    for round in 0..3 {
        last = pass(&format!("C recent-set round {round}"), FILES - 20, FILES);
    }
    for round in 0..2 {
        pass(&format!("D new-set round {round}"), 40, 60);
    }
    println!("cache at end: {:?}", cache_size());
    println!("final C round: {last:?}");
}
