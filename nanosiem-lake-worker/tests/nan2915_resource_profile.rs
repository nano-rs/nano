// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local prevalence-part census. Run explicitly with NAN2915_PARTIAL_ROOT set
//! to a disposable fixture's `parts/h` directory; this never touches R2.

use arrow_array::{Array, ListArray, StringArray, UInt16Array, UInt64Array};
use nanosiem_lake_worker::parts::format::{PartKeys, PARTIAL_PREVALENCE_FILE};
use nanosiem_lake_worker::parts::levels::Level;
use nanosiem_lake_worker::parts::part_log::{load_log, LocalObjectStore};
use nanosiem_lake_worker::part_ingest::prevalence::IngestPrevalence;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use rusqlite::{params, Connection};
use slatedb::config::{CompressionCodec, Settings, WriteOptions};
use slatedb::db_cache::foyer::{FoyerCache, FoyerCacheOptions};
use slatedb::db_cache::{DbCache, SplitCache};
use slatedb::object_store::local::LocalFileSystem;
use slatedb::{Db, WriteBatch};
use std::collections::HashSet;
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

fn partials(root: &Path, paths: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("fixture directory") {
        let path = entry.expect("fixture entry").path();
        if path.is_dir() {
            partials(&path, paths);
        } else if path
            .file_name()
            .is_some_and(|name| name == "prevalence.parquet")
        {
            paths.push(path);
        }
    }
}

fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) }, 0);
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1_000_000.0;
    seconds(usage.ru_utime) + seconds(usage.ru_stime)
}

fn io_bytes(name: &str) -> u64 {
    fs::read_to_string("/proc/self/io")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix(name)
                .and_then(|n| n.trim().parse::<u64>().ok())
        })
        .unwrap()
}

#[tokio::test]
#[ignore = "requires an explicitly selected local fixture"]
async fn census_hourly_prevalence_partials() {
    let root = PathBuf::from(std::env::var("NAN2915_PARTIAL_ROOT").expect("fixture root"));
    let mut paths = if let (Ok(store), Ok(tenant)) = (
        std::env::var("NAN2915_STORE_ROOT"),
        std::env::var("NAN2915_TENANT"),
    ) {
        let store = PathBuf::from(store);
        let objects = LocalObjectStore::new(&store).unwrap();
        load_log(&objects, &tenant)
            .await
            .unwrap()
            .parts()
            .filter(|part| part.level == Level::Hour)
            .map(|part| {
                let keys =
                    PartKeys::new(&tenant, part.level, part.event_hour, &part.part_id).unwrap();
                store.join(keys.file(PARTIAL_PREVALENCE_FILE))
            })
            .filter(|path| path.starts_with(&root))
            .collect::<Vec<_>>()
    } else {
        let mut paths = Vec::new();
        partials(&root, &mut paths);
        paths
    };
    paths.sort();
    assert!(!paths.is_empty(), "no prevalence partials in fixture");
    let start = Instant::now();
    let mut bytes = 0_u64;
    let mut rows = 0_u64;
    let mut fingerprints = 0_u64;
    let mut saturated = 0_u64;
    let mut cap = None;
    // Optional day-directory run estimates the number of keys that ingest's
    // one-million-key guard would need to hold for that day.
    let distinct_day = std::env::var_os("NAN2915_DISTINCT_DAY").is_some();
    let mut keys = HashSet::new();
    for path in &paths {
        bytes += fs::metadata(path).unwrap().len();
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap())
            .unwrap()
            .with_batch_size(8_192)
            .build()
            .unwrap();
        for batch in reader {
            let batch = batch.unwrap();
            let hosts = batch
                .column_by_name("host_fingerprints")
                .unwrap()
                .as_any()
                .downcast_ref::<ListArray>()
                .unwrap();
            let caps = batch
                .column_by_name("host_cap")
                .and_then(|column| column.as_any().downcast_ref::<UInt16Array>());
            let row_cap = caps.map_or(65, |values| values.value(0));
            let kind = batch
                .column_by_name("kind")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let scope = batch
                .column_by_name("scope")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let entity = batch
                .column_by_name("entity")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            for i in 0..batch.num_rows() {
                let n = hosts.value_length(i) as u64;
                fingerprints += n;
                saturated += u64::from(n >= row_cap as u64);
                cap = Some(row_cap);
                if distinct_day {
                    let mut hash = std::collections::hash_map::DefaultHasher::new();
                    (kind.value(i), scope.value(i), entity.value(i)).hash(&mut hash);
                    keys.insert(hash.finish());
                }
            }
            rows += batch.num_rows() as u64;
        }
    }
    eprintln!("prevalence census: files={} compressed_bytes={} rows={} fingerprints={} saturated_rows={} host_cap={} scan_seconds={:.3} raw_fingerprint_bytes={} distinct_day_key_fingerprints={}",
        paths.len(), bytes, rows, fingerprints, saturated, cap.unwrap_or_default(),
        start.elapsed().as_secs_f64(), fingerprints * 8, keys.len());
}

/// Legacy fixture capacity probe. Its 65-host rows can establish key-index
/// disk and insert cost, but cannot certify the 1,000-host production cap.
#[tokio::test]
#[ignore = "requires NAN2915_PARTIAL_ROOT pointing to a fixture scope"]
async fn profile_sqlite_index() {
    let root = PathBuf::from(std::env::var("NAN2915_PARTIAL_ROOT").expect("fixture scope"));
    let mut paths = if let (Ok(store), Ok(tenant)) = (
        std::env::var("NAN2915_STORE_ROOT"),
        std::env::var("NAN2915_TENANT"),
    ) {
        let store = PathBuf::from(store);
        let objects = LocalObjectStore::new(&store).unwrap();
        load_log(&objects, &tenant)
            .await
            .unwrap()
            .parts()
            .filter(|part| part.level == Level::Hour)
            .map(|part| {
                let keys =
                    PartKeys::new(&tenant, part.level, part.event_hour, &part.part_id).unwrap();
                store.join(keys.file(PARTIAL_PREVALENCE_FILE))
            })
            .filter(|path| path.starts_with(&root))
            .collect::<Vec<_>>()
    } else {
        let mut paths = Vec::new();
        partials(&root, &mut paths);
        paths
    };
    paths.sort();
    assert!(!paths.is_empty(), "no prevalence partials in fixture scope");
    let state_root = PathBuf::from(
        std::env::var("NAN2915_STATE_ROOT").expect("explicit disk-backed state directory"),
    );
    assert!(state_root.is_dir(), "state directory does not exist");
    let dir = tempfile::tempdir_in(state_root).unwrap();
    let db_path = dir.path().join("state.sqlite");
    let mut db = Connection::open(&db_path).unwrap();
    db.execute_batch(
        "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
        PRAGMA auto_vacuum=INCREMENTAL;
        PRAGMA cache_size=-16384; PRAGMA temp_store=FILE;
        CREATE TABLE entity(kind TEXT NOT NULL, artifact TEXT NOT NULL,
            hosts BLOB NOT NULL, first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL, occurrences INTEGER NOT NULL,
            PRIMARY KEY(kind, artifact)) WITHOUT ROWID;
        CREATE INDEX entity_expiry ON entity(last_seen);",
    )
    .unwrap();
    let start = Instant::now();
    let cpu_start = cpu_seconds();
    let writes_start = io_bytes("write_bytes:");
    let mut rows = 0_u64;
    let mut inserted = 0_u64;
    for path in paths {
        let tx = db.transaction().unwrap();
        let mut insert = tx
            .prepare_cached(
                "INSERT INTO entity(kind,artifact,hosts,first_seen,last_seen,occurrences)
            VALUES (?1,?2,?3,0,0,1) ON CONFLICT(kind,artifact) DO NOTHING",
            )
            .unwrap();
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap())
            .unwrap()
            .with_batch_size(8_192)
            .build()
            .unwrap();
        for batch in reader {
            let batch = batch.unwrap();
            let kind = batch
                .column_by_name("kind")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let entity = batch
                .column_by_name("entity")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let hosts = batch
                .column_by_name("host_fingerprints")
                .unwrap()
                .as_any()
                .downcast_ref::<ListArray>()
                .unwrap();
            for i in 0..batch.num_rows() {
                let n = hosts.value_length(i) as usize;
                // Size-equivalent opaque host payload. The existing fixture
                // cannot drive production's 1,000-host compatibility check.
                let bytes = vec![0_u8; n * 8];
                inserted += insert
                    .execute(params![kind.value(i), entity.value(i), bytes])
                    .unwrap() as u64;
                rows += 1;
            }
        }
        drop(insert);
        tx.commit().unwrap();
    }
    let keys: u64 = db
        .query_row("SELECT COUNT(*) FROM entity", [], |r| r.get(0))
        .unwrap();
    let bytes = fs::metadata(db_path).unwrap().len();
    let peak_rss_kib = fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")
                .and_then(|n| n.split_whitespace().next())
                .and_then(|n| n.parse::<u64>().ok())
        })
        .unwrap();
    eprintln!("prevalence SQLite: rows={rows} inserts={inserted} keys={keys} db_bytes={bytes} peak_rss_kib={peak_rss_kib} seconds={:.3} cpu_seconds={:.3} write_bytes={}", start.elapsed().as_secs_f64(), cpu_seconds() - cpu_start, io_bytes("write_bytes:").saturating_sub(writes_start));
    assert_eq!(keys, inserted);
}

/// First-pass SlateDB capacity probe over the same signed-live fixture. The
/// legacy partials cap host sets at 65, so this measures key cardinality and
/// object-store write cost, not production host-tail correctness. It is kept
/// separate from ingest until the R2 credential and log-head replay contract
/// can be exercised end to end.
#[tokio::test]
#[ignore = "requires explicit fixture and disposable state directory"]
async fn profile_slatedb_index() {
    let root = PathBuf::from(std::env::var("NAN2915_PARTIAL_ROOT").expect("fixture scope"));
    let store_root = PathBuf::from(std::env::var("NAN2915_STORE_ROOT").expect("signed store root"));
    let tenant = std::env::var("NAN2915_TENANT").expect("fixture tenant");
    let state_root =
        PathBuf::from(std::env::var("NAN2915_STATE_ROOT").expect("disposable state root"));
    assert!(state_root.is_dir());
    let objects = LocalObjectStore::new(&store_root).unwrap();
    let mut paths = load_log(&objects, &tenant)
        .await
        .unwrap()
        .parts()
        .filter(|part| part.level == Level::Hour)
        .map(|part| {
            let keys = PartKeys::new(&tenant, part.level, part.event_hour, &part.part_id).unwrap();
            store_root.join(keys.file(PARTIAL_PREVALENCE_FILE))
        })
        .filter(|path| path.starts_with(&root))
        .collect::<Vec<_>>();
    paths.sort();
    assert!(!paths.is_empty());
    let directory = tempfile::tempdir_in(state_root).unwrap();
    let local = Arc::new(LocalFileSystem::new_with_prefix(directory.path()).unwrap());
    let block_cache: Arc<dyn DbCache> = Arc::new(FoyerCache::new_with_opts(FoyerCacheOptions {
        max_capacity: 32 * 1024 * 1024,
        shards: 8,
    }));
    let meta_cache: Arc<dyn DbCache> = Arc::new(FoyerCache::new_with_opts(FoyerCacheOptions {
        max_capacity: 64 * 1024 * 1024,
        shards: 8,
    }));
    let cache: Arc<dyn DbCache> = Arc::new(
        SplitCache::new()
            .with_block_cache(Some(block_cache))
            .with_meta_cache(Some(meta_cache))
            .build(),
    );
    let db = Db::builder("prevalence-v1", local)
        .with_db_cache(cache)
        .with_settings(Settings {
            flush_interval: None,
            l0_sst_size_bytes: 32 * 1024 * 1024,
            max_unflushed_bytes: 128 * 1024 * 1024,
            compression_codec: Some(CompressionCodec::Zstd),
            ..Settings::default()
        })
        .build()
        .await
        .unwrap();
    let started = Instant::now();
    let cpu_start = cpu_seconds();
    let writes_start = io_bytes("write_bytes:");
    let mut rows = 0_u64;
    let mut writes = 0_u64;
    for path in &paths {
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap())
            .unwrap()
            .with_batch_size(8_192)
            .build()
            .unwrap();
        for batch in reader {
            let batch = batch.unwrap();
            let kind = batch
                .column_by_name("kind")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let entity = batch
                .column_by_name("entity")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let hosts = batch
                .column_by_name("host_fingerprints")
                .unwrap()
                .as_any()
                .downcast_ref::<ListArray>()
                .unwrap();
            let mut write = WriteBatch::new();
            for i in 0..batch.num_rows() {
                let mut key = Vec::with_capacity(kind.value(i).len() + entity.value(i).len() + 1);
                key.extend_from_slice(kind.value(i).as_bytes());
                key.push(0);
                key.extend_from_slice(entity.value(i).as_bytes());
                let fingerprint_values = hosts.value(i);
                let fingerprint_values = fingerprint_values
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .unwrap();
                let mut value = Vec::with_capacity(24 + fingerprint_values.len() * 8);
                value.resize(24, 0);
                for host in fingerprint_values.values() {
                    value.extend_from_slice(&host.to_le_bytes());
                }
                write.put(key, value);
                rows += 1;
                writes += 1;
            }
            // With background WAL flushing disabled, waiting for durability
            // here would block forever before the explicit per-part flush.
            db.write_with_options(
                write,
                &WriteOptions {
                    await_durable: false,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }
        db.flush().await.unwrap();
    }
    db.close().await.unwrap();
    let stored_bytes = directory_bytes(directory.path());
    let peak_rss_kib = fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")
                .and_then(|n| n.split_whitespace().next())
                .and_then(|n| n.parse::<u64>().ok())
        })
        .unwrap();
    eprintln!("prevalence SlateDB: parts={} rows={rows} writes={writes} stored_bytes={stored_bytes} peak_rss_kib={peak_rss_kib} seconds={:.3} cpu_seconds={:.3} write_bytes={}",
        paths.len(), started.elapsed().as_secs_f64(), cpu_seconds() - cpu_start,
        io_bytes("write_bytes:").saturating_sub(writes_start));
}

fn directory_bytes(root: &Path) -> u64 {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            if path.is_dir() {
                directory_bytes(&path)
            } else {
                fs::metadata(path).unwrap().len()
            }
        })
        .sum()
}

/// Resource lower bound for the real ingest merge path. The signed fixture
/// predates the 1,000-host partial format, so this rewrites only its cap
/// marker; host sets beyond the legacy 65 cannot be reconstructed. It may
/// reveal a stall, but cannot certify count-tail or 30-day capacity parity.
#[tokio::test]
#[ignore = "requires signed week-r35 fixture and disposable state directory"]
async fn profile_real_ingest_slatedb_merges() {
    let root = PathBuf::from(std::env::var("NAN2915_PARTIAL_ROOT").expect("fixture scope"));
    let store_root = PathBuf::from(std::env::var("NAN2915_STORE_ROOT").expect("signed store root"));
    let tenant = std::env::var("NAN2915_TENANT").expect("fixture tenant");
    let state_root = PathBuf::from(std::env::var("NAN2915_STATE_ROOT").expect("disposable state root"));
    assert!(state_root.is_dir());
    let objects = LocalObjectStore::new(&store_root).unwrap();
    let mut parts = load_log(&objects, &tenant).await.unwrap().parts()
        .filter(|part| part.level == Level::Hour)
        .filter_map(|part| {
            let keys = PartKeys::new(&tenant, part.level, part.event_hour, &part.part_id).ok()?;
            let path = store_root.join(keys.file(PARTIAL_PREVALENCE_FILE));
            path.starts_with(&root).then_some((part.part_id.to_string(), part.max_time_us, path))
        }).collect::<Vec<_>>();
    parts.sort_by(|a, b| a.2.cmp(&b.2));
    assert!(!parts.is_empty());
    let directory = tempfile::tempdir_in(&state_root).unwrap();
    let mut state = IngestPrevalence::open(&tenant, directory.path(), None).await.unwrap();
    let started = Instant::now();
    let cpu_start = cpu_seconds();
    let writes_start = io_bytes("write_bytes:");
    let mut worst_seconds = 0_f64;
    for (id, max_time_us, original) in &parts {
        let converted = directory.path().join(format!("{id}.parquet"));
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(original).unwrap())
            .unwrap().with_batch_size(8_192).build().unwrap();
        let mut writer = None;
        for batch in reader {
            let batch = batch.unwrap();
            let mut columns = batch.columns().to_vec();
            columns.push(Arc::new(UInt16Array::from(vec![1_000_u16; batch.num_rows()])));
            let mut fields = batch.schema().fields().iter().cloned().collect::<Vec<_>>();
            fields.push(Arc::new(arrow_schema::Field::new("host_cap", arrow_schema::DataType::UInt16, false)));
            let schema = Arc::new(arrow_schema::Schema::new(fields));
            let batch = arrow_array::RecordBatch::try_new(schema, columns).unwrap();
            if writer.is_none() {
                writer = Some(ArrowWriter::try_new(File::create(&converted).unwrap(), batch.schema(), None).unwrap());
            }
            writer.as_mut().unwrap().write(&batch).unwrap();
        }
        writer.expect("nonempty signed partial").close().unwrap();
        let part_started = Instant::now();
        state.absorb_part_with_id(&tenant, id, &converted, *max_time_us).await.unwrap();
        let elapsed = part_started.elapsed().as_secs_f64();
        worst_seconds = worst_seconds.max(elapsed);
        eprintln!("prevalence ingest merge: part={id} seconds={elapsed:.3}");
        fs::remove_file(converted).unwrap();
    }
    let peak_rss_kib = fs::read_to_string("/proc/self/status").unwrap().lines()
        .find_map(|line| line.strip_prefix("VmHWM:")
            .and_then(|n| n.split_whitespace().next())
            .and_then(|n| n.parse::<u64>().ok())).unwrap();
    eprintln!("prevalence ingest SlateDB: parts={} worst_part_seconds={worst_seconds:.3} state_bytes={} peak_rss_kib={peak_rss_kib} wall_seconds={:.3} cpu_seconds={:.3} write_bytes={}",
        parts.len(), directory_bytes(directory.path()), started.elapsed().as_secs_f64(), cpu_seconds()-cpu_start,
        io_bytes("write_bytes:").saturating_sub(writes_start));
}

#[tokio::test]
async fn slate_state_reopens_by_tenant_prefix_without_cross_tenant_values() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalFileSystem::new_with_prefix(directory.path()).unwrap());
    let tenant_a = "11111111-1111-4111-8111-111111111111";
    let tenant_b = "22222222-2222-4222-8222-222222222222";
    let path = |tenant: &str| format!("lake/prevalence-state/v1/tenant={tenant}/db");
    let a = Db::open(path(tenant_a), store.clone()).await.unwrap();
    let b = Db::open(path(tenant_b), store.clone()).await.unwrap();
    a.put(b"ip\x008.8.8.8", b"tenant-a-count-9").await.unwrap();
    b.put(b"ip\x008.8.8.8", b"tenant-b-count-1").await.unwrap();
    a.close().await.unwrap();
    b.close().await.unwrap();
    let restarted_a = Db::open(path(tenant_a), store.clone()).await.unwrap();
    let restarted_b = Db::open(path(tenant_b), store).await.unwrap();
    assert_eq!(
        restarted_a
            .get(b"ip\x008.8.8.8")
            .await
            .unwrap()
            .unwrap()
            .as_ref(),
        b"tenant-a-count-9"
    );
    assert_eq!(
        restarted_b
            .get(b"ip\x008.8.8.8")
            .await
            .unwrap()
            .unwrap()
            .as_ref(),
        b"tenant-b-count-1"
    );
    restarted_a.close().await.unwrap();
    restarted_b.close().await.unwrap();
}
