// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3183 catch-up stage costs on real edge segments, in release:
//! NAN3183_SEGMENTS=/path/to/segments cargo test --release -p nanosiem-lake-worker --lib catchup_stage_costs -- --ignored --nocapture

use super::ingest::value_heap_bytes;
use super::schema::{decode, infer_schema};
use super::writer::{sort_by_time_uid, PartDraft, PartWriter, PartialSource};
use crate::bronze::admit_bronze_files_salvaging;
use crate::enrichment::BronzeIngestEnricher;
use crate::parts::levels::Level;
use crate::parts::provenance::{PartInputs, SourceObject};
use crate::parts::{event_hour_of, DedupWindow};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;

fn ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1e3
}

fn finished_draft(record: &crate::parts::provenance::ProvenanceRecord, schema: arrow_schema::SchemaRef) -> PartDraft {
    PartDraft {
        tenant_id: record.tenant_id.clone(),
        signer_key_id: record.signer_key_id.clone(),
        level: Level::L0,
        event_hour: record.event_hour,
        schema_fingerprint: crate::parts::format::schema_fingerprint(&schema).unwrap(),
        schema,
        inputs: record.inputs.clone(),
        admission: record.admission.clone(),
        rows_in: 0,
        duplicates_dropped: 0,
        window: DedupWindow::Exact,
        build: "bench".into(),
    }
}

#[test]
#[ignore]
fn catchup_stage_costs() {
    let dir = std::path::PathBuf::from(std::env::var("NAN3183_SEGMENTS").expect("NAN3183_SEGMENTS"));
    let repeat: usize = std::env::var("NAN3183_REPEAT").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
    crate::parts::block_index::set_enabled(true);
    crate::parts::token_counts::set_enabled(true);
    crate::identity_observations::set_enabled(true);
    let mut paths = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "parquet")).collect::<Vec<_>>();
    paths.sort();
    let tenant = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let enricher = BronzeIngestEnricher::disabled();
    let work = tempfile::tempdir().unwrap();
    let mut schema = Arc::new(super::ingest::seed_schema());
    for round in 0..repeat {
        let started = Instant::now();
        let (admission, _) = admit_bronze_files_salvaging(&paths, tenant, &enricher).unwrap();
        let admit_ms = ms(started);
        let mut rows = admission.batch.into_rows();
        let n = rows.len();
        let started = Instant::now();
        let refs = rows.iter().map(|r| &r.ocsf_event).collect::<Vec<_>>();
        let proposed = infer_schema(&refs).unwrap();
        let infer_ms = ms(started);
        let started = Instant::now();
        if let Some(grown) = super::schema::additive_merge(&schema, &proposed).unwrap() {
            schema = Arc::new(grown);
        }
        let root = arrow_schema::DataType::Struct(schema.fields().clone());
        assert!(!refs.iter().any(|e| super::ingest::truncates(e, &root)));
        let truncates_ms = ms(started);
        let started = Instant::now();
        decode(schema.clone(), &refs).unwrap();
        let check_decode_ms = ms(started);
        let started = Instant::now();
        let (_, checked) = super::ingest::Ingestor::shape_check(&schema, &refs).unwrap();
        let shape_check_ms = ms(started);
        assert_eq!(checked.unwrap().num_rows(), n);
        println!("  shape check (parallel infer + truncates + decode, kept as the buffer) {shape_check_ms:.0} ms ({:.0} us/row)", shape_check_ms * 1e3 / n as f64);
        let started = Instant::now();
        let heap = refs.iter().map(|v| value_heap_bytes(v)).sum::<u64>();
        let heap_ms = ms(started);
        let started = Instant::now();
        let json_bytes = refs.iter().map(|v| serde_json::to_vec(v).unwrap().len()).sum::<usize>();
        let to_json_ms = ms(started);
        drop(refs);
        let values = rows.iter_mut().map(|r| std::mem::take(&mut r.ocsf_event)).collect::<Vec<Value>>();
        let hour = event_hour_of(super::ingest::event_time_us(&values[0]).unwrap());
        let values = values.into_iter().filter(|v| event_hour_of(super::ingest::event_time_us(v).unwrap()) == hour).collect::<Vec<_>>();
        let refs = values.iter().collect::<Vec<_>>();
        let started = Instant::now();
        let batch = decode(schema.clone(), &refs).unwrap();
        let flush_decode_ms = ms(started);
        let arrow_bytes = batch.get_array_memory_size();
        let started = Instant::now();
        let batch = sort_by_time_uid(&batch).unwrap();
        let sort_ms = ms(started);
        let draft = PartDraft {
            tenant_id: tenant.into(),
            signer_key_id: crate::parts::provenance::tests::SIGNER.into(),
            level: Level::L0,
            event_hour: hour,
            schema: schema.clone(),
            schema_fingerprint: crate::parts::format::schema_fingerprint(&schema).unwrap(),
            inputs: PartInputs::Sources {
                sources: vec![SourceObject { key: "k".into(), version: "1".into(), bytes: 1, sha256: "0".repeat(64), rows: 1, edge_sha256: None }],
                edge_log: None,
            },
            admission: Some(crate::parts::provenance::Admission {
                ocsf_version: "1.9.0".into(), admission_contract: "t".into(), feed_pins: Default::default(),
            }),
            rows_in: batch.num_rows() as u64,
            duplicates_dropped: 0,
            window: DedupWindow::Exact,
            build: "bench".into(),
        };
        let started = Instant::now();
        let mut writer = PartWriter::create(work.path(), draft, PartialSource::FromRows, 1_000 + round as i64, batch.num_rows() as u64).unwrap();
        writer.write(&batch).unwrap();
        let write_ms = ms(started);
        let started = Instant::now();
        let finished = writer.finish().unwrap();
        let finish_ms = ms(started);
        let files = finished.record.files.all().len();
        // NAN-3183 paths: parallel decode, and the hour cut into 4 parts
        // written on parallel threads.
        let started = Instant::now();
        let parallel = super::schema::decode_parallel(schema.clone(), &refs).unwrap();
        let parallel_decode_ms = ms(started);
        let started = Instant::now();
        let sorted = sort_by_time_uid(&parallel).unwrap();
        let rows = sorted.num_rows();
        let size = rows.div_ceil(4);
        let mut drafts = Vec::new();
        for offset in (0..rows).step_by(size) {
            let len = size.min(rows - offset);
            let mut draft = finished_draft(&finished.record, schema.clone());
            draft.rows_in = len as u64;
            drafts.push((draft, sorted.slice(offset, len)));
        }
        let parts = super::ingest::write_l0_parts(work.path(), drafts, 5_000 + round as i64).unwrap();
        let parallel_write_ms = ms(started);
        println!("  parallel decode {parallel_decode_ms:.0} ms ({:.0} us/row) | sort + 4 parallel part writes {parallel_write_ms:.0} ms ({:.0} us/row, {} parts)",
            parallel_decode_ms * 1e3 / rows as f64, parallel_write_ms * 1e3 / rows as f64, parts.len());
        let per = |v: f64| v * 1e3 / n as f64;
        println!(
            "round {round}: {n} rows ({} in hour) from {} segments; heap {:.1} KB/row, json {:.1} KB/row, arrow {:.1} KB/row; {files} part files\n  \
             admit {admit_ms:.0} ms ({:.0} us/row) | infer {infer_ms:.0} ({:.0}) | truncates {truncates_ms:.0} ({:.0}) | check decode {check_decode_ms:.0} ({:.0}) | heap walk {heap_ms:.0} ({:.0}) | to_json {to_json_ms:.0} ({:.0})\n  \
             flush decode {flush_decode_ms:.0} ({:.0}) | sort {sort_ms:.0} ({:.0}) | part write {write_ms:.0} ({:.0}) | finish {finish_ms:.0} ({:.0})",
            batch.num_rows(), paths.len(), heap as f64 / n as f64 / 1024.0, json_bytes as f64 / n as f64 / 1024.0,
            arrow_bytes as f64 / batch.num_rows() as f64 / 1024.0,
            per(admit_ms), per(infer_ms), per(truncates_ms), per(check_decode_ms), per(heap_ms), per(to_json_ms),
            per(flush_decode_ms), per(sort_ms), per(write_ms), per(finish_ms),
        );
    }
}

/// Resident set of this process (bytes).
fn rss_bytes() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let pages = statm.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    pages * 4096
}

/// Samples RSS every 2 ms; `take` returns the max since the last take.
pub(crate) struct RssSampler {
    guard_max: Arc<std::sync::atomic::AtomicU64>,
    max: Arc<std::sync::atomic::AtomicU64>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl RssSampler {
    pub(crate) fn start() -> Self {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        let max = Arc::new(AtomicU64::new(rss_bytes()));
        let guard_max = Arc::new(AtomicU64::new(0));
        let guard_sample = guard_max.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let (m, s) = (max.clone(), stop.clone());
        let thread = std::thread::spawn(move || while !s.load(Ordering::Relaxed) {
            m.fetch_max(rss_bytes(), Ordering::Relaxed);
            if let Some((used, _)) = super::merge_lanes::cgroup_memory() {
                guard_sample.fetch_max(used, Ordering::Relaxed);
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        });
        Self { guard_max, max, stop, thread: Some(thread) }
    }
    pub(crate) fn guard_peak(&self) -> u64 {
        self.guard_max.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub(crate) fn take(&self) -> u64 {
        self.max.swap(rss_bytes(), std::sync::atomic::Ordering::Relaxed)
    }
}

impl Drop for RssSampler {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// `batch` with every `metadata.uid` suffixed (distinct copies of real rows).
fn with_uid_suffix(batch: &arrow_array::RecordBatch, suffix: &str) -> arrow_array::RecordBatch {
    use arrow_array::{Array, StringArray, StructArray};
    let index = batch.schema().index_of("metadata").unwrap();
    let metadata = batch.column(index).as_any().downcast_ref::<StructArray>().unwrap();
    let (fields, mut columns, nulls) = metadata.clone().into_parts();
    let uid = fields.iter().position(|f| f.name() == "uid").unwrap();
    let old = columns[uid].as_any().downcast_ref::<StringArray>().unwrap();
    let fresh = old.iter().map(|v| v.map(|v| format!("{v}-{suffix}"))).collect::<StringArray>();
    columns[uid] = Arc::new(fresh);
    let mut all = batch.columns().to_vec();
    all[index] = Arc::new(StructArray::new(fields, columns, nulls));
    arrow_array::RecordBatch::try_new(batch.schema(), all).unwrap()
}

fn mib(bytes: impl Into<f64>) -> f64 {
    bytes.into() / (1024.0 * 1024.0)
}

/// NAN-3183 OOM: every large allocation of one catch-up cycle (admission,
/// the Arrow buffer, a reference full flush build with parallel L0
/// writers), measured as live heap (all threads) and RSS:
/// NAN3183_SEGMENTS=/path cargo test --release -p nanosiem-lake-worker --lib catchup_memory_profile -- --ignored --nocapture
#[test]
#[ignore]
fn catchup_memory_profile() {
    use crate::test_heap::{live, peak, reset_peak, track_all_threads, MEASUREMENT};
    let _serial = MEASUREMENT.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::path::PathBuf::from(std::env::var("NAN3183_SEGMENTS").expect("NAN3183_SEGMENTS"));
    let flush_rows: usize = std::env::var("NAN3183_FLUSH_ROWS").ok().and_then(|v| v.parse().ok()).unwrap_or(4 * super::ingest::L0_PARALLEL_MIN_ROWS);
    crate::parts::block_index::set_enabled(true);
    crate::parts::token_counts::set_enabled(true);
    crate::identity_observations::set_enabled(true);
    let mut paths = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "parquet")).collect::<Vec<_>>();
    paths.sort();
    let source_bytes = paths.iter().map(|p| std::fs::metadata(p).unwrap().len()).sum::<u64>();
    let tenant = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let enricher = BronzeIngestEnricher::disabled();
    let work = tempfile::tempdir().unwrap();
    // NAN3183_ALLOC: "glibc" (defaults), "tuned" (tune_allocator), or
    // "trim" (tuned + release_freed after every flush, as ingest does).
    let alloc = std::env::var("NAN3183_ALLOC").unwrap_or_else(|_| "trim".into());
    if alloc != "glibc" {
        super::memory::tune_allocator();
    }
    let rss = RssSampler::start();
    track_all_threads(true);

    // A. One admission group: JSON values, shape check (infer + decode).
    let admit = |schema: &arrow_schema::SchemaRef| {
        let (admission, _) = admit_bronze_files_salvaging(&paths, tenant, &enricher).unwrap();
        let rows = admission.batch.into_rows();
        let refs = rows.iter().map(|r| &r.ocsf_event).collect::<Vec<_>>();
        let modelled = refs.iter().map(|v| value_heap_bytes(v)).sum::<u64>();
        let json_live = live();
        let (grown, batch) = super::ingest::Ingestor::shape_check(schema, &refs).unwrap();
        drop(refs);
        (grown, batch.unwrap(), modelled, json_live)
    };
    let base = live();
    reset_peak();
    rss.take();
    let seed = Arc::new(super::ingest::seed_schema());
    let (schema, batch, modelled, json_live) = admit(&seed);
    let n = batch.num_rows();
    let admit_peak = peak() - base;
    let admit_rss = rss.take();
    let arrow_bytes = batch.get_array_memory_size();
    println!("A admission: {n} rows, {} source bytes ({:.0} B/row): JSON live {:.0} MiB ({:.1} KB/row; model {:.1} KB/row), peak {:.0} MiB ({:.1} KB/row, {:.0} B/source byte; model heap {:.0} B/source byte), arrow {:.2} KB/row ({:.1} B/source byte), RSS peak {:.0} MiB",
        source_bytes, source_bytes as f64 / n as f64,
        mib((json_live - base) as f64), (json_live - base) as f64 / n as f64 / 1024.0, modelled as f64 / n as f64 / 1024.0,
        mib(admit_peak as f64), admit_peak as f64 / n as f64 / 1024.0, admit_peak as f64 / source_bytes as f64,
        modelled as f64 / source_bytes as f64, arrow_bytes as f64 / n as f64 / 1024.0, arrow_bytes as f64 / source_bytes as f64, mib(admit_rss as f64));

    // B. A full flush buffer: distinct-uid copies of the admitted rows, one
    // batch per admission like the live buffer.
    let copies = flush_rows.div_ceil(n);
    let base = live();
    let hour_batches = (0..copies).map(|c| with_uid_suffix(&batch, &format!("c{c}"))).collect::<Vec<_>>();
    let buffer_rows = hour_batches.iter().map(|b| b.num_rows()).sum::<usize>();
    let buffer_accounted = hour_batches.iter().map(|b| b.get_array_memory_size()).sum::<usize>();
    let buffer_live = live() - base;
    println!("B buffer: {buffer_rows} rows in {copies} batches: accounted {:.0} MiB ({:.2} KB/row), live {:.0} MiB, RSS {:.0} MiB",
        mib(buffer_accounted as f64), buffer_accounted as f64 / buffer_rows as f64 / 1024.0, mib(buffer_live as f64), mib(rss_bytes() as f64));

    // C. The flush build (FlushPlan::build): align + concat + sort, then the
    // hour cut into parallel L0 part writes.
    let build = |hour_batches: &[arrow_array::RecordBatch], writers: usize, now: i64| {
        let started = Instant::now();
        let sorted = super::ingest::sorted_hour(hour_batches, &schema).unwrap();
        let sort_ms = ms(started);
        let rows = sorted.num_rows();
        let chunks = super::ingest::l0_chunks(rows);
        let draft = |len: usize| {
            let mut draft = finished_draft_for(tenant, &schema, hour_of(&sorted));
            draft.rows_in = len as u64;
            draft
        };
        let drafts = chunks.iter().map(|(offset, len)| (draft(*len), sorted.slice(*offset, *len))).collect::<Vec<_>>();
        drop(sorted);
        let started = Instant::now();
        let parts = super::ingest::write_l0_parts_with(work.path(), drafts, now, writers).unwrap();
        (sort_ms, ms(started), parts)
    };
    let mut l0 = Vec::new();
    for writers in [4usize, 2, 1] {
        let base = live();
        reset_peak();
        rss.take();
        let (sort_ms, write_ms, finished) = build(&hour_batches, writers, 10_000 + writers as i64);
        let build_peak = peak() - base;
        let parts = finished.len();
        if writers == 4 {
            l0.extend(finished);
        }
        println!("C flush build ({writers} writers, {parts} parts): heap peak above buffer {:.0} MiB ({:.1} KB/row, {:.2}x buffer), RSS peak {:.0} MiB; sort {sort_ms:.0} ms, write {write_ms:.0} ms ({:.0} rows/s)",
            mib(build_peak as f64), build_peak as f64 / buffer_rows as f64 / 1024.0, build_peak as f64 / buffer_accounted as f64,
            mib(rss.take() as f64), buffer_rows as f64 / (sort_ms + write_ms) * 1e3);
    }

    // D. The pipelined steady state: a flush in flight (its buffer + build)
    // while the next buffer fills and an admission runs.
    let base = live();
    reset_peak();
    rss.take();
    let next = (0..copies).map(|c| with_uid_suffix(&batch, &format!("n{c}"))).collect::<Vec<_>>();
    std::thread::scope(|scope| {
        let flight = scope.spawn(|| build(&hour_batches, 4, 20_000));
        let _ = admit(&schema);
        flight.join().unwrap();
    });
    let pipelined_peak = peak() - base;
    println!("D pipelined (flight build + next buffer + admission): heap peak above flight buffer {:.0} MiB, RSS peak {:.0} MiB",
        mib(pipelined_peak as f64), mib(rss.take() as f64));
    drop(hour_batches);

    // E. A minute merge of two flushes' L0 parts (what the minute lane
    // runs during catch-up), alone.
    let (_, _, second) = build(&next, 4, 30_000);
    drop(next);
    l0.extend(second);
    let inputs = l0.iter().map(|part| super::merge::MergeInput {
        part: crate::parts::part_log::PartRef::from_record(&part.record, &"0".repeat(64), true), dir: part.dir.clone() }).collect::<Vec<_>>();
    let rows_in = inputs.iter().map(|i| i.part.rows).sum::<u64>();
    let base = live();
    reset_peak();
    rss.take();
    let started = Instant::now();
    let merged = super::merge::merge_parts(work.path(), tenant, Level::Minute, hour_of(&batch), &inputs, schema.clone(),
        &crate::parts::format::schema_fingerprint(&schema).unwrap(), crate::parts::provenance::tests::SIGNER, "bench", 40_000).unwrap();
    println!("E minute merge of {} L0 parts ({rows_in} rows -> {}) in {:.0} ms: heap peak {:.0} MiB, RSS peak {:.0} MiB (decode window {} rows)",
        inputs.len(), merged.finished.record.rows, ms(started), mib((peak() - base) as f64), mib(rss.take() as f64),
        super::merge::decode_window_rows_for(0));

    // F. Steady catch-up: cycle after cycle, a pipelined flush build (its
    // own thread, like spawn_blocking) beside the next admissions. Live heap
    // is flat; does RSS keep climbing (allocator retention)?
    let cycles: usize = std::env::var("NAN3183_CYCLES").ok().and_then(|v| v.parse().ok()).unwrap_or(30);
    let deep = |b: &arrow_array::RecordBatch, tag: &str| {
        let b = with_uid_suffix(b, tag);
        let all = arrow_array::UInt32Array::from_iter_values(0..b.num_rows() as u32);
        arrow_select::take::take_record_batch(&b, &all).unwrap()
    };
    let mut buffer = (0..copies).map(|c| deep(&batch, &format!("f0-{c}"))).collect::<Vec<_>>();
    let cycles_started = Instant::now();
    for cycle in 1..=cycles {
        let sealed = std::mem::take(&mut buffer);
        std::thread::scope(|scope| {
            let flight = scope.spawn(|| build(&sealed, 4, 100_000 + cycle as i64));
            for c in 0..copies {
                let (_, admitted, _, _) = admit(&schema);
                buffer.push(deep(&admitted, &format!("f{cycle}-{c}")));
            }
            for part in flight.join().unwrap().2 {
                let _ = std::fs::remove_dir_all(&part.dir);
            }
        });
        drop(sealed);
        if alloc == "trim" {
            super::memory::release_freed();
        }
        if cycle % 5 == 0 || cycle == 1 {
            println!("F[{alloc}] cycle {cycle}: live {:.0} MiB, RSS {:.0} MiB (peak {:.0} MiB)", mib(live() as f64), mib(rss_bytes() as f64), mib(rss.take() as f64));
        }
    }
    println!("F[{alloc}] {cycles} cycles of {buffer_rows} rows in {:.1} s: {:.0} rows/s (admission + pipelined build)",
        cycles_started.elapsed().as_secs_f64(), (cycles * buffer_rows) as f64 / cycles_started.elapsed().as_secs_f64());
    track_all_threads(false);
}

fn hour_of(batch: &arrow_array::RecordBatch) -> i32 {
    let time = batch.column_by_name("time").unwrap();
    event_hour_of(crate::generation::event_time_us_from_array(time.as_ref(), 0).unwrap())
}

fn finished_draft_for(tenant: &str, schema: &arrow_schema::SchemaRef, hour: i32) -> PartDraft {
    PartDraft {
        tenant_id: tenant.into(),
        signer_key_id: crate::parts::provenance::tests::SIGNER.into(),
        level: Level::L0,
        event_hour: hour,
        schema: schema.clone(),
        schema_fingerprint: crate::parts::format::schema_fingerprint(schema).unwrap(),
        inputs: PartInputs::Sources {
            sources: vec![SourceObject { key: "k".into(), version: "1".into(), bytes: 1, sha256: "0".repeat(64), rows: 1, edge_sha256: None }],
            edge_log: None,
        },
        admission: Some(crate::parts::provenance::Admission {
            ocsf_version: "1.9.0".into(), admission_contract: "t".into(), feed_pins: Default::default(),
        }),
        rows_in: 0,
        duplicates_dropped: 0,
        window: DedupWindow::Exact,
        build: "bench".into(),
    }
}
