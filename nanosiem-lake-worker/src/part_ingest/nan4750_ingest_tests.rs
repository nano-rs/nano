// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4750 (bakeoff 1.0.11 wall #2): a class-filtered query on the open
//! hour kept ~992 of 993 row groups, because only the hour merge wrote
//! class-labelled family files and every L0 part mixed all classes. A flush
//! now writes each `(source, class)` of at least `CLASS_FAMILY_MIN_ROWS`
//! buffered rows as its own class-labelled L0 part. These tests run the
//! production path (`Ingestor::open`, admission, `flush_plan`, the L0
//! writer, signing and publication into the part store) and read the
//! signed records back from the store as a reader does.

use super::*;
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::part_query::prune::file_family_may_match;
use crate::parts::part_log::{LocalObjectStore, ObjectStore};
use crate::parts::provenance::{LocalPartSigner, SignedProvenance};
use crate::planner::CandidateHint;
use serde_json::json;

const TENANT: &str = "47500000-0000-4000-8000-000000000001";
const BASE_HOUR: i64 = 492_120;
/// Ten minutes into the hour: it is the open (current) hour.
const CLOCK: i64 = BASE_HOUR * 3_600_000 + 600_000;
/// Two large families (one per source) and a small one sharing a source.
const AUTH_ROWS: usize = 9_000;
const NETWORK_ROWS: usize = 9_000;
const PROCESS_ROWS: usize = 2_000;

fn class_of(i: usize) -> (i64, &'static str) {
    if i < AUTH_ROWS {
        (3002, "windows_event")
    } else if i < AUTH_ROWS + NETWORK_ROWS {
        (4001, "firewall")
    } else {
        (1007, "windows_event")
    }
}

fn event(i: usize) -> Value {
    let (class, source) = class_of(i);
    // Interleaved in time: every class spans the whole window, as live
    // traffic does, so a time-chunked L0 mixes them.
    let time = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(BASE_HOUR * 3_600_000 + (i as i64 * 7_919) % 590_000).unwrap();
    let uid = format!("nan4750-{i:06}");
    let raw = format!("raw {uid} class {class}");
    let mut row = json!({
        "class_uid": class, "category_uid": class / 1000, "activity_id": 1, "type_uid": class * 100 + 1,
        "severity_id": 1, "time": time.to_rfc3339(), "message": format!("class {class} seq {i}"),
        "raw_data": raw, "raw_data_size": raw.len(),
        "metadata": {"uid": uid, "version": "1.9.0", "log_source": source, "tenant_uid": TENANT,
            "product": {"name": source, "vendor_name": "fixture"}},
    });
    match class {
        1007 => {
            row["process"] = json!({"pid": 4000 + i % 97, "name": format!("proc{}", i % 97),
                "file": {"name": format!("proc{}.exe", i % 97), "type_id": 1}});
            row["actor"] = json!({"process": {"pid": 600, "name": "services.exe"}});
            row["device"] = json!({"hostname": format!("ws-{}.corp.local", i % 13), "type_id": 2});
            row["status"] = json!("Success");
        }
        3002 => {
            row["actor"] = json!({"user": {"name": format!("user{}", i % 17)}});
            row["user"] = json!({"name": format!("user{}", i % 17), "uid": "S-1-5-21-1"});
            row["src_endpoint"] = json!({"ip": format!("10.0.{}.{}", i % 7, i % 200), "hostname": format!("ws-{}.corp.local", i % 13)});
            row["dst_endpoint"] = json!({"ip": "192.168.1.1", "port": 445});
            row["status"] = json!("Failure");
            row["status_id"] = json!(2);
        }
        _ => {
            row["src_endpoint"] = json!({"ip": format!("10.0.{}.{}", i % 7, i % 200), "hostname": format!("ws-{}.corp.local", i % 13)});
            row["dst_endpoint"] = json!({"ip": "203.0.113.9", "port": 443});
            row["status"] = json!("Success");
        }
    }
    row
}

fn write_bronze(path: &std::path::Path, events: &[Value]) {
    use arrow_json::reader::infer_json_schema_from_seekable;
    let mut lines = Vec::new();
    for event in events {
        serde_json::to_writer(&mut lines, event).unwrap();
        lines.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut std::io::Cursor::new(lines.clone()), None).unwrap();
    let reader = arrow_json::ReaderBuilder::new(Arc::new(schema)).build(std::io::Cursor::new(lines)).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        writer
            .get_or_insert_with(|| parquet::arrow::ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap())
            .write(&batch)
            .unwrap();
    }
    writer.unwrap().close().unwrap();
}

/// `(class_uid, metadata.log_source)` of every row of a published data file.
fn file_rows(bytes: Vec<u8>) -> Vec<(i64, String)> {
    let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
        .unwrap().build().unwrap();
    let mut rows = Vec::new();
    for batch in reader {
        let batch = batch.unwrap();
        let sources = super::super::writer::log_source_strings(&batch).unwrap();
        let classes = batch.column_by_name("class_uid");
        for row in 0..batch.num_rows() {
            rows.push((super::super::merge::class_at(classes, row).unwrap(), sources.value(row).to_string()));
        }
    }
    rows
}

struct PublishedFile {
    log_sources: Option<Vec<String>>,
    class_id: Option<i64>,
    row_groups: u32,
    rows: Vec<(i64, String)>,
}

/// Every data file of the live L0 parts, from the signed records in the
/// part store (verified against the tenant keys, as a reader loads them).
async fn published_l0_files(ingestor: &Ingestor<'_>, parts: &LocalObjectStore, signer: &LocalPartSigner) -> Vec<PublishedFile> {
    let mut files = Vec::new();
    for part in ingestor.live_parts() {
        assert_eq!(part.level, Level::L0, "nothing merged in the open hour yet");
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        let bytes = parts.get(&keys.provenance()).await.unwrap().expect("provenance published");
        let signed = SignedProvenance::verify_bytes(&bytes, TENANT, &signer.trusted()).expect("signed record verifies");
        for data in &signed.record.files.data {
            let body = parts.get(&keys.file(&data.name)).await.unwrap().expect("data file published");
            files.push(PublishedFile {
                log_sources: data.log_sources.clone(),
                class_id: data.class_id,
                row_groups: data.row_groups,
                rows: file_rows(body),
            });
        }
    }
    files
}

#[tokio::test]
async fn a_class_filtered_query_on_the_open_hour_prunes_to_that_class() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = LocalPartSigner::new("lab-signer-nan4750", ed25519_dalek::SigningKey::from_bytes(&[47; 32])).unwrap();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.prevalence_enabled = false;
    let mut ingestor = Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, &signer,
        signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), CLOCK).await.expect("ingest opens");

    let total = AUTH_ROWS + NETWORK_ROWS + PROCESS_ROWS;
    write_bronze(&root.join("sources/bronze/a.parquet"), &(0..total).map(event).collect::<Vec<_>>());
    spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: "bronze/a.parquet".into(), version: "1".into(),
        bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: CLOCK - 5_000 }).unwrap();
    let report = ingestor.tick(CLOCK).await.unwrap();
    assert_eq!(report.admitted_rows, total as u64);
    ingestor.flush_now(CLOCK + 1_000).await.unwrap();

    let files = published_l0_files(&ingestor, &parts, &signer).await;
    // One flush hour of 20k rows wrote one L0 part before (l0_chunks); now
    // one per large family plus the mixed rest: max(1, 3) = 3 parts.
    let live = ingestor.live_parts();
    assert_eq!(live.len(), 3, "two class parts and the rest");
    assert_eq!(live.iter().map(|part| part.rows).sum::<u64>(), total as u64, "every admitted row is in exactly one part");
    let mut labels = files.iter().map(|file| (file.class_id, file.log_sources.clone())).collect::<Vec<_>>();
    labels.sort();
    labels.dedup();
    assert_eq!(labels, vec![
        (None, None),
        (Some(3002), Some(vec!["windows_event".to_string()])),
        (Some(4001), Some(vec!["firewall".to_string()])),
    ]);
    // Exact labels: a labelled file holds only rows of its source and class,
    // and the rest holds none of a labelled family.
    for file in &files {
        match (file.class_id, &file.log_sources) {
            (Some(class), Some(sources)) => assert!(file.rows.iter().all(|(c, s)| *c == class && *s == sources[0])),
            _ => assert!(file.rows.iter().all(|(c, _)| *c == 1007)),
        }
    }

    // The planner's signed-family stage (`file_family_may_match`, what the
    // engine applies per data file): a class-filtered query keeps its class
    // file and the mixed rest, and never drops a matching row.
    for (class, rows) in [(4001, NETWORK_ROWS), (3002, AUTH_ROWS)] {
        let hints = [CandidateHint::Class { value: class }];
        let (kept, pruned): (Vec<_>, Vec<_>) = files.iter()
            .partition(|file| file_family_may_match(file.log_sources.as_deref(), file.class_id, &hints));
        assert!(pruned.iter().all(|file| file.rows.iter().all(|(c, _)| *c != class)), "a pruned file held a matching row");
        assert_eq!(kept.iter().flat_map(|file| &file.rows).filter(|(c, _)| *c == class).count(), rows, "every matching row kept");
        assert_eq!(kept.iter().filter(|file| file.class_id.is_some()).count(), 1, "only its own class file");
        let kept_groups = kept.iter().map(|file| file.row_groups).sum::<u32>();
        let all_groups = files.iter().map(|file| file.row_groups).sum::<u32>();
        assert!(kept_groups < all_groups, "class {class}: kept {kept_groups} of {all_groups} row groups");
        // Rows a reader still decodes: its class plus the small mixed rest,
        // not the other large class (before: every row of the hour).
        assert_eq!(kept.iter().map(|file| file.rows.len()).sum::<usize>(), rows + PROCESS_ROWS);
    }
}

/// Below `CLASS_FAMILY_MIN_ROWS` per family a flush is unchanged: one mixed
/// L0 part (no extra objects for small or low-rate tenants).
#[tokio::test]
async fn a_small_flush_stays_one_mixed_part() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = LocalPartSigner::new("lab-signer-nan4750", ed25519_dalek::SigningKey::from_bytes(&[47; 32])).unwrap();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.prevalence_enabled = false;
    let mut ingestor = Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, &signer,
        signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), CLOCK).await.expect("ingest opens");
    // 3,000 rows of each class: all under the floor.
    let rows = (0..3_000).chain(AUTH_ROWS..AUTH_ROWS + 3_000).chain(AUTH_ROWS + NETWORK_ROWS..AUTH_ROWS + NETWORK_ROWS + 2_000)
        .map(event).collect::<Vec<_>>();
    write_bronze(&root.join("sources/bronze/a.parquet"), &rows);
    spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: "bronze/a.parquet".into(), version: "1".into(),
        bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: CLOCK - 5_000 }).unwrap();
    assert_eq!(ingestor.tick(CLOCK).await.unwrap().admitted_rows, rows.len() as u64);
    ingestor.flush_now(CLOCK + 1_000).await.unwrap();
    let files = published_l0_files(&ingestor, &parts, &signer).await;
    assert_eq!(ingestor.live_parts().len(), 1);
    assert!(files.iter().all(|file| file.class_id.is_none() && file.log_sources.is_none()));
}
