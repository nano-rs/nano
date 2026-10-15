// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3492 acceptance: the trusted-local bronze listing queue feeds
//! `ingest[T]` exactly once.
//!
//! Bronze objects sit under `tenant_id=T/{seconds}-{id}.parquet` exactly as
//! Vector's open-core bronze sink writes them. The queue lists the prefix,
//! ingest commits L0 parts, and:
//! - every input row is in the live set once;
//! - a crash after the part-log commit but before the cursor is persisted
//!   (at every flush, repeatedly) replays as duplicates, never as new rows;
//! - a restart after a clean drain delivers nothing.

use anyhow::Result;
use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::ReaderBuilder;
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::part_ingest::bronze_list::{
    BronzeListQueue, BronzeListSettings, BronzeLister, ListedBronze,
};
use nanosiem_lake_worker::part_ingest::dedup::read_time_uids;
use nanosiem_lake_worker::part_ingest::discovery::NoticeHandle;
use nanosiem_lake_worker::part_ingest::ingest::seed_schema;
use nanosiem_lake_worker::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice};
use nanosiem_lake_worker::parts::format::PartKeys;
use nanosiem_lake_worker::parts::part_log::{load_log, LocalObjectStore, ObjectStore};
use nanosiem_lake_worker::parts::provenance::LocalPartSigner;
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const TENANT: &str = "6f3d1060-5b8e-4d4c-9a3e-0e2b7c9c7106";
/// 2026-09-25T00:00:00Z
const DAY0_S: i64 = 1_790_294_400;

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan3492", SigningKey::from_bytes(&[21; 32])).unwrap()
}

fn event(uid: &str, time_s: i64, i: usize) -> Value {
    let time = chrono::DateTime::from_timestamp(time_s, (i as u32 % 1000) * 1_000_000).unwrap();
    let raw = format!(
        "raw {uid} host-{} logon token{} mimikatz{}",
        i % 7,
        i % 13,
        if i % 97 == 0 { "-marker" } else { "" }
    );
    json!({
        "activity_id": 1,
        "activity_name": "Logon",
        "actor": {"user": {"name": format!("USER{}", i % 5)}},
        "category_name": "Identity & Access Management",
        "category_uid": 3,
        "class_name": "Authentication",
        "class_uid": 3002,
        "message": format!("Failed logon for user{} from 10.0.{}.{}", i % 5, i % 3, i % 250),
        "raw_data": raw,
        "raw_data_size": raw.len(),
        "metadata": {
            "log_name": "security",
            "log_source": if i % 3 == 0 { "WINDOWS_EVENT" } else { "CLOUDTRAIL" },
            "product": {"name": "fixture", "vendor_name": "nano"},
            "tenant_uid": TENANT,
            "uid": uid,
            "version": "1.9.0"
        },
        "severity": "Informational",
        "severity_id": 1,
        "src_endpoint": {"ip": format!("10.0.{}.{}", i % 3, i % 250), "hostname": format!("ws-{}.corp.local", i % 11)},
        "dst_endpoint": {"ip": format!("192.168.1.{}", i % 20)},
        "user": {"name": format!("user{}", i % 5), "uid": format!("S-1-5-21-{}", i % 5)},
        "status": "Failure",
        "status_id": 2,
        "time": time.to_rfc3339(),
        "type_uid": 300201
    })
}

fn write_bronze(path: &Path, events: &[Value]) {
    let mut json = Vec::new();
    for event in events {
        serde_json::to_writer(&mut json, event).unwrap();
        json.push(b'\n');
    }
    let (schema, _) =
        infer_json_schema_from_seekable(&mut Cursor::new(json.clone()), None).unwrap();
    let reader = ReaderBuilder::new(Arc::new(schema))
        .build(Cursor::new(json))
        .unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        let w = writer.get_or_insert_with(|| {
            ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None)
                .unwrap()
        });
        w.write(&batch).unwrap();
    }
    writer.unwrap().close().unwrap();
}

/// A directory "bucket": the bronze location root, listed in key order.
#[derive(Clone)]
struct DirLister(PathBuf);

#[async_trait]
impl BronzeLister for DirLister {
    async fn list_after(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ListedBronze>> {
        let dir = self.0.join(prefix);
        let mut keys = match std::fs::read_dir(&dir) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .map(|name| format!("{prefix}{name}"))
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };
        keys.sort();
        Ok(keys
            .into_iter()
            .filter(|key| start_after.is_none_or(|s| key.as_str() > s))
            .take(limit)
            .map(|key| {
                let bytes = std::fs::metadata(self.0.join(&key))
                    .map(|m| m.len())
                    .unwrap_or(0);
                ListedBronze {
                    etag: format!("etag-{bytes}"),
                    key,
                    bytes,
                    last_modified_ms: None,
                }
            })
            .collect())
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    parts: LocalObjectStore,
    sources: LocalObjectStore,
    signer: LocalPartSigner,
    rows: usize,
}

/// `objects` bronze objects of `rows` events each, one every 20 s.
fn fixture(objects: usize, rows: usize) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let bronze = root.join("bronze-v2");
    std::fs::create_dir_all(bronze.join(format!("tenant_id={TENANT}"))).unwrap();
    let mut n = 0;
    for o in 0..objects {
        let at = DAY0_S + 2_400 + (o as i64) * 20;
        let events = (0..rows)
            .map(|r| {
                n += 1;
                event(&format!("uid-{o:05}-{r:04}"), at - 5 + (r as i64 % 5), n)
            })
            .collect::<Vec<_>>();
        write_bronze(
            &bronze.join(format!("tenant_id={TENANT}/{at}-{o:08x}.parquet")),
            &events,
        );
    }
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(&bronze).unwrap();
    Fixture {
        _dir: dir,
        parts,
        sources,
        signer: signer(),
        rows: objects * rows,
        root,
    }
}

fn queue(fx: &Fixture) -> BronzeListQueue<DirLister> {
    let settings = BronzeListSettings {
        settle_secs: Some(60),
        poll_ms: Some(100),
    };
    BronzeListQueue::open(
        DirLister(fx.root.join("bronze-v2")),
        TENANT,
        &fx.root.join("state"),
        &settings,
    )
    .unwrap()
}

fn config(root: &Path) -> IngestConfig {
    let mut cfg = IngestConfig::new(TENANT, root.join("work"));
    cfg.flush_interval_override_ms = Some(10_000);
    cfg.max_objects_per_admission = 12;
    cfg.prevalence_enabled = false;
    cfg.source_key_prefix = Some(format!("tenant_id={TENANT}/"));
    cfg
}

async fn open<'a>(
    fx: &'a Fixture,
    queue: &'a dyn NoticeQueue,
    now_ms: i64,
) -> Result<Ingestor<'a>> {
    Ingestor::open(
        config(&fx.root),
        &fx.parts,
        &fx.sources,
        queue,
        &fx.signer,
        fx.signer.trusted(),
        BronzeIngestEnricher::disabled(),
        &seed_schema(),
        now_ms,
    )
    .await
}

async fn live_rows(fx: &Fixture) -> Vec<(i64, String)> {
    let set = load_log(&fx.parts, TENANT).await.unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let mut rows = Vec::new();
    for part in set.parts() {
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        for index in 0..part.data_files as usize {
            let bytes = fx.parts.get(&keys.data(index)).await.unwrap().unwrap();
            let path = scratch
                .path()
                .join(format!("{}-{index}.parquet", part.part_id));
            std::fs::write(&path, bytes).unwrap();
            rows.extend(read_time_uids(&path).unwrap());
        }
    }
    rows
}

fn assert_exactly_once(rows: &[(i64, String)], expected: usize) {
    let unique = rows.iter().map(|(_, u)| u.as_str()).collect::<HashSet<_>>();
    assert_eq!(
        unique.len(),
        rows.len(),
        "a uid appears more than once in the live set"
    );
    assert_eq!(rows.len(), expected, "live set lost or gained rows");
}

/// The queue with an injected crash: the `fail_ack_at`-th ack fails before
/// the cursor is persisted (the part-log commit already happened).
struct CrashingAck<'q> {
    queue: &'q BronzeListQueue<DirLister>,
    fail_ack_at: AtomicUsize,
    acks: AtomicUsize,
}

#[async_trait]
impl NoticeQueue for CrashingAck<'_> {
    async fn pending(&self, max: usize) -> Result<Vec<(NoticeHandle, SourceNotice)>> {
        self.queue.pending(max).await
    }

    async fn ack(&self, handles: &[NoticeHandle]) -> Result<()> {
        if !handles.is_empty()
            && self.acks.fetch_add(1, Ordering::SeqCst) + 1
                == self.fail_ack_at.load(Ordering::SeqCst)
        {
            anyhow::bail!("injected crash after the log commit, before the cursor persisted");
        }
        self.queue.ack(handles).await
    }
}

#[tokio::test(flavor = "current_thread")]
async fn listing_feeds_ingest_exactly_once_and_restarts_idle() {
    let fx = fixture(40, 10);
    let q = queue(&fx);
    let mut clock = (DAY0_S + 2_400) * 1_000;
    let mut ingestor = open(&fx, &q, clock).await.unwrap();
    for _ in 0..30 {
        clock += 11_000;
        ingestor.tick(clock).await.unwrap();
    }
    ingestor.flush_now(clock).await.unwrap();
    let health = ingestor.health();
    assert_eq!(
        (health.objects_rejected_total, health.rows_rejected_total),
        (0, 0),
        "nothing refused"
    );
    assert!(
        q.pending(10).await.unwrap().is_empty(),
        "everything listed was acked"
    );
    assert_exactly_once(&live_rows(&fx).await, fx.rows);
    let watermark = q.watermark().expect("old objects settle at once");
    assert!(
        watermark.ends_with(&format!("{:08x}.parquet", 39)),
        "watermark {watermark}"
    );
    drop(ingestor);
    drop(q);
    // A restart (new process) lists nothing new and commits nothing.
    let q = queue(&fx);
    assert!(q.pending(10).await.unwrap().is_empty());
    let before = load_log(&fx.parts, TENANT).await.unwrap().parts().count();
    let mut ingestor = open(&fx, &q, clock).await.unwrap();
    clock += 11_000;
    ingestor.tick(clock).await.unwrap();
    ingestor.flush_now(clock).await.unwrap();
    assert_eq!(
        load_log(&fx.parts, TENANT).await.unwrap().parts().count(),
        before
    );
    assert_exactly_once(&live_rows(&fx).await, fx.rows);
}

#[tokio::test(flavor = "current_thread")]
async fn crash_between_commit_and_cursor_replays_without_duplicates() {
    let fx = fixture(120, 10);
    let mut clock = (DAY0_S + 2_400) * 1_000;
    let mut crashes = 0;
    for round in 0..40 {
        // Every round is a new process: the queue reopens from its state file.
        let q = queue(&fx);
        if q.pending(1).await.unwrap().is_empty() {
            break;
        }
        let crashing = CrashingAck {
            queue: &q,
            fail_ack_at: AtomicUsize::new(if round % 2 == 0 { 1 } else { usize::MAX }),
            acks: AtomicUsize::new(0),
        };
        let mut ingestor = open(&fx, &crashing, clock).await.unwrap();
        for _ in 0..3 {
            clock += 11_000;
            if ingestor.tick(clock).await.is_err() {
                crashes += 1;
                break;
            }
        }
        drop(ingestor); // the process "dies": buffer, window and queue memory are lost
    }
    let q = queue(&fx);
    let mut ingestor = open(&fx, &q, clock).await.unwrap();
    for _ in 0..30 {
        clock += 11_000;
        ingestor.tick(clock).await.unwrap();
    }
    ingestor.flush_now(clock).await.unwrap();
    assert!(crashes >= 3, "the test injected crashes ({crashes})");
    assert!(q.pending(1).await.unwrap().is_empty());
    assert_exactly_once(&live_rows(&fx).await, fx.rows);
}
