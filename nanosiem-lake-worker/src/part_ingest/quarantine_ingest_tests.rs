// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3643 end to end on a real ingestor: an object admission refuses whole
//! is quarantined with its reason, survives as long as its TTL, and an
//! operator replay after the cause is fixed admits it exactly once through
//! normal admission (uid dedupe included); another tenant cannot replay it.

use super::*;
use serde_json::json;
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::quarantine::ReplayRefused;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;

const TENANT: &str = "36430000-0000-4000-8000-000000000001";
const OTHER: &str = "36430000-0000-4000-8000-000000000002";
/// 2026-10-01T00:00Z, hours since epoch.
const BASE_HOUR: i64 = 492_096;

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan3643", ed25519_dalek::SigningKey::from_bytes(&[43; 32])).unwrap()
}

fn event(i: usize) -> Value {
    // The `nan2868_part_ingest` fixture shape (it passes bronze admission).
    let time = chrono::DateTime::<chrono::Utc>::from_timestamp(BASE_HOUR * 3_600 + i as i64 * 7, 0).unwrap();
    let uid = format!("gws-{i:05}");
    let raw = format!("raw {uid} token{i}");
    json!({
        "activity_id": 1, "activity_name": "Logon", "actor": {"user": {"name": format!("USER{}", i % 5)}},
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Authentication", "class_uid": 3002,
        "message": format!("token logon {i}"), "raw_data": raw, "raw_data_size": raw.len(),
        "metadata": {"log_name": "security", "log_source": "WINDOWS_EVENT",
            "product": {"name": "fixture", "vendor_name": "nano"}, "tenant_uid": TENANT, "uid": uid, "version": "1.9.0"},
        "severity": "Informational", "severity_id": 1,
        "src_endpoint": {"ip": format!("10.0.0.{}", i % 250), "hostname": format!("ws-{}.corp.local", i % 11)},
        "dst_endpoint": {"ip": format!("192.168.1.{}", i % 20)},
        "user": {"name": format!("user{}", i % 5), "uid": format!("S-1-5-21-{}", i % 5)},
        "status": "Success", "status_id": 1, "time": time.to_rfc3339(), "type_uid": 300201
    })
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

#[tokio::test(flavor = "current_thread")]
async fn refused_object_is_quarantined_then_replayed_once_after_the_fix() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(1_000);
    config.prevalence_enabled = false;
    let clock = BASE_HOUR * 3_600_000 + 600_000;
    let mut ingestor = Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, &signer,
        signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.expect("ingest opens");
    let events = (0..6).map(event).collect::<Vec<_>>();
    let deliver = |name: &str, at: i64| {
        let key = format!("bronze/{name}.parquet");
        write_bronze(&root.join("sources").join(&key), &events);
        spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key, version: "1".into(), bytes: 0, sha256: None,
            edge_sha256: None, notified_at_ms: at }).unwrap();
    };

    // Control: the fixture rows pass admission.
    let control = (100..102).map(event).collect::<Vec<_>>();
    write_bronze(&root.join("sources").join("bronze/control.parquet"), &control);
    spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: "bronze/control.parquet".into(), version: "1".into(),
        bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: clock - 5_000 }).unwrap();
    ingestor.tick(clock - 4_000).await.unwrap();
    ingestor.flush_now(clock - 3_000).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 2, "control rows commit: {:?}", ingestor.quarantine_entries().unwrap());

    // An admission bug refuses the whole object: refused, acked, quarantined.
    ingestor.refuse_admissions = true;
    deliver("gws", clock);
    ingestor.tick(clock + 1_000).await.unwrap();
    ingestor.flush_now(clock + 2_000).await.unwrap();
    assert!(spool.pending(10).await.unwrap().is_empty(), "the refused notice is acknowledged");
    assert_eq!(ingestor.health().objects_rejected_total, 1);
    assert_eq!(ingestor.health().objects_quarantined_total, 1);
    assert_eq!(ingestor.health().rows_committed_total, 2);
    let entries = ingestor.quarantine_entries().unwrap();
    assert_eq!(entries.len(), 1);
    let entry = entries[0].clone();
    assert_eq!((entry.tenant_id.as_str(), entry.source_key.as_str(), entry.scope.as_str()), (TENANT, "bronze/gws.parquet", "object"));
    assert_eq!((entry.reason.as_str(), entry.rows_rejected), ("admission_invalid", 6));
    assert!(entry.detail.contains("simulated admission bug"), "{}", entry.detail);

    // A replay requested while the bug is live is refused again and stays.
    ingestor.request_quarantine_replay(TENANT, &entry.id, clock + 3_000).unwrap();
    ingestor.tick(clock + 4_000).await.unwrap();
    let still = ingestor.quarantine_entries().unwrap();
    assert_eq!(still.len(), 1);
    assert_eq!((still[0].refusals, still[0].replay_requested_at_ms), (2, None), "refused again, request cleared");
    assert_eq!(ingestor.health().rows_committed_total, 2);
    ingestor.tick(clock + 5_000).await.unwrap();
    assert_eq!(ingestor.quarantine_entries().unwrap()[0].refusals, 2, "a cleared request is not retried");

    // Another tenant can never replay it.
    let cross = ingestor.request_quarantine_replay(OTHER, &entry.id, clock + 5_000).unwrap_err();
    assert_eq!(cross.downcast_ref::<ReplayRefused>(), Some(&ReplayRefused::CrossTenant));

    // The fix ships: the replay is admitted once and leaves the quarantine.
    ingestor.refuse_admissions = false;
    ingestor.request_quarantine_replay(TENANT, &entry.id, clock + 6_000).unwrap();
    ingestor.tick(clock + 7_000).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 2 + 6, "every refused row is committed: {:?} {:?}",
        ingestor.quarantine_entries().unwrap(), ingestor.health());
    assert_eq!(ingestor.health().quarantine_replays_total, 1);
    assert!(ingestor.quarantine_entries().unwrap().is_empty());
    let again = ingestor.request_quarantine_replay(TENANT, &entry.id, clock + 8_000).unwrap_err();
    assert_eq!(again.downcast_ref::<ReplayRefused>(), Some(&ReplayRefused::NotFound), "a committed replay cannot run twice");
    let consumed = ingestor.log.live().consumed(&SourceRef {
        key: super::super::quarantine::quarantine_replay_key(TENANT, &entry.id),
        version: QUARANTINE_REPLAY_VERSION.into(),
        sha256: entry.id.clone(),
    });
    assert!(consumed, "the replay is a consumed source in the part log");

    // The source re-sends the same events later: uid dedupe drops them all.
    deliver("gws-resent", clock + 9_000);
    ingestor.tick(clock + 10_000).await.unwrap();
    ingestor.flush_now(clock + 11_000).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 2 + 6, "no duplicates after a replay");
    assert!(spool.pending(10).await.unwrap().is_empty());
}

/// NAN-4554 on the production `Ingestor::open`: a refused object's
/// quarantined copy is in the tenant bucket before its ack; a pod
/// replacement (a fresh work dir) restores it, the operator replays it on
/// the new pod, and the next replacement does not bring it back.
#[tokio::test(flavor = "current_thread")]
async fn the_quarantine_survives_a_pod_replacement() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let clock = BASE_HOUR * 3_600_000 + 600_000;
    let seed = seed_schema();
    let open = |work: &str| {
        let mut config = IngestConfig::new(TENANT, root.join(work));
        config.flush_interval_override_ms = Some(1_000);
        config.prevalence_enabled = false;
        Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, &signer,
            signer.trusted(), BronzeIngestEnricher::disabled(), &seed, clock)
    };
    let mirrored = || {
        let prefix = root.join("parts").join(super::super::quarantine_store::store_prefix(TENANT).unwrap());
        std::fs::read_dir(prefix.join("records")).map(|dir| dir.count()).unwrap_or(0)
    };

    let mut ingestor = open("pod-1").await.expect("ingest opens");
    ingestor.refuse_admissions = true;
    write_bronze(&root.join("sources/bronze/gws.parquet"), &(0..6).map(event).collect::<Vec<_>>());
    spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: "bronze/gws.parquet".into(), version: "1".into(),
        bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: clock }).unwrap();
    ingestor.tick(clock + 1_000).await.unwrap();
    ingestor.flush_now(clock + 2_000).await.unwrap();
    assert!(spool.pending(10).await.unwrap().is_empty(), "refused and acknowledged");
    assert_eq!(mirrored(), 1, "the quarantined copy reached the bucket with the flush that acknowledged it");
    assert_eq!(ingestor.health().quarantine_mirrored_total, 1);
    let id = ingestor.quarantine_entries().unwrap()[0].id.clone();
    drop(ingestor);

    // Pod replacement: the ephemeral work dir is gone.
    std::fs::remove_dir_all(root.join("pod-1")).unwrap();
    let mut ingestor = open("pod-2").await.expect("ingest opens");
    ingestor.tick(clock + 3_000).await.unwrap();
    assert_eq!(ingestor.health().quarantine_restored_total, 1);
    let entries = ingestor.quarantine_entries().unwrap();
    assert_eq!((entries.len(), entries[0].id.as_str(), entries[0].rows_rejected), (1, id.as_str(), 6));

    // The fix ships; the operator replays it on the new pod.
    ingestor.request_quarantine_replay(TENANT, &id, clock + 4_000).unwrap();
    ingestor.tick(clock + 5_000).await.unwrap();
    ingestor.flush_now(clock + 6_000).await.unwrap();
    ingestor.tick(clock + 7_000).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 6, "{:?}", ingestor.health());
    assert!(ingestor.quarantine_entries().unwrap().is_empty());
    drop(ingestor);

    // Another replacement: the released entry stays released.
    std::fs::remove_dir_all(root.join("pod-2")).unwrap();
    let mut ingestor = open("pod-3").await.expect("ingest opens");
    ingestor.tick(clock + 8_000).await.unwrap();
    assert!(ingestor.quarantine_entries().unwrap().is_empty(), "a committed replay is never restored");
    assert_eq!(ingestor.health().quarantine_restored_total, 0);
}

/// A part store whose bucket refuses the quarantine mirror (403) while set
/// (only keys containing `only`, when set), counting quarantine calls.
struct RefusingMirror {
    inner: LocalObjectStore,
    refuse: std::sync::atomic::AtomicBool,
    only: std::sync::Mutex<Option<String>>,
    /// Quarantine PUT attempts (objects + records), object PUT attempts,
    /// and quarantine record LISTs.
    attempts: std::sync::atomic::AtomicUsize,
    object_puts: std::sync::atomic::AtomicUsize,
    lists: std::sync::atomic::AtomicUsize,
}

impl RefusingMirror {
    fn new(inner: LocalObjectStore, refuse: bool) -> Self {
        Self { inner, refuse: refuse.into(), only: std::sync::Mutex::new(None), attempts: 0.into(), object_puts: 0.into(), lists: 0.into() }
    }

    fn check(&self, key: &str) -> Result<()> {
        if !key.contains(super::super::quarantine_store::QUARANTINE_STORE_DIR) {
            return Ok(());
        }
        self.attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let selected = self.only.lock().unwrap().as_deref().is_none_or(|only| key.contains(only));
        if self.refuse.load(std::sync::atomic::Ordering::SeqCst) && selected {
            return Err(super::super::r2_put::TerminalPutError { key: key.into(), status: 403, code: "AccessDenied".into() }.into());
        }
        Ok(())
    }

    fn count(&self, counter: &std::sync::atomic::AtomicUsize) -> usize {
        counter.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl ObjectStore for RefusingMirror {
    async fn object_size(&self, key: &str) -> Result<Option<u64>> { self.inner.object_size(key).await }
    async fn modified_ms(&self, key: &str) -> Result<Option<i64>> { self.inner.modified_ms(key).await }
    async fn get_range(&self, key: &str, range: std::ops::Range<u64>) -> Result<Option<Vec<u8>>> { self.inner.get_range(key, range).await }
    async fn get_to_file(&self, key: &str, path: &std::path::Path) -> Result<bool> { self.inner.get_to_file(key, path).await }
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> { self.inner.get(key).await }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        self.check(key)?;
        self.inner.put_if_absent(key, bytes).await
    }
    async fn put_if_absent_with(&self, key: &str, bytes: &[u8], hints: &WriteHints) -> Result<bool> {
        self.check(key)?;
        self.inner.put_if_absent_with(key, bytes, hints).await
    }
    async fn put_file_if_absent_with(&self, key: &str, path: &std::path::Path, sha256_hex: &str, bytes: u64, hints: &WriteHints)
        -> Result<bool> {
        if key.contains(super::super::quarantine_store::QUARANTINE_STORE_DIR) {
            self.object_puts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.check(key)?;
        self.inner.put_file_if_absent_with(key, path, sha256_hex, bytes, hints).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> { self.inner.put(key, bytes).await }
    async fn delete(&self, key: &str) -> Result<()> { self.inner.delete(key).await }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> { self.inner.list(prefix).await }
    async fn list_page(&self, prefix: &str, after: Option<&str>, limit: usize) -> Result<Vec<String>> {
        if prefix.contains(super::super::quarantine_store::QUARANTINE_STORE_DIR) {
            self.lists.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.refuse.load(std::sync::atomic::Ordering::SeqCst) && self.only.lock().unwrap().as_deref() == Some("LIST") {
                anyhow::bail!("bucket LIST refused");
            }
        }
        self.inner.list_page(prefix, after, limit).await
    }
}

/// NAN-4554: while the bucket refuses the mirror, the flush acknowledging
/// the refused object waits (a retryable error, never a fatal one, even on
/// a 403) for up to `MIRROR_HOLD_MS`; then it proceeds pod-local, and the
/// change is mirrored once the bucket takes it.
#[tokio::test(flavor = "current_thread")]
async fn a_refusing_bucket_holds_the_ack_then_proceeds_pod_local() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = RefusingMirror::new(LocalObjectStore::new(root.join("parts")).unwrap(), true);
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let clock = BASE_HOUR * 3_600_000 + 600_000;
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(1_000);
    config.prevalence_enabled = false;
    let mut ingestor = Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, &signer,
        signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.expect("ingest opens");
    ingestor.refuse_admissions = true;
    write_bronze(&root.join("sources/bronze/gws.parquet"), &(0..6).map(event).collect::<Vec<_>>());
    spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: "bronze/gws.parquet".into(), version: "1".into(),
        bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: clock }).unwrap();
    let _ = ingestor.tick(clock + 1_000).await;
    let held = ingestor.flush_now(clock + 2_000).await.unwrap_err();
    assert!(!fatal_ingest_error(&held), "a mirror refusal is never fatal: {held:#}");
    assert_eq!(spool.pending(10).await.unwrap().len(), 1, "not acknowledged while the copy is pod-local only");
    let hold = super::super::quarantine_store::MIRROR_HOLD_MS;
    // The bucket has refused since the tick's first mirror attempt.
    assert!(ingestor.flush_now(clock + 1_000 + hold - 1).await.is_err(), "still held");
    ingestor.flush_now(clock + 1_000 + hold).await.unwrap();
    assert!(spool.pending(10).await.unwrap().is_empty(), "past the hold: acknowledged, kept pod-local");
    assert_eq!(ingestor.quarantine_entries().unwrap().len(), 1);
    // Backed off between the few flushes, not retried on every call.
    let failures = ingestor.health().quarantine_mirror_failures_total;
    assert!((1..=4).contains(&failures), "{failures} mirror attempts failed");

    assert_eq!(ingestor.health().quarantine_mirror_failing_ids, 1);

    // The bucket takes it again: the queued change is mirrored on its next
    // backoff step (at most MIRROR_RETRY_MAX_MS later).
    parts.refuse.store(false, std::sync::atomic::Ordering::SeqCst);
    let max = super::super::quarantine_store::MIRROR_RETRY_MAX_MS;
    ingestor.tick(clock + 3_000 + hold + max).await.unwrap();
    assert_eq!(ingestor.health().quarantine_mirrored_total, 1);
    assert_eq!((ingestor.health().quarantine_mirror_failing_ids, ingestor.health().quarantine_mirror_failing_since_ms), (0, None));
}

/// Review P1: while the bucket refuses, each failing id backs off on its
/// own (exponential, capped): store calls over 15 min of 1 s ticks stay a
/// handful, not ~2 per tick; one failing id never blocks a later one; and
/// an object PUT that succeeded is not repeated when only its record fails.
#[tokio::test(flavor = "current_thread")]
async fn a_refusing_bucket_is_retried_with_backoff_per_id() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = RefusingMirror::new(LocalObjectStore::new(root.join("parts")).unwrap(), true);
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let clock = BASE_HOUR * 3_600_000 + 600_000;
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(3_600_000);
    config.prevalence_enabled = false;
    let mut ingestor = Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, &signer,
        signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.expect("ingest opens");
    ingestor.refuse_admissions = true;
    for (index, name) in ["a", "b"].iter().enumerate() {
        write_bronze(&root.join(format!("sources/bronze/{name}.parquet")), &(0..3 + index).map(event).collect::<Vec<_>>());
        spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: format!("bronze/{name}.parquet"), version: "1".into(),
            bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: clock + index as i64 }).unwrap();
    }
    let mut now = clock + 1_000;
    let _ = ingestor.tick(now).await;
    let ids = ingestor.quarantine_entries().unwrap().into_iter().map(|entry| entry.id).collect::<Vec<_>>();
    assert_eq!(ids.len(), 2, "both refused and kept");
    let start = parts.count(&parts.attempts);
    for _ in 0..900 {
        now += 1_000;
        let _ = ingestor.tick(now).await;
    }
    let calls = parts.count(&parts.attempts) - start;
    // Per id: retries at +2, +4, +8, ... capped at 300 s: ~9 in 900 s.
    assert!(calls <= 2 * 10, "{calls} quarantine PUT attempts in 900 ticks (backoff)");
    assert_eq!(ingestor.health().quarantine_mirror_failing_ids, 2);

    // Only the first id's keys are refused now: the second is mirrored on
    // its next step, the first keeps backing off (no head-of-line block).
    *parts.only.lock().unwrap() = Some(ids[0].clone());
    let max = super::super::quarantine_store::MIRROR_RETRY_MAX_MS;
    now += max;
    let _ = ingestor.tick(now).await;
    assert_eq!(ingestor.health().quarantine_mirrored_total, 1, "{:?}", ingestor.health());
    assert_eq!(ingestor.health().quarantine_mirror_failing_ids, 1);

    // Its object is in, only its records are refused: retries never
    // re-upload the object.
    *parts.only.lock().unwrap() = Some("records/".into());
    now += max;
    let _ = ingestor.tick(now).await;
    let objects = parts.count(&parts.object_puts);
    for _ in 0..3 {
        now += max;
        let _ = ingestor.tick(now).await;
    }
    assert_eq!(parts.count(&parts.object_puts), objects, "the mirrored object is not PUT again");
    parts.refuse.store(false, std::sync::atomic::Ordering::SeqCst);
    now += max;
    ingestor.tick(now).await.unwrap();
    assert_eq!((ingestor.health().quarantine_mirrored_total, ingestor.health().quarantine_mirror_failing_ids), (2, 0));
}

/// Review P1/P2: a failing restore backs off (no LIST storm every tick),
/// never holds ingest, and reports `quarantine_restore_pending` and its
/// error until it completes.
#[tokio::test(flavor = "current_thread")]
async fn a_failing_restore_backs_off_and_is_reported() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = RefusingMirror::new(LocalObjectStore::new(root.join("parts")).unwrap(), true);
    *parts.only.lock().unwrap() = Some("LIST".into());
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let clock = BASE_HOUR * 3_600_000 + 600_000;
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.prevalence_enabled = false;
    let mut ingestor = Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, &signer,
        signer.trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.expect("ingest opens");
    let mut now = clock;
    for _ in 0..600 {
        now += 1_000;
        ingestor.tick(now).await.unwrap();
    }
    let lists = parts.count(&parts.lists);
    assert!(lists <= 12, "{lists} restore LISTs in 600 ticks (backoff; ~2 per tick without it)");
    assert!(ingestor.health().quarantine_restore_pending);
    assert!(ingestor.health().quarantine_restore_error.as_deref().is_some_and(|error| error.contains("LIST refused")));

    parts.refuse.store(false, std::sync::atomic::Ordering::SeqCst);
    now += super::super::quarantine_store::MIRROR_RETRY_MAX_MS;
    ingestor.tick(now).await.unwrap();
    assert!(!ingestor.health().quarantine_restore_pending);
    assert_eq!((ingestor.health().quarantine_restore_error.as_deref(), ingestor.health().quarantine_restore_refused.as_deref()), (None, None));
}

/// NAN-4554 import, on the production `Ingestor::open`: an object exported
/// from a lost pod is verified and kept on a fresh pod, mirrored to the
/// tenant bucket by the cell's own store, idempotent per id, refused for
/// another tenant, bad bytes or a conflicting copy (nothing written), and
/// its replay commits its rows exactly once even when imported again.
#[tokio::test(flavor = "current_thread")]
async fn an_exported_object_is_imported_verified_mirrored_and_replayed_once() {
    use crate::part_ingest::quarantine::{ImportRefused, Imported};
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let clock = BASE_HOUR * 3_600_000 + 600_000;
    let seed = seed_schema();
    let open = |work: &str| {
        let mut config = IngestConfig::new(TENANT, root.join(work));
        config.flush_interval_override_ms = Some(1_000);
        config.prevalence_enabled = false;
        Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, &signer,
            signer.trusted(), BronzeIngestEnricher::disabled(), &seed, clock)
    };
    let object_key = |id: &str| root.join("parts").join(format!("{}objects/{id}.parquet",
        super::super::quarantine_store::store_prefix(TENANT).unwrap()));

    // The export of the lost pod: an entry and its bytes (no bucket copy).
    let mut old = open("pod-old").await.expect("ingest opens");
    old.refuse_admissions = true;
    write_bronze(&root.join("sources/bronze/gws.parquet"), &(0..6).map(event).collect::<Vec<_>>());
    spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: "bronze/gws.parquet".into(), version: "1".into(),
        bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: clock }).unwrap();
    old.tick(clock + 1_000).await.unwrap();
    old.flush_now(clock + 2_000).await.unwrap();
    let entry = old.quarantine_entries().unwrap().remove(0);
    let exported = root.join("export.parquet");
    assert!(old.quarantine_handle().unwrap().copy_to(&entry.id, &exported).unwrap());
    drop(old);
    std::fs::remove_dir_all(root.join("pod-old")).unwrap();
    std::fs::remove_dir_all(root.join("parts").join(super::super::quarantine_store::store_prefix(TENANT).unwrap())).unwrap();

    let mut ingestor = open("pod-new").await.expect("ingest opens");
    let stage = |ingestor: &Ingestor<'_>, bytes: &[u8]| {
        let path = ingestor.quarantine_handle().unwrap().staging_path(&format!("import-{}", uuid::Uuid::new_v4().simple()));
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let bytes = std::fs::read(&exported).unwrap();
    let refusal = |result: anyhow::Result<Imported>| result.unwrap_err().downcast::<ImportRefused>().unwrap();

    // Review P1: refused until this work dir is restored from the bucket.
    let staged = stage(&ingestor, &bytes);
    assert_eq!(refusal(ingestor.import_quarantined(&entry, &staged, clock + 2_500)), ImportRefused::RestorePending);
    assert!(!staged.exists());
    ingestor.tick(clock + 3_000).await.unwrap();

    // Refused before any write: another tenant, bytes that are not the id.
    let foreign = QuarantineEntry { tenant_id: OTHER.into(), ..entry.clone() };
    let staged = stage(&ingestor, &bytes);
    assert_eq!(refusal(ingestor.import_quarantined(&foreign, &staged, clock + 4_000)), ImportRefused::CrossTenant);
    assert!(!staged.exists(), "a refused import leaves nothing behind");
    let staged = stage(&ingestor, b"not the exported bytes");
    assert_eq!(refusal(ingestor.import_quarantined(&entry, &staged, clock + 4_000)), ImportRefused::Digest);
    let staged = stage(&ingestor, &bytes);
    let expired = QuarantineEntry { expires_at_ms: clock, ..entry.clone() };
    assert_eq!(refusal(ingestor.import_quarantined(&expired, &staged, clock + 4_000)), ImportRefused::Expired);
    assert!(ingestor.quarantine_entries().unwrap().is_empty());

    // Imported: kept, then mirrored by the cell's own store.
    let staged = stage(&ingestor, &bytes);
    assert_eq!(ingestor.import_quarantined(&entry, &staged, clock + 4_000).unwrap(), Imported::New);
    assert_eq!(ingestor.health().quarantine_imported_total, 1);
    ingestor.tick(clock + 5_000).await.unwrap();
    assert_eq!(std::fs::read(object_key(&entry.id)).unwrap(), bytes, "in the tenant bucket via the cell mirror");
    // Again: a no-op.
    let staged = stage(&ingestor, &bytes);
    assert_eq!(ingestor.import_quarantined(&entry, &staged, clock + 6_000).unwrap(), Imported::Exists);
    assert_eq!((ingestor.quarantine_entries().unwrap().len(), ingestor.health().quarantine_imported_total), (1, 1));

    // Replayed once: 6 rows. Importing it again is refused (released).
    ingestor.refuse_admissions = false;
    ingestor.request_quarantine_replay(TENANT, &entry.id, clock + 7_000).unwrap();
    for step in 0..4 {
        ingestor.tick(clock + 8_000 + step * 1_000).await.unwrap();
        ingestor.flush_now(clock + 8_500 + step * 1_000).await.unwrap();
    }
    assert_eq!(ingestor.health().rows_committed_total, 6, "{:?}", ingestor.health());
    assert!(ingestor.quarantine_entries().unwrap().is_empty(), "released");
    let staged = stage(&ingestor, &bytes);
    assert_eq!(refusal(ingestor.import_quarantined(&entry, &staged, clock + 20_000)), ImportRefused::Released);
    assert!(!staged.exists() && ingestor.quarantine_entries().unwrap().is_empty());
    let again = ingestor.request_quarantine_replay(TENANT, &entry.id, clock + 21_000).unwrap_err();
    assert_eq!(again.downcast_ref::<ReplayRefused>(), Some(&ReplayRefused::NotFound));
    assert_eq!(ingestor.health().rows_committed_total, 6, "a second replay of the same rows commits nothing new");
}

/// NAN-4554 review P1, on the production `Ingestor::open`: an object whose
/// event hour is beyond the 72 h dedup horizon (tzd's days-old entries) is
/// imported and replayed once; importing it again more than 48 h later
/// (past the part log's consumed-source memory, `ID_MEMORY_MS`) is refused
/// on the same pod and, from the bucket's release record, on a replaced
/// pod, so its rows commit exactly once. The control at the end shows what
/// the tombstone prevents: without it, the same import commits them again.
#[tokio::test(flavor = "current_thread")]
async fn a_released_import_beyond_the_dedup_horizon_commits_exactly_once() {
    use crate::part_ingest::quarantine::{ImportRefused, Imported};
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    std::fs::create_dir_all(root.join("sources").join("bronze")).unwrap();
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    // The events are 4 days old when they are refused, imported and replayed.
    let clock = BASE_HOUR * 3_600_000 + 4 * 86_400_000;
    let seed = seed_schema();
    let open = |work: &str| {
        let mut config = IngestConfig::new(TENANT, root.join(work));
        config.flush_interval_override_ms = Some(1_000);
        config.prevalence_enabled = false;
        Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, &signer,
            signer.trusted(), BronzeIngestEnricher::disabled(), &seed, clock)
    };
    let refusal = |result: anyhow::Result<Imported>| result.unwrap_err().downcast::<ImportRefused>().unwrap();
    let stage = |ingestor: &Ingestor<'_>, bytes: &[u8]| {
        let path = ingestor.quarantine_handle().unwrap().staging_path(&format!("import-{}", uuid::Uuid::new_v4().simple()));
        std::fs::write(&path, bytes).unwrap();
        path
    };

    // The lost pod's export (no bucket copy).
    let mut old = open("pod-old").await.expect("ingest opens");
    old.refuse_admissions = true;
    write_bronze(&root.join("sources/bronze/gws.parquet"), &(0..6).map(event).collect::<Vec<_>>());
    spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: "bronze/gws.parquet".into(), version: "1".into(),
        bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: clock }).unwrap();
    old.tick(clock + 1_000).await.unwrap();
    old.flush_now(clock + 2_000).await.unwrap();
    let entry = old.quarantine_entries().unwrap().remove(0);
    let exported = root.join("export.parquet");
    assert!(old.quarantine_handle().unwrap().copy_to(&entry.id, &exported).unwrap());
    let bytes = std::fs::read(&exported).unwrap();
    drop(old);
    std::fs::remove_dir_all(root.join("pod-old")).unwrap();
    std::fs::remove_dir_all(root.join("parts").join(super::super::quarantine_store::store_prefix(TENANT).unwrap())).unwrap();

    // Import and replay once: +6.
    let mut ingestor = open("pod-new").await.expect("ingest opens");
    ingestor.tick(clock + 3_000).await.unwrap();
    assert_eq!(ingestor.import_quarantined(&entry, &stage(&ingestor, &bytes), clock + 4_000).unwrap(), Imported::New);
    ingestor.request_quarantine_replay(TENANT, &entry.id, clock + 5_000).unwrap();
    for step in 0..4 {
        ingestor.tick(clock + 6_000 + step * 1_000).await.unwrap();
        ingestor.flush_now(clock + 6_500 + step * 1_000).await.unwrap();
    }
    assert_eq!(ingestor.health().rows_committed_total, 6, "{:?}", ingestor.health());
    assert!(ingestor.quarantine_entries().unwrap().is_empty(), "released");

    // 49 h later (the log forgot the consumed replay source; unrelated
    // data keeps flowing): re-import on the same pod is refused.
    let later = clock + 49 * 3_600_000;
    write_bronze(&root.join("sources/bronze/other.parquet"), &(200..202).map(event).collect::<Vec<_>>());
    spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: "bronze/other.parquet".into(), version: "1".into(),
        bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: later }).unwrap();
    ingestor.tick(later + 1_000).await.unwrap();
    ingestor.flush_now(later + 2_000).await.unwrap();
    assert_eq!(ingestor.health().rows_committed_total, 6 + 2);
    assert_eq!(refusal(ingestor.import_quarantined(&entry, &stage(&ingestor, &bytes), later + 20_000)), ImportRefused::Released);
    assert!(ingestor.request_quarantine_replay(TENANT, &entry.id, later + 21_000).is_err());
    for step in 0..4 {
        ingestor.tick(later + 22_000 + step * 1_000).await.unwrap();
        ingestor.flush_now(later + 22_500 + step * 1_000).await.unwrap();
    }
    assert_eq!(ingestor.health().rows_committed_total, 6 + 2, "never committed twice");
    assert!(ingestor.health().quarantine_mirror_failing_ids == 0);
    drop(ingestor);

    // A replaced pod learns the release from the bucket's record.
    std::fs::remove_dir_all(root.join("pod-new")).unwrap();
    let mut ingestor = open("pod-3").await.expect("ingest opens");
    ingestor.tick(later + 30_000).await.unwrap();
    assert!(!ingestor.health().quarantine_restore_pending);
    assert_eq!(refusal(ingestor.import_quarantined(&entry, &stage(&ingestor, &bytes), later + 31_000)), ImportRefused::Released);
    assert!(ingestor.request_quarantine_replay(TENANT, &entry.id, later + 32_000).is_err());
    for step in 0..4 {
        ingestor.tick(later + 33_000 + step * 1_000).await.unwrap();
        ingestor.flush_now(later + 33_500 + step * 1_000).await.unwrap();
    }
    assert_eq!(ingestor.health().rows_committed_total, 0, "the replaced pod commits nothing: +6 exactly once overall");

    // Control: with the tombstone gone (the pre-fix behavior), the same
    // import is kept and its replay commits the 4-day-old rows a second
    // time (the consumed-source memory is 48 h; uid dedupe does not see
    // beyond its 72 h horizon).
    std::fs::remove_file(root.join("pod-3/bronze-quarantine/released").join(&entry.id)).unwrap();
    assert_eq!(ingestor.import_quarantined(&entry, &stage(&ingestor, &bytes), later + 40_000).unwrap(), Imported::New);
    ingestor.request_quarantine_replay(TENANT, &entry.id, later + 41_000).unwrap();
    for step in 0..4 {
        ingestor.tick(later + 42_000 + step * 1_000).await.unwrap();
        ingestor.flush_now(later + 42_500 + step * 1_000).await.unwrap();
    }
    assert_eq!(ingestor.health().rows_committed_total, 6, "the duplicate the tombstone prevents: {:?}", ingestor.health());
}

/// NAN-4554 import caps and conflicts on the production `Quarantine::open`.
#[test]
fn import_refuses_over_cap_and_a_conflicting_copy() {
    use crate::part_ingest::quarantine::{ImportRefused, Imported, Quarantine};
    let root = tempfile::tempdir().unwrap();
    let source = Quarantine::open(&root.path().join("old"), TENANT).unwrap();
    let keep = |body: &[u8], now: i64| {
        let id = crate::parts::sha256_hex(body);
        let path = root.path().join(format!("{id}.bin"));
        std::fs::write(&path, body).unwrap();
        source.keep(&path, &id, &super::super::quarantine::Refusal { source_key: "bronze/a.parquet", source_version: "1",
            scope: "object", reason: "admission_invalid", detail: "admission_crashed: test", rows_rejected: 3 }, now).unwrap();
        source.get(&id).unwrap().unwrap()
    };
    let now = BASE_HOUR * 3_600_000;
    let small = keep(b"0123456789", now);
    let big = keep(b"0123456789abcdefghij", now + 1);
    let quarantine = Quarantine::open(&root.path().join("new"), TENANT).unwrap().with_limits(20, 15);
    quarantine.mark_restored(None).unwrap();
    let stage = |bytes: &[u8]| {
        let path = quarantine.staging_path(&format!("import-{}", uuid::Uuid::new_v4().simple()));
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let refusal = |result: anyhow::Result<Imported>| result.unwrap_err().downcast::<ImportRefused>().unwrap();
    assert_eq!(refusal(quarantine.import(&big, &stage(b"0123456789abcdefghij"), now + 2)), ImportRefused::ObjectTooLarge);
    assert_eq!(quarantine.import(&small, &stage(b"0123456789"), now + 2).unwrap(), Imported::New);
    let other = keep(b"ABCDEFGHIJKLMNO", now + 3);
    assert_eq!(refusal(quarantine.import(&other, &stage(b"ABCDEFGHIJKLMNO"), now + 4)), ImportRefused::OverCap);
    // The kept copy rotted: the same id with the right bytes is a conflict,
    // never silently replaced.
    let (path, _) = quarantine.data_file(&small.id).unwrap().unwrap();
    std::fs::write(&path, b"rotted....").unwrap();
    assert_eq!(refusal(quarantine.import(&small, &stage(b"0123456789"), now + 5)), ImportRefused::Conflict);
    assert_eq!(quarantine.list().unwrap().len(), 1);
    let wrong_size = QuarantineEntry { bytes: 11, ..small.clone() };
    let fresh = Quarantine::open(&root.path().join("fresh"), TENANT).unwrap();
    fresh.mark_restored(None).unwrap();
    let staged = fresh.staging_path("import-size");
    std::fs::write(&staged, b"0123456789").unwrap();
    assert_eq!(refusal(fresh.import(&wrong_size, &staged, now + 6)), ImportRefused::Size);
    assert!(fresh.list().unwrap().is_empty() && !staged.exists());
}

/// NAN-4554: the import body streams to disk under its cap; the entry
/// header decodes strictly.
#[tokio::test(flavor = "current_thread")]
async fn import_body_is_bounded_and_the_entry_header_is_strict() {
    use base64::Engine;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join(".import.tmp");
    assert!(super::super::cell::stage_import_body(axum::body::Body::from(vec![7_u8; 100]), &path, 100).await.unwrap());
    assert_eq!(std::fs::read(&path).unwrap().len(), 100);
    assert!(!super::super::cell::stage_import_body(axum::body::Body::from(vec![7_u8; 101]), &path, 100).await.unwrap());
    assert!(!path.exists(), "an over-cap body is removed");

    let quarantine = crate::part_ingest::quarantine::Quarantine::open(&root.path().join("q"), TENANT).unwrap();
    let body = b"bytes";
    let id = crate::parts::sha256_hex(body);
    let kept = root.path().join("k.bin");
    std::fs::write(&kept, body).unwrap();
    quarantine.keep(&kept, &id, &super::super::quarantine::Refusal { source_key: "bronze/a.parquet", source_version: "1",
        scope: "object", reason: "admission_invalid", detail: "d", rows_rejected: 1 }, BASE_HOUR * 3_600_000).unwrap();
    let entry = quarantine.get(&id).unwrap().unwrap();
    let mut headers = axum::http::HeaderMap::new();
    let encoded = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&entry).unwrap());
    headers.insert(super::super::cell::QUARANTINE_IMPORT_ENTRY_HEADER, encoded.parse().unwrap());
    assert_eq!(super::super::cell::import_entry(&headers), Some(entry.clone()));
    let mut extra = serde_json::to_value(&entry).unwrap();
    extra["unexpected"] = json!(1);
    let encoded = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&extra).unwrap());
    headers.insert(super::super::cell::QUARANTINE_IMPORT_ENTRY_HEADER, encoded.parse().unwrap());
    assert_eq!(super::super::cell::import_entry(&headers), None, "unknown fields are refused");
}
