// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4137: the hosted landing[T] halves against fakes of the tenant
//! Worker's landing ledger DO and edge-log producer route, plus open-core
//! parity of the discover/emit refactor.

use super::*;
use crate::landing::{
    convert_file, decode_bronze, refused_key, BronzeObjects, Converter, Engine, Ledger, PrefixDiscover, TickReport,
    REFUSED_PREFIX,
};
use arrow_json::reader::{infer_json_schema_from_seekable, ReaderBuilder};
use nanosiem_core::parsers::landing_ocsf::LandingOcsfStage;
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};
use std::io::Cursor;

const TENANT: &str = "6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b";
const OTHER_TENANT: &str = "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d";
const SOURCE: &str = "0b8f6c1e-3c55-4a8e-9d3e-2f7c1a4b5d60";
const CREDENTIAL: &str = "1b84f015-b560-433b-8bb6-ed4e39f48334";

fn source() -> LandingSource {
    LandingSource {
        source_id: Uuid::parse_str(SOURCE).unwrap(),
        route_key: "tenzir_sysmon".into(),
        credential_id: Uuid::parse_str(CREDENTIAL).unwrap(),
        active: true,
    }
}

fn key(tenant: &str, name: &str) -> String {
    format!("{LANDING_PREFIX}tenant_id={tenant}/source={SOURCE}/{name}")
}

fn sysmon(uid: Option<&str>, pid: i64) -> Value {
    let mut event = json!({
        "class_uid": 1007, "class_name": "Process Activity",
        "category_uid": 1, "category_name": "System Activity",
        "activity_id": 1, "activity_name": "Launch", "type_uid": 100701,
        "severity_id": 1, "severity": "Informational",
        "time": 1_791_975_595_105_i64,
        "message": "Process launched",
        "metadata": {"version": "1.9.0", "product": {"name": "Sysmon", "vendor_name": "Microsoft"}},
        "device": {"hostname": "wks-01", "type_id": 0},
        "actor": {"process": {"pid": 900, "name": "explorer.exe"}},
        "process": {"pid": pid, "cmd_line": "cmd.exe /c echo x"}
    });
    if let Some(uid) = uid {
        event["metadata"]["uid"] = json!(uid);
    }
    event
}

fn ndjson(events: &[Value]) -> Vec<u8> {
    let mut out = Vec::new();
    for event in events {
        serde_json::to_writer(&mut out, event).unwrap();
        out.push(b'\n');
    }
    out
}

fn parquet(events: &[Value]) -> Vec<u8> {
    let json = ndjson(events);
    let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(json.clone()), None).unwrap();
    let schema = Arc::new(schema);
    let reader = ReaderBuilder::new(schema.clone()).build(Cursor::new(json)).unwrap();
    let mut out = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut out, schema, None).unwrap();
    for batch in reader {
        writer.write(&batch.unwrap()).unwrap();
    }
    writer.close().unwrap();
    out
}

fn stage() -> LandingOcsfStage {
    LandingOcsfStage::new(1).unwrap()
}

fn memory() -> Operator {
    Operator::new(opendal::services::Memory::default()).unwrap().finish()
}

async fn keys_under(store: &Operator, prefix: &str) -> Vec<String> {
    let mut keys = store
        .list_with(prefix)
        .recursive(true)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|entry| entry.path().to_string())
        .filter(|path| !path.ends_with('/'))
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

/// Decoded bronze rows minus the stage's wall-clock stamps
/// (`metadata.logged_time` / `processed_time` are "now" at conversion).
fn stable_events(bytes: &[u8]) -> Vec<Value> {
    decode_bronze(bytes)
        .unwrap()
        .into_iter()
        .map(|event| {
            let mut event = event.unwrap();
            let metadata = event["metadata"].as_object_mut().unwrap();
            assert!(metadata.remove("logged_time").is_some() && metadata.remove("processed_time").is_some());
            event
        })
        .collect()
}

fn parquet_schema(bytes: &[u8]) -> arrow_schema::SchemaRef {
    ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(bytes)).unwrap().schema().clone()
}

/// The uids admission reads from bronze bytes (the 6 h / 72 h window key).
fn uids_of(segments: &[(String, Vec<u8>)]) -> Vec<String> {
    let mut uids = segments
        .iter()
        .flat_map(|(_, bytes)| decode_bronze(bytes).unwrap())
        .map(|event| event.unwrap()["metadata"]["uid"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    uids.sort();
    uids
}

// ------------------------------------------------------------------ fakes

#[derive(Debug, Clone)]
struct FakeFile {
    file: LedgerFile,
    /// landed | leased | accepted | refused
    state: &'static str,
    reason: Option<String>,
    leased_by: u64,
}

#[derive(Default)]
struct LedgerState {
    epoch: u64,
    files: Vec<FakeFile>,
    commits: Vec<LedgerCommit>,
    /// Simulate a crash/outage on the next commit (after the produce).
    fail_next_commit: bool,
    /// A Worker from before NAN-4321: 400 to a commit with row accounting keys.
    pre_row_accounting: bool,
    /// A Worker from before NAN-4325: 400 to a commit with `contentSha256`.
    pre_content_hash: bool,
    /// A Worker from before NAN-4336: 400 to a commit with `rowsClamped`.
    pre_rows_clamped: bool,
    /// (source, sha256) of every accepted file that carried a hash (the
    /// Worker keeps them 72 h; landing-ledger.js tests the window).
    hashes: Vec<(Uuid, String)>,
}

/// The tenant landing-ledger DO as TZ-FRONT CONTRACT.md B1-B3 describes
/// it: every `lease` fences older epochs; `next` hands out landed files
/// and files leased by a fenced epoch, counting an attempt; commits under
/// a stale epoch, or for a file the epoch does not lease, are `fenced`; a
/// `retry` lands the file again, and past five attempts refuses it
/// (`attempts_exhausted`).
#[derive(Default)]
struct FakeLedger(Mutex<LedgerState>);

impl FakeLedger {
    fn land_as(&self, key: &str, bytes: u64, source_id: Uuid) -> u64 {
        let mut state = self.0.lock().unwrap();
        let seq = state.files.len() as u64 + 1;
        state.files.push(FakeFile {
            file: LedgerFile {
                key: key.into(),
                seq,
                source_id,
                bytes,
                etag: Some(format!("etag-{seq}")),
                attempt: 0,
                landed_at: Some(chrono::Utc::now().timestamp_millis()),
                source_slug: Some("tenzir-sysmon".into()),
                credential_id: Some(Uuid::parse_str(CREDENTIAL).unwrap()),
            },
            state: "landed",
            reason: None,
            leased_by: 0,
        });
        seq
    }

    fn land(&self, key: &str, bytes: u64) -> u64 {
        self.land_as(key, bytes, Uuid::parse_str(SOURCE).unwrap())
    }

    fn set_attempt(&self, seq: u64, attempt: i32) {
        self.0.lock().unwrap().files.iter_mut().find(|f| f.file.seq == seq).unwrap().file.attempt = attempt;
    }

    fn file(&self, seq: u64) -> FakeFile {
        self.0.lock().unwrap().files.iter().find(|f| f.file.seq == seq).unwrap().clone()
    }

    /// Does the current epoch `epoch` lease `key`? (The produce route's check.)
    fn leases(&self, epoch: u64, key: &str) -> bool {
        let state = self.0.lock().unwrap();
        epoch == state.epoch && state.files.iter().any(|f| f.file.key == key && f.state == "leased" && f.leased_by == epoch)
    }
}

#[async_trait::async_trait]
impl LandingLedgerTransport for FakeLedger {
    async fn lease(&self, consumer_id: &str) -> Result<u64> {
        ensure!(!consumer_id.is_empty() && consumer_id.len() <= 128, "bad consumerId");
        let mut state = self.0.lock().unwrap();
        state.epoch += 1;
        Ok(state.epoch)
    }

    async fn next(&self, epoch: u64, max: usize) -> Result<NextOutcome> {
        ensure!((1..=16).contains(&max), "max out of range");
        let mut state = self.0.lock().unwrap();
        if epoch != state.epoch {
            return Ok(NextOutcome::Fenced);
        }
        let mut out = Vec::new();
        for f in state.files.iter_mut().filter(|f| f.state == "landed" || (f.state == "leased" && f.leased_by < epoch)).take(max) {
            f.state = "leased";
            f.leased_by = epoch;
            f.file.attempt += 1;
            out.push(f.file.clone());
        }
        Ok(NextOutcome::Files(out))
    }

    async fn commit(&self, commit: &LedgerCommit) -> Result<LedgerCommitOutcome> {
        let mut state = self.0.lock().unwrap();
        if std::mem::take(&mut state.fail_next_commit) {
            bail!("connection reset before the commit reached the ledger");
        }
        ensure!(commit.outcome != "refused" || commit.reason.is_some(), "400: refused needs a reason");
        if state.pre_row_accounting && (commit.has_row_accounting() || commit.content_sha256.is_some()) {
            return Ok(LedgerCommitOutcome::Invalid);
        }
        if (state.pre_rows_clamped || state.pre_content_hash || state.pre_row_accounting) && commit.rows_clamped.is_some() {
            return Ok(LedgerCommitOutcome::Invalid);
        }
        if state.pre_content_hash && commit.content_sha256.is_some() {
            return Ok(LedgerCommitOutcome::Invalid);
        }
        if commit.epoch != state.epoch {
            return Ok(LedgerCommitOutcome::Fenced);
        }
        state.commits.push(commit.clone());
        let epoch = state.epoch;
        let LedgerState { files, hashes, .. } = &mut *state;
        let Some(f) = files.iter_mut().find(|f| f.file.key == commit.key) else { return Ok(LedgerCommitOutcome::Unknown) };
        if matches!(f.state, "accepted" | "refused" | "duplicate") {
            let same = f.state == commit.outcome || (f.state == "duplicate" && commit.outcome == "accepted");
            return Ok(if same { LedgerCommitOutcome::Replayed } else { LedgerCommitOutcome::Conflict });
        }
        if f.state != "leased" || f.leased_by != epoch {
            return Ok(LedgerCommitOutcome::Fenced);
        }
        match commit.outcome {
            "accepted" => match &commit.content_sha256 {
                Some(sha) if hashes.contains(&(f.file.source_id, sha.clone())) => f.state = "duplicate",
                Some(sha) => {
                    hashes.push((f.file.source_id, sha.clone()));
                    f.state = "accepted";
                }
                None => f.state = "accepted",
            },
            "refused" => {
                f.state = "refused";
                f.reason = commit.reason.map(str::to_string);
            }
            "retry" if f.file.attempt >= 5 => {
                f.state = "refused";
                f.reason = Some("attempts_exhausted".into());
            }
            "retry" => f.state = "landed",
            other => bail!("400: unknown outcome {other}"),
        }
        Ok(LedgerCommitOutcome::Committed { state: Some(f.state.to_string()) })
    }
}

/// The edge-log produce route for one tenant: it refuses keys that are not
/// its tenant's, and (with a ledger) a produce whose epoch does not lease
/// the named landed file.
struct FakeProducer {
    tenant: String,
    ledger: Option<Arc<FakeLedger>>,
    segments: Mutex<Vec<(String, Vec<u8>)>>,
    busy: Mutex<u32>,
}

impl FakeProducer {
    fn new(tenant: &str, ledger: Option<Arc<FakeLedger>>) -> Self {
        Self { tenant: tenant.into(), ledger, segments: Mutex::default(), busy: Mutex::new(0) }
    }
    fn segments(&self) -> Vec<(String, Vec<u8>)> {
        self.segments.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl EdgeLogProducer for FakeProducer {
    fn tenant_id(&self) -> &str {
        &self.tenant
    }

    async fn produce(&self, produce: Produce<'_>) -> Result<AppendOutcome> {
        if !is_edge_segment_key(&self.tenant, produce.segment_key) || !own_landing_key(&self.tenant, produce.landing_key) {
            bail!("edge log produce refused with HTTP 403");
        }
        ensure!(sha256_hex(produce.bytes) == produce.sha256 && produce.bytes.len() <= MAX_SEGMENT_BYTES, "400: invalid segment");
        if let Some(ledger) = &self.ledger {
            if !ledger.leases(produce.epoch, produce.landing_key) {
                return Ok(AppendOutcome::Fenced);
            }
        }
        {
            let mut busy = self.busy.lock().unwrap();
            if *busy > 0 {
                *busy -= 1;
                return Ok(AppendOutcome::Busy);
            }
        }
        let mut segments = self.segments.lock().unwrap();
        if let Some(seq) = segments.iter().position(|(k, _)| k == produce.segment_key) {
            return Ok(if segments[seq].1 == produce.bytes {
                AppendOutcome::Replayed { seq: seq as u64 + 1 }
            } else {
                AppendOutcome::Conflict
            });
        }
        segments.push((produce.segment_key.into(), produce.bytes.to_vec()));
        Ok(AppendOutcome::Appended { seq: segments.len() as u64 })
    }
}

struct Hosted {
    store: Operator,
    ledger: Arc<FakeLedger>,
    producer: Arc<FakeProducer>,
    counters: Arc<LandingCounters>,
    discover: LeaseDiscover<FakeLedger>,
    emit: EdgeAppend<FakeProducer>,
    stage: LandingOcsfStage,
}

impl Hosted {
    fn new() -> Self {
        let ledger = Arc::new(FakeLedger::default());
        let producer = Arc::new(FakeProducer::new(TENANT, Some(ledger.clone())));
        Self::with(memory(), ledger, producer, "cell-a:1")
    }

    /// A landing[T] process over shared Worker state (a restart is a new one).
    fn with(store: Operator, ledger: Arc<FakeLedger>, producer: Arc<FakeProducer>, consumer: &str) -> Self {
        let counters = Arc::new(LandingCounters::default());
        Self {
            store,
            discover: LeaseDiscover::new(ledger.clone(), TENANT, consumer, counters.clone()),
            emit: EdgeAppend::new(producer.clone(), counters.clone()).with_limits(MAX_SEGMENT_BYTES, Duration::ZERO),
            ledger,
            producer,
            counters,
            stage: stage(),
        }
    }

    async fn land(&self, key: &str, bytes: Vec<u8>) -> u64 {
        let size = bytes.len() as u64;
        self.store.write(key, bytes).await.unwrap();
        self.ledger.land(key, size)
    }

    async fn tick(&self) -> Result<TickReport> {
        Engine {
            store: &self.store,
            discover: &self.discover,
            emit: &self.emit,
            stage: &self.stage,
            tenant_id: TENANT,
            max_files_per_tick: MAX_LEASE_FILES,
        }
        .tick()
        .await
    }
}

// ------------------------------------------------------------------ open-core parity

#[derive(Default)]
struct NullLedger(Mutex<Vec<(i64, String)>>);

#[async_trait::async_trait]
impl Ledger for NullLedger {
    async fn source(&self, _source_id: Uuid) -> Result<Option<LandingSource>> {
        Ok(Some(source()))
    }
    async fn claim(&self, _key: &str, _etag: &str, _size: u64, _source_id: Option<Uuid>) -> Result<crate::landing::Claim> {
        Ok(crate::landing::Claim::Owned { id: 1, attempt: 1 })
    }
    async fn accepted(&self, id: i64, _converted: &Converted, bronze_keys: &str) -> Result<()> {
        self.0.lock().unwrap().push((id, bronze_keys.to_string()));
        Ok(())
    }
    async fn refused(&self, _id: i64, _reason: &str, _rows: u64, _sha: Option<&str>) -> Result<()> {
        Ok(())
    }
    async fn redelivered(&self, _id: i64) -> Result<()> {
        Ok(())
    }
}

/// Open core after the refactor writes what `convert_file` makes (one
/// `bronze-v2/` object per shard: the same rows, the same contract; only
/// the stage's wall-clock stamps differ between two conversions), records
/// the keys it wrote, and deletes the landed object; hosted appends the
/// same bronze as one edge segment when the object fits.
#[tokio::test]
async fn open_core_parity_and_hosted_append_the_same_bronze_bytes() {
    let file = parquet(&[sysmon(Some("sysmon:wks-01:5"), 5), sysmon(None, 6)]);
    let expected = convert_file(&file, crate::landing::FileFormat::Parquet, &stage(), TENANT, &source(), chrono::Utc::now()).unwrap();
    assert_eq!(expected.objects.len(), 1);

    let store = memory();
    store.write(&key(TENANT, "a.parquet"), file.clone()).await.unwrap();
    let converter = Converter { store: store.clone(), ledger: NullLedger::default(), stage: stage(), tenant_id: TENANT.into(), max_files_per_tick: 10, emit: BronzeObjects };
    let report = converter.tick().await.unwrap();
    assert_eq!(report, TickReport { listed: 1, accepted: 1, ..Default::default() });
    let bronze = keys_under(&store, BRONZE_PREFIX).await;
    assert_eq!(bronze.len(), 1);
    assert!(bronze[0].starts_with(&format!("{BRONZE_PREFIX}tenant_id={TENANT}/")), "{bronze:?}");
    let written = store.read(&bronze[0]).await.unwrap().to_vec();
    assert_eq!(stable_events(&written), stable_events(&expected.objects[0].1), "open core bronze unchanged");
    assert_eq!(converter.ledger.0.lock().unwrap().clone(), vec![(1, bronze[0].clone())]);
    assert!(keys_under(&store, LANDING_PREFIX).await.is_empty());

    // The same engine, hosted halves: identical bronze bytes, one segment.
    let hosted = Hosted::new();
    hosted.land(&key(TENANT, "a.parquet"), file).await;
    let report = hosted.tick().await.unwrap();
    assert_eq!((report.listed, report.accepted), (1, 1), "{report:?}");
    let segments = hosted.producer.segments();
    assert_eq!(segments.len(), 1);
    assert_eq!(stable_events(&segments[0].1), stable_events(&written), "hosted appends the open-core bronze rows");
    assert_eq!(parquet_schema(&segments[0].1), parquet_schema(&written), "same bronze row contract");
    assert!(is_edge_segment_key(TENANT, &segments[0].0) && segments[0].0.contains("/shard=0/"), "{}", segments[0].0);
    // The engine borrowed for open core also accepts the open-core halves directly.
    let _ = Engine { store: &store, discover: &PrefixDiscover { ledger: &NullLedger::default() }, emit: &BronzeObjects,
        stage: &stage(), tenant_id: TENANT, max_files_per_tick: 1 };
}

#[test]
fn encode_bronze_batch_is_encode_bronze() {
    let file = ndjson(&[sysmon(Some("u1"), 1), sysmon(Some("u2"), 2)]);
    let converted = convert_file(&file, crate::landing::FileFormat::Ndjson { gzip: false }, &stage(), TENANT, &source(), chrono::Utc::now()).unwrap();
    let body = &converted.objects[0].1;
    // Re-encoding the decoded batch reproduces the object.
    let split = split_segments(body, 2, usize::MAX).unwrap();
    assert_eq!(split, vec![(body.clone(), 2)]);
    let reader = ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(body)).unwrap().build().unwrap();
    let batch = reader.map(Result::unwrap).next().unwrap();
    assert_eq!(&encode_bronze_batch(&batch).unwrap(), body);
}

// ------------------------------------------------------------------ hosted happy path + counters

#[tokio::test]
async fn hosted_converts_commits_then_deletes_and_counts() {
    let hosted = Hosted::new();
    let seq = hosted.land(&key(TENANT, "x/good.ndjson"), ndjson(&[sysmon(Some("a"), 1), json!({"class_uid": "nope"})])).await;
    let report = hosted.tick().await.unwrap();
    assert_eq!((report.listed, report.accepted, report.failed), (1, 1, 0), "{report:?}");
    assert_eq!(hosted.ledger.file(seq).state, "accepted");
    let commit = hosted.ledger.0.lock().unwrap().commits.last().cloned().unwrap();
    assert_eq!(commit, LedgerCommit { epoch: 1, key: key(TENANT, "x/good.ndjson"), outcome: "accepted", rows: Some(1), reason: None,
        rows_refused: Some(1), row_reason: Some("raw_data_missing"), detail: Some("field=raw_data".into()),
        content_sha256: Some(sha256_hex(&ndjson(&[sysmon(Some("a"), 1), json!({"class_uid": "nope"})]))), rows_clamped: None });
    assert!(keys_under(&hosted.store, LANDING_PREFIX).await.is_empty(), "deleted after the commit");
    // The ledger's source slug becomes the route key (`-` → `_`).
    let segment = &hosted.producer.segments()[0].1;
    assert_eq!(stable_events(segment)[0]["metadata"]["log_source"], json!("tenzir_sysmon"), "{:?}", stable_events(segment)[0]["metadata"]);
    let status = hosted.counters.status();
    assert_eq!((status.files_accepted, status.rows_accepted, status.rows_refused, status.segments_appended), (1, 1, 1, 1));
    assert_eq!(status.sources[SOURCE].files_accepted, 1);
    assert_eq!(hosted.discover.outstanding(), 0);
    // Nothing left: an empty tick.
    assert_eq!(hosted.tick().await.unwrap(), TickReport::default());
}

#[test]
fn ledger_files_without_a_slug_or_credential_fall_back() {
    let file: LedgerFile = serde_json::from_value(json!({"key": "k", "seq": 1, "sourceId": SOURCE, "bytes": 3, "etag": "e",
        "attempt": 1, "landedAt": 1_791_975_595_105_i64})).unwrap();
    let source = file.landing_source();
    assert_eq!((source.route_key.as_str(), source.credential_id, source.active), (FALLBACK_ROUTE_KEY, Uuid::nil(), true));
    let bad: LedgerFile = serde_json::from_value(json!({"key": "k", "seq": 1, "sourceId": SOURCE, "bytes": 3,
        "attempt": 1, "sourceSlug": "Bad Slug!"})).unwrap();
    assert_eq!(bad.landing_source().route_key, FALLBACK_ROUTE_KEY);
}

// ------------------------------------------------------------------ segment keys

#[test]
fn segment_keys_are_deterministic_v4_and_inside_the_worker_window() {
    let now = chrono::Utc::now();
    let landed = now.timestamp_millis() - 90_000;
    let a = segment_key(TENANT, &"ab".repeat(32), 0, Some(landed), now);
    assert_eq!(a, segment_key(TENANT, &"ab".repeat(32), 0, Some(landed), now), "same file, same index, same key");
    assert_ne!(a, segment_key(TENANT, &"ab".repeat(32), 1, Some(landed), now));
    assert_ne!(a, segment_key(TENANT, &"cd".repeat(32), 0, Some(landed), now));
    assert!(is_edge_segment_key(TENANT, &a), "{a}");
    let file = a.rsplit('/').next().unwrap().strip_suffix(".parquet").unwrap();
    let (secs, uuid) = file.split_once('-').unwrap();
    assert_eq!(secs, format!("{:010}", landed.div_euclid(1000)));
    let uuid = Uuid::parse_str(uuid).unwrap();
    assert_eq!((uuid.get_version_num(), uuid.get_variant()), (4, uuid::Variant::RFC4122));
    // A landed time outside now-7d..now+5min (or unknown) uses now.
    for landed in [None, Some(now.timestamp_millis() - 8 * 86_400_000), Some(now.timestamp_millis() + 3_600_000)] {
        let key = segment_key(TENANT, &"ab".repeat(32), 0, landed, now);
        assert!(key.contains(&format!("/{:010}-", now.timestamp())), "{key}");
    }
}

// ------------------------------------------------------------------ fencing

#[tokio::test]
async fn a_stale_epoch_is_refused_and_never_commits() {
    let ledger = Arc::new(FakeLedger::default());
    let producer = Arc::new(FakeProducer::new(TENANT, Some(ledger.clone())));
    let store = memory();
    let old = Hosted::with(store.clone(), ledger.clone(), producer.clone(), "pod-a:1");
    let seq = old.land(&key(TENANT, "a.ndjson"), ndjson(&[sysmon(Some("f1"), 1)])).await;
    assert_eq!(old.discover.epoch().await.unwrap(), 1);

    // A newer landing[T] takes the lease: the old one is fenced at once.
    let new = Hosted::with(store.clone(), ledger.clone(), producer.clone(), "pod-b:1");
    assert_eq!(new.discover.epoch().await.unwrap(), 2);
    let error = old.tick().await.unwrap_err();
    assert!(error.downcast_ref::<LedgerFenced>().is_some(), "{error:#}");
    assert_eq!(ledger.file(seq).state, "landed", "the fenced converter leased nothing");

    // Fenced mid-file: the old one leased and converted, then a newer lease
    // landed before its produce. The produce and the commit are refused;
    // the newer converter finishes the file.
    let ledger = Arc::new(FakeLedger::default());
    let producer = Arc::new(FakeProducer::new(TENANT, Some(ledger.clone())));
    let old = Hosted::with(memory(), ledger.clone(), producer.clone(), "pod-a:1");
    old.land(&key(TENANT, "b.ndjson"), ndjson(&[sysmon(Some("f2"), 2)])).await;
    let (_, candidates) = old.discover.discover(&old.store, TENANT, 10).await.unwrap();
    let candidate = candidates.into_iter().next().unwrap();
    assert_eq!(candidate.leased.as_ref().unwrap().epoch, 1);
    let new = Hosted::with(old.store.clone(), ledger.clone(), producer.clone(), "pod-b:1");
    new.discover.epoch().await.unwrap();
    let converted = convert_file(&old.store.read(&candidate.key).await.unwrap().to_vec(),
        crate::landing::FileFormat::Ndjson { gzip: false }, &stage(), TENANT, &source(), chrono::Utc::now()).unwrap();
    let error = old.emit.emit(&old.store, TENANT, &candidate, &converted).await.unwrap_err();
    assert!(error.downcast_ref::<LedgerFenced>().is_some(), "{error:#}");
    assert!(producer.segments().is_empty(), "a fenced epoch produces nothing");
    let error = old.discover.finish_accepted(&old.store, &candidate, 1, &converted, "").await.unwrap_err();
    assert!(error.downcast_ref::<LedgerFenced>().is_some(), "{error:#}");
    assert_eq!(ledger.0.lock().unwrap().commits.len(), 0, "no commit under the stale epoch");
    assert!(old.store.exists(&candidate.key).await.unwrap(), "a fenced converter never deletes");
    // The newer lease takes over the file the fenced epoch held.
    assert_eq!(new.tick().await.unwrap().accepted, 1);
    assert_eq!((ledger.file(1).state, ledger.file(1).file.attempt), ("accepted", 2));
}

// ------------------------------------------------------------------ crash between produce and commit

#[tokio::test]
async fn a_crash_between_append_and_commit_reconverts_with_the_same_uids() {
    let ledger = Arc::new(FakeLedger::default());
    let producer = Arc::new(FakeProducer::new(TENANT, Some(ledger.clone())));
    let store = memory();
    let first = Hosted::with(store.clone(), ledger.clone(), producer.clone(), "pod-a:1");
    // One row with the sender's uid, one without (derived from the file).
    let seq = first.land(&key(TENANT, "c.ndjson"), ndjson(&[sysmon(Some("sender-uid"), 1), sysmon(None, 2)])).await;
    ledger.0.lock().unwrap().fail_next_commit = true;
    let report = first.tick().await.unwrap();
    assert_eq!((report.accepted, report.failed), (0, 1), "{report:?}");
    assert_eq!(producer.segments().len(), 1, "produced before the lost commit");
    assert!(store.exists(&key(TENANT, "c.ndjson")).await.unwrap(), "kept until the commit lands");
    drop(first); // the process dies here

    // The respawn leases a new epoch; `next` hands the fenced epoch's file out again.
    let second = Hosted::with(store.clone(), ledger.clone(), producer.clone(), "pod-a:2");
    let report = second.tick().await.unwrap();
    assert_eq!(report.accepted, 1, "{report:?}");
    assert_eq!((ledger.file(seq).state, ledger.file(seq).file.attempt), ("accepted", 2));
    // The deterministic key replays identical bytes; bytes that differ (the
    // stage's wall-clock stamps) go under a fresh key. Either way ingest[T]'s
    // uid window sees the same uids.
    let segments = producer.segments();
    assert!(matches!(segments.len(), 1 | 2), "{}", segments.len());
    for segment in &segments {
        let uids = uids_of(std::slice::from_ref(segment));
        assert_eq!(uids.len(), 2);
        assert!(uids.contains(&"sender-uid".to_string()));
        assert_eq!(uids, uids_of(&segments[..1]));
    }
    assert!(keys_under(&store, LANDING_PREFIX).await.is_empty());
}

#[tokio::test]
async fn a_lost_commit_is_retried_locally_without_spending_an_attempt() {
    let hosted = Hosted::new();
    let seq = hosted.land(&key(TENANT, "d.ndjson"), ndjson(&[sysmon(Some("d"), 1)])).await;
    hosted.ledger.0.lock().unwrap().fail_next_commit = true;
    assert_eq!(hosted.tick().await.unwrap().failed, 1);
    assert_eq!(hosted.discover.outstanding(), 1, "still leased by this epoch");
    let report = hosted.tick().await.unwrap();
    assert_eq!((report.listed, report.accepted), (1, 1), "{report:?}");
    assert_eq!((hosted.ledger.file(seq).state, hosted.ledger.file(seq).file.attempt), ("accepted", 1));
    assert_eq!(hosted.discover.outstanding(), 0);
}

#[tokio::test]
async fn a_reconversion_with_the_same_bytes_replays_its_segment() {
    let hosted = Hosted::new();
    hosted.land(&key(TENANT, "e.ndjson"), ndjson(&[sysmon(Some("e"), 1)])).await;
    let (_, candidates) = hosted.discover.discover(&hosted.store, TENANT, 1).await.unwrap();
    let converted = convert_file(&hosted.store.read(&candidates[0].key).await.unwrap().to_vec(),
        crate::landing::FileFormat::Ndjson { gzip: false }, &stage(), TENANT, &source(), chrono::Utc::now()).unwrap();
    let first = hosted.emit.emit(&hosted.store, TENANT, &candidates[0], &converted).await.unwrap();
    let again = hosted.emit.emit(&hosted.store, TENANT, &candidates[0], &converted).await.unwrap();
    assert_eq!(first, again, "the same segment seq");
    assert_eq!(hosted.producer.segments().len(), 1);
}

// ------------------------------------------------------------------ refusals

#[tokio::test]
async fn bad_files_are_refused_whole_moved_aside_and_committed_without_wedging() {
    let hosted = Hosted::new();
    let bad = hosted.land(&key(TENANT, "bad.parquet"), b"not parquet".to_vec()).await;
    // Five attempts spent already: refused, whatever the content.
    let tired = hosted.land(&key(TENANT, "tired.ndjson"), ndjson(&[sysmon(Some("t"), 1)])).await;
    hosted.ledger.set_attempt(tired, 5);
    // The Worker's source differs from the folder's: never trusted.
    let other_source = hosted.ledger.land_as(&key(TENANT, "other.ndjson"), 10, Uuid::new_v4());
    hosted.store.write(&key(TENANT, "other.ndjson"), ndjson(&[sysmon(Some("o"), 1)])).await.unwrap();
    // Leased but already gone from the bucket (moved by a crashed attempt).
    let gone = hosted.ledger.land(&key(TENANT, "gone.parquet"), 10);
    hosted.ledger.set_attempt(gone, 5);

    let report = hosted.tick().await.unwrap();
    assert_eq!((report.listed, report.refused, report.failed), (4, 4, 0), "{report:?}");
    for (seq, reason) in [(bad, "parquet_unreadable"), (tired, "attempts_exhausted"), (other_source, "source_unknown"),
        (gone, "attempts_exhausted")]
    {
        let file = hosted.ledger.file(seq);
        assert_eq!((file.state, file.reason.as_deref()), ("refused", Some(reason)), "file {seq}");
    }
    assert!(keys_under(&hosted.store, LANDING_PREFIX).await.is_empty());
    let refused = keys_under(&hosted.store, REFUSED_PREFIX).await;
    assert_eq!(refused.len(), 3, "{refused:?}");
    assert!(refused.contains(&refused_key(&key(TENANT, "bad.parquet"))));
    assert!(hosted.producer.segments().is_empty());
    let status = hosted.counters.status();
    assert_eq!(status.files_refused, 4);
    assert_eq!(status.refused_by_reason["attempts_exhausted"], 2);
    // Reasons are value-free codes only (the ledger's `[a-z0-9_]{1,64}`).
    assert!(status.refused_by_reason.keys().all(|r| r.len() <= 64 && r.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')));
    assert_eq!(hosted.discover.outstanding(), 0);
}

/// A file that fails every time (here: the landed object cannot be read)
/// is handed back with `retry` after the local retries, spends its five
/// ledger attempts, and ends refused: it never wedges the converter.
#[tokio::test]
async fn a_persistently_failing_file_ends_refused_after_its_attempts() {
    let hosted = Hosted::new();
    let seq = hosted.ledger.land(&key(TENANT, "never-there.ndjson"), 10);
    let good = hosted.land(&key(TENANT, "fine.ndjson"), ndjson(&[sysmon(Some("fine"), 1)])).await;
    let mut ticks = 0;
    while hosted.ledger.file(seq).state != "refused" {
        hosted.tick().await.unwrap();
        ticks += 1;
        assert!(ticks <= 5 * LOCAL_RETRIES as usize + 1, "wedged");
    }
    assert_eq!(hosted.ledger.file(seq).reason.as_deref(), Some("attempts_exhausted"));
    assert_eq!(hosted.ledger.file(good).state, "accepted", "the bad file never blocked the good one");
    assert_eq!(hosted.discover.outstanding(), 0);
    assert_eq!(hosted.counters.status().refused_by_reason["attempts_exhausted"], 1);
}

#[tokio::test]
async fn a_full_edge_log_holds_the_file_without_spending_an_attempt() {
    let hosted = Hosted::new();
    let seq = hosted.land(&key(TENANT, "held.ndjson"), ndjson(&[sysmon(Some("h"), 1)])).await;
    *hosted.producer.busy.lock().unwrap() = BUSY_RETRIES + 1;
    let report = hosted.tick().await.unwrap();
    assert_eq!((report.held, report.accepted, report.refused), (1, 0, 0), "{report:?}");
    let file = hosted.ledger.file(seq);
    assert_eq!((file.state, file.file.attempt), ("leased", 1), "held under this epoch, no retry commit");
    assert!(hosted.store.exists(&key(TENANT, "held.ndjson")).await.unwrap());
    // Six more full rounds would exhaust attempts if holds counted; they do not.
    for _ in 0..6 {
        *hosted.producer.busy.lock().unwrap() = BUSY_RETRIES + 1;
        assert_eq!(hosted.tick().await.unwrap().held, 1);
    }
    assert_eq!(hosted.tick().await.unwrap().accepted, 1);
    assert_eq!((hosted.ledger.file(seq).state, hosted.ledger.file(seq).file.attempt), ("accepted", 1));
    assert_eq!(hosted.counters.status().files_held, 7);
    assert!(hosted.ledger.0.lock().unwrap().commits.iter().all(|c| c.outcome != "retry"));
}

#[test]
fn oversized_objects_split_into_segments_and_a_huge_row_refuses_the_file() {
    // Distinct command lines so slices do not compress below the cap.
    let events = (0..2000)
        .map(|i| {
            let mut event = sysmon(Some(&format!("u{i}")), i);
            event["process"]["cmd_line"] = json!(format!("cmd.exe /c {}", Uuid::new_v4()));
            event
        })
        .collect::<Vec<_>>();
    let converted = convert_file(&ndjson(&events), crate::landing::FileFormat::Ndjson { gzip: false }, &stage(), TENANT, &source(), chrono::Utc::now()).unwrap();
    let (_, body, rows) = &converted.objects[0];
    let max = body.len() / 3;
    let segments = split_segments(body, *rows, max).unwrap();
    assert!(segments.len() >= 3, "{}", segments.len());
    assert!(segments.iter().all(|(bytes, _)| bytes.len() <= max));
    assert_eq!(segments.iter().map(|(_, rows)| rows).sum::<u64>(), 2000);
    let uids = uids_of(&segments.iter().map(|(b, _)| (String::new(), b.clone())).collect::<Vec<_>>());
    assert_eq!(uids.len(), 2000);
    let error = split_segments(body, *rows, 10).unwrap_err();
    assert_eq!(error.downcast_ref::<FileRefusal>().map(|r| r.reason), Some("segment_too_large"));
}

// ------------------------------------------------------------------ isolation

/// A ledger that leases a key outside the tenant's landing folder (a bug
/// or a hostile Worker state) never makes the converter read, copy or
/// delete it: `lake/parts` and other tenants' landed files are untouched.
#[tokio::test]
async fn the_converter_never_touches_lake_parts_or_another_tenants_files() {
    let hosted = Hosted::new();
    let part = format!("lake/parts/v1/tenant={TENANT}/p.parquet");
    hosted.store.write(&part, b"PART".to_vec()).await.unwrap();
    let parts_seq = hosted.ledger.land(&part, 4);
    let foreign = key(OTHER_TENANT, "f.ndjson");
    hosted.store.write(&foreign, ndjson(&[sysmon(Some("x"), 1)])).await.unwrap();
    let foreign_seq = hosted.ledger.land(&foreign, 10);

    let report = hosted.tick().await.unwrap();
    assert_eq!(report.refused, 2, "{report:?}");
    assert_eq!(hosted.ledger.file(parts_seq).reason.as_deref(), Some("key_outside_landing"));
    assert_eq!(hosted.ledger.file(foreign_seq).reason.as_deref(), Some("tenant_mismatch"));
    assert_eq!(hosted.store.read(&part).await.unwrap().to_vec(), b"PART");
    assert!(hosted.store.exists(&foreign).await.unwrap());
    assert!(keys_under(&hosted.store, REFUSED_PREFIX).await.is_empty(), "nothing outside the folder is copied");
    assert!(hosted.producer.segments().is_empty());
}

#[tokio::test]
async fn cross_tenant_appends_are_refused() {
    let now = chrono::Utc::now();
    let sha = "ab".repeat(32);
    // The key check every produce passes, client side.
    let mine = segment_key(TENANT, &sha, 0, None, now);
    let landed = key(TENANT, "a.ndjson");
    assert!(check_append_key(TENANT, &mine, &landed).is_ok());
    for (segment, landing) in [
        (segment_key(OTHER_TENANT, &sha, 0, None, now), landed.clone()),
        (format!("lake/parts/v1/tenant={TENANT}/x"), landed.clone()),
        (format!("bronze-v2/shard=0/tenant_id={TENANT}/../x"), landed.clone()),
        (format!("bronze-v2/shard=0/tenant_id={TENANT}/a\nb"), landed.clone()),
        (mine.clone(), key(OTHER_TENANT, "a.ndjson")),
        (mine.clone(), format!("lake/parts/v1/tenant={TENANT}/p.parquet")),
        (mine.clone(), format!("{LANDING_PREFIX}tenant_id={TENANT}/../x")),
    ] {
        let error = check_append_key(TENANT, &segment, &landing).unwrap_err();
        assert!(error.downcast_ref::<CrossTenantAppend>().is_some(), "{segment} {landing}");
    }
    // A producer bound to another tenant is never used for this one.
    let counters = Arc::new(LandingCounters::default());
    let emit = EdgeAppend::new(Arc::new(FakeProducer::new(OTHER_TENANT, None)), counters);
    let converted = convert_file(&ndjson(&[sysmon(Some("a"), 1)]), crate::landing::FileFormat::Ndjson { gzip: false },
        &stage(), TENANT, &source(), chrono::Utc::now()).unwrap();
    let candidate = Candidate { key: landed.clone(), etag: None, size: 1,
        leased: Some(LeasedFile { id: 1, attempt: 1, epoch: 1, landed_at_ms: None, source: Some(source()) }) };
    let error = emit.emit(&memory(), TENANT, &candidate, &converted).await.unwrap_err();
    assert!(error.downcast_ref::<CrossTenantAppend>().is_some(), "{error:#}");
    assert!(emit.producer().segments().is_empty());
    // The HTTP producer refuses before any request leaves (nothing listens).
    let http = HttpEdgeLogProducer::new("http://127.0.0.1:9", TENANT, Zeroizing::new(TOKEN.into())).unwrap();
    let foreign = segment_key(OTHER_TENANT, &sha, 0, None, now);
    let produce = Produce { epoch: 1, landing_key: &landed, segment_key: &foreign, sha256: &sha256_hex(b"x"), bytes: b"x" };
    let error = http.produce(produce).await.unwrap_err();
    assert!(error.downcast_ref::<CrossTenantAppend>().is_some(), "{error:#}");
    // And the Worker side (the fake mirrors its key checks) refuses too.
    assert!(FakeProducer::new(TENANT, None).produce(produce).await.is_err());
}

// ------------------------------------------------------------------ HTTP wire

const TOKEN: &str = "lnd_0123456789abcdefghijklmnopqrstuvwxyz";

/// The clients against TZ-FRONT CONTRACT.md §B: routes, bodies, headers and
/// status mapping.
#[tokio::test]
async fn http_clients_speak_the_worker_contract() {
    use axum::{body::Bytes as AxumBytes, extract::State, http::{HeaderMap, StatusCode}, routing::post, Router};
    #[derive(Clone, Default)]
    struct App(Arc<Mutex<Vec<(String, Value, HeaderMap, usize)>>>);
    async fn handle(action: &'static str, State(app): State<App>, headers: HeaderMap, body: AxumBytes) -> (StatusCode, Vec<u8>) {
        let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        app.0.lock().unwrap().push((action.into(), value.clone(), headers.clone(), body.len()));
        if auth != format!("Bearer {TOKEN}") {
            return (StatusCode::UNAUTHORIZED, b"no".to_vec());
        }
        let segment = headers.get("x-nano-edge-segment-key").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        match action {
            "lease" => (StatusCode::OK, br#"{"kind":"ok","epoch":4,"pendingFiles":1,"backlogBytes":12,"uploadBytes":0,"oldestPendingAgeMs":null}"#.to_vec()),
            "next" if value["epoch"] == 3 => (StatusCode::CONFLICT, br#"{"kind":"fenced"}"#.to_vec()),
            "next" if value["epoch"] == 5 => (StatusCode::SERVICE_UNAVAILABLE, br#"{"kind":"busy"}"#.to_vec()),
            "next" => (StatusCode::OK, serde_json::to_vec(&json!({"kind": "ok", "epoch": 4, "files": [{
                "key": "landing-ocsf-v1/tenant_id=t/source=s/a.parquet", "seq": 9, "sourceId": SOURCE, "bytes": 12,
                "etag": "e", "attempt": 1, "landedAt": 1_791_975_595_105_i64}]})).unwrap()),
            "commit" if value["epoch"] == 3 => (StatusCode::CONFLICT, br#"{"kind":"fenced"}"#.to_vec()),
            "commit" if value["key"] == "decided" => (StatusCode::CONFLICT, br#"{"kind":"conflict"}"#.to_vec()),
            "commit" if value["key"] == "unknown" => (StatusCode::NOT_FOUND, br#"{"kind":"not_found"}"#.to_vec()),
            "commit" if value["key"] == "old-worker" => (StatusCode::BAD_REQUEST, br#"{"error":"invalid control body"}"#.to_vec()),
            "commit" if value["key"] == "again" => (StatusCode::OK, br#"{"kind":"replay"}"#.to_vec()),
            "commit" if value["outcome"] == "retry" => (StatusCode::OK, br#"{"kind":"ok","state":"refused","reason":"attempts_exhausted"}"#.to_vec()),
            "commit" => (StatusCode::OK, br#"{"kind":"ok","state":"refused"}"#.to_vec()),
            "produce" if headers.get("x-nano-landing-epoch").unwrap() == "3" => (StatusCode::CONFLICT, br#"{"kind":"fenced"}"#.to_vec()),
            "produce" if segment.ends_with("busy.parquet") => (StatusCode::SERVICE_UNAVAILABLE, br#"{"kind":"busy"}"#.to_vec()),
            "produce" if segment.contains("conflict") => (StatusCode::PRECONDITION_FAILED, br#"{"kind":"conflict"}"#.to_vec()),
            "produce" => (StatusCode::OK, br#"{"kind":"appended","seq":17}"#.to_vec()),
            _ => (StatusCode::NOT_FOUND, Vec::new()),
        }
    }
    let app = App::default();
    let router = Router::new()
        .route("/landing-ledger/v1/lease", post(|s, h, b| handle("lease", s, h, b)))
        .route("/landing-ledger/v1/next", post(|s, h, b| handle("next", s, h, b)))
        .route("/landing-ledger/v1/commit", post(|s, h, b| handle("commit", s, h, b)))
        .route("/edge-log/v1/produce", post(|s, h, b| handle("produce", s, h, b)))
        .with_state(app.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let base = format!("http://127.0.0.1:{}", address.port());

    let ledger = HttpLandingLedger::new(&base, Zeroizing::new(TOKEN.into())).unwrap();
    assert_eq!(ledger.lease("cell-a:1").await.unwrap(), 4);
    assert_eq!(ledger.next(3, 500).await.unwrap(), NextOutcome::Fenced);
    assert_eq!(ledger.next(5, 1).await.unwrap(), NextOutcome::Busy);
    let NextOutcome::Files(files) = ledger.next(4, 500).await.unwrap() else { panic!() };
    assert_eq!((files[0].seq, files[0].attempt, files[0].bytes, files[0].landed_at), (9, 1, 12, Some(1_791_975_595_105)));
    let commit = |epoch, key: &str, outcome| LedgerCommit { epoch, key: key.into(), outcome, rows: Some(0),
        reason: (outcome == "refused").then_some("parquet_unreadable"), rows_refused: None, row_reason: None, detail: None,
        content_sha256: None, rows_clamped: None };
    assert_eq!(ledger.commit(&commit(3, "k", "refused")).await.unwrap(), LedgerCommitOutcome::Fenced);
    assert_eq!(ledger.commit(&commit(4, "decided", "accepted")).await.unwrap(), LedgerCommitOutcome::Conflict);
    assert_eq!(ledger.commit(&commit(4, "unknown", "accepted")).await.unwrap(), LedgerCommitOutcome::Unknown);
    assert_eq!(ledger.commit(&commit(4, "again", "accepted")).await.unwrap(), LedgerCommitOutcome::Replayed);
    assert_eq!(ledger.commit(&commit(4, "k", "refused")).await.unwrap(), LedgerCommitOutcome::Committed { state: Some("refused".into()) });
    let retry = LedgerCommit { epoch: 4, key: "k".into(), outcome: "retry", rows: None, reason: None, rows_refused: None,
        row_reason: None, detail: None, content_sha256: None, rows_clamped: None };
    assert_eq!(ledger.commit(&retry).await.unwrap(), LedgerCommitOutcome::Committed { state: Some("refused".into()) });
    // NAN-4321 keys go camelCase; a Worker from before them answers 400.
    let counted = LedgerCommit { epoch: 4, key: "old-worker".into(), outcome: "accepted", rows: Some(7), reason: None,
        rows_refused: Some(3), row_reason: Some("ocsf_attribute_unknown"), detail: Some("class_uid=4001 field=user".into()),
        content_sha256: Some("ab".repeat(32)), rows_clamped: None };
    assert_eq!(ledger.commit(&counted).await.unwrap(), LedgerCommitOutcome::Invalid);

    let producer = HttpEdgeLogProducer::new(&base, TENANT, Zeroizing::new(TOKEN.into())).unwrap();
    let landed = key(TENANT, "a.ndjson");
    let segment = segment_key(TENANT, &"ab".repeat(32), 0, None, chrono::Utc::now());
    let sha = sha256_hex(b"seg");
    let produce = |epoch, segment: &str| {
        let (landed, segment, sha) = (landed.clone(), segment.to_string(), sha.clone());
        let producer = &producer;
        async move {
            producer.produce(Produce { epoch, landing_key: &landed, segment_key: &segment, sha256: &sha, bytes: b"seg" }).await
        }
    };
    assert_eq!(produce(4, &segment).await.unwrap(), AppendOutcome::Appended { seq: 17 });
    assert_eq!(produce(3, &segment).await.unwrap(), AppendOutcome::Fenced);
    let named = |name: &str| format!("bronze-v2/shard=0/tenant_id={TENANT}/{name}");
    assert_eq!(produce(4, &named("1791975595-busy.parquet")).await.unwrap(), AppendOutcome::Busy);
    assert_eq!(produce(4, &named("1791975595-conflict.parquet")).await.unwrap(), AppendOutcome::Conflict);

    let calls = app.0.lock().unwrap().clone();
    let lease = calls.iter().find(|(a, _, _, _)| a == "lease").unwrap();
    assert_eq!(lease.1, json!({"consumerId": "cell-a:1"}));
    let next = calls.iter().find(|(a, v, _, _)| a == "next" && v["epoch"] == 4).unwrap();
    assert_eq!(next.1, json!({"epoch": 4, "max": MAX_LEASE_FILES}), "max is clamped to 1..16");
    // Commit bodies carry exactly the contract's keys.
    let refused = calls.iter().rev().find(|(a, v, _, _)| a == "commit" && v["outcome"] == "refused").unwrap();
    assert_eq!(refused.1, json!({"epoch": 4, "key": "k", "outcome": "refused", "rows": 0, "reason": "parquet_unreadable"}));
    let retried = calls.iter().find(|(a, v, _, _)| a == "commit" && v["outcome"] == "retry").unwrap();
    assert_eq!(retried.1, json!({"epoch": 4, "key": "k", "outcome": "retry"}));
    let counted = calls.iter().find(|(a, v, _, _)| a == "commit" && v["key"] == "old-worker").unwrap();
    assert_eq!(counted.1, json!({"epoch": 4, "key": "old-worker", "outcome": "accepted", "rows": 7, "rowsRefused": 3,
        "rowReason": "ocsf_attribute_unknown", "detail": "class_uid=4001 field=user", "contentSha256": "ab".repeat(32)}));
    let produced = calls.iter().find(|(a, _, _, _)| a == "produce").unwrap();
    let header = |name: &str| produced.2.get(name).unwrap().to_str().unwrap().to_string();
    assert_eq!(header("x-nano-landing-epoch"), "4");
    assert_eq!(header("x-nano-landing-key"), landed);
    assert_eq!(header("x-nano-edge-segment-key"), segment);
    assert_eq!(header("x-nano-content-sha256"), sha);
    assert_eq!((header("content-length"), produced.3), ("3".to_string(), 3));
    // Plain http is loopback only.
    assert!(HttpLandingLedger::new("http://example.com", Zeroizing::new(TOKEN.into())).is_err());
}

// ------------------------------------------------------------------ NAN-4321: row accounting

/// OCSF 1.9 Authentication (3002), as the hosted-Tenzir validation sent it.
fn auth(uid: &str) -> Value {
    json!({
        "class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201, "severity_id": 1,
        "time": 1_791_975_595_105_i64, "message": format!("auth {uid}"), "status_id": 1,
        "metadata": {"version": "1.9.0", "product": {"name": "fullval", "vendor_name": "Tenzir"}, "uid": uid},
        "user": {"name": "u1"}, "src_endpoint": {"ip": "10.66.0.1"}, "dst_endpoint": {"ip": "10.66.0.2"}
    })
}

/// OCSF 1.9 Network Activity (4001).
fn network(uid: &str) -> Value {
    json!({
        "class_uid": 4001, "category_uid": 4, "activity_id": 6, "type_uid": 400106, "severity_id": 1,
        "time": 1_791_975_595_105_i64, "message": format!("net {uid}"), "status_id": 1,
        "metadata": {"version": "1.9.0", "product": {"name": "fullval", "vendor_name": "Tenzir"}, "uid": uid},
        "src_endpoint": {"ip": "10.66.0.1", "port": 40000}, "dst_endpoint": {"ip": "10.66.0.2", "port": 443}
    })
}

/// OCSF 1.9 File System Activity (1001) with hashes.
fn file_activity(uid: &str, sha256: Value) -> Value {
    json!({
        "class_uid": 1001, "category_uid": 1, "activity_id": 1, "type_uid": 100101, "severity_id": 1,
        "time": 1_791_975_595_105_i64, "message": format!("file {uid}"),
        "metadata": {"version": "1.9.0", "product": {"name": "fullval", "vendor_name": "Tenzir"}, "uid": uid},
        "device": {"hostname": "fv-host", "type_id": 2},
        "actor": {"process": {"pid": 2000, "name": "explorer.exe"}},
        "file": {"name": "drop.exe", "type_id": 1, "hashes": [{"algorithm_id": 3, "value": sha256}]}
    })
}

fn class_uids(segments: &[(String, Vec<u8>)]) -> Vec<i64> {
    let mut classes = segments
        .iter()
        .flat_map(|(_, bytes)| stable_events(bytes))
        .map(|event| event["class_uid"].as_i64().unwrap())
        .collect::<Vec<_>>();
    classes.sort();
    classes
}

fn last_commit(hosted: &Hosted) -> LedgerCommit {
    hosted.ledger.0.lock().unwrap().commits.last().cloned().unwrap()
}

/// The validation's mixed-class file kept 10/20 rows and said nothing. Every
/// valid row of every class converts; the rows OCSF refuses (here 4001 rows
/// carrying `user`, which Network Activity does not define: why the
/// validation's 4001 rows vanished) are committed as `rowsRefused` with
/// their class and attribute path.
#[tokio::test]
async fn a_mixed_class_file_converts_every_class_and_counts_its_refused_rows() {
    let hosted = Hosted::new();
    let mut events = (0..4).map(|i| auth(&format!("a{i}"))).collect::<Vec<_>>();
    events.extend((0..3).map(|i| network(&format!("n{i}"))));
    events.extend((0..2).map(|i| {
        let mut event = network(&format!("bad{i}"));
        event["user"] = json!({"name": "u1"});
        event
    }));
    let seq = hosted.land(&key(TENANT, "mixed.parquet"), parquet(&events)).await;
    let report = hosted.tick().await.unwrap();
    assert_eq!((report.accepted, report.failed), (1, 0), "{report:?}");
    assert_eq!(hosted.ledger.file(seq).state, "accepted");
    assert_eq!(class_uids(&hosted.producer.segments()), vec![3002, 3002, 3002, 3002, 4001, 4001, 4001], "both classes kept");
    let commit = last_commit(&hosted);
    assert_eq!((commit.rows, commit.rows_refused, commit.row_reason), (Some(7), Some(2), Some("ocsf_attribute_unknown")));
    assert_eq!(commit.detail.as_deref(), Some("class_uid=4001 field=user"));
    let status = hosted.counters.status();
    assert_eq!((status.rows_accepted, status.rows_refused), (7, 2));
}

/// The validation's partly bad file (20 x 3002 + 5 x unknown class 99999)
/// kept 20/25 as a plain accept.
#[tokio::test]
async fn a_partly_bad_file_reports_its_refused_rows_with_the_class() {
    let hosted = Hosted::new();
    let mut events = (0..4).map(|i| auth(&format!("p{i}"))).collect::<Vec<_>>();
    events.extend((0..2).map(|i| {
        let mut event = auth(&format!("x{i}"));
        event["class_uid"] = json!(99999);
        event["type_uid"] = json!(9_999_901);
        event
    }));
    hosted.land(&key(TENANT, "partial.parquet"), parquet(&events)).await;
    hosted.tick().await.unwrap();
    let commit = last_commit(&hosted);
    assert_eq!((commit.outcome, commit.rows, commit.rows_refused), ("accepted", Some(4), Some(2)));
    assert_eq!(commit.row_reason, Some("ocsf_class_uid_unknown"));
    assert_eq!(commit.detail.as_deref(), Some("class_uid=99999 field=class_uid"));
}

/// The validation's 1001 file kept 94/100: upstream typed some hex hashes
/// as durations. The refused rows name the hash attribute.
#[tokio::test]
async fn mistyped_hashes_are_refused_rows_with_their_attribute_path() {
    let hosted = Hosted::new();
    let mut events = (0..3).map(|i| file_activity(&format!("f{i}"), json!(format!("{i:064x}")))).collect::<Vec<_>>();
    events.push(file_activity("f-dur", json!(86_400_000_000_000_i64)));
    hosted.land(&key(TENANT, "files.ndjson"), ndjson(&events)).await;
    hosted.tick().await.unwrap();
    let commit = last_commit(&hosted);
    assert_eq!((commit.outcome, commit.rows, commit.rows_refused), ("accepted", Some(3), Some(1)), "{commit:?}");
    assert_eq!(commit.row_reason, Some("ocsf_attribute_wrong_type"));
    let detail = commit.detail.unwrap();
    assert!(detail.starts_with("class_uid=1001 field=file.hashes"), "{detail}");
    assert!(detail.ends_with(".value") && !detail.contains("86400"), "a path, never the value: {detail}");
}

/// A file refused whole names its rows, the class and the attribute; a file
/// that is not OCSF at all says so instead of `raw_data_missing`.
#[tokio::test]
async fn whole_refusals_carry_rows_and_detail_and_non_ocsf_is_named() {
    let hosted = Hosted::new();
    let wrong = (0..3)
        .map(|i| {
            let mut event = network(&format!("w{i}"));
            event["dst_endpoint"]["port"] = json!("443");
            event
        })
        .collect::<Vec<_>>();
    let wtype = hosted.land(&key(TENANT, "wtype.parquet"), parquet(&wrong)).await;
    let plain = (0..5).map(|i| json!({"a": i, "b": format!("x{i}"), "c": [1, 2]})).collect::<Vec<_>>();
    let not_ocsf = hosted.land(&key(TENANT, "notocsf.parquet"), parquet(&plain)).await;
    let report = hosted.tick().await.unwrap();
    assert_eq!(report.refused, 2, "{report:?}");
    assert_eq!(hosted.ledger.file(wtype).reason.as_deref(), Some("ocsf_attribute_wrong_type"));
    assert_eq!(hosted.ledger.file(not_ocsf).reason.as_deref(), Some("not_ocsf"));
    let commits = hosted.ledger.0.lock().unwrap().commits.clone();
    let of = |name: &str| commits.iter().find(|c| c.key == key(TENANT, name)).cloned().unwrap();
    let wtype = of("wtype.parquet");
    assert_eq!((wtype.rows, wtype.rows_refused), (Some(0), Some(3)), "refused rows never count as accepted rows");
    assert_eq!(wtype.detail.as_deref(), Some("class_uid=4001 field=dst_endpoint.port"));
    let not_ocsf = of("notocsf.parquet");
    assert_eq!((not_ocsf.rows_refused, not_ocsf.detail), (Some(5), None));
    let status = hosted.counters.status();
    assert_eq!((status.refused_by_reason["not_ocsf"], status.rows_refused), (1, 8));
}

/// A Worker from before NAN-4321 answers 400 to the new keys: the decision
/// is committed again without them, never retried into `attempts_exhausted`.
#[tokio::test]
async fn an_older_worker_still_gets_every_decision() {
    let hosted = Hosted::new();
    hosted.ledger.0.lock().unwrap().pre_row_accounting = true;
    let accepted = hosted.land(&key(TENANT, "a.ndjson"), ndjson(&[auth("o1"), json!({"class_uid": 3002})])).await;
    let refused = hosted.land(&key(TENANT, "b.ndjson"), ndjson(&[json!({"a": 1})])).await;
    let report = hosted.tick().await.unwrap();
    assert_eq!((report.accepted, report.refused, report.failed), (1, 1, 0), "{report:?}");
    assert_eq!(hosted.ledger.file(accepted).state, "accepted");
    assert_eq!((hosted.ledger.file(refused).state, hosted.ledger.file(refused).reason.as_deref()), ("refused", Some("not_ocsf")));
    assert!(hosted.ledger.0.lock().unwrap().commits.iter().all(|c| !c.has_row_accounting()));
}

// ------------------------------------------------------------------ NAN-4325: duplicate files

/// The same bytes landed under two keys: both convert (their rows carry the
/// same uids, so ingest[T]'s uid window drops the repeat), both commit with
/// the same content hash, and the ledger decides the second to commit `duplicate`:
/// 1 accepted + 1 duplicate, the rows counted once.
#[tokio::test]
async fn the_same_file_under_two_keys_is_one_accepted_and_one_duplicate() {
    let hosted = Hosted::new();
    let bytes = ndjson(&[auth("d1"), auth("d2"), json!({"class_uid": 3002})]);
    let first = hosted.land(&key(TENANT, "first.ndjson"), bytes.clone()).await;
    let again = hosted.land(&key(TENANT, "again.ndjson"), bytes.clone()).await;
    let report = hosted.tick().await.unwrap();
    assert_eq!(report.failed, 0, "{report:?}");
    // NAN-4682: files of one tick are handled concurrently, so which of two
    // identical files commits first (and is `accepted`) is not defined; the
    // outcome is: exactly one accepted, one duplicate, rows counted once.
    let mut states = [hosted.ledger.file(first).state, hosted.ledger.file(again).state];
    states.sort();
    assert_eq!(states, ["accepted", "duplicate"]);
    let commits = hosted.ledger.0.lock().unwrap().commits.clone();
    let hashes = commits.iter().map(|c| c.content_sha256.clone()).collect::<Vec<_>>();
    assert_eq!(hashes, vec![Some(sha256_hex(&bytes)); 2], "both commits carry the landed bytes' sha256");
    let status = hosted.counters.status();
    assert_eq!((status.files_accepted, status.rows_accepted, status.rows_refused), (1, 2, 1), "rows are not double-counted");
    assert_eq!(status.sources[SOURCE].files_accepted, 1);
    // Both were emitted with identical uids: search keeps one copy. NAN-4682:
    // converted concurrently in the same millisecond, the two files are the
    // same bytes under the same deterministic segment key, and the edge log
    // replays the second instead of appending it (one segment).
    let segments = hosted.producer.segments();
    assert!(matches!(segments.len(), 1 | 2), "{}", segments.len());
    assert_eq!(uids_of(&segments[..1]), uids_of(&segments[segments.len() - 1..]));
    assert!(keys_under(&hosted.store, LANDING_PREFIX).await.is_empty(), "the duplicate's landed object is deleted too");
    assert_eq!(hosted.discover.outstanding(), 0);
}

/// Files one byte apart are different data: both accepted.
#[tokio::test]
async fn files_one_byte_apart_are_both_accepted() {
    let hosted = Hosted::new();
    let a = ndjson(&[auth("b1")]);
    // The same event one millisecond later: one digit of `time` differs.
    let at = a.windows(13).position(|w| w == b"1791975595105").unwrap() + 12;
    let mut b = a.clone();
    b[at] = b'6';
    assert_eq!(a.len(), b.len());
    assert_eq!(a.iter().zip(&b).filter(|(x, y)| x != y).count(), 1, "exactly one byte differs");
    let first = hosted.land(&key(TENANT, "a.ndjson"), a).await;
    let second = hosted.land(&key(TENANT, "b.ndjson"), b).await;
    hosted.tick().await.unwrap();
    assert_eq!((hosted.ledger.file(first).state, hosted.ledger.file(second).state), ("accepted", "accepted"));
    assert_eq!(hosted.counters.status().files_accepted, 2);
}

/// A Worker from before NAN-4325 (with NAN-4321) answers 400 to the hash:
/// the commit is retried without it and keeps its row accounting.
#[tokio::test]
async fn a_worker_without_duplicate_detection_still_accepts_with_row_accounting() {
    let hosted = Hosted::new();
    hosted.ledger.0.lock().unwrap().pre_content_hash = true;
    let bytes = ndjson(&[auth("w1"), json!({"class_uid": 3002})]);
    let first = hosted.land(&key(TENANT, "w1.ndjson"), bytes.clone()).await;
    let again = hosted.land(&key(TENANT, "w2.ndjson"), bytes).await;
    let report = hosted.tick().await.unwrap();
    assert_eq!((report.accepted, report.failed), (2, 0), "{report:?}");
    assert_eq!((hosted.ledger.file(first).state, hosted.ledger.file(again).state), ("accepted", "accepted"));
    let commits = hosted.ledger.0.lock().unwrap().commits.clone();
    assert!(commits.iter().all(|c| c.content_sha256.is_none() && c.rows_refused == Some(1)), "{commits:?}");
}

/// NAN-4336: a landed file whose rows run 14 h into the future is accepted
/// at once, each such row clamped to the conversion time, and the ledger is
/// told how many (`rowsClamped`); a Worker from before NAN-4336 answers 400
/// to the key and the commit goes again without it, keeping the rest.
#[tokio::test]
async fn future_dated_rows_are_clamped_and_counted_on_the_commit() {
    for old_worker in [false, true] {
        let hosted = Hosted::new();
        hosted.ledger.0.lock().unwrap().pre_rows_clamped = old_worker;
        let now = chrono::Utc::now().timestamp_millis();
        let mut future = auth("future");
        future["time"] = json!(now + 14 * 3_600_000);
        let mut present = auth("present");
        present["time"] = json!(now - 60_000);
        let seq = hosted.land(&key(TENANT, "skewed.ndjson"), ndjson(&[future, present])).await;
        let report = hosted.tick().await.unwrap();
        assert_eq!((report.accepted, report.failed), (1, 0), "{report:?}");
        assert_eq!(hosted.ledger.file(seq).state, "accepted");
        let commit = last_commit(&hosted);
        assert_eq!(commit.rows, Some(2));
        assert_eq!(commit.rows_clamped, (!old_worker).then_some(1), "{commit:?}");
        assert!(commit.content_sha256.is_some(), "the other keys survive the fallback");
    }
    // The clamped row itself: ingest time, original kept, marked.
    let mut future = auth("future");
    let original = chrono::Utc::now().timestamp_millis() + 14 * 3_600_000;
    future["time"] = json!(original);
    let at = chrono::Utc::now();
    let converted = convert_file(&ndjson(&[future]), crate::landing::FileFormat::Ndjson { gzip: false }, &stage(), TENANT,
        &source(), at).unwrap();
    assert_eq!(converted.rows_time_clamped, 1);
    let rows = converted.objects.iter().flat_map(|(_, body, _)| crate::landing::decode_bronze(body).unwrap()).map(Result::unwrap)
        .collect::<Vec<_>>();
    assert_eq!(crate::iceberg::ocsf_time_millis(rows[0].get("time")), Some(at.timestamp_millis()));
    let kept = chrono::DateTime::parse_from_rfc3339(rows[0]["metadata"]["original_time"].as_str().unwrap()).unwrap();
    assert_eq!(kept.timestamp_millis(), original);
    assert_eq!(rows[0]["metadata"]["labels"], json!([crate::bronze::TIME_CLAMPED_LABEL]));
}

// ------------------------------------------------------------------ NAN-4319 bounded memory + poison files

/// Rows of an encoded bronze object (its Parquet footer).
fn object_rows(body: &[u8]) -> u64 {
    ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(body)).unwrap().metadata().file_metadata().num_rows() as u64
}

/// A Tenzir-shaped file of `rows` rows through the production hosted path
/// (`Engine` over the lease ledger and edge-log producer): every row lands,
/// in segments no larger than one Vector bronze batch, and the tick's heap
/// peak stays under 64 MiB plus a few copies of the COMPRESSED file (the
/// landed bytes, their reader copy, the encoded segments and the fake
/// producer's copies): nothing grows with the decoded rows. Before NAN-4319
/// the whole file was decoded at once (50k rows: 371 MiB peak, one 50k-row
/// segment that then OOM-killed ingest[T]; 500k rows: 4.8 GB RSS).
async fn tenzir_file_converts_in_bounded_memory(rows: usize) {
    let file = crate::landing_fixture::tenzir_auth_parquet("bounded", rows, chrono::Utc::now().timestamp_millis() - 3_600_000);
    let bound = (64 << 20) + 4 * file.len() as isize;
    let hosted = Hosted::new();
    let seq = hosted.land(&key(TENANT, "tenzir/auth.parquet"), file).await;
    let peak = {
        let _serial = crate::test_heap::MEASUREMENT.lock().unwrap_or_else(|e| e.into_inner());
        crate::test_heap::track_current_thread(true);
        let base = crate::test_heap::reset_peak();
        let report = hosted.tick().await;
        let peak = crate::test_heap::peak() - base;
        crate::test_heap::track_current_thread(false);
        assert_eq!(report.unwrap().accepted, 1);
        peak
    };
    assert_eq!(hosted.ledger.file(seq).state, "accepted");
    let segments = hosted.producer.segments();
    let per_segment = segments.iter().map(|(_, body)| object_rows(body)).collect::<Vec<_>>();
    assert_eq!(per_segment.iter().sum::<u64>(), rows as u64, "every row lands");
    assert!(per_segment.iter().all(|n| *n <= crate::landing::MAX_OBJECT_ROWS as u64), "{per_segment:?}");
    assert_eq!(segments.len(), rows.div_ceil(crate::landing::MAX_OBJECT_ROWS));
    assert_eq!(hosted.counters.status().rows_accepted, rows as u64);
    assert!(peak < bound, "{rows} rows peaked at {} MiB (bound {} MiB)", peak >> 20, bound >> 20);
    eprintln!("NAN-4319: {rows} rows in {} segments, conversion tick heap peak {} MiB (bound {} MiB)", segments.len(), peak >> 20, bound >> 20);
}

#[tokio::test(flavor = "current_thread")]
async fn nan4319_a_50k_row_tenzir_file_converts_in_bounded_memory() {
    tenzir_file_converts_in_bounded_memory(50_000).await;
}

/// The same bound at 10x the rows (slow in a debug build: ~3 min; run with
/// `--ignored`, or in release).
#[tokio::test(flavor = "current_thread")]
#[ignore = "500k rows through the VRL stage: minutes in a debug build"]
async fn nan4319_a_500k_row_tenzir_file_converts_in_the_same_bounded_memory() {
    tenzir_file_converts_in_bounded_memory(500_000).await;
}

/// A file whose conversion kills landing[T] (an OOM SIGKILL: no error, no
/// commit) is not retried forever: every restart is a new lease, every
/// `next` that hands the file out spends one durable ledger attempt, and
/// past [`crate::landing::MAX_ATTEMPTS`] the next process refuses it
/// (`attempts_exhausted`), moves it aside, counts it, and goes on.
#[tokio::test]
async fn nan4319_a_file_that_crashes_conversion_is_refused_after_its_attempts_across_restarts() {
    let store = memory();
    let ledger = Arc::new(FakeLedger::default());
    let producer = Arc::new(FakeProducer::new(TENANT, Some(ledger.clone())));
    let first = Hosted::with(store.clone(), ledger.clone(), producer.clone(), "cell-a:1");
    let poison = first.land(&key(TENANT, "poison.ndjson"), ndjson(&[sysmon(Some("p"), 1)])).await;
    // Five processes each lease the file and die mid-conversion.
    for restart in 0..crate::landing::MAX_ATTEMPTS {
        let process = Hosted::with(store.clone(), ledger.clone(), producer.clone(), &format!("cell-a:{restart}"));
        let (_, leased) = process.discover.discover(&process.store, TENANT, 1).await.unwrap();
        assert_eq!(leased.len(), 1);
        drop(process); // SIGKILL: no commit, no retry.
    }
    let good = first.land(&key(TENANT, "good.ndjson"), ndjson(&[sysmon(Some("g"), 1)])).await;
    let survivor = Hosted::with(store.clone(), ledger.clone(), producer.clone(), "cell-a:after");
    let report = survivor.tick().await.unwrap();
    assert_eq!((report.refused, report.accepted), (1, 1), "{report:?}");
    let file = ledger.file(poison);
    assert_eq!((file.state, file.reason.as_deref()), ("refused", Some("attempts_exhausted")));
    assert_eq!(ledger.file(good).state, "accepted", "the tenant's later files flow");
    assert!(keys_under(&store, REFUSED_PREFIX).await.contains(&refused_key(&key(TENANT, "poison.ndjson"))));
    assert_eq!(survivor.counters.status().refused_by_reason["attempts_exhausted"], 1);
}

// ------------------------------------------------------------------ NAN-4337: Hive class_uid partitions

/// Real Tenzir 6.19.1 output of the documented sink (`ocsf_derive |
/// ocsf_cast null_fill=true | to_file "/w/out/**/events-{uuid}.parquet",
/// partition_by=[class_uid] { write_parquet }`, see
/// `tests/fixtures/tenzir-6.19.1-hive-class-uid.tql`): the file Tenzir wrote
/// under `class_uid=4001/`, gzipped for the repo. It has no `class_uid`
/// column: partition_by moves it to the path.
fn tenzir_hive_4001() -> Vec<u8> {
    use std::io::Read as _;
    let gz: &[u8] = include_bytes!("../tests/fixtures/tenzir-6.19.1-hive-class-uid-4001.parquet.gz");
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz).read_to_end(&mut out).unwrap();
    out
}

/// Real Tenzir 6.19.1 Authentication output that keeps its `class_uid`
/// (3002) column (no partition_by).
const TENZIR_AUTH_3002: &[u8] = include_bytes!("../tests/fixtures/tenzir-6.19.1-ocsf-auth-ip.parquet");

#[tokio::test]
async fn tenzir_partition_by_output_takes_class_uid_from_its_hive_folder() {
    let file = tenzir_hive_4001();
    assert!(parquet_schema(&file).field_with_name("class_uid").is_err(), "partition_by drops the column");

    // Each key in its own tenant ledger: the same bytes twice would be a
    // duplicate (NAN-4325).
    for name in ["class_uid=4001/events-01a15f81.parquet", "2026/10/21/class_uid=4001/events-01a15f81.parquet"] {
        let hosted = Hosted::new();
        let seq = hosted.land(&key(TENANT, name), file.clone()).await;
        let report = hosted.tick().await.unwrap();
        assert_eq!((report.accepted, report.refused, report.failed), (1, 0, 0), "{name}: {report:?}");
        assert_eq!(hosted.ledger.file(seq).state, "accepted");
        assert_eq!(class_uids(&hosted.producer.segments()), vec![4001]);
        let commit = last_commit(&hosted);
        assert_eq!((commit.rows, commit.rows_refused, commit.row_reason), (Some(1), None, None), "{commit:?}");
    }
    // The bug (2026-10-21): the same bytes outside a class folder are refused whole.
    let hosted = Hosted::new();
    let flat = hosted.land(&key(TENANT, "events-01a15f83.parquet"), file).await;
    hosted.tick().await.unwrap();
    let flat = hosted.ledger.file(flat);
    assert_eq!((flat.state, flat.reason.as_deref()), ("refused", Some("ocsf_class_uid_missing_or_invalid")));
}

#[tokio::test]
async fn a_class_column_that_contradicts_its_folder_refuses_the_file() {
    let hosted = Hosted::new();
    let conflict = hosted.land(&key(TENANT, "class_uid=4001/auth.parquet"), TENZIR_AUTH_3002.to_vec()).await;
    let report = hosted.tick().await.unwrap();
    assert_eq!((report.accepted, report.refused), (0, 1), "{report:?}");
    let file = hosted.ledger.file(conflict);
    assert_eq!((file.state, file.reason.as_deref()), ("refused", Some("class_uid_partition_conflict")));
    let commit = last_commit(&hosted);
    assert_eq!(commit.detail.as_deref(), Some("class_uid=4001 field=class_uid"));
    assert!(hosted.producer.segments().is_empty());
    assert!(keys_under(&hosted.store, REFUSED_PREFIX).await.contains(&refused_key(&key(TENANT, "class_uid=4001/auth.parquet"))));

    // A column that agrees with its folder converts as before.
    let agree = hosted.land(&key(TENANT, "class_uid=3002/auth.parquet"), TENZIR_AUTH_3002.to_vec()).await;
    hosted.tick().await.unwrap();
    assert_eq!(hosted.ledger.file(agree).state, "accepted");
    assert!(class_uids(&hosted.producer.segments()).iter().all(|class| *class == 3002));
}

/// A mixed file under a class folder: rows without the column take it, rows
/// that carry the same class stay, one row of another class refuses it all.
#[tokio::test]
async fn partition_rows_mix_and_a_single_contradicting_row_refuses_the_file() {
    let hosted = Hosted::new();
    let mut bare = network("bare");
    bare.as_object_mut().unwrap().remove("class_uid");
    let ok = hosted.land(&key(TENANT, "class_uid=4001/ok.ndjson"), ndjson(&[bare.clone(), network("own")])).await;
    hosted.tick().await.unwrap();
    assert_eq!(hosted.ledger.file(ok).state, "accepted");
    assert_eq!(last_commit(&hosted).rows, Some(2));

    let bad = hosted.land(&key(TENANT, "class_uid=4001/bad.ndjson"), ndjson(&[bare, auth("other")])).await;
    hosted.tick().await.unwrap();
    assert_eq!(hosted.ledger.file(bad).reason.as_deref(), Some("class_uid_partition_conflict"));
}

#[tokio::test]
async fn junk_and_ambiguous_class_folders_are_refused_before_reading() {
    let hosted = Hosted::new();
    let file = tenzir_hive_4001();
    let junk = hosted.land(&key(TENANT, "class_uid=abc/events.parquet"), file.clone()).await;
    let unknown = hosted.land(&key(TENANT, "class_uid=99999/events.parquet"), file.clone()).await;
    let two = hosted.land(&key(TENANT, "class_uid=4001/class_uid=4001/events.parquet"), file).await;
    let report = hosted.tick().await.unwrap();
    assert_eq!((report.accepted, report.refused, report.failed), (0, 3, 0), "{report:?}");
    for (seq, reason) in [(junk, "class_uid_partition_invalid"), (unknown, "class_uid_partition_invalid"),
        (two, "class_uid_partition_ambiguous")]
    {
        let file = hosted.ledger.file(seq);
        assert_eq!((file.state, file.reason.as_deref()), ("refused", Some(reason)), "file {seq}");
    }
    assert!(hosted.producer.segments().is_empty());
    assert!(keys_under(&hosted.store, LANDING_PREFIX).await.is_empty());
}
