// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4682: landing converter throughput.
//!
//! `landing_throughput_bench` times rows/s and CPU per row through the
//! production converter (`Converter::tick` over the production
//! `LandingOcsfStage::new(1)`, `BronzeObjects`, an in-memory store) on a
//! generated Tenzir-shaped corpus. Run it optimized:
//!
//! ```text
//! cargo test -p nanosiem-lake-worker --lib landing_throughput_bench \
//!   --config 'profile.test.opt-level=3' --config 'profile.test.package."*".opt-level=3' \
//!   -- --ignored --nocapture
//! ```

use super::*;

/// Files and rows per file of the generated corpus (Tenzir `to_s3` files of a
/// few thousand rows each, half typed Parquet, half gzipped NDJSON).
const BENCH_FILES: usize = 32;
const BENCH_ROWS_PER_FILE: usize = 4_000;

/// A Tenzir-shaped row: half carry a sender uid, half get one derived.
fn bench_row(file: usize, row: usize) -> Value {
    let uid = row.is_multiple_of(2).then(|| format!("sysmon:wks-{file:02}:{row}"));
    let mut event = sysmon(uid.as_deref(), (file * 100_000 + row) as i64);
    event["device"]["hostname"] = json!(format!("wks-{:03}", row % 211));
    event["process"]["cmd_line"] = json!(format!("C:\\Windows\\System32\\cmd.exe /c echo {row} && whoami /all"));
    event["actor"]["user"] = json!({"name": format!("user{}", row % 97), "domain": "CORP"});
    event["device"]["ip"] = json!(format!("10.{}.{}.{}", file % 250, (row / 250) % 250, row % 250));
    event
}

pub(super) fn bench_corpus(files: usize, rows_per_file: usize) -> Vec<(String, Vec<u8>)> {
    (0..files)
        .map(|file| {
            let events = (0..rows_per_file).map(|row| bench_row(file, row)).collect::<Vec<_>>();
            if file.is_multiple_of(2) {
                (key(&format!("bench/{file:03}.parquet")), parquet(&events))
            } else {
                (key(&format!("bench/{file:03}.ndjson.gz")), gzip(&ndjson(&events)))
            }
        })
        .collect()
}

/// Process CPU time (all threads), seconds.
fn process_cpu_secs() -> f64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage writes a full rusage into the pointer it is given.
    let usage = unsafe {
        libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr());
        usage.assume_init()
    };
    let secs = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    secs(usage.ru_utime) + secs(usage.ru_stime)
}

#[test]
#[ignore = "throughput bench (NAN-4682): run optimized with --ignored --nocapture"]
fn landing_throughput_bench() {
    let corpus = bench_corpus(BENCH_FILES, BENCH_ROWS_PER_FILE);
    let rows = (BENCH_FILES * BENCH_ROWS_PER_FILE) as f64;
    let cores = std::thread::available_parallelism().map_or(1, usize::from);

    // 1. One file at a time on one thread: the per-row conversion cost.
    let stage = stage();
    let started = (std::time::Instant::now(), process_cpu_secs());
    let mut accepted = 0_u64;
    for (key, bytes) in &corpus {
        let parsed = parse_key(key, TENANT).unwrap();
        let converted = convert_landed(bytes, parsed.format, None, &stage, TENANT, &source(), Utc::now()).unwrap();
        accepted += converted.rows_accepted;
    }
    let (wall, cpu) = (started.0.elapsed().as_secs_f64(), process_cpu_secs() - started.1);
    assert_eq!(accepted as f64, rows);
    println!(
        "NAN-4682 bench convert_landed (1 thread): {rows} rows in {wall:.2}s = {:.0} rows/s, CPU {:.1} us/row",
        rows / wall,
        cpu * 1e6 / rows
    );

    // 2. The production converter end to end: tick until the folder is empty.
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(cores).enable_all().build().unwrap();
    runtime.block_on(async {
        let store = Operator::new(opendal::services::Memory::default()).unwrap().finish();
        for (key, bytes) in &corpus {
            store.write(key, bytes.clone()).await.unwrap();
        }
        let converter = Converter {
            store: store.clone(),
            ledger: MemoryLedger { sources: vec![source()], ..Default::default() },
            stage: stage.clone(),
            tenant_id: TENANT.into(),
            max_files_per_tick: 64,
            emit: BronzeObjects,
        };
        let started = (std::time::Instant::now(), process_cpu_secs());
        let mut accepted = 0;
        while accepted < BENCH_FILES {
            let report = converter.tick().await.unwrap();
            assert_eq!(report.failed, 0, "{report:?}");
            accepted += report.accepted;
        }
        let (wall, cpu) = (started.0.elapsed().as_secs_f64(), process_cpu_secs() - started.1);
        println!(
            "NAN-4682 bench Converter::tick ({cores} cores): {rows} rows in {wall:.2}s = {:.0} rows/s, CPU {:.1} us/row",
            rows / wall,
            cpu * 1e6 / rows
        );
    });
}

// --- NAN-4682 equivalence: in-memory pre-check vs the Parquet round trip ---

fn tenzir_hive_4001() -> Vec<u8> {
    let gz: &[u8] = include_bytes!("../tests/fixtures/tenzir-6.19.1-hive-class-uid-4001.parquet.gz");
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz).read_to_end(&mut out).unwrap();
    out
}

/// `(name, bytes, format, partition, route key)`.
type CorpusFile = (&'static str, Vec<u8>, FileFormat, Option<u32>, &'static str);

/// The landing fixture corpus: the real Tenzir 6.19.1 files, the shapes the
/// landing tests use (typed Parquet, NDJSON, gzip, RFC 3339 times, bad and
/// non-OCSF rows, rows admission refuses, a Hive partition, the platform
/// audit lane), plus value shapes whose JSON rendering could drift (floats,
/// big integers, unicode and escapes, nulls inside objects and arrays,
/// future times that clamp).
fn equivalence_corpus() -> Vec<CorpusFile> {
    use nanosiem_core::audit::{AuditEvent, AuditSource};
    let nd = FileFormat::Ndjson { gzip: false };
    let mut odd = sysmon(None, 42);
    odd["message"] = json!("caf\u{e9} \"quoted\" \\ back\tslash \u{1F600} \u{0001}");
    odd["severity_id"] = json!(99);
    odd["count"] = json!(18_446_744_073_709_551_615_u64);
    odd["unmapped"] = json!({"ratio": 0.1, "tiny": 1e-300, "big": 1.7976931348623157e308, "neg": -0.0, "n": null, "list": [1, null, "x", {"k": null}]});
    odd["device"]["os"] = json!(null);
    let mut rfc = sysmon(Some("rfc"), 9);
    rfc["time"] = json!("2026-10-14T12:00:00.250Z");
    let mut naive = sysmon(Some("naive"), 10);
    naive["time"] = json!("2026-10-14T12:00:00.123456");
    let mut future = sysmon(Some("future"), 11);
    future["time"] = json!(4_102_444_800_000_i64);
    let mut no_class = sysmon(Some("np"), 7);
    no_class.as_object_mut().unwrap().remove("class_uid");
    let mut bad_ip = sysmon(Some("badip"), 12);
    bad_ip["device"]["ip"] = json!("not-an-ip");
    let mut mixed = ndjson(&[sysmon(Some("m1"), 1), odd.clone()]);
    mixed.extend_from_slice(b"not json\n[1,2]\n{\"hello\": 1}\n");
    mixed.extend_from_slice(&ndjson(&[json!({"class_uid": 1007, "metadata": {"version": "1.9.0"}}), bad_ip]));
    let at = chrono::DateTime::parse_from_rfc3339("2026-10-21T06:02:00.123Z").unwrap().with_timezone(&Utc);
    let audit = |id: &str, tenant: &str| {
        AuditEvent::builder(AuditSource::Detection, "rule_created")
            .success(true)
            .build()
            .to_ocsf_event_for_lake(at, Uuid::parse_str(id).unwrap(), tenant)
    };
    let audit_file = ndjson(&[
        audit("018f6a1e-0d2b-7c3a-9e4f-5a6b7c8d9e01", TENANT),
        audit("018f6a1e-0d2b-7c3a-9e4f-5a6b7c8d9e02", "someone-else"),
    ]);
    let many: Vec<Value> = (0..(ROW_CHUNK * 2 + 17)).map(|i| bench_row(3, i)).collect();
    vec![
        ("tenzir-auth-ip", TENZIR_AUTH_PARQUET.to_vec(), FileFormat::Parquet, None, "tenzir_sysmon"),
        ("tenzir-hive-4001", tenzir_hive_4001(), FileFormat::Parquet, Some(4001), "tenzir_sysmon"),
        ("typed-parquet", parquet(&[sysmon(Some("a"), 1), sysmon(None, 2)]), FileFormat::Parquet, None, "tenzir_sysmon"),
        ("ndjson", ndjson(&[sysmon(None, 1), odd, rfc, naive, future]), nd, None, "tenzir_sysmon"),
        ("gzip-mixed", gzip(&mixed), FileFormat::Ndjson { gzip: true }, None, "tenzir_sysmon"),
        ("partition", ndjson(&[no_class, sysmon(Some("wp"), 8)]), nd, Some(1007), "tenzir_sysmon"),
        ("multi-chunk", gzip(&ndjson(&many)), FileFormat::Ndjson { gzip: true }, None, "tenzir_sysmon"),
        ("multi-chunk-parquet", parquet(&many), FileFormat::Parquet, None, "tenzir_sysmon"),
        ("audit-lane", audit_file, nd, None, nanosiem_core::parsers::landing_ocsf::PLATFORM_AUDIT_ROUTE_KEY),
        ("nothing-admissible", b"garbage\n".to_vec(), nd, None, "tenzir_sysmon"),
        ("not-ocsf", ndjson(&[json!({"hello": "world"})]), nd, None, "tenzir_sysmon"),
    ]
}

/// Everything a conversion decides, except the random bronze key suffix.
fn decided(result: &std::result::Result<Converted, FileRefusal>) -> String {
    match result {
        Err(refusal) => format!("refused {refusal:?}"),
        Ok(c) => format!(
            "accepted={} refused={} first={:?} detail={:?} class_from_path={} sha={} clamped={} objects={:?}",
            c.rows_accepted,
            c.rows_refused,
            c.first_refusal,
            c.first_refusal_detail,
            c.rows_class_from_path,
            c.content_sha256,
            c.rows_time_clamped,
            c.objects
                .iter()
                .map(|(key, bytes, rows)| (key.rsplit_once('/').map_or("", |(dir, _)| dir).to_string(), hex::encode(Sha256::digest(bytes)), *rows))
                .collect::<Vec<_>>()
        ),
    }
}

/// NAN-4682: the pre-check without the Parquet round trip decides exactly
/// what the round trip decided, and writes byte-identical bronze, over the
/// whole fixture corpus. Per row, the values it checks are the values the
/// round trip read back.
#[test]
fn landing_precheck_in_memory_matches_the_parquet_round_trip() {
    let received = DateTime::<Utc>::from_timestamp_millis(1_792_843_200_123).unwrap();
    for shards in [1, 4] {
        let stage = LandingOcsfStage::new_at(shards, received).unwrap();
        for (name, bytes, format, partition, route_key) in equivalence_corpus() {
            let landed = LandingSource { route_key: route_key.into(), ..source() };
            let run = |mode| convert_landed_with(&bytes, format, partition, &stage, TENANT, &landed, received, mode);
            let (fast, reference) = (run(Precheck::InMemory), run(Precheck::ParquetRoundTrip));
            assert_eq!(decided(&fast), decided(&reference), "{name} (shards={shards})");
            if let Ok(converted) = &fast {
                assert!(converted.rows_accepted > 0, "{name}");
            }

            // Row level: every prepared row, read back both ways.
            let mut runner = stage.runner();
            let mut prepared = Vec::new();
            visit_rows(&bytes, format, |chunk| {
                for (i, mut row) in chunk.into_iter().enumerate() {
                    if !row.is_object() {
                        continue;
                    }
                    let _ = apply_partition_class(&mut row, partition);
                    normalize_time(&mut row);
                    let ctx = StageContext {
                        tenant_id: TENANT,
                        source_type: route_key,
                        credential_id: CREDENTIAL,
                        event_key: Some(format!("k:{}:{i}", prepared.len())),
                    };
                    if let Ok(bronze) = runner.prepare(row, &ctx) {
                        prepared.push(bronze);
                    }
                }
                Ok(())
            })
            .ok();
            let all = prepared.iter().collect::<Vec<_>>();
            if all.is_empty() {
                continue;
            }
            let fast = precheck_view(&all).unwrap();
            let reference = decode_bronze(&encode_bronze(&all).unwrap()).unwrap();
            assert_eq!(fast.len(), reference.len(), "{name}");
            for (index, (a, b)) in fast.into_iter().zip(reference).enumerate() {
                match (a, b) {
                    (Ok(a), Ok(b)) => {
                        assert_eq!(a, b, "{name} row {index}");
                        assert_eq!(
                            precheck_source_row(a, TENANT),
                            precheck_source_row(b, TENANT),
                            "{name} row {index}"
                        );
                    }
                    (Err(a), Err(b)) => assert_eq!(
                        crate::bronze::classify_row_refusal(&a),
                        crate::bronze::classify_row_refusal(&b),
                        "{name} row {index}"
                    ),
                    (a, b) => panic!("{name} row {index}: {a:?} vs {b:?}"),
                }
            }
        }
    }
}

// --- NAN-4682 concurrency: many files, two converters, a crash mid-batch ---

/// A ledger with Postgres' claim semantics (one owner per `(key, etag)`,
/// a lease that can expire) that records every acknowledgement, so a double
/// claim or an early ack is visible.
#[derive(Default)]
struct LeaseLedger {
    files: Mutex<Vec<LeaseRow>>,
    double_acks: std::sync::atomic::AtomicUsize,
}

#[derive(Debug, Clone)]
struct LeaseRow {
    key: String,
    etag: String,
    state: &'static str,
    attempts: i32,
    expired: bool,
}

impl LeaseLedger {
    /// Every live claim's lease runs out (the claiming process died).
    fn expire_all(&self) {
        for row in self.files.lock().unwrap().iter_mut() {
            row.expired = true;
        }
    }

    fn rows(&self) -> Vec<LeaseRow> {
        self.files.lock().unwrap().clone()
    }

    fn finish(&self, id: i64, state: &'static str) {
        let mut files = self.files.lock().unwrap();
        let row = &mut files[id as usize];
        if row.state != "claimed" {
            self.double_acks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        row.state = state;
    }
}

#[async_trait]
impl Ledger for LeaseLedger {
    async fn source(&self, source_id: Uuid) -> Result<Option<LandingSource>> {
        Ok((source_id == source().source_id).then(source))
    }
    async fn claim(&self, key: &str, etag: &str, _size: u64, _source_id: Option<Uuid>) -> Result<Claim> {
        // Let other tasks run between the read and the write: a claim check
        // that is not atomic would show up as a double claim.
        tokio::task::yield_now().await;
        let mut files = self.files.lock().unwrap();
        if let Some((id, row)) = files.iter_mut().enumerate().find(|(_, row)| row.key == key && row.etag == etag) {
            return Ok(match row.state {
                "claimed" if row.expired => {
                    row.expired = false;
                    row.attempts += 1;
                    Claim::Owned { id: id as i64, attempt: row.attempts }
                }
                "claimed" => Claim::Leased,
                _ => Claim::Finished { id: id as i64 },
            });
        }
        files.push(LeaseRow { key: key.into(), etag: etag.into(), state: "claimed", attempts: 1, expired: false });
        Ok(Claim::Owned { id: files.len() as i64 - 1, attempt: 1 })
    }
    async fn accepted(&self, id: i64, _converted: &Converted, _bronze_keys: &str) -> Result<()> {
        self.finish(id, "accepted");
        Ok(())
    }
    async fn refused(&self, id: i64, _reason: &str, _rows: u64, _sha: Option<&str>) -> Result<()> {
        self.finish(id, "refused");
        Ok(())
    }
    async fn redelivered(&self, _id: i64) -> Result<()> {
        Ok(())
    }
}

/// Shares one ledger between converters (one database, several nodes).
struct Shared(Arc<LeaseLedger>);

#[async_trait]
impl Ledger for Shared {
    async fn source(&self, source_id: Uuid) -> Result<Option<LandingSource>> {
        self.0.source(source_id).await
    }
    async fn claim(&self, key: &str, etag: &str, size: u64, source_id: Option<Uuid>) -> Result<Claim> {
        self.0.claim(key, etag, size, source_id).await
    }
    async fn accepted(&self, id: i64, converted: &Converted, bronze_keys: &str) -> Result<()> {
        self.0.accepted(id, converted, bronze_keys).await
    }
    async fn refused(&self, id: i64, reason: &str, rows: u64, sha: Option<&str>) -> Result<()> {
        self.0.refused(id, reason, rows, sha).await
    }
    async fn redelivered(&self, id: i64) -> Result<()> {
        self.0.redelivered(id).await
    }
}

/// The production bronze writer, except that it "crashes" (fails the emit
/// after writing the file's first object, the rest never written) for keys
/// in `crash`, while `crashing` is set.
struct CrashingEmit {
    crash: std::collections::BTreeSet<String>,
    crashing: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl Emit for CrashingEmit {
    async fn emit(&self, store: &Operator, tenant_id: &str, candidate: &Candidate, converted: &Converted) -> Result<String> {
        if self.crashing.load(std::sync::atomic::Ordering::SeqCst) && self.crash.contains(&candidate.key) {
            assert!(converted.objects.len() > 1, "the crash must leave objects unwritten");
            let (key, body, _) = &converted.objects[0];
            store.write(key, body.clone()).await?;
            tokio::task::yield_now().await;
            anyhow::bail!("converter died mid-upload");
        }
        BronzeObjects.emit(store, tenant_id, candidate, converted).await
    }
}

/// Every bronze row's uid, with repeats.
async fn bronze_uids(store: &Operator) -> Vec<String> {
    let mut uids = Vec::new();
    for key in keys_under(store, BRONZE_PREFIX).await {
        let bytes = store.read(&key).await.unwrap().to_vec();
        for event in decode_bronze(&bytes).unwrap() {
            uids.push(event.unwrap()["metadata"]["uid"].as_str().unwrap().to_string());
        }
    }
    uids.sort();
    uids
}

/// NAN-4682: many files handled concurrently by two converters over one
/// ledger and one bucket, one of them dying mid-upload on some files and
/// restarting. Every file is claimed by one owner at a time and finished
/// exactly once; a file is acknowledged only after all its bronze is
/// written; after the restart no row is lost, and the only repeats are rows
/// of files whose upload died (same uids: the lake's uid window drops them).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_converters_finish_every_file_once_and_survive_a_crash_mid_batch() {
    let store = Operator::new(opendal::services::Memory::default()).unwrap().finish();
    let sharded = LandingOcsfStage::new(4).unwrap();
    let files = 48_usize;
    let rows_per_file = 300_usize;
    let mut expected = Vec::new();
    let mut crash = std::collections::BTreeSet::new();
    for file in 0..files {
        // Four bronze shards: each file is four bronze objects (four PUTs).
        let events: Vec<Value> = (0..rows_per_file).map(|row| bench_row(file, row)).collect();
        let (name, body) = if file.is_multiple_of(2) {
            (format!("c/{file:03}.parquet"), parquet(&events))
        } else {
            (format!("c/{file:03}.ndjson.gz"), gzip(&ndjson(&events)))
        };
        store.write(&key(&name), body).await.unwrap();
        if file.is_multiple_of(5) {
            crash.insert(key(&name));
        }
        let converted = convert_file(
            &store.read(&key(&name)).await.unwrap().to_vec(),
            parse_key(&key(&name), TENANT).unwrap().format,
            &sharded,
            TENANT,
            &source(),
            Utc::now(),
        )
        .unwrap();
        expected.extend(events_of(&converted).iter().map(|e| e["metadata"]["uid"].as_str().unwrap().to_string()));
    }
    // A file nobody can convert is refused once, never retried forever.
    store.write(&key("c/zz-bad.parquet"), b"nope".to_vec()).await.unwrap();
    expected.sort();
    assert_eq!(expected.len(), files * rows_per_file);

    let ledger = Arc::new(LeaseLedger::default());
    let emit = || CrashingEmit { crash: crash.clone(), crashing: std::sync::atomic::AtomicBool::new(true) };
    let node = |emit| Converter {
        store: store.clone(),
        ledger: Shared(ledger.clone()),
        stage: sharded.clone(),
        tenant_id: TENANT.into(),
        max_files_per_tick: 64,
        emit,
    };
    let (a, b) = (node(emit()), node(emit()));
    let (ra, rb) = futures::future::join(a.tick(), b.tick()).await;
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    let crashed = crash.len();
    // Every died upload is a failure; a node may also fail a file the
    // other node finished and deleted under it (its stat finds nothing).
    assert!(ra.failed + rb.failed >= crashed, "{ra:?} {rb:?}");
    assert_eq!(ra.accepted + rb.accepted, files - crashed, "{ra:?} {rb:?}");
    assert_eq!(ra.refused + rb.refused, 1, "{ra:?} {rb:?}");
    assert_eq!(ledger.double_acks.load(std::sync::atomic::Ordering::SeqCst), 0, "a file was finished twice");
    // No ack before the upload: a file whose upload died is still landed
    // and still claimed (its lease will expire), never finished.
    let rows = ledger.rows();
    assert_eq!(rows.len(), files + 1, "one ledger row per (key, etag)");
    for row in &rows {
        if crash.contains(&row.key) {
            assert_eq!(row.state, "claimed", "{}: finished although its upload died", row.key);
            assert!(store.exists(&row.key).await.unwrap(), "{}: deleted although its upload died", row.key);
        } else {
            assert_ne!(row.state, "claimed", "{}", row.key);
            assert_eq!(row.attempts, 1, "{}: claimed {} times", row.key, row.attempts);
        }
    }
    // Before the restart: every finished file's rows exactly once.
    let before = bronze_uids(&store).await;
    let mut unique = before.clone();
    unique.dedup();
    assert_eq!(unique.len(), before.len(), "a row was written twice before the restart");

    // Restart: both nodes come back (the dead one's leases expire).
    ledger.expire_all();
    let (a, b) = (node(emit()), node(emit()));
    a.emit.crashing.store(false, std::sync::atomic::Ordering::SeqCst);
    b.emit.crashing.store(false, std::sync::atomic::Ordering::SeqCst);
    let (ra, rb) = futures::future::join(a.tick(), b.tick()).await;
    let (ra, rb) = (ra.unwrap(), rb.unwrap());
    // (A failure here is only the race above: the file was finished by the
    // other node; the ledger checks below prove nothing is left behind.)
    assert_eq!(ra.accepted + rb.accepted, crashed, "{ra:?} {rb:?}");
    assert_eq!(ledger.double_acks.load(std::sync::atomic::Ordering::SeqCst), 0, "a file was finished twice");
    assert!(keys_under(&store, &format!("{LANDING_PREFIX}tenant_id={TENANT}/")).await.is_empty(), "every file finished");
    for row in ledger.rows() {
        assert_ne!(row.state, "claimed", "{}", row.key);
        assert_eq!(row.attempts, if crash.contains(&row.key) { 2 } else { 1 }, "{}", row.key);
    }
    // No row lost; repeats only from the died uploads' first objects.
    let after = bronze_uids(&store).await;
    let mut distinct = after.clone();
    distinct.dedup();
    assert_eq!(distinct, expected, "every landed row is in bronze");
    let repeats = after.len() - distinct.len();
    assert!(repeats <= crashed * rows_per_file, "repeats {repeats} beyond the died uploads");
    let crashed_uids: std::collections::BTreeSet<String> = {
        let mut set = std::collections::BTreeSet::new();
        for window in after.windows(2) {
            if window[0] == window[1] {
                set.insert(window[0].clone());
            }
        }
        set
    };
    for uid in &crashed_uids {
        let file: usize = uid.split(':').nth(1).and_then(|w| w.strip_prefix("wks-")).map_or(usize::MAX, |n| n.parse().unwrap());
        assert!(file == usize::MAX || file.is_multiple_of(5), "{uid} repeated but its file never crashed");
    }
}

/// Several converters, same files, no crashes: every row lands exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_converters_never_double_convert_a_file() {
    let store = Operator::new(opendal::services::Memory::default()).unwrap().finish();
    let mut expected = 0;
    for file in 0..40_usize {
        let events: Vec<Value> = (0..50).map(|row| sysmon(Some(&format!("once:{file}:{row}")), row)).collect();
        expected += events.len();
        store.write(&key(&format!("o/{file:03}.ndjson")), ndjson(&events)).await.unwrap();
    }
    let ledger = Arc::new(LeaseLedger::default());
    let nodes: Vec<_> = (0..3)
        .map(|_| Converter {
            store: store.clone(),
            ledger: Shared(ledger.clone()),
            stage: stage(),
            tenant_id: TENANT.into(),
            max_files_per_tick: 64,
            emit: BronzeObjects,
        })
        .collect();
    let reports = futures::future::join_all(nodes.iter().map(Converter::tick)).await;
    let accepted: usize = reports.iter().map(|r| r.as_ref().unwrap().accepted).sum();
    assert_eq!(accepted, 40, "{reports:?}");
    assert_eq!(ledger.double_acks.load(std::sync::atomic::Ordering::SeqCst), 0);
    let uids = bronze_uids(&store).await;
    let mut distinct = uids.clone();
    distinct.dedup();
    assert_eq!((uids.len(), distinct.len()), (expected, expected), "a file was converted twice");
}

/// NAN-4682 (review): a file's bronze objects are published concurrently; one
/// failed PUT among them fails the whole emit, and the file is never
/// acknowledged or deleted while the other PUTs are still in flight or done.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_failed_concurrent_bronze_put_never_acks_the_file() {
    use crate::parts::part_log::ObjectStore;
    #[derive(Default)]
    struct FailsThird {
        puts: std::sync::atomic::AtomicUsize,
        objects: Mutex<Vec<String>>,
    }
    #[async_trait]
    impl ObjectStore for FailsThird {
        async fn get(&self, _key: &str) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }
        async fn put_if_absent(&self, key: &str, _bytes: &[u8]) -> Result<bool> {
            let n = self.puts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 2 {
                anyhow::bail!("bronze PUT failed");
            }
            // The other PUTs are still in flight when the failure lands.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            self.objects.lock().unwrap().push(key.to_string());
            Ok(true)
        }
        async fn list(&self, _prefix: &str) -> Result<Vec<String>> {
            Ok(Vec::new())
        }
        async fn put(&self, _key: &str, _bytes: &[u8]) -> Result<()> {
            anyhow::bail!("immutable")
        }
        async fn delete(&self, _key: &str) -> Result<()> {
            anyhow::bail!("immutable")
        }
    }
    let store = Operator::new(opendal::services::Memory::default()).unwrap().finish();
    let events: Vec<Value> = (0..300).map(|row| bench_row(0, row)).collect();
    let landed = key("p/000.ndjson");
    store.write(&landed, ndjson(&events)).await.unwrap();
    let ledger = Arc::new(LeaseLedger::default());
    let converter = Converter {
        store: store.clone(),
        ledger: Shared(ledger.clone()),
        stage: LandingOcsfStage::new(4).unwrap(),
        tenant_id: TENANT.into(),
        max_files_per_tick: 8,
        emit: PublishedBronze { store: FailsThird::default() },
    };
    let report = converter.tick().await.unwrap();
    assert_eq!((report.accepted, report.failed), (0, 1), "{report:?}");
    assert!(converter.emit.store.puts.load(std::sync::atomic::Ordering::SeqCst) >= 3, "the file is several objects");
    let rows = ledger.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].state, "claimed", "acknowledged although a bronze PUT failed");
    assert!(store.exists(&landed).await.unwrap(), "deleted although a bronze PUT failed");
}
