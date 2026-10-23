// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3867 lean erasure: the pure planning/filter/probe pieces, an
//! end-to-end run on a real ingestor (signed parts in a local store, the
//! filtered compaction merge, the part log), tenant isolation, idempotent
//! replay, a crash between publish and commit, and convergence at tenant-a shape.

use super::*;
use crate::enrichment::BronzeIngestEnricher;
use crate::erasure::resolve_string_leaf;
use crate::part_ingest::ingest::seed_schema;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::format::{LogKeys, PartId};
use crate::parts::part_log::{load_log, LocalObjectStore, LogEntry, LogOp, RetireReason};
use crate::parts::provenance::LocalPartSigner;
use arrow_array::Array;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Mutex;

const TENANT: &str = "3867aaaa-0000-4000-8000-000000000001";
const OTHER: &str = "3867bbbb-0000-4000-8000-000000000002";
const SUBJECT: &str = "jdoe";
const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// 2026-10-01T00:00Z, hours since epoch.
const BASE_HOUR: i32 = 492_096;
const HOUR_MS: i64 = 3_600_000;

#[path = "lean_erasure_catalog_tests.rs"]
mod catalog_tests;

fn subject() -> ErasureSubject {
    ErasureSubject::new(ErasureIdentifierType::Username, SUBJECT).unwrap()
}

fn order(tenant: &str, phase: LeanPhase) -> LeanErasureOrder {
    LeanErasureOrder {
        tenant_id: tenant.into(),
        order_id: Uuid::from_u128(0x3867),
        request_id: Uuid::from_u128(0x3868),
        subject: subject(),
        identifier_hash: Some(HASH.into()),
        redact_free_text: true,
        floor_us: 0,
        cutoff_us: i64::MAX / 2,
        progress: LeanProgress { executor: LEAN_EXECUTOR_KIND.into(), phase, sweep_started_ms: Some(0), ..LeanProgress::default() },
    }
}

fn part_ref(created_ms: i64, level: Level, hour: i32) -> PartRef {
    PartRef {
        part_id: PartId::new(created_ms).unwrap(),
        level,
        event_hour: hour,
        event_day: (level == Level::Day).then_some(hour / 24),
        rows: 10,
        min_time_us: i64::from(hour) * HOUR_MS * 1_000,
        max_time_us: (i64::from(hour) + if level == Level::Day { 24 } else { 1 }) * HOUR_MS * 1_000 - 1,
        schema_fingerprint: "0".repeat(64),
        provenance_sha256: "0".repeat(64),
        merkle_root: "0".repeat(64),
        sorted: true,
        data_bytes: 1,
        row_groups: 1,
        data_files: 1,
    }
}

// ---------------------------------------------------------------------------
// Credential, selector, filter, probe inputs.
// ---------------------------------------------------------------------------

#[test]
fn the_ledger_credential_is_bound_to_its_tenant_capability_and_expiry() {
    let now = Utc::now();
    let good = ErasureLedgerCredential {
        tenant_id: TENANT.into(),
        capability: "publish".into(),
        database_url: "postgresql://u:p@db/x?sslmode=verify-full".into(),
        expires_at: (now + chrono::Duration::minutes(10)).to_rfc3339(),
    };
    assert!(good.validate(TENANT, now).is_ok());
    // NEGATIVE cross-tenant: another tenant's login is refused outright.
    assert!(good.validate(OTHER, now).is_err());
    assert!(ErasureLedgerCredential { capability: "finding_drain".into(), ..good.clone() }.validate(TENANT, now).is_err());
    assert!(ErasureLedgerCredential { database_url: "https://db".into(), ..good.clone() }.validate(TENANT, now).is_err());
    assert!(good.validate(TENANT, now + chrono::Duration::minutes(11)).is_err());
    // The exchange field: absent or unreadable is idle, never an error; the
    // Debug form never prints the URL.
    assert!(ledger_from_exchange(None, TENANT).is_none());
    assert!(ledger_from_exchange(Some(&json!({"tenant_id": TENANT})), TENANT).is_none());
    assert!(ledger_from_exchange(Some(&serde_json::to_value(json!({"tenant_id": TENANT, "capability": "publish",
        "database_url": good.database_url, "expires_at": good.expires_at})).unwrap()), OTHER).is_none());
    assert!(ledger_from_exchange(Some(&json!({"tenant_id": TENANT, "capability": "publish",
        "database_url": good.database_url, "expires_at": good.expires_at})), TENANT).is_some());
    assert!(!format!("{good:?}").contains("postgresql://"));
}

fn batch(rows: &[(&str, &str, &str)]) -> RecordBatch {
    use arrow_array::StructArray;
    use arrow_schema::{DataType, Field, Fields};
    let names = StringArray::from(rows.iter().map(|r| Some(r.0)).collect::<Vec<_>>());
    let messages = StringArray::from(rows.iter().map(|r| Some(r.1)).collect::<Vec<_>>());
    let raw = StringArray::from(rows.iter().map(|r| Some(r.2)).collect::<Vec<_>>());
    let user = StructArray::new(Fields::from(vec![Field::new("name", DataType::Utf8, true)]), vec![Arc::new(names) as _], None);
    RecordBatch::try_from_iter(vec![
        ("user", Arc::new(user) as arrow_array::ArrayRef),
        ("message", Arc::new(messages) as _),
        ("raw_data", Arc::new(raw) as _),
    ])
    .unwrap()
}

fn strings(batch: &RecordBatch, path: &str) -> Vec<String> {
    let leaf = resolve_string_leaf(batch, path).unwrap();
    let leaf = arrow_cast::cast(&leaf, &arrow_schema::DataType::Utf8).unwrap();
    let values = leaf.as_any().downcast_ref::<StringArray>().unwrap();
    (0..values.len()).map(|i| if values.is_null(i) { String::new() } else { values.value(i).to_string() }).collect()
}

#[test]
fn the_row_filter_drops_subject_rows_and_redacts_only_whole_token_mentions() {
    let filter = order(TENANT, LeanPhase::Scan).filter().unwrap();
    let input = batch(&[
        ("JDoe", "login jdoe ok", "raw"),
        ("alice", "alice saw JDOE@corp", "jdoe,x"),
        ("bob", "jdoex is someone else", "xjdoe"),
        ("carol", "nothing", "none"),
    ]);
    let (kept, removed, rewritten) = filter.apply(input).unwrap();
    assert_eq!(removed, 1, "the subject's own row (case-insensitive) is dropped");
    assert_eq!(strings(&kept, "user.name"), ["alice", "bob", "carol"], "row order is preserved");
    assert_eq!(rewritten, 1);
    let messages = strings(&kept, "message");
    assert_eq!(messages[0], format!("alice saw {HASH}@corp"));
    assert_eq!(strings(&kept, "raw_data")[0], format!("{HASH},x"));
    // Word-bounded: a longer token is not the subject (and the token index
    // never recorded `jdoe` for it, so redaction stays within what pruning sees).
    assert_eq!(messages[1], "jdoex is someone else");
    assert_eq!(strings(&kept, "raw_data")[1], "xjdoe");
    // Without redaction (request option off) only rows are dropped.
    let mut plain = order(TENANT, LeanPhase::Scan);
    plain.redact_free_text = false;
    let (kept, removed, rewritten) = plain.filter().unwrap().apply(batch(&[("jdoe", "x", "y"), ("a", "jdoe", "jdoe")])).unwrap();
    assert_eq!((kept.num_rows(), removed, rewritten), (1, 1, 0));
}

#[test]
fn subject_tokens_follow_the_ingest_tokenizer() {
    assert_eq!(subject_tokens("jdoe").unwrap(), ["jdoe"]);
    assert_eq!(subject_tokens("j.doe@corp.example").unwrap(), ["corp", "doe", "example", "j"]);
    assert!(subject_tokens("---").is_none(), "no token: undecidable, the part is rewritten");
    assert!(subject_tokens(&"a".repeat(TOKEN_MAX_BYTES + 1)).is_none());
}

#[test]
fn entity_ranges_decide_only_listed_paths_case_insensitively() {
    let schema = crate::parts::sidecar::entity_ranges_schema();
    let path = StringArray::from(vec!["user.name", "src_endpoint.ip", "process.name"]);
    let value = StringArray::from(vec!["JDoe", "10.0.0.9", "jdoe"]);
    let ts = arrow_array::TimestampMicrosecondArray::from(vec![0_i64; 3]);
    let ts_type = schema.field_with_name("first_time").unwrap().data_type().clone();
    let ts = arrow_cast::cast(&ts, &ts_type).unwrap();
    let batch = RecordBatch::try_new(schema.clone(), vec![
        Arc::new(path), Arc::new(value), ts.clone(), ts, Arc::new(arrow_array::UInt64Array::from(vec![1_u64; 3])),
    ]).unwrap();
    let mut bytes = Vec::new();
    let mut writer = parquet::arrow::ArrowWriter::try_new(&mut bytes, schema, None).unwrap();
    writer.write(&batch).unwrap();
    writer.close().unwrap();
    assert!(entity_ranges_hold(&bytes, &["user.name", "actor.user.name"], "jdoe").unwrap());
    assert!(!entity_ranges_hold(&bytes, &["actor.user.name"], "jdoe").unwrap(), "only the selector's paths count");
    assert!(entity_ranges_hold(&bytes, &["src_endpoint.ip", "dst_endpoint.ip"], "10.0.0.9").unwrap());
    assert!(!entity_ranges_hold(&bytes, &["src_endpoint.ip", "dst_endpoint.ip"], "10.0.0.1").unwrap());
}

// ---------------------------------------------------------------------------
// Planning and the phase machine.
// ---------------------------------------------------------------------------

#[test]
fn choose_rewrite_bounds_a_step_and_keeps_day_parts_alone() {
    assert_eq!(choose_rewrite(&[]).unwrap(), None);
    let l0 = part_ref(1_800_000_000_000, Level::L0, BASE_HOUR);
    let (level, inputs) = choose_rewrite(&[l0.clone()]).unwrap().unwrap();
    assert_eq!((level, inputs.len()), (Level::Minute, 1), "an L0 rewrite is a minute part, as any L0 merge");
    let hour = part_ref(1_800_000_000_001, Level::Hour, BASE_HOUR);
    assert_eq!(choose_rewrite(&[l0.clone(), hour.clone()]).unwrap().unwrap().0, Level::Hour);
    let day = part_ref(1_800_000_000_002, Level::Day, BASE_HOUR);
    let (level, inputs) = choose_rewrite(&[l0.clone(), day.clone(), hour]).unwrap().unwrap();
    assert_eq!((level, inputs), (Level::Day, vec![day]));
    let many = (0..100).map(|i| part_ref(1_800_000_000_000 + i, Level::L0, BASE_HOUR)).collect::<Vec<_>>();
    assert_eq!(choose_rewrite(&many).unwrap().unwrap().1.len(), MAX_REWRITE_INPUTS);
    let adopted = PartRef { sorted: false, ..part_ref(1_800_000_000_003, Level::Hour, BASE_HOUR) };
    assert_eq!(choose_rewrite(&[adopted]).unwrap_err(), ADOPTED_PART_UNSUPPORTED);
}

#[test]
fn the_phase_machine_scans_then_sweeps_until_a_sweep_changes_nothing() {
    let mut progress = LeanProgress { sweep_started_ms: Some(100), ..LeanProgress::default() };
    clean(&mut progress, BASE_HOUR, None);
    end_of_pass(&mut progress, 200);
    assert_eq!((progress.phase, progress.sweeps, progress.cursor_hour), (LeanPhase::Tail, 1, None));
    assert_eq!(progress.sweep_started_ms, Some(100), "the first sweep revisits everything created since the scan began");
    changed(&mut progress, 41, BASE_HOUR, None);
    changed(&mut progress, 40, BASE_HOUR, None);
    assert_eq!(progress.last_commit_seq, Some(41));
    end_of_pass(&mut progress, 300);
    // The second sweep revisits everything created since the FIRST sweep
    // began (200), not since it ended: a late add behind its cursor is seen.
    assert_eq!((progress.phase, progress.sweeps, progress.sweep_started_ms), (LeanPhase::Tail, 2, Some(200)));
    assert_eq!(progress.pass_began_ms, Some(300));
    // A slice of an hour keeps the cursor and records where it stopped.
    clean(&mut progress, BASE_HOUR + 3, Some("x".into()));
    assert_eq!((progress.cursor_hour, progress.resume.as_ref().map(|r| r.hour)), (None, Some(BASE_HOUR + 3)));
    clean(&mut progress, BASE_HOUR + 3, None);
    assert_eq!((progress.cursor_hour, progress.resume.clone()), (Some(BASE_HOUR + 3), None));
    end_of_pass(&mut progress, 400);
    assert_eq!(progress.phase, LeanPhase::Prevalence);
    // Progress round-trips through the order row (bounded JSON).
    let json = serde_json::to_value(&progress).unwrap();
    assert!(json.to_string().len() < 1_024);
    assert_eq!(serde_json::from_value::<LeanProgress>(json).unwrap(), progress);
}

#[test]
fn plan_hour_respects_window_cursor_and_sweep_start() {
    let parts = vec![
        part_ref(1_000, Level::Hour, BASE_HOUR),
        part_ref(2_000, Level::L0, BASE_HOUR + 1),
        part_ref(3_000, Level::Minute, BASE_HOUR + 1),
        part_ref(9_000, Level::L0, BASE_HOUR + 5),
    ];
    let mut o = order(TENANT, LeanPhase::Scan);
    assert_eq!(plan_hour(&parts, &o).unwrap().0, BASE_HOUR);
    o.progress.cursor_hour = Some(BASE_HOUR);
    let (hour, inputs) = plan_hour(&parts, &o).unwrap();
    assert_eq!((hour, inputs.len()), (BASE_HOUR + 1, 2));
    // The window: rows at or after the cutoff are out of scope.
    o.cutoff_us = i64::from(BASE_HOUR + 1) * HOUR_MS * 1_000;
    assert!(plan_hour(&parts, &o).is_none());
    // A tail sweep visits only parts created since it started.
    let mut tail = order(TENANT, LeanPhase::Tail);
    tail.progress.sweep_started_ms = Some(2_500);
    let planned = std::iter::from_fn({
        let mut t = tail.clone();
        let parts = parts.clone();
        move || {
            let (hour, inputs) = plan_hour(&parts, &t)?;
            t.progress.cursor_hour = Some(hour);
            Some((hour, inputs.len()))
        }
    }).collect::<Vec<_>>();
    assert_eq!(planned, vec![(BASE_HOUR + 1, 1), (BASE_HOUR + 5, 1)]);
}

/// tenant-a shape: ~250 parts/day for 7 days (L0 and minute parts beside hour
/// parts), the subject in a sparse subset, a compaction and late adds racing
/// the scan. The executor's planning converges in bounded steps, every step
/// touches at most [`MAX_REWRITE_INPUTS`] parts, and no subject part survives.
#[test]
fn erasure_converges_at_b12_shape_in_bounded_steps() {
    let days = 7;
    let created = std::cell::Cell::new(1_800_000_000_000_i64);
    let next_id = || {
        created.set(created.get() + 1);
        created.get()
    };
    // part id -> (ref, holds the subject)
    let mut live: BTreeMap<String, (PartRef, bool)> = BTreeMap::new();
    for h in 0..days * 24 {
        let hour = BASE_HOUR + h;
        // ~10.5 parts/hour: one hour part + L0/minute parts.
        let per_hour = if h % 2 == 0 { 11 } else { 10 };
        for i in 0..per_hour {
            let level = match i { 0 => Level::Hour, 1..=3 => Level::Minute, _ => Level::L0 };
            let part = part_ref(next_id(), level, hour);
            let holds = (h * 31 + i) % 97 == 0 || (h % 24 == 13 && i == 0);
            live.insert(part.part_id.to_string(), (part, holds));
        }
    }
    let total = live.len();
    assert!(total >= 250 * 7, "{total} parts");
    let subject_parts = live.values().filter(|(_, holds)| *holds).count();
    assert!(subject_parts > 5 && subject_parts < total / 10);
    let mut o = order(TENANT, LeanPhase::Scan);
    o.progress.sweep_started_ms = Some(created.get());
    let (mut steps, mut commits, mut max_inputs) = (0_usize, 0_u64, 0_usize);
    let mut raced = false;
    while o.progress.phase != LeanPhase::Prevalence {
        steps += 1;
        assert!(steps < 4 * 24 * days as usize + 64, "did not converge ({steps} steps)");
        let refs = live.values().map(|(p, _)| p.clone()).collect::<Vec<_>>();
        let Some((hour, candidates)) = plan_hour(&refs, &o) else {
            end_of_pass(&mut o.progress, next_id());
            continue;
        };
        // Mid-scan: a compaction of an already-scanned hour that still held
        // the subject (it committed before our rewrite would have), and a
        // late add of the subject into an early hour.
        if !raced && hour == BASE_HOUR + 80 {
            raced = true;
            let early = BASE_HOUR + 13;
            let merged = part_ref(next_id(), Level::Hour, early);
            live.retain(|_, (p, _)| p.event_hour != early);
            live.insert(merged.part_id.to_string(), (merged, true));
            let late = part_ref(next_id(), Level::L0, BASE_HOUR + 2);
            live.insert(late.part_id.to_string(), (late, true));
        }
        // The probe: subject-holding parts are candidates (sidecars sound).
        let may = candidates.iter().filter(|p| live[p.part_id.as_str()].1).cloned().collect::<Vec<_>>();
        match choose_rewrite(&may).unwrap() {
            None => clean(&mut o.progress, hour, None),
            Some((level, inputs)) => {
                max_inputs = max_inputs.max(inputs.len());
                for input in &inputs {
                    live.remove(input.part_id.as_str());
                }
                let output = part_ref(next_id(), level, inputs[0].event_hour);
                live.insert(output.part_id.to_string(), (output, false));
                commits += 1;
                changed(&mut o.progress, commits, hour, None);
            }
        }
    }
    assert!(raced);
    assert!(live.values().all(|(_, holds)| !holds), "a subject part survived");
    assert!(max_inputs <= MAX_REWRITE_INPUTS);
    assert!(o.progress.sweeps >= 2, "the raced parts needed a sweep");
    // Bounded: about two steps per affected hour plus one per hour per pass.
    assert!(steps <= 3 * 24 * days as usize + 2 * commits as usize, "{steps} steps, {commits} commits");
}

// ---------------------------------------------------------------------------
// End to end on a real ingestor.
// ---------------------------------------------------------------------------

/// The work-order ledger with the database's tenant confinement (RLS).
#[derive(Default)]
struct MemoryLedger {
    orders: Mutex<Vec<LeanErasureOrder>>,
    states: Mutex<BTreeMap<Uuid, String>>,
    passes: Mutex<Vec<StepRecord>>,
    counters: Mutex<StepRecord>,
    /// Test hook: also hand out another tenant's orders (a broken RLS).
    leak: bool,
}

impl MemoryLedger {
    fn with(orders: Vec<LeanErasureOrder>) -> Arc<Self> {
        Arc::new(Self { orders: Mutex::new(orders), ..Self::default() })
    }
    fn state(&self, id: Uuid) -> Option<String> {
        self.states.lock().unwrap().get(&id).cloned()
    }
}

#[async_trait::async_trait]
impl ErasureLedger for MemoryLedger {
    async fn claim(&self, tenant_id: &str, _node: &str) -> Result<Option<LeanErasureOrder>> {
        let states = self.states.lock().unwrap();
        Ok(self.orders.lock().unwrap().iter()
            .filter(|o| self.leak || o.tenant_id == tenant_id)
            .find(|o| !matches!(states.get(&o.order_id).map(String::as_str), Some("completed" | "failed")))
            .cloned())
    }
    async fn record_step(&self, tenant_id: &str, _node: &str, order: &LeanErasureOrder, step: &StepRecord) -> Result<()> {
        ensure!(order.tenant_id == tenant_id);
        for stored in self.orders.lock().unwrap().iter_mut().filter(|o| o.order_id == order.order_id) {
            stored.progress = order.progress.clone();
        }
        self.states.lock().unwrap().insert(order.order_id, "running".into());
        self.counters.lock().unwrap().absorb(step);
        if step.changed() {
            self.passes.lock().unwrap().push(step.clone());
        }
        Ok(())
    }
    async fn complete(&self, tenant_id: &str, _node: &str, order: &LeanErasureOrder) -> Result<()> {
        ensure!(order.tenant_id == tenant_id);
        self.states.lock().unwrap().insert(order.order_id, "completed".into());
        Ok(())
    }
    async fn fail(&self, _tenant: &str, _node: &str, order: &LeanErasureOrder, code: Option<&str>, message: &str) -> Result<()> {
        if let Some(code) = code {
            self.states.lock().unwrap().insert(order.order_id, format!("failed:{code}:{message}"));
        }
        Ok(())
    }
}

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan3867", ed25519_dalek::SigningKey::from_bytes(&[38; 32])).unwrap()
}

/// Event `i` of hour `h`: every 4th belongs to the subject; others mention
/// it in free text every 5th.
fn event(tenant: &str, h: i32, i: usize) -> Value {
    let time = chrono::DateTime::<Utc>::from_timestamp(i64::from(BASE_HOUR + h) * 3_600 + i as i64 * 13, 0).unwrap();
    let user = if i % 4 == 0 { "JDoe".to_string() } else { format!("user{}", i % 7) };
    let message = if i % 5 == 0 { format!("session for jdoe on host {i}") } else { format!("event {h} {i}") };
    let raw = format!("raw {user} {i}");
    json!({
        "time": time.to_rfc3339(), "class_uid": 3002, "class_name": "Authentication", "category_uid": 3,
        "category_name": "Identity & Access Management", "activity_id": 1, "activity_name": "Logon", "type_uid": 300201,
        "severity": "Informational", "severity_id": 1,
        "user": {"name": user}, "actor": {"user": {"name": format!("svc{}", i % 3)}},
        "src_endpoint": {"ip": format!("10.0.{}.{}", h, i % 50)}, "dst_endpoint": {"ip": format!("192.168.1.{}", i % 20)},
        "message": message, "raw_data_size": raw.len(), "raw_data": raw, "status": "Success", "status_id": 1,
        // The token index does not cover `unmapped`: a mention there is
        // only found by rewriting the part.
        "unmapped": {"note": if i % 9 == 0 { format!("seen jdoe at desk {i}") } else { format!("desk note {i}") }},
        "metadata": {"uid": format!("{tenant}-{h}-{i:05}"), "version": "1.9.0", "log_name": "security", "log_source": "WINDOWS_EVENT",
            "tenant_uid": tenant, "product": {"name": "fixture", "vendor_name": "nano"}},
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

const HOURS: i32 = 3;
const PER_HOUR: usize = 80;

struct Lake {
    root: std::path::PathBuf,
    clock: i64,
}

impl Lake {
    fn parts(&self) -> LocalObjectStore {
        LocalObjectStore::new(self.root.join("parts")).unwrap()
    }

    async fn ingestor<'a>(&self, tenant: &str, parts: &'a LocalObjectStore, sources: &'a LocalObjectStore,
        spool: &'a SpoolQueue, signer: &'a LocalPartSigner) -> Ingestor<'a> {
        let mut config = IngestConfig::new(tenant, self.root.join(format!("work-{tenant}")));
        config.flush_interval_override_ms = Some(1_000);
        config.prevalence_enabled = false;
        Ingestor::open(config, parts, sources, spool as &dyn NoticeQueue, signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), self.clock).await.expect("ingest opens")
    }

    /// Ingest `HOURS` hours of events for `tenant` and seal them.
    async fn ingest(&mut self, tenant: &str) {
        let parts = self.parts();
        let sources_dir = self.root.join(format!("sources-{tenant}"));
        std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
        let sources = LocalObjectStore::new(&sources_dir).unwrap();
        let spool = SpoolQueue::new(self.root.join(format!("spool-{tenant}")), tenant).unwrap();
        let signer = signer();
        let mut ingestor = self.ingestor(tenant, &parts, &sources, &spool, &signer).await;
        for h in 0..HOURS {
            // Two objects per hour: several parts per hour before sealing.
            for half in 0..2 {
                let events = (half * PER_HOUR / 2..(half + 1) * PER_HOUR / 2).map(|i| event(tenant, h, i)).collect::<Vec<_>>();
                let key = format!("bronze/{h}-{half}.parquet");
                write_bronze(&sources_dir.join(&key), &events);
                self.clock += 5_000;
                spool.deliver(&SourceNotice { tenant_id: tenant.into(), key, version: "1".into(), bytes: 0, sha256: None,
                    edge_sha256: None, notified_at_ms: self.clock }).unwrap();
                let report = ingestor.tick(self.clock + 1_000).await.expect("admit");
                assert_eq!(report.admitted_rows, (PER_HOUR / 2) as u64, "{report:?} {:?}", ingestor.health());
                ingestor.flush_now(self.clock + 2_000).await.expect("flush");
            }
        }
        let want = (HOURS as usize * PER_HOUR) as u64;
        assert_eq!(load_log(&parts, tenant).await.unwrap().parts().map(|p| p.rows).sum::<u64>(), want);
    }

    /// Tick `tenant`'s ingestor with `ledger` until the order leaves the
    /// running state (or `max` ticks).
    async fn run(&mut self, tenant: &str, ledger: Arc<MemoryLedger>, order: Uuid, max: usize) -> usize {
        let parts = self.parts();
        let sources = LocalObjectStore::new(self.root.join(format!("sources-{tenant}"))).unwrap();
        let spool = SpoolQueue::new(self.root.join(format!("spool-{tenant}")), tenant).unwrap();
        let signer = signer();
        let mut ingestor = self.ingestor(tenant, &parts, &sources, &spool, &signer).await;
        ingestor.set_erasure_ledger_fixed(ledger.clone(), "lean-cell:cell-test".into());
        for tick in 0..max {
            self.clock += 61_000;
            ingestor.tick(self.clock).await.expect("tick");
            if ledger.state(order).is_some_and(|s| s != "running") {
                return tick + 1;
            }
        }
        max
    }
}

/// Rows of every live part of `tenant`: (user.name, message, raw_data).
async fn live_rows(lake: &Lake, tenant: &str) -> Vec<(String, String, String, String)> {
    let parts = lake.parts();
    let live = load_log(&parts, tenant).await.unwrap();
    let mut out = Vec::new();
    for part in live.parts() {
        let keys = PartKeys::new(tenant, part.level, part.event_hour, &part.part_id).unwrap();
        for index in 0..part.data_files as usize {
            let file = std::fs::File::open(lake.root.join("parts").join(keys.data(index))).unwrap();
            let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file).unwrap().build().unwrap();
            for batch in reader {
                let batch = batch.unwrap();
                let (names, messages, raws) = (strings(&batch, "user.name"), strings(&batch, "message"), strings(&batch, "raw_data"));
                let notes = strings(&batch, "unmapped.note");
                for i in 0..batch.num_rows() {
                    out.push((names[i].clone(), messages[i].clone(), raws[i].clone(), notes[i].clone()));
                }
            }
        }
    }
    out.sort();
    out
}

async fn log_ops(lake: &Lake, tenant: &str) -> Vec<LogOp> {
    let parts = lake.parts();
    let head = load_log(&parts, tenant).await.unwrap().head().map(|(seq, _, _)| seq).unwrap();
    let keys = LogKeys::new(tenant).unwrap();
    let mut ops = Vec::new();
    for seq in 0..=head {
        if let Some(bytes) = parts.get(&keys.entry(seq)).await.unwrap() {
            ops.push(LogEntry::parse_bytes(&bytes, tenant).unwrap().op);
        }
    }
    ops
}

fn erasure_ops(ops: &[LogOp], unit: &str) -> usize {
    ops.iter().filter(|op| match op {
        LogOp::Rewrite { deletion_unit, .. } => deletion_unit == unit,
        LogOp::Retire { deletion_unit, reason: RetireReason::Erasure, .. } => deletion_unit == unit,
        _ => false,
    }).count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lean_erasure_removes_the_subject_and_leaves_the_other_tenant_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let mut lake = Lake { root: dir.path().to_path_buf(), clock: i64::from(BASE_HOUR + HOURS + 1) * HOUR_MS };
    lake.ingest(TENANT).await;
    lake.ingest(OTHER).await;
    let before = live_rows(&lake, TENANT).await;
    let other_before = live_rows(&lake, OTHER).await;
    let other_parts = load_log(&lake.parts(), OTHER).await.unwrap().parts().map(|p| p.part_id.clone()).collect::<Vec<_>>();
    let subject_rows = before.iter().filter(|r| r.0.eq_ignore_ascii_case(SUBJECT)).count();
    assert!(subject_rows > 0);

    // NEGATIVE cross-tenant (ledger side): a ledger that leaks OTHER's order
    // to TENANT's executor is refused; nothing of OTHER is touched.
    let foreign = MemoryLedger { orders: Mutex::new(vec![order(OTHER, LeanPhase::Scan)]), leak: true, ..MemoryLedger::default() };
    let foreign = Arc::new(foreign);
    lake.run(TENANT, foreign.clone(), order(OTHER, LeanPhase::Scan).order_id, 5).await;
    assert_ne!(foreign.state(order(OTHER, LeanPhase::Scan).order_id).as_deref(), Some("completed"));
    assert_eq!(live_rows(&lake, OTHER).await, other_before);

    let ledger = MemoryLedger::with(vec![order(TENANT, LeanPhase::Scan)]);
    let id = order(TENANT, LeanPhase::Scan).order_id;
    let ticks = lake.run(TENANT, ledger.clone(), id, 200).await;
    assert_eq!(ledger.state(id).as_deref(), Some("completed"), "after {ticks} ticks");

    let after = live_rows(&lake, TENANT).await;
    assert_eq!(after.len(), before.len() - subject_rows, "exactly the subject's rows are gone");
    assert!(after.iter().all(|r| !r.0.eq_ignore_ascii_case(SUBJECT)));
    assert!(after.iter().all(|r| !r.1.to_lowercase().split(|c: char| !c.is_alphanumeric()).any(|t| t == SUBJECT)),
        "free-text mentions are redacted");
    assert!(after.iter().any(|r| r.1.contains(HASH)), "mentions became the request's identifier hash");
    // `unmapped` is not token-indexed; its mentions are redacted too.
    assert!(before.iter().any(|r| !r.0.eq_ignore_ascii_case(SUBJECT) && r.3.contains(SUBJECT)), "fixture mentions the subject in unmapped");
    assert!(after.iter().all(|r| !r.3.to_lowercase().split(|c: char| !c.is_alphanumeric()).any(|t| t == SUBJECT)),
        "unmapped mentions are redacted");
    assert!(after.iter().any(|r| r.3.contains(HASH)));
    // The receipt: rewrite entries carrying the order's deletion unit, and
    // pass records naming their part-log seqs.
    let unit = format!("erasure:{id}");
    let ops = log_ops(&lake, TENANT).await;
    let commits = erasure_ops(&ops, &unit);
    assert!(commits >= 1);
    let passes = ledger.passes.lock().unwrap().clone();
    assert_eq!(passes.len(), commits);
    assert!(passes.iter().all(|p| p.part_log_first_seq.is_some() && p.parts_superseded + p.parts_retired > 0));
    let counters = ledger.counters.lock().unwrap().clone();
    assert_eq!(counters.rows_removed, subject_rows as u64);
    assert!(counters.rows_redacted > 0);
    // Zero cross-tenant effect: OTHER keeps its parts and rows, subject included.
    assert_eq!(live_rows(&lake, OTHER).await, other_before);
    let other_after = load_log(&lake.parts(), OTHER).await.unwrap().parts().map(|p| p.part_id.clone()).collect::<Vec<_>>();
    assert_eq!(other_after, other_parts);
    assert!(erasure_ops(&log_ops(&lake, OTHER).await, &unit) == 0);

    // Idempotent: a second order for the same subject finds nothing and
    // commits nothing.
    let mut again = order(TENANT, LeanPhase::Scan);
    again.order_id = Uuid::from_u128(0x3869);
    let ledger2 = MemoryLedger::with(vec![again.clone()]);
    lake.run(TENANT, ledger2.clone(), again.order_id, 200).await;
    assert_eq!(ledger2.state(again.order_id).as_deref(), Some("completed"));
    assert_eq!(erasure_ops(&log_ops(&lake, TENANT).await, &format!("erasure:{}", again.order_id)), 0);
    assert_eq!(live_rows(&lake, TENANT).await, after);
}

/// A crash after the step published its output but before the log commit:
/// the output is an unreferenced orphan, the restarted executor re-takes
/// the order from its recorded progress and converges to the same result.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_between_publish_and_commit_is_resumed_without_loss() {
    let dir = tempfile::tempdir().unwrap();
    let mut lake = Lake { root: dir.path().to_path_buf(), clock: i64::from(BASE_HOUR + HOURS + 1) * HOUR_MS };
    lake.ingest(TENANT).await;
    let before = live_rows(&lake, TENANT).await;
    let subject_rows = before.iter().filter(|r| r.0.eq_ignore_ascii_case(SUBJECT)).count();
    let ledger = MemoryLedger::with(vec![order(TENANT, LeanPhase::Scan)]);
    let id = order(TENANT, LeanPhase::Scan).order_id;
    {
        // Tick until a step is in flight (inline: its output is published),
        // then drop the ingestor without the commit tick.
        let parts = lake.parts();
        let sources = LocalObjectStore::new(lake.root.join(format!("sources-{TENANT}"))).unwrap();
        let spool = SpoolQueue::new(lake.root.join(format!("spool-{TENANT}")), TENANT).unwrap();
        let signer = signer();
        let mut ingestor = lake.ingestor(TENANT, &parts, &sources, &spool, &signer).await;
        ingestor.set_erasure_ledger_fixed(ledger.clone(), "lean-cell:cell-test".into());
        let unit = format!("erasure:{id}");
        let mut in_flight = false;
        for _ in 0..50 {
            lake.clock += 61_000;
            ingestor.tick(lake.clock).await.unwrap();
            if ingestor.erasure_step_in_flight() {
                in_flight = true;
                break;
            }
        }
        assert!(in_flight, "a step started");
        // Compactions may commit meanwhile; the erasure itself has not.
        assert_eq!(erasure_ops(&log_ops(&lake, TENANT).await, &unit), 0, "nothing of the erasure committed yet");
    }
    let ticks = lake.run(TENANT, ledger.clone(), id, 200).await;
    assert_eq!(ledger.state(id).as_deref(), Some("completed"), "after {ticks} ticks");
    let after = live_rows(&lake, TENANT).await;
    assert_eq!(after.len(), before.len() - subject_rows);
    assert!(after.iter().all(|r| !r.0.eq_ignore_ascii_case(SUBJECT)));
}


/// An in-memory step I/O: every probe is a false positive (the sidecars
/// over-approximate), and a rewrite changes something only when one of
/// its inputs holds the subject (it retires the batch).
struct FalsePositiveIo {
    live: Mutex<BTreeMap<String, (PartRef, bool)>>,
    rewrites: Mutex<Vec<usize>>,
}

#[async_trait::async_trait]
impl StepIo for FalsePositiveIo {
    async fn probe(&self, _part: &PartRef) -> Result<Probe> {
        Ok(Probe::MayContain("token_index"))
    }
    async fn rewrite(&self, _level: Level, _hour: i32, inputs: &[PartRef]) -> Result<StepKind> {
        self.rewrites.lock().unwrap().push(inputs.len());
        assert!(inputs.len() <= MAX_REWRITE_INPUTS);
        let mut live = self.live.lock().unwrap();
        if !inputs.iter().any(|part| live[part.part_id.as_str()].1) {
            return Ok(StepKind::Clean);
        }
        for part in inputs {
            live.remove(part.part_id.as_str());
        }
        Ok(StepKind::Retire { rows_removed: 1 })
    }
}

/// Review P1 (NAN-3867): a clean first batch must not end the hour. 80 L0
/// parts in one hour (more than one step probes), the subject only in
/// parts 35, 38 and 70, every probe a false positive: the steps work the
/// hour batch by batch and slice by slice until no subject part is left.
#[tokio::test]
async fn a_clean_batch_or_slice_never_skips_the_rest_of_the_hour() {
    let parts = (0..80).map(|i| (part_ref(1_800_000_000_000 + i, Level::L0, BASE_HOUR), [35, 38, 70].contains(&i)))
        .collect::<Vec<_>>();
    let io = FalsePositiveIo {
        live: Mutex::new(parts.into_iter().map(|(p, holds)| (p.part_id.to_string(), (p, holds))).collect()),
        rewrites: Mutex::new(Vec::new()),
    };
    let mut o = order(TENANT, LeanPhase::Scan);
    let mut steps = 0;
    while o.progress.phase != LeanPhase::Prevalence {
        steps += 1;
        assert!(steps < 32, "did not converge");
        let refs = io.live.lock().unwrap().values().map(|(p, _)| p.clone()).collect::<Vec<_>>();
        let Some((hour, candidates)) = plan_hour(&refs, &o) else {
            end_of_pass(&mut o.progress, 1_900_000_000_000);
            continue;
        };
        assert!(candidates.len() <= MAX_PROBES_PER_STEP);
        let truncated = candidates.len() >= MAX_PROBES_PER_STEP;
        let step = execute_step(&io, hour, candidates, truncated).await.unwrap();
        match step.kind {
            StepKind::Clean => clean(&mut o.progress, hour, step.resume_after),
            StepKind::Retire { .. } | StepKind::Rewrite { .. } => {
                changed(&mut o.progress, steps as u64, hour, step.resume_after);
            }
            StepKind::Unsupported(code) => panic!("{code}"),
        }
    }
    assert!(io.live.lock().unwrap().values().all(|(_, holds)| !holds), "a subject part survived");
    // The first slice's clean batch handed over to the next; the second
    // slice (parts 64..) was reached.
    let rewrites = io.rewrites.lock().unwrap().clone();
    assert!(rewrites.len() >= 3, "{rewrites:?}");
}

/// Review P1 (NAN-3867): `unmapped` is not token-indexed, so a footer must
/// prove it empty before a part may be pruned.
#[test]
fn unmapped_is_pruned_only_when_the_footer_proves_it_empty() {
    use arrow_array::{ArrayRef, StructArray};
    use arrow_schema::{DataType, Field, Fields, Schema};
    let footer_of = |notes: Vec<Option<&str>>| {
        let note: ArrayRef = Arc::new(StringArray::from(notes.clone()));
        let fields = Fields::from(vec![Field::new("note", DataType::Utf8, true)]);
        let unmapped = StructArray::new(fields.clone(), vec![note], None);
        let message: ArrayRef = Arc::new(StringArray::from(vec!["m"; notes.len()]));
        let schema = Arc::new(Schema::new(vec![
            Field::new("message", DataType::Utf8, true),
            Field::new("unmapped", DataType::Struct(fields), true),
        ]));
        let batch = RecordBatch::try_new(schema.clone(), vec![message, Arc::new(unmapped)]).unwrap();
        let mut bytes = Vec::new();
        let mut writer = parquet::arrow::ArrowWriter::try_new(&mut bytes, schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        let length = u32::from_le_bytes(bytes[bytes.len() - 8..bytes.len() - 4].try_into().unwrap()) as usize;
        bytes[bytes.len() - 8 - length..].to_vec()
    };
    assert!(unmapped_all_null(&footer_of(vec![None, None])).unwrap());
    assert!(!unmapped_all_null(&footer_of(vec![None, Some("seen jdoe")])).unwrap());
    assert!(unmapped_all_null(b"bad").is_err());
}


/// Review round 2: a day batch is rewritten first; the resume point must
/// stay below every lower-id part that may still hold the subject.
#[tokio::test]
async fn a_rewritten_day_batch_never_resumes_past_unrewritten_candidates() {
    let mut parts = (1..=5).map(|i| (part_ref(1_800_000_000_000 + i, Level::L0, BASE_HOUR), i == 3)).collect::<Vec<_>>();
    parts.push((part_ref(1_800_000_000_100, Level::Day, BASE_HOUR), true));
    let io = FalsePositiveIo {
        live: Mutex::new(parts.into_iter().map(|(p, holds)| (p.part_id.to_string(), (p, holds))).collect()),
        rewrites: Mutex::new(Vec::new()),
    };
    let mut o = order(TENANT, LeanPhase::Scan);
    for step in 0..16 {
        if o.progress.phase != LeanPhase::Scan {
            break;
        }
        let refs = io.live.lock().unwrap().values().map(|(p, _)| p.clone()).collect::<Vec<_>>();
        let Some((hour, candidates)) = plan_hour(&refs, &o) else {
            end_of_pass(&mut o.progress, 1_900_000_000_000);
            continue;
        };
        let outcome = execute_step(&io, hour, candidates, false).await.unwrap();
        if step == 0 {
            assert_eq!(outcome.inputs.len(), 1, "the day part goes first");
            assert_eq!(outcome.resume_after, None, "parts 1..5 are not proven clean");
        }
        match outcome.kind {
            StepKind::Clean => clean(&mut o.progress, hour, outcome.resume_after),
            _ => changed(&mut o.progress, step, hour, outcome.resume_after),
        }
    }
    assert!(io.live.lock().unwrap().values().all(|(_, holds)| !holds), "a subject part survived");
}
