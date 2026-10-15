// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::Mutex;

use super::*;
use crate::parts::{Level, LogKeys};
use crate::parts::part_log::{AppendOutcome, LocalObjectStore, ObjectStore, PartLogWriter};
use crate::parts::provenance::tests::{sample_record, signer, TENANT};
use crate::parts::provenance::PartSigner;

/// The bucket as a map; ETags are the quoted sha256 of the bytes.
#[derive(Default)]
struct MemBucket {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
    weak: Mutex<BTreeSet<String>>,
}

impl MemBucket {
    fn put(&self, key: &str, bytes: &[u8]) {
        self.objects.lock().unwrap().insert(key.to_owned(), bytes.to_vec());
    }
    fn remove(&self, key: &str) {
        self.objects.lock().unwrap().remove(key);
    }
}

#[async_trait]
impl BucketEvidence for MemBucket {
    fn source(&self) -> &'static str { "r2_list" }
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.objects.lock().unwrap().get(key).cloned())
    }
    async fn list(&self, prefix: &str) -> Result<Vec<ObservedObject>> {
        let weak = self.weak.lock().unwrap().clone();
        Ok(self.objects.lock().unwrap().iter().filter(|(key, _)| key.starts_with(prefix)).map(|(key, bytes)| ObservedObject {
            key: key.clone(),
            etag: if weak.contains(key) { format!("W/\"{}\"", sha256_hex(bytes)) } else { format!("\"{}\"", sha256_hex(bytes)) },
            size: bytes.len() as u64,
        }).collect())
    }
}

/// Control: fixed gaps; the backfill mimics the SQL function's idempotence.
#[derive(Default)]
struct MemLedger {
    gaps: Vec<ReceiptGap>,
    rows: Mutex<BTreeMap<String, (String, u64)>>,
    receipted: BTreeSet<String>,
    evidence: Mutex<Vec<Value>>,
}

#[async_trait]
impl ReceiptLedger for MemLedger {
    async fn gaps(&self, _tenant: uuid::Uuid, limit: i32) -> Result<Vec<ReceiptGap>> {
        Ok(self.gaps.iter().take(limit as usize).cloned().collect())
    }
    async fn backfill(&self, _tenant: uuid::Uuid, file: &PlannedFile, _reason: &str, evidence: &Value) -> Result<Value> {
        self.evidence.lock().unwrap().push(evidence.clone());
        if self.receipted.contains(&file.key) {
            return Ok(json!({"status": "already_receipted"}));
        }
        let etag = file.etag.clone().unwrap();
        let mut rows = self.rows.lock().unwrap();
        match rows.get(&file.key) {
            None => {
                rows.insert(file.key.clone(), (etag, file.size));
                Ok(json!({"status": "backfilled"}))
            }
            Some(existing) if *existing == (etag, file.size) => Ok(json!({"status": "already_backfilled"})),
            Some(_) => bail!("conflicting backfill"),
        }
    }
}

struct Fixture {
    tenant: uuid::Uuid,
    bucket: MemBucket,
    gap: ReceiptGap,
    keys: PartKeys,
}

/// One committed add of a signed part: entry, provenance and two files in
/// the bucket, and the gap control would report for it.
async fn fixture() -> Fixture {
    let tenant = uuid::Uuid::parse_str(TENANT).unwrap();
    let mut record = sample_record();
    record.files.data[0].sha256 = sha256_hex(b"D");
    record.files.data[0].tokens.sha256 = sha256_hex(b"T");
    let signer = signer(7);
    let signature = signer.sign(TENANT, std::slice::from_ref(&record)).await.unwrap().remove(0);
    let provenance = SignedProvenance::assemble(record.clone(), signature, &signer.trusted()).unwrap().to_bytes().unwrap();
    let part = PartRef {
        part_id: record.part_id.clone(), level: record.level, event_hour: record.event_hour, event_day: None, rows: record.rows,
        min_time_us: record.min_time_us, max_time_us: record.max_time_us, schema_fingerprint: record.schema_fingerprint.clone(),
        provenance_sha256: sha256_hex(&provenance), merkle_root: record.merkle_root.clone(), sorted: true, data_bytes: 1,
        row_groups: 1, data_files: 1,
    };
    let dir = tempfile::tempdir().unwrap();
    let store = LocalObjectStore::new(dir.path()).unwrap();
    let schema = arrow_schema::Schema::new(vec![arrow_schema::Field::new(
        "time", arrow_schema::DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, Some("+00:00".into())), false)]);
    let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema, 1).await.unwrap();
    let source = crate::parts::part_log::SourceRef { key: "bronze/1.parquet".into(), version: "1".into(), sha256: "d".repeat(64) };
    let AppendOutcome::Committed { seq, entry_sha256 } =
        writer.append(LogOp::Add { parts: vec![part.clone()], consumed: vec![source], edge_log: None }, 2).await.unwrap();
    let entry_key = LogKeys::new(TENANT).unwrap().entry(seq);
    let bucket = MemBucket::default();
    bucket.put(&entry_key, &store.get(&entry_key).await.unwrap().unwrap());
    let keys = PartKeys::new(TENANT, Level::L0, record.event_hour, &record.part_id).unwrap();
    bucket.put(&keys.provenance(), &provenance);
    bucket.put(&keys.file("data-00000.parquet"), b"D");
    bucket.put(&keys.file("tokens-00000.nti"), b"T");
    let gap = ReceiptGap {
        part_id: record.part_id.as_str().to_owned(), added_seq: seq as i64, op_kind: "add".into(), entry_key, entry_sha256,
        committed_at: chrono::Utc::now(), live: false, removed_seq: Some(seq as i64 + 1),
    };
    Fixture { tenant, bucket, gap, keys }
}

#[tokio::test]
async fn a_verified_part_plans_every_provenance_file() {
    let f = fixture().await;
    f.bucket.put(&f.keys.file("stray.bin"), b"x");
    let plan = plan_part(f.tenant, &f.gap, &f.bucket).await.unwrap();
    assert_eq!(plan.refused, None);
    let keys: Vec<&str> = plan.files.iter().map(|file| file.key.as_str()).collect();
    assert_eq!(keys, [f.keys.file("data-00000.parquet"), f.keys.file("tokens-00000.nti"), f.keys.provenance()]);
    assert!(plan.files.iter().all(|file| file.refused.is_none() && file.etag.as_deref().is_some_and(strong_etag)));
    assert_eq!(plan.files[0].sha256, sha256_hex(b"D"));
    assert_eq!(plan.unexpected, [f.keys.file("stray.bin")], "listed but unnamed objects are reported, not planned");
}

#[tokio::test]
async fn a_broken_chain_refuses_the_whole_part() {
    let f = fixture().await;
    let mut wrong_sha = f.gap.clone();
    wrong_sha.entry_sha256 = "0".repeat(64);
    assert!(plan_part(f.tenant, &wrong_sha, &f.bucket).await.unwrap().refused.unwrap().contains("sha256 control indexed"));

    let mut other_part = f.gap.clone();
    other_part.part_id = "1790330400999-0000000000000001".into();
    assert!(plan_part(f.tenant, &other_part, &f.bucket).await.unwrap().refused.unwrap().contains("does not add"));

    f.bucket.put(&f.keys.provenance(), b"{}");
    let plan = plan_part(f.tenant, &f.gap, &f.bucket).await.unwrap();
    assert!(plan.refused.unwrap().contains("provenance_sha256"));
    assert!(plan.files.is_empty());

    f.bucket.remove(&f.gap.entry_key);
    assert!(plan_part(f.tenant, &f.gap, &f.bucket).await.unwrap().refused.unwrap().contains("absent"));
}

#[tokio::test]
async fn missing_resized_or_weak_objects_are_refused_per_file() {
    let f = fixture().await;
    f.bucket.remove(&f.keys.file("data-00000.parquet"));
    f.bucket.put(&f.keys.file("tokens-00000.nti"), b"TT");
    f.bucket.weak.lock().unwrap().insert(f.keys.provenance());
    let plan = plan_part(f.tenant, &f.gap, &f.bucket).await.unwrap();
    assert_eq!(plan.refused, None);
    let reasons: Vec<String> = plan.files.iter().map(|file| file.refused.clone().unwrap()).collect();
    assert!(reasons[0].contains("absent"));
    assert!(reasons[1].contains("size 2 differs from provenance 1"));
    assert!(reasons[2].contains("strong ETag"));
}

#[tokio::test]
async fn dry_run_writes_nothing_and_apply_is_idempotent() {
    let f = fixture().await;
    let ledger = MemLedger { gaps: vec![f.gap.clone()], ..Default::default() };
    let mut lines = Vec::new();
    let dry = reconcile(f.tenant, &ledger, &f.bucket, 100, false, "", &mut |line| lines.push(line)).await.unwrap();
    assert_eq!((dry.gap_parts, dry.files_planned, dry.files_refused, dry.backfilled), (1, 3, 0, 0));
    assert!(ledger.rows.lock().unwrap().is_empty() && ledger.evidence.lock().unwrap().is_empty(), "dry run is read-only");
    assert_eq!(lines.len(), 1);

    assert!(reconcile(f.tenant, &ledger, &f.bucket, 100, true, " ", &mut |_| {}).await.is_err(), "apply needs a reason");
    let first = reconcile(f.tenant, &ledger, &f.bucket, 100, true, "NAN-3499", &mut |_| {}).await.unwrap();
    assert_eq!((first.backfilled, first.already_backfilled, first.apply_errors), (3, 0, 0));
    let again = reconcile(f.tenant, &ledger, &f.bucket, 100, true, "NAN-3499", &mut |_| {}).await.unwrap();
    assert_eq!((again.backfilled, again.already_backfilled, again.apply_errors), (0, 3, 0));

    let evidence = ledger.evidence.lock().unwrap()[0].clone();
    assert_eq!(evidence["bucket"], format!("nano-shared-r2-{TENANT}"));
    assert_eq!(evidence["key"], f.keys.file("data-00000.parquet"));
    assert_eq!(evidence["etag"], format!("\"{}\"", sha256_hex(b"D")));
    assert_eq!(evidence["length"], 1);
    assert_eq!(evidence["sha256_source"], "signed_provenance");
    assert_eq!(evidence["added_seq"], f.gap.added_seq);
}

#[tokio::test]
async fn apply_skips_refused_files_and_objects_that_changed_after_planning() {
    let f = fixture().await;
    f.bucket.remove(&f.keys.file("data-00000.parquet"));
    let ledger = MemLedger { gaps: vec![f.gap.clone()], ..Default::default() };
    let summary = reconcile(f.tenant, &ledger, &f.bucket, 100, true, "NAN-3499", &mut |_| {}).await.unwrap();
    assert_eq!((summary.files_refused, summary.backfilled), (1, 2));
    assert!(!ledger.rows.lock().unwrap().contains_key(&f.keys.file("data-00000.parquet")), "a refused file is never backfilled");
}

#[test]
fn gap_windows_split_on_fifteen_minute_silences() {
    let at = |minute: i64| chrono::DateTime::from_timestamp(1_791_000_000 + minute * 60, 0).unwrap();
    let gap = |seq: i64, minute: i64| ReceiptGap {
        part_id: format!("p{seq}"), added_seq: seq, op_kind: "add".into(), entry_key: String::new(), entry_sha256: String::new(),
        committed_at: at(minute), live: false, removed_seq: None,
    };
    let windows = gap_windows(&[gap(1, 0), gap(2, 10), gap(3, 24), gap(9, 60), gap(10, 61)]);
    assert_eq!(windows.iter().map(|w| (w.first_seq, w.last_seq, w.parts)).collect::<Vec<_>>(), [(1, 3, 3), (9, 10, 2)]);
}

#[test]
fn cloudflare_keys_are_percent_encoded_per_byte() {
    assert_eq!(percent_encode_key("lake/parts/v1/tenant=x/a b.json"), "lake%2Fparts%2Fv1%2Ftenant%3Dx%2Fa%20b.json");
}
