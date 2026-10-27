// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2868 acceptance: `ingest[T]` over the part contract.
//!
//! - per-hour row count and Merkle-root parity with bronze admission;
//! - crash replay (fault injection at every commit hop, and a real
//!   `kill -9` of the binary) leaves every uid exactly once in the live set;
//! - merges supersede, sidecars verify, the token index finds a token.

use anyhow::Result;
use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::ReaderBuilder;
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::bronze::admit_bronze_files;
use nanosiem_lake_worker::enrichment::{write_ioc_snapshot, BronzeIngestEnricher, IocSnapshot, IocSnapshotInput};
use nanosiem_lake_worker::lean_platform_bundle::{PlatformBundle, PlatformGrant, TenantPlatformPolicy};
use nanosiem_lake_worker::part_ingest::dedup::read_time_uids;
use nanosiem_lake_worker::part_ingest::discovery::NoticeHandle;
use nanosiem_lake_worker::part_ingest::ingest::seed_schema;
use nanosiem_lake_worker::part_ingest::merge::{merge_parts, MergeInput};
use nanosiem_lake_worker::part_ingest::schema::decode;
use nanosiem_lake_worker::part_ingest::writer::{log_source_strings, sort_by_time_uid};
use nanosiem_lake_worker::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use nanosiem_lake_worker::parts::format::PartKeys;
use nanosiem_lake_worker::parts::levels::Level;
use nanosiem_lake_worker::parts::part_log::{load_log, LiveSet, LocalObjectStore, ObjectStore};
use nanosiem_lake_worker::parts::provenance::{row_digests, LocalPartSigner, MerkleBuilder, SignedProvenance, TenantKeySet, LOWERCASED_AT_REST};
use nanosiem_lake_worker::parts::sidecar::decode_token_index;
use nanosiem_lake_worker::parts::{event_hour_of, sha256_hex};
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

const TENANT: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
const TENANT_B: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f01";
/// 2026-09-25T00:00:00Z
const DAY0_S: i64 = 1_790_294_400;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[11; 32])
}

const SIGNER_KEY_ID: &str = "lab-signer-test-0001";
const SIGNER_KEY_ID_B: &str = "lab-signer-test-0002";

fn signer() -> LocalPartSigner {
    LocalPartSigner::new(SIGNER_KEY_ID, key()).unwrap()
}

fn trusted() -> TenantKeySet {
    signer().trusted()
}

fn event(uid: &str, time_s: i64, i: usize) -> Value {
    let time = chrono::DateTime::from_timestamp(time_s, (i as u32 % 1000) * 1_000_000).unwrap();
    let raw = format!("raw {uid} host-{} logon token{} mimikatz{}", i % 7, i % 13, if i % 97 == 0 { "-marker" } else { "" });
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
    let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(json.clone()), None).unwrap();
    let reader = ReaderBuilder::new(Arc::new(schema)).build(Cursor::new(json)).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        let w = writer.get_or_insert_with(|| ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap());
        w.write(&batch).unwrap();
    }
    writer.unwrap().close().unwrap();
}

struct Fixture {
    _dir: tempfile::TempDir,
    signer: LocalPartSigner,
    root: PathBuf,
    parts: LocalObjectStore,
    sources: LocalObjectStore,
    spool: SpoolQueue,
    /// (key, notified_at_s)
    objects: Vec<(String, i64)>,
    unique_uids: usize,
    tenant: String,
}

/// Owns only the child started by this test; a failed assertion still reaps it.
struct OwnedIngestProcess(std::process::Child);

impl Drop for OwnedIngestProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `objects` bronze objects of `rows` events, one every 20 s from 00:40Z,
/// spanning several hours, with a late object for hour 0 at the end and
/// every 5th object replayed (the same events in a new object).
fn fixture(objects: usize, rows: usize) -> Fixture {
    fixture_for(TENANT, objects, rows)
}

fn fixture_for(tenant: &str, objects: usize, rows: usize) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let mut list = Vec::new();
    let mut uids = HashSet::new();
    let mut n = 0;
    for o in 0..objects {
        let at = DAY0_S + 2_400 + (o as i64) * 20;
        let late = o == objects - 1;
        let events = (0..rows)
            .map(|r| {
                n += 1;
                let uid = format!("uid-{o:05}-{r:04}");
                uids.insert(uid.clone());
                let time = if late { DAY0_S + 60 + r as i64 } else { at - 5 + (r as i64 % 5) };
                let mut value = event(&uid, time, n);
                value["metadata"]["tenant_uid"] = json!(tenant);
                value
            })
            .collect::<Vec<_>>();
        let key = format!("bronze/{at}-{o:05}.parquet");
        write_bronze(&sources_dir.join(&key), &events);
        list.push((key, at));
        if o % 5 == 4 {
            let replay = format!("bronze/{}-{o:05}-replay.parquet", at + 7);
            write_bronze(&sources_dir.join(&replay), &events);
            list.push((replay, at + 7));
        }
    }
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), tenant).unwrap();
    Fixture { _dir: dir, signer: signer(), root, parts, sources, spool, objects: list, unique_uids: uids.len(), tenant: tenant.into() }
}

fn notice(key: &str, at_s: i64) -> SourceNotice {
    SourceNotice {
        tenant_id: TENANT.into(),
        key: key.into(),
        version: "1".into(),
        bytes: 0,
        sha256: None,
        edge_sha256: None,
        notified_at_ms: at_s * 1_000,
    }
}

fn config(root: &Path) -> IngestConfig {
    let mut cfg = IngestConfig::new(TENANT, root.join("work"));
    cfg.flush_interval_override_ms = Some(10_000);
    cfg.max_objects_per_admission = 12;
    // These fixtures exercise the d level; production keeps h on top
    // (NAN-2886, MergePolicy::day_merges).
    cfg.merge_policy.day_merges = true;
    cfg
}

async fn open<'a>(fx: &'a Fixture, queue: &'a dyn NoticeQueue, parts: &'a dyn ObjectStore, now_ms: i64) -> Result<Ingestor<'a>> {
    Ingestor::open(
        config(&fx.root),
        parts,
        &fx.sources,
        queue,
        &fx.signer,
        trusted(),
        BronzeIngestEnricher::disabled(),
        &seed_schema(),
        now_ms,
    )
    .await
}

async fn live(fx: &Fixture) -> LiveSet {
    load_log(&fx.parts, &fx.tenant).await.unwrap()
}

/// Every (time, uid) in the live set, read back from R2 (the local store).
async fn live_rows(fx: &Fixture) -> Vec<(i64, String)> {
    let set = live(fx).await;
    let mut rows = Vec::new();
    let scratch = tempfile::tempdir().unwrap();
    for part in set.parts() {
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        for index in 0..part.data_files as usize {
            let bytes = fx.parts.get(&keys.data(index)).await.unwrap().unwrap();
            let path = scratch.path().join(format!("{}-{index}.parquet", part.part_id));
            std::fs::write(&path, bytes).unwrap();
            rows.extend(read_time_uids(&path).unwrap());
        }
    }
    rows
}

fn assert_exactly_once(rows: &[(i64, String)], expected: usize) {
    let unique = rows.iter().map(|(_, u)| u.as_str()).collect::<HashSet<_>>();
    assert_eq!(unique.len(), rows.len(), "a uid appears more than once in the live set");
    assert_eq!(rows.len(), expected, "live set lost or gained rows");
}

/// Bronze reference: per event hour, (rows, Merkle root) over the unique
/// admitted events, encoded under `schema`.
fn bronze_reference(fx: &Fixture, schema: arrow_schema::SchemaRef) -> BTreeMap<i32, (u64, String)> {
    let mut by_uid = BTreeMap::new();
    for (key, _) in &fx.objects {
        let admission = admit_bronze_files(&[fx.root.join("sources").join(key)], TENANT).unwrap();
        for row in admission.batch.into_rows() {
            by_uid.entry(row.event_uid).or_insert(row.ocsf_event);
        }
    }
    let values = by_uid.values().collect::<Vec<_>>();
    let batch = sort_by_time_uid(&decode(schema, &values).unwrap()).unwrap();
    per_hour_roots(&batch)
}

fn per_hour_roots(batch: &arrow_array::RecordBatch) -> BTreeMap<i32, (u64, String)> {
    let digests = row_digests(batch).unwrap();
    let uids = nanosiem_lake_worker::part_ingest::writer::uid_strings(batch).unwrap();
    let time = batch.column_by_name("time").unwrap();
    let time = time.as_any().downcast_ref::<arrow_array::TimestampMicrosecondArray>().unwrap();
    let mut hours: BTreeMap<i32, MerkleBuilder> = BTreeMap::new();
    for i in 0..batch.num_rows() {
        hours.entry(event_hour_of(time.value(i))).or_default().push_row(uids.value(i), &digests[i]);
    }
    hours.into_iter().map(|(h, m)| (h, (m.leaves(), m.root_hex().unwrap()))).collect()
}

async fn drive(ingestor: &mut Ingestor<'_>, fx: &Fixture, deliver: &dyn Fn(&str, i64)) -> Result<()> {
    for (key, at) in &fx.objects {
        deliver(key, *at);
        ingestor.tick(*at * 1_000).await?;
    }
    let end = fx.objects.last().unwrap().1 * 1_000 + 20_000;
    ingestor.tick(end).await?;
    ingestor.flush_now(end).await?;
    Ok(())
}

/// NAN-2984: with the production (eps-derived) flush policy, a lone batch on
/// an idle tenant is committed to the part log 10 s after admission (was
/// 30 s), and not before the 5 s floor.
#[tokio::test(flavor = "current_thread")]
async fn idle_tenant_batch_commits_within_the_default_age_cap() {
    let fx = fixture(1, 5);
    let mut cfg = config(&fx.root);
    cfg.flush_interval_override_ms = None;
    assert_eq!(cfg.flush_policy, nanosiem_lake_worker::parts::levels::FlushPolicy::default());
    let t0 = DAY0_S * 1_000;
    let mut ingestor = Ingestor::open(
        cfg, &fx.parts, &fx.sources, &fx.spool, &fx.signer,
        trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), t0,
    ).await.unwrap();
    let (key, at) = fx.objects[0].clone();
    fx.spool.deliver(&notice(&key, at)).unwrap();
    let admitted = ingestor.tick(t0).await.unwrap();
    assert_eq!(admitted.admitted_rows, 5);
    assert_eq!(admitted.flushed_parts, 0);
    for elapsed in [1_000, 5_000, 9_999] {
        assert_eq!(ingestor.tick(t0 + elapsed).await.unwrap().flushed_parts, 0, "flushed early at +{elapsed} ms");
    }
    assert!(live(&fx).await.parts().next().is_none());
    assert_eq!(ingestor.tick(t0 + 10_000).await.unwrap().flushed_parts, 1);
    assert_eq!(live(&fx).await.parts().count(), 1);
    assert_exactly_once(&live_rows(&fx).await, 5);
}

/// NAN-3522 over-commit hold: held, each admission takes one object; paused,
/// nothing is admitted and nothing is lost (notices stay pending, unacked);
/// lifted, the rest drains. Every row lands exactly once.
#[tokio::test(flavor = "current_thread")]
async fn the_overcommit_hold_slows_admission_and_never_drops_rows() {
    let fx = fixture(3, 5);
    let t0 = DAY0_S * 1_000;
    let mut ingestor = Ingestor::open(
        config(&fx.root), &fx.parts, &fx.sources, &fx.spool, &fx.signer,
        trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), t0,
    ).await.unwrap();
    for (key, at) in &fx.objects {
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    // Held and paused (bucket in debt): nothing admitted, all pending.
    ingestor.set_admission_hold(Some(0), true);
    assert_eq!(ingestor.tick(t0).await.unwrap().admitted_rows, 0);
    assert_eq!(ingestor.health().pending_notices, 3);
    // Held, may admit, no byte budget: exactly one object per admission.
    ingestor.set_admission_hold(Some(0), false);
    assert_eq!(ingestor.tick(t0 + 1_000).await.unwrap().admitted_rows, 5);
    // A budget that fits more: the first object plus what fits (here the rest).
    ingestor.set_admission_hold(Some(u64::MAX), false);
    assert_eq!(ingestor.tick(t0 + 2_000).await.unwrap().admitted_rows, 10);
    // Lifted: nothing left to drain; nothing was dropped.
    ingestor.set_admission_hold(None, true);
    assert_eq!(ingestor.tick(t0 + 3_000).await.unwrap().admitted_rows, 0);
    ingestor.flush_now(t0 + 20_000).await.unwrap();
    assert_exactly_once(&live_rows(&fx).await, 15);
}

#[tokio::test(flavor = "current_thread")]
async fn tenant_ioc_match_is_written_into_signed_l0_with_revision() {
    let fx = fixture(1, 1);
    let snapshot_path = fx.root.join("ioc.parquet");
    let digest = write_ioc_snapshot(&snapshot_path, &[IocSnapshotInput {
        ioc_value: "10.0.1.1".into(),
        ioc_type: "ip".into(),
        source_id: "tenant-feed".into(),
        threat_type: "test-threat".into(),
        ..Default::default()
    }]).unwrap();
    let snapshot = IocSnapshot::open(&snapshot_path, &digest).unwrap();
    let mut ingestor = Ingestor::open(
        config(&fx.root), &fx.parts, &fx.sources, &fx.spool, &fx.signer,
        trusted(), BronzeIngestEnricher::new(None, Some(snapshot), None),
        &seed_schema(), DAY0_S * 1_000,
    ).await.unwrap();
    ingestor.set_initial_enrichment_revision(Some("revision-one".into())).unwrap();
    drive(&mut ingestor, &fx, &|key, at| { fx.spool.deliver(&notice(key, at)).unwrap(); }).await.unwrap();
    let set = live(&fx).await;
    let part = set.parts().next().unwrap();
    let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
    let provenance = fx.parts.get(&keys.provenance()).await.unwrap().unwrap();
    let signed = SignedProvenance::verify_bytes(&provenance, TENANT, &trusted()).unwrap();
    let pins = &signed.record.admission.as_ref().unwrap().feed_pins;
    assert_eq!(pins["ioc"].as_deref(), Some(digest.as_str()));
    assert_eq!(pins["ioc_revision"].as_deref(), Some("revision-one"));
    let data = fx.parts.get(&keys.data(0)).await.unwrap().unwrap();
    let mut reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(data)).unwrap().build().unwrap();
    let batch = reader.next().unwrap().unwrap();
    let mut json = arrow_json::LineDelimitedWriter::new(Vec::new());
    json.write(&batch).unwrap();
    json.finish().unwrap();
    let row: Value = serde_json::from_slice(&json.into_inner()).unwrap();
    assert_eq!(row["enrichments"][0]["data"]["source_id"], "tenant-feed");
}

#[tokio::test(flavor = "current_thread")]
async fn platform_geo_asn_and_ioc_are_in_signed_part() {
    let fx = fixture(1, 1);
    let (key, at) = &fx.objects[0];
    let mut source = event("platform-geo", DAY0_S + 61, 1);
    source["src_endpoint"]["ip"] = json!("8.8.8.8");
    write_bronze(&fx.root.join("sources").join(key), &[source]);
    let path = fx.root.join("platform.bundle");
    let digest = PlatformBundle::publish(&path, Some(&test_mmdb_bytes()), &[IocSnapshotInput {
        ioc_value: "8.8.8.8".into(), ioc_type: "ip".into(), source_id: "threatfox".into(),
        threat_type: "malware".into(), ..Default::default()
    }], BTreeMap::from([("ipinfo_lite".into(), 1), ("threatfox".into(), 2)])).unwrap();
    let bundle = Arc::new(PlatformBundle::open(&path, &digest).unwrap());
    let now = chrono::Utc::now();
    let policy = TenantPlatformPolicy {
        tenant_id: TENANT.parse().unwrap(), revision: 1, bundle_sha256: digest.clone(),
        grants: BTreeMap::from([
            ("ipinfo_lite".into(), PlatformGrant { feed_revision: 1, valid_until: now + chrono::Duration::minutes(5), premium: None }),
            ("threatfox".into(), PlatformGrant { feed_revision: 2, valid_until: now + chrono::Duration::minutes(5), premium: None }),
        ]),
    };
    let mut ingestor = Ingestor::open(
        config(&fx.root), &fx.parts, &fx.sources, &fx.spool, &fx.signer, trusted(),
        BronzeIngestEnricher::disabled().with_lean_platform(bundle, policy),
        &seed_schema(), DAY0_S * 1_000,
    ).await.unwrap();
    let started = std::time::Instant::now();
    fx.spool.deliver(&notice(key, *at)).unwrap();
    ingestor.tick(*at * 1_000).await.unwrap();
    ingestor.flush_now(*at * 1_000 + 1).await.unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(120));
    let set = live(&fx).await;
    let part = set.parts().next().unwrap();
    let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
    let provenance = fx.parts.get(&keys.provenance()).await.unwrap().unwrap();
    let signed = SignedProvenance::verify_bytes(&provenance, TENANT, &trusted()).unwrap();
    assert_eq!(signed.record.admission.as_ref().unwrap().feed_pins["platform_bundle"].as_deref(), Some(digest.as_str()));
    assert_eq!(signed.record.admission.as_ref().unwrap().feed_pins["platform_policy_revision"].as_deref(), Some("1"));
    let data = fx.parts.get(&keys.data(0)).await.unwrap().unwrap();
    let mut reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(data)).unwrap().build().unwrap();
    let batch = reader.next().unwrap().unwrap();
    let mut json = arrow_json::LineDelimitedWriter::new(Vec::new());
    json.write(&batch).unwrap(); json.finish().unwrap();
    let row: Value = serde_json::from_slice(&json.into_inner()).unwrap();
    assert_eq!(row["src_endpoint"]["location"]["country"], "US");
    assert_eq!(row["src_endpoint"]["autonomous_system"]["number"], 64500);
    assert_eq!(row["src_endpoint"]["autonomous_system"]["name"], "Fixture network");
    assert_eq!(row["src_endpoint"]["location"]["continent"], "North America");
    let geo = row["enrichments"].as_array().unwrap().iter()
        .find(|e| e["provider"] == "platform/ipinfo_lite" && e["name"] == "src_endpoint.ip").unwrap();
    assert_eq!(geo["data"]["country_name"], "United States");
    assert_eq!(geo["data"]["continent_code"], "NA");
    assert_eq!(geo["data"]["as_domain"], "fixture.example");
    assert!(row["enrichments"].as_array().unwrap().iter().any(|e| e["provider"] == "platform/threatfox"));
    assert!(row["enrichments"].as_array().unwrap().iter().any(|e| e["provider"] == "platform/ipinfo_lite"));
}

/// Run the same admitted row through the signed log, verified part fetcher,
/// native compiler and production broad_npl planning path. The policy file is
/// replaced between requests, as it is by the cell's control plane.
/// NAN-4168: enrichment is enforced at ingest only. A revoked or expired
/// grant and a feed revision refresh change what new rows get stamped with;
/// rows already stamped read back unchanged.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256 and NANO_LAKE_COMPILER"]
async fn signed_platform_part_stays_visible_to_native_query_after_policy_revoke() {
    use nanosiem_lake_worker::executor::{ExecutorMode, NativeExecutor};
    use nanosiem_lake_worker::native::NativeChdb;
    use nanosiem_lake_worker::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
    use nanosiem_lake_worker::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
    use nanosiem_lake_worker::part_query::log_view::PartLogView;
    use nanosiem_lake_worker::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
    use std::collections::BTreeSet;
    use std::time::{Duration, Instant};

    let fx = fixture(1, 1);
    let (key, _at) = &fx.objects[0];
    let event_time_s = chrono::Utc::now().timestamp() - 10;
    let mut source = event("native-platform", event_time_s, 1);
    source["src_endpoint"]["ip"] = json!("8.8.8.8");
    source["dst_endpoint"]["ip"] = json!("9.9.9.9");
    write_bronze(&fx.root.join("sources").join(key), &[source]);
    let ioc_initial_path = fx.root.join("tenant-ioc-initial.parquet");
    let ioc_digest = write_ioc_snapshot(&ioc_initial_path, &[IocSnapshotInput {
        ioc_value: "8.8.8.8".into(), ioc_type: "ip".into(),
        source_id: "tenant-a-feed".into(), threat_type: "tenant-specific".into(),
        ..Default::default()
    }]).unwrap();
    let ioc_path = fx.root.join("tenant-ioc.parquet");
    std::os::unix::fs::symlink(&ioc_initial_path, &ioc_path).unwrap();
    let ioc_digest_file = fx.root.join("tenant-ioc.sha256");
    std::fs::write(&ioc_digest_file, &ioc_digest).unwrap();
    let ioc_revision_file = fx.root.join("tenant-ioc.revision");
    std::fs::write(&ioc_revision_file, "101").unwrap();
    let custom_store = nanosiem_lake_worker::ip_context::IpContextStore::new(
        fx.root.join("custom-store"), TENANT.into()).unwrap();
    custom_store.upsert(vec![nanosiem_lake_worker::ip_context::IpContextInput {
        network: "9.9.9.9/32".into(), source_id: "tenant-a-cmdb".into(),
        country_code: "CA".into(), asn: "AS64501".into(),
        updated_at: chrono::Utc::now(), deleted: false,
        country: String::new(), continent: String::new(), continent_code: String::new(),
        as_name: String::new(), as_domain: String::new(),
    }]).unwrap();
    let (custom_initial_path, custom_digest) = custom_store.assignment().unwrap().unwrap();
    let custom_path = fx.root.join("custom-current.parquet");
    std::os::unix::fs::symlink(&custom_initial_path, &custom_path).unwrap();
    let custom_digest_file = fx.root.join("custom.sha256");
    std::fs::write(&custom_digest_file, &custom_digest).unwrap();
    let bundle_path = fx.root.join("platform.bundle");
    let digest = PlatformBundle::publish(&bundle_path, Some(&test_mmdb_bytes()), &[
        IocSnapshotInput {
            ioc_value: "8.8.8.8".into(), ioc_type: "ip".into(), source_id: "threatfox".into(),
            threat_type: "malware".into(), ..Default::default()
        },
        IocSnapshotInput {
            ioc_value: "9.9.9.9".into(), ioc_type: "ip".into(), source_id: "spur".into(),
            threat_type: "premium-malware".into(), ..Default::default()
        },
    ], BTreeMap::from([("ipinfo_lite".into(), 1), ("threatfox".into(), 2), ("spur".into(), 3)])).unwrap();
    let now = chrono::Utc::now();
    let mut policy = TenantPlatformPolicy {
        tenant_id: TENANT.parse().unwrap(), revision: 1, bundle_sha256: digest.clone(),
        grants: BTreeMap::from([
            ("ipinfo_lite".into(), PlatformGrant { feed_revision: 1, valid_until: now + chrono::Duration::minutes(5), premium: None }),
            ("threatfox".into(), PlatformGrant { feed_revision: 2, valid_until: now + chrono::Duration::minutes(5), premium: None }),
            ("spur".into(), PlatformGrant { feed_revision: 3, valid_until: now + chrono::Duration::minutes(5),
                premium: Some(nanosiem_core::platform_enrichment::PremiumStampRight {
                    tier: "premium".into(), grant_revision: 1, entitlement_revision: 7,
                }) }),
        ]),
    };
    let policy_path = fx.root.join("policy.json");
    std::fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let signing_key = fx.root.join("signing-key.hex");
    std::fs::write(&signing_key, hex::encode([11; 32])).unwrap();
    let run_ingest = || {
        let parts_dir = fx.root.join("parts");
        let sources_dir = fx.root.join("sources");
        let spool_dir = fx.root.join("spool");
        let work_dir = fx.root.join("work");
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_lake_part_ingest"))
            .env("RUST_LOG", "info")
            .args(["run", "--tenant-id", TENANT, "--signer-key-id", SIGNER_KEY_ID,
                "--signing-key-file", signing_key.to_str().unwrap(),
                "--parts-dir", parts_dir.to_str().unwrap(),
                "--sources-dir", sources_dir.to_str().unwrap(),
                "--spool-dir", spool_dir.to_str().unwrap(),
                "--work-dir", work_dir.to_str().unwrap(),
                "--platform-bundle-file", bundle_path.to_str().unwrap(),
                "--platform-policy-file", policy_path.to_str().unwrap(),
                "--ioc-snapshot-file", ioc_path.to_str().unwrap(),
                "--ioc-digest-file", ioc_digest_file.to_str().unwrap(),
                "--ioc-revision-file", ioc_revision_file.to_str().unwrap(),
                "--custom-snapshot-file", custom_path.to_str().unwrap(),
                "--custom-digest-file", custom_digest_file.to_str().unwrap(),
                "--tick-ms", "100", "--flush-ms", "1000", "--exit-when-idle"])
            .output().unwrap();
        assert!(output.status.success(), "ingest exit: {}", String::from_utf8_lossy(&output.stderr));
        format!("{} {}", String::from_utf8_lossy(&output.stderr), String::from_utf8_lossy(&output.stdout))
    };
    let accepted = Instant::now();
    fx.spool.deliver(&notice(key, event_time_s)).unwrap();
    let ingest_a_log = run_ingest();

    let signed_a = live(&fx).await;
    let part_a = signed_a.parts().next().unwrap_or_else(|| panic!("A has no signed part; ingest: {ingest_a_log}"));
    let keys_a = PartKeys::new(TENANT, part_a.level, part_a.event_hour, &part_a.part_id).unwrap();
    let provenance_a = fx.parts.get(&keys_a.provenance()).await.unwrap().unwrap();
    let record_a = SignedProvenance::verify_bytes(&provenance_a, TENANT, &trusted()).unwrap();
    let pins_a = &record_a.record.admission.as_ref().unwrap().feed_pins;
    assert_eq!(pins_a["ioc"].as_deref(), Some(ioc_digest.as_str()));
    assert_eq!(pins_a["ioc_revision"].as_deref(), Some("101"));
    assert_eq!(pins_a["ip_context"].as_deref(), Some(custom_digest.as_str()));
    assert_eq!(pins_a["platform_bundle"].as_deref(), Some(digest.as_str()));
    let data_a = fx.parts.get(&keys_a.data(0)).await.unwrap().unwrap();
    let mut rows_a = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(data_a)).unwrap().build().unwrap();
    let mut row_json = arrow_json::LineDelimitedWriter::new(Vec::new());
    row_json.write(&rows_a.next().unwrap().unwrap()).unwrap();
    row_json.finish().unwrap();
    let row_a: Value = serde_json::from_slice(&row_json.into_inner()).unwrap();
    assert_eq!(row_a["dst_endpoint"]["location"]["country"], "CA", "{row_a}");
    // The same source notice after a process restart must leave one row.
    fx.spool.deliver(&notice(key, event_time_s)).unwrap();
    run_ingest();

    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(fx.root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted()).await.unwrap();
    let bucket = "nan2918-local-proof";
    let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: fx.root.join("query-cache"), max_bytes: 128 << 20,
        query_max_bytes: 128 << 20, fetch_concurrency: 2,
        fetch_deadline: Duration::from_secs(30),
    }, TENANT, bucket, &parts_key_prefix(TENANT).unwrap(),
    Arc::new(StoreObjectSource::local(bucket, store.clone(), fx.root.join("parts")))).unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted(), cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    // chDB leaves worker threads behind the C ABI; keep the verified image
    // mapped for the full test process, as the other native integration tests do.
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start_named_with_mode(runtime, 1, "nan2918-native", ExecutorMode::ReadOnly).unwrap();
    let engine = PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT.into(), bucket: bucket.into(),
        compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
        max_query_bytes: 128 << 20, max_memory_bytes: 1 << 30,
        max_execution_seconds: 30, threads: 1,
    }, store, view, fetcher, executor).unwrap();
    let request = |query: &str| BroadNplRequest {
        request_id: uuid::Uuid::new_v4().to_string(), tenant_id: TENANT.into(),
        dataset: "logs".into(), query: query.into(),
        start: chrono::DateTime::from_timestamp(event_time_s - 300, 0).unwrap().to_rfc3339(),
        end: chrono::DateTime::from_timestamp(event_time_s + 300, 0).unwrap().to_rfc3339(),
        limit: 10, offset: 0, table_view: false, use_cache: false,
        cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
        clear_boundaries: BTreeMap::new(), watch_weights: Default::default(), minimum_clear_revision: None,
        deny_source_types: BTreeSet::new(),
    };
    let query = |q: &str| request(q);
    let visible = engine.broad_npl(&query("enriched_src_country_code=US | stats count")).await.unwrap();
    assert_eq!(visible["result"]["rows"][0]["count"], 1, "{visible}");
    let names = engine.broad_npl(&query("* | stats count by src_endpoint.autonomous_system.name")).await.unwrap();
    assert_eq!(names["result"]["rows"][0]["src_endpoint.autonomous_system.name"], "Fixture network", "{names}");
    let attributes = engine.broad_npl(&query("* | table src_endpoint.autonomous_system.number, src_endpoint.autonomous_system.name, src_endpoint.location.country, src_endpoint.location.continent, enrichments.name, enrichments.provider, enrichments.data.country_name, enrichments.data.continent_code, enrichments.data.as_domain")).await.unwrap();
    let row = &attributes["result"]["rows"][0];
    assert_eq!(row["src_endpoint.autonomous_system.number"], 64500, "{attributes}");
    assert_eq!(row["src_endpoint.autonomous_system.name"], "Fixture network", "{attributes}");
    assert_eq!(row["src_endpoint.location.country"], "US", "{attributes}");
    assert_eq!(row["src_endpoint.location.continent"], "North America", "{attributes}");
    let names = row["enrichments.name"].as_array().unwrap();
    let index = names.iter().enumerate().find(|(i, name)| **name == "src_endpoint.ip"
        && row["enrichments.provider"][*i] == "platform/ipinfo_lite").unwrap().0;
    assert_eq!(row["enrichments.data.country_name"][index], "United States", "{attributes}");
    assert_eq!(row["enrichments.data.continent_code"][index], "NA", "{attributes}");
    assert_eq!(row["enrichments.data.as_domain"][index], "fixture.example", "{attributes}");
    let all_fields = engine.broad_npl(&query(r#"src_endpoint.autonomous_system.number=64500 src_endpoint.autonomous_system.name="Fixture network" src_endpoint.location.country=US src_endpoint.location.continent="North America" enrichments.data.country_name="United States" enrichments.data.continent_code=NA enrichments.data.as_domain=fixture.example | stats count"#)).await.unwrap();
    assert_eq!(all_fields["result"]["rows"][0]["count"], 1, "{all_fields}");
    assert!(accepted.elapsed() <= Duration::from_secs(120), "accepted row exceeded query visibility budget");
    eprintln!("nan2918 initial accepted-to-query-visible_ms={}", accepted.elapsed().as_millis());
    let ioc = engine.broad_npl(&query("ioc_src_ip_threat_type=malware | stats count")).await.unwrap();
    assert_eq!(ioc["result"]["rows"][0]["count"], 1, "{ioc}");
    let raw_stamps = engine.broad_npl(&query("* | table enrichments.provider, enrichments.data.threat_type")).await.unwrap();
    let stamps_text = raw_stamps["result"]["rows"].to_string();
    assert!(stamps_text.contains("platform/spur") && stamps_text.contains("tenant-a-feed"), "{raw_stamps}");
    let custom = engine.broad_npl(&query("enriched_dest_country_code=CA | stats count")).await.unwrap();
    assert_eq!(custom["result"]["rows"][0]["count"], 1, "{custom}");
    policy.revision += 1;
    policy.grants.clear();
    std::fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let revoked = engine.broad_npl(&query("enriched_src_country_code=US | stats count")).await.unwrap();
    assert_eq!(revoked["result"]["rows"][0]["count"], 1, "{revoked}");
    let revoked_ioc = engine.broad_npl(&query("ioc_src_ip_threat_type=malware | stats count")).await.unwrap();
    assert_eq!(revoked_ioc["result"]["rows"][0]["count"], 1, "{revoked_ioc}");
    let revoked_stamps = engine.broad_npl(&query("* | table enrichments.provider, enrichments.data.threat_type")).await.unwrap();
    let revoked_text = revoked_stamps["result"]["rows"].to_string();
    assert!(revoked_text.contains("platform/spur") && revoked_text.contains("tenant-a-feed"), "{revoked_stamps}");
    policy.revision += 1;
    policy.grants.insert("ipinfo_lite".into(), PlatformGrant {
        feed_revision: 1, valid_until: now - chrono::Duration::seconds(1), premium: None,
    });
    std::fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let expired = engine.broad_npl(&query("enriched_src_country_code=US | stats count")).await.unwrap();
    assert_eq!(expired["result"]["rows"][0]["count"], 1, "{expired}");

    // Tenant B ingests the same platform feed bytes under a different grant.
    // It receives geo/ASN but no threatfox match, and its query process has a
    // separate signed log, object store, policy and verified cache.
    let fx_b = fixture_for(TENANT_B, 1, 1);
    let (key_b, _at_b) = &fx_b.objects[0];
    let mut source_b = event("native-platform-b", event_time_s, 1);
    source_b["metadata"]["tenant_uid"] = json!(TENANT_B);
    source_b["src_endpoint"]["ip"] = json!("8.8.8.8");
    source_b["dst_endpoint"]["ip"] = json!("9.9.9.9");
    write_bronze(&fx_b.root.join("sources").join(key_b), &[source_b]);
    let policy_b = TenantPlatformPolicy {
        tenant_id: TENANT_B.parse().unwrap(), revision: 7, bundle_sha256: digest.clone(),
        grants: BTreeMap::from([("ipinfo_lite".into(), PlatformGrant {
            feed_revision: 1, valid_until: now + chrono::Duration::minutes(5), premium: None,
        })]),
    };
    let policy_b_path = fx_b.root.join("policy.json");
    std::fs::write(&policy_b_path, serde_json::to_vec(&policy_b).unwrap()).unwrap();
    let signing_b = fx_b.root.join("signing-key.hex");
    std::fs::write(&signing_b, hex::encode([12; 32])).unwrap();
    let trusted_b = LocalPartSigner::new(SIGNER_KEY_ID_B, SigningKey::from_bytes(&[12; 32])).unwrap().trusted();
    let parts_b = fx_b.root.join("parts");
    let sources_b = fx_b.root.join("sources");
    let spool_b = fx_b.root.join("spool");
    let work_b = fx_b.root.join("work");
    fx_b.spool.deliver(&SourceNotice { tenant_id: TENANT_B.into(), ..notice(key_b, event_time_s) }).unwrap();
    let output_b = std::process::Command::new(env!("CARGO_BIN_EXE_lake_part_ingest"))
        .args(["run", "--tenant-id", TENANT_B, "--signer-key-id", SIGNER_KEY_ID_B,
            "--signing-key-file", signing_b.to_str().unwrap(),
            "--parts-dir", parts_b.to_str().unwrap(), "--sources-dir", sources_b.to_str().unwrap(),
            "--spool-dir", spool_b.to_str().unwrap(), "--work-dir", work_b.to_str().unwrap(),
            "--platform-bundle-file", bundle_path.to_str().unwrap(),
            "--platform-policy-file", policy_b_path.to_str().unwrap(),
            "--tick-ms", "100", "--flush-ms", "1000", "--exit-when-idle"])
        .output().unwrap();
    assert!(output_b.status.success(), "tenant B ingest exit: {}", String::from_utf8_lossy(&output_b.stderr));
    let signed_b = live(&fx_b).await;
    let part_b = signed_b.parts().next().unwrap();
    let keys_b = PartKeys::new(TENANT_B, part_b.level, part_b.event_hour, &part_b.part_id).unwrap();
    let provenance_b = fx_b.parts.get(&keys_b.provenance()).await.unwrap().unwrap();
    let record_b = SignedProvenance::verify_bytes(&provenance_b, TENANT_B, &trusted_b).unwrap();
    assert_eq!(record_b.record.admission.as_ref().unwrap().feed_pins["platform_policy_revision"].as_deref(), Some("7"));
    assert_eq!(record_b.record.admission.as_ref().unwrap().feed_pins["platform_bundle"].as_deref(), Some(digest.as_str()));
    assert!(SignedProvenance::verify_bytes(&provenance_b, TENANT, &trusted()).is_err());
    let store_b: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(&parts_b).unwrap());
    let view_b = PartLogView::open(store_b.as_ref(), TENANT_B, trusted_b.clone()).await.unwrap();
    let cache_b = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: fx_b.root.join("query-cache"), max_bytes: 128 << 20,
        query_max_bytes: 128 << 20, fetch_concurrency: 2,
        fetch_deadline: Duration::from_secs(30),
    }, TENANT_B, bucket, &parts_key_prefix(TENANT_B).unwrap(),
    Arc::new(StoreObjectSource::local(bucket, store_b.clone(), parts_b.clone()))).unwrap();
    let fetcher_b = PartFetcher::new(TENANT_B, bucket, store_b.clone(), trusted_b, cache_b).unwrap();
    let runtime_b = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime_b.clone());
    let executor_b = NativeExecutor::start_named_with_mode(runtime_b, 1, "nan2918-native-b", ExecutorMode::ReadOnly).unwrap();
    let engine_b = PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT_B.into(), bucket: bucket.into(),
        compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
        max_query_bytes: 128 << 20, max_memory_bytes: 1 << 30,
        max_execution_seconds: 30, threads: 1,
    }, store_b, view_b, fetcher_b, executor_b).unwrap();
    let mut request_b = request("enriched_src_country_code=US | stats count");
    request_b.tenant_id = TENANT_B.into();
    let geo_b = engine_b.broad_npl(&request_b).await.unwrap();
    assert_eq!(geo_b["result"]["rows"][0]["count"], 1, "{geo_b}");
    request_b.query = "ioc_src_ip_threat_type=malware | stats count".into();
    let ioc_b = engine_b.broad_npl(&request_b).await.unwrap();
    assert_eq!(ioc_b["result"]["rows"][0]["count"], 0, "{ioc_b}");
    request_b.query = "* | table enrichments.provider".into();
    let stamps_b = engine_b.broad_npl(&request_b).await.unwrap();
    let stamps_b_text = stamps_b["result"]["rows"].to_string();
    assert!(!stamps_b_text.contains("platform/spur") && !stamps_b_text.contains("tenant-a-feed"), "{stamps_b}");
    assert!(engine.broad_npl(&request_b).await.is_err(), "A accepted B's query request");
    let request_a = request("enriched_src_country_code=US | stats count");
    assert!(engine_b.broad_npl(&request_a).await.is_err(), "B accepted A's query request");

    // Keep the actual ingest binary running across the production 30-second
    // refresh interval. Replace A's policy atomically, then admit a new Bronze
    // source; its signed part must pin the new revision and query immediately.
    let parts_dir = fx.root.join("parts");
    let sources_dir = fx.root.join("sources");
    let spool_dir = fx.root.join("spool");
    let work_dir = fx.root.join("work");
    let ingest_command = |production_cadence: bool| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_lake_part_ingest"));
        command.args(["run", "--tenant-id", TENANT, "--signer-key-id", SIGNER_KEY_ID,
        "--signing-key-file", signing_key.to_str().unwrap(),
        "--parts-dir", parts_dir.to_str().unwrap(), "--sources-dir", sources_dir.to_str().unwrap(),
        "--spool-dir", spool_dir.to_str().unwrap(), "--work-dir", work_dir.to_str().unwrap(),
        "--platform-bundle-file", bundle_path.to_str().unwrap(),
        "--platform-policy-file", policy_path.to_str().unwrap(),
        "--ioc-snapshot-file", ioc_path.to_str().unwrap(),
        "--ioc-digest-file", ioc_digest_file.to_str().unwrap(),
        "--ioc-revision-file", ioc_revision_file.to_str().unwrap(),
        "--custom-snapshot-file", custom_path.to_str().unwrap(),
        "--custom-digest-file", custom_digest_file.to_str().unwrap()]);
        if production_cadence {
            command.args(["--tick-ms", "1000"]);
        } else {
            command.args(["--tick-ms", "100", "--flush-ms", "1000"]);
        }
        command.stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        command
    };
    let mut running = OwnedIngestProcess(ingest_command(false).spawn().unwrap());
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(running.0.try_wait().unwrap().is_none(), "persistent ingest binary exited before rotation");
    let next_digest = PlatformBundle::publish(&bundle_path, Some(&test_mmdb_bytes()), &[
        IocSnapshotInput { ioc_value: "8.8.8.8".into(), ioc_type: "ip".into(),
            source_id: "threatfox".into(), threat_type: "malware-rotated".into(),
            ..Default::default() },
    ], BTreeMap::from([("ipinfo_lite".into(), 1), ("threatfox".into(), 3)])).unwrap();
    assert_ne!(next_digest, digest, "source rotation reused the old bundle bytes");
    policy.revision += 1;
    policy.bundle_sha256 = next_digest.clone();
    policy.grants = BTreeMap::from([
        ("ipinfo_lite".into(), PlatformGrant { feed_revision: 1, valid_until: chrono::Utc::now() + chrono::Duration::minutes(5), premium: None }),
        ("threatfox".into(), PlatformGrant { feed_revision: 3, valid_until: chrono::Utc::now() + chrono::Duration::minutes(5), premium: None }),
    ]);
    let policy_next = fx.root.join("policy.next.json");
    std::fs::write(&policy_next, serde_json::to_vec(&policy).unwrap()).unwrap();
    std::fs::rename(&policy_next, &policy_path).unwrap();
    let changed_at = Instant::now();
    tokio::time::sleep(Duration::from_secs(31)).await;
    assert!(running.0.try_wait().unwrap().is_none(), "persistent ingest binary exited during refresh");
    let rotation_key = "bronze/rotation.parquet";
    let rotation_time = chrono::Utc::now().timestamp();
    let mut rotation_row = event("native-rotation", rotation_time, 2);
    rotation_row["src_endpoint"]["ip"] = json!("8.8.8.8");
    write_bronze(&fx.root.join("sources").join(rotation_key), &[rotation_row]);
    fx.spool.deliver(&notice(rotation_key, rotation_time)).unwrap();
    let rotation_accepted = Instant::now();
    loop {
        engine.refresh().await.unwrap();
        if let Ok(result) = engine.broad_npl(&query("enriched_src_country_code=US | stats count")).await {
            if result["result"]["rows"][0]["count"] == 2 {
                break;
            }
        }
        assert!(rotation_accepted.elapsed() < Duration::from_secs(120), "rotated source missed 120-second query visibility budget");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let rotated_ioc = engine.broad_npl(&query("ioc_src_ip_threat_type=malware-rotated | stats count")).await.unwrap();
    assert_eq!(rotated_ioc["result"]["rows"][0]["count"], 1, "{rotated_ioc}");
    // The row stamped under threatfox revision 2 keeps its verdict after the
    // feed refreshed to revision 3.
    let refreshed_ioc = engine.broad_npl(&query("ioc_src_ip_threat_type=malware | stats count")).await.unwrap();
    assert_eq!(refreshed_ioc["result"]["rows"][0]["count"], 1, "{refreshed_ioc}");
    assert!(changed_at.elapsed() >= Duration::from_secs(30), "refresh interval was not exercised");
    eprintln!("nan2918 scheduled source refresh wall_ms={} accepted-to-query-visible_ms={}",
        changed_at.elapsed().as_millis(), rotation_accepted.elapsed().as_millis());
    let set_after_rotation = live(&fx).await;
    let mut saw_revision = false;
    for part in set_after_rotation.parts() {
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        let bytes = fx.parts.get(&keys.provenance()).await.unwrap().unwrap();
        let signed = SignedProvenance::verify_bytes(&bytes, TENANT, &trusted()).unwrap();
        saw_revision |= signed.record.admission.as_ref().is_some_and(|admission|
            admission.feed_pins["platform_policy_revision"].as_deref() == Some(policy.revision.to_string().as_str())
            && admission.feed_pins["platform_bundle"].as_deref() == Some(next_digest.as_str()));
    }
    assert!(saw_revision, "rotated signed part did not pin policy revision {}", policy.revision);

    // Pace actual Bronze admissions for three minutes while the same ingest
    // child and native query engine remain active. Prepare the files before
    // timing so fixture serialization is outside the offered ingest rate.
    if std::env::var("NAN2918_SOAK_SECONDS").as_deref() == Ok("180") {
        drop(running);
        running = OwnedIngestProcess(ingest_command(true).spawn().unwrap());
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(running.0.try_wait().unwrap().is_none(), "production-cadence ingest exited before soak");
        fx.spool.deliver(&notice(rotation_key, rotation_time)).unwrap();
        eprintln!("nan2918-soak SIGKILL restart and source replay delivered");
        let sample_bundle = std::env::var_os("NAN2918_SOAK_BUNDLE_FILE").map(PathBuf::from);
        let sample_digest = if let Some(path) = &sample_bundle {
            let digest = std::env::var("NAN2918_SOAK_BUNDLE_SHA256").unwrap();
            let sample = PlatformBundle::open(path, &digest).unwrap();
            assert_eq!(sample.bytes() as u64, std::fs::metadata(path).unwrap().len());
            let next_link = fx.root.join("platform-next.bundle");
            std::os::unix::fs::symlink(path, &next_link).unwrap();
            std::fs::rename(next_link, &bundle_path).unwrap();
            policy.revision += 1;
            policy.bundle_sha256 = digest.clone();
            policy.grants = BTreeMap::from([
                ("ipinfo_lite".into(), PlatformGrant { feed_revision: 1,
                    valid_until: chrono::Utc::now() + chrono::Duration::minutes(10), premium: None }),
                ("threatfox".into(), PlatformGrant { feed_revision: 1,
                    valid_until: chrono::Utc::now() + chrono::Duration::minutes(10), premium: None }),
                ("spur".into(), PlatformGrant { feed_revision: 1,
                    valid_until: chrono::Utc::now() + chrono::Duration::minutes(10),
                    premium: Some(nanosiem_core::platform_enrichment::PremiumStampRight {
                        tier: "premium".into(), grant_revision: 1, entitlement_revision: 7,
                    }) }),
            ]);
            let next_policy = fx.root.join("soak-policy-next.json");
            std::fs::write(&next_policy, serde_json::to_vec(&policy).unwrap()).unwrap();
            std::fs::rename(next_policy, &policy_path).unwrap();
            tokio::time::sleep(Duration::from_secs(31)).await;
            assert!(running.0.try_wait().unwrap().is_none(), "sample bundle refresh stopped ingest");
            Some(digest)
        } else { None };
        let soak_seconds = 180usize;
        let soak_rows_per_second = match std::env::var("NAN2918_SOAK_EPS").as_deref() {
            Ok("300") => 300usize,
            Ok("20") | Err(_) => 20usize,
            other => panic!("unsupported NAN2918_SOAK_EPS: {other:?}"),
        };
        let mut soak = Vec::with_capacity(soak_seconds);
        for second in 0..soak_seconds {
            let key = format!("bronze/soak-{second:03}.parquet");
            let source_time_s = chrono::Utc::now().timestamp();
            let rows = (0..soak_rows_per_second)
                .map(|row| {
                    let mut value = event(&format!("soak-{second:03}-{row:02}"),
                        source_time_s, row);
                    value["src_endpoint"]["ip"] = json!("8.8.8.8");
                    value["dst_endpoint"]["ip"] = json!("9.9.9.9");
                    value
                })
                .collect::<Vec<_>>();
            write_bronze(&fx.root.join("sources").join(&key), &rows);
            soak.push((key, source_time_s));
        }
        let soak_started = Instant::now();
        eprintln!("nan2918-soak pace_started_ms={}", chrono::Utc::now().timestamp_millis());
        let offer_times = Arc::new((0..soak_seconds)
            .map(|_| std::sync::atomic::AtomicU64::new(0))
            .collect::<Vec<_>>());
        let paced_times = offer_times.clone();
        let paced_sources = soak.clone();
        let paced_spool_dir = spool_dir.clone();
        let offer_driver = std::thread::spawn(move || {
            let spool = SpoolQueue::new(paced_spool_dir, TENANT).unwrap();
            for (second, (key, _)) in paced_sources.iter().enumerate() {
                let due = Duration::from_secs(second as u64);
                let wait = due.saturating_sub(soak_started.elapsed());
                if !wait.is_zero() {
                    std::thread::sleep(wait);
                }
                let offered_us = soak_started.elapsed().as_micros() as u64 + 1;
                spool.deliver(&notice(key, chrono::Utc::now().timestamp())).unwrap();
                paced_times[second].store(offered_us, std::sync::atomic::Ordering::Release);
            }
        });
        let mut queried_rows = 0usize;
        let mut latest_visibility_ms = 0u128;
        let mut pinned_update = false;
        for (second, (_, source_time_s)) in soak.iter().enumerate() {
            let next = Duration::from_secs((second + 1) as u64);
            let wait = next.saturating_sub(soak_started.elapsed());
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
            if second == 65 {
                let next_ioc = fx.root.join("tenant-ioc-102.parquet");
                let next_ioc_digest = write_ioc_snapshot(&next_ioc, &[IocSnapshotInput {
                    ioc_value: "8.8.8.8".into(), ioc_type: "ip".into(),
                    source_id: "tenant-a-feed-next".into(), threat_type: "tenant-updated".into(),
                    ..Default::default()
                }]).unwrap();
                let next_ioc_link = fx.root.join("tenant-ioc-next-link.parquet");
                std::os::unix::fs::symlink(&next_ioc, &next_ioc_link).unwrap();
                std::fs::rename(next_ioc_link, &ioc_path).unwrap();
                let next_ioc_digest_file = fx.root.join("tenant-ioc-next.sha256");
                std::fs::write(&next_ioc_digest_file, &next_ioc_digest).unwrap();
                std::fs::rename(next_ioc_digest_file, &ioc_digest_file).unwrap();
                let next_ioc_revision_file = fx.root.join("tenant-ioc-next.revision");
                std::fs::write(&next_ioc_revision_file, "102").unwrap();
                std::fs::rename(next_ioc_revision_file, &ioc_revision_file).unwrap();
                custom_store.upsert(vec![nanosiem_lake_worker::ip_context::IpContextInput {
                    network: "9.9.9.9/32".into(), source_id: "tenant-a-cmdb".into(),
                    country_code: "GB".into(), asn: "AS64502".into(),
                    updated_at: chrono::Utc::now(), deleted: false,
                    country: String::new(), continent: String::new(), continent_code: String::new(),
                    as_name: String::new(), as_domain: String::new(),
                }]).unwrap();
                let (next_custom, next_custom_digest) = custom_store.assignment().unwrap().unwrap();
                let next_custom_link = fx.root.join("custom-next-link.parquet");
                std::os::unix::fs::symlink(next_custom, &next_custom_link).unwrap();
                std::fs::rename(next_custom_link, &custom_path).unwrap();
                let next_custom_digest_file = fx.root.join("custom-next.sha256");
                std::fs::write(&next_custom_digest_file, &next_custom_digest).unwrap();
                std::fs::rename(next_custom_digest_file, &custom_digest_file).unwrap();
                eprintln!("nan2918-soak tenant ioc/custom source rotated at second={second} elapsed_ms={}", soak_started.elapsed().as_millis());
            }
            if second == 85 && sample_digest.is_some() {
                policy.revision += 1;
                policy.grants.remove("threatfox");
                policy.grants.remove("spur");
                let next_policy = fx.root.join("soak-policy-revoked.json");
                std::fs::write(&next_policy, serde_json::to_vec(&policy).unwrap()).unwrap();
                std::fs::rename(next_policy, &policy_path).unwrap();
                eprintln!("nan2918-soak platform IOC grants revoked at second={second} elapsed_ms={}", soak_started.elapsed().as_millis());
            }
            if second % 30 == 29 || second + 1 == soak_seconds {
                let target = (second + 1) * soak_rows_per_second;
                let latest_uid = format!("soak-{second:03}-00");
                let offered_us = offer_times[second].load(std::sync::atomic::Ordering::Acquire);
                assert!(offered_us > 0, "paced notice was not offered: {latest_uid}");
                loop {
                    engine.refresh().await.unwrap();
                    let result = engine.broad_npl(&query(&format!("metadata.uid={latest_uid} | stats count"))).await.unwrap();
                    if result["result"]["rows"][0]["count"] == 1 {
                        latest_visibility_ms = soak_started.elapsed().as_micros()
                            .saturating_sub((offered_us - 1) as u128) / 1_000;
                        queried_rows = target;
                        break;
                    }
                    assert!(soak_started.elapsed().as_micros()
                            .saturating_sub((offered_us - 1) as u128) < 120_000_000,
                        "latest offered Bronze row exceeded 120-second query visibility: {latest_uid} {result}");
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                eprintln!("nan2918-soak seconds={} offered_rows={} source_time_s={} queried_at_ms={} latest_query_visible_ms={}",
                    second + 1, queried_rows, source_time_s, chrono::Utc::now().timestamp_millis(), latest_visibility_ms);
                if second == 29 && sample_digest.is_some() {
                    let stamps = engine.broad_npl(&query(&format!("metadata.uid={latest_uid} | table enrichments.provider"))).await.unwrap();
                    assert!(stamps["result"]["rows"].to_string().contains("platform/threatfox"), "sample bundle did not stamp threatfox: {stamps}");
                }
                if second == 119 {
                    let stamps = engine.broad_npl(&query(&format!("metadata.uid={latest_uid} | table enrichments.provider, enriched_dest_country_code"))).await.unwrap();
                    let text = stamps["result"]["rows"].to_string();
                    assert!(text.contains("tenant-a-feed-next") && text.contains("GB"), "tenant source refresh missing: {stamps}");
                    if let Some(digest) = &sample_digest {
                        assert!(!text.contains("platform/threatfox"), "revoked platform stamp remained visible: {stamps}");
                        let set = live(&fx).await;
                        for part in set.parts() {
                            let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
                            let bytes = fx.parts.get(&keys.provenance()).await.unwrap().unwrap();
                            let signed = SignedProvenance::verify_bytes(&bytes, TENANT, &trusted()).unwrap();
                            pinned_update |= signed.record.admission.as_ref().is_some_and(|admission|
                                admission.feed_pins["platform_bundle"].as_deref() == Some(digest.as_str())
                                && admission.feed_pins["ioc_revision"].as_deref() == Some("102"));
                        }
                        assert!(pinned_update, "updated signed L0 did not pin sample bundle and tenant IOC");
                    }
                }
            }
        }
        offer_driver.join().unwrap();
        let offer_us = offer_times.iter().map(|stamp| stamp.load(std::sync::atomic::Ordering::Acquire)).collect::<Vec<_>>();
        let offer_window_ms = (offer_us[soak_seconds - 1] - offer_us[0]) / 1_000;
        let max_offer_gap_ms = offer_us.windows(2).map(|pair| (pair[1] - pair[0]) / 1_000).max().unwrap();
        eprintln!("nan2918-soak offer_window_ms={offer_window_ms} max_offer_gap_ms={max_offer_gap_ms}");
        assert!(offer_window_ms <= 180_000 && max_offer_gap_ms <= 2_000,
            "20 eps notice pacing exceeded 180-second window or 2-second maximum gap");
        assert_eq!(queried_rows, soak_seconds * soak_rows_per_second);
        let all_rows = engine.broad_npl(&query("* | stats count")).await.unwrap();
        assert_eq!(all_rows["result"]["rows"][0]["count"],
            (soak_seconds * soak_rows_per_second + 2) as u64,
            "signed native query lost or duplicated a paced Bronze row: {all_rows}");
        assert!(latest_visibility_ms <= 120_000);
        assert!(running.0.try_wait().unwrap().is_none(), "persistent ingest binary exited during soak");
        eprintln!("nan2918-soak complete offered={} duration_ms={}", queried_rows, soak_started.elapsed().as_millis());
    }
}

fn test_mmdb_bytes() -> Vec<u8> {
    fn text(s: &str) -> Vec<u8> { [vec![0x40 | s.len() as u8], s.as_bytes().to_vec()].concat() }
    fn uint(n: u64, kind: u8) -> Vec<u8> {
        let bytes = n.to_be_bytes();
        let i = bytes.iter().position(|b| *b != 0).unwrap_or(7);
        let mut out = if kind < 8 { vec![(kind << 5) | (8 - i) as u8] } else { vec![(8 - i) as u8, kind - 7] };
        out.extend(&bytes[i..]); out
    }
    fn map(pairs: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
        let mut out = vec![0xe0 | pairs.len() as u8];
        for (k, v) in pairs { out.extend(text(k)); out.extend(v); }
        out
    }
    let us = map(vec![("country", text("United States")), ("country_code", text("US")), ("asn", text("AS64500")),
        ("as_name", text("Fixture network")), ("as_domain", text("fixture.example")),
        ("continent", text("North America")), ("continent_code", text("NA"))]);
    let ca = map(vec![("country", text("Canada")), ("country_code", text("CA")), ("asn", text("AS64501"))]);
    let a = 18_u32;
    let b = a + us.len() as u32;
    let mut bytes = Vec::new();
    for pointer in [1, b, a, b] { bytes.extend(&pointer.to_be_bytes()[1..]); }
    bytes.extend([0; 16]); bytes.extend(us); bytes.extend(ca);
    bytes.extend(b"\xab\xcd\xefMaxMind.com");
    bytes.extend(map(vec![
        ("node_count", uint(2, 6)), ("record_size", uint(24, 5)), ("ip_version", uint(6, 5)),
        ("database_type", text("ipinfo_lite")), ("languages", vec![1, 4, 0x42, b'e', b'n']),
        ("binary_format_major_version", uint(2, 5)), ("binary_format_minor_version", uint(0, 5)),
        ("build_epoch", uint(1_799_999_000, 9)), ("description", map(vec![("en", text("fixture"))])),
    ]));
    bytes
}

#[tokio::test(flavor = "current_thread")]
async fn ingest_merges_and_matches_bronze_per_hour() {
    let fx = fixture(420, 12);
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, DAY0_S * 1_000).await.unwrap();
    drive(&mut ingestor, &fx, &|k, at| {
        fx.spool.deliver(&notice(k, at)).unwrap();
    })
    .await
    .unwrap();
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "every notice acked");
    let rows = live_rows(&fx).await;
    assert_exactly_once(&rows, fx.unique_uids);
    let before = live(&fx).await;
    assert!(before.parts().any(|p| p.level == Level::Minute), "minute merges ran while ingesting");

    // Seal the hours, then the day.
    let mut clock = (DAY0_S + 4 * 3_600) * 1_000;
    for _ in 0..50 {
        ingestor.tick(clock).await.unwrap();
        clock += 1_000;
    }
    let hourly = live(&fx).await;
    assert!(hourly.parts().all(|p| p.level == Level::Hour), "every sealed hour is one hour part");
    let hours = hourly.parts().map(|p| p.event_hour).collect::<Vec<_>>();
    assert_eq!(hours.len(), hours.iter().collect::<HashSet<_>>().len());
    for part in hourly.parts() {
        let keys = PartKeys::new(TENANT, Level::Hour, part.event_hour, &part.part_id).unwrap();
        let provenance = fx.parts.get(&keys.provenance()).await.unwrap().unwrap();
        let signed = SignedProvenance::verify_bytes(&provenance, TENANT, &trusted()).unwrap();
        let sources = signed.record.files.data.iter().filter_map(|file| file.log_sources.as_ref()).collect::<Vec<_>>();
        assert!(sources.iter().any(|values| values == &&vec!["cloudtrail".to_string()]));
        assert!(sources.iter().any(|values| values == &&vec!["windows_event".to_string()]));
        for (index, file) in signed.record.files.data.iter().enumerate() {
            let expected = file.log_sources.as_ref().unwrap();
            let path = fx.root.join("parts").join(keys.data(index));
            let pairs = read_time_uids(&path).unwrap();
            assert!(pairs.windows(2).all(|pair| pair[0] < pair[1]));
            let mut reader = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path).unwrap()).unwrap().build().unwrap();
            for batch in &mut reader {
                let batch = batch.unwrap();
                let values = log_source_strings(&batch).unwrap();
                for row in 0..batch.num_rows() {
                    assert_eq!(values.value(row), expected[0]);
                }
            }
        }
    }
    // A late rewrite can use an already clustered H part as an input. Its
    // files must be merged as separate streams and preserve the logical root.
    let prior = hourly.parts().next().unwrap().clone();
    let prior_keys = PartKeys::new(TENANT, Level::Hour, prior.event_hour, &prior.part_id).unwrap();
    let merged = merge_parts(
        fx.root.as_path(), TENANT, Level::Hour, prior.event_hour,
        &[MergeInput { part: prior.clone(), dir: fx.root.join("parts").join(&prior_keys.dir) }],
        Arc::new(hourly.schema().unwrap().to_arrow().unwrap()), &prior.schema_fingerprint,
        SIGNER_KEY_ID, "source-family-test", DAY0_S * 1_000,
    ).unwrap();
    assert_eq!(merged.finished.record.rows, prior.rows);
    assert_eq!(merged.finished.record.merkle_root, prior.merkle_root);
    let mut clock = (DAY0_S + 26 * 3_600) * 1_000 + 60_000;
    for _ in 0..10 {
        ingestor.tick(clock).await.unwrap();
        clock += 1_000;
    }
    let daily = live(&fx).await;
    let parts = daily.parts().cloned().collect::<Vec<_>>();
    assert_eq!(parts.len(), 1, "the sealed day is one day part");
    assert_eq!(parts[0].level, Level::Day);
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);

    // Admission preserves bronze row counts. Merkle roots intentionally differ
    // because the signed rows now contain immutable ingest-time prevalence.
    let schema = Arc::new(daily.schema().unwrap().to_arrow().unwrap());
    let reference = bronze_reference(&fx, schema);
    let keys = PartKeys::new(TENANT, Level::Day, parts[0].event_hour, &parts[0].part_id).unwrap();
    let provenance = fx.parts.get(&keys.provenance()).await.unwrap().unwrap();
    assert_eq!(sha256_hex(&provenance), parts[0].provenance_sha256);
    let signed = SignedProvenance::verify_bytes(&provenance, TENANT, &trusted()).unwrap();
    parts[0].check_record(&signed.record, &parts[0].provenance_sha256).unwrap();
    assert_eq!(signed.record.signer_key_id, SIGNER_KEY_ID);
    assert_eq!(signed.record.lowercased_at_rest.iter().map(String::as_str).collect::<Vec<_>>(), LOWERCASED_AT_REST);
    let from_record = signed
        .record
        .hours
        .iter()
        .map(|h| (h.event_hour, (h.rows, h.merkle_root.clone())))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(from_record.iter().map(|(hour, (rows, _))| (*hour, *rows)).collect::<BTreeMap<_, _>>(),
        reference.iter().map(|(hour, (rows, _))| (*hour, *rows)).collect::<BTreeMap<_, _>>(),
        "per-hour row counts match bronze after stamping");
    assert!(reference.len() >= 3, "fixture spans several hours");

    // Every file verifies against the record; the token index finds a token.
    for (name, sha, bytes) in signed.record.files.all() {
        let body = fx.parts.get(&keys.file(name)).await.unwrap().unwrap();
        assert_eq!((sha256_hex(&body).as_str(), body.len() as u64), (sha, bytes), "{name}");
    }
    let tokens = decode_token_index(&fx.parts.get(&keys.tokens(0)).await.unwrap().unwrap()).unwrap();
    assert_eq!(tokens.len() as u32, signed.record.files.data[0].row_groups);
    assert!(tokens.iter().any(|g| g.may_contain_all(&["mimikatz".into(), "marker".into()])));
    assert!(tokens.iter().all(|g| !g.may_contain_all(&["zzqqxyzzy-absent-token".into()])));
}

#[tokio::test(flavor = "current_thread")]
async fn signed_l0_stamps_use_prior_tenant_state_across_restart() {
    assert_eq!(stamps_after_restart(false).await, vec![1, 1, 2]);
}

/// A lost tenant DB is rebuilt from the provenance-verified live set: the
/// third host still sees the two earlier hosts, counted once.
#[tokio::test(flavor = "current_thread")]
async fn missing_state_rebuilds_from_signed_live_parts() {
    assert_eq!(stamps_after_restart(true).await, vec![1, 1, 2]);
}

async fn stamps_after_restart(lose_state: bool) -> Vec<u64> {
    let fx = fixture(3, 1);
    write_stamp_sources(&fx);
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, DAY0_S * 1_000).await.unwrap();
    for (key, at) in fx.objects.iter().take(2) {
        fx.spool.deliver(&notice(key, *at)).unwrap();
        ingestor.tick(at * 1_000).await.unwrap();
        ingestor.flush_now(at * 1_000).await.unwrap();
    }
    drop(ingestor);
    if lose_state {
        std::fs::remove_dir_all(fx.root.join("work/prevalence").join(TENANT)).unwrap();
    }
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, (DAY0_S + 2_500) * 1_000).await.unwrap();
    let (key, at) = &fx.objects[2];
    let accepted_at = Instant::now();
    fx.spool.deliver(&notice(key, *at)).unwrap();
    ingestor.tick(at * 1_000).await.unwrap();
    ingestor.flush_now(at * 1_000).await.unwrap();

    let stamps = dest_ip_stamps(&fx).await.into_iter().map(|stamp| stamp.expect("stamped")).collect();
    eprintln!("local accepted event to signed, searchable part stamp: {:.3} s", accepted_at.elapsed().as_secs_f64());
    stamps
}

/// Every live row's `prevalence_dest_ip`, sorted; `None` when unstamped.
async fn dest_ip_stamps(fx: &Fixture) -> Vec<Option<u64>> {
    let mut stamps = Vec::new();
    for part in live(fx).await.parts() {
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        let bytes = fx.parts.get(&keys.provenance()).await.unwrap().unwrap();
        SignedProvenance::verify_bytes(&bytes, TENANT, &trusted()).unwrap();
        for index in 0..part.data_files as usize {
            let path = fx.root.join("parts").join(keys.data(index));
            let reader = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path).unwrap()).unwrap().build().unwrap();
            for batch in reader {
                let batch = batch.unwrap();
                let Some(column) = batch.column_by_name("prevalence_dest_ip") else {
                    stamps.extend((0..batch.num_rows()).map(|_| None));
                    continue;
                };
                let stamp = arrow_cast::cast(column.as_ref(), &arrow_schema::DataType::UInt64).unwrap();
                let stamp = stamp.as_any().downcast_ref::<arrow_array::UInt64Array>().unwrap();
                stamps.extend((0..batch.num_rows()).map(|row| arrow_array::Array::is_valid(stamp, row).then(|| stamp.value(row))));
            }
        }
    }
    stamps.sort_unstable();
    stamps
}

fn write_stamp_sources(fx: &Fixture) {
    for (index, (key, at)) in fx.objects.iter().enumerate() {
        let mut value = event(&format!("stamp-{index}"), *at, index);
        value["dst_endpoint"]["ip"] = json!("8.8.8.8");
        value["src_endpoint"]["hostname"] = json!(format!("host-{index}"));
        write_bronze(&fx.root.join("sources").join(key), &[value]);
    }
}

/// A state write that fails after its `Add` committed must not fail the
/// flush: a retry would re-consume the sources (DoubleConsume, fatal). The
/// entry stays pending, merges wait, and the next tick replays it once.
#[tokio::test(flavor = "current_thread")]
async fn prevalence_apply_failure_after_commit_replays_instead_of_failing_the_flush() {
    let fx = fixture(3, 1);
    write_stamp_sources(&fx);
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, DAY0_S * 1_000).await.unwrap();
    let (key, at) = &fx.objects[0];
    fx.spool.deliver(&notice(key, *at)).unwrap();
    ingestor.tick(at * 1_000).await.unwrap();
    ingestor.flush_now(at * 1_000).await.unwrap();

    let (key, at) = &fx.objects[1];
    ingestor.fail_next_prevalence_apply();
    fx.spool.deliver(&notice(key, *at)).unwrap();
    ingestor.tick(at * 1_000).await.unwrap();
    ingestor.flush_now(at * 1_000).await.unwrap();
    assert!(ingestor.prevalence_pending(), "the failed apply stays pending");
    ingestor.tick(at * 1_000 + 1).await.unwrap();
    assert!(!ingestor.prevalence_pending(), "the next tick replays the committed add");

    let (key, at) = &fx.objects[2];
    fx.spool.deliver(&notice(key, *at)).unwrap();
    ingestor.tick(at * 1_000).await.unwrap();
    ingestor.flush_now(at * 1_000).await.unwrap();
    assert_eq!(dest_ip_stamps(&fx).await, vec![Some(1), Some(1), Some(2)]);
}

async fn open_with<'a>(fx: &'a Fixture, cfg: IngestConfig, now_ms: i64) -> Result<Ingestor<'a>> {
    Ingestor::open(cfg, &fx.parts, &fx.sources, &fx.spool, &fx.signer, trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await
}

/// A lost (or first-enabled) tenant DB rebuilds in the background. Ingest
/// keeps publishing unstamped rows meanwhile: a stamp is permanent, so a
/// half-rebuilt count must never be saved. A restart resumes the saved part
/// list; stamping starts once the state reaches the log head.
#[tokio::test(flavor = "current_thread")]
async fn background_rebuild_keeps_ingest_visible_and_stamps_only_when_complete() {
    let fx = fixture(4, 1);
    write_stamp_sources(&fx);
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, DAY0_S * 1_000).await.unwrap();
    assert_eq!(ingestor.prevalence_status(), "stamping", "a tenant with no parts stamps at once");
    for (key, at) in fx.objects.iter().take(2) {
        fx.spool.deliver(&notice(key, *at)).unwrap();
        ingestor.tick(at * 1_000).await.unwrap();
        ingestor.flush_now(at * 1_000).await.unwrap();
    }
    drop(ingestor);
    std::fs::remove_dir_all(fx.root.join("work/prevalence").join(TENANT)).unwrap();

    // Slowest possible rebuild: one part per tick.
    let slow = || {
        let mut cfg = config(&fx.root);
        cfg.prevalence_rebuild_budget_ms = 0;
        cfg
    };
    let now = (DAY0_S + 2_500) * 1_000;
    let mut ingestor = open_with(&fx, slow(), now).await.unwrap();
    assert_eq!(ingestor.prevalence_status(), "unstamped: rebuilding (0/2 parts)");
    let (key, at) = &fx.objects[2];
    fx.spool.deliver(&notice(key, *at)).unwrap();
    ingestor.tick(at * 1_000).await.unwrap();
    ingestor.flush_now(at * 1_000).await.unwrap();
    assert_eq!(ingestor.prevalence_status(), "unstamped: rebuilding (1/2 parts)");
    assert_eq!(live(&fx).await.parts().count(), 3, "the part admitted mid-rebuild is visible");
    assert_eq!(dest_ip_stamps(&fx).await, vec![None, Some(1), Some(1)], "no stamp before the rebuild completes");

    // A restart mid-rebuild resumes the saved list at its cursor.
    drop(ingestor);
    let mut ingestor = open_with(&fx, slow(), now).await.unwrap();
    assert_eq!(ingestor.prevalence_status(), "unstamped: rebuilding (1/2 parts)");
    ingestor.tick(at * 1_000 + 1).await.unwrap();
    assert_eq!(ingestor.prevalence_status(), "unstamped: catching up with committed adds");
    ingestor.tick(at * 1_000 + 2).await.unwrap();
    assert_eq!(ingestor.prevalence_status(), "stamping");

    // Stamped from the next part: hosts 0-2, each counted once.
    let (key, at) = &fx.objects[3];
    fx.spool.deliver(&notice(key, *at)).unwrap();
    ingestor.tick(at * 1_000).await.unwrap();
    ingestor.flush_now(at * 1_000).await.unwrap();
    assert_eq!(dest_ip_stamps(&fx).await, vec![None, Some(1), Some(1), Some(3)]);
}

/// Tick at `clock` (ms) until every live part is one sealed `h` part per
/// hour (bounded).
async fn seal_hours(ingestor: &mut Ingestor<'_>, fx: &Fixture, mut clock: i64) -> i64 {
    for _ in 0..50 {
        ingestor.tick(clock).await.unwrap();
        clock += 1_000;
        if live(fx).await.parts().all(|p| p.level == Level::Hour) {
            break;
        }
    }
    assert!(live(fx).await.parts().all(|p| p.level == Level::Hour), "every hour sealed");
    clock
}

/// NAN-3864 (tenant-a 2026-10-14, 05Z-21:35Z): rows committed while the
/// state was behind the log head stayed null forever. Ingest still never
/// waits on prevalence, but their hour is owed a restamp, and once the state
/// is at the head the hour's seal merge stamps exactly those rows (stamped
/// rows never change). The value reads the state at restamp time: here host 2's
/// row counts hosts 0-2 (3), never fewer than its arrival count (2).
#[tokio::test(flavor = "current_thread")]
async fn rows_committed_while_behind_are_restamped_once_the_state_is_at_the_head() {
    let fx = fixture(3, 1);
    write_stamp_sources(&fx);
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, DAY0_S * 1_000).await.unwrap();
    for (key, at) in fx.objects.iter().take(2) {
        fx.spool.deliver(&notice(key, *at)).unwrap();
        ingestor.tick(at * 1_000).await.unwrap();
        ingestor.flush_now(at * 1_000).await.unwrap();
    }
    drop(ingestor);
    std::fs::remove_dir_all(fx.root.join("work/prevalence").join(TENANT)).unwrap();
    let mut cfg = config(&fx.root);
    cfg.prevalence_rebuild_budget_ms = 0;
    let now = (DAY0_S + 2_500) * 1_000;
    let mut ingestor = open_with(&fx, cfg, now).await.unwrap();
    assert_eq!(ingestor.prevalence_status(), "unstamped: rebuilding (0/2 parts)");
    let (key, at) = &fx.objects[2];
    fx.spool.deliver(&notice(key, *at)).unwrap();
    let admitted = Instant::now();
    ingestor.tick(at * 1_000).await.unwrap();
    ingestor.flush_now(at * 1_000).await.unwrap();
    assert!(admitted.elapsed() < std::time::Duration::from_secs(5), "ingest never waits on the behind state");
    assert_eq!(dest_ip_stamps(&fx).await, vec![None, Some(1), Some(1)], "committed unstamped while behind");
    let hour = event_hour_of(at * 1_000_000);
    assert_eq!(ingestor.prevalence_owed_hours(), vec![hour], "its hour is owed a restamp");
    for _ in 0..200 {
        if ingestor.prevalence_status() == "stamping" { break; }
        ingestor.tick(at * 1_000 + 1).await.unwrap();
    }
    assert_eq!(ingestor.prevalence_status(), "stamping");

    // Review P1: a minute merge of the owed hour (its L0s, before the hour
    // seals) is on the freshness path and does no lookups; the hour stays
    // owed for its seal.
    let mut clock = at * 1_000 + 120_000;
    for _ in 0..20 {
        if live(&fx).await.parts().any(|p| p.level == Level::Minute) { break; }
        ingestor.tick(clock).await.unwrap();
        clock += 1_000;
    }
    assert!(live(&fx).await.parts().any(|p| p.level == Level::Minute), "the owed hour's L0s merged into m");
    assert!(live(&fx).await.parts().all(|p| p.level != Level::Hour), "the hour is not sealed yet");
    assert_eq!(ingestor.health().prevalence_restamped_rows_total, 0, "no restamp on a minute merge");
    assert_eq!(dest_ip_stamps(&fx).await, vec![None, Some(1), Some(1)], "still unstamped until the seal");
    assert_eq!(ingestor.prevalence_owed_hours(), vec![hour], "still owed");

    seal_hours(&mut ingestor, &fx, (DAY0_S + 4 * 3_600) * 1_000).await;
    assert_eq!(dest_ip_stamps(&fx).await, vec![Some(1), Some(1), Some(3)], "the seal merge restamped only the unstamped row");
    assert!(ingestor.prevalence_owed_hours().is_empty(), "the sealed hour is cleared");
    assert_eq!(ingestor.health().prevalence_restamped_rows_total, 1);
    assert_eq!(ingestor.health().prevalence_restamp_rewrites_total, 0, "no extra rewrite: the seal merge carried it");
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
}

/// NAN-3879 (production, 2026-10-15, 08:11Z/09:00Z/10:00Z): a post-commit apply cut
/// at the ingest wait leaves its `Add` pending. A stamp is permanent, so a
/// batch admitted then must never be stamped from the state that misses those
/// rows (it would read first-seen artifacts as never seen: false rarity). It
/// is committed unstamped, its hours are owed, and once the state is at the
/// head the hour seal restamps it exactly. This models the hour roll: the
/// batch straddles 01:00Z, so both hours are owed, and the admission never
/// waits long on the overrunning state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rows_at_the_hour_roll_admitted_behind_a_cut_apply_are_owed_and_restamped_exactly() {
    use nanosiem_lake_worker::part_ingest::ingest::PREVALENCE_ADMIT_OVERRUN_WAITS;
    let fx = fixture(1, 1);
    let roll_s = DAY0_S + 3_600;
    // Event times per object: two before the roll, then one straddling it.
    // One distinct host per row, all to 8.8.8.8.
    let objects: [&[i64]; 3] = [&[roll_s - 40], &[roll_s - 20], &[roll_s - 2, roll_s + 2]];
    let mut host = 0;
    let keys = objects.iter().enumerate().map(|(index, times)| {
        let events = times.iter().map(|time| {
            host += 1;
            let mut value = event(&format!("roll-{index}-{host}"), *time, host);
            value["dst_endpoint"]["ip"] = json!("8.8.8.8");
            value["src_endpoint"]["hostname"] = json!(format!("host-{host}"));
            value
        }).collect::<Vec<_>>();
        let key = format!("bronze/roll-{index}.parquet");
        write_bronze(&fx.root.join("sources").join(&key), &events);
        (key, times[times.len() - 1] + 5)
    }).collect::<Vec<_>>();
    let wait = std::time::Duration::from_millis(300);
    let mut cfg = config(&fx.root);
    cfg.prevalence_ingest_wait = wait;
    let mut ingestor = open_with(&fx, cfg, (roll_s - 60) * 1_000).await.unwrap();
    assert_eq!(ingestor.prevalence_status(), "stamping");
    let bound = wait * (2 + PREVALENCE_ADMIT_OVERRUN_WAITS) + std::time::Duration::from_secs(3);
    let step = |index: usize| {
        let (key, at) = keys[index].clone();
        fx.spool.deliver(&notice(&key, at)).unwrap();
        at * 1_000
    };

    let now = step(0);
    ingestor.tick(now).await.unwrap();
    ingestor.flush_now(now).await.unwrap();
    // Object 1's post-commit apply and the next catch-up step overrun.
    ingestor.stall_next_prevalence_ops(2);
    let now = step(1);
    ingestor.tick(now).await.unwrap();
    ingestor.flush_now(now).await.unwrap();
    assert!(ingestor.prevalence_pending(), "the cut apply stays pending");

    // The hour-roll batch, admitted while object 1's add is not in the state.
    let now = step(2);
    let started = Instant::now();
    ingestor.tick(now).await.unwrap();
    ingestor.flush_now(now).await.unwrap();
    assert!(started.elapsed() < bound, "admission waited {:?}", started.elapsed());
    assert_eq!(dest_ip_stamps(&fx).await, vec![None, None, Some(1), Some(1)], "never stamped from a state missing object 1");
    let hours = vec![event_hour_of((roll_s - 2) * 1_000_000), event_hour_of((roll_s + 2) * 1_000_000)];
    assert_ne!(hours[0], hours[1], "the batch straddles the roll");
    assert_eq!(ingestor.prevalence_owed_hours(), hours, "both hours of the roll are owed");
    assert!(ingestor.health().prevalence_unstamped_batches_total >= 1);

    // The store answers again: the state reaches the head, and the seal of
    // each owed hour restamps exactly the unstamped rows, counting every
    // host in the state (objects 0-2: 4 hosts).
    let mut clock = now + 1_000;
    for _ in 0..20 {
        if ingestor.prevalence_status() == "stamping" && !ingestor.prevalence_pending() { break; }
        ingestor.tick(clock).await.unwrap();
        clock += 1_000;
    }
    assert_eq!(ingestor.prevalence_status(), "stamping");
    assert!(!ingestor.prevalence_pending());
    seal_hours(&mut ingestor, &fx, (roll_s + 4 * 3_600) * 1_000).await;
    assert_eq!(dest_ip_stamps(&fx).await, vec![Some(1), Some(1), Some(4), Some(4)], "restamped exactly at the seal");
    assert!(ingestor.prevalence_owed_hours().is_empty(), "both sealed hours are cleared");
    assert_eq!(ingestor.health().prevalence_restamped_rows_total, 2);
}

/// NAN-3864: the owed set survives a restart (it is saved in the tenant
/// bucket), so a roll in the middle of a catch-up does not forget the rows
/// it left unstamped.
#[tokio::test(flavor = "current_thread")]
async fn owed_restamp_hours_survive_a_restart() {
    let fx = fixture(3, 1);
    write_stamp_sources(&fx);
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, DAY0_S * 1_000).await.unwrap();
    for (key, at) in fx.objects.iter().take(2) {
        fx.spool.deliver(&notice(key, *at)).unwrap();
        ingestor.tick(at * 1_000).await.unwrap();
        ingestor.flush_now(at * 1_000).await.unwrap();
    }
    drop(ingestor);
    std::fs::remove_dir_all(fx.root.join("work/prevalence").join(TENANT)).unwrap();
    let mut cfg = config(&fx.root);
    cfg.prevalence_rebuild_budget_ms = 0;
    let mut ingestor = open_with(&fx, cfg, (DAY0_S + 2_500) * 1_000).await.unwrap();
    let (key, at) = &fx.objects[2];
    fx.spool.deliver(&notice(key, *at)).unwrap();
    ingestor.tick(at * 1_000).await.unwrap();
    ingestor.flush_now(at * 1_000).await.unwrap();
    let owed = ingestor.prevalence_owed_hours();
    assert_eq!(owed, vec![event_hour_of(at * 1_000_000)]);
    // The next tick saves the set to the tenant bucket; then the process
    // goes away mid-catch-up (a roll).
    ingestor.tick(at * 1_000 + 1).await.unwrap();
    drop(ingestor);

    let mut ingestor = open(&fx, &fx.spool, &fx.parts, (DAY0_S + 2_600) * 1_000).await.unwrap();
    let mut clock = (DAY0_S + 2_600) * 1_000;
    while ingestor.prevalence_status() != "stamping" || ingestor.prevalence_owed_hours().is_empty() {
        ingestor.tick(clock).await.unwrap();
        clock += 1;
        assert!(clock < (DAY0_S + 2_600) * 1_000 + 50, "the owed hour was not restored");
    }
    assert_eq!(ingestor.prevalence_owed_hours(), owed, "the restarted process still owes the hour");
    seal_hours(&mut ingestor, &fx, (DAY0_S + 4 * 3_600) * 1_000).await;
    assert_eq!(dest_ip_stamps(&fx).await, vec![Some(1), Some(1), Some(3)], "stamped after the restart");
    assert!(ingestor.prevalence_owed_hours().is_empty());
}

/// NAN-3864 gap backfill (the tenant-a window 2026-10-14 05Z-21:35Z): hours that
/// were sealed with unstamped rows before the restamp existed are queued by
/// the operator and rewritten one sealed hour at a time; rows stamped on
/// arrival keep their stamp. A second request finds nothing owed and skips
/// the rewrite (the part is not replaced).
#[tokio::test(flavor = "current_thread")]
async fn an_operator_window_restamps_sealed_hours_ingested_unstamped() {
    let fx = fixture(3, 1);
    write_stamp_sources(&fx);
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, DAY0_S * 1_000).await.unwrap();
    let (key, at) = &fx.objects[0];
    fx.spool.deliver(&notice(key, *at)).unwrap();
    ingestor.tick(at * 1_000).await.unwrap();
    ingestor.flush_now(at * 1_000).await.unwrap();
    drop(ingestor);
    // The old behaviour: rows written with no stamp and nothing owed (no
    // grant here stands in for the pre-fix binary).
    let mut cfg = config(&fx.root);
    cfg.prevalence_enabled = false;
    let mut ingestor = open_with(&fx, cfg, (DAY0_S + 2_500) * 1_000).await.unwrap();
    for (key, at) in fx.objects.iter().skip(1) {
        fx.spool.deliver(&notice(key, *at)).unwrap();
        ingestor.tick(at * 1_000).await.unwrap();
        ingestor.flush_now(at * 1_000).await.unwrap();
    }
    let clock = seal_hours(&mut ingestor, &fx, (DAY0_S + 4 * 3_600) * 1_000).await;
    assert!(ingestor.prevalence_owed_hours().is_empty(), "no grant: nothing owed");
    drop(ingestor);
    assert_eq!(dest_ip_stamps(&fx).await, vec![None, None, Some(1)]);

    let mut ingestor = open(&fx, &fx.spool, &fx.parts, clock).await.unwrap();
    let mut clock = clock;
    for _ in 0..200 {
        if ingestor.prevalence_status() == "stamping" { break; }
        ingestor.tick(clock).await.unwrap();
        clock += 1_000;
    }
    assert_eq!(ingestor.prevalence_status(), "stamping");
    let sealed = live(&fx).await.parts().cloned().collect::<Vec<_>>();
    // Review P1: a window starting more than 7 days ago is refused (its
    // rows would read as never seen and be stamped rare).
    let stale = nanosiem_lake_worker::part_ingest::reindex::CountBackfill {
        start_ms: DAY0_S * 1_000, end_ms: clock - 1 };
    let error = ingestor.queue_prevalence_restamp(stale, DAY0_S * 1_000 + 7 * 86_400_000 + 1).unwrap_err();
    assert!(error.to_string().contains("7 days"), "{error:#}");
    assert!(ingestor.prevalence_owed_hours().is_empty(), "a refused window marks nothing");
    let window = nanosiem_lake_worker::part_ingest::reindex::CountBackfill { start_ms: DAY0_S * 1_000, end_ms: clock - 1 };
    let hours = ingestor.queue_prevalence_restamp(window.clone(), clock).unwrap();
    assert_eq!(hours, sealed.iter().map(|p| p.event_hour).collect::<Vec<_>>());
    for _ in 0..5 {
        ingestor.tick(clock).await.unwrap();
        clock += 1_000;
    }
    assert_eq!(dest_ip_stamps(&fx).await, vec![Some(1), Some(3), Some(3)], "only the unstamped rows changed");
    assert!(ingestor.prevalence_owed_hours().is_empty());
    assert_eq!(ingestor.health().prevalence_restamp_rewrites_total, 1);
    assert_eq!(ingestor.health().prevalence_restamped_rows_total, 2);
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);

    // Nothing left to restamp: no rewrite, the part stays.
    let restamped = live(&fx).await.parts().map(|p| p.part_id.clone()).collect::<Vec<_>>();
    clock += 60_000;
    ingestor.queue_prevalence_restamp(window, clock).unwrap();
    for _ in 0..5 {
        ingestor.tick(clock).await.unwrap();
        clock += 1_000;
    }
    assert!(ingestor.prevalence_owed_hours().is_empty());
    assert_eq!(live(&fx).await.parts().map(|p| p.part_id.clone()).collect::<Vec<_>>(), restamped);
    assert_eq!(ingestor.health().prevalence_restamp_rewrites_total, 1);
}

/// Until the platform serves the prevalence owner, a production exchange has no
/// prevalence grant. Ingest must keep running, unstamped (search reads N/A).
#[tokio::test(flavor = "current_thread")]
async fn without_a_prevalence_grant_ingest_runs_unstamped() {
    let fx = fixture(3, 1);
    write_stamp_sources(&fx);
    let mut cfg = config(&fx.root);
    cfg.prevalence_enabled = false;
    let mut ingestor = open_with(&fx, cfg, DAY0_S * 1_000).await.unwrap();
    assert_eq!(ingestor.prevalence_status(), "unstamped: no prevalence grant");
    for (key, at) in &fx.objects {
        fx.spool.deliver(&notice(key, *at)).unwrap();
        ingestor.tick(at * 1_000).await.unwrap();
        ingestor.flush_now(at * 1_000).await.unwrap();
    }
    assert_eq!(dest_ip_stamps(&fx).await, vec![None, None, None]);
    assert!(!ingestor.prevalence_pending());
    assert!(!fx.root.join("work/prevalence").exists(), "no tenant prevalence state is opened");
}

/// NAN-3017: a refreshed exchange that withholds the prevalence grant must
/// not leave the state on a credential that is about to expire. The state is
/// closed (suspended) and ingest keeps running unstamped, like a process that
/// started without a grant.
#[tokio::test(flavor = "current_thread")]
async fn withdrawn_prevalence_grant_suspends_stamping_and_ingest_keeps_running() {
    let fx = fixture(3, 1);
    write_stamp_sources(&fx);
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, DAY0_S * 1_000).await.unwrap();
    assert_eq!(ingestor.prevalence_status(), "stamping");
    let (key, at) = &fx.objects[0];
    fx.spool.deliver(&notice(key, *at)).unwrap();
    ingestor.tick(at * 1_000).await.unwrap();
    ingestor.flush_now(at * 1_000).await.unwrap();
    assert!(ingestor.suspend_prevalence().await, "a live state is suspended");
    assert!(!ingestor.suspend_prevalence().await, "suspending twice is a no-op");
    assert_eq!(ingestor.prevalence_status(), "unstamped: no prevalence grant");
    for (key, at) in fx.objects.iter().skip(1) {
        fx.spool.deliver(&notice(key, *at)).unwrap();
        ingestor.tick(at * 1_000).await.unwrap();
        ingestor.flush_now(at * 1_000).await.unwrap();
    }
    let mut stamps = dest_ip_stamps(&fx).await;
    stamps.sort();
    assert_eq!(stamps, vec![None, None, Some(1)], "one row stamped before, two unstamped after the withdrawal");
    assert!(!ingestor.prevalence_pending());
}

/// A queue/store wrapper that fails the Nth call of an operation.
struct Faulty<'a> {
    spool: &'a SpoolQueue,
    parts: &'a LocalObjectStore,
    fail_ack_at: AtomicUsize,
    fail_put_at: AtomicUsize,
    acks: AtomicUsize,
    puts: AtomicUsize,
}

#[async_trait]
impl NoticeQueue for Faulty<'_> {
    async fn pending(&self, max: usize) -> Result<Vec<(NoticeHandle, SourceNotice)>> {
        self.spool.pending(max).await
    }
    async fn ack(&self, handles: &[NoticeHandle]) -> Result<()> {
        if self.acks.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_ack_at.load(Ordering::SeqCst) {
            anyhow::bail!("injected crash before ack");
        }
        self.spool.ack(handles).await
    }
}

#[async_trait]
impl ObjectStore for Faulty<'_> {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.parts.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        if self.puts.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_put_at.load(Ordering::SeqCst) {
            anyhow::bail!("injected crash mid-publish");
        }
        self.parts.put_if_absent(key, bytes).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.parts.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.parts.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.parts.list(prefix).await
    }
}

#[tokio::test]
async fn cold_restart_defers_dedup_reads_and_preserves_exactly_once() {
    let fx = fixture(2, 10);
    let now = (DAY0_S + 2_500) * 1_000;
    for (key, at) in &fx.objects {
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, now).await.unwrap();
    ingestor.tick(now).await.unwrap();
    ingestor.flush_now(now + 11_000).await.unwrap();
    drop(ingestor);

    // A new source object carries the same UIDs, so source receipt dedup
    // alone cannot protect this replay after a cold process start.
    let (original, _) = &fx.objects[0];
    let replay = "bronze/cold-restart-replay.parquet";
    let bytes = fx.sources.get(original).await.unwrap().unwrap();
    fx.sources.put(replay, &bytes).await.unwrap();
    fx.spool.deliver(&notice(replay, DAY0_S + 2_520)).unwrap();
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, now + 20_000).await.unwrap();
    assert_eq!(ingestor.window_uids(), 0, "opening must not scan historical part data");
    ingestor.tick(now + 20_000).await.unwrap();
    ingestor.flush_now(now + 31_000).await.unwrap();
    assert!(fx.spool.pending(1).await.unwrap().is_empty());
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
}

#[tokio::test(flavor = "current_thread")]
async fn crash_at_every_commit_hop_replays_without_duplicates() {
    let fx = fixture(120, 10);
    for (key, at) in &fx.objects {
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    let faulty = Faulty {
        spool: &fx.spool,
        parts: &fx.parts,
        fail_ack_at: AtomicUsize::new(0),
        fail_put_at: AtomicUsize::new(0),
        acks: AtomicUsize::new(0),
        puts: AtomicUsize::new(0),
    };
    let mut clock = (DAY0_S + 2_400) * 1_000;
    let mut crashes = 0;
    // Alternate the injected crash point: after the log commit but before
    // the ack (every row then replays as a duplicate), and mid-publish (the
    // part files are orphans that no log entry names).
    for round in 0..40 {
        if fx.spool.pending(1).await.unwrap().is_empty() {
            break;
        }
        faulty.acks.store(0, Ordering::SeqCst);
        faulty.puts.store(0, Ordering::SeqCst);
        match round % 3 {
            0 => faulty.fail_ack_at.store(1, Ordering::SeqCst),
            1 => faulty.fail_put_at.store(3, Ordering::SeqCst),
            _ => {
                faulty.fail_ack_at.store(usize::MAX, Ordering::SeqCst);
                faulty.fail_put_at.store(usize::MAX, Ordering::SeqCst);
            }
        }
        let mut ingestor = open(&fx, &faulty, &faulty, clock).await.unwrap();
        let mut result = Ok(());
        for _ in 0..3 {
            clock += 11_000;
            if let Err(error) = ingestor.tick(clock).await {
                result = Err(error);
                break;
            }
        }
        if result.is_err() {
            crashes += 1;
        }
        drop(ingestor); // the process "dies": buffer and window are lost
    }
    faulty.fail_ack_at.store(usize::MAX, Ordering::SeqCst);
    faulty.fail_put_at.store(usize::MAX, Ordering::SeqCst);
    let mut ingestor = open(&fx, &faulty, &faulty, clock).await.unwrap();
    for _ in 0..20 {
        clock += 11_000;
        ingestor.tick(clock).await.unwrap();
    }
    ingestor.flush_now(clock).await.unwrap();
    assert!(crashes >= 5, "the test injected crashes ({crashes})");
    assert!(fx.spool.pending(1).await.unwrap().is_empty());
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
}

#[tokio::test(flavor = "multi_thread")]
async fn kill_9_replay_has_no_duplicates() {
    let fx = fixture(200, 10);
    for (key, at) in &fx.objects {
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    let key_file = fx.root.join("key.hex");
    std::fs::write(&key_file, hex::encode(key().to_bytes())).unwrap();
    let args = |extra: &[&str]| {
        let mut args = vec![
            "run".to_string(),
            "--tenant-id".into(), TENANT.into(),
            "--signing-key-file".into(), key_file.display().to_string(),
            "--signer-key-id".into(), SIGNER_KEY_ID.into(),
            "--parts-dir".into(), fx.root.join("parts").display().to_string(),
            "--sources-dir".into(), fx.root.join("sources").display().to_string(),
            "--spool-dir".into(), fx.root.join("spool").display().to_string(),
            "--work-dir".into(), fx.root.join("work").display().to_string(),
            "--tick-ms".into(), "5".into(),
            "--flush-ms".into(), "40".into(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        args
    };
    let bin = env!("CARGO_BIN_EXE_lake_part_ingest");
    let mut kills = 0;
    for round in 0..12_u64 {
        if fx.spool.pending(1).await.unwrap().is_empty() {
            break;
        }
        let mut child = std::process::Command::new(bin).args(args(&[])).spawn().unwrap();
        // Pseudo-random kill points between 60 and 700 ms.
        let delay = 60 + (round * 7_919 % 640);
        std::thread::sleep(std::time::Duration::from_millis(delay));
        // SIGKILL: no destructor, no flush, no ack.
        unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
        let _ = child.wait();
        kills += 1;
    }
    let status = std::process::Command::new(bin).args(args(&["--exit-when-idle"])).status().unwrap();
    assert!(status.success());
    assert!(kills >= 3, "the test killed the process ({kills})");
    assert!(fx.spool.pending(1).await.unwrap().is_empty());
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
}

#[test]
fn fixture_objects_pass_bronze_admission() {
    let fx = fixture(2, 3);
    let admission = admit_bronze_files(&[fx.root.join("sources").join(&fx.objects[0].0)], TENANT);
    assert!(admission.is_ok(), "{:#}", admission.err().unwrap());
}

/// Every live row's `message`, by uid, read back from the part store.
async fn live_messages(fx: &Fixture) -> BTreeMap<String, String> {
    use arrow_array::Array as _;
    let set = live(fx).await;
    let mut out = BTreeMap::new();
    let scratch = tempfile::tempdir().unwrap();
    for part in set.parts() {
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        for index in 0..part.data_files as usize {
            let bytes = fx.parts.get(&keys.data(index)).await.unwrap().unwrap();
            let path = scratch.path().join(format!("{}-{index}.parquet", part.part_id));
            std::fs::write(&path, bytes).unwrap();
            let reader = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&path).unwrap()).unwrap().build().unwrap();
            for batch in reader {
                let batch = batch.unwrap();
                let uids = nanosiem_lake_worker::part_ingest::writer::uid_strings(&batch).unwrap();
                let message = batch.column_by_name("message").unwrap();
                let message = arrow_cast::cast(message, &arrow_schema::DataType::Utf8).unwrap();
                let message = message.as_any().downcast_ref::<arrow_array::StringArray>().unwrap();
                for i in 0..batch.num_rows() {
                    if !message.is_null(i) {
                        out.insert(uids.value(i).to_string(), message.value(i).to_string());
                    }
                }
            }
        }
    }
    out
}

/// NAN-3704: a cross-batch duplicate is still dropped (the first row is
/// kept), but one whose payload differs from the kept row's is counted in
/// `same_uid_payload_diff_total`; an identical payload (or one differing only
/// in `logged_time`, which the in-batch normalisation excludes) is a plain
/// duplicate. In-batch merges are unchanged and never counted there.
#[tokio::test(flavor = "current_thread")]
async fn cross_batch_same_uid_payload_diff_is_counted_and_the_first_row_kept() {
    let fx = fixture(1, 3);
    let t0 = DAY0_S * 1_000;
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, t0).await.unwrap();
    let (key, at) = fx.objects[0].clone();
    fx.spool.deliver(&notice(&key, at)).unwrap();
    assert_eq!(ingestor.tick(at * 1_000).await.unwrap().admitted_rows, 3);
    let before = live_messages(&fx).await;
    assert!(before.is_empty(), "nothing committed before the flush");

    // The fixture's rows, rebuilt exactly (fixture(1, _) is all "late").
    let original = |r: i64| event(&format!("uid-00000-{r:04}"), DAY0_S + 60 + r, r as usize + 1);
    let identical = original(0);
    let mut changed = original(1);
    changed["message"] = json!("a different event under the same uid");
    let mut relogged = original(2);
    relogged["metadata"]["logged_time"] = json!(1_790_294_999_000_i64);
    // In-batch: one new uid twice, differing only in logged_time (merged by
    // admission, as before).
    let mut fresh = event("uid-fresh", DAY0_S + 70, 4);
    fresh["metadata"]["logged_time"] = json!(1_790_294_470_000_i64);
    let mut fresh_retry = fresh.clone();
    fresh_retry["metadata"]["logged_time"] = json!(1_790_294_471_000_i64);
    let second = format!("bronze/{}-second.parquet", at + 20);
    write_bronze(&fx.root.join("sources").join(&second), &[identical, changed, relogged, fresh, fresh_retry]);
    fx.spool.deliver(&notice(&second, at + 20)).unwrap();
    let report = ingestor.tick((at + 20) * 1_000).await.unwrap();
    assert_eq!(report.admitted_rows, 4, "four identities after the in-batch merge");
    assert_eq!(report.duplicates, 3);
    ingestor.flush_now((at + 40) * 1_000).await.unwrap();

    let health = ingestor.health();
    assert_eq!(health.duplicates_dropped_total, 3, "every cross-batch duplicate is still dropped");
    assert_eq!(health.same_uid_payload_diff_total, 1, "only the changed payload counts");
    assert_exactly_once(&live_rows(&fx).await, 4);
    let messages = live_messages(&fx).await;
    let kept = &messages["uid-00000-0001"];
    assert!(!kept.contains("different event"), "the first row is kept: {kept}");
    assert!(messages.contains_key("uid-fresh"));
}

/// NAN-3719: two rows of one object under the same uid with different
/// source identities (two identical non-JSON lines through a raw-hash
/// fallback, or two cutover probes) used to refuse the whole object, every
/// unrelated row with it. Now one copy is kept, the other is dropped and
/// counted in `same_uid_payload_diff_total`, and the other 100 rows commit.
/// Replaying the object (same notice, or the same bytes under a new key)
/// changes nothing.
#[tokio::test(flavor = "current_thread")]
async fn a_conflicting_uid_pair_in_one_object_drops_one_row_not_the_object() {
    let fx = fixture(1, 1);
    let at = DAY0_S + 3_600;
    let t0 = at * 1_000;
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, t0).await.unwrap();
    let probe = |time_s: i64| {
        let mut e = event("probe-raw-hash", time_s, 0);
        e["message"] = json!("nano source cutover probe");
        e
    };
    let mut events = (0..100).map(|r| event(&format!("real-{r:03}"), at - 60 + r as i64 % 50, r)).collect::<Vec<_>>();
    // The later probe first: the earliest one is kept whatever the order.
    events.insert(37, probe(at - 10));
    events.insert(81, probe(at - 30));
    let key = format!("bronze/{at}-probe-conflict.parquet");
    write_bronze(&fx.root.join("sources").join(&key), &events);
    fx.spool.deliver(&notice(&key, at)).unwrap();
    let report = ingestor.tick(t0).await.unwrap();
    assert_eq!(report.admitted_rows, 101, "100 real rows plus one probe copy");
    ingestor.flush_now(t0 + 1_000).await.unwrap();
    let health = ingestor.health();
    assert_eq!(health.objects_rejected_total, 0, "the object is never refused whole");
    assert_eq!(health.rows_rejected_total, 0, "the losing copy is a duplicate, not a refusal");
    assert_eq!(health.same_uid_payload_diff_total, 1);
    assert!(reject_entries(&fx).is_empty());
    assert_exactly_once(&live_rows(&fx).await, 101);
    let kept = live_rows(&fx).await.into_iter().find(|(_, uid)| uid == "probe-raw-hash").unwrap();
    assert_eq!(kept.0 / 1_000_000, at - 30, "the earliest probe copy is kept");

    // Replay: the same notice again, then the same bytes under a new key.
    fx.spool.deliver(&notice(&key, at)).unwrap();
    let copy = format!("bronze/{}-probe-conflict-copy.parquet", at + 5);
    write_bronze(&fx.root.join("sources").join(&copy), &events);
    fx.spool.deliver(&notice(&copy, at + 5)).unwrap();
    for step in 0..3 {
        ingestor.tick(t0 + 5_000 + step * 1_000).await.unwrap();
    }
    ingestor.flush_now(t0 + 20_000).await.unwrap();
    let health = ingestor.health();
    assert!(fx.spool.pending(1).await.unwrap().is_empty());
    assert_eq!(health.objects_rejected_total, 0);
    assert_eq!(health.same_uid_payload_diff_total, 2,
        "the copy's admission drops its losing probe again; its kept probe matches the committed one");
    assert_exactly_once(&live_rows(&fx).await, 101);
}

#[tokio::test(flavor = "current_thread")]
async fn a_shape_drifted_object_is_coerced_not_refused_and_never_wedges_ingest() {
    let fx = fixture(30, 5);
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, DAY0_S * 1_000).await.unwrap();
    // Establish unmapped.ctx as a struct leaf with a clean object.
    let clean_key = format!("bronze/{}-clean.parquet", DAY0_S + 2_440);
    let mut clean = event("clean-0", DAY0_S + 2_400, 1);
    clean["unmapped"] = json!({"ctx": {"k": "v"}});
    write_bronze(&fx.root.join("sources").join(&clean_key), &[clean]);
    fx.spool.deliver(&notice(&clean_key, DAY0_S + 2_440)).unwrap();
    ingestor.tick((DAY0_S + 2_440) * 1_000).await.unwrap();
    ingestor.flush_now((DAY0_S + 2_441) * 1_000).await.unwrap();
    // B4: an object whose unmapped.ctx is a scalar where the tenant schema
    // has a struct. Type drift is never a refusal: the value moves to
    // unmapped.nano_coerced and the row commits.
    let drifted = (0..5)
        .map(|r| {
            let mut e = event(&format!("drift-{r}"), DAY0_S + 2_400, r);
            e["unmapped"] = json!({"ctx": "flat"});
            e
        })
        .collect::<Vec<_>>();
    let drift_key = format!("bronze/{}-drift.parquet", DAY0_S + 2_450);
    write_bronze(&fx.root.join("sources").join(&drift_key), &drifted);
    // Not drift: rows admission itself refuses (a source event must keep a
    // non-empty raw_data; OCSF 1.9 shape violations fail the same way) are
    // refused alone; the object's other rows commit.
    let invalid = (0..5)
        .map(|r| {
            let mut e = event(&format!("ocsf-{r}"), DAY0_S + 2_400, r);
            if r < 2 {
                e["raw_data"] = Value::Null;
            }
            e
        })
        .collect::<Vec<_>>();
    let invalid_key = format!("bronze/{}-invalid.parquet", DAY0_S + 2_451);
    write_bronze(&fx.root.join("sources").join(&invalid_key), &invalid);
    // Deliver the good objects, the odd ones in the middle of a batch.
    for (i, (key, at)) in fx.objects.iter().enumerate() {
        fx.spool.deliver(&notice(key, *at)).unwrap();
        if i == 10 {
            fx.spool.deliver(&notice(&drift_key, *at)).unwrap();
            fx.spool.deliver(&notice(&invalid_key, *at)).unwrap();
        }
    }
    let end = fx.objects.last().unwrap().1 * 1_000 + 20_000;
    for step in 0..5 {
        ingestor.tick(end + step * 11_000).await.unwrap();
    }
    ingestor.flush_now(end + 60_000).await.unwrap();
    assert!(fx.spool.pending(1).await.unwrap().is_empty());
    assert_eq!(ingestor.health().objects_rejected_total, 0, "no object is refused whole");
    assert_eq!(ingestor.health().rows_coerced_total, 5);
    let rejections = reject_entries(&fx);
    assert_eq!(rejections.len(), 1, "{rejections:?}");
    assert_eq!((rejections[0].scope.as_str(), rejections[0].rows_rejected), ("rows", 2));
    assert_eq!(rejections[0].reason, "admission_invalid");
    assert_eq!(rejections[0].source.key, invalid_key);
    let rows = live_rows(&fx).await;
    let uids = rows.iter().map(|(_, u)| u.as_str()).collect::<HashSet<_>>();
    assert!((0..5).all(|r| uids.contains(format!("drift-{r}").as_str())), "every drifted row commits");
    assert!(!uids.contains("ocsf-0") && !uids.contains("ocsf-1") && uids.contains("ocsf-2"));
    assert_exactly_once(&rows, fx.unique_uids + 1 + 5 + 3);
}

fn reject_entries(fx: &Fixture) -> Vec<nanosiem_lake_worker::parts::part_log::Rejection> {
    use nanosiem_lake_worker::parts::format::LogKeys;
    use nanosiem_lake_worker::parts::part_log::{LogEntry, LogOp};
    let keys = LogKeys::new(TENANT).unwrap();
    let mut out = Vec::new();
    for seq in 0.. {
        let Some(bytes) = futures::executor::block_on(fx.parts.get(&keys.entry(seq))).unwrap() else { break };
        if let LogOp::Reject { rejections } = LogEntry::parse_bytes(&bytes, TENANT).unwrap().op {
            out.extend(rejections);
        }
    }
    out
}

/// NAN-3662: an Entra SignInLogs row as azure_monitor 1.0.0 emitted it on
/// tenant-b: Authentication 3002 whose `device` names no identifier, so
/// the strict OCSF constraint refuses it (`constraint_failed` at `device`).
fn sign_in_without_device_id(uid: &str, time_s: i64, i: usize, slug: &str) -> Value {
    let mut e = event(uid, time_s, i);
    e["device"] = json!({"os": {"name": "Windows10", "type_id": 100}, "type_id": 0});
    e["metadata"]["log_source"] = json!(slug);
    e["metadata"]["profiles"] = json!(["host"]);
    e
}

/// One admission of three objects: every row of the SignInLogs object
/// refused (100, `azure_monitor`), two rows of an `entra_audit` object
/// refused beside three good ones, and a clean fixture object. Returns the
/// logged rejections, by object key.
async fn refusal_admission(tag: bool) -> (Fixture, BTreeMap<String, nanosiem_lake_worker::parts::part_log::Rejection>) {
    let fx = fixture(1, 5);
    let mut cfg = config(&fx.root);
    cfg.refusal_source_counts = tag;
    let t0 = (DAY0_S + 2_440) * 1_000;
    let mut ingestor = Ingestor::open(
        cfg, &fx.parts, &fx.sources, &fx.spool, &fx.signer, trusted(), BronzeIngestEnricher::disabled(), &seed_schema(), t0,
    )
    .await
    .unwrap();
    let signin_key = format!("bronze/{}-signin.parquet", DAY0_S + 2_430);
    let signin = (0..100).map(|r| sign_in_without_device_id(&format!("signin-{r}"), DAY0_S + 2_400, r, "azure_monitor")).collect::<Vec<_>>();
    write_bronze(&fx.root.join("sources").join(&signin_key), &signin);
    let audit_key = format!("bronze/{}-audit.parquet", DAY0_S + 2_431);
    let audit = (0..5)
        .map(|r| {
            if r < 2 {
                sign_in_without_device_id(&format!("audit-{r}"), DAY0_S + 2_400, r, "entra_audit")
            } else {
                let mut e = event(&format!("audit-{r}"), DAY0_S + 2_400, r);
                e["metadata"]["log_source"] = json!("entra_audit");
                e
            }
        })
        .collect::<Vec<_>>();
    write_bronze(&fx.root.join("sources").join(&audit_key), &audit);
    for (key, at) in [(signin_key, DAY0_S + 2_430), (audit_key, DAY0_S + 2_431)].iter().chain(fx.objects.iter()) {
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    ingestor.tick(t0).await.unwrap();
    ingestor.flush_now(t0 + 20_000).await.unwrap();
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "every notice is acknowledged");
    let rows = live_rows(&fx).await;
    let uids = rows.iter().map(|(_, u)| u.as_str()).collect::<HashSet<_>>();
    assert!(!uids.iter().any(|u| u.starts_with("signin-")), "no SignInLogs row lands");
    assert!(uids.contains("audit-2") && !uids.contains("audit-0") && !uids.contains("audit-1"));
    let by_key = reject_entries(&fx).into_iter().map(|r| (r.source.key.clone(), r)).collect::<BTreeMap<_, _>>();
    assert_eq!(by_key.len(), 2, "{by_key:?}");
    (fx, by_key)
}

/// NAN-3662 with `NANO_LAKE_REFUSAL_SOURCE_COUNTS` on: each object's
/// rejection names its own source lane, reason and OCSF attribute (the
/// multi-object group is split so a rejection never carries another
/// object's rows), value-free; query[T]'s window counts them per source.
#[tokio::test(flavor = "current_thread")]
async fn lean_refusals_are_tagged_per_source_lane_when_the_flag_is_on() {
    use nanosiem_lake_worker::parts::refusal_tally::{attribute, RefusalWindow, BUCKET_MS};
    let (_fx, by_key) = refusal_admission(true).await;
    let signin = by_key.iter().find(|(k, _)| k.ends_with("-signin.parquet")).unwrap().1;
    let audit = by_key.iter().find(|(k, _)| k.ends_with("-audit.parquet")).unwrap().1;
    assert_eq!((signin.scope.as_str(), signin.rows_rejected), ("object", 100));
    assert!(signin.detail.starts_with("nano_refusals=v1 azure_monitor:100:ocsf_constraint_failed@device; "), "{}", signin.detail);
    assert_eq!((audit.scope.as_str(), audit.rows_rejected), ("rows", 2));
    assert!(audit.detail.starts_with("nano_refusals=v1 entra_audit:2:ocsf_constraint_failed@device; 2 rows refused"), "{}", audit.detail);
    for rejection in [signin, audit] {
        assert!(rejection.detail.len() <= 512);
        for value in ["USER", "user0", "10.0.", "ws-", "Windows10", "raw "] {
            assert!(!rejection.detail.contains(value), "a row value leaked into the detail: {}", rejection.detail);
        }
    }
    let attributed = attribute(signin);
    assert_eq!(attributed.len(), 1);
    assert_eq!((attributed[0].source_slug.as_str(), attributed[0].rows), ("azure_monitor", 100));
    // The query[T] fold: a refused-only lane (nothing of azure_monitor is
    // live) still has its count and value-free cause.
    let mut window = RefusalWindow::new(49 * 3_600_000);
    let at = (DAY0_S + 2_460) * 1_000;
    window.record(at, &[signin.clone(), audit.clone()]);
    let rows = window.rows(0, i64::MAX);
    let summary = rows.iter().map(|r| (r.source.as_str(), r.rows, r.reason.as_str(), r.field.as_deref())).collect::<Vec<_>>();
    assert_eq!(summary, vec![
        ("azure_monitor", 100, "ocsf_constraint_failed", Some("device")),
        ("entra_audit", 2, "ocsf_constraint_failed", Some("device")),
    ]);
    assert!(rows.iter().all(|r| r.bucket_start_ms == at - at % BUCKET_MS));
}

/// NAN-3662 default (flag off): the log keeps today's untagged details, and
/// the reader still counts every refused row, on the default source.
#[tokio::test(flavor = "current_thread")]
async fn lean_refusals_stay_untagged_by_default_and_still_count() {
    use nanosiem_lake_worker::parts::refusal_tally::{attribute, DETAIL_TAG};
    let (_fx, by_key) = refusal_admission(false).await;
    for rejection in by_key.values() {
        assert!(!rejection.detail.starts_with(DETAIL_TAG), "{}", rejection.detail);
    }
    let total = by_key.values().flat_map(attribute).inspect(|t| assert_eq!(t.source_slug, "default")).map(|t| t.rows).sum::<u64>();
    assert_eq!(total, 102);
}

#[tokio::test(flavor = "current_thread")]
async fn truncating_rows_are_coerced_and_only_rows_without_time_are_refused() {
    let fx = fixture(6, 4);
    // Establish unmapped.code as an Int64 leaf with a clean object.
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, DAY0_S * 1_000).await.unwrap();
    let clean_key = format!("bronze/{}-clean.parquet", DAY0_S + 2_440);
    let mut clean = event("clean-0", DAY0_S + 2_400, 1);
    clean["unmapped"] = json!({"code": 1});
    write_bronze(&fx.root.join("sources").join(&clean_key), &[clean]);
    fx.spool.deliver(&notice(&clean_key, DAY0_S + 2_440)).unwrap();
    ingestor.tick((DAY0_S + 2_440) * 1_000).await.unwrap();
    ingestor.flush_now((DAY0_S + 2_441) * 1_000).await.unwrap();
    // One object whose unmapped.code column is Float64: whole values decode
    // into the Int64 leaf, the fractional one is coerced into
    // unmapped.nano_coerced; one row has no time and is refused alone.
    let events = (0..6)
        .map(|r| {
            let mut e = event(&format!("mixed-{r}"), DAY0_S + 2_400, r);
            e["unmapped"] = json!({"code": if r == 4 { 5.5 } else { 5.0 }});
            if r == 5 {
                e["time"] = json!("not a time");
            }
            e
        })
        .collect::<Vec<_>>();
    let key = format!("bronze/{}-mixed.parquet", DAY0_S + 2_450);
    write_bronze(&fx.root.join("sources").join(&key), &events);
    fx.spool.deliver(&notice(&key, DAY0_S + 2_450)).unwrap();
    ingestor.tick((DAY0_S + 2_450) * 1_000).await.unwrap();
    ingestor.flush_now((DAY0_S + 2_451) * 1_000).await.unwrap();
    let rows = live_rows(&fx).await;
    let uids = rows.iter().map(|(_, u)| u.as_str()).collect::<HashSet<_>>();
    assert!(uids.contains("mixed-0") && uids.contains("mixed-4") && uids.contains("clean-0"), "the drifted row is kept");
    assert!(!uids.contains("mixed-5"), "the row without a valid time is refused");
    assert_eq!(ingestor.health().rows_coerced_total, 1);
    let rejections = reject_entries(&fx);
    assert_eq!(rejections.len(), 1, "{rejections:?}");
    assert_eq!((rejections[0].scope.as_str(), rejections[0].rows_rejected), ("rows", 1));
    assert_eq!(rejections[0].reason, "admission_invalid");
    assert_eq!(rejections[0].source.key, key);
    assert!(fx.spool.pending(1).await.unwrap().is_empty());
    assert_eq!(ingestor.health().rows_rejected_total, 1);
}

/// Parts store that fails the first log entry create of one kind (B2).
struct FailFirstEntry<'a> {
    parts: &'a LocalObjectStore,
    kind: &'static str,
    armed: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl ObjectStore for FailFirstEntry<'_> {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.parts.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        let needle = format!("\"kind\":\"{}\"", self.kind);
        let hit = key.contains("/log/entries/") && std::str::from_utf8(bytes).is_ok_and(|t| t.contains(&needle));
        if hit && self.armed.swap(false, Ordering::SeqCst) {
            anyhow::bail!("injected {} append failure", self.kind);
        }
        self.parts.put_if_absent(key, bytes).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.parts.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.parts.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.parts.list(prefix).await
    }
}

/// A flush holding rows and a refusal fails at one log append (`kind`),
/// then retries in-process: every entry lands exactly once.
async fn partial_flush_failure_commits_once(kind: &'static str) {
    let fx = fixture(8, 5);
    let store = FailFirstEntry { parts: &fx.parts, kind, armed: std::sync::atomic::AtomicBool::new(true) };
    let mut ingestor = open(&fx, &fx.spool, &store, DAY0_S * 1_000).await.unwrap();
    for (key, at) in &fx.objects {
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    fx.spool.deliver(&notice("bronze/missing.parquet", DAY0_S + 2_400)).unwrap();
    let mut clock = fx.objects.last().unwrap().1 * 1_000 + 20_000;
    ingestor.tick(clock).await.unwrap(); // admit; the flush is due one interval later
    clock += 11_000;
    assert!(ingestor.tick(clock).await.is_err(), "the {kind} append failed mid-flush");
    for _ in 0..4 {
        clock += 11_000;
        ingestor.tick(clock).await.unwrap();
    }
    ingestor.flush_now(clock).await.unwrap();
    assert!(fx.spool.pending(1).await.unwrap().is_empty());
    assert_eq!(reject_entries(&fx).len(), 1, "the refusal is logged once");
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_reject_append_is_retried_and_rows_commit_once() {
    partial_flush_failure_commits_once("reject").await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_add_after_a_logged_reject_never_relogs_or_recommits() {
    partial_flush_failure_commits_once("add").await;
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_ack_never_admits_new_rows_into_the_committed_buffer() {
    let fx = fixture(24, 5);
    let faulty = Faulty {
        spool: &fx.spool,
        parts: &fx.parts,
        fail_ack_at: AtomicUsize::new(1),
        fail_put_at: AtomicUsize::new(usize::MAX),
        acks: AtomicUsize::new(0),
        puts: AtomicUsize::new(0),
    };
    let mut ingestor = open(&fx, &faulty, &fx.parts, DAY0_S * 1_000).await.unwrap();
    let (first, second) = fx.objects.split_at(fx.objects.len() / 2);
    for (key, at) in first {
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    let mut clock = first.last().unwrap().1 * 1_000 + 20_000;
    ingestor.tick(clock).await.unwrap(); // admit
    clock += 11_000;
    assert!(ingestor.tick(clock).await.is_err(), "add committed, ack failed");
    // New notices arrive before the in-process retry.
    for (key, at) in second {
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    for _ in 0..8 {
        clock += 11_000;
        ingestor.tick(clock).await.unwrap();
    }
    ingestor.flush_now(clock).await.unwrap();
    assert!(fx.spool.pending(1).await.unwrap().is_empty());
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
}

#[tokio::test(flavor = "current_thread")]
async fn thousands_of_refusals_chunk_into_several_reject_entries() {
    let fx = fixture(2, 3);
    let mut cfg = config(&fx.root);
    cfg.max_objects_per_admission = 3_000;
    let mut ingestor = Ingestor::open(
        cfg,
        &fx.parts,
        &fx.sources,
        &fx.spool,
        &fx.signer,
        trusted(),
        BronzeIngestEnricher::disabled(),
        &seed_schema(),
        DAY0_S * 1_000,
    )
    .await
    .unwrap();
    for n in 0..2_500 {
        fx.spool.deliver(&notice(&format!("bronze/missing-{n:05}.parquet"), DAY0_S + 2_400)).unwrap();
    }
    let mut clock = (DAY0_S + 2_400) * 1_000;
    // A flush takes at most MAX_FLUSH_OBJECTS notices (NAN-3006): 5 flushes.
    for _ in 0..8 {
        ingestor.tick(clock).await.unwrap();
        clock += 11_000;
    }
    ingestor.flush_now(clock).await.unwrap();
    assert!(fx.spool.pending(1).await.unwrap().is_empty());
    assert_eq!(reject_entries(&fx).len(), 2_500);
    assert_eq!(ingestor.health().objects_rejected_total, 2_500);
}

/// A signer that refuses the first `fail` calls (an owner 5xx).
struct FlakySigner {
    inner: LocalPartSigner,
    fail: AtomicUsize,
}

#[async_trait]
impl nanosiem_lake_worker::parts::provenance::PartSigner for FlakySigner {
    fn key_id(&self) -> &str {
        self.inner.key_id()
    }
    async fn sign(
        &self,
        tenant_id: &str,
        records: &[nanosiem_lake_worker::parts::provenance::ProvenanceRecord],
    ) -> Result<Vec<nanosiem_lake_worker::parts::provenance::Ed25519Signature>> {
        if self.fail.load(Ordering::SeqCst) > 0 {
            self.fail.fetch_sub(1, Ordering::SeqCst);
            anyhow::bail!("lake-parts:sign refused: 503");
        }
        self.inner.sign(tenant_id, records).await
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_failing_sign_holds_the_buffer_and_the_retry_commits_exactly_once() {
    use nanosiem_lake_worker::parts::provenance::PartSigner as _;
    let fx = fixture(20, 5);
    let flaky = FlakySigner { inner: signer(), fail: AtomicUsize::new(3) };
    let mut ingestor = Ingestor::open(
        config(&fx.root),
        &fx.parts,
        &fx.sources,
        &fx.spool,
        &flaky,
        trusted(),
        BronzeIngestEnricher::disabled(),
        &seed_schema(),
        DAY0_S * 1_000,
    )
    .await
    .unwrap();
    for (key, at) in &fx.objects {
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    let mut clock = fx.objects.last().unwrap().1 * 1_000 + 20_000;
    let mut errors = 0;
    for _ in 0..12 {
        match ingestor.tick(clock).await {
            Ok(_) => {}
            Err(_) => errors += 1,
        }
        clock += 11_000;
    }
    ingestor.flush_now(clock).await.unwrap();
    assert!(errors >= 1, "the injected owner failures surfaced");
    assert!(fx.spool.pending(1).await.unwrap().is_empty());
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
    let _ = flaky.key_id();
}

/// A deterministic native-owner latency/fault model. Every immutable upload
/// pays reserve/verify/PUT/HEAD/complete/register latency; every 200th call
/// refuses transiently. Control calls share the native writer's paced budget.
/// The production retry must retry that file rather than restart the flush.
struct SlowTransientParts {
    inner: LocalObjectStore,
    delay_ms: u64,
    next_owner_call: tokio::sync::Mutex<tokio::time::Instant>,
    calls: AtomicUsize,
    faults: AtomicUsize,
    creates: AtomicUsize,
}

#[async_trait]
impl ObjectStore for SlowTransientParts {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> { self.inner.get(key).await }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        for stage in 0..6 {
            if matches!(stage, 0 | 1 | 4 | 5) {
                let mut next = self.next_owner_call.lock().await;
                tokio::time::sleep_until(*next).await;
                *next = tokio::time::Instant::now() + std::time::Duration::from_millis(25);
            }
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call % 200 == 0 && !key.contains("/log/") {
                self.faults.fetch_add(1, Ordering::SeqCst);
                return Err(nanosiem_lake_worker::part_ingest::native_writer::OwnerRefused { status: 503 }.into());
            }
        }
        let created = self.inner.put_if_absent(key, bytes).await?;
        if created { self.creates.fetch_add(1, Ordering::SeqCst); }
        Ok(created)
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> { self.inner.put(key, bytes).await }
    async fn delete(&self, key: &str) -> Result<()> { self.inner.delete(key).await }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> { self.inner.list(prefix).await }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_hundred_event_hours_with_slow_transient_owner_commit_within_watchdog() {
    wide_transient_owner_regression(50).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_hundred_event_hours_with_400ms_paced_owner_commit_within_watchdog() {
    wide_transient_owner_regression(400).await;
}

async fn wide_transient_owner_regression(delay_ms: u64) {
    let fx = fixture(4, 125);
    for (object, (key, at)) in fx.objects.iter().enumerate() {
        let events = (0..125).map(|row| {
            let index = object * 125 + row;
            event(&format!("wide-owner-{index}"), DAY0_S - (500 - index as i64) * 3_600 + 60, index)
        }).collect::<Vec<_>>();
        write_bronze(&fx.root.join("sources").join(key), &events);
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    let store: &'static SlowTransientParts = Box::leak(Box::new(SlowTransientParts {
        inner: LocalObjectStore::new(fx.root.join("parts")).unwrap(),
        delay_ms, next_owner_call: tokio::sync::Mutex::new(tokio::time::Instant::now()),
        calls: AtomicUsize::new(0), faults: AtomicUsize::new(0), creates: AtomicUsize::new(0),
    }));
    let owner: &'static LocalPartSigner = Box::leak(Box::new(signer()));
    let mut cfg = config(&fx.root);
    cfg.max_objects_per_admission = 4;
    cfg.prevalence_enabled = false;
    let mut clock = (DAY0_S + 2_500) * 1_000;
    let queue = OrderingQueue {
        spool: &fx.spool, parts: &fx.parts, sources: &fx.sources,
        issued: std::sync::atomic::AtomicBool::new(false),
        keys: std::sync::Mutex::new(BTreeMap::new()), ranges: AtomicUsize::new(0), acked: AtomicUsize::new(0),
    };
    let mut ingestor = Ingestor::open(cfg, store, &fx.sources, &queue, owner, trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.unwrap();
    ingestor.set_background_store(store);
    ingestor.set_background_signer(owner);
    let started = std::time::Instant::now();
    tokio::time::timeout(std::time::Duration::from_secs(900), async {
        for attempt in 0..12 {
            let (report, _) = ingestor.tick_ingest(clock).await.unwrap();
            if attempt == 0 {
                assert_eq!(report.flushed_parts, 500, "wide buffers seal before the age interval elapses");
            }
            ingestor.flush_now(clock + 1).await.unwrap();
            clock += 11_000;
            if fx.spool.pending(1).await.unwrap().is_empty() { break; }
        }
    }).await.expect("500 historical hours must commit inside the edge stall watchdog");
    let elapsed = started.elapsed();
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "every source notice drained");
    let set = live(&fx).await;
    assert_eq!(set.parts().map(|part| part.event_hour).collect::<HashSet<_>>().len(), 500);
    let part_files = set.parts().map(|part| {
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        std::fs::read_dir(fx.root.join("parts").join(keys.provenance()).parent().unwrap()).unwrap().count()
    }).sum::<usize>();
    assert_exactly_once(&live_rows(&fx).await, 500);
    assert_eq!(queue.acked.load(Ordering::SeqCst), 4, "each source notice acknowledged once");
    let log_keys = nanosiem_lake_worker::parts::format::LogKeys::new(TENANT).unwrap();
    let mut consumed = HashSet::new();
    let mut adds = 0;
    for seq in 1..=set.head().unwrap().0 {
        let bytes = fx.parts.get(&log_keys.entry(seq)).await.unwrap().unwrap();
        let entry = nanosiem_lake_worker::parts::part_log::LogEntry::parse_bytes(&bytes, TENANT).unwrap();
        if let nanosiem_lake_worker::parts::part_log::LogOp::Add { consumed: sources, .. } = entry.op {
            adds += 1;
            for source in sources {
                assert!(consumed.insert((source.key, source.version, source.sha256)),
                    "a source must be consumed by exactly one Add");
            }
        }
    }
    assert_eq!(consumed.len(), 4);
    assert_eq!(adds, queue.ranges.load(Ordering::SeqCst), "one Add per issued flush range");
    assert!(store.faults.load(Ordering::SeqCst) > 0, "transient failures were exercised");
    assert_eq!(load_log(&fx.parts, TENANT_B).await.unwrap().parts().count(), 0,
        "wide history and retries remain fenced to their tenant");
    eprintln!("wide-owner regression: event_hours=500 parts={} part_files={} simulated_calls={} transient_faults={} creates={} latency_ms_per_call={} watchdog_s=900 commit_ms={}",
        set.parts().count(), part_files, store.calls.load(Ordering::SeqCst), store.faults.load(Ordering::SeqCst),
        store.creates.load(Ordering::SeqCst), delay_ms, elapsed.as_millis());
}

/// An unknown native PUT permanently closes only that immutable identity.
struct UnknownNativePut {
    inner: LocalObjectStore,
    hour_prefix: String,
    blocked_key: std::sync::Mutex<Option<String>>,
}

#[async_trait]
impl ObjectStore for UnknownNativePut {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> { self.inner.get(key).await }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        let blocked = {
            let mut blocked = self.blocked_key.lock().unwrap();
            if blocked.is_none() && key.starts_with(&self.hour_prefix) && key.ends_with("data-00000.parquet") {
                *blocked = Some(key.to_string());
            }
            blocked.as_deref() == Some(key)
        };
        if blocked {
            return Err(nanosiem_lake_worker::part_ingest::native_writer::NativePutUnresolved { key: key.to_string() }.into());
        }
        self.inner.put_if_absent(key, bytes).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> { self.inner.put(key, bytes).await }
    async fn delete(&self, key: &str) -> Result<()> { self.inner.delete(key).await }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> { self.inner.list(prefix).await }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unresolved_native_put_rebuilds_only_its_hour_and_keeps_completed_other_parts() {
    let fx = fixture(1, 4);
    let (key, _) = &fx.objects[0];
    let events = (0..4).map(|hour| event(&format!("unknown-put-{hour}"), DAY0_S + hour as i64 * 3_600 + 60, hour)).collect::<Vec<_>>();
    write_bronze(&fx.root.join("sources").join(key), &events);
    // The object reaches the tenant after its newest event (hour 3): with the
    // fixture's notice time (00:40Z) NAN-4336 clamps hours 1-3 into hour 0.
    fx.spool.deliver(&notice(key, DAY0_S + 3 * 3_600 + 120)).unwrap();
    let failed_hour = event_hour_of((DAY0_S + 3 * 3_600) * 1_000_000);
    let keys = PartKeys::new(TENANT, Level::L0, failed_hour, &nanosiem_lake_worker::parts::format::PartId::new(1).unwrap()).unwrap();
    let key = keys.provenance();
    let hour_prefix = format!("{}/", Path::new(&key).parent().unwrap().parent().unwrap().display());
    let store: &'static UnknownNativePut = Box::leak(Box::new(UnknownNativePut {
        inner: LocalObjectStore::new(fx.root.join("parts")).unwrap(), hour_prefix,
        blocked_key: std::sync::Mutex::new(None),
    }));
    let owner: &'static LocalPartSigner = Box::leak(Box::new(signer()));
    let mut cfg = config(&fx.root);
    cfg.prevalence_enabled = false;
    let clock = (DAY0_S + 4 * 3_600) * 1_000;
    let mut ingestor = Ingestor::open(cfg, store, &fx.sources, &fx.spool, owner, trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.unwrap();
    ingestor.set_background_store(store);
    ingestor.set_background_signer(owner);
    ingestor.tick_ingest(clock).await.unwrap();
    assert!(ingestor.flush_now(clock + 11_001).await.is_err(), "unknown PUT fails closed");
    assert_eq!(fx.spool.pending(2).await.unwrap().len(), 1);
    assert_eq!(live(&fx).await.parts().count(), 0);
    let remote_before = store.list(&format!("lake/parts/v1/tenant={TENANT}/")).await.unwrap();
    let kept_data = remote_before.into_iter().filter(|key| key.ends_with("data-00000.parquet")
        && !key.starts_with(&store.hour_prefix)).collect::<HashSet<_>>();
    assert_eq!(kept_data.len(), 3, "other hours completed before the unresolved PUT");
    ingestor.flush_now(clock + 11_002).await.unwrap();
    assert!(fx.spool.pending(1).await.unwrap().is_empty());
    let set = live(&fx).await;
    let live_data = set.parts().map(|part| PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap().data(0)).collect::<HashSet<_>>();
    assert!(kept_data.is_subset(&live_data), "successful hours keep the same part ids");
    assert!(!live_data.contains(store.blocked_key.lock().unwrap().as_ref().unwrap()), "unknown identity is never reused");
    assert_eq!(set.parts().count(), 4);
    assert_exactly_once(&live_rows(&fx).await, 4);
    assert_eq!(load_log(&fx.parts, TENANT_B).await.unwrap().parts().count(), 0);
}

/// Historical rows fan out into many L0s in one background flush. A failed
/// publication must leave every notice pending until a successful retry's Add.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn many_hour_background_publication_failure_retries_without_acking_or_losing_rows() {
    let fx = fixture(4, 12);
    for (object, (key, at)) in fx.objects.iter().enumerate() {
        let events = (0..12).map(|row| {
            let index = object * 12 + row;
            event(&format!("many-hour-{index}"), DAY0_S - (48 - index as i64) * 3_600 + 60, index)
        }).collect::<Vec<_>>();
        write_bronze(&fx.root.join("sources").join(key), &events);
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(fx.root.join("parts")).unwrap()));
    let owner: &'static FlakySigner = Box::leak(Box::new(FlakySigner {
        inner: signer(), fail: AtomicUsize::new(1),
    }));
    let mut cfg = config(&fx.root);
    cfg.max_objects_per_admission = 1;
    cfg.prevalence_enabled = false;
    cfg.commit_when_ready = false; // Maintenance must not retry the failed flight.
    cfg.cache_max_bytes = 1;
    let mut clock = (DAY0_S + 2_500) * 1_000;
    let mut ingestor = Ingestor::open(cfg, store, &fx.sources, &fx.spool, owner, trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.unwrap();
    ingestor.set_background_store(store);
    ingestor.set_background_signer(owner);
    ingestor.tick_ingest(clock).await.unwrap();
    clock += 11_000;
    ingestor.tick_ingest(clock).await.unwrap();
    assert_eq!(ingestor.health().flushes_pipelined_total, 1, "the first 24 hours publish in the background");
    let failure = tokio::time::timeout(std::time::Duration::from_secs(120), ingestor.flush_now(clock + 1))
        .await.expect("publication failure must surface within the step budget").unwrap_err();
    assert!(failure.to_string().contains("pipelined flush build/publish"));
    assert_eq!(owner.fail.load(Ordering::SeqCst), 0, "the owner refusal was exercised");
    assert_eq!(fx.spool.pending(8).await.unwrap().len(), 4, "no notice is acknowledged before publication succeeds");
    assert_eq!(live(&fx).await.parts().count(), 0, "failed publication has no committed Add");
    let prefix = format!("lake/parts/v1/tenant={TENANT}/");
    let uploaded_before_retry = store.list(&prefix).await.unwrap().into_iter()
        .filter(|key| key.ends_with(".parquet")).collect::<HashSet<_>>();
    assert!(!uploaded_before_retry.is_empty(), "files completed before signing failed");
    let local_parts = fx.root.join("work/parts");
    let retained_dirs = std::fs::read_dir(&local_parts).unwrap().flatten()
        .filter(|entry| entry.file_type().unwrap().is_dir()).map(|entry| entry.path()).collect::<Vec<_>>();
    assert!(!retained_dirs.is_empty());
    clock += 60_001;
    ingestor.tick_maintain(clock, &[], &mut Default::default()).await.unwrap();
    assert_eq!(live(&fx).await.parts().count(), 0, "maintenance does not retry the failed flight");
    assert!(retained_dirs.iter().all(|path| path.is_dir()),
        "cache eviction must preserve immutable output held by a failed flight");
    tokio::time::timeout(std::time::Duration::from_secs(120), ingestor.flush_now(clock + 2))
        .await.expect("publication retry must finish").unwrap();
    assert_eq!(fx.spool.pending(8).await.unwrap().len(), 2);
    let uploaded_after_retry = store.list(&prefix).await.unwrap().into_iter()
        .filter(|key| key.ends_with(".parquet")).collect::<HashSet<_>>();
    assert_eq!(uploaded_before_retry, uploaded_after_retry,
        "retry keeps completed immutable files under the same part ids");
    for _ in 0..3 {
        clock += 11_000;
        ingestor.tick_ingest(clock).await.unwrap();
    }
    ingestor.flush_now(clock + 1).await.unwrap();
    assert!(fx.spool.pending(1).await.unwrap().is_empty());
    let set = live(&fx).await;
    assert_eq!(set.parts().map(|part| part.event_hour).collect::<HashSet<_>>().len(), 48);
    assert_exactly_once(&live_rows(&fx).await, 48);
    assert_eq!(load_log(&fx.parts, TENANT_B).await.unwrap().parts().count(), 0,
        "the retry never creates parts for another tenant");
}

#[tokio::test(flavor = "current_thread")]
async fn a_tiny_cache_budget_evicts_and_merges_still_refetch_verified_parts() {
    let fx = fixture(120, 6);
    let mut cfg = config(&fx.root);
    cfg.cache_max_bytes = 1;
    let mut ingestor = Ingestor::open(
        cfg,
        &fx.parts,
        &fx.sources,
        &fx.spool,
        &fx.signer,
        trusted(),
        BronzeIngestEnricher::disabled(),
        &seed_schema(),
        DAY0_S * 1_000,
    )
    .await
    .unwrap();
    drive(&mut ingestor, &fx, &|k, at| {
        fx.spool.deliver(&notice(k, at)).unwrap();
    })
    .await
    .unwrap();
    let mut clock = (DAY0_S + 4 * 3_600) * 1_000;
    for _ in 0..60 {
        ingestor.tick(clock).await.unwrap();
        clock += 61_000;
    }
    let live = live(&fx).await;
    assert!(live.parts().all(|p| p.level == Level::Hour), "hour merges ran over evicted inputs");
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
    assert!(ingestor.health().cache_bytes <= 1, "cache held to its budget: {}", ingestor.health().cache_bytes);
}

// ---------------------------------------------------------------------------
// Lake-part delete gate (`lean_part_gc_gate_v1`): ingest never deletes a part
// file on its own credential; only the sanctioned pass does, and only while
// the tenant's lake_part delete grant is enabled.
// ---------------------------------------------------------------------------

mod part_gc_gate {
    use super::*;
    use nanosiem_lake_worker::lake_part_gc::{
        GcPolicy, IndexStatus, LakePartDeleteAuthority, LakePartDeletePermit, LakePartDeleteReceipt,
        LakePartDeleteRequest, LakePartGcState, LakePartIndexClient, ListedPartObject, StorePartLogReader,
    };
    use nanosiem_lake_worker::lake_part_gc::index::IndexRequest;
    use nanosiem_lake_worker::part_ingest::part_gc_gate::{
        ExchangedGrantAuthority, LakePartGcRunner, PartGcAuthority, PartGcDecision, PartObjectLister, SanctionedPartGc,
    };
    use nanosiem_lake_worker::parts::part_log::PartRef;
    use std::sync::Mutex;

    /// Owner + Worker stand-in: permits everything, and `retire` really
    /// deletes from the store (as the Worker would, behind its receipt).
    struct DeletingAuthority {
        store: Arc<LocalObjectStore>,
        retired: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl LakePartDeleteAuthority for DeletingAuthority {
        async fn worker_supports_lake_part_delete(&self) -> Result<bool> {
            Ok(true)
        }

        async fn authorize(&self, request: &LakePartDeleteRequest) -> Result<LakePartDeletePermit> {
            let now = chrono::Utc::now();
            Ok(serde_json::from_value(json!({
                "request": request,
                "permit_id": request.permit_id()?,
                "owner_authorization": {
                    "schema_version": 1, "signer_key_id": "owner-test",
                    "issued_at": now.to_rfc3339(), "expires_at": (now + chrono::Duration::minutes(5)).to_rfc3339(),
                    "identity_sha256": request.digest()?, "signature_base64": "sig"
                }
            }))?)
        }

        async fn prepare(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeletePermit> {
            Ok(permit.clone())
        }

        async fn retire(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeleteReceipt> {
            self.store.delete(&permit.request.key).await?;
            self.retired.lock().unwrap().push(permit.request.key.clone());
            Ok(LakePartDeleteReceipt {
                schema_version: nanosiem_lake_worker::lake_part_gc::delete_control::DELETE_CONTROL_SCHEMA_VERSION,
                permit_id: permit.permit_id.clone(),
                identity_sha256: permit.owner_authorization.identity_sha256.clone(),
                receipt_sha256: "a".repeat(64),
                state: "receipt_appended".into(),
                final_head_absent: true,
            })
        }
    }

    /// Control's index: accepts entries in order.
    #[derive(Default)]
    struct AcceptingIndex {
        shas: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl LakePartIndexClient for AcceptingIndex {
        async fn index(&self, request: &IndexRequest) -> Result<IndexStatus> {
            use base64::Engine as _;
            let mut shas = self.shas.lock().unwrap();
            for entry in &request.entries {
                assert_eq!(entry.seq, shas.len() as u64);
                shas.push(sha256_hex(&base64::engine::general_purpose::STANDARD.decode(&entry.entry_base64)?));
            }
            Ok(IndexStatus {
                tenant_uuid: TENANT.into(),
                indexed_through_seq: shas.len().checked_sub(1).map(|n| n as u64),
                head_entry_sha256: shas.last().cloned(),
                checkpoint_seq: request.checkpoint.as_ref().map(|c| c.seq),
                folded_through_seq: None,
            })
        }
    }

    struct StoreLister(Arc<LocalObjectStore>);

    #[async_trait]
    impl PartObjectLister for StoreLister {
        async fn list_part_objects(&self, prefix: &str) -> Result<Vec<ListedPartObject>> {
            let mut out = Vec::new();
            for key in self.0.list(prefix).await? {
                let bytes = self.0.get(&key).await?.unwrap_or_default();
                out.push(ListedPartObject {
                    strong_etag: format!("\"{}\"", sha256_hex(&bytes)),
                    content_length: bytes.len() as u64,
                    uploaded_at_ms: 0,
                    key,
                });
            }
            Ok(out)
        }
    }

    /// A sanctioned pass that must never run.
    struct ForbiddenPass;

    #[async_trait]
    impl SanctionedPartGc for ForbiddenPass {
        async fn run_pass(&self, _now_ms: i64) -> Result<nanosiem_lake_worker::lake_part_gc::PassReport> {
            panic!("the sanctioned pass ran while the gate was closed");
        }
    }

    struct Unreadable;

    #[async_trait]
    impl PartGcAuthority for Unreadable {
        async fn decision(&self, _now_ms: i64) -> Result<PartGcDecision> {
            anyhow::bail!("control grant store unreachable")
        }
    }

    /// Asynchronous route stand-in: schedule once, report on a later tick.
    #[derive(Default)]
    struct ObservedPass {
        starts: AtomicUsize,
        polls: AtomicUsize,
        in_flight: Mutex<bool>,
    }

    #[async_trait]
    impl SanctionedPartGc for ObservedPass {
        async fn run_pass(&self, _: i64) -> Result<nanosiem_lake_worker::lake_part_gc::PassReport> {
            panic!("the route must schedule, never block ingest on a pass");
        }
        async fn schedule_pass(&self, _: i64) -> Option<Result<nanosiem_lake_worker::lake_part_gc::PassReport>> {
            let mut busy = self.in_flight.lock().unwrap();
            assert!(!*busy, "only one pass may be in flight");
            *busy = true;
            self.starts.fetch_add(1, Ordering::SeqCst);
            None
        }
        async fn poll_report(&self, _: i64) -> Option<Result<nanosiem_lake_worker::lake_part_gc::PassReport>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            let mut busy = self.in_flight.lock().unwrap();
            if !*busy { return None; }
            *busy = false;
            Some(Ok(nanosiem_lake_worker::lake_part_gc::PassReport {
                deleted: 3, ..Default::default()
            }))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retryable_partial_flush_polls_gc_without_acking_or_merging() {
        let fx = fixture(2, 3);
        let store = FailFirstEntry { parts: &fx.parts, kind: "add", armed: true.into() };
        let clock = fx.objects.last().unwrap().1 * 1_000 + 20_000;
        let mut ingestor = open(&fx, &fx.spool, &store, clock).await.unwrap();
        for (key, at) in &fx.objects { fx.spool.deliver(&notice(key, *at)).unwrap(); }
        ingestor.tick(clock).await.unwrap(); // admit, not due yet
        let pass = Arc::new(ObservedPass::default());
        let gate = Arc::new(ExchangedGrantAuthority::new(TENANT, Some(pass.clone())));
        gate.update(Some(&grant(true)));
        ingestor.set_part_gc_authority(gate);
        let pending = fx.spool.pending(20).await.unwrap();
        let error = ingestor.tick(clock + 11_000).await.unwrap_err();
        assert!(error.to_string().contains("injected add append failure"));
        assert_eq!(pass.starts.load(Ordering::SeqCst), 1);
        assert_eq!(fx.spool.pending(20).await.unwrap(), pending, "failed flush keeps its ACKs");
        assert_eq!(ingestor.health().merges_total, 0);
        assert_eq!(ingestor.health().rows_committed_total, 0);
        store.armed.store(true, Ordering::SeqCst);
        assert!(ingestor.tick(clock + 22_000).await.is_err());
        assert_eq!(ingestor.health().part_gc_deleted_total, 3, "poll while flush still fails");
        assert_eq!(pass.starts.load(Ordering::SeqCst), 1, "600 s cadence");
        assert_eq!(fx.spool.pending(20).await.unwrap(), pending);
        ingestor.tick(clock + 33_000).await.unwrap();
        assert!(fx.spool.pending(20).await.unwrap().is_empty());
        assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
        assert_eq!(pass.starts.load(Ordering::SeqCst), 1, "success must not double schedule");
        ingestor.tick(clock + 611_000).await.unwrap();
        assert_eq!(pass.starts.load(Ordering::SeqCst), 2, "600 s from original schedule");
    }

    struct FailingQueue { fatal: bool }
    #[async_trait]
    impl NoticeQueue for FailingQueue {
        async fn pending(&self, _: usize) -> Result<Vec<(NoticeHandle, SourceNotice)>> {
            if self.fatal {
                return Err(nanosiem_lake_worker::parts::part_log::Fenced { seq: 0 }.into());
            }
            anyhow::bail!("injected pending failure")
        }
        async fn ack(&self, _: &[NoticeHandle]) -> Result<()> { panic!("must not ACK") }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fenced_ingest_never_polls_or_schedules_a_new_pass() {
        let fx = fixture(1, 1);
        let queue = FailingQueue { fatal: true };
        let mut ingestor = open(&fx, &queue, &fx.parts, DAY0_S * 1_000).await.unwrap();
        let pass = Arc::new(ObservedPass::default());
        let gate = Arc::new(ExchangedGrantAuthority::new(TENANT, Some(pass.clone())));
        gate.update(Some(&grant(true)));
        ingestor.set_part_gc_authority(gate);
        let error = ingestor.tick(DAY0_S * 1_000).await.unwrap_err();
        assert!(error.downcast_ref::<nanosiem_lake_worker::parts::part_log::Fenced>().is_some());
        assert_eq!(pass.starts.load(Ordering::SeqCst), 0);
        assert_eq!(pass.polls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retryable_ingest_keeps_disabled_and_unreadable_authority_closed() {
        let fx = fixture(1, 1);
        let queue = FailingQueue { fatal: false };
        let mut ingestor = open(&fx, &queue, &fx.parts, DAY0_S * 1_000).await.unwrap();
        let gate = Arc::new(ExchangedGrantAuthority::new(TENANT, Some(Arc::new(ForbiddenPass))));
        gate.update(Some(&grant(false)));
        ingestor.set_part_gc_authority(gate);
        assert_eq!(ingestor.tick(DAY0_S * 1_000).await.unwrap_err().to_string(), "injected pending failure");
        assert_eq!(blocked(&ingestor).0, "grant_disabled");
        ingestor.set_part_gc_authority(Arc::new(Unreadable));
        assert!(ingestor.tick(DAY0_S * 1_000 + 1).await.is_err());
        assert_eq!(blocked(&ingestor).0, "authority_unreadable");
        assert_eq!(ingestor.health().part_gc_deleted_total, 0);
    }

    fn grant(enabled: bool) -> Value {
        json!({"schema_version": 1, "tenant_id": TENANT, "tenant_slug": "acme", "enabled": enabled,
            "revision": "r1", "expires_at": "2099-01-01T00:00:00Z"})
    }

    fn data_keys(part: &PartRef) -> Vec<String> {
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        (0..part.data_files as usize).map(|i| keys.data(i)).collect()
    }

    fn provenance_key(part: &PartRef) -> String {
        PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap().provenance()
    }

    async fn exists(fx: &Fixture, key: &str) -> bool {
        fx.parts.get(key).await.unwrap().is_some()
    }

    /// Superseded part refs split by whether their removal is past `grace_ms`
    /// at `now_ms`.
    async fn superseded(fx: &Fixture, now_ms: i64, grace_ms: i64) -> (Vec<PartRef>, Vec<PartRef>) {
        let set = live(fx).await;
        let past: HashSet<_> = set.removed_before(now_ms - grace_ms).cloned().collect();
        let mut old = Vec::new();
        let mut young = Vec::new();
        for id in set.removed_before(i64::MAX) {
            let part = set.removed_ref(id).unwrap().clone();
            if past.contains(id) { old.push(part) } else { young.push(part) }
        }
        (old, young)
    }

    async fn assert_nothing_deleted(fx: &Fixture) {
        let (old, young) = superseded(fx, 0, 0).await;
        for part in old.iter().chain(&young) {
            for key in data_keys(part) {
                assert!(exists(fx, &key).await, "superseded {key} was deleted with the gate closed");
            }
        }
    }

    async fn assert_live_set_intact(fx: &Fixture) {
        let set = live(fx).await;
        for part in set.parts() {
            assert!(exists(fx, &provenance_key(part)).await, "live provenance deleted");
            for key in data_keys(part) {
                assert!(exists(fx, &key).await, "live part file {key} was deleted");
            }
        }
        assert_exactly_once(&live_rows(fx).await, fx.unique_uids);
    }

    /// Ingest, merge, then seal hours at DAY0+4h so some supersessions are
    /// older than the 1 h grace and the hour merges are younger.
    async fn merged(fx: &Fixture) -> (Ingestor<'_>, i64) {
        let mut ingestor = open(fx, &fx.spool, &fx.parts, DAY0_S * 1_000).await.unwrap();
        drive(&mut ingestor, fx, &|k, at| {
            fx.spool.deliver(&notice(k, at)).unwrap();
        })
        .await
        .unwrap();
        let mut clock = (DAY0_S + 4 * 3_600) * 1_000;
        for _ in 0..50 {
            ingestor.tick(clock).await.unwrap();
            clock += 1_000;
        }
        (ingestor, clock)
    }

    #[tokio::test]
    async fn reader_race_gc_child() {
        let Some(root) = std::env::var_os("NANO_TEST_READER_RACE_ROOT") else { return };
        let store = Arc::new(LocalObjectStore::new(PathBuf::from(root).join("parts")).unwrap());
        let runner = LakePartGcRunner {
            authority: Arc::new(DeletingAuthority { store: store.clone(), retired: Mutex::new(Vec::new()) }),
            index: Arc::new(AcceptingIndex::default()),
            reader: Arc::new(StorePartLogReader::new(store.clone(), TENANT, trusted()).unwrap()),
            lister: Arc::new(StoreLister(store)),
            tenant_slug: "acme".into(), tenant_uuid: TENANT.into(),
            policy: GcPolicy { max_requests: 1_000_000, ..GcPolicy::default() },
            state: tokio::sync::Mutex::new(LakePartGcState::genesis()),
        };
        let report = runner.run_pass((DAY0_S + 8 * 3_600) * 1_000).await.unwrap();
        assert!(report.deleted > 0);
        assert!(report.paused_reason.is_none());
    }

    /// A membership snapshot can still select superseded inputs. GC runs in
    /// another process while footer/row readers reopen the selected paths.
    #[tokio::test]
    async fn superseded_writer_paths_remain_readable_during_multiprocess_gc() {
        reader_gc_race(false).await;
    }

    #[tokio::test]
    #[ignore = "requires pinned native chDB"]
    async fn native_searches_survive_superseded_writer_multiprocess_gc() {
        reader_gc_race(true).await;
    }

    async fn reader_gc_race(native: bool) {
        use nanosiem_lake_worker::part_query::fetch::{parts_key_prefix, PartFetcher, PartFile, StoreObjectSource};
        use nanosiem_lake_worker::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
        let fx = fixture(30, 12);
        let (_ingestor, _) = merged(&fx).await;
        let (old, _) = superseded(&fx, (DAY0_S + 8 * 3_600) * 1_000, 3_600_000).await;
        assert!(!old.is_empty());
        let store = Arc::new(LocalObjectStore::new(fx.root.join("parts")).unwrap());
        let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
            root: fx.root.join("reader-cache"), max_bytes: 128 << 20, query_max_bytes: 128 << 20,
            fetch_concurrency: 4, fetch_deadline: std::time::Duration::from_secs(30),
        }, TENANT, "bucket", &parts_key_prefix(TENANT).unwrap(),
            Arc::new(StoreObjectSource::local("bucket", store.clone(), fx.root.join("parts")))).unwrap();
        let fetcher = PartFetcher::new(TENANT, "bucket", store.clone(), trusted(), cache).unwrap()
            .with_local_root(Some(fx.root.join("parts")));
        let wanted = old.iter().flat_map(|part| (0..part.data_files as usize)
            .map(move |i| (part.clone(), PartFile::Data(i)))).collect::<Vec<_>>();
        let selected = fetcher.ensure_files(&wanted).await.unwrap();
        let expected = selected.files.iter().map(|file| read_time_uids(&file.path).unwrap()).collect::<Vec<_>>();
        let connection = native.then(|| {
            let runtime = nanosiem_lake_worker::native::NativeChdb::load_verified(
                std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
                &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
            ).unwrap();
            let connection = runtime.connect(&[]).unwrap();
            std::mem::forget(runtime);
            connection
        });
        let read = |file: &nanosiem_lake_worker::part_query::fetch::LocalFile, rows: &Vec<(i64, String)>| {
            assert_eq!(&read_time_uids(&file.path).unwrap(), rows);
            if let Some(connection) = &connection {
                let result = connection.query_with_params(
                    "SELECT count() AS n FROM file({path:String}, 'Parquet') WHERE length(metadata.uid) > 0",
                    "JSONEachRow", &[("path", file.path.to_str().unwrap())],
                ).unwrap_or_else(|error| panic!("native read of {} (still exists: {}): {error}", file.path.display(), file.path.exists()));
                let value: Value = serde_json::from_slice(&result.data).unwrap();
                assert_eq!(value["n"].as_u64().or_else(|| value["n"].as_str().and_then(|n| n.parse().ok())), Some(rows.len() as u64));
            }
        };
        let mut child = OwnedIngestProcess(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["part_gc_gate::reader_race_gc_child", "--exact", "--nocapture"])
            .env("NANO_TEST_READER_RACE_ROOT", &fx.root).spawn().unwrap());
        // Reopen like native readers, rather than relying on an already-open fd.
        for _ in 0..10 {
            for (file, rows) in selected.files.iter().zip(&expected) {
                read(file, rows);
            }
            tokio::task::yield_now().await;
        }
        assert!(child.0.wait().unwrap().success());
        fetcher.retire_removed(Some(&Default::default())).await.unwrap();
        for ((part, index), (file, rows)) in wanted.iter().zip(selected.files.iter().zip(&expected)) {
            let PartFile::Data(index) = index else { unreachable!() };
            assert!(!store.path(&PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap().data(*index)).unwrap().exists());
            read(file, rows);
        }
        let paths = selected.files.iter().map(|file| file.path.clone()).collect::<Vec<_>>();
        drop(selected);
        fetcher.retire_removed(None).await.unwrap();
        assert!(paths.iter().all(|path| !path.exists()), "retirement follows lease release");
        assert_live_set_intact(&fx).await;
    }

    fn blocked(ingestor: &Ingestor<'_>) -> (String, u64, u64) {
        let b = ingestor.health().part_gc_blocked.clone().expect("gc reported blocked");
        (b.reason, b.parts, b.bytes)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn closed_gate_never_deletes_and_reports_blocked() {
        let fx = fixture(420, 12);
        let (mut ingestor, clock) = merged(&fx).await;
        let now = clock + 30 * 60_000;
        let (old, young) = superseded(&fx, now, 3_600_000).await;
        assert!(!old.is_empty() && !young.is_empty(), "fixture has both old and young supersessions");

        // No gate wired at all (the default): authority missing.
        ingestor.tick(now).await.unwrap();
        let (reason, parts, bytes) = blocked(&ingestor);
        let blocked_seconds = ingestor.health().part_gc_blocked.as_ref().unwrap().blocked_seconds;
        assert_eq!(reason, "authority_missing");
        assert!(parts > 0 && bytes > 0, "pending superseded parts and bytes are reported: {parts} {bytes}");

        // Grant disabled (the lean-birth default): no delete, no pass.
        let gate = Arc::new(ExchangedGrantAuthority::new(TENANT, Some(Arc::new(ForbiddenPass))));
        gate.update(Some(&grant(false)));
        ingestor.set_part_gc_authority(gate.clone());
        ingestor.tick(now + 1_000).await.unwrap();
        assert_eq!(blocked(&ingestor).0, "grant_disabled");
        assert!(blocked(&ingestor).1 > 0, "lake_part_gc_blocked counts the kept parts");

        // Grant never delivered by the exchange.
        gate.update(None);
        ingestor.tick(now + 2_000).await.unwrap();
        assert_eq!(blocked(&ingestor).0, "grant_not_delivered");

        // Enabled grant, but no sanctioned path wired: still no delete.
        let no_path = Arc::new(ExchangedGrantAuthority::new(TENANT, None));
        no_path.update(Some(&grant(true)));
        ingestor.set_part_gc_authority(no_path);
        ingestor.tick(now + 3_000).await.unwrap();
        assert_eq!(blocked(&ingestor).0, "sanctioned_path_unavailable");
        let health = ingestor.health().part_gc_blocked.as_ref().unwrap();
        assert_eq!(health.detail, "sanctioned_route_not_wired");
        assert_eq!(health.blocked_seconds, blocked_seconds + 3, "reason changes preserve the blocked duration");

        // The authority itself cannot be read: fail closed.
        ingestor.set_part_gc_authority(Arc::new(Unreadable));
        ingestor.tick(now + 4_000).await.unwrap();
        assert_eq!(blocked(&ingestor).0, "authority_unreadable");
        ingestor.tick(now + 7_201_000).await.unwrap();
        assert_eq!(ingestor.health().part_gc_blocked.as_ref().unwrap().blocked_seconds, blocked_seconds + 7201);

        assert_eq!(ingestor.health().part_gc_deleted_total, 0);
        assert_nothing_deleted(&fx).await;
        assert_live_set_intact(&fx).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enabled_grant_deletes_only_superseded_parts_past_grace_via_the_sanctioned_pass() {
        let fx = fixture(420, 12);
        let (mut ingestor, clock) = merged(&fx).await;
        let now = clock + 30 * 60_000;
        let (old, young) = superseded(&fx, now, 3_600_000).await;
        assert!(!old.is_empty() && !young.is_empty());

        let store = Arc::new(LocalObjectStore::new(fx.root.join("parts")).unwrap());
        let authority = Arc::new(DeletingAuthority { store: store.clone(), retired: Mutex::new(Vec::new()) });
        let runner = LakePartGcRunner {
            authority: authority.clone(),
            index: Arc::new(AcceptingIndex::default()),
            reader: Arc::new(StorePartLogReader::new(store.clone(), TENANT, trusted()).unwrap()),
            lister: Arc::new(StoreLister(store.clone())),
            tenant_slug: "acme".into(),
            tenant_uuid: TENANT.into(),
            policy: GcPolicy { max_requests: 1_000_000, ..GcPolicy::default() },
            state: tokio::sync::Mutex::new(LakePartGcState::genesis()),
        };
        let gate = Arc::new(ExchangedGrantAuthority::new(TENANT, Some(Arc::new(runner))));
        gate.update(Some(&grant(true)));
        ingestor.set_part_gc_authority(gate);
        ingestor.tick(now).await.unwrap();

        assert!(ingestor.health().part_gc_blocked.is_none(), "{:?} {:?}", ingestor.health().part_gc_blocked, ingestor.health().part_gc_last_pause);
        assert!(ingestor.health().part_gc_deleted_total > 0);
        for part in &old {
            for key in data_keys(part) {
                assert!(!exists(&fx, &key).await, "superseded past grace {key} was kept");
            }
            assert!(exists(&fx, &provenance_key(part)).await, "provenance stays until retention");
        }
        for part in &young {
            for key in data_keys(part) {
                assert!(exists(&fx, &key).await, "superseded within grace {key} was deleted");
            }
        }
        let retired = authority.retired.lock().unwrap().clone();
        let old_ids: HashSet<String> = old.iter().map(|p| p.part_id.to_string()).collect();
        assert!(
            retired.iter().all(|key| old_ids.iter().any(|id| key.contains(id.as_str()))),
            "only superseded-past-grace parts were deleted"
        );
        assert_live_set_intact(&fx).await;
    }

    /// The lean cell's wired sanctioned route (`lean_part_gc_sanctioned_v1`,
    /// `part_ingest::part_gc_cell`) end to end over HTTPS: a mocked owner
    /// (`lake-part-deletes:authorize`, `lake-part-log:index`) that has a
    /// mocked control attest every key (grant row, holds) and index the log,
    /// and a mocked tenant Worker retention authority that deletes only on an
    /// owner-signed, prepared permit. Nothing else can delete a part here.
    mod sanctioned_route {
        use super::*;
        use axum::body::Bytes;
        use axum::extract::State;
        use axum::http::{HeaderMap, StatusCode};
        use axum::response::{IntoResponse, Response};
        use axum::routing::post;
        use axum::Router;
        use nanosiem_lake_worker::lake_part_gc::delete_control::{
            DELETE_CONTROL_CONTRACT, DELETE_CONTROL_SCHEMA_VERSION,
        };
        use nanosiem_lake_worker::part_ingest::part_gc_cell::{
            CellPartGcWiring, CellSanctionedPartGc, LakePartGcAccess, DEFAULT_LOG_READS_PER_SECOND, OWNER_DELETE_SCOPE,
            PASSES_PER_INVENTORY,
        };
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};

        const OWNER_TOKEN: &str = "owner-delete-bearer";
        const WORKER_TOKEN: &str = "retention-only-token";

        /// Hops a test can make fail (503, or a transport-looking 500).
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Hop {
            Owner,
            ControlAttest,
            ControlIndex,
            WorkerCapabilities,
            WorkerPrepare,
            WorkerRetire,
        }

        /// Control's grant row, holds, index and audit rows; the owner's and
        /// Worker's view of what happened.
        #[derive(Default)]
        struct Plane {
            control_grant_enabled: bool,
            holds: Vec<String>,
            fail: Option<Hop>,
            index_shas: Vec<String>,
            stall_index: bool,
            /// Control audit rows: one per attested key.
            attested: Vec<String>,
            /// Deleted-key records reported back to control.
            reported_deleted: Vec<String>,
            prepared: HashSet<String>,
            retired: Vec<String>,
            owner_calls: usize,
            worker_calls: usize,
            first_attest_delay: bool,
            incomplete_refusals: usize,
            last_publication: Option<(std::time::Instant, u64)>,
            phase_observations: usize,
            required_arrival: Option<(u64, String)>,
            pending_log_reservation: bool,
            last_fresh_absence: Option<(std::time::Instant, u64)>,
            refreshed_owner_tokens: HashSet<String>,
            refreshed_worker_tokens: HashSet<String>,
            used_owner_tokens: HashSet<String>,
            used_worker_tokens: HashSet<String>,
        }

        struct ObservedReader {
            inner: StorePartLogReader,
            plane: Arc<std::sync::Mutex<Plane>>,
        }
        #[async_trait]
        impl nanosiem_lake_worker::lake_part_gc::PartLogReader for ObservedReader {
            async fn verified_entry(&self, seq: u64) -> Result<Option<nanosiem_lake_worker::lake_part_gc::index::VerifiedEntryBytes>> {
                let entry = self.inner.verified_entry(seq).await?;
                if entry.is_none() {
                    self.plane.lock().unwrap().last_fresh_absence = Some((std::time::Instant::now(), seq));
                }
                Ok(entry)
            }
            async fn newest_checkpoint(&self) -> Result<Option<nanosiem_lake_worker::lake_part_gc::index::CheckpointClaim>> {
                self.inner.newest_checkpoint().await
            }
            async fn verified_provenance(&self, part: &PartRef) -> Result<nanosiem_lake_worker::parts::provenance::ProvenanceRecord> {
                self.inner.verified_provenance(part).await
            }
        }

        #[derive(Clone)]
        struct Mocks {
            plane: Arc<std::sync::Mutex<Plane>>,
            store: Arc<LocalObjectStore>,
            control_url: String,
            http: reqwest::Client,
        }

        fn refuse(status: u16, code: &str) -> Response {
            (StatusCode::from_u16(status).unwrap(), axum::Json(json!({"error": code}))).into_response()
        }

        fn bearer_is(headers: &HeaderMap, token: &str) -> bool {
            headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {token}"))
        }

        // ---- control (plain HTTP, reached only by the owner) --------------

        async fn control_attest(State(m): State<Mocks>, body: Bytes) -> Response {
            let request: LakePartDeleteRequest = match serde_json::from_slice(&body) {
                Ok(request) => request,
                Err(_) => return refuse(400, "lake_part_request_invalid"),
            };
            // Like production control, refuse while a committed entry remains
            // above the indexed head. The ongoing arrival task is never paused.
            let delay = {
                let mut plane = m.plane.lock().unwrap();
                std::mem::take(&mut plane.first_attest_delay)
            };
            if delay {
                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            }
            let next = m.plane.lock().unwrap().index_shas.len() as u64;
            let key = nanosiem_lake_worker::parts::format::LogKeys::new(TENANT)
                .unwrap()
                .entry(next);
            let next_present = m.store.get(&key).await.unwrap().is_some();
            let mut plane = m.plane.lock().unwrap();
            if plane.phase_observations < 24 {
                if let Some((published, published_next)) = plane.last_publication {
                    let absence = plane.last_fresh_absence.map(|(at, seq)| (at.elapsed().as_micros(), seq));
                    eprintln!("ATTEST publication_age_us={} published_next={} observed_next={} fresh_absence_age_seq={:?} next_present={} reserved={} refusal={}",
                        published.elapsed().as_micros(), published_next, next, absence, next_present, plane.pending_log_reservation,
                        if next_present || plane.pending_log_reservation { "lake_part_index_incomplete" } else { "none" });
                    plane.phase_observations += 1;
                }
            }
            if next_present || plane.pending_log_reservation {
                plane.incomplete_refusals += 1;
                return refuse(409, "lake_part_index_incomplete");
            }
            if plane.fail == Some(Hop::ControlAttest) {
                return refuse(503, "lake_part_attestation_unavailable");
            }
            if !plane.control_grant_enabled {
                return refuse(403, "lake_part_grant_required");
            }
            if plane.holds.iter().any(|hold| request.key.contains(hold.as_str())) {
                return refuse(409, "lake_part_held");
            }
            if request.reason != nanosiem_lake_worker::lake_part_gc::LakePartDeleteReason::Superseded
                && request.reason != nanosiem_lake_worker::lake_part_gc::LakePartDeleteReason::Orphan
            {
                // Everything else is inside the tenant's retention here.
                return refuse(409, "lake_part_within_retention");
            }
            if let Some((seq, sha)) = &plane.required_arrival {
                assert_eq!(plane.index_shas.get(*seq as usize), Some(sha),
                    "fresh arrival's exact validated chain is indexed before authorization");
            }
            plane.attested.push(request.key.clone());
            axum::Json(json!({"attested": true})).into_response()
        }

        async fn control_index(State(m): State<Mocks>, body: Bytes) -> Response {
            use base64::Engine as _;
            let request: Value = serde_json::from_slice(&body).unwrap();
            let mut plane = m.plane.lock().unwrap();
            if plane.fail == Some(Hop::ControlIndex) {
                return refuse(503, "lake_part_index_unavailable");
            }
            if plane.stall_index && !request["entries"].as_array().unwrap().is_empty() {
                return refuse(409, "lake_part_index_gap");
            }
            for entry in request["entries"].as_array().unwrap() {
                assert_eq!(entry["seq"].as_u64().unwrap(), plane.index_shas.len() as u64, "index pushed out of order");
                let bytes = base64::engine::general_purpose::STANDARD.decode(entry["entry_base64"].as_str().unwrap()).unwrap();
                let parsed = nanosiem_lake_worker::parts::part_log::LogEntry::parse_bytes(&bytes, TENANT).unwrap();
                assert_eq!(parsed.seq, plane.index_shas.len() as u64);
                assert_eq!(parsed.prev_sha256.as_str(), plane.index_shas.last().map(String::as_str)
                    .unwrap_or(nanosiem_lake_worker::parts::part_log::GENESIS_PREV),
                    "control fixture validates the exact current indexed chain");
                plane.index_shas.push(sha256_hex(&bytes));
            }
            if !request["entries"].as_array().unwrap().is_empty() {
                plane.last_publication = Some((std::time::Instant::now(), plane.index_shas.len() as u64));
            }
            for deleted in request["deleted"].as_array().unwrap() {
                plane.reported_deleted.push(deleted["key"].as_str().unwrap().to_string());
            }
            axum::Json(json!({
                "tenant_uuid": TENANT,
                "indexed_through_seq": plane.index_shas.len().checked_sub(1),
                "head_entry_sha256": plane.index_shas.last(),
                "checkpoint_seq": request["checkpoint"].get("seq"),
                "folded_through_seq": null,
            }))
            .into_response()
        }

        // ---- owner (TLS, private CA, cell bearer) --------------------------

        async fn forward(m: &Mocks, path: &str, body: Bytes) -> (u16, Bytes) {
            let response = m.http.post(format!("{}{path}", m.control_url)).body(body).send().await.unwrap();
            (response.status().as_u16(), response.bytes().await.unwrap())
        }

        async fn owner_authorize(State(m): State<Mocks>, headers: HeaderMap, body: Bytes) -> Response {
            {
                let mut plane = m.plane.lock().unwrap();
                plane.owner_calls += 1;
                let bearer = headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                plane.used_owner_tokens.insert(bearer.clone());
                if !bearer_is(&headers, OWNER_TOKEN)
                    && !plane.refreshed_owner_tokens.contains(&bearer)
                {
                    return refuse(401, "unauthorized");
                }
                if plane.fail == Some(Hop::Owner) {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "upstream reset").into_response();
                }
            }
            let (status, answer) = forward(&m, "/attest", body.clone()).await;
            if status != 200 {
                return (StatusCode::from_u16(status).unwrap(), answer).into_response();
            }
            let request: LakePartDeleteRequest = serde_json::from_slice(&body).unwrap();
            let digest = request.digest().unwrap();
            let now = chrono::Utc::now();
            axum::Json(json!({
                "request": request,
                "permit_id": request.permit_id().unwrap(),
                "owner_authorization": {
                    "schema_version": 1, "signer_key_id": "owner-test",
                    "issued_at": now.to_rfc3339(), "expires_at": (now + chrono::Duration::minutes(5)).to_rfc3339(),
                    "identity_sha256": digest, "signature_base64": format!("sig-{digest}")
                }
            }))
            .into_response()
        }

        async fn owner_index(State(m): State<Mocks>, headers: HeaderMap, body: Bytes) -> Response {
            {
                let mut plane = m.plane.lock().unwrap();
                plane.owner_calls += 1;
                let bearer = headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                plane.used_owner_tokens.insert(bearer.clone());
                if !bearer_is(&headers, OWNER_TOKEN)
                    && !plane.refreshed_owner_tokens.contains(&bearer)
                {
                    return refuse(401, "unauthorized");
                }
                if plane.fail == Some(Hop::Owner) {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "upstream reset").into_response();
                }
            }
            let (status, answer) = forward(&m, "/index", body).await;
            (StatusCode::from_u16(status).unwrap(), answer).into_response()
        }

        // ---- tenant Worker retention authority (TLS, retention bearer) -----

        fn worker_refuse(status: u16, reason: &str) -> Response {
            (StatusCode::from_u16(status).unwrap(), axum::Json(json!({"reason": reason}))).into_response()
        }

        fn worker_gate(m: &Mocks, headers: &HeaderMap, hop: Hop) -> Option<Response> {
            let mut plane = m.plane.lock().unwrap();
            plane.worker_calls += 1;
            let bearer = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            plane.used_worker_tokens.insert(bearer.clone());
            if !bearer_is(headers, WORKER_TOKEN) && !plane.refreshed_worker_tokens.contains(&bearer)
            {
                return Some(worker_refuse(401, "retention_unauthorized"));
            }
            (plane.fail == Some(hop)).then(|| worker_refuse(503, "authority_unavailable"))
        }

        /// The Worker checks the owner's signature over the permit identity.
        fn signed(permit: &Value) -> bool {
            let auth = &permit["owner_authorization"];
            auth["signature_base64"].as_str() == Some(&format!("sig-{}", auth["identity_sha256"].as_str().unwrap_or("")))
        }

        async fn worker_capabilities(State(m): State<Mocks>, headers: HeaderMap) -> Response {
            if let Some(refused) = worker_gate(&m, &headers, Hop::WorkerCapabilities) {
                return refused;
            }
            axum::Json(json!({"schema_version": DELETE_CONTROL_SCHEMA_VERSION, "contract": DELETE_CONTROL_CONTRACT,
                "operations": ["lake_part_delete"]}))
            .into_response()
        }

        async fn worker_prepare(State(m): State<Mocks>, headers: HeaderMap, body: Bytes) -> Response {
            if let Some(refused) = worker_gate(&m, &headers, Hop::WorkerPrepare) {
                return refused;
            }
            let permit: Value = serde_json::from_slice(&body).unwrap();
            if !signed(&permit) {
                return worker_refuse(403, "owner_permit_invalid");
            }
            m.plane.lock().unwrap().prepared.insert(permit["permit_id"].as_str().unwrap().to_string());
            axum::Json(permit).into_response()
        }

        async fn worker_retire(State(m): State<Mocks>, headers: HeaderMap, body: Bytes) -> Response {
            if let Some(refused) = worker_gate(&m, &headers, Hop::WorkerRetire) {
                return refused;
            }
            let permit: Value = serde_json::from_slice(&body).unwrap();
            let permit_id = permit["permit_id"].as_str().unwrap().to_string();
            if !signed(&permit) || !m.plane.lock().unwrap().prepared.contains(&permit_id) {
                return worker_refuse(409, "tombstone_missing");
            }
            let key = permit["request"]["key"].as_str().unwrap().to_string();
            let Some(bytes) = m.store.get(&key).await.unwrap() else {
                return worker_refuse(409, "object_missing");
            };
            if permit["request"]["strong_etag"].as_str()
                != Some(&format!("\"{}\"", sha256_hex(&bytes)))
                || permit["request"]["content_length"].as_u64() != Some(bytes.len() as u64)
            {
                return worker_refuse(409, "identity_mismatch");
            }
            m.store.delete(&key).await.unwrap();
            assert!(m.store.get(&key).await.unwrap().is_none());
            m.plane.lock().unwrap().retired.push(key);
            axum::Json(json!({
                "schema_version": DELETE_CONTROL_SCHEMA_VERSION,
                "permit_id": permit_id,
                "identity_sha256": permit["owner_authorization"]["identity_sha256"],
                "receipt_sha256": sha256_hex(permit_id.as_bytes()),
                "state": "receipt_appended",
                "final_head_absent": true,
            }))
            .into_response()
        }

        // ---- TLS plumbing ---------------------------------------------------

        struct Ca {
            issuer: CertifiedIssuer<'static, KeyPair>,
        }

        impl Ca {
            fn new() -> Self {
                let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                params.distinguished_name.push(DnType::CommonName, "test private CA");
                Self { issuer: CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap() }
            }

            fn leaf(&self) -> (Vec<u8>, KeyPair) {
                let key = KeyPair::generate().unwrap();
                let cert = CertificateParams::new(vec!["localhost".to_string()]).unwrap().signed_by(&key, &self.issuer).unwrap();
                (cert.der().to_vec(), key)
            }
        }

        async fn serve_tls(app: Router, leaf: (Vec<u8>, KeyPair)) -> u16 {
            use hyper_util::rt::TokioIo;
            use hyper_util::service::TowerToHyperService;
            use tokio_rustls::rustls;
            let (der, leaf_key) = leaf;
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let config = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![rustls::pki_types::CertificateDer::from(der)],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
                )
                .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else { return };
                    let (acceptor, app) = (acceptor.clone(), app.clone());
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else { return };
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(tls), TowerToHyperService::new(app))
                            .await;
                    });
                }
            });
            port
        }

        /// The mocked planes plus the cell's wired pass over them.
        struct Harness {
            plane: Arc<std::sync::Mutex<Plane>>,
            pass: Arc<CellSanctionedPartGc>,
            worker_port: u16,
            _ca_dir: tempfile::TempDir,
        }

        fn access(worker_port: u16) -> LakePartGcAccess {
            LakePartGcAccess::parse(&access_json(worker_port)).unwrap()
        }

        fn access_json(worker_port: u16) -> Value {
            json!({
                "schema_version": 1,
                "owner_delete": {"token": OWNER_TOKEN, "audience": "owner", "scope": OWNER_DELETE_SCOPE,
                    "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339()},
                "retention_authority": {"url": format!("https://localhost:{worker_port}/"), "token": WORKER_TOKEN},
                "policy": {"max_requests": 512, "log_reads_per_second": 200}
            })
        }

        async fn harness(fx: &Fixture) -> Harness {
            harness_with_reader(fx, None).await
        }

        /// NAN-4566: one sanctioned pass over a complete view, whatever the
        /// scheduling. `run_pass_now` folds the part log in bounded slices
        /// (production's 2 s `CATCH_UP_SLICE`) and pauses `log_catching_up`
        /// when a slice ends before the log head: the harness's 321-entry log
        /// at 200 paced reads/s sits right at that cut, so a busy farm runner
        /// returned the pause before the pass ever reached control. That pause
        /// is production's routine answer and its task keeps folding on it
        /// (`run_catch_up`); do the same here. Every slice applies at least
        /// one entry, so the fold ends within `log entries + 1` passes, and a
        /// pass that stops to fold must not have reached any plane.
        async fn pass_over_complete_view(fx: &Fixture, h: &Harness, now: i64) -> nanosiem_lake_worker::lake_part_gc::PassReport {
            let entries = live(fx).await.head().map_or(0, |(seq, _, _)| seq + 1);
            for _ in 0..=entries {
                let report = h.pass.run_pass_now(now).await.unwrap();
                if report.paused_reason.as_deref() != Some("log_catching_up") {
                    return report;
                }
                let plane = h.plane.lock().unwrap();
                assert_eq!((report.indexed, report.deleted), (0, 0), "a folding pass publishes and deletes nothing: {report:?}");
                assert_eq!((plane.owner_calls, plane.worker_calls), (0, 0), "a folding pass reaches no plane: {report:?}");
                assert!(plane.attested.is_empty() && plane.retired.is_empty());
            }
            panic!("the bounded fold did not reach the log head within {} passes", entries + 1);
        }

        async fn harness_with_reader(fx: &Fixture, reader: Option<Arc<dyn nanosiem_lake_worker::lake_part_gc::PartLogReader>>) -> Harness {
            harness_with_inputs(fx, reader, None).await
        }

        async fn harness_with_inputs(
            fx: &Fixture,
            reader: Option<Arc<dyn nanosiem_lake_worker::lake_part_gc::PartLogReader>>,
            lister: Option<Arc<dyn PartObjectLister>>,
        ) -> Harness {
            let store = Arc::new(LocalObjectStore::new(fx.root.join("parts")).unwrap());
            let plane = Arc::new(std::sync::Mutex::new(Plane { control_grant_enabled: true, ..Plane::default() }));
            let http = reqwest::Client::new();
            // Control first (plain HTTP; only the owner reaches it).
            let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let control_url = format!("http://{}", control_listener.local_addr().unwrap());
            let mocks = Mocks { plane: plane.clone(), store: store.clone(), control_url, http };
            let control = Router::new()
                .route("/attest", post(control_attest))
                .route("/index", post(control_index))
                .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024))
                .with_state(mocks.clone());
            tokio::spawn(async move { axum::serve(control_listener, control).await.unwrap() });

            let ca = Ca::new();
            let owner = Router::new()
                .route("/internal/v1/enterprise-shared/lake-part-deletes:authorize", post(owner_authorize))
                .route("/internal/v1/enterprise-shared/lake-part-log:index", post(owner_index))
                .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024))
                .with_state(mocks.clone());
            let owner_port = serve_tls(owner, ca.leaf()).await;
            let worker = Router::new()
                .route("/admin/retention/capabilities", post(worker_capabilities))
                .route("/admin/retention/lake-part/prepare", post(worker_prepare))
                .route("/admin/retention/lake-part/retire", post(worker_retire))
                .with_state(mocks);
            let worker_port = serve_tls(worker, ca.leaf()).await;

            let ca_dir = tempfile::tempdir().unwrap();
            let ca_file = ca_dir.path().join("owner-server-ca.crt");
            std::fs::write(&ca_file, ca.issuer.pem()).unwrap();
            let roots = reqwest::Certificate::from_pem_bundle(ca.issuer.pem().as_bytes()).unwrap();
            let worker_http = reqwest::Client::builder().https_only(true).tls_certs_only(roots).build().unwrap();
            let pass = CellSanctionedPartGc::new(CellPartGcWiring {
                tenant_uuid: TENANT.into(),
                owner_url: format!("https://localhost:{owner_port}/internal/v1/enterprise-shared/lake-parts:sign"),
                owner_ca_file: Some(ca_file),
                reader: reader.unwrap_or_else(|| Arc::new(ObservedReader {
                    inner: StorePartLogReader::new(store.clone(), TENANT, trusted()).unwrap(),
                    plane: plane.clone(),
                })),
                lister: lister.unwrap_or_else(|| Arc::new(StoreLister(store))),
                state_dir: Some(fx.root.join("gc-state")),
                worker_http: Some(worker_http),
            })
            .unwrap()
            // Wall-clock tests delete hundreds of keys; production paces
            // authorizes at 240/min (covered by the executor's paused-clock test).
            .with_authorizes_per_minute(1_000_000);
            pass.update(Some(&access(worker_port)), Some(&grant(true)));
            Harness { plane, pass: Arc::new(pass), worker_port, _ca_dir: ca_dir }
        }

        /// Real S3 pagination, deliberately slower than log arrivals. The
        /// production OpenDAL lister finishes one inventory per owned task.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn sustained_arrivals_during_real_s3_pages_reach_receipted_absence() {
            sustained_arrival_fixture(1000, false, 50).await;
        }

        // Retained overload reproduction; combined transport integration must
        // rerun this exact paced domain before claiming 50/s convergence.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[ignore = "50/s standalone convergence remains unresolved; explicit diagnostic"]
        async fn sustained_arrivals_50_per_second_phase_diagnostic() {
            sustained_arrival_fixture(1000, false, 20).await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn adversarial_refresh_faster_than_s3_pages_fails_closed_at_bounded_retries() {
            sustained_arrival_fixture(10, true, 50).await;
        }

        async fn sustained_arrival_fixture(refresh_ms: u64, adversarial: bool, arrival_ms: u64) {
            use tracing_subscriber::prelude::*;
            let _ = tracing_subscriber::registry().with(
                tracing_subscriber::fmt::layer().with_ansi(false).without_time().with_filter(
                    tracing_subscriber::filter::filter_fn(|meta| *meta.level() == tracing::Level::INFO
                        && meta.target() == "nanosiem_lake_worker::lake_part_gc::executor")
                )
            ).try_init();
            use nanosiem_lake_worker::part_ingest::s3_store::{S3Location, S3ObjectStore};
            use nanosiem_lake_worker::parts::format::LogKeys;
            use nanosiem_lake_worker::parts::part_log::{LogEntry, LogOp, LOG_FORMAT};
            #[derive(Clone)]
            struct Pages {
                objects: Arc<Vec<ListedPartObject>>,
                calls: Arc<AtomicUsize>,
                starts: Arc<AtomicUsize>,
                store: Arc<LocalObjectStore>,
            }
            async fn page(
                State(p): State<Pages>,
                axum::extract::Query(query): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >,
            ) -> Response {
                p.calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if !query.contains_key("continuation-token") && !query.contains_key("start-after") {
                    p.starts.fetch_add(1, Ordering::SeqCst);
                }
                let start = query
                    .get("continuation-token")
                    .map(|v| v.parse::<usize>().unwrap())
                    .unwrap_or_else(|| {
                        query
                            .get("start-after")
                            .map(|key| p.objects.partition_point(|object| object.key <= *key))
                            .unwrap_or(0)
                    });
                let end = (start + 64).min(p.objects.len());
                let mut xml = format!("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>parts</Name><Prefix>{}</Prefix><IsTruncated>{}</IsTruncated>", query.get("prefix").unwrap(), end < p.objects.len());
                if end < p.objects.len() {
                    xml.push_str(&format!(
                        "<NextContinuationToken>{end}</NextContinuationToken>"
                    ));
                }
                for object in &p.objects[start..end] {
                    if p.store.get(&object.key).await.unwrap().is_none() { continue; }
                    xml.push_str(&format!("<Contents><Key>{}</Key><LastModified>2020-01-01T00:00:00Z</LastModified><ETag>{}</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>", object.key, object.strong_etag, object.content_length));
                }
                xml.push_str("</ListBucketResult>");
                ([(axum::http::header::CONTENT_TYPE, "application/xml")], xml).into_response()
            }
            struct S3Lister(Arc<S3ObjectStore>, Arc<AtomicUsize>);
            #[async_trait]
            impl PartObjectLister for S3Lister {
                fn inventory_scope(&self) -> Option<String> {
                    Some(self.0.inventory_scope())
                }
                async fn list_part_objects(&self, prefix: &str) -> Result<Vec<ListedPartObject>> {
                    self.1.fetch_add(1, Ordering::SeqCst);
                    self.0.list_with_metadata(prefix).await
                }
            }
            let fx = fixture(420, 12);
            let (mut ingestor, clock) = merged(&fx).await;
            let now = clock + 30 * 60_000;
            let (old, young) = superseded(&fx, now, 3_600_000).await;
            let old_ids: HashSet<_> = old.iter().map(|part| part.part_id.to_string()).collect();
            let prefix = format!(
                "{}/tenant={TENANT}/parts/",
                nanosiem_lake_worker::parts::format::PARTS_ROOT
            );
            let store = Arc::new(fx.parts.clone());
            let foreign = format!(
                "{}/tenant=00000000-0000-0000-0000-000000000099/parts/sentinel",
                nanosiem_lake_worker::parts::format::PARTS_ROOT
            );
            store.put(&foreign, b"another tenant").await.unwrap();
            let objects = StoreLister(store.clone())
                .list_part_objects(&prefix)
                .await
                .unwrap();
            let expected: HashSet<_> = objects.iter().filter_map(|object| {
                let parsed = nanosiem_lake_worker::lake_part_gc::request::parse_part_file_key(&object.key)?;
                (old_ids.contains(&parsed.part_id.to_string()) && !parsed.is_provenance()).then(|| object.key.clone())
            }).collect();
            assert!(expected.len() > 512, "exercise multiple bounded passes including auxiliary files");
            assert!(objects.len() > 64);
            let calls = Arc::new(AtomicUsize::new(0));
            let starts = Arc::new(AtomicUsize::new(0));
            let pages = objects.len().div_ceil(64);
            eprintln!("S3 inventory objects={} pages={pages} historical_eligible={}", objects.len(), expected.len());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let app = Router::new()
                .route("/parts", axum::routing::get(page))
                .route("/parts/", axum::routing::get(page))
                .with_state(Pages {
                    objects: Arc::new(objects),
                    calls: calls.clone(),
                    starts: starts.clone(),
                    store: store.clone(),
                });
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let location = S3Location {
                endpoint,
                region: "auto".into(),
                bucket: "parts".into(),
                prefix: String::new(),
                access_key_id: "test".into(),
                secret_access_key: "test".into(),
                session_token: None,
            };
            let s3 = Arc::new(S3ObjectStore::new(&location).unwrap());
            let listing_tasks = Arc::new(AtomicUsize::new(0));
            let lister = S3Lister(s3.clone(), listing_tasks.clone());
            let h = harness_with_inputs(&fx, None, Some(Arc::new(lister))).await;
            h.plane.lock().unwrap().first_attest_delay = true;
            // Exchange policy enables legal 200 reads/s from genesis and on every refresh.
            let gate = Arc::new(ExchangedGrantAuthority::new(TENANT, Some(h.pass.clone() as Arc<dyn SanctionedPartGc>)));
            gate.update(Some(&grant(true)));
            ingestor.set_part_gc_authority(gate);
            let set = live(&fx).await;
            let (head, sha, epoch) = set.head().unwrap();
            let (mut seq, mut prev) = (head, sha.to_string());
            let schema = set.schema().unwrap().clone();
            let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
            let arrivals = tokio::spawn(async move {
                let keys = LogKeys::new(TENANT).unwrap();
                let mut count = 0;
                loop {
                    tokio::select! {
                        _ = &mut stopped => break,
                        _ = tokio::time::sleep(std::time::Duration::from_millis(arrival_ms)) => {}
                    }
                    seq += 1;
                    let entry = LogEntry {
                        format: LOG_FORMAT.into(),
                        tenant_id: TENANT.into(),
                        seq,
                        prev_sha256: prev,
                        writer_epoch: epoch,
                        appended_at_ms: clock + count,
                        op: LogOp::Schema {
                            schema: schema.clone(),
                        },
                    };
                    let bytes = entry.to_bytes().unwrap();
                    prev = sha256_hex(&bytes);
                    store.put(&keys.entry(seq), &bytes).await.unwrap();
                    count += 1;
                }
                count
            });
            let (stop_refresh, mut refresh_stopped) = tokio::sync::oneshot::channel::<()>();
            let (gc, plane, worker_port) = (h.pass.clone(), h.plane.clone(), h.worker_port);
            let refreshes = tokio::spawn(async move {
                let mut count = 0;
                loop {
                    tokio::select! {
                        _ = &mut refresh_stopped => break,
                        _ = tokio::time::sleep(std::time::Duration::from_millis(refresh_ms)) => {}
                    }
                    count += 1;
                    let (owner, worker) = (
                        format!("{OWNER_TOKEN}-{count}"),
                        format!("{WORKER_TOKEN}-{count}"),
                    );
                    {
                        let mut plane = plane.lock().unwrap();
                        plane
                            .refreshed_owner_tokens
                            .insert(format!("Bearer {owner}"));
                        plane
                            .refreshed_worker_tokens
                            .insert(format!("Bearer {worker}"));
                    }
                    let mut credentials = access_json(worker_port);
                    credentials["owner_delete"]["token"] = json!(owner);
                    credentials["retention_authority"]["token"] = json!(worker);
                    let mut renewed = location.clone();
                    renewed.access_key_id = format!("test-{count}");
                    s3.replace(&renewed).unwrap();
                    gc.update(
                        Some(&LakePartGcAccess::parse(&credentials).unwrap()),
                        Some(&grant(true)),
                    );
                    // Every update preserves the legal 200 reads/s policy.
                    // The route remains the same authority/grant/policy contract.
                }
                count
            });
            let trace_plane = h.plane.clone();
            let trace_gc = h.pass.clone();
            let trace_calls = calls.clone();
            let trace = tokio::spawn(async move {
                let begun = std::time::Instant::now();
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    let plane = trace_plane.lock().unwrap();
                    eprintln!("PHASE elapsed_ms={} reads={} listing_http={} indexed={} owner_calls={} worker_calls={} permits={} prepares={} retires={} reports={} incomplete_refusals={}", begun.elapsed().as_millis(), trace_gc.reads(), trace_calls.load(Ordering::SeqCst), plane.index_shas.len(), plane.owner_calls, plane.worker_calls, plane.attested.len(), plane.prepared.len(), plane.retired.len(), plane.reported_deleted.len(), plane.incomplete_refusals);
                }
            });
            let mut reports = Vec::new();
            let mut completed = 0usize;
            let mut indexed_reported = 0u64;
            let mut tasks_run = 0usize;
            let mut finished = Ok(());
            // Real ingest scheduler starts distinct tasks only at the ordinary
            // ten-minute cadence; wall-clock arrivals and refresh continue.
            for task in 0..3 {
                let scheduled = now + task * nanosiem_lake_worker::part_ingest::ingest::SANCTIONED_GC_INTERVAL_MS;
                ingestor.tick(scheduled).await.unwrap();
                let proof_budget = std::time::Duration::from_millis(
                    pages as u64 * 100 + 512 * arrival_ms + 20_000);
                if let Err(error) = tokio::time::timeout(proof_budget, h.pass.wait_idle()).await {
                    finished = Err(error);
                    break;
                }
                let outcome = h.pass.poll_report(scheduled + 1).await.unwrap();
                if adversarial {
                    reports.push(outcome);
                    break;
                }
                let report = outcome.unwrap();
                // NAN-4162: one listing feeds PASSES_PER_INVENTORY bounded
                // passes of at most 512 deletes each.
                assert!(report.deleted <= 512 * PASSES_PER_INVENTORY as u64, "owned task {task}: {report:?}");
                assert_eq!(report.deleted_reported, report.deleted);
                assert!(report.paused_reason.is_none(), "owned task {task}: {report:?}");
                {
                    let plane = h.plane.lock().unwrap();
                    let end = completed + report.deleted as usize;
                    for (name, keys) in [("permit", &plane.attested), ("retire", &plane.retired), ("report", &plane.reported_deleted)] {
                        assert_eq!(keys.len(), end, "owned task {task} {name} accounting");
                        let unique: HashSet<_> = keys[completed..end].iter().cloned().collect();
                        assert_eq!(unique.len(), report.deleted as usize, "owned task {task} duplicate {name}");
                        assert!(unique.is_subset(&expected), "owned task {task} unexpected {name}");
                    }
                    assert_eq!(plane.attested[completed..end].iter().collect::<HashSet<_>>(), plane.retired[completed..end].iter().collect::<HashSet<_>>());
                    assert_eq!(plane.retired[completed..end].iter().collect::<HashSet<_>>(), plane.reported_deleted[completed..end].iter().collect::<HashSet<_>>());
                }
                indexed_reported += report.indexed;
                // NAN-3495: between passes index-only publication pushes
                // arrivals too; together they count every published prefix.
                h.pass.wait_index_idle().await;
                assert_eq!((indexed_reported + h.pass.index_only_indexed()) as usize, h.plane.lock().unwrap().index_shas.len(),
                    "owned-task and index-only reports count every published verified prefix");
                completed += report.deleted as usize;
                eprintln!("PASS owned_task={task} scheduled_ms={scheduled} budget=512 pacing=200/s cadence_ms=600000 report={report:?} reads={}", h.pass.reads());
                reports.push(Ok(report));
                tasks_run += 1;
                let starts_before = starts.load(Ordering::SeqCst);
                ingestor.tick(scheduled + 599_999).await.unwrap();
                assert_eq!(starts.load(Ordering::SeqCst), starts_before, "ordinary cadence forbids another task");
                if completed == expected.len() { break; }
            }
            stop.send(()).unwrap();
            stop_refresh.send(()).unwrap();
            let arrivals = arrivals.await.unwrap();
            let refreshes = refreshes.await.unwrap();
            server.abort();
            trace.abort();
            {
                let plane = h.plane.lock().unwrap();
                eprintln!("GC progress arrivals={arrivals} refreshes={refreshes} list_http={} starts={} indexed={} owner_calls={} worker_calls={} attested={} retired={} reported={}", calls.load(Ordering::SeqCst), starts.load(Ordering::SeqCst), plane.index_shas.len(), plane.owner_calls, plane.worker_calls, plane.attested.len(), plane.retired.len(), plane.reported_deleted.len());
            }
            finished.unwrap();
            let outcome = reports.pop().expect("completed owned task");
            if adversarial {
                let error = outcome.unwrap_err();
                assert!(format!("{error:#}").contains("credential restart budget exhausted"), "{error:#}");
                {
                    // NAN-3495: index-only publication may reach the owner's
                    // index route (no listing, no fence on S3 pages); nothing
                    // is ever attested, prepared or retired.
                    let plane = h.plane.lock().unwrap();
                    assert!(plane.attested.is_empty());
                    assert_eq!(plane.worker_calls, 0);
                    assert!(plane.retired.is_empty());
                }
                assert!(calls.load(Ordering::SeqCst) <= 33, "bounded refresh attempts");
                assert_nothing_deleted(&fx).await;
                eprintln!("PASS adversarial rapid refresh closed at bounded listing retries, zero authority/delete hops");
                return;
            }
            let report = outcome.unwrap();
            assert!(report.paused_reason.is_none(), "{report:?}");
            assert!(
                refreshes > 1,
                "ordinary exchange refreshes must overlap pagination and deletion"
            );
            assert!(
                arrivals >= pages as i64 * 3,
                "arrivals must continue throughout the slow listing"
            );
            assert_eq!(
                listing_tasks.load(Ordering::SeqCst),
                tasks_run,
                "one full listing per distinct owned task (credential refresh may retry the first HTTP page)"
            );
            assert!(
                calls.load(Ordering::SeqCst) <= pages * 3 + refreshes + 3,
                "only obsolete in-flight pages may be retried"
            );
            assert_eq!(completed, expected.len(), "full union across owned tasks");
            assert_eq!(expected.len(), 1360);
            assert_eq!(report.deleted_reported, report.deleted);
            {
                let plane = h.plane.lock().unwrap();
                assert!(plane.index_shas.len() > head as usize + 1);
                assert!(plane
                    .used_owner_tokens
                    .iter()
                    .any(|token| plane.refreshed_owner_tokens.contains(token)));
                assert!(plane
                    .used_worker_tokens
                    .iter()
                    .any(|token| plane.refreshed_worker_tokens.contains(token)));
                assert!(
                    plane.incomplete_refusals > 0,
                    "must retry the authoritative incomplete-index refusal"
                );
                assert_eq!(
                    plane.retired.iter().cloned().collect::<HashSet<_>>(),
                    expected
                );
                assert_eq!(
                    plane.retired.len(),
                    expected.len(),
                    "no duplicate actual deletion"
                );
                assert_eq!(
                    plane
                        .reported_deleted
                        .iter()
                        .cloned()
                        .collect::<HashSet<_>>(),
                    expected
                );
                assert_eq!(
                    plane.attested.iter().cloned().collect::<HashSet<_>>(),
                    expected
                );
                assert_eq!(plane.prepared.len(), expected.len());
                assert_eq!(plane.attested.len(), expected.len(), "no duplicate permit");
                assert_eq!(plane.reported_deleted.len(), expected.len(), "no duplicate report");
                eprintln!("PASS arrivals={arrivals} refreshes={refreshes} pages={pages} indexed={} authorize={} prepare={} retire={} receipt={} report={}", plane.index_shas.len(), plane.attested.len(), plane.prepared.len(), plane.retired.len(), completed, completed);
            }
            for key in expected {
                assert!(
                    !exists(&fx, &key).await,
                    "historical eligible key remains: {key}"
                );
            }
            assert!(
                exists(&fx, &foreign).await,
                "distinct tenant object must remain"
            );
            assert_kept(&fx, &all_part_files(&young), "within grace").await;
            assert_kept(
                &fx,
                &old.iter().map(provenance_key).collect::<Vec<_>>(),
                "protected provenance",
            )
            .await;
            assert_live_set_intact(&fx).await;
        }

        fn all_part_files(parts: &[PartRef]) -> Vec<String> {
            parts.iter().flat_map(|p| data_keys(p).into_iter().chain([provenance_key(p)])).collect()
        }

        async fn assert_kept(fx: &Fixture, keys: &[String], why: &str) {
            for key in keys {
                assert!(exists(fx, key).await, "{why}: {key} was deleted");
            }
        }

        /// Enabled grant + control attestation: superseded data files past
        /// grace are deleted through the ingest gate, each with a control
        /// audit row and a reported receipt. Live parts, parts within grace
        /// and retained provenance stay.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn enabled_grant_and_attestation_delete_through_the_wired_route() {
            let fx = fixture(420, 12);
            let (mut ingestor, clock) = merged(&fx).await;
            let now = clock + 30 * 60_000;
            let h = harness(&fx).await;
            let gate = Arc::new(ExchangedGrantAuthority::new(TENANT, Some(h.pass.clone() as Arc<dyn SanctionedPartGc>)));
            gate.update(Some(&grant(true)));
            ingestor.set_part_gc_authority(gate);

            // Completion is collected before the full-pass cadence permits
            // another start. This exercises the actual ingest health path.
            let later = now + 1;
            let (old, young) = superseded(&fx, later, 3_600_000).await;
            assert!(!old.is_empty());
            ingestor.tick(now).await.unwrap();
            h.pass.wait_idle().await;
            let owner_calls = h.plane.lock().unwrap().owner_calls;
            ingestor.tick(later).await.unwrap();
            h.pass.wait_idle().await;
            assert_eq!(h.plane.lock().unwrap().owner_calls, owner_calls, "polling must not start another full pass");

            let health = ingestor.health();
            assert!(health.part_gc_deleted_total > 0, "{:?} {:?}", health.part_gc_blocked, health.part_gc_last_pause);
            assert!(health.part_gc_blocked.is_none(), "{:?}", health.part_gc_blocked);
            let plane = h.plane.lock().unwrap();
            let old_provenance: HashSet<String> = old.iter().map(provenance_key).collect();
            let retired: HashSet<String> = plane.retired.iter().cloned().collect();
            assert!(retired.len() as u64 >= health.part_gc_deleted_total);
            for key in &retired {
                // Data files, token sidecars and partials of a superseded
                // part past grace; never its provenance.
                assert!(
                    old.iter().any(|p| key.contains(&format!("/{}/", p.part_id))) && !old_provenance.contains(key),
                    "{key} is not a superseded-past-grace part file"
                );
            }
            assert!(
                old.iter().flat_map(data_keys).any(|key| retired.contains(&key)),
                "superseded data files were deleted"
            );
            let attested: HashSet<String> = plane.attested.iter().cloned().collect();
            assert!(retired.is_subset(&attested), "every delete has a control attestation row");
            let reported: HashSet<String> = plane.reported_deleted.iter().cloned().collect();
            assert!(retired.is_subset(&reported), "every receipted delete is reported back to control");
            drop(plane);
            for key in &retired {
                assert!(!exists(&fx, key).await, "{key} survived its receipt");
            }
            // Retained: superseded provenance stays until retention.
            assert_kept(&fx, &old.iter().map(provenance_key).collect::<Vec<_>>(), "retained provenance").await;
            assert_kept(&fx, &all_part_files(&young), "superseded within grace").await;
            assert_live_set_intact(&fx).await;
        }

        /// NAN-4601, the large-tenant hold (2026-10-25): catalog attach failed, so
        /// ingest holds the recorded catalog. Deletes stay held (fail closed)
        /// but the part-log index keeps following the log through the same
        /// wired route: before this, the hold dropped the whole gate and the
        /// index head froze with it. Production path: `Ingestor::open`, the
        /// cell's gate (`ExchangedGrantAuthority`) over the cell's pass, an
        /// enabled grant, then the hold the activation records.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_held_catalog_keeps_the_index_feed_and_deletes_nothing() {
            let fx = fixture(420, 12);
            let (mut ingestor, clock) = merged(&fx).await;
            let (old, _) = superseded(&fx, clock + 30 * 60_000, 3_600_000).await;
            assert!(!old.is_empty(), "there is something a delete pass would take");
            let h = harness(&fx).await;
            let gate = Arc::new(ExchangedGrantAuthority::new(TENANT, Some(h.pass.clone() as Arc<dyn SanctionedPartGc>)));
            gate.update(Some(&grant(true)));
            // The activation.rs order (catalog_attach_failed, the large tenant): the attach
            // failure is recorded first, then the cell installs the gate
            // (`set_part_gc_authority` holds it). The cell.rs report-failure
            // order (gate first, then `hold_catalog`) moves the installed gate
            // aside through the same `take()`.
            ingestor.hold_catalog("catalog_attach_failed");
            ingestor.set_part_gc_authority(gate.clone());

            let mut now = clock + 30 * 60_000;
            let first = now;
            tokio::time::timeout(std::time::Duration::from_secs(60), async {
                loop {
                    ingestor.tick(now).await.unwrap();
                    h.pass.wait_index_idle().await;
                    let head = live(&fx).await.head().map(|(seq, _, _)| seq).unwrap();
                    if h.plane.lock().unwrap().index_shas.len() as u64 == head + 1 {
                        break;
                    }
                    // Past the index-only cadence (60 s, jittered, backs off to 5 min).
                    now += 6 * 60_000;
                }
            })
            .await
            .expect("the part-log index reached the log head while the catalog was held");

            // Deletes stay held: nothing planned, authorized, attested or deleted.
            {
                let plane = h.plane.lock().unwrap();
                assert!(plane.attested.is_empty() && plane.retired.is_empty() && plane.prepared.is_empty(),
                    "a held catalog never deletes");
                assert_eq!(plane.worker_calls, 0, "no Worker call while held");
                assert!(plane.reported_deleted.is_empty());
            }
            h.pass.wait_idle().await;
            let health = ingestor.health();
            assert_eq!(health.part_gc_deleted_total, 0);
            let blocked = health.part_gc_blocked.as_ref().expect("the hold is reported");
            assert_eq!((blocked.reason.as_str(), blocked.detail.as_str()), ("catalog_held", "catalog_attach_failed"));
            assert_eq!(blocked.blocked_seconds, ((now - first) / 1000) as u64, "held time counts from the first held tick");
            assert!(blocked.parts > 0, "the superseded parts it keeps");
            let metrics = blocked.metric_lines("c", "t");
            assert!(metrics.contains("lake_part_gc_blocked_seconds{cell=\"c\",tenant=\"t\",reason=\"catalog_held\",detail=\"catalog_attach_failed\"}"),
                "{metrics}");
            assert_eq!(health.agent_catalog.as_ref().unwrap()["gc_attached"], false);
            assert_nothing_deleted(&fx).await;
            assert_live_set_intact(&fx).await;
        }

        struct PausedHistory {
            reader: StorePartLogReader,
            reached: tokio::sync::Notify,
            resume: tokio::sync::Notify,
            paused: std::sync::atomic::AtomicBool,
        }

        #[async_trait]
        impl nanosiem_lake_worker::lake_part_gc::PartLogReader for PausedHistory {
            async fn verified_entry(
                &self,
                seq: u64,
            ) -> Result<Option<nanosiem_lake_worker::lake_part_gc::index::VerifiedEntryBytes>>
            {
                if seq == 2048 && !self.paused.swap(true, Ordering::SeqCst) {
                    self.reached.notify_one();
                    self.resume.notified().await;
                }
                self.reader.verified_entry(seq).await
            }
            async fn newest_checkpoint(
                &self,
            ) -> Result<Option<nanosiem_lake_worker::lake_part_gc::index::CheckpointClaim>>
            {
                self.reader.newest_checkpoint().await
            }
            async fn verified_provenance(
                &self,
                part: &PartRef,
            ) -> Result<nanosiem_lake_worker::parts::provenance::ProvenanceRecord> {
                self.reader.verified_provenance(part).await
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn fresh_cell_catches_up_large_signed_history_before_any_delete() {
            use nanosiem_lake_worker::parts::format::LogKeys;
            use nanosiem_lake_worker::parts::part_log::{LogEntry, LogOp, LOG_FORMAT};
            let fx = fixture(420, 12);
            let (_ingestor, clock) = merged(&fx).await;
            let set = live(&fx).await;
            let (mut seq, mut prev, epoch) = set
                .head()
                .map(|(seq, sha, epoch)| (seq, sha.to_string(), epoch))
                .unwrap();
            let keys = LogKeys::new(TENANT).unwrap();
            // Canonical schema commits extend a real ingestor-produced log;
            // its live parts retain their owner-signed provenance.
            for n in 0..6144 {
                seq += 1;
                let entry = LogEntry {
                    format: LOG_FORMAT.into(),
                    tenant_id: TENANT.into(),
                    seq,
                    prev_sha256: prev,
                    writer_epoch: epoch,
                    appended_at_ms: clock + n,
                    op: LogOp::Schema {
                        schema: set.schema().unwrap().clone(),
                    },
                };
                let bytes = entry.to_bytes().unwrap();
                prev = sha256_hex(&bytes);
                fx.parts.put(&keys.entry(seq), &bytes).await.unwrap();
            }
            let reader = Arc::new(PausedHistory {
                reader: StorePartLogReader::new(Arc::new(fx.parts.clone()), TENANT, trusted())
                    .unwrap(),
                reached: tokio::sync::Notify::new(),
                resume: tokio::sync::Notify::new(),
                paused: std::sync::atomic::AtomicBool::new(false),
            });
            let mut h = harness_with_reader(&fx, Some(reader.clone())).await;
            // Keep the same route but remove wall-clock read delays in this test.
            let pass = Arc::try_unwrap(h.pass)
                .ok()
                .unwrap()
                .with_log_reads_per_second(0);
            h.pass = Arc::new(pass);
            let now = clock + 30 * 60_000;
            h.pass.run_pass(now).await.unwrap();
            tokio::time::timeout(
                std::time::Duration::from_secs(20),
                reader.reached.notified(),
            )
            .await
            .unwrap();
            {
                let plane = h.plane.lock().unwrap();
                assert_eq!((plane.owner_calls, plane.worker_calls), (0, 0));
                assert!(plane.retired.is_empty());
            }
            assert_nothing_deleted(&fx).await;
            reader.resume.notify_one();
            tokio::time::timeout(std::time::Duration::from_secs(30), h.pass.wait_idle())
                .await
                .unwrap();
            let report = h.pass.poll_report(now + 1).await.unwrap().unwrap();
            assert!(report.paused_reason.is_none(), "{report:?}");
            assert!(
                report.deleted > 0,
                "a full verified view must permit real candidate deletes"
            );
            let plane = h.plane.lock().unwrap();
            assert_eq!(plane.index_shas.len() as u64, seq + 1);
            assert_eq!(
                report.indexed,
                seq + 1,
                "all bounded index slices are reported"
            );
            assert_eq!(plane.retired.len() as u64, report.deleted);
            // NAN-4162: one task runs at most PASSES_PER_INVENTORY bounded
            // passes (each at most 512 deletes) from its one listing.
            assert!(
                report.deleted <= 512 * PASSES_PER_INVENTORY as u64,
                "catch-up must run at most one task's bounded destructive passes"
            );
            assert!(plane.retired.iter().all(|key| plane.attested.contains(key)));
            drop(plane);
            assert_live_set_intact(&fx).await;
        }

        /// Append `count` schema entries to the fixture's signed log; the
        /// last sequence.
        async fn extend_log(fx: &Fixture, clock: i64, count: i64) -> u64 {
            use nanosiem_lake_worker::parts::format::LogKeys;
            use nanosiem_lake_worker::parts::part_log::{LogEntry, LogOp, LOG_FORMAT};
            let set = live(fx).await;
            let (mut seq, mut prev, epoch) = set.head().map(|(seq, sha, epoch)| (seq, sha.to_string(), epoch)).unwrap();
            let keys = LogKeys::new(TENANT).unwrap();
            for n in 0..count {
                seq += 1;
                let entry = LogEntry {
                    format: LOG_FORMAT.into(),
                    tenant_id: TENANT.into(),
                    seq,
                    prev_sha256: prev,
                    writer_epoch: epoch,
                    appended_at_ms: clock + n,
                    op: LogOp::Schema { schema: set.schema().unwrap().clone() },
                };
                let bytes = entry.to_bytes().unwrap();
                prev = sha256_hex(&bytes);
                fx.parts.put(&keys.entry(seq), &bytes).await.unwrap();
            }
            seq
        }

        /// The SHA-256 of log entries `0..=through`, as control indexed them.
        async fn log_shas(fx: &Fixture, through: u64) -> Vec<String> {
            let keys = nanosiem_lake_worker::parts::format::LogKeys::new(TENANT).unwrap();
            let mut shas = Vec::new();
            for seq in 0..=through {
                shas.push(sha256_hex(&fx.parts.get(&keys.entry(seq)).await.unwrap().unwrap()));
            }
            shas
        }

        /// Blocks the first read of `hold` until resumed; records every read.
        struct HeldFold {
            reader: StorePartLogReader,
            hold: u64,
            reached: tokio::sync::Notify,
            resume: tokio::sync::Notify,
            held: std::sync::atomic::AtomicBool,
            reads: std::sync::Mutex<Vec<u64>>,
        }

        #[async_trait]
        impl nanosiem_lake_worker::lake_part_gc::PartLogReader for HeldFold {
            async fn verified_entry(&self, seq: u64) -> Result<Option<nanosiem_lake_worker::lake_part_gc::index::VerifiedEntryBytes>> {
                self.reads.lock().unwrap().push(seq);
                if seq == self.hold && !self.held.swap(true, Ordering::SeqCst) {
                    self.reached.notify_one();
                    self.resume.notified().await;
                }
                self.reader.verified_entry(seq).await
            }
            async fn read_ahead_bytes(&self, seq: u64) -> Result<Option<Vec<u8>>> {
                self.reads.lock().unwrap().push(seq);
                if seq == self.hold && !self.held.swap(true, Ordering::SeqCst) {
                    self.reached.notify_one();
                    self.resume.notified().await;
                }
                self.reader.read_ahead_bytes(seq).await
            }
            async fn newest_checkpoint(&self) -> Result<Option<nanosiem_lake_worker::lake_part_gc::index::CheckpointClaim>> {
                self.reader.newest_checkpoint().await
            }
            async fn verified_provenance(&self, part: &PartRef) -> Result<nanosiem_lake_worker::parts::provenance::ProvenanceRecord> {
                self.reader.verified_provenance(part).await
            }
        }

        /// NAN-3495 (the load-test tenant r28): every cell restart starts with a cold view
        /// (its state dir is on an ephemeral volume) and the part-log index
        /// froze for the whole genesis fold (~17 min). A cold cell now
        /// publishes from control's stored head while its view folds: only
        /// the entries after that head, and nothing is planned or deleted
        /// until the fold completes. The pass then finds control at its view
        /// head and deletes as before.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_cold_view_publishes_the_index_from_controls_head_while_it_folds() {
            let fx = fixture(420, 12);
            let (_ingestor, clock) = merged(&fx).await;
            let stored_head = extend_log(&fx, clock, 3000).await;
            let head = extend_log(&fx, clock + 3000, 40).await;
            let reader = Arc::new(HeldFold {
                reader: StorePartLogReader::new(Arc::new(fx.parts.clone()), TENANT, trusted()).unwrap(),
                hold: 1024,
                reached: tokio::sync::Notify::new(),
                resume: tokio::sync::Notify::new(),
                held: std::sync::atomic::AtomicBool::new(false),
                reads: std::sync::Mutex::new(Vec::new()),
            });
            let mut h = harness_with_reader(&fx, Some(reader.clone())).await;
            h.pass = Arc::new(Arc::try_unwrap(h.pass).ok().unwrap().with_log_reads_per_second(0));
            // Control kept what the previous cell published (its stored head).
            h.plane.lock().unwrap().index_shas = log_shas(&fx, stored_head).await;
            let now = clock + 30 * 60_000;
            h.pass.run_pass(now).await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(20), reader.reached.notified()).await.unwrap();
            // The pass is folding (held at 1024). An ingest poll starts the
            // index-only publication beside it.
            assert!(h.pass.poll_report(now + 1).await.is_none(), "the pass is still folding");
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                while h.plane.lock().unwrap().index_shas.len() as u64 != head + 1 {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the index reached the log head while the view was still folding");
            {
                let plane = h.plane.lock().unwrap();
                assert!(plane.attested.is_empty() && plane.retired.is_empty() && plane.worker_calls == 0,
                    "nothing is planned or deleted from a partial view");
            }
            let reads = reader.reads.lock().unwrap().clone();
            assert!(!reads.iter().any(|seq| (1100..=stored_head).contains(seq)),
                "the index-only publication read only entries after control's head");
            assert!((stored_head + 1..=head).all(|seq| reads.contains(&seq)));
            assert_nothing_deleted(&fx).await;

            // The fold completes; the pass publishes nothing new (control is
            // at its view head) and deletes.
            reader.resume.notify_one();
            let report = tokio::time::timeout(std::time::Duration::from_secs(60), async {
                loop {
                    h.pass.wait_idle().await;
                    if let Some(report) = h.pass.poll_report(now + 2).await {
                        break report.unwrap();
                    }
                }
            })
            .await
            .unwrap();
            assert!(report.paused_reason.is_none(), "{report:?}");
            assert!(report.deleted > 0, "a complete view still deletes");
            let plane = h.plane.lock().unwrap();
            assert_eq!(plane.index_shas.len() as u64, head + 1);
            assert!(plane.retired.iter().all(|key| plane.attested.contains(key)));
            drop(plane);
            assert_live_set_intact(&fx).await;
        }

        /// NAN-3495: a persisted view older than control's index (the cell
        /// died after its index-only task published past its last view save)
        /// resumes from that checkpoint, folds the rest, and finds control at
        /// its head: no gap, no re-push, no refold from genesis.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_stale_view_checkpoint_resumes_behind_controls_index() {
            let fx = fixture(420, 12);
            let (_ingestor, clock) = merged(&fx).await;
            let now = clock + 30 * 60_000;
            let first = harness(&fx).await;
            assert!(first.pass.schedule_pass(now).await.is_none());
            tokio::time::timeout(std::time::Duration::from_secs(30), first.pass.wait_idle()).await.unwrap();
            let report = first.pass.poll_report(now + 1).await.unwrap().unwrap();
            assert!(report.paused_reason.is_none(), "{report:?}");
            let checkpoint = live(&fx).await.head().map(|(seq, _, _)| seq).unwrap();
            assert!(fx.root.join("gc-state/lake-part-gc/view.json").exists());
            drop(first);

            let head = extend_log(&fx, clock, 300).await;
            let reader = Arc::new(HeldFold {
                reader: StorePartLogReader::new(Arc::new(fx.parts.clone()), TENANT, trusted()).unwrap(),
                hold: u64::MAX,
                reached: tokio::sync::Notify::new(),
                resume: tokio::sync::Notify::new(),
                held: std::sync::atomic::AtomicBool::new(false),
                reads: std::sync::Mutex::new(Vec::new()),
            });
            let restarted = harness_with_reader(&fx, Some(reader.clone())).await;
            restarted.plane.lock().unwrap().index_shas = log_shas(&fx, head).await;
            assert!(restarted.pass.schedule_pass(now + 2).await.is_none());
            tokio::time::timeout(std::time::Duration::from_secs(30), restarted.pass.wait_idle()).await.unwrap();
            let report = restarted.pass.poll_report(now + 3).await.unwrap().unwrap();
            assert!(report.paused_reason.is_none(), "{report:?}");
            assert_eq!(report.indexed, 0, "control already had every entry");
            assert_eq!(restarted.plane.lock().unwrap().index_shas.len() as u64, head + 1);
            let reads = reader.reads.lock().unwrap().clone();
            assert!(!reads.iter().any(|seq| *seq < checkpoint), "resumed from the checkpoint, not genesis: {:?}",
                reads.iter().min());
            assert_live_set_intact(&fx).await;
        }

        struct ArrivalAtRecheck {
            reader: StorePartLogReader,
            store: Arc<LocalObjectStore>,
            entry: nanosiem_lake_worker::parts::part_log::LogEntry,
            plane: std::sync::Mutex<Option<Arc<std::sync::Mutex<Plane>>>>,
            probes: AtomicUsize,
            /// (event, any key already deleted when it was observed)
            observations: std::sync::Mutex<Vec<(&'static str, bool)>>,
        }
        #[async_trait]
        impl nanosiem_lake_worker::lake_part_gc::PartLogReader for ArrivalAtRecheck {
            async fn verified_entry(
                &self,
                seq: u64,
            ) -> Result<Option<nanosiem_lake_worker::lake_part_gc::index::VerifiedEntryBytes>>
            {
                if seq == self.entry.seq && self.probes.fetch_add(1, Ordering::SeqCst) == 1 {
                    assert!(
                        self.plane
                            .lock()
                            .unwrap()
                            .as_ref()
                            .unwrap()
                            .lock()
                            .unwrap()
                            .retired
                            .is_empty(),
                        "arrival precedes any delete"
                    );
                    let key = nanosiem_lake_worker::parts::format::LogKeys::new(TENANT)
                        .unwrap()
                        .entry(seq);
                    self.store
                        .put(&key, &self.entry.to_bytes().unwrap())
                        .await?;
                }
                let entry = self.reader.verified_entry(seq).await?;
                let event = if seq == self.entry.seq {
                    Some(if entry.is_some() { "arrival_observed" } else { "fresh_initial_absence" })
                } else if seq == self.entry.seq + 1 && entry.is_none() {
                    Some("fresh_successor_absence")
                } else { None };
                if let Some(event) = event {
                    // NAN-4162: later bounded passes of the same task re-read
                    // the tail after the first pass deleted; the test checks
                    // that the first pass's observations precede deletion.
                    let deleted = !self.plane.lock().unwrap().as_ref().unwrap().lock().unwrap().retired.is_empty();
                    let mut observations = self.observations.lock().unwrap();
                    assert!(observations.len() < 32 * PASSES_PER_INVENTORY, "bounded fresh-read event observations");
                    observations.push((event, deleted));
                }
                Ok(entry)
            }
            async fn newest_checkpoint(
                &self,
            ) -> Result<Option<nanosiem_lake_worker::lake_part_gc::index::CheckpointClaim>>
            {
                self.reader.newest_checkpoint().await
            }
            async fn verified_provenance(
                &self,
                part: &PartRef,
            ) -> Result<nanosiem_lake_worker::parts::provenance::ProvenanceRecord> {
                self.reader.verified_provenance(part).await
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn arrival_after_listing_resumes_bounded_fold_before_deletion() {
            use nanosiem_lake_worker::parts::part_log::{LogEntry, LogOp, LOG_FORMAT};
            let fx = fixture(420, 12);
            let (_ingestor, clock) = merged(&fx).await;
            let set = live(&fx).await;
            let (seq, prev, epoch) = set.head().unwrap();
            let store = Arc::new(fx.parts.clone());
            let reader = Arc::new(ArrivalAtRecheck {
                reader: StorePartLogReader::new(store.clone(), TENANT, trusted()).unwrap(),
                store,
                plane: std::sync::Mutex::new(None),
                probes: AtomicUsize::new(0),
                observations: std::sync::Mutex::new(Vec::new()),
                entry: LogEntry {
                    format: LOG_FORMAT.into(),
                    tenant_id: TENANT.into(),
                    seq: seq + 1,
                    prev_sha256: prev.into(),
                    writer_epoch: epoch,
                    appended_at_ms: clock,
                    op: LogOp::Schema {
                        schema: set.schema().unwrap().clone(),
                    },
                },
            });
            let mut h = harness_with_reader(&fx, Some(reader.clone())).await;
            *reader.plane.lock().unwrap() = Some(h.plane.clone());
            h.plane.lock().unwrap().required_arrival = Some((reader.entry.seq,
                sha256_hex(&reader.entry.to_bytes().unwrap())));
            let expected_head = reader.entry.seq;
            let pass = Arc::try_unwrap(h.pass)
                .ok()
                .unwrap()
                .with_log_reads_per_second(0);
            h.pass = Arc::new(pass);
            let now = clock + 30 * 60_000;
            h.pass.run_pass(now).await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(20), h.pass.wait_idle())
                .await
                .unwrap();
            let report = h.pass.poll_report(now + 1).await.unwrap().unwrap();
            assert!(report.paused_reason.is_none(), "{report:?}");
            assert!(report.deleted > 0);
            assert_eq!(
                h.plane.lock().unwrap().index_shas.len() as u64,
                expected_head + 1
            );
            let observations = reader.observations.lock().unwrap();
            eprintln!("ARRIVAL_FRESHNESS events={observations:?} actual_tail_reads={}",
                reader.probes.load(Ordering::SeqCst));
            let position = |event| observations.iter().position(|(seen, _)| *seen == event).unwrap();
            let arrival = position("arrival_observed");
            assert!(position("fresh_initial_absence") < arrival);
            // Initial ordered read-ahead may speculatively observe a higher
            // missing sequence. Require a NEW real successor probe after the
            // canonical arrival is observed, not the first speculative probe.
            let successor = arrival + 1 + observations[arrival + 1..].iter()
                .position(|(seen, _)| *seen == "fresh_successor_absence").expect("a fresh successor probe after the arrival");
            assert!(observations[..=successor].iter().all(|(_, deleted)| !deleted),
                "fresh tail and arrival observations precede deletion: {observations:?}");
            assert_eq!(
                h.plane.lock().unwrap().index_shas[expected_head as usize],
                sha256_hex(&reader.entry.to_bytes().unwrap()),
                "the newly present canonical arrival is indexed before any deletion"
            );
            assert_live_set_intact(&fx).await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn current_index_with_uncommitted_reservation_never_authorizes() {
            let fx = fixture(420, 12);
            let (_ingestor, clock) = merged(&fx).await;
            let h = harness(&fx).await;
            reservation_never_authorizes(&fx, &h, clock).await;
        }

        /// NAN-4566: the same guarantee when the fold provably spans several
        /// slices. At production's default 100 paced reads/s the 321-entry
        /// log needs >= 3.2 s, past one 2 s slice on any runner, so the first
        /// pass always stops `log_catching_up` before reaching control.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn reservation_never_authorizes_across_bounded_fold_slices() {
            let fx = fixture(420, 12);
            let (_ingestor, clock) = merged(&fx).await;
            let mut h = harness(&fx).await;
            h.pass = Arc::new(Arc::try_unwrap(h.pass).ok().unwrap().with_log_reads_per_second(DEFAULT_LOG_READS_PER_SECOND));
            assert!(live(&fx).await.head().unwrap().0 as u32 >= 2 * DEFAULT_LOG_READS_PER_SECOND, "the fold spans slices");
            h.plane.lock().unwrap().pending_log_reservation = true;
            let first = h.pass.run_pass_now(clock + 30 * 60_000).await.unwrap();
            assert_eq!(first.paused_reason.as_deref(), Some("log_catching_up"), "{first:?}");
            assert_eq!(h.plane.lock().unwrap().owner_calls, 0, "a partial view never reaches the owner");
            reservation_never_authorizes(&fx, &h, clock).await;
        }

        async fn reservation_never_authorizes(fx: &Fixture, h: &Harness, clock: i64) {
            h.plane.lock().unwrap().pending_log_reservation = true;
            let now = clock + 30 * 60_000;
            let report = pass_over_complete_view(fx, h, now).await;
            assert_eq!(report.paused_reason.as_deref(), Some("lake_part_index_incomplete"), "{report:?}");
            assert_eq!(report.deleted, 0);
            assert!(!h.plane.lock().unwrap().index_shas.is_empty());
            assert!(h.plane.lock().unwrap().attested.is_empty());
            assert_nothing_deleted(fx).await;
            // Explicit fixture reservation expiry; production expiry remains
            // control's effective completion deadline, never client inference.
            h.plane.lock().unwrap().pending_log_reservation = false;
            let resumed = h.pass.run_pass_now(now + 1).await.unwrap();
            assert!(resumed.deleted > 0, "{resumed:?}");
            assert_live_set_intact(fx).await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn stalled_index_backoffs_without_deleting_or_rescheduling() {
            let fx = fixture(420, 12);
            let (_ingestor, clock) = merged(&fx).await;
            let h = harness(&fx).await;
            h.plane.lock().unwrap().stall_index = true;
            let now = clock + 30 * 60_000;
            assert!(h.pass.schedule_pass(now).await.is_none());
            tokio::time::timeout(std::time::Duration::from_secs(20), h.pass.wait_idle()).await.unwrap();
            let owner_calls = h.plane.lock().unwrap().owner_calls;
            assert!(owner_calls <= 17, "one bounded sync, including gap recovery status reads");
            let report = h.pass.poll_report(now + 1).await.unwrap().unwrap();
            assert_eq!(report.paused_reason.as_deref(), Some("index_catch_up_no_progress"));
            assert!(report.backoff);
            assert_eq!(report.deleted, 0);
            // NAN-3495: during the pass back-off one index-only task keeps
            // publishing (index calls only: nothing is attested or deleted)...
            tokio::time::timeout(std::time::Duration::from_secs(20), h.pass.wait_idle()).await.unwrap();
            let index_only_calls = h.plane.lock().unwrap().owner_calls;
            assert!(index_only_calls > owner_calls, "index publication continues while the pass backs off");
            assert!(h.plane.lock().unwrap().attested.is_empty());
            // ...but the pass itself is not rescheduled, and the index-only
            // task keeps its own cadence (no second one a tick later).
            assert!(h.pass.schedule_pass(now + 2).await.is_none());
            assert!(h.pass.poll_report(now + 3).await.is_none());
            h.pass.wait_idle().await;
            assert_eq!(h.plane.lock().unwrap().owner_calls, index_only_calls);
            assert_nothing_deleted(&fx).await;
        }

        /// The cell's grant disabled (or never delivered, or no route): the
        /// gate never starts the pass, and no plane sees a call.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_closed_grant_or_missing_route_reaches_no_plane() {
            let fx = fixture(420, 12);
            let (mut ingestor, clock) = merged(&fx).await;
            let now = clock + 30 * 60_000;
            let h = harness(&fx).await;
            let gate = Arc::new(ExchangedGrantAuthority::new(TENANT, Some(h.pass.clone() as Arc<dyn SanctionedPartGc>)));
            ingestor.set_part_gc_authority(gate.clone());

            gate.update(Some(&grant(false)));
            ingestor.tick(now).await.unwrap();
            assert_eq!(blocked(&ingestor).0, "grant_disabled");

            // Enabled grant, but the latest exchange carried no route.
            gate.update(Some(&grant(true)));
            h.pass.update(None, Some(&grant(true)));
            ingestor.tick(now + 600_001).await.unwrap();
            assert_eq!(blocked(&ingestor).0, "sanctioned_path_unavailable");

            // A route with a disabled grant never runs a pass either.
            h.pass.update(Some(&access(1)), Some(&grant(false)));
            assert!(h.pass.run_pass_now(now).await.is_err(), "a pass needs an enabled grant");
            h.pass.wait_idle().await;

            let plane = h.plane.lock().unwrap();
            assert_eq!((plane.owner_calls, plane.worker_calls), (0, 0), "no plane was called");
            drop(plane);
            assert_nothing_deleted(&fx).await;
            assert_live_set_intact(&fx).await;
        }

        /// Control's own grant row is disabled (the cell's copy says enabled):
        /// the attestation refuses and the pass pauses with nothing deleted.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn control_refusing_the_grant_deletes_nothing() {
            let fx = fixture(420, 12);
            let (_ingestor, clock) = merged(&fx).await;
            let now = clock + 30 * 60_000;
            let h = harness(&fx).await;
            h.plane.lock().unwrap().control_grant_enabled = false;
            let report = pass_over_complete_view(&fx, &h, now).await;
            assert_eq!(report.paused_reason.as_deref(), Some("lake_part_grant_required"), "{report:?}");
            assert_eq!(report.deleted, 0);
            assert!(h.plane.lock().unwrap().retired.is_empty());
            assert_nothing_deleted(&fx).await;
        }

        /// A legal hold on a superseded part: that part is never deleted, and
        /// the pass stops at it.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_held_part_is_never_deleted() {
            let fx = fixture(420, 12);
            let (_ingestor, clock) = merged(&fx).await;
            let now = clock + 30 * 60_000;
            let (old, _young) = superseded(&fx, now, 3_600_000).await;
            let h = harness(&fx).await;
            // Hold every superseded part: none may go.
            h.plane.lock().unwrap().holds = old.iter().map(|p| p.part_id.to_string()).collect();
            let report = pass_over_complete_view(&fx, &h, now).await;
            assert_eq!(report.paused_reason.as_deref(), Some("lake_part_held"), "{report:?}");
            assert_eq!(report.deleted, 0);
            assert!(h.plane.lock().unwrap().retired.is_empty());
            assert_kept(&fx, &all_part_files(&old), "held part").await;
            assert_live_set_intact(&fx).await;
        }

        /// A failure at any hop (owner, control attest, control index, Worker
        /// capability / prepare / retire) deletes nothing.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_failure_in_any_hop_deletes_nothing() {
            let fx = fixture(420, 12);
            let (_ingestor, clock) = merged(&fx).await;
            let now = clock + 30 * 60_000;
            for hop in [
                Hop::Owner,
                Hop::ControlAttest,
                Hop::ControlIndex,
                Hop::WorkerCapabilities,
                Hop::WorkerPrepare,
                Hop::WorkerRetire,
            ] {
                let h = harness(&fx).await;
                h.plane.lock().unwrap().fail = Some(hop);
                let report = pass_over_complete_view(&fx, &h, now).await;
                assert_eq!(report.deleted, 0, "{hop:?}: {report:?}");
                assert!(report.paused_reason.is_some(), "{hop:?} must stop the pass: {report:?}");
                assert!(h.plane.lock().unwrap().retired.is_empty(), "{hop:?} deleted something");
                assert_nothing_deleted(&fx).await;
            }
            // A wrong owner bearer is a stop, never a per-key skip.
            let h = harness(&fx).await;
            let mut wrong = access_json(h.worker_port);
            wrong["owner_delete"]["token"] = json!("stolen");
            h.pass.update(Some(&LakePartGcAccess::parse(&wrong).unwrap()), Some(&grant(true)));
            let report = pass_over_complete_view(&fx, &h, now).await;
            assert_eq!(report.deleted, 0);
            assert!(report.paused_reason.as_deref().is_some_and(|r| r.contains("401")), "{report:?}");
            let owner_calls = h.plane.lock().unwrap().owner_calls;
            assert!(owner_calls <= 1, "a refused bearer stops the pass at once: {owner_calls} calls, {report:?}");
            assert_nothing_deleted(&fx).await;
            assert_live_set_intact(&fx).await;
        }
    }
}

/// NAN-2982: a bare keyword over the first real ingest-built part answered
/// 500 on the first lean tenant while `*` answered 200. The canary rows are
/// apache OCSF events: `raw_data`, no `message`.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256 and NANO_LAKE_COMPILER"]
async fn keyword_search_over_ingest_built_part_answers() {
    use nanosiem_lake_worker::executor::{ExecutorMode, NativeExecutor};
    use nanosiem_lake_worker::native::NativeChdb;
    use nanosiem_lake_worker::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
    use nanosiem_lake_worker::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
    use nanosiem_lake_worker::part_query::log_view::PartLogView;
    use nanosiem_lake_worker::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
    use std::collections::BTreeSet;
    use std::time::Duration;

    let fx = fixture(1, 1);
    let (source_key, _at) = &fx.objects[0];
    let event_time_s = chrono::Utc::now().timestamp() - 60;
    let events = (1..=5).map(|i| {
        let raw = format!("10.9.8.{i} - - [28/Sep/2026:17:00:00 +0000] \"GET /claude-canary-20260928T170713Z/{i} HTTP/1.1\" 200 512 \"-\" \"canary\"");
        json!({
            "activity_id": 3, "activity_name": "Get",
            "category_name": "Network Activity", "category_uid": 4,
            "class_name": "HTTP Activity", "class_uid": 4002,
            "http_request": {"http_method": "GET", "url": {"path": format!("/claude-canary-20260928T170713Z/{i}")}, "user_agent": "canary"},
            "http_response": {"code": 200, "length": 512, "status": "Success"},
            "metadata": {"log_name": "apache", "log_source": "apache_access",
                "product": {"name": "Apache HTTP Server", "vendor_name": "Apache Software Foundation"},
                "profiles": ["host"], "tenant_uid": TENANT, "uid": format!("canary-{i}"), "version": "1.9.0"},
            "raw_data": raw, "raw_data_size": raw.len(),
            "severity": "Informational", "severity_id": 1,
            "src_endpoint": {"ip": format!("10.9.8.{i}")},
            "status": "Success", "status_id": 1,
            "time": chrono::DateTime::from_timestamp(event_time_s - i, 0).unwrap().to_rfc3339(),
            "traffic": {"bytes_out": 512}, "type_uid": 400203
        })
    }).collect::<Vec<_>>();
    write_bronze(&fx.root.join("sources").join(source_key), &events);
    let key_file = fx.root.join("signing-key.hex");
    std::fs::write(&key_file, hex::encode(key().to_bytes())).unwrap();
    fx.spool.deliver(&notice(source_key, event_time_s)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_lake_part_ingest"))
        .args(["run", "--tenant-id", TENANT, "--signer-key-id", SIGNER_KEY_ID,
            "--signing-key-file", key_file.to_str().unwrap(),
            "--parts-dir", fx.root.join("parts").to_str().unwrap(),
            "--sources-dir", fx.root.join("sources").to_str().unwrap(),
            "--spool-dir", fx.root.join("spool").to_str().unwrap(),
            "--work-dir", fx.root.join("work").to_str().unwrap(),
            "--tick-ms", "100", "--flush-ms", "1000", "--exit-when-idle"])
        .output().unwrap();
    assert!(output.status.success(), "ingest exit: {}", String::from_utf8_lossy(&output.stderr));
    assert!(live(&fx).await.parts().next().is_some(), "no signed part: {}", String::from_utf8_lossy(&output.stderr));

    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(fx.root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted()).await.unwrap();
    let bucket = "nan2982-local-proof";
    let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: fx.root.join("query-cache"), max_bytes: 128 << 20,
        query_max_bytes: 128 << 20, fetch_concurrency: 2,
        fetch_deadline: Duration::from_secs(30),
    }, TENANT, bucket, &parts_key_prefix(TENANT).unwrap(),
    Arc::new(StoreObjectSource::local(bucket, store.clone(), fx.root.join("parts")))).unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted(), cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start_named_with_mode(runtime, 1, "nan2982-native", ExecutorMode::ReadOnly).unwrap();
    let engine = PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT.into(), bucket: bucket.into(),
        compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
        max_query_bytes: 128 << 20, max_memory_bytes: 1 << 30,
        max_execution_seconds: 30, threads: 1,
    }, store, view, fetcher, executor).unwrap();
    let request = |query: &str, table_view: bool| BroadNplRequest {
        request_id: uuid::Uuid::new_v4().to_string(), tenant_id: TENANT.into(),
        dataset: "logs".into(), query: query.into(),
        start: chrono::DateTime::from_timestamp(event_time_s - 7_200, 0).unwrap().to_rfc3339(),
        end: chrono::DateTime::from_timestamp(event_time_s + 60, 0).unwrap().to_rfc3339(),
        limit: 50, offset: 0, table_view, use_cache: false,
        cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
        clear_boundaries: BTreeMap::new(), watch_weights: Default::default(), minimum_clear_revision: None,
        deny_source_types: BTreeSet::new(),
    };
    for table_view in [true, false] {
        for (query, expected) in [("*", 5), ("claude", 5), ("canary", 5), ("absentword", 0), ("claude | stats count", 1)] {
            let result = engine.broad_npl(&request(query, table_view)).await
                .unwrap_or_else(|error| panic!("{query:?} table_view={table_view}: {} {error}", error.status()));
            assert_eq!(result["result"]["result_rows"], expected, "{query:?} table_view={table_view}: {result}");
            if !table_view && query == "claude" {
                // The typed default never leaks into event rows that lack the field.
                assert!(result["result"]["rows"][0].get("message").is_none(), "{result}");
            }
        }
    }
}

/// NAN-3077: evicted signed L0 inputs drain into M under the default config.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_background_minute_merge_drains_evicted_l0_without_pacing_stall() {
    let reindex = std::env::var("NANO_LAKE_REINDEX_OLD_HOURS").ok().as_deref() == Some("1");
    if reindex {
        nanosiem_lake_worker::parts::block_index::set_enabled(true);
        nanosiem_lake_worker::parts::token_counts::set_enabled(true);
    }
    let fx = fixture(12, 3);
    let mut cfg = config(&fx.root);
    cfg.background_merges = true;
    cfg.prevalence_enabled = false;
    cfg.merge_policy.day_merges = false;
    let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(fx.root.join("parts")).unwrap()));
    let owner: &'static LocalPartSigner = Box::leak(Box::new(signer()));
    let mut ingestor = open_with(&fx, cfg, DAY0_S * 1_000).await.unwrap();
    ingestor.set_background_store(store);
    ingestor.set_background_signer(owner);
    // Accumulate real signed L0s without running the maintenance phase.
    for (key, at) in &fx.objects {
        fx.spool.deliver(&notice(key, *at)).unwrap();
        ingestor.tick_ingest(*at * 1_000).await.unwrap();
        ingestor.flush_now(*at * 1_000).await.unwrap();
    }
    let before = live(&fx).await;
    assert_eq!(before.parts().filter(|p| p.level == Level::L0).count(), 12);
    if std::env::var("NANO_LAKE_UID_SIDECAR_WRITE").ok().as_deref() == Some("1") {
        for part in before.parts() {
            let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
            let bytes = store.get(&keys.provenance()).await.unwrap().unwrap();
            let signed = SignedProvenance::verify_bytes(&bytes, TENANT, &trusted()).unwrap();
            assert!(signed.record.files.data.iter().all(|data| data.uid_blooms.is_some()));
            if std::env::var_os("NANO_LAKE_ENTITY_SIDECAR_FIELDS").is_some() {
                assert!(signed.record.files.data.iter().all(|data| data.entity_blooms.is_some()));
            }
        }
    }
    // Force the production background fetch path, including every signed
    // sidecar. Per-object default sleeps formerly hold the only merge slot.
    for part in before.parts() {
        std::fs::remove_dir_all(fx.root.join("work/parts").join(part.part_id.as_str())).unwrap();
    }
    let clock = (fx.objects.last().unwrap().1 + 16 * 60) * 1_000;
    ingestor.tick(clock).await.unwrap();
    assert!(!ingestor.health().stalled, "ingest has no pending notices despite the L0 backlog");
    assert!(ingestor.health().oldest_unmerged_l0_age_ms > 15 * 60_000);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            ingestor.tick(clock).await.unwrap();
            if live(&fx).await.parts().all(|p| p.level == Level::Minute) { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("tiny L0 backlog did not complete its default Minute merge");
    assert_eq!(ingestor.health().oldest_unmerged_l0_age_ms, 0);
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
    if reindex {
        nanosiem_lake_worker::parts::block_index::set_enabled(false);
        nanosiem_lake_worker::parts::token_counts::set_enabled(false);
    }
}

/// a lean test tenant (2026-09-29): an hour seal is minutes of CPU. With
/// `background_merges` (the cell's mode) it runs as one background task the
/// tick polls and never awaits; later ticks commit it. Every notice is
/// still acked, rows stay exactly-once, and sealed hours end as one h part.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_merges_seal_hours_without_holding_the_tick() {
    let fx = fixture(420, 12);
    let mut cfg = config(&fx.root);
    cfg.merge_policy.day_merges = false;
    cfg.background_merges = true;
    let mut ingestor = open_with(&fx, cfg, DAY0_S * 1_000).await.unwrap();
    drive(&mut ingestor, &fx, &|k, at| {
        fx.spool.deliver(&notice(k, at)).unwrap();
    })
    .await
    .unwrap();
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "every notice acked");
    let mut clock = (DAY0_S + 4 * 3_600) * 1_000;
    let mut sealed = false;
    for _ in 0..2_000 {
        let started = std::time::Instant::now();
        ingestor.tick(clock).await.unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "a tick waited on a merge");
        clock += 1_000;
        if live(&fx).await.parts().all(|p| p.level == Level::Hour) {
            sealed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(sealed, "background merges sealed every hour");
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
}

/// a lean test tenant OOM loop (2026-09-29): after a restart mid catch-up, the first
/// tick saw zero lag (health not yet computed) and started an hour merge
/// beside the catch-up flushes; ingest[T] hit its 4.5 GiB cap, restarted,
/// and did it again. Lag now comes from this tick's pull: while the backlog
/// is older than the hour seal, no h merge runs (minute merges run inline).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_mid_catch_up_never_starts_an_hour_merge() {
    let fx = fixture(420, 12);
    let cfg = || {
        let mut cfg = config(&fx.root);
        cfg.merge_policy.day_merges = false;
        cfg.background_merges = true;
        cfg.max_objects_per_admission = 4;
        cfg
    };
    // First life: the first half is ingested live and committed as L0/M.
    let (first, rest) = fx.objects.split_at(fx.objects.len() / 2);
    {
        let mut ingestor = open_with(&fx, cfg(), DAY0_S * 1_000).await.unwrap();
        for (key, at) in first {
            fx.spool.deliver(&notice(key, *at)).unwrap();
            ingestor.tick(*at * 1_000).await.unwrap();
        }
        let end = first.last().unwrap().1 * 1_000 + 20_000;
        ingestor.tick(end).await.unwrap();
        ingestor.flush_now(end).await.unwrap();
    }
    // The rest arrives while ingest is down; it restarts 4 h later with
    // sealed, settled hours of L0/M parts and a backlog older than the seal.
    for (key, at) in rest {
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    let mut clock = (DAY0_S + 4 * 3_600) * 1_000;
    let mut ingestor = open_with(&fx, cfg(), clock).await.unwrap();
    let hour_parts = |set: &LiveSet| {
        set.parts().filter(|p| p.level == Level::Hour).map(|p| p.part_id.clone()).collect::<HashSet<_>>()
    };
    let before = hour_parts(&live(&fx).await);
    let mut caught_up = false;
    for _ in 0..3_000 {
        let backlog = !fx.spool.pending(1).await.unwrap().is_empty();
        ingestor.tick(clock).await.unwrap();
        clock += 1_000;
        // Give any background merge time to land, so one started during
        // the catch-up would be visible here.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        if backlog {
            assert_eq!(hour_parts(&live(&fx).await), before, "an hour merge ran during catch-up");
        } else {
            caught_up = true;
            if live(&fx).await.parts().all(|p| p.level == Level::Hour) {
                break;
            }
        }
    }
    assert!(caught_up, "the backlog drained");
    assert!(live(&fx).await.parts().all(|p| p.level == Level::Hour), "hours seal once caught up");
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
}

/// NAN-3056: the admission buffer is bounded by bytes, not only rows. With a
/// tiny budget every tick admits one object and flushes it; nothing is lost
/// or duplicated.
#[tokio::test(flavor = "current_thread")]
async fn byte_budget_bounds_admission_and_flushes() {
    let fx = fixture(60, 12);
    let mut cfg = config(&fx.root);
    cfg.buffer_budget_bytes = 1;
    let mut ingestor = open_with(&fx, cfg, DAY0_S * 1_000).await.unwrap();
    drive(&mut ingestor, &fx, &|k, at| {
        fx.spool.deliver(&notice(k, at)).unwrap();
    })
    .await
    .unwrap();
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "every notice acked");
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
    assert!(ingestor.health().parts_written_total >= 60, "one flush per object at a 1-byte budget");
}

/// A local prevalence state store whose writes, once `hang` is set, never
/// complete (the state store stopped flushing).
#[derive(Debug)]
struct HangingStore {
    inner: slatedb::object_store::memory::InMemory,
    hang: Arc<std::sync::atomic::AtomicBool>,
    writes: Arc<AtomicUsize>,
}

impl std::fmt::Display for HangingStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HangingStore")
    }
}

#[async_trait]
impl slatedb::object_store::ObjectStore for HangingStore {
    async fn put_opts(&self, path: &slatedb::object_store::path::Path, payload: slatedb::object_store::PutPayload,
        opts: slatedb::object_store::PutOptions) -> slatedb::object_store::Result<slatedb::object_store::PutResult> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.hang.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        self.inner.put_opts(path, payload, opts).await
    }
    async fn put_multipart_opts(&self, path: &slatedb::object_store::path::Path, opts: slatedb::object_store::PutMultipartOptions)
        -> slatedb::object_store::Result<Box<dyn slatedb::object_store::MultipartUpload>> {
        if self.hang.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        self.inner.put_multipart_opts(path, opts).await
    }
    async fn get_opts(&self, path: &slatedb::object_store::path::Path, options: slatedb::object_store::GetOptions)
        -> slatedb::object_store::Result<slatedb::object_store::GetResult> {
        self.inner.get_opts(path, options).await
    }
    fn delete_stream(&self, locations: futures::stream::BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::path::Path>>)
        -> futures::stream::BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::path::Path>> {
        self.inner.delete_stream(locations)
    }
    fn list(&self, prefix: Option<&slatedb::object_store::path::Path>)
        -> futures::stream::BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::ObjectMeta>> {
        self.inner.list(prefix)
    }
    async fn list_with_delimiter(&self, prefix: Option<&slatedb::object_store::path::Path>)
        -> slatedb::object_store::Result<slatedb::object_store::ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }
    async fn copy_opts(&self, from: &slatedb::object_store::path::Path, to: &slatedb::object_store::path::Path,
        options: slatedb::object_store::CopyOptions) -> slatedb::object_store::Result<()> {
        self.inner.copy_opts(from, to, options).await
    }
}

/// a lean test tenant (2026-09-30): the prevalence state store stopped flushing
/// (SlateDB backpressure never released) and the ingest loop blocked on it
/// forever: no commits, detect appends refused. Now every prevalence
/// operation is bounded: past `prevalence_op_timeout` the state is dropped
/// as stalled, rows are committed unstamped, and health reports it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_prevalence_store_that_never_flushes_never_stops_ingest() {
    let fx = fixture(6, 1);
    write_stamp_sources(&fx);
    let store = Arc::new(HangingStore {
        inner: slatedb::object_store::memory::InMemory::new(),
        hang: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        writes: Arc::new(AtomicUsize::new(0)),
    });
    let mut cfg = config(&fx.root);
    cfg.prevalence_op_timeout = std::time::Duration::from_secs(2);
    cfg.prevalence_read_store = Some(store.clone());
    let mut ingestor = open_with(&fx, cfg, DAY0_S * 1_000).await.unwrap();
    assert_eq!(ingestor.prevalence_status(), "stamping");
    let (key, at) = &fx.objects[0];
    fx.spool.deliver(&notice(key, *at)).unwrap();
    ingestor.tick(at * 1_000).await.unwrap();
    ingestor.flush_now(at * 1_000).await.unwrap();
    assert!(store.writes.load(Ordering::SeqCst) > 0, "stamping state writes reached the store");

    // From here every state write hangs forever.
    store.hang.store(true, Ordering::SeqCst);
    for (key, at) in fx.objects.iter().skip(1) {
        fx.spool.deliver(&notice(key, *at)).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(30), ingestor.tick(at * 1_000)).await
            .expect("a stalled prevalence store must not block the tick").unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(30), ingestor.flush_now(at * 1_000)).await
            .expect("a stalled prevalence store must not block the flush").unwrap();
    }
    // Every object was committed (merges may have combined parts).
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "every notice acked");
    // One stamp source row per object (write_stamp_sources).
    assert_exactly_once(&live_rows(&fx).await, fx.objects.len());
    let health = ingestor.health();
    assert!(health.prevalence_stalls_total >= 1, "the stall is reported");
    assert!(health.prevalence_degraded, "prevalence is marked degraded");
    assert!(ingestor.prevalence_status().starts_with("unstamped"), "{}", ingestor.prevalence_status());
}

/// Counts every part fetch (object GET) the ingestor makes.
struct CountingParts<'a> {
    parts: &'a LocalObjectStore,
    gets: AtomicUsize,
    /// GETs of part files (provenance, data, sidecars), not log objects.
    part_gets: AtomicUsize,
}

impl<'a> CountingParts<'a> {
    fn new(parts: &'a LocalObjectStore) -> Self {
        Self { parts, gets: AtomicUsize::new(0), part_gets: AtomicUsize::new(0) }
    }
}

#[async_trait]
impl ObjectStore for CountingParts<'_> {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        if key.contains("/parts/") {
            self.part_gets.fetch_add(1, Ordering::SeqCst);
        }
        self.parts.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        self.parts.put_if_absent(key, bytes).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.parts.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.parts.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.parts.list(prefix).await
    }
}

/// A backfill interleaving `hours` event hours (round-robin, `rounds`
/// objects of `rows` per hour), every 7th object replayed later as a new
/// object, all arriving within minutes (every hour stays in the 6 h exact
/// dedup window). Returns (fixture, unique uids).
fn interleaved_backfill(hours: i64, rounds: usize, rows: usize) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let mut list = Vec::new();
    let mut uids = HashSet::new();
    let mut replays = Vec::new();
    let mut n = 0;
    let arrival0 = DAY0_S + hours * 3_600 + 3_600;
    for round in 0..rounds {
        for hour in 0..hours {
            let o = list.len();
            let events = (0..rows)
                .map(|r| {
                    n += 1;
                    let uid = format!("uid-{hour:03}-{round:02}-{r:04}");
                    uids.insert(uid.clone());
                    event(&uid, DAY0_S + hour * 3_600 + round as i64 * 60 + r as i64 % 60, n)
                })
                .collect::<Vec<_>>();
            let at = arrival0 + o as i64 * 5;
            let key = format!("bronze/{at}-{o:05}.parquet");
            write_bronze(&sources_dir.join(&key), &events);
            list.push((key, at));
            if o % 7 == 3 {
                replays.push(events);
            }
        }
    }
    for events in replays {
        let o = list.len();
        let at = arrival0 + o as i64 * 5;
        let key = format!("bronze/{at}-{o:05}-replay.parquet");
        write_bronze(&sources_dir.join(&key), &events);
        list.push((key, at));
    }
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    Fixture { _dir: dir, signer: signer(), root, parts, sources, spool, objects: list, unique_uids: uids.len(), tenant: TENANT.into() }
}

struct BackfillRun {
    fetches: usize,
    slowest_tick_ms: u128,
    duplicates: u64,
    live: usize,
}

async fn bounded_tick(ingestor: &mut Ingestor<'_>, now_ms: i64) -> (nanosiem_lake_worker::part_ingest::ingest::TickReport, u128) {
    let began = Instant::now();
    let report = tokio::time::timeout(std::time::Duration::from_secs(60), ingestor.tick(now_ms))
        .await
        .unwrap_or_else(|_| panic!("ingest tick at {now_ms} stalled for 60 s"))
        .unwrap();
    (report, began.elapsed().as_millis())
}

/// Drive `fx` through an ingestor configured by `configure`, each tick
/// bounded by 60 s of wall time (a stalled tick fails the test).
async fn run_backfill(fx: &Fixture, configure: impl Fn(&mut IngestConfig)) -> BackfillRun {
    let counting = CountingParts::new(&fx.parts);
    let mut cfg = config(&fx.root);
    cfg.flush_interval_override_ms = Some(5_000);
    cfg.max_objects_per_admission = 4;
    configure(&mut cfg);
    let start = fx.objects[0].1 * 1_000 - 1_000;
    let mut ingestor = Ingestor::open(cfg, &counting, &fx.sources, &fx.spool, &fx.signer, trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), start).await.unwrap();
    let mut slowest = 0;
    let mut duplicates = 0;
    for (key, at) in &fx.objects {
        fx.spool.deliver(&notice(key, *at)).unwrap();
        let (report, ms) = bounded_tick(&mut ingestor, *at * 1_000).await;
        duplicates += report.duplicates;
        slowest = slowest.max(ms);
    }
    let mut clock = fx.objects.last().unwrap().1 * 1_000 + 10_000;
    for _ in 0..40 {
        let (report, ms) = bounded_tick(&mut ingestor, clock).await;
        duplicates += report.duplicates;
        slowest = slowest.max(ms);
        clock += 60_000;
    }
    ingestor.flush_now(clock).await.unwrap();
    assert_eq!(ingestor.health().pending_notices, 0, "every notice is consumed");
    let rows = live_rows(fx).await;
    assert_exactly_once(&rows, fx.unique_uids);
    BackfillRun { fetches: counting.gets.load(Ordering::SeqCst), slowest_tick_ms: slowest, duplicates, live: rows.len() }
}

/// NAN-3061: an interleaved backfill over more event hours than the part
/// cache holds neither stalls ingest nor makes dedup depend on a part
/// being cache-resident.
///
/// Every hour stays in the 6 h exact window (arrival is compressed into
/// minutes) while the cache is forced to evict every part on every sweep.
/// The window holds each hour's uid hashes in memory, so an evicted part is
/// never needed to dedup a row of a held hour; parts come back only for
/// merges. When the window's own cap evicts an hour, its next row re-fetches
/// that hour's parts from the store (never from the cache alone) and the
/// hour is re-hydrated. Measured on this fixture (90 objects, 30 hours, 15
/// replays): unbounded cache 3 part GETs; starved cache 735 (merge inputs);
/// starved cache + window cap 1,077 (re-hydration). Every run commits each
/// event exactly once, drops every replayed row as a duplicate, and no tick
/// takes more than about a second.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interleaved_backfill_past_the_part_cache_never_stalls_and_dedups_exactly() {
    let replays_of = |fx: &Fixture| fx.objects.iter().filter(|(key, _)| key.ends_with("-replay.parquet")).count() as u64 * 40;
    let roomy = interleaved_backfill(30, 3, 40);
    let roomy_run = run_backfill(&roomy, |_| {}).await;
    let starved = interleaved_backfill(30, 3, 40);
    let starved_run = run_backfill(&starved, |cfg| cfg.cache_max_bytes = 1).await;
    // The window's own cap below the backfill's uids: hours leave the
    // window while their rows still arrive, and are re-hydrated from parts
    // the cache no longer holds.
    let capped = interleaved_backfill(30, 3, 40);
    // The hours arrive 31 h after their events, past the NAN-3387 remote
    // dedup horizon; this case pins the exact re-hydration path that the
    // horizon bypasses, so it turns the horizon off.
    let capped_run = run_backfill(&capped, |cfg| {
        cfg.cache_max_bytes = 1;
        cfg.max_window_uids = 500;
        cfg.late_hour_remote_dedup_ms = None;
    }).await;
    eprintln!("starved cache + window cap 500: fetches={} slowest_tick_ms={} dups={} live={}",
        capped_run.fetches, capped_run.slowest_tick_ms, capped_run.duplicates, capped_run.live);
    assert_eq!(capped_run.duplicates, replays_of(&capped));
    eprintln!(
        "roomy cache: fetches={} slowest_tick_ms={} dups={} live={}; starved cache: fetches={} slowest_tick_ms={} dups={} live={}",
        roomy_run.fetches, roomy_run.slowest_tick_ms, roomy_run.duplicates, roomy_run.live,
        starved_run.fetches, starved_run.slowest_tick_ms, starved_run.duplicates, starved_run.live,
    );
    assert_eq!(roomy_run.duplicates, replays_of(&roomy));
    assert_eq!(starved_run.duplicates, replays_of(&starved));
    assert_eq!(starved_run.live, roomy_run.live);
}

/// NAN-3387 (the load-test tenant, 2026-10-08): an audit backfill spanning ~100 old
/// event hours arrived after a respawn had swept the part cache. Admission
/// prepared the uid window for every hour by downloading every live part of
/// it from R2 before buffering anything, which took longer than the 900 s
/// edge stall watchdog. The watchdog restarted ingest, and the respawn
/// re-admitted the same backfill, so ingest for every source stayed
/// blocked.
///
/// Event hours past the dedup horizon must admit without fetching any part,
/// and a live-hour object in the same pull must commit in that same tick.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_hour_backfill_admits_without_fetching_parts_and_never_holds_the_live_hour() {
    const HOURS: i64 = 30;
    let fx = interleaved_backfill(HOURS, 1, 20);
    // 1. Commit 30 hours of history.
    let mut clock = fx.objects[0].1 * 1_000;
    let mut ingestor = open(&fx, &fx.spool, &fx.parts, clock).await.unwrap();
    for (key, at) in &fx.objects {
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    for _ in 0..20 {
        clock += 11_000;
        ingestor.tick(clock).await.unwrap();
    }
    ingestor.flush_now(clock).await.unwrap();
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "history committed");
    drop(ingestor);

    // 2. Respawn 7 h later (every history hour now past the 6 h horizon)
    //    with the part cache swept. One backfill object touches every
    //    history hour, and a live object of the current hour arrives with it.
    std::fs::remove_dir_all(fx.root.join("work/parts")).unwrap();
    let now_s = clock / 1_000 + 7 * 3_600;
    let backfill = (0..HOURS)
        .map(|hour| event(&format!("late-{hour:03}"), DAY0_S + hour * 3_600 + 1_800, 50_000 + hour as usize))
        .collect::<Vec<_>>();
    write_bronze(&fx.root.join("sources/bronze/late-backfill.parquet"), &backfill);
    let live_events = (0..5).map(|i| event(&format!("live-{i}"), now_s - 5 + i, 60_000 + i as usize)).collect::<Vec<_>>();
    write_bronze(&fx.root.join("sources/bronze/live-now.parquet"), &live_events);
    fx.spool.deliver(&notice("bronze/late-backfill.parquet", now_s)).unwrap();
    fx.spool.deliver(&notice("bronze/live-now.parquet", now_s)).unwrap();

    let counting = CountingParts::new(&fx.parts);
    let mut ingestor = Ingestor::open(config(&fx.root), &counting, &fx.sources, &fx.spool, &fx.signer, trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), now_s * 1_000).await.unwrap();
    let before = counting.part_gets.load(Ordering::SeqCst);
    let (report, _) = ingestor.tick_ingest(now_s * 1_000).await.unwrap();
    let admission_part_gets = counting.part_gets.load(Ordering::SeqCst) - before;
    assert_eq!(report.admitted_rows, HOURS as u64 + 5, "backfill and live rows admitted in one tick");
    assert_eq!(admission_part_gets, 0, "admitting {HOURS} old hours fetched {admission_part_gets} part files from the store");

    ingestor.flush_now(now_s * 1_000 + 11_000).await.unwrap();
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "backfill and live objects acked");
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids + HOURS as usize + 5);
}

/// A bare fixture: no prepared objects.
fn empty_fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    Fixture { _dir: dir, signer: signer(), root, parts, sources, spool, objects: Vec::new(), unique_uids: 0, tenant: TENANT.into() }
}

/// NAN-3703 history: event A in hour 0 and event B in hour 63, each
/// arriving two minutes after its event and committed, then the clock run
/// on in 10-minute ticks (merges and window eviction included) to 71 h
/// past DAY0, when hour 0 ended 70 h ago and hour 63 ended 7 h ago. Returns
/// the clock (ms) and the redelivered events.
async fn late_dedup_history(fx: &Fixture) -> (i64, Vec<Value>) {
    let a = event("late-a", DAY0_S + 1_800, 1);
    let b = event("late-b", DAY0_S + 63 * 3_600 + 1_800, 2);
    write_bronze(&fx.root.join("sources/bronze/a.parquet"), std::slice::from_ref(&a));
    write_bronze(&fx.root.join("sources/bronze/b.parquet"), std::slice::from_ref(&b));
    let mut clock = (DAY0_S + 1_920) * 1_000;
    let mut ingestor = open(fx, &fx.spool, &fx.parts, clock).await.unwrap();
    fx.spool.deliver(&notice("bronze/a.parquet", clock / 1_000)).unwrap();
    let b_at = (DAY0_S + 63 * 3_600 + 1_920) * 1_000;
    let end = (DAY0_S + 71 * 3_600 + 60) * 1_000;
    let mut b_sent = false;
    while clock < end {
        if !b_sent && clock >= b_at {
            fx.spool.deliver(&notice("bronze/b.parquet", clock / 1_000)).unwrap();
            b_sent = true;
        }
        bounded_tick(&mut ingestor, clock).await;
        clock += 600_000;
    }
    ingestor.flush_now(clock).await.unwrap();
    // Window eviction spilled both hours; their runs land in the background.
    for _ in 0..500 {
        if ingestor.health().late_dedup_tier_hours >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        bounded_tick(&mut ingestor, clock).await;
    }
    assert_eq!(ingestor.health().late_dedup_tier_hours, 2, "hours 0 and 63 are in the late tier");
    let levels = live(fx).await.parts().map(|part| part.level.code().to_string()).collect::<Vec<_>>();
    // Hour 0 was merged into a day part after the window spilled it: the
    // tier covers that output by inheritance, without reading it.
    assert!(levels.iter().any(|level| level == "d"), "hour 0 reached a day part: {levels:?}");
    assert_eq!(ingestor.health().late_dedup_tier_uids, 2);
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "history committed");
    assert_exactly_once(&live_rows(fx).await, 2);
    (clock, vec![a, b])
}

/// NAN-3703 acceptance: a redelivery of an event whose hour ended 7 h ago
/// and of one whose hour ended 70 h ago, each sent twice 60 s apart after a
/// respawn with the part cache swept, is deduped before it is written: the
/// live set keeps one row per uid, the redeliveries are counted as
/// duplicates, and admission fetches no part from the store.
///
/// Before NAN-3703 both hours were past the NAN-3387 remote-dedup horizon
/// and not cached, so each redelivery's first copy was admitted (2 rows per
/// uid until the hour's next merge).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_redelivery_of_7h_and_70h_old_hours_is_deduped_before_it_is_written() {
    let fx = empty_fixture();
    let (clock, events) = late_dedup_history(&fx).await;
    // Respawn with the part cache swept: only the late tier (persisted under
    // the work dir) can know these uids.
    std::fs::remove_dir_all(fx.root.join("work/parts")).unwrap();
    let counting = CountingParts::new(&fx.parts);
    let mut ingestor = open(&fx, &fx.spool, &counting, clock).await.unwrap();
    let mut now = clock;
    for _ in 0..500 {
        bounded_tick(&mut ingestor, now).await;
        if ingestor.health().late_dedup_tier_ready {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(ingestor.health().late_dedup_tier_ready, "the tier reloads its runs");
    write_bronze(&fx.root.join("sources/bronze/redelivery-1.parquet"), &events);
    write_bronze(&fx.root.join("sources/bronze/redelivery-2.parquet"), &events);
    let before = counting.part_gets.load(Ordering::SeqCst);
    for (copy, key) in ["bronze/redelivery-1.parquet", "bronze/redelivery-2.parquet"].iter().enumerate() {
        now += 60_000 * copy as i64;
        fx.spool.deliver(&notice(key, now / 1_000)).unwrap();
        let (report, _) = ingestor.tick_ingest(now).await.unwrap();
        assert_eq!(report.duplicates, 2, "copy {copy}: both rows are duplicates");
        ingestor.flush_now(now + 11_000).await.unwrap();
    }
    assert_eq!(counting.part_gets.load(Ordering::SeqCst) - before, 0, "admission fetched no part");
    let health = ingestor.health();
    assert_eq!(health.late_dedup_tier_duplicates_total, 4);
    assert_eq!(health.late_dedup_unverified_rows_total, 0);
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "redeliveries acked");
    let rows = live_rows(&fx).await;
    assert_exactly_once(&rows, 2);
}

/// Every part GET under the store parks forever (a stalled R2).
struct HangingParts {
    parts: LocalObjectStore,
    hung: AtomicUsize,
}

#[async_trait]
impl ObjectStore for HangingParts {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if key.contains("/parts/") {
            self.hung.fetch_add(1, Ordering::SeqCst);
            futures::future::pending::<()>().await;
        }
        self.parts.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        self.parts.put_if_absent(key, bytes).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.parts.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.parts.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.parts.list(prefix).await
    }
}

/// NAN-3703: with the late tier lost (work dir swept) and the store
/// hanging, a late redelivery never blocks the live path. The live-hour
/// object of the same pull commits in the same tick, admission fetches no
/// part, the late row is admitted and counted as unverified, and the
/// background fold that would rebuild the tier hangs without slowing later
/// ticks. Merge stays the backstop for that copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_or_stalled_late_tier_never_blocks_live_ingest() {
    let fx = empty_fixture();
    let (clock, events) = late_dedup_history(&fx).await;
    std::fs::remove_dir_all(fx.root.join("work/parts")).unwrap();
    std::fs::remove_dir_all(fx.root.join("work/late-uids")).unwrap();
    let hanging: &'static HangingParts = Box::leak(Box::new(HangingParts {
        parts: LocalObjectStore::new(fx.root.join("parts")).unwrap(),
        hung: AtomicUsize::new(0),
    }));
    let counting = CountingParts::new(&fx.parts);
    let mut ingestor = open(&fx, &fx.spool, &counting, clock).await.unwrap();
    ingestor.set_background_store(hanging);
    let now = clock + 60_000;
    write_bronze(&fx.root.join("sources/bronze/redelivery.parquet"), &events);
    let live_events = (0..3).map(|i| event(&format!("live-{i}"), now / 1_000 - 5 + i, 100 + i as usize)).collect::<Vec<_>>();
    write_bronze(&fx.root.join("sources/bronze/live.parquet"), &live_events);
    fx.spool.deliver(&notice("bronze/redelivery.parquet", now / 1_000)).unwrap();
    fx.spool.deliver(&notice("bronze/live.parquet", now / 1_000)).unwrap();
    let before = counting.part_gets.load(Ordering::SeqCst);
    let began = Instant::now();
    let (report, _) = tokio::time::timeout(std::time::Duration::from_secs(10), ingestor.tick_ingest(now)).await
        .expect("a missing late tier must not block admission").unwrap();
    assert_eq!(report.admitted_rows, 5, "late and live rows admitted in one tick");
    assert_eq!(counting.part_gets.load(Ordering::SeqCst) - before, 0, "admission fetched no part");
    assert_eq!(ingestor.health().late_dedup_unverified_rows_total, 2, "both late rows counted as unverified");
    // Later ticks start the fold, which hangs on the store; none of them waits.
    let mut slowest = 0;
    for step in 1..=5 {
        let (_, ms) = bounded_tick(&mut ingestor, now + step * 11_000).await;
        slowest = slowest.max(ms);
    }
    let elapsed = began.elapsed();
    assert!(hanging.hung.load(Ordering::SeqCst) > 0, "a background fold is parked on the stalled store");
    assert_eq!(ingestor.health().late_dedup_tier_folds_total, 0);
    assert!(slowest < 5_000 && elapsed.as_secs() < 30, "ticks stayed fast: slowest {slowest} ms, total {elapsed:?}");
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "late and live objects acked");
    let rows = live_rows(&fx).await;
    for i in 0..3 {
        assert!(rows.iter().any(|(_, uid)| uid == &format!("live-{i}")), "live row {i} committed");
    }
}

/// The edge contract's ordering, checked at every queue call (NAN-3183):
/// a flush's range is issued only once the previous flush is acked, and an
/// ack names only objects whose `add` is already in the log.
struct OrderingQueue<'a> {
    spool: &'a SpoolQueue,
    parts: &'a LocalObjectStore,
    sources: &'a LocalObjectStore,
    issued: std::sync::atomic::AtomicBool,
    keys: std::sync::Mutex<BTreeMap<String, String>>,
    ranges: AtomicUsize,
    acked: AtomicUsize,
}

#[async_trait]
impl NoticeQueue for OrderingQueue<'_> {
    async fn pending(&self, max: usize) -> Result<Vec<(NoticeHandle, SourceNotice)>> {
        let pending = self.spool.pending(max).await?;
        let mut keys = self.keys.lock().unwrap();
        for (handle, notice) in &pending {
            keys.insert(handle.0.clone(), notice.key.clone());
        }
        Ok(pending)
    }
    async fn ack(&self, handles: &[NoticeHandle]) -> Result<()> {
        anyhow::ensure!(self.issued.swap(false, Ordering::SeqCst), "an ack without an issued range");
        let live = load_log(self.parts, TENANT).await?;
        for handle in handles {
            let key = self.keys.lock().unwrap().remove(&handle.0).expect("each handle is acknowledged only once");
            let bytes = self.sources.get(&key).await?.expect("source object");
            let source = nanosiem_lake_worker::parts::part_log::SourceRef { key, version: "1".into(), sha256: sha256_hex(&bytes) };
            anyhow::ensure!(live.consumed(&source), "an ack before its add committed: {}", source.key);
        }
        self.acked.fetch_add(handles.len(), Ordering::SeqCst);
        self.spool.ack(handles).await
    }
    async fn ack_skipped(&self, acks: &[(NoticeHandle, nanosiem_lake_worker::part_ingest::discovery::AckCounts)]) -> Result<()> {
        anyhow::ensure!(!self.issued.load(Ordering::SeqCst), "skips acked while a range is outstanding");
        let handles = acks.iter().map(|(h, _)| h.clone()).collect::<Vec<_>>();
        self.spool.ack(&handles).await
    }
    async fn range_for_flush(&self, _sources: &[nanosiem_lake_worker::parts::provenance::SourceObject], _rejected: u64, _duplicate: u64)
        -> Result<Option<nanosiem_lake_worker::parts::EdgeLogRange>> {
        anyhow::ensure!(!self.issued.swap(true, Ordering::SeqCst), "a range issued before the previous flush was acked");
        self.ranges.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
}

async fn pipelined_ticks(ingestor: &mut Ingestor<'_>, clock: &mut i64, ticks: usize, spool: &SpoolQueue) -> Result<()> {
    for _ in 0..ticks {
        *clock += 11_000;
        ingestor.tick(*clock).await?;
        if spool.pending(1).await?.is_empty() && ingestor.health().buffered_rows == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    Ok(())
}

/// NAN-3183: while catching up, a flush builds and uploads its parts in the
/// background as the next buffer admits. Flushes still commit in order (a
/// range waits for the previous ack, an ack waits for its add), and every
/// row lands exactly once, including across a crash with a flush in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipelined_catch_up_flushes_commit_in_order_exactly_once() {
    pipelined_catch_up_case(true).await;
}

/// NAN-4573: the same with commits on the tick (the pre-#7830 default). Its
/// slower catch-up let the restarted clock trail the fixture's event times
/// by more than 5 min, so an object was clamped into the hour before its
/// events while its replay (admitted later) was not: the two copies landed
/// in different hours and both stayed live (1210 rows for 1200 uids).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipelined_catch_up_committing_on_the_tick_is_exactly_once() {
    pipelined_catch_up_case(false).await;
}

async fn pipelined_catch_up_case(commit_when_ready: bool) {
    let fx = fixture(120, 10);
    for (key, at) in &fx.objects {
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    let queue = OrderingQueue {
        spool: &fx.spool, parts: &fx.parts, sources: &fx.sources,
        issued: Default::default(), keys: Default::default(), ranges: AtomicUsize::new(0), acked: AtomicUsize::new(0),
    };
    // The cell hands ingest 'static handles for background work.
    let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(fx.root.join("parts")).unwrap()));
    let background_signer: &'static LocalPartSigner = Box::leak(Box::new(signer()));
    let reopen = |clock: i64| {
        let queue = &queue;
        let fx = &fx;
        async move {
            let mut cfg = config(&fx.root);
            cfg.commit_when_ready = commit_when_ready;
            let mut ingestor = Ingestor::open(cfg, &fx.parts, &fx.sources, queue, &fx.signer, trusted(),
                BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.unwrap();
            ingestor.set_background_store(store);
            ingestor.set_background_signer(background_signer);
            ingestor
        }
    };
    let mut clock = (DAY0_S + 2_400) * 1_000;
    let mut ingestor = reopen(clock).await;
    // Crash with a flush in flight (sealed and range issued, not committed).
    let mut crashed = false;
    for _ in 0..40 {
        clock += 11_000;
        ingestor.tick(clock).await.unwrap();
        if ingestor.health().flushes_pipelined_total >= 3 && queue.issued.load(Ordering::SeqCst) {
            crashed = true;
            break;
        }
    }
    assert!(crashed, "a pipelined flush was in flight");
    let before = ingestor.health().flushes_pipelined_total;
    drop(ingestor);
    // The process died between the range and the ack: the edge source
    // (here, its stand-in) forgets the issued range with the process.
    queue.issued.store(false, Ordering::SeqCst);
    let mut ingestor = reopen(clock).await;
    pipelined_ticks(&mut ingestor, &mut clock, 400, &fx.spool).await.unwrap();
    ingestor.flush_now(clock + 11_000).await.unwrap();
    // Measured: 3 pipelined before the crash, 1 after, 7 ranges in all.
    assert!(ingestor.health().flushes_pipelined_total >= 1, "catch-up pipelines again after the restart");
    assert!(before + ingestor.health().flushes_pipelined_total >= 4, "catch-up flushes pipelined");
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "every notice acked");
    assert!(queue.ranges.load(Ordering::SeqCst) >= 6);
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
}

/// NAN-3619: the edge contract with two ranges allowed outstanding. Ranges
/// are acknowledged strictly in issue order (an ack must name exactly the
/// oldest outstanding flush's objects), only after their `add` committed,
/// and no skip is acked while a range is outstanding.
struct DepthTwoQueue<'a> {
    spool: &'a SpoolQueue,
    parts: &'a LocalObjectStore,
    sources: &'a LocalObjectStore,
    /// Keys of each issued, unacknowledged range, oldest first.
    issued: std::sync::Mutex<std::collections::VecDeque<std::collections::BTreeSet<String>>>,
    keys: std::sync::Mutex<BTreeMap<String, String>>,
    ranges: AtomicUsize,
    acked: AtomicUsize,
    peak_outstanding: AtomicUsize,
    /// Largest `pending(max)` asked for, and empty `ack_skipped` calls.
    max_pending_window: AtomicUsize,
    empty_skip_acks: AtomicUsize,
    /// NAN-4539: while set, an `ack` waits (before any check) so a test can
    /// drop the commit mid-ack; `ack_entered` is signaled as one starts.
    stall_ack: std::sync::atomic::AtomicBool,
    ack_entered: tokio::sync::Notify,
}

impl<'a> DepthTwoQueue<'a> {
    fn new(fx: &'a Fixture) -> Self {
        Self {
            spool: &fx.spool, parts: &fx.parts, sources: &fx.sources,
            issued: Default::default(), keys: Default::default(),
            ranges: AtomicUsize::new(0), acked: AtomicUsize::new(0), peak_outstanding: AtomicUsize::new(0),
            max_pending_window: AtomicUsize::new(0), empty_skip_acks: AtomicUsize::new(0),
            stall_ack: Default::default(), ack_entered: tokio::sync::Notify::new(),
        }
    }
}

#[async_trait]
impl NoticeQueue for DepthTwoQueue<'_> {
    async fn pending(&self, max: usize) -> Result<Vec<(NoticeHandle, SourceNotice)>> {
        self.max_pending_window.fetch_max(max, Ordering::SeqCst);
        let pending = self.spool.pending(max).await?;
        let mut keys = self.keys.lock().unwrap();
        for (handle, notice) in &pending {
            keys.insert(handle.0.clone(), notice.key.clone());
        }
        Ok(pending)
    }
    async fn ack(&self, handles: &[NoticeHandle]) -> Result<()> {
        if self.stall_ack.load(Ordering::SeqCst) {
            self.ack_entered.notify_one();
            while self.stall_ack.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
        let acked = handles.iter()
            .map(|h| self.keys.lock().unwrap().get(&h.0).cloned().expect("acked handle was pending"))
            .collect::<std::collections::BTreeSet<_>>();
        {
            let issued = self.issued.lock().unwrap();
            let oldest = issued.front().ok_or_else(|| anyhow::anyhow!("an ack without an issued range"))?;
            anyhow::ensure!(*oldest == acked, "an ack out of issue order: {acked:?} while {oldest:?} is the oldest range");
        }
        let live = load_log(self.parts, TENANT).await?;
        for key in &acked {
            let bytes = self.sources.get(key).await?.expect("source object");
            let source = nanosiem_lake_worker::parts::part_log::SourceRef { key: key.clone(), version: "1".into(), sha256: sha256_hex(&bytes) };
            anyhow::ensure!(live.consumed(&source), "an ack before its add committed: {key}");
        }
        self.issued.lock().unwrap().pop_front();
        self.acked.fetch_add(handles.len(), Ordering::SeqCst);
        self.spool.ack(handles).await
    }
    async fn ack_skipped(&self, acks: &[(NoticeHandle, nanosiem_lake_worker::part_ingest::discovery::AckCounts)]) -> Result<()> {
        if acks.is_empty() {
            self.empty_skip_acks.fetch_add(1, Ordering::SeqCst);
        }
        anyhow::ensure!(self.issued.lock().unwrap().is_empty(), "skips acked while a range is outstanding");
        let handles = acks.iter().map(|(h, _)| h.clone()).collect::<Vec<_>>();
        self.spool.ack(&handles).await
    }
    async fn range_for_flush(&self, sources: &[nanosiem_lake_worker::parts::provenance::SourceObject], _rejected: u64, _duplicate: u64)
        -> Result<Option<nanosiem_lake_worker::parts::EdgeLogRange>> {
        let mut issued = self.issued.lock().unwrap();
        anyhow::ensure!(issued.len() < 2, "a third range issued while two are outstanding");
        issued.push_back(sources.iter().map(|s| s.key.clone()).collect());
        self.peak_outstanding.fetch_max(issued.len(), Ordering::SeqCst);
        self.ranges.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
    fn max_outstanding_ranges(&self) -> usize {
        2
    }
}

/// The background part store with a brake: while `capture` is on, every
/// part that starts uploading is marked slow, and every upload of a slow
/// part sleeps. Lets a test make the older flight finish after the younger.
struct BrakedParts {
    inner: LocalObjectStore,
    capture: std::sync::atomic::AtomicBool,
    slow: std::sync::Mutex<HashSet<String>>,
    fast_provenance: AtomicUsize,
}

impl BrakedParts {
    fn part_of(key: &str) -> Option<String> {
        if !key.contains("/parts/") || key.contains("/log/") {
            return None;
        }
        key.rsplit('/').nth(1).map(str::to_string)
    }
    async fn brake(&self, key: &str) {
        let Some(part) = Self::part_of(key) else { return };
        let slow = {
            let mut slow = self.slow.lock().unwrap();
            if self.capture.load(Ordering::SeqCst) {
                slow.insert(part.clone());
            }
            slow.contains(&part)
        };
        if slow {
            tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
        }
    }
}

#[async_trait]
impl ObjectStore for BrakedParts {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        self.brake(key).await;
        let written = self.inner.put_if_absent(key, bytes).await?;
        let slow = Self::part_of(key).is_some_and(|part| self.slow.lock().unwrap().contains(&part));
        if key.ends_with("/provenance.json") && !slow {
            self.fast_provenance.fetch_add(1, Ordering::SeqCst);
        }
        Ok(written)
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.inner.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.list(prefix).await
    }
}

fn depth_two_config(root: &Path) -> IngestConfig {
    let mut cfg = config(root);
    cfg.flush_depth = 2;
    // Commit-when-ready on too: its reaps are the ones that must not
    // commit the younger flight ahead of the older one.
    cfg.commit_when_ready = true;
    cfg
}

/// Drive a depth-2 ingestor until two flights are in flight, the older one
/// braked (still uploading) and the younger one fully published.
async fn two_flights_younger_done(ingestor: &mut Ingestor<'_>, clock: &mut i64, braked: &BrakedParts) {
    braked.capture.store(true, Ordering::SeqCst);
    for _ in 0..20 {
        *clock += 11_000;
        ingestor.tick(*clock).await.unwrap();
        if ingestor.health().flushes_pipelined_total >= 1 {
            break;
        }
    }
    assert_eq!(ingestor.health().flushes_pipelined_total, 1, "the first catch-up flush is in flight");
    // Its uploads have started (and are braked): stop capturing.
    let started = Instant::now();
    while braked.slow.lock().unwrap().is_empty() {
        assert!(started.elapsed().as_secs() < 30, "the first flight never started uploading");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    braked.capture.store(false, Ordering::SeqCst);
    // The next due flush seals beside it (depth 2) instead of waiting
    // (the fresh buffer is due one tick after it first admits).
    for _ in 0..3 {
        *clock += 11_000;
        ingestor.tick(*clock).await.unwrap();
        if ingestor.health().flushes_pipelined_total >= 2 {
            break;
        }
    }
    assert_eq!(ingestor.health().flushes_pipelined_total, 2, "a second flush sealed");
    assert_eq!(ingestor.health().flushes_in_flight, 2, "both flushes in flight at once");
    // Wait for the younger flight to finish publishing.
    let started = Instant::now();
    while braked.fast_provenance.load(Ordering::SeqCst) == 0 {
        assert!(started.elapsed().as_secs() < 30, "the second flight never published");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
}

/// NAN-3619: with two flushes in flight, a younger flight that finishes
/// first waits for the older one: nothing commits or acks out of seal
/// order, and every row lands exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_flights_commit_in_seal_order_when_the_younger_finishes_first() {
    let fx = fixture(120, 10);
    for (key, at) in &fx.objects {
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    let queue = DepthTwoQueue::new(&fx);
    let braked: &'static BrakedParts = Box::leak(Box::new(BrakedParts {
        inner: LocalObjectStore::new(fx.root.join("parts")).unwrap(),
        capture: Default::default(), slow: Default::default(), fast_provenance: AtomicUsize::new(0),
    }));
    let background_signer: &'static LocalPartSigner = Box::leak(Box::new(signer()));
    let mut clock = (DAY0_S + 2_400) * 1_000;
    let mut ingestor = Ingestor::open(depth_two_config(&fx.root), &fx.parts, &fx.sources, &queue, &fx.signer, trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.unwrap();
    ingestor.set_background_store(braked);
    ingestor.set_background_signer(background_signer);
    two_flights_younger_done(&mut ingestor, &mut clock, braked).await;
    // Commit-when-ready reaps only the oldest flight, and it is not ready:
    // the finished younger flight must not commit or ack ahead of it.
    let mut report = Default::default();
    ingestor.tick_maintain(clock, &[], &mut report).await.unwrap();
    assert_eq!(queue.acked.load(Ordering::SeqCst), 0, "nothing acked ahead of the older flight");
    assert_eq!(ingestor.health().flushes_in_flight, 2, "the younger flight waits behind the older one");
    assert!(live_rows(&fx).await.is_empty(), "no add committed ahead of the older flight");
    assert_eq!(queue.peak_outstanding.load(Ordering::SeqCst), 2);
    // Drain: both commit in order (the queue enforces it), then the rest.
    pipelined_ticks(&mut ingestor, &mut clock, 400, &fx.spool).await.unwrap();
    ingestor.flush_now(clock + 11_000).await.unwrap();
    assert_eq!(ingestor.health().flushes_in_flight_peak, 2);
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "every notice acked");
    assert!(queue.issued.lock().unwrap().is_empty());
    assert_eq!(queue.acked.load(Ordering::SeqCst), fx.objects.len());
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
}

/// NAN-3619: a crash with two sealed, uncommitted flushes in flight (ranges
/// issued, no `add`) replays every row exactly once after the restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_crash_with_two_flights_in_flight_replays_exactly_once() {
    let fx = fixture(120, 10);
    for (key, at) in &fx.objects {
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    let queue = DepthTwoQueue::new(&fx);
    let braked: &'static BrakedParts = Box::leak(Box::new(BrakedParts {
        inner: LocalObjectStore::new(fx.root.join("parts")).unwrap(),
        capture: Default::default(), slow: Default::default(), fast_provenance: AtomicUsize::new(0),
    }));
    let background_signer: &'static LocalPartSigner = Box::leak(Box::new(signer()));
    let reopen = |clock: i64| {
        let (queue, fx) = (&queue, &fx);
        async move {
            let mut ingestor = Ingestor::open(depth_two_config(&fx.root), &fx.parts, &fx.sources, queue, &fx.signer, trusted(),
                BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.unwrap();
            ingestor.set_background_store(braked);
            ingestor.set_background_signer(background_signer);
            ingestor
        }
    };
    let mut clock = (DAY0_S + 2_400) * 1_000;
    let mut ingestor = reopen(clock).await;
    two_flights_younger_done(&mut ingestor, &mut clock, braked).await;
    assert_eq!(queue.acked.load(Ordering::SeqCst), 0);
    // The process dies between seal and commit with both flights out: the
    // edge source (its stand-in here) forgets the issued ranges with it.
    drop(ingestor);
    queue.issued.lock().unwrap().clear();
    braked.slow.lock().unwrap().clear();
    let mut ingestor = reopen(clock).await;
    pipelined_ticks(&mut ingestor, &mut clock, 400, &fx.spool).await.unwrap();
    ingestor.flush_now(clock + 11_000).await.unwrap();
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "every notice acked");
    assert!(queue.issued.lock().unwrap().is_empty());
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
}

/// NAN-4539: the foreground part store, signaling once (when armed) that a
/// part-log entry landed, so a test can drop the commit right after its
/// `add` committed.
struct LogSignalParts<'a> {
    inner: &'a LocalObjectStore,
    armed: std::sync::atomic::AtomicBool,
    landed: tokio::sync::Notify,
    entries: AtomicUsize,
}

impl<'a> LogSignalParts<'a> {
    fn new(inner: &'a LocalObjectStore) -> Self {
        Self { inner, armed: Default::default(), landed: tokio::sync::Notify::new(), entries: AtomicUsize::new(0) }
    }
}

#[async_trait]
impl ObjectStore for LogSignalParts<'_> {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        let written = self.inner.put_if_absent(key, bytes).await?;
        if written && key.contains("/log/entries/") {
            self.entries.fetch_add(1, Ordering::SeqCst);
            if self.armed.swap(false, Ordering::SeqCst) {
                self.landed.notify_one();
            }
        }
        Ok(written)
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.inner.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.list(prefix).await
    }
}

/// Every `add` entry of the part log: the sources it consumed.
async fn logged_adds(fx: &Fixture) -> Vec<Vec<String>> {
    use nanosiem_lake_worker::parts::part_log::{LogEntry, LogOp};
    let keys = nanosiem_lake_worker::parts::format::LogKeys::new(TENANT).unwrap();
    let mut adds = Vec::new();
    for seq in 0.. {
        let Some(bytes) = fx.parts.get(&keys.entry(seq)).await.unwrap() else { break };
        if let LogOp::Add { consumed, .. } = LogEntry::parse_bytes(&bytes, TENANT).unwrap().op {
            adds.push(consumed.into_iter().map(|source| source.key).collect());
        }
    }
    adds
}

fn assert_each_source_added_once(adds: &[Vec<String>]) {
    let mut seen = HashSet::new();
    for key in adds.iter().flatten() {
        assert!(seen.insert(key.clone()), "{key} consumed by two adds");
    }
}

/// NAN-4539: a commit of the oldest flight dropped at every await (its
/// background task, right after its `add` landed while prevalence applies,
/// and mid-ack) keeps that flight, its reservation and its immutable output.
/// The next commit resumes it: the landed `add` is adopted (no second
/// append, no DoubleConsume), acks stay in issue order, nothing is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_pipelined_commit_keeps_the_oldest_flight_and_resumes_exactly_once() {
    let fx = fixture(120, 10);
    for (key, at) in &fx.objects {
        fx.spool.deliver(&notice(key, *at)).unwrap();
    }
    let queue = DepthTwoQueue::new(&fx);
    let parts = LogSignalParts::new(&fx.parts);
    let braked: &'static BrakedParts = Box::leak(Box::new(BrakedParts {
        inner: LocalObjectStore::new(fx.root.join("parts")).unwrap(),
        capture: Default::default(), slow: Default::default(), fast_provenance: AtomicUsize::new(0),
    }));
    let background_signer: &'static LocalPartSigner = Box::leak(Box::new(signer()));
    let mut clock = (DAY0_S + 2_400) * 1_000;
    let mut ingestor = Ingestor::open(depth_two_config(&fx.root), &parts, &fx.sources, &queue, &fx.signer, trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.unwrap();
    ingestor.set_background_store(braked);
    ingestor.set_background_signer(background_signer);
    two_flights_younger_done(&mut ingestor, &mut clock, braked).await;
    let reserved = ingestor.health().clone();

    // 1. Dropped while the older (braked) flight's task is awaited.
    let dropped = tokio::time::timeout(std::time::Duration::from_millis(50), ingestor.flush_now(clock)).await;
    assert!(dropped.is_err(), "the older flight is still uploading");
    assert_eq!(ingestor.health().flushes_in_flight, 2, "a dropped commit keeps the oldest flight");
    assert_eq!(queue.acked.load(Ordering::SeqCst), 0);

    // 2. Dropped right after its add landed, while prevalence applies.
    ingestor.stall_next_prevalence_ops(1);
    parts.armed.store(true, Ordering::SeqCst);
    let entries = parts.entries.load(Ordering::SeqCst);
    tokio::select! {
        outcome = ingestor.flush_now(clock) => panic!("the stalled apply finished first: {outcome:?}"),
        _ = parts.landed.notified() => {}
    }
    assert_eq!(parts.entries.load(Ordering::SeqCst), entries + 1, "exactly the oldest add landed");
    assert_eq!(ingestor.health().flushes_in_flight, 2, "an add without its acks keeps the flight");
    assert_eq!(queue.acked.load(Ordering::SeqCst), 0, "nothing acked yet");
    assert_eq!(logged_adds(&fx).await.len(), 1);

    // 3. The retry adopts that add, then is dropped mid-ack.
    queue.stall_ack.store(true, Ordering::SeqCst);
    tokio::select! {
        outcome = ingestor.flush_now(clock) => panic!("the stalled ack finished first: {outcome:?}"),
        _ = queue.ack_entered.notified() => {}
    }
    assert_eq!(parts.entries.load(Ordering::SeqCst), entries + 1, "the landed add is adopted, never appended again");
    assert_eq!(ingestor.health().flushes_in_flight, 2, "a dropped ack keeps the flight");
    queue.stall_ack.store(false, Ordering::SeqCst);
    braked.slow.lock().unwrap().clear();

    // Drain: every flight commits in issue order, each source once.
    pipelined_ticks(&mut ingestor, &mut clock, 400, &fx.spool).await.unwrap();
    ingestor.flush_now(clock + 11_000).await.unwrap();
    assert!(reserved.flushes_in_flight_peak <= 2 && ingestor.health().flushes_in_flight_peak <= 2);
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "every notice acked");
    assert!(queue.issued.lock().unwrap().is_empty());
    assert_eq!(queue.acked.load(Ordering::SeqCst), fx.objects.len(), "each notice acked exactly once");
    let adds = logged_adds(&fx).await;
    assert_each_source_added_once(&adds);
    assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
}

/// NAN-4539: the serial path too. A flush dropped after its `add` landed
/// (prevalence stalled) keeps its immutable output; the retry republishes the
/// same parts, adopts the landed add instead of appending a second one, and
/// the cursor replay applies its prevalence exactly once.
#[tokio::test(flavor = "current_thread")]
async fn a_serial_flush_dropped_after_its_add_landed_is_adopted_not_reappended() {
    let fx = fixture(3, 1);
    write_stamp_sources(&fx);
    let parts = LogSignalParts::new(&fx.parts);
    let mut ingestor = Ingestor::open(config(&fx.root), &parts, &fx.sources, &fx.spool, &fx.signer, trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), DAY0_S * 1_000).await.unwrap();
    let (key, at) = &fx.objects[0];
    fx.spool.deliver(&notice(key, *at)).unwrap();
    ingestor.tick(at * 1_000).await.unwrap();
    ingestor.flush_now(at * 1_000).await.unwrap();

    let (key, at) = &fx.objects[1];
    fx.spool.deliver(&notice(key, *at)).unwrap();
    ingestor.tick(at * 1_000).await.unwrap();
    ingestor.stall_next_prevalence_ops(1);
    parts.armed.store(true, Ordering::SeqCst);
    tokio::select! {
        outcome = ingestor.flush_now(at * 1_000) => panic!("the stalled apply finished first: {outcome:?}"),
        _ = parts.landed.notified() => {}
    }
    let entries = parts.entries.load(Ordering::SeqCst);
    assert!(ingestor.prevalence_pending(), "the landed add's apply is owed");
    // The retry: the same parts, the landed add adopted (a re-append would
    // double-consume the source, a fatal error).
    ingestor.flush_now(at * 1_000).await.expect("the retry adopts the landed add");
    assert_eq!(parts.entries.load(Ordering::SeqCst), entries, "no second add");
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "the source is acked after the adopted add");
    ingestor.tick(at * 1_000 + 1).await.unwrap();
    assert!(!ingestor.prevalence_pending(), "the next tick replays the committed add");

    let (key, at) = &fx.objects[2];
    fx.spool.deliver(&notice(key, *at)).unwrap();
    ingestor.tick(at * 1_000).await.unwrap();
    ingestor.flush_now(at * 1_000).await.unwrap();
    let adds = logged_adds(&fx).await;
    assert_eq!(adds.len(), 3, "one add per source");
    assert_each_source_added_once(&adds);
    assert_eq!(dest_ip_stamps(&fx).await, vec![Some(1), Some(1), Some(2)], "prevalence applied exactly once");
}

#[test]
fn flush_pipeline_defaults_are_bounded_without_deployment_switches() {
    use nanosiem_lake_worker::part_ingest::ingest::edge_source_config;
    let cfg = IngestConfig::new(TENANT, "/tmp/x");
    assert_eq!(cfg.flush_depth, 2);
    assert!(cfg.commit_when_ready);
    assert_eq!(edge_source_config(1).max_issued_ranges, 1);
    assert_eq!(edge_source_config(2).max_issued_ranges, 2);
    assert_eq!(edge_source_config(2).max_buffered_bytes,
        nanosiem_lake_worker::edge_log::EdgeLogSourceConfig::default().max_buffered_bytes);
}

/// Ready commits default on; an explicit serial baseline still exercises the
/// previous off behavior for the offline comparison (no environment switch).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn commit_when_ready_defaults_on_and_serial_comparison_preserves_the_old_path() {
    assert!(IngestConfig::new(TENANT, "/tmp/x").commit_when_ready);
    for on in [false, true] {
        let fx = fixture(120, 10);
        for (key, at) in &fx.objects {
            fx.spool.deliver(&notice(key, *at)).unwrap();
        }
        let queue = DepthTwoQueue::new(&fx);
        let braked: &'static BrakedParts = Box::leak(Box::new(BrakedParts {
            inner: LocalObjectStore::new(fx.root.join("parts")).unwrap(),
            capture: Default::default(), slow: Default::default(), fast_provenance: AtomicUsize::new(0),
        }));
        let background_signer: &'static LocalPartSigner = Box::leak(Box::new(signer()));
        let mut cfg = config(&fx.root);
        cfg.flush_depth = 1;
        cfg.commit_when_ready = on;
        let mut clock = (DAY0_S + 2_400) * 1_000;
        let mut ingestor = Ingestor::open(cfg, &fx.parts, &fx.sources, &queue, &fx.signer, trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), clock).await.unwrap();
        ingestor.set_background_store(braked);
        ingestor.set_background_signer(background_signer);
        for _ in 0..20 {
            clock += 11_000;
            ingestor.tick(clock).await.unwrap();
            if ingestor.health().flushes_pipelined_total >= 1 {
                break;
            }
        }
        assert_eq!(ingestor.health().flushes_in_flight, 1, "a flight is in flight");
        let acked = queue.acked.load(Ordering::SeqCst);
        // Its parts are published (provenance is the last write).
        let started = Instant::now();
        while braked.fast_provenance.load(Ordering::SeqCst) == 0 {
            assert!(started.elapsed().as_secs() < 30, "the flight never published");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let mut report = Default::default();
        ingestor.tick_maintain(clock, &[], &mut report).await.unwrap();
        if on {
            assert_eq!(ingestor.health().flushes_in_flight, 0, "on: maintenance commits the ready flight");
            assert!(queue.acked.load(Ordering::SeqCst) > acked);
        } else {
            assert_eq!(ingestor.health().flushes_in_flight, 1, "off: the flight waits for the next ingest phase");
            assert_eq!(queue.acked.load(Ordering::SeqCst), acked);
        }
        pipelined_ticks(&mut ingestor, &mut clock, 400, &fx.spool).await.unwrap();
        ingestor.flush_now(clock + 11_000).await.unwrap();
        assert!(fx.spool.pending(1).await.unwrap().is_empty());
        assert_exactly_once(&live_rows(&fx).await, fx.unique_uids);
        if on {
            assert_eq!(queue.empty_skip_acks.load(Ordering::SeqCst), 0, "on: no empty skip ack");
        } else {
            assert_eq!(queue.max_pending_window.load(Ordering::SeqCst), 48, "off: the pending window stays 4 x 12");
            assert!(queue.empty_skip_acks.load(Ordering::SeqCst) > 0, "off: the empty skip ack is still sent");
        }
    }
}

/// NAN-3774: an R2 stand-in whose prevalence reads and/or writes stall
/// while a gate is closed (R2 request timeouts on tenant-a, 2026-10-13). Opening
/// the gate resumes the stalled requests. Each process gets its own handle
/// ([`GatedStore::handle`]) on the shared objects; [`GatedStore::kill`]
/// fails every request of a process that has exited, so its leftover
/// SlateDB tasks never write behind the next process.
#[derive(Debug, Default)]
struct GatedStore {
    inner: Arc<slatedb::object_store::memory::InMemory>,
    stall_reads: std::sync::atomic::AtomicBool,
    stall_writes: std::sync::atomic::AtomicBool,
    dead: std::sync::atomic::AtomicBool,
}

impl GatedStore {
    /// A fresh handle on the same objects (a new process).
    fn handle(&self) -> Arc<Self> {
        Arc::new(Self { inner: self.inner.clone(), ..Self::default() })
    }

    fn stall(&self, reads: bool, writes: bool) {
        self.stall_reads.store(reads, Ordering::SeqCst);
        self.stall_writes.store(writes, Ordering::SeqCst);
    }

    /// This handle's process exited: its stalled and later requests fail.
    fn kill(&self) {
        self.dead.store(true, Ordering::SeqCst);
    }

    async fn pass(&self, gate: &std::sync::atomic::AtomicBool) -> slatedb::object_store::Result<()> {
        while gate.load(Ordering::SeqCst) && !self.dead.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        if self.dead.load(Ordering::SeqCst) {
            return Err(slatedb::object_store::Error::Generic { store: "GatedStore", source: "request timed out".into() });
        }
        Ok(())
    }
}

impl std::fmt::Display for GatedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GatedStore")
    }
}

#[async_trait]
impl slatedb::object_store::ObjectStore for GatedStore {
    async fn put_opts(&self, path: &slatedb::object_store::path::Path, payload: slatedb::object_store::PutPayload,
        opts: slatedb::object_store::PutOptions) -> slatedb::object_store::Result<slatedb::object_store::PutResult> {
        self.pass(&self.stall_writes).await?;
        self.inner.put_opts(path, payload, opts).await
    }
    async fn put_multipart_opts(&self, path: &slatedb::object_store::path::Path, opts: slatedb::object_store::PutMultipartOptions)
        -> slatedb::object_store::Result<Box<dyn slatedb::object_store::MultipartUpload>> {
        self.pass(&self.stall_writes).await?;
        self.inner.put_multipart_opts(path, opts).await
    }
    async fn get_opts(&self, path: &slatedb::object_store::path::Path, options: slatedb::object_store::GetOptions)
        -> slatedb::object_store::Result<slatedb::object_store::GetResult> {
        self.pass(&self.stall_reads).await?;
        self.inner.get_opts(path, options).await
    }
    fn delete_stream(&self, locations: futures::stream::BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::path::Path>>)
        -> futures::stream::BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::path::Path>> {
        self.inner.delete_stream(locations)
    }
    fn list(&self, prefix: Option<&slatedb::object_store::path::Path>)
        -> futures::stream::BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::ObjectMeta>> {
        self.inner.list(prefix)
    }
    async fn list_with_delimiter(&self, prefix: Option<&slatedb::object_store::path::Path>)
        -> slatedb::object_store::Result<slatedb::object_store::ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }
    async fn copy_opts(&self, from: &slatedb::object_store::path::Path, to: &slatedb::object_store::path::Path,
        options: slatedb::object_store::CopyOptions) -> slatedb::object_store::Result<()> {
        self.pass(&self.stall_writes).await?;
        self.inner.copy_opts(from, to, options).await
    }
}

/// NAN-3774 config: prevalence on `store`, a short ingest wait, and the
/// default 45 s `prevalence_op_timeout` (no test here needs the stall
/// detector for ingest to keep committing).
/// What one ingest tick + flush may take while the prevalence store stalls.
/// A held tick waits for the stall itself (unbounded here: [`GatedStore`]
/// holds until killed; the 45 s op timeout in production), so the bound only
/// needs a wide margin over a tick's own work (`prevalence_ingest_wait` is
/// 250 ms) for a loaded build-farm VM. 3 s was tripped by flush I/O jitter
/// alone with extra load beside the suite (NAN-4573).
const STALLED_STORE_TICK_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

fn gated_config(fx: &Fixture, store: &Arc<GatedStore>) -> IngestConfig {
    let mut cfg = config(&fx.root);
    cfg.prevalence_read_store = Some(store.clone());
    cfg.prevalence_ingest_wait = std::time::Duration::from_millis(250);
    // The cell's merge mode (`cell.rs` sets it with its background handles):
    // a merge computes off the tick and is reaped without waiting. Inline
    // merges (the lab default) compute on the tick, so the "held tick +
    // flush" bounds below measured the L0 merge that comes due a few calls
    // in, not prevalence; under farm suite load it took 2-7 s (NAN-4573).
    cfg.background_merges = true;
    cfg
}

/// Deliver one object and run a tick plus a flush, returning how long the
/// two took together.
async fn ingest_one(fx: &Fixture, ingestor: &mut Ingestor<'_>, key: &str, at: i64) -> std::time::Duration {
    fx.spool.deliver(&notice(key, at)).unwrap();
    let began = Instant::now();
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        ingestor.tick(at * 1_000).await.unwrap();
        ingestor.flush_now(at * 1_000).await.unwrap();
    }).await.expect("ingest never blocks on prevalence");
    began.elapsed()
}

/// Tick (no new input) until prevalence stamps at the log head again.
async fn tick_until_stamping(ingestor: &mut Ingestor<'_>, mut now_ms: i64) -> i64 {
    let deadline = Instant::now() + std::time::Duration::from_secs(60);
    while ingestor.prevalence_status() != "stamping" {
        assert!(Instant::now() < deadline, "prevalence never caught up: {}", ingestor.prevalence_status());
        now_ms += 1_000;
        ingestor.tick(now_ms).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    now_ms
}

/// The tenant state's (host_count, total_occurrences) for `8.8.8.8`, the
/// destination every `write_stamp_sources` row carries, read by a fresh
/// writer on the same store (the ingestor is dropped first). Occurrences
/// count every applied row, so an `Add` applied twice shows here.
async fn dest_ip_prevalence(fx: &Fixture, store: &Arc<GatedStore>, now_ms: i64) -> (u64, u64) {
    use nanosiem_lake_worker::part_ingest::prevalence::IngestPrevalence;
    store.kill();
    let mut state = IngestPrevalence::open_with_reads(TENANT, &fx.root.join("work"), None, Some(store.handle())).await.unwrap();
    state.advance_watermark(now_ms * 1_000);
    let mut probe = json!({"dst_endpoint": {"ip": "8.8.8.8"}, "src_endpoint": {"hostname": "probe"}});
    state.stamp(&mut probe).await.unwrap();
    let entry = probe["enrichments"].as_array().unwrap().iter()
        .find(|entry| entry["value"] == json!("8.8.8.8"))
        .unwrap_or_else(|| panic!("no prevalence stamp for 8.8.8.8: {probe}"))
        .clone();
    state.close().await.unwrap();
    (entry["data"]["host_count"].as_u64().unwrap_or(0), entry["data"]["total_occurrences"].as_u64().unwrap_or(0))
}

/// NAN-3774 (tenant-a 2026-10-13: ingest_lag 147 s / 126 s): R2 timeouts stalled
/// the prevalence store and every flush waited 45 s behind it. Prevalence is
/// derived: with its reads and writes stalled, each tick + flush finishes
/// within a few ingest waits and commits every row (unstamped), without
/// needing the 45 s stall detector. When R2 recovers the state catches up
/// from the part log, applying every committed `Add` exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_prevalence_store_never_holds_a_commit_and_catches_up_exactly_once() {
    let fx = fixture(6, 1);
    write_stamp_sources(&fx);
    let store = Arc::new(GatedStore::default());
    let mut ingestor = open_with(&fx, gated_config(&fx, &store), DAY0_S * 1_000).await.unwrap();
    assert_eq!(ingestor.prevalence_status(), "stamping");
    let (first, rest) = fx.objects.split_first().unwrap();
    let (last, stalled) = rest.split_last().unwrap();
    ingest_one(&fx, &mut ingestor, &first.0, first.1).await;

    // R2 stops answering prevalence reads and writes.
    store.stall(true, true);
    for (key, at) in stalled {
        let took = ingest_one(&fx, &mut ingestor, key, *at).await;
        assert!(took < STALLED_STORE_TICK_BOUND, "a stalled prevalence store held tick + flush for {took:?}");
    }
    assert!(fx.spool.pending(1).await.unwrap().is_empty(), "every notice committed and acked");
    assert_exactly_once(&live_rows(&fx).await, 1 + stalled.len());
    let now = last.1 * 1_000;
    ingestor.tick(now).await.unwrap();
    let health = ingestor.health().clone();
    assert_eq!(health.prevalence_stalls_total, 0, "ingest kept committing without the 45 s stall detector");
    assert!(health.prevalence_deferred_total >= 1, "the overruns are counted");
    // Whether the in-memory state has applied the adds yet depends on which
    // probe overran last (applies land in the memtable without R2); what
    // matters is that nothing waited and that they all become durable once
    // R2 answers again, exactly once (checked below from a fresh reader).

    // R2 recovers: the stalled requests complete and the state catches up.
    store.stall(false, false);
    let now = tick_until_stamping(&mut ingestor, now).await;
    assert!(!ingestor.prevalence_pending());
    ingestor.tick(now).await.unwrap();
    assert_eq!(ingestor.health().prevalence_behind_entries, 0);
    assert_eq!(ingestor.health().prevalence_behind_ms, 0);
    ingest_one(&fx, &mut ingestor, &last.0, last.1).await;
    let stamps = dest_ip_stamps(&fx).await;
    assert_eq!(stamps.last().copied().flatten(), Some(fx.objects.len() as u64 - 1),
        "the row after recovery counts every earlier host: {stamps:?}");
    drop(ingestor);
    let objects = fx.objects.len() as u64;
    assert_eq!(dest_ip_prevalence(&fx, &store, now + 1_000).await, (objects, objects),
        "every committed row is in the state exactly once");
}

/// NAN-3774: adds committed while the store stalled are owed to the state
/// across restarts. A restart, then another one part-way through the
/// catch-up, still applies every `Add` exactly once (the cursor and each
/// chunk land together).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_mid_catch_up_applies_every_add_exactly_once() {
    let fx = fixture(6, 1);
    write_stamp_sources(&fx);
    let store = Arc::new(GatedStore::default());
    let mut ingestor = open_with(&fx, gated_config(&fx, &store), DAY0_S * 1_000).await.unwrap();
    let (first, rest) = fx.objects.split_first().unwrap();
    let (last, stalled) = rest.split_last().unwrap();
    ingest_one(&fx, &mut ingestor, &first.0, first.1).await;
    store.stall(false, true);
    for (key, at) in stalled {
        let took = ingest_one(&fx, &mut ingestor, key, *at).await;
        assert!(took < STALLED_STORE_TICK_BOUND, "a stalled prevalence store held tick + flush for {took:?}");
    }
    assert!(ingestor.prevalence_pending());
    // The process restarts; its stalled writes time out.
    drop(ingestor);
    store.kill();

    // One entry per catch-up step, then a restart part-way through.
    let store = store.handle();
    let mut slow = gated_config(&fx, &store);
    slow.prevalence_rebuild_budget_ms = 0;
    let now = last.1 * 1_000;
    // NAN-3849: one-entry batches, so the restart lands between batches.
    slow.prevalence_catch_up_batch_entries = 1;
    let mut ingestor = open_with(&fx, slow, now).await.unwrap();
    assert_eq!(ingestor.prevalence_status(), "unstamped: catching up with committed adds");
    ingestor.tick(now + 1).await.unwrap();
    assert_eq!(ingestor.prevalence_status(), "unstamped: catching up with committed adds",
        "still part-way through the catch-up");
    drop(ingestor);
    store.kill();

    let store = store.handle();
    let mut ingestor = open_with(&fx, gated_config(&fx, &store), now + 2).await.unwrap();
    let now = tick_until_stamping(&mut ingestor, now + 2).await;
    ingest_one(&fx, &mut ingestor, &last.0, last.1).await;
    let stamps = dest_ip_stamps(&fx).await;
    assert_eq!(stamps.last().copied().flatten(), Some(fx.objects.len() as u64 - 1), "{stamps:?}");
    drop(ingestor);
    let objects = fx.objects.len() as u64;
    assert_eq!(dest_ip_prevalence(&fx, &store, now + 1_000).await, (objects, objects),
        "no add counted twice across the restarts");
}

/// NAN-4460 (the large tenant 2026-10-23: 16,883 entries behind after a 62 h outage, ~26
/// entries a batch, a ~5 h ETA): a long backlog grows the catch-up batches
/// with the backlog, then shrinks them back to today's size near the head. Runs
/// on the production `Ingestor` with prevalence on the production open path,
/// the cap from the large tenant's ingest memory limit. Every committed `Add` lands exactly
/// once, and every tick stays bounded while the state is behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_prevalence_backlog_scales_its_catch_up_batches_and_lands_every_add_once() {
    use nanosiem_lake_worker::part_ingest::prevalence::{catch_up_max_rows_for, CATCH_UP_MAX_SCALE};
    let fx = fixture(40, 1);
    write_stamp_sources(&fx);
    let store = Arc::new(GatedStore::default());
    let mut ingestor = open_with(&fx, gated_config(&fx, &store), DAY0_S * 1_000).await.unwrap();
    let (first, rest) = fx.objects.split_first().unwrap();
    let (last, stalled) = rest.split_last().unwrap();
    ingest_one(&fx, &mut ingestor, &first.0, first.1).await;
    // The state's writes stall (the outage); every Add commits and is owed.
    store.stall(false, true);
    for (key, at) in stalled {
        let took = ingest_one(&fx, &mut ingestor, key, *at).await;
        assert!(took < STALLED_STORE_TICK_BOUND, "a stalled prevalence store held tick + flush for {took:?}");
    }
    assert!(ingestor.prevalence_pending());
    drop(ingestor);
    store.kill();

    // A fresh process catches up. Base batches of 2 entries stand in for
    // 32 (the backlog is 38 entries rather than 16,883).
    let store = store.handle();
    let mut cfg = gated_config(&fx, &store);
    cfg.prevalence_catch_up_batch_entries = 2;
    cfg.prevalence_catch_up_max_rows = catch_up_max_rows_for(4_831_838_208);
    // NAN-4550: one catch-up batch per step (the step budget only bounds how
    // many batches a tick runs, never their size or scale), so the scale is
    // observed after every batch. With the 2 s budget a fast host ran every
    // batch of the climb and the descent inside one tick, and the per-tick
    // sample saw [1, 2, 1].
    cfg.prevalence_rebuild_budget_ms = 0;
    let mut now = last.1 * 1_000;
    let mut ingestor = open_with(&fx, cfg, now).await.unwrap();
    assert_eq!(ingestor.prevalence_status(), "unstamped: catching up with committed adds");
    let behind = stalled.len() as u64;
    let mut scales = vec![ingestor.prevalence_catch_up_scale()];
    let mut seen_batches = ingestor.health().prevalence_catch_up_batches_total;
    // A liveness bound only: the scales asserted below depend on the batch
    // sequence, not on how fast the host runs it.
    let deadline = Instant::now() + std::time::Duration::from_secs(60);
    while ingestor.prevalence_status() != "stamping" {
        assert!(Instant::now() < deadline, "prevalence never caught up: {}", ingestor.prevalence_status());
        now += 1_000;
        let began = Instant::now();
        ingestor.tick(now).await.unwrap();
        assert!(began.elapsed() < std::time::Duration::from_secs(3), "a catch-up tick held ingest for {:?}", began.elapsed());
        let batches = ingestor.health().prevalence_catch_up_batches_total;
        assert!(batches <= seen_batches + 1, "one batch per step: every batch's scale is sampled ({seen_batches} -> {batches})");
        seen_batches = batches;
        scales.push(ingestor.prevalence_catch_up_scale());
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let batches = ingestor.health().prevalence_catch_up_batches_total;
    let largest = scales.iter().copied().max().unwrap();
    eprintln!("{behind} entries behind: {batches} catch-up batches, scales {scales:?}");
    assert!((4..=CATCH_UP_MAX_SCALE).contains(&largest), "the batch grew with the backlog: {scales:?}");
    assert!(batches * 2 <= behind / 2, "at least twice fewer batches than at a fixed size: {batches} for {behind}");
    assert_eq!(ingestor.prevalence_catch_up_scale(), 1, "back to today's batch at the head");
    ingest_one(&fx, &mut ingestor, &last.0, last.1).await;
    let stamps = dest_ip_stamps(&fx).await;
    assert_eq!(stamps.last().copied().flatten(), Some(fx.objects.len() as u64 - 1), "{stamps:?}");
    drop(ingestor);
    let objects = fx.objects.len() as u64;
    assert_eq!(dest_ip_prevalence(&fx, &store, now + 1_000).await, (objects, objects),
        "every committed add is in the state exactly once");
}

/// NAN-3774 (tenant-a 2026-10-13 15:18Z: the first flush after the r48 roll
/// committed only after the prevalence state was ready, ingest_lag 152 s):
/// after a restart that must rebuild the tenant state (lost DB) with R2
/// stalling, the first tick + flush still commit at once (unstamped); the
/// rebuild finishes afterwards and counts every row once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_flush_after_a_cold_start_never_waits_on_the_prevalence_rebuild() {
    let fx = fixture(6, 1);
    write_stamp_sources(&fx);
    let lost = Arc::new(GatedStore::default());
    let mut ingestor = open_with(&fx, gated_config(&fx, &lost), DAY0_S * 1_000).await.unwrap();
    let (before, after) = fx.objects.split_at(3);
    for (key, at) in before {
        ingest_one(&fx, &mut ingestor, key, *at).await;
    }
    drop(ingestor);
    lost.kill();
    std::fs::remove_dir_all(fx.root.join("work/prevalence").join(TENANT)).unwrap();

    // Cold start on an empty state: it rebuilds from the live parts.
    let store = Arc::new(GatedStore::default());
    let now = after[0].1 * 1_000;
    let mut ingestor = open_with(&fx, gated_config(&fx, &store), now).await.unwrap();
    assert!(ingestor.prevalence_status().starts_with("unstamped: rebuilding (0/"), "{}", ingestor.prevalence_status());
    store.stall(true, true);
    let (first, rest) = after.split_first().unwrap();
    let took = ingest_one(&fx, &mut ingestor, &first.0, first.1).await;
    assert!(took < std::time::Duration::from_secs(3), "the first flush waited {took:?} on the rebuild");
    assert_eq!(live_rows(&fx).await.len(), before.len() + 1, "the first flush committed");

    store.stall(false, false);
    let now = tick_until_stamping(&mut ingestor, now).await;
    for (key, at) in rest {
        ingest_one(&fx, &mut ingestor, key, *at).await;
    }
    let stamps = dest_ip_stamps(&fx).await;
    assert_eq!(stamps.last().copied().flatten(), Some(fx.objects.len() as u64 - 1), "{stamps:?}");
    drop(ingestor);
    let objects = fx.objects.len() as u64;
    assert_eq!(dest_ip_prevalence(&fx, &store, now + 1_000).await, (objects, objects));
}

/// NAN-4168, production query path: rows stamped by the real ingest binary
/// (platform bundle + tenant policy) are served by query[T] exactly as the
/// `lake_part_query` binary wires it: a `QueryBootstrap` document,
/// `server::open_engine`, `QueryService::new`, its background prewarm, and the HTTP
/// `/v1/query` route (axum router over a socket). A search projecting endpoint
/// fields plus country returns the stored stamps, and a stats by country
/// counts them, after the policy grants are revoked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256 and NANO_LAKE_COMPILER"]
async fn platform_stamps_return_through_the_query_service_route() {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper_util::rt::TokioIo;
    use nanosiem_lake_worker::part_query::server::{open_engine, OpenOptions, QueryBootstrap, QueryService};
    use std::time::Duration;

    let fx = fixture(1, 1);
    let (key, _at) = &fx.objects[0];
    let event_time_s = chrono::Utc::now().timestamp() - 10;
    let mut source = event("service-platform", event_time_s, 1);
    source["src_endpoint"]["ip"] = json!("8.8.8.8");
    source["dst_endpoint"]["ip"] = json!("9.9.9.9");
    write_bronze(&fx.root.join("sources").join(key), &[source]);
    let bundle_path = fx.root.join("platform.bundle");
    let digest = PlatformBundle::publish(&bundle_path, Some(&test_mmdb_bytes()), &[
        IocSnapshotInput { ioc_value: "8.8.8.8".into(), ioc_type: "ip".into(), source_id: "threatfox".into(),
            threat_type: "malware".into(), ..Default::default() },
        IocSnapshotInput { ioc_value: "8.8.8.8".into(), ioc_type: "ip".into(), source_id: "tor_exit_nodes".into(),
            threat_type: "tor".into(), ..Default::default() },
    ], BTreeMap::from([("ipinfo_lite".into(), 1), ("threatfox".into(), 2), ("tor_exit_nodes".into(), 2)])).unwrap();
    let now = chrono::Utc::now();
    let grant = |feed_revision| PlatformGrant { feed_revision, valid_until: now + chrono::Duration::minutes(5), premium: None };
    let mut policy = TenantPlatformPolicy {
        tenant_id: TENANT.parse().unwrap(), revision: 1, bundle_sha256: digest.clone(),
        grants: BTreeMap::from([("ipinfo_lite".into(), grant(1)), ("threatfox".into(), grant(2)), ("tor_exit_nodes".into(), grant(2))]),
    };
    let policy_path = fx.root.join("policy.json");
    std::fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let signing_key = fx.root.join("signing-key.hex");
    std::fs::write(&signing_key, hex::encode([11; 32])).unwrap();
    fx.spool.deliver(&notice(key, event_time_s)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_lake_part_ingest"))
        .args(["run", "--tenant-id", TENANT, "--signer-key-id", SIGNER_KEY_ID,
            "--signing-key-file", signing_key.to_str().unwrap(),
            "--parts-dir", fx.root.join("parts").to_str().unwrap(),
            "--sources-dir", fx.root.join("sources").to_str().unwrap(),
            "--spool-dir", fx.root.join("spool").to_str().unwrap(),
            "--work-dir", fx.root.join("work").to_str().unwrap(),
            "--platform-bundle-file", bundle_path.to_str().unwrap(),
            "--platform-policy-file", policy_path.to_str().unwrap(),
            "--tick-ms", "100", "--flush-ms", "1000", "--exit-when-idle"])
        .output().unwrap();
    assert!(output.status.success(), "ingest exit: {}", String::from_utf8_lossy(&output.stderr));
    // Revoke every grant: stamps already written must still be served.
    policy.revision += 1;
    policy.grants.clear();
    std::fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();

    // The query[T] bootstrap document (lab form: local parts, no R2).
    let state = tempfile::tempdir().unwrap();
    let bootstrap: QueryBootstrap = serde_json::from_value(json!({
        "format": "nano.query-bootstrap.v1", "tenant_id": TENANT, "bucket": "nan4168-service",
        "trusted_signer_keys": [{"key_id": SIGNER_KEY_ID,
            "public_key_hex": hex::encode(self::key().verifying_key().to_bytes())}],
        "engine": {
            "chdb_library": std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            "chdb_sha256": std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
            "compiler": std::env::var("NANO_LAKE_COMPILER").unwrap(),
            "cache_bytes": 256u64 << 20, "cache_query_bytes": 128u64 << 20, "prewarm_hours": 24,
        },
    })).unwrap();
    let options = OpenOptions {
        bootstrap, r2: None, parts_dir: Some(fx.root.join("parts")), state_dir: state.path().to_path_buf(),
        memory_cap_bytes: 4 << 30, size_classes: true, cpu_millis: 2000,
    };
    let (engine, gate) = open_engine(&options).await.unwrap();
    let service = QueryService::new(engine, gate, state.path().to_path_buf(), "compiler".into(),
        options.bootstrap.engine.chdb_sha256.clone(), None, options.bootstrap.engine.prewarm_hours, None);
    // The query role's default (no readiness-gating prewarm).
    service.clone().start_ready_with_background_prewarm();

    let call = |method: &'static str, uri: &'static str, body: Option<Value>| {
        let service = service.clone();
        async move {
            let (client, server) = tokio::net::UnixStream::pair().unwrap();
            tokio::spawn(service.serve_stream(server));
            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
            tokio::spawn(connection);
            let request = hyper::Request::builder().method(method).uri(uri)
                .header("host", "cell").header("content-type", "application/json")
                .body(Full::new(Bytes::from(body.map_or_else(String::new, |b| b.to_string())))).unwrap();
            let response = sender.send_request(request).await.unwrap();
            let status = response.status().as_u16();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null))
        }
    };
    let deadline = Instant::now() + Duration::from_secs(120);
    let search = |query: &str| json!({
        "route": "broad_npl", "request_id": uuid::Uuid::new_v4().to_string(), "tenant_id": TENANT,
        "dataset": "logs", "query": query,
        "start": chrono::DateTime::from_timestamp(event_time_s - 7 * 86_400, 0).unwrap().to_rfc3339(),
        "end": chrono::DateTime::from_timestamp(event_time_s + 300, 0).unwrap().to_rfc3339(),
        "limit": 10, "table_view": false,
    });
    let (status, rows) = loop {
        let (status, body) = call("POST", "/v1/query", Some(search(
            "* | table src_endpoint.ip, dst_endpoint.ip, src_endpoint.location.country, src_endpoint.autonomous_system.number, enrichments.provider, enrichments.data.feed_revision_id"))).await;
        if status == 200 || Instant::now() > deadline { break (status, body); }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert_eq!(status, 200, "{rows}");
    let row = &rows["result"]["rows"][0];
    assert_eq!(row["src_endpoint.ip"], "8.8.8.8", "{rows}");
    assert_eq!(row["dst_endpoint.ip"], "9.9.9.9", "{rows}");
    assert_eq!(row["src_endpoint.location.country"], "US", "{rows}");
    assert_eq!(row["src_endpoint.autonomous_system.number"], 64500, "{rows}");
    let providers = row["enrichments.provider"].to_string();
    for provider in ["platform/ipinfo_lite", "platform/threatfox", "platform/tor_exit_nodes"] {
        assert!(providers.contains(provider), "{provider}: {rows}");
    }
    let (status, stats) = call("POST", "/v1/query", Some(search("* | stats count by src_endpoint.location.country"))).await;
    assert_eq!(status, 200, "{stats}");
    assert_eq!(stats["result"]["rows"][0]["src_endpoint.location.country"], "US", "{stats}");
    assert_eq!(stats["result"]["rows"][0]["count"], 1, "{stats}");
}
