// SPDX-License-Identifier: AGPL-3.0-or-later
//! Opt-in, seeded production-component CPU profile. No service credentials or PG.
use crate::bronze::{admit_bronze_files, precheck_source_row};
use crate::landing::{convert_file, FileFormat, LandingSource};
use crate::part_ingest::{
    dedup::{Seen, UidWindow},
    merge::{merge_parts, MergeInput},
    prevalence::{EntryRef, IngestPrevalence},
    schema::{decode, infer_schema},
    writer::{sort_by_time_uid, PartDraft, PartWriter, PartialSource},
};
use crate::parts::{
    format::schema_fingerprint,
    levels::Level,
    provenance::{Admission, PartInputs, SourceObject, ADMISSION_CONTRACT},
    DedupPolicy, DedupWindow,
};
use nanosiem_core::parsers::landing_ocsf::LandingOcsfStage;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
        Arc,
    },
    time::Instant,
};

const TENANT: &str = "48310000-0000-4000-8000-000000000001";
const START: i64 = 1_791_936_000_000;
static ENABLED: AtomicBool = AtomicBool::new(false);
static VALIDATION_NS: AtomicU64 = AtomicU64::new(0);
static PARQUET_NS: AtomicU64 = AtomicU64::new(0);
static JSON_NS: AtomicU64 = AtomicU64::new(0);
static IDENTITY_NS: AtomicU64 = AtomicU64::new(0);
static DEDUP_NS: AtomicU64 = AtomicU64::new(0);
static RESTAMP_NS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn scope(counter: &'static str) -> Scope {
    Scope {
        counter,
        started: ThreadCpu::start(),
    }
}
pub(crate) struct Scope {
    counter: &'static str,
    started: ThreadCpu,
}
impl Drop for Scope {
    fn drop(&mut self) {
        let ns = ThreadCpu(self.started.0).elapsed();
        if ns == 0 {
            return;
        }
        match self.counter {
            "json" => &JSON_NS,
            "identity" => &IDENTITY_NS,
            "dedup" => &DEDUP_NS,
            "restamp" => &RESTAMP_NS,
            _ => &PARQUET_NS,
        }
        .fetch_add(ns, Relaxed);
    }
}
pub(crate) fn timed_reader<I: Iterator>(inner: I) -> impl Iterator<Item = I::Item> {
    struct Reader<I>(I);
    impl<I: Iterator> Iterator for Reader<I> {
        type Item = I::Item;
        fn next(&mut self) -> Option<Self::Item> {
            let _scope = scope("parquet");
            self.0.next()
        }
    }
    Reader(inner)
}
fn subcounters() -> [u64; 5] {
    [
        VALIDATION_NS.load(Relaxed),
        PARQUET_NS.load(Relaxed),
        JSON_NS.load(Relaxed),
        IDENTITY_NS.load(Relaxed),
        DEDUP_NS.load(Relaxed),
    ]
}
fn record_subsets(totals: &mut BTreeMap<String, f64>, stage: &str, before: [u64; 5]) {
    for ((label, now), old) in [
        "validation",
        "parquet_decode",
        "json_decode",
        "source_identity",
        "dedup",
    ]
    .iter()
    .zip(subcounters())
    .zip(before)
    {
        *totals.entry(format!("{stage}_{label}_subset")).or_default() += (now - old) as f64 / 1e9;
    }
}

pub(crate) struct ThreadCpu(u64);
impl ThreadCpu {
    pub(crate) fn start() -> Self {
        if !ENABLED.load(Relaxed) {
            return Self(0);
        }
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: a valid writable timespec; this clock measures only the caller.
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t) },
            0
        );
        Self(t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64)
    }
    pub(crate) fn elapsed(self) -> u64 {
        if self.0 == 0 {
            0
        } else {
            Self::start().0 - self.0
        }
    }
}
pub(crate) fn record_validation(ns: u64) {
    if ns > 0 {
        VALIDATION_NS.fetch_add(ns, Relaxed);
    }
}
fn cpu() -> f64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid writable timespec; process CPU includes every worker thread.
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut t) },
        0
    );
    t.tv_sec as f64 + t.tv_nsec as f64 / 1e9
}
fn measure<T>(totals: &mut BTreeMap<String, f64>, label: &str, work: impl FnOnce() -> T) -> T {
    let start = cpu();
    let result = work();
    *totals.entry(label.into()).or_default() += cpu() - start;
    result
}

/// Fixed seed and the six-class percentage mix in agent-query/gen_ocsf.py.
fn event(i: usize) -> Value {
    let host = (i.wrapping_mul(7919).wrapping_add(4831)) % 1000;
    let raw = format!(
        "seed=4831 host={host} sequence={i} payload={}",
        "0123456789abcdef".repeat(48)
    );
    let mut e = json!({"time": START + i as i64 / 10, "activity_id":1,"severity_id":1,
        "metadata":{"uid":format!("nan4831-{i}"),"version":"1.9.0","product":{"name":"fixture","vendor_name":"nano"}},
        "raw_data":raw,"message":format!("event {i} on host-{host:04}")});
    match i % 100 {
        0..=29 => {
            e["class_uid"] = json!(1007);
            e["category_uid"] = json!(1);
            e["type_uid"] = json!(100701);
            e["device"] = json!({"hostname":format!("host-{host:04}"),"type_id":0});
            e["actor"] = json!({"process":{"pid":900,"name":"explorer.exe"}});
            e["process"] =
                json!({"pid":i%65000,"name":"cmd.exe","cmd_line":format!("cmd.exe /c echo {i}")});
        }
        75..=84 => {
            e["class_uid"] = json!(3002);
            e["category_uid"] = json!(3);
            e["type_uid"] = json!(300201);
            e["user"] = json!({"name":format!("user{}",i%97)});
            e["dst_endpoint"] = json!({"hostname":"dc.fixture","ip":"10.0.0.10"});
            e["src_endpoint"] = json!({"hostname":format!("host-{host:04}"),"ip":format!("10.0.{}.{}",host/250,host%250)});
        }
        30..=59 => {
            e["class_uid"] = json!(4001);
            e["category_uid"] = json!(4);
            e["type_uid"] = json!(400101);
            e["src_endpoint"] = json!({"hostname":format!("host-{host:04}"),"ip":format!("10.0.{}.{}",host/250,host%250)});
            e["dst_endpoint"] = json!({"ip":"192.0.2.1","port":443});
        }
        60..=74 => {
            e["class_uid"] = json!(4003);
            e["category_uid"] = json!(4);
            e["type_uid"] = json!(400301);
            e["src_endpoint"] = json!({"hostname":format!("host-{host:04}"),"ip":"10.0.0.1"});
            e["dst_endpoint"] = json!({"ip":"10.0.0.53","port":53});
            e["query"] = json!({"hostname":format!("d{}.example",i%4096),"type":"A","class":"IN"});
        }
        85..=92 => {
            e["class_uid"] = json!(1001);
            e["category_uid"] = json!(1);
            e["type_uid"] = json!(100101);
            e["device"] = json!({"hostname":format!("host-{host:04}"),"type_id":0});
            e["actor"] = json!({"user":{"name":"fixture"}});
            e["file"] = json!({"name":"fixture.exe","type_id":1,"hashes":[{"algorithm_id":3,"value":format!("{:064x}",i%4096)}]});
        }
        _ => {
            e["class_uid"] = json!(4002);
            e["category_uid"] = json!(4);
            e["activity_id"] = json!(3);
            e["type_uid"] = json!(400203);
            e["src_endpoint"] = json!({"hostname":format!("host-{host:04}"),"ip":"10.0.0.1"});
            e["dst_endpoint"] = json!({"ip":"192.0.2.1","port":443});
            e["http_request"] = json!({"http_method":"GET","url":{"hostname":"fixture.example","path":"/","scheme":"https"}});
            e["http_response"] = json!({"code":200});
        }
    }
    e
}

pub(crate) fn reference_precheck(
    event: Value,
    tenant_id: &str,
) -> Result<(), crate::bronze::RowRefusal> {
    // Exact pre-PR implementation, including the discarded identity encode.
    let check = || -> anyhow::Result<()> {
        nanosiem_core::platform_enrichment::reject_producer_provenance(&event)?;
        let uid = event
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty() && v.len() <= 4096)
            .ok_or_else(|| anyhow::anyhow!("Vector bronze event has no bounded metadata.uid"))?
            .to_owned();
        crate::bronze::source_identity_digest(&event)?;
        let row = crate::iceberg::EventRow {
            event_uid: uid,
            event_kind: crate::iceberg::EventKind::Source,
            ocsf_event: event.clone(),
        };
        crate::iceberg::normalize_event(&row, tenant_id).map(|_| ())
    };
    check().map_err(|e| crate::bronze::classify_row_refusal(&e))
}

#[test]
fn nan4831_precheck_keeps_fail_closed_refusals() {
    let stage = LandingOcsfStage::new(1).unwrap();
    let source = LandingSource {
        source_id: uuid::Uuid::from_u128(4831),
        credential_id: uuid::Uuid::from_u128(4832),
        route_key: "fixture".into(),
        active: true,
    };
    for class in [0, 30, 60, 75, 85, 93] {
        let bytes = serde_json::to_vec(&event(class)).unwrap();
        let converted = convert_file(
            &bytes,
            FileFormat::Ndjson { gzip: false },
            &stage,
            TENANT,
            &source,
            chrono::DateTime::from_timestamp_millis(START + 3_600_000).unwrap(),
        )
        .unwrap();
        let good = crate::landing::decode_bronze(&converted.objects[0].1)
            .unwrap()
            .remove(0)
            .unwrap();
        assert!(precheck_source_row(good.clone(), TENANT).is_ok());
        for case in 0..17 {
            let mut bad = good.clone();
            match case {
                0 => bad["metadata"]["uid"] = json!(""),
                1 => bad["metadata"]["uid"] = json!("x".repeat(4097)),
                2 => bad["metadata"]["uid"] = json!("bad\nuid"),
                3 => bad["metadata"]["tenant_uid"] = json!("foreign"),
                4 => bad["metadata"]["version"] = json!("0.0.0"),
                5 => bad["metadata"]["log_source"] = json!(""),
                6 => bad["raw_data"] = json!(""),
                7 => bad["raw_data_size"] = json!(999_999),
                8 => bad["time"] = json!(-1),
                9 => bad["time"] = json!("bad time"),
                10 => bad["class_uid"] = json!(999_999),
                11 => bad["severity_id"] = json!(999_999),
                12 => bad["metadata"] = Value::Null,
                13 => bad = Value::Null,
                14 => bad["class_uid"] = json!("1007"),
                15 => bad["unmapped"] = json!({"nested":[{"provider":"platform/forged"}]}),
                _ => bad["unmapped"] = json!({"feed_revision_id":"forged"}),
            }
            let reference = reference_precheck(bad.clone(), TENANT);
            assert!(
                reference.is_err(),
                "class {class} case {case} must be refused"
            );
            assert_eq!(precheck_source_row(bad.clone(), TENANT), reference);
            // Serialize the invalid row as an untrusted bronze object and
            // prove the production admission gate still refuses it.
            if let Some(time) = bad.get("time").and_then(Value::as_i64).filter(|n| *n > 0) {
                let bronze = nanosiem_core::parsers::landing_ocsf::BronzeRow {
                    event_json: serde_json::to_string(&bad).unwrap(),
                    time_micros: time * 1000,
                    partition: String::new(),
                    uid: "fixture".into(),
                };
                let bytes = crate::landing::encode_bronze(&[&bronze]).unwrap();
                let temp = tempfile::tempdir().unwrap();
                let path = temp.path().join("untrusted.parquet");
                std::fs::write(&path, bytes).unwrap();
                assert!(
                    admit_bronze_files(&[path], TENANT).is_err(),
                    "class {class} case {case}"
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "farm-only CPU profile: 9M rows, optimized test build"]
async fn nan4831_mythos_profile() {
    profile(900, 10_000).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "farm-only profile smoke; changes global diagnostic index settings"]
async fn nan4831_profile_smoke() {
    profile(2, 100).await;
}

async fn profile(chunks: usize, rows_per_chunk: usize) {
    let root = tempfile::tempdir().unwrap();
    let stage = LandingOcsfStage::new(1).unwrap();
    let source = LandingSource {
        source_id: uuid::Uuid::from_u128(4831),
        credential_id: uuid::Uuid::from_u128(4832),
        route_key: "mythos_fixture".into(),
        active: true,
    };
    let mut totals = BTreeMap::<String, f64>::new();
    let store = crate::parts::part_log::LocalObjectStore::new(root.path().join("objects")).unwrap();
    let signer = crate::parts::provenance::LocalPartSigner::new(
        "nan4831-fixture",
        ed25519_dalek::SigningKey::from_bytes(&[48; 32]),
    )
    .unwrap();
    let mut artifacts = std::collections::BTreeSet::new();
    crate::parts::block_index::set_enabled(true);
    crate::parts::token_counts::set_enabled(true);
    crate::identity_observations::set_enabled(true);
    let mut minutes = Vec::new();
    let mut l0 = Vec::new();
    let mut window = UidWindow::new(TENANT, DedupPolicy::default());
    let mut prevalence = IngestPrevalence::open(TENANT, root.path(), None)
        .await
        .unwrap();
    prevalence.initialize_at(0, &"0".repeat(64)).await.unwrap();
    let mut schema: Option<arrow_schema::SchemaRef> = None;
    let mut fingerprints = None;
    let mut admitted_total = 0;
    let mut hour = 0;
    let mut baseline_precheck = 0.0;
    let mut candidate_precheck = 0.0;
    let mut baseline_landing = 0.0;
    let mut candidate_landing = 0.0;
    let mut paired_trials = Vec::new();
    ENABLED.store(true, Relaxed);
    let wall = Instant::now();
    let all_cpu = cpu();
    let mut generator_cpu = 0.0;
    let mut paired_cpu = 0.0;
    for chunk in 0..chunks {
        // Generator CPU deliberately outside every reported stage.
        let generator_start = cpu();
        let events = (chunk * rows_per_chunk..(chunk + 1) * rows_per_chunk)
            .map(event)
            .collect::<Vec<_>>();
        let mut bytes = Vec::new();
        for e in &events {
            serde_json::to_writer(&mut bytes, e).unwrap();
            bytes.push(b'\n');
        }
        drop(events);
        generator_cpu += cpu() - generator_start;
        let before = subcounters();
        let converted = measure(&mut totals, "landing", || {
            convert_file(
                &bytes,
                FileFormat::Ndjson { gzip: false },
                &stage,
                TENANT,
                &source,
                chrono::DateTime::from_timestamp_millis(START + 3_600_000).unwrap(),
            )
            .unwrap()
        });
        assert_eq!(
            (converted.rows_accepted, converted.rows_refused),
            (rows_per_chunk as u64, 0),
            "{:?}",
            converted.first_refusal
        );
        record_subsets(&mut totals, "landing", before);
        let mut paths = Vec::new();
        for (n, (_, bytes, _)) in converted.objects.iter().enumerate() {
            let path = root.path().join(format!("bronze-{chunk}-{n}.parquet"));
            std::fs::write(&path, bytes).unwrap();
            paths.push(path);
        }
        let before = subcounters();
        let admitted = measure(&mut totals, "admission", || {
            admit_bronze_files(&paths, TENANT).unwrap()
        });
        record_subsets(&mut totals, "admission", before);
        admitted_total += admitted.batch.len();
        let sources = admitted
            .files
            .iter()
            .map(|f| SourceObject {
                key: f.path.file_name().unwrap().to_str().unwrap().into(),
                version: "1".into(),
                bytes: f.bytes,
                sha256: f.sha256.clone(),
                rows: f.rows,
                edge_sha256: None,
            })
            .collect::<Vec<_>>();
        let mut rows = admitted.batch.into_rows();
        artifacts.extend(crate::part_ingest::prevalence::stamp_artifacts_of(&rows).unwrap());
        // Paired end-to-end precheck comparison on actual landing output,
        // outside pipeline CPU. Alternate order to reduce warm-cache bias.
        if chunk % 150 == 0 {
            let paired_start = cpu();
            ENABLED.store(false, Relaxed);
            let pair_reference_before = baseline_landing;
            let pair_candidate_before = candidate_landing;
            let mut landing_run = |old: bool| {
                let t = cpu();
                let result = crate::landing::convert_landed_with(
                    &bytes,
                    FileFormat::Ndjson { gzip: false },
                    None,
                    &stage,
                    TENANT,
                    &source,
                    chrono::DateTime::from_timestamp_millis(START + 3_600_000).unwrap(),
                    if old {
                        crate::landing::Precheck::LegacyPrecheck
                    } else {
                        crate::landing::Precheck::InMemory
                    },
                )
                .unwrap();
                assert_eq!(
                    (result.rows_accepted, result.rows_refused),
                    (rows_per_chunk as u64, 0)
                );
                drop(result);
                if old {
                    baseline_landing += cpu() - t;
                } else {
                    candidate_landing += cpu() - t;
                }
            };
            landing_run((chunk / 150) % 2 == 0);
            landing_run((chunk / 150) % 2 != 0);
            paired_trials.push(json!({"chunk":chunk,"rows":rows_per_chunk,"reference_cpu_s":baseline_landing-pair_reference_before,"candidate_cpu_s":candidate_landing-pair_candidate_before}));
            let mut run = |old: bool| {
                let t = cpu();
                for r in &rows {
                    let mut e = r.ocsf_event.clone();
                    e["time"] = json!(START);
                    if old {
                        reference_precheck(e, TENANT).unwrap();
                    } else {
                        precheck_source_row(e, TENANT).unwrap();
                    }
                }
                if old {
                    baseline_precheck += cpu() - t;
                } else {
                    candidate_precheck += cpu() - t;
                }
            };
            run((chunk / 150) % 2 == 0);
            run((chunk / 150) % 2 != 0);
            ENABLED.store(true, Relaxed);
            paired_cpu += cpu() - paired_start;
        }
        measure(&mut totals, "dedupe_window", || {
            for row in &rows {
                hour = (crate::iceberg::ocsf_time_millis(row.ocsf_event.get("time")).unwrap()
                    / 3_600_000) as i32;
                assert_eq!(window.observe(hour, &row.event_uid, 1, START), Seen::New);
            }
        });
        let t = cpu();
        prevalence
            .stamp_all(rows.iter_mut().map(|r| &mut r.ocsf_event))
            .await
            .unwrap();
        *totals.entry("prevalence_stamp".into()).or_default() += cpu() - t;
        let refs = rows.iter().map(|r| &r.ocsf_event).collect::<Vec<_>>();
        let batch = measure(&mut totals, "l0_shape_decode", || {
            let proposed = Arc::new(infer_schema(&refs).unwrap());
            let merged = match &schema {
                Some(previous) => crate::part_ingest::schema::additive_merge(previous, &proposed)
                    .unwrap()
                    .map(Arc::new)
                    .unwrap_or_else(|| previous.clone()),
                None => proposed,
            };
            schema = Some(merged.clone());
            fingerprints = Some(schema_fingerprint(&merged).unwrap());
            sort_by_time_uid(&decode(merged, &refs).unwrap()).unwrap()
        });
        let part = measure(&mut totals, "l0_encode_sidecars", || {
            let draft = PartDraft {
                tenant_id: TENANT.into(),
                signer_key_id: "nan4831-fixture".into(),
                level: Level::L0,
                event_hour: hour,
                schema: schema.clone().unwrap(),
                schema_fingerprint: fingerprints.clone().unwrap(),
                inputs: PartInputs::Sources {
                    sources,
                    edge_log: None,
                },
                admission: Some(Admission {
                    ocsf_version: "1.9.0".into(),
                    admission_contract: ADMISSION_CONTRACT.into(),
                    feed_pins: Default::default(),
                }),
                rows_in: rows_per_chunk as u64,
                duplicates_dropped: 0,
                window: DedupWindow::Exact,
                build: "cpu-profile".into(),
            };
            let mut writer = PartWriter::create(
                root.path(),
                draft,
                PartialSource::FromRows,
                START + chunk as i64,
                rows_per_chunk as u64,
            )
            .unwrap();
            writer.write(&batch).unwrap();
            writer.finish().unwrap()
        });
        let t = cpu();
        let published = crate::part_ingest::writer::publish_parts(
            &store,
            &signer,
            &signer.trusted(),
            std::slice::from_ref(&part),
        )
        .await
        .unwrap();
        *totals.entry("sign_publish".into()).or_default() += cpu() - t;
        let t = cpu();
        let entry_hash = format!("{chunk:064x}");
        let entry = EntryRef {
            seq: chunk as u64 + 1,
            sha256: &entry_hash,
            rebuild: false,
            parts: 1,
        };
        prevalence
            .apply_part(
                TENANT,
                &entry,
                0,
                part.record.part_id.as_str(),
                &part.dir.join(
                    &part
                        .record
                        .files
                        .partials
                        .iter()
                        .find(|p| p.kind == crate::parts::provenance::PartialKind::Prevalence)
                        .unwrap()
                        .name,
                ),
                part.record.max_time_us,
            )
            .await
            .unwrap();
        *totals.entry("prevalence_apply".into()).or_default() += cpu() - t;
        l0.push(MergeInput {
            part: published.into_iter().next().unwrap(),
            dir: part.dir.clone(),
        });
        for p in paths {
            std::fs::remove_file(p).unwrap();
        }
        if (chunk + 1) % 60 == 0 || chunk + 1 == chunks {
            let minute = measure(&mut totals, "minute_merge", || {
                merge_parts(
                    root.path(),
                    TENANT,
                    Level::Minute,
                    hour,
                    &l0,
                    schema.clone().unwrap(),
                    fingerprints.as_ref().unwrap(),
                    "nan4831-fixture",
                    "cpu-profile",
                    START + 10_000 + chunk as i64,
                )
                .unwrap()
                .finished
            });
            let t = cpu();
            let published = crate::part_ingest::writer::publish_parts(
                &store,
                &signer,
                &signer.trusted(),
                std::slice::from_ref(&minute),
            )
            .await
            .unwrap();
            *totals.entry("sign_publish".into()).or_default() += cpu() - t;
            for p in l0.drain(..) {
                std::fs::remove_dir_all(p.dir).unwrap();
            }
            minutes.push(MergeInput {
                part: published.into_iter().next().unwrap(),
                dir: minute.dir.clone(),
            });
            eprintln!(
                "NAN4831 progress rows={admitted_total} wall_s={:.1}",
                wall.elapsed().as_secs_f64()
            );
        }
    }
    let t = cpu();
    let scalars = prevalence
        .lookup()
        .observe(artifacts)
        .await
        .unwrap()
        .scalars();
    *totals
        .entry("prevalence_restamp_lookup".into())
        .or_default() += cpu() - t;
    let restamp = Arc::new(crate::part_ingest::restamp::RestampMap::new(scalars));
    let restamp_before = RESTAMP_NS.load(Relaxed);
    let hour_part = measure(&mut totals, "hour_merge", || {
        crate::part_ingest::restamp::with_restamp(Some(restamp.clone()), || {
            merge_parts(
                root.path(),
                TENANT,
                Level::Hour,
                hour,
                &minutes,
                schema.unwrap(),
                fingerprints.as_ref().unwrap(),
                "nan4831-fixture",
                "cpu-profile",
                START + 100_000,
            )
            .unwrap()
            .finished
        })
    });
    *totals.entry("hour_restamp_subset".into()).or_default() +=
        (RESTAMP_NS.load(Relaxed) - restamp_before) as f64 / 1e9;
    let t = cpu();
    crate::part_ingest::writer::publish_parts(
        &store,
        &signer,
        &signer.trusted(),
        std::slice::from_ref(&hour_part),
    )
    .await
    .unwrap();
    *totals.entry("sign_publish".into()).or_default() += cpu() - t;
    assert_eq!(hour_part.record.rows, admitted_total as u64);
    let t = cpu();
    prevalence.close().await.unwrap();
    *totals.entry("prevalence_close".into()).or_default() += cpu() - t;
    let net_cpu = cpu() - all_cpu - generator_cpu - paired_cpu;
    let accounted = totals
        .iter()
        .filter(|(k, _)| !k.ends_with("_subset"))
        .map(|(_, v)| v)
        .sum::<f64>();
    totals.insert("pipeline_other".into(), (net_cpu - accounted).max(0.0));
    ENABLED.store(false, Relaxed);
    println!(
        "NAN4831_RESULT {}",
        json!({"rows":admitted_total,"hosts":1000,"seed":4831,"virtual_rate_eps":10000,"chunks":chunks,"rows_per_chunk":rows_per_chunk,"wall_s":wall.elapsed().as_secs_f64(),"cpu_s":totals,
        "paired_rows":chunks.div_ceil(150)*rows_per_chunk,"precheck_reference_cpu_s":baseline_precheck,"precheck_candidate_cpu_s":candidate_precheck,"landing_reference_cpu_s":baseline_landing,"landing_candidate_cpu_s":candidate_landing,"paired_trials":paired_trials,
        "limitations":"component harness; no offered-rate pacing, network, owner RPC, platform stamping or cold state; validation subsets overlap stage totals"})
    );
}
