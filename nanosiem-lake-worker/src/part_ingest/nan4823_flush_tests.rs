// SPDX-License-Identifier: AGPL-3.0-or-later

//! Catch-up bench using the same real bronze/spool/part-store harness as
//! NAN-4770, with production sizing and default flush/admission policy.
use super::nan4749_ingest_tests::{event, Lab, CLOCK, TENANT};
use super::*;
use std::time::Instant;

// Explicit farm-only entry point: run the test executable in two actual
// cgroup boundaries. Never silently replace a cgroup run with model inputs.
#[test]
#[ignore = "farm only: needs sudo systemd-run and cgroup v2"]
fn nan4823_catchup_bench() {
    let mut maxima = Vec::new();
    let mut wide_maxima = Vec::new();
    for (cap, case, cores) in [
        (2_090_000_000_u64, "nan4823_mythos", 4),
        (3_413_114_880, "nan4823_fp", 4),
        (32 * 1024 * 1024 * 1024, "nan4823_large", 16),
    ] {
        let output = std::process::Command::new("sudo")
            .args([
                "-n",
                "systemd-run",
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "-p",
                &format!("MemoryMax={cap}"),
                "-p",
                "MemorySwapMax=0",
                "-p",
                &format!("CPUQuota={}%", cores * 100),
            ])
            .arg(std::env::current_exe().unwrap())
            .args([case, "--ignored", "--nocapture", "--test-threads=1"])
            .output()
            .expect("farm cgroup launcher");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprint!("{stdout}{stderr}");
        assert!(
            output.status.success(),
            "{case}: actual cgroup bench failed"
        );
        let text = format!("{stdout}{stderr}");
        let result = text
            .lines()
            .find(|line| line.contains("NAN-4823 result") && line.contains("raw=false:"))
            .unwrap();
        let wide = text
            .lines()
            .find(|line| line.contains("NAN-4823 result") && line.contains("raw=true:"))
            .unwrap();
        wide_maxima.push(
            wide.split("max_rows=")
                .nth(1)
                .unwrap()
                .split(',')
                .next()
                .unwrap()
                .parse::<usize>()
                .unwrap(),
        );
        let wide_seals = text
            .lines()
            .filter(|line| line.contains("NAN-4823 seal") && line.contains("raw=true:"))
            .collect::<Vec<_>>();
        let largest = wide_seals
            .iter()
            .max_by_key(|line| {
                line.split("rows=")
                    .nth(1)
                    .unwrap()
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .parse::<usize>()
                    .unwrap()
            })
            .unwrap();
        let writers = largest
            .split("writers=")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let required_writers = if cap < 3_000_000_000 {
            2
        } else {
            cores as usize
        };
        assert!(
            writers >= required_writers,
            "a wide full flush lost useful memory-backed writers: required={required_writers} {largest}"
        );
        maxima.push(
            result
                .split("max_rows=")
                .nth(1)
                .unwrap()
                .split(',')
                .next()
                .unwrap()
                .parse::<usize>()
                .unwrap(),
        );
    }
    assert!(
        wide_maxima[1] > wide_maxima[0],
        "wide rows must scale too: {wide_maxima:?}"
    );
    assert!(
        maxima[0] > 65_536,
        "the smaller role still hits the legacy cap"
    );
    assert!(
        maxima[2] > maxima[1],
        "large roles must scale too: {maxima:?}"
    );
    assert!(
        wide_maxima[2] > wide_maxima[1],
        "large wide flushes must scale too: {wide_maxima:?}"
    );
    assert!(
        maxima[1] > maxima[0],
        "more real cgroup memory must buy larger flushes: {maxima:?}"
    );
}

#[test]
#[ignore = "invoked by nan4823_catchup_bench in a real cgroup"]
fn nan4823_mythos() {
    run(2_090_000_000, 4);
}
#[test]
#[ignore = "invoked by nan4823_catchup_bench in a real cgroup"]
fn nan4823_fp() {
    run(3_413_114_880, 4);
}

#[test]
#[ignore = "invoked by nan4823_catchup_bench in a real cgroup"]
fn nan4823_large() {
    run(32 * 1024 * 1024 * 1024, 16);
}

fn run(cap: u64, cores: usize) {
    let cgroup = crate::cgroup_memory::for_process();
    // The kernel rounds memory.max to a page boundary. Size from the
    // boundary actually read back, rather than the requested approximation.
    let actual_cap = cgroup.limit().expect("real finite memory.max").bytes;
    assert!(
        actual_cap.abs_diff(cap) < 4096,
        "requested {cap}, actual {actual_cap}"
    );
    let cap = actual_cap;
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(cores)
        .build_global();
    super::super::memory::tune_allocator();
    crate::parts::block_index::set_enabled(true);
    crate::parts::token_counts::set_enabled(true);
    crate::identity_observations::set_enabled(true);
    for raw in [false, true] {
        let mut lab = Lab::new(cap);
        lab.config.cpu_millis = cores as u32 * 1000;
        lab.config.flush_interval_override_ms = None;
        // Isolate L0 costs; history merge sizing is a separate change.
        lab.config.max_merges_per_tick = 0;
        let make = |i: usize| {
            if raw {
                let mut row = event(i);
                row["time"] =
                    serde_json::json!(chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
                        CLOCK - 120_000 - (i % 120_000) as i64
                    )
                    .unwrap()
                    .to_rfc3339());
                return row;
            }
            serde_json::json!({"time": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(CLOCK - 5_000).unwrap().to_rfc3339(),
                "class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201, "severity_id": 1,
                "metadata": {"uid": format!("nan4823-{i:08}"), "tenant_uid": TENANT, "version": "1.9.0",
                    "log_source": "WINDOWS_EVENT", "product": {"name": "fixture"}},
                "raw_data": "fixture", "raw_data_size": 7,
                "message": "authentication", "user": {"name": "fixture-user"}, "dst_endpoint": {"ip": "192.0.2.1"}})
        };
        let (objects, rows) = (if cores > 4 { 64 } else { 24 }, 10_000);
        for object in 0..objects {
            lab.land(
                &format!("o{object:02}"),
                &(object * rows..(object + 1) * rows)
                    .map(make)
                    .collect::<Vec<_>>(),
                CLOCK - 120_000,
            );
        }
        eprintln!("NAN-4823 fixtures ready cap={cap} raw={raw}: {objects} x {rows} rows");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(cores)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut ingestor = lab.open().await;
            let parts: &'static crate::parts::part_log::LocalObjectStore = Box::leak(Box::new(
                crate::parts::part_log::LocalObjectStore::new(lab.root.join("parts")).unwrap()));
            let signer: &'static crate::parts::provenance::LocalPartSigner = Box::leak(Box::new(
                crate::parts::provenance::LocalPartSigner::new("lab-signer-nan4749", ed25519_dalek::SigningKey::from_bytes(&[47; 32])).unwrap()));
            ingestor.set_background_store(parts);
            ingestor.set_background_signer(signer);
            let sampler = super::super::catchup_bench::RssSampler::start();
            let started = Instant::now();
            let mut seals = Vec::new();

            while ingestor.health().rows_committed_total < (objects * rows) as u64 {
                assert!(started.elapsed().as_secs() < 1200, "catch-up stalled");
                let now = CLOCK + started.elapsed().as_millis() as i64;
                ingestor.tick(now).await.unwrap();
                assert_eq!(ingestor.health().objects_rejected_total, 0, "valid fixture rejected");
                assert_eq!(ingestor.health().objects_quarantined_total, 0, "valid fixture quarantined");
                for flight in &ingestor.flush_in_flight {
                    let entry = (flight.sealed_ms, flight.buffer.rows, flight.buffer.handles.len(), flight.buffer.hours.len(),
                        planned_l0_parts(&flight.buffer, ingestor.flush_parallelism()), flight.writers);
                    if !seals.iter().any(|e: &(i64, usize, usize, usize, usize, usize)| e.0 == entry.0) {
                        eprintln!("NAN-4823 seal cap={cap} raw={raw}: rows={} objects={} hours={} planned_parts={} writers={} bytes={}",
                            entry.1, entry.2, entry.3, entry.4, entry.5, flight.buffer.bytes);
                        seals.push(entry);
                    }
                }
                if ingestor.buffer.rows > 0 && ingestor.flush_in_flight.is_empty() && !ingestor.behind_last_tick {
                    let buffer = &ingestor.buffer;
                    let plan = ingestor.flush_plan(buffer, ingestor.schema.clone(), None, now).unwrap();
                    let entry = (now, buffer.rows, buffer.handles.len(), buffer.hours.len(), planned_l0_parts(buffer, ingestor.flush_parallelism()), plan.writers);
                    let before = ingestor.health().parts_written_total;
                    ingestor.flush_now(now).await.unwrap();
                    let parts = (ingestor.health().parts_written_total - before) as usize;
                    eprintln!("NAN-4823 seal cap={cap} raw={raw}: rows={} objects={} hours={} planned_parts={parts} writers={} bytes=sync",
                        entry.1, entry.2, entry.3, entry.5.min(parts));
                    seals.push((entry.0, entry.1, entry.2, entry.3, parts, entry.5.min(parts)));
                }
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            let health = ingestor.health();
            assert_eq!((health.objects_consumed_total, health.objects_quarantined_total, health.objects_rejected_total), (objects as u64, 0, 0));
            assert_eq!(health.merge_memory_stops_total, 0);
            let peak_used = sampler.guard_peak();
            let peak_rss = sampler.take();
            assert!(peak_used > 0);
            assert!(peak_used < (cap as f64 * super::super::merge_quota::MEMORY_GUARD_SHARE) as u64);
            eprintln!("NAN-4823 result cap={cap} raw={raw}: {:.1} eps, {} parts, {} seals, max_rows={}, peak_guard_used={} peak_rss={}, guard_stops={} quarantine={}",
                (objects * rows) as f64 / started.elapsed().as_secs_f64(), health.parts_written_total, seals.len(),
                seals.iter().map(|e| e.1).max().unwrap_or(0), peak_used, peak_rss, health.merge_memory_stops_total, health.objects_quarantined_total);
        });
    }
}

/// The default live-ingest age policy still produces one data file per
/// ten-second interval at low EPS, independent of the role's memory.
#[tokio::test]
async fn nan4823_low_rate_file_fanout() {
    use crate::parts::part_log::ObjectStore;
    for cap in [2_089_996_288, 3_413_114_880] {
        let mut lab = Lab::new(cap);
        lab.config.flush_interval_override_ms = None;
        lab.config.max_merges_per_tick = 0;
        let mut ingestor = lab.open().await;
        for i in 0..6 {
            let now = CLOCK + i as i64 * 10_000;
            lab.land(&format!("low-{i}"), &[event(i)], now);
            if i == 0 {
                // Cold width sampling continues in this tick. It must not
                // manufacture a high EWMA and shorten the ten-second age.
                lab.land("low-extra", &[event(1_000)], now);
            }
            ingestor.tick(now).await.unwrap();
            assert_eq!(ingestor.health().parts_written_total, i as u64);
            ingestor.tick(now + 9_999).await.unwrap();
            assert_eq!(ingestor.health().parts_written_total, i as u64);
            ingestor.tick(now + 10_000).await.unwrap();
            assert_eq!(ingestor.health().parts_written_total, i as u64 + 1);
        }
        assert_eq!(ingestor.health().rows_committed_total, 7);
        assert_eq!(ingestor.health().objects_quarantined_total, 0);
        let store = crate::parts::part_log::LocalObjectStore::new(lab.root.join("parts")).unwrap();
        let files = store
            .list("")
            .await
            .unwrap()
            .into_iter()
            .filter(|key| key.contains("/data-") && key.ends_with(".parquet"))
            .count();
        assert_eq!(files, 6, "one data file per live part (360 files/hour)");
        assert_eq!(
            ingestor.live_parts().len(),
            6,
            "hour query fanout stays six parts"
        );
    }
}

/// A known encoded size can exhaust preselection's byte bound while the
/// filling buffer is still below its own cap. It must seal immediately,
/// acknowledge only its old object, then admit the new one from idle.
#[tokio::test]
async fn nan4823_known_size_cap_refusal_seals_before_age() {
    for cap in [2_090_000_000, 3_413_114_880] {
        let lab = Lab::new(cap);
        lab.land("first", &[event(0)], CLOCK);
        let mut ingestor = lab.open().await;
        ingestor.tick(CLOCK).await.unwrap();
        assert_eq!(ingestor.health().rows_committed_total, 0);
        assert_eq!(ingestor.buffer.rows, 1);
        let key = "bronze/known.parquet";
        let path = lab.root.join("sources").join(key);
        super::nan4749_ingest_tests::write_bronze(&path, &[event(1)]);
        let bytes = std::fs::metadata(&path).unwrap().len();
        assert!(bytes > 0);
        lab.spool
            .deliver(&super::super::discovery::SourceNotice {
                tenant_id: TENANT.into(),
                key: key.into(),
                version: "1".into(),
                bytes,
                sha256: None,
                edge_sha256: None,
                notified_at_ms: CLOCK + 1,
            })
            .unwrap();
        // A valid learned ratio can overpredict the next object's width.
        // It fits from idle, but not beside the existing filling buffer.
        ingestor.heap_per_source_byte = 1.0;
        let limit = super::super::memory::buffer_cap(lab.config.buffer_budget_bytes);
        ingestor.arrow_per_source_byte =
            (limit as f64 - ingestor.buffer.bytes as f64 / 2.0) / bytes as f64;
        ingestor.tick(CLOCK + 1).await.unwrap();
        assert_eq!(
            ingestor.health().rows_committed_total,
            1,
            "preselection refusal must not wait an hour for age"
        );
        assert_eq!(
            ingestor.health().objects_consumed_total,
            1,
            "only the old object is acknowledged"
        );
        ingestor.tick(CLOCK + 2).await.unwrap();
        ingestor.flush_now(CLOCK + 3).await.unwrap();
        assert_eq!(ingestor.health().rows_committed_total, 2);
        assert_eq!(ingestor.health().objects_consumed_total, 2);
        assert_eq!(ingestor.health().objects_quarantined_total, 0);
        assert_eq!(ingestor.health().rows_rejected_total, 0);
        let actual = super::nan4770_ingest_tests::committed_rows(&ingestor, &lab).await;
        assert_eq!(
            actual.len(),
            2,
            "both source rows are published exactly once"
        );
    }
}

// Reproducible synthetic companion to the repo's OCSF raw-event fixture.
// Four class families: authentication 40%, process 30%, network 20%, DNS 10%.
// Event time advances 100 us/row: 10,000 rows/s for 890 seconds, across two
// event hours. Notice objects contain 10,000 rows (one offered second).
const MYTHOS_SEED: u64 = 0x4823_1014_5eed_0001;
const MYTHOS_ROWS: usize = 8_900_000;
const MYTHOS_OBJECT_ROWS: usize = 10_000;
const MYTHOS_HOSTS: usize = 1_000;

fn splitmix(mut n: u64) -> u64 {
    n = n.wrapping_add(0x9e3779b97f4a7c15);
    n = (n ^ (n >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    n = (n ^ (n >> 27)).wrapping_mul(0x94d049bb133111eb);
    n ^ (n >> 31)
}

struct MythosGenerator {
    bank: RecordBatch,
}

impl MythosGenerator {
    fn new() -> Self {
        let families = [
            (3002, 3, "Authentication", "Identity & Access Management"),
            (1007, 1, "Process Activity", "System Activity"),
            (4001, 4, "Network Activity", "Network Activity"),
            (4003, 4, "DNS Activity", "Network Activity"),
        ];
        let mut templates = Vec::with_capacity(MYTHOS_HOSTS * families.len());
        for host in 0..MYTHOS_HOSTS {
            for (class, category, class_name, category_name) in families {
                let mut row = event(host);
                row["class_uid"] = serde_json::json!(class);
                row["category_uid"] = serde_json::json!(category);
                row["type_uid"] = serde_json::json!(class * 100 + 1);
                row["class_name"] = serde_json::json!(class_name);
                row["category_name"] = serde_json::json!(category_name);
                row["activity_name"] = serde_json::json!("fixture activity");
                row["src_endpoint"]["hostname"] =
                    serde_json::json!(format!("ws-{host:04}.corp.local"));
                row["src_endpoint"]["ip"] =
                    serde_json::json!(format!("10.{}.{}.{}", host / 250, host % 250, 1));
                // Authentication's top-level user and endpoints are not
                // attributes of every OCSF class. Preserve the raw-event
                // payload while supplying each family's actual contract.
                if class != 3002 {
                    row.as_object_mut().unwrap().remove("user");
                }
                if class >= 4000 {
                    // Network actor is gated by the optional host profile.
                    row.as_object_mut().unwrap().remove("actor");
                }
                if class == 1007 {
                    row.as_object_mut().unwrap().remove("src_endpoint");
                    row.as_object_mut().unwrap().remove("dst_endpoint");
                    row["device"] = serde_json::json!({
                        "hostname": format!("ws-{host:04}.corp.local"), "type_id": 0
                    });
                    row["process"] = serde_json::json!({
                        "name": "powershell.exe", "pid": 1000 + host,
                        "cmd_line": format!("powershell.exe -File job-{host}.ps1")
                    });
                }
                if class == 4003 {
                    row["query"] = serde_json::json!({
                        "hostname": format!("service-{}.corp.local", host % 100), "type": "A"
                    });
                }
                // Fail with the exact schema diagnostic before generating
                // millions of rows or running the capped catch-up process.
                if host == 0 {
                    let source = crate::iceberg::EventRow {
                        event_uid: row["metadata"]["uid"].as_str().unwrap().to_owned(),
                        event_kind: crate::iceberg::EventKind::Source,
                        ocsf_event: row.clone(),
                    };
                    crate::iceberg::normalize_event(&source, TENANT)
                        .unwrap_or_else(|error| panic!("fixture class {class}: {error:#}"));
                }
                templates.push(row);
            }
        }
        let refs = templates.iter().collect::<Vec<_>>();
        let schema = Arc::new(super::super::schema::infer_schema(&refs).unwrap());
        Self {
            bank: super::super::schema::decode(schema, &refs).unwrap(),
        }
    }

    /// Generate Arrow directly from the raw-event fixture bank: bounded
    /// scratch per object, no 8.9M-row JSON heap or repeated schema inference.
    fn batch(&self, start: usize, rows: usize) -> RecordBatch {
        use arrow_array::{
            Array, Int64Array, StringArray, StructArray, TimestampMicrosecondArray, UInt32Array,
        };
        let random = (start..start + rows)
            .map(|i| splitmix(MYTHOS_SEED ^ i as u64))
            .collect::<Vec<_>>();
        let indices = UInt32Array::from_iter_values(random.iter().map(|random| {
            let family = match random % 10 {
                0..=3 => 0,
                4..=6 => 1,
                7..=8 => 2,
                _ => 3,
            };
            ((random >> 32) % MYTHOS_HOSTS as u64 * 4 + family) as u32
        }));
        let batch = arrow_select::take::take_record_batch(&self.bank, &indices).unwrap();
        let schema = batch.schema();
        let mut columns = batch.columns().to_vec();
        let meta_index = schema.index_of("metadata").unwrap();
        let meta = batch
            .column(meta_index)
            .as_any()
            .downcast_ref::<StructArray>()
            .unwrap();
        let (fields, mut values, nulls) = meta.clone().into_parts();
        let uid = fields
            .iter()
            .position(|field| field.name() == "uid")
            .unwrap();
        values[uid] = Arc::new(StringArray::from_iter_values(
            (start..start + rows).map(|i| format!("nan4823-{MYTHOS_SEED:016x}-{i:08x}")),
        ));
        columns[meta_index] = Arc::new(StructArray::new(fields, values, nulls));
        let start_us = (CLOCK - 120_000) * 1_000 - MYTHOS_ROWS as i64 * 100;
        columns[schema.index_of("time").unwrap()] = Arc::new(
            TimestampMicrosecondArray::from_iter_values(
                (start..start + rows).map(|i| start_us + i as i64 * 100),
            )
            .with_timezone("+00:00"),
        );
        let raw_index = schema.index_of("raw_data").unwrap();
        let old_raw = batch
            .column(raw_index)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let raw = StringArray::from_iter_values((0..rows).map(|row| {
            format!(
                "{}<!-- event={:08x} nonce={:016x} -->",
                old_raw.value(row),
                start + row,
                random[row]
            )
        }));
        columns[schema.index_of("raw_data_size").unwrap()] = Arc::new(
            Int64Array::from_iter_values((0..rows).map(|row| raw.value(row).len() as i64)),
        );
        columns[raw_index] = Arc::new(raw);
        RecordBatch::try_new(schema, columns).unwrap()
    }

    fn land(&self, lab: &Lab, start: usize, rows: usize) {
        let batch = self.batch(start, rows);
        let key = format!("bronze/seed-{start:08}.parquet");
        let properties = parquet::file::properties::WriterProperties::builder()
            .set_compression(parquet::basic::Compression::ZSTD(
                parquet::basic::ZstdLevel::try_new(3).unwrap(),
            ))
            .build();
        let mut writer = parquet::arrow::ArrowWriter::try_new(
            std::fs::File::create(lab.root.join("sources").join(&key)).unwrap(),
            batch.schema(),
            Some(properties),
        )
        .unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        let object_bytes = std::fs::metadata(lab.root.join("sources").join(&key))
            .unwrap()
            .len();
        lab.spool
            .deliver(&super::super::discovery::SourceNotice {
                tenant_id: TENANT.into(),
                key,
                version: "1".into(),
                bytes: object_bytes,
                sha256: None,
                edge_sha256: None,
                notified_at_ms: CLOCK - 890_000 + start as i64 / 10,
            })
            .unwrap();
    }
}

/// Fast canonical-admission check of every class and the seeded host mix.
#[tokio::test]
async fn nan4823_seeded_fixture_is_canonical() {
    let lab = Lab::new(2_090_000_000);
    let generator = MythosGenerator::new();
    generator.land(&lab, 0, 4_000);
    let mut ingestor = lab.open().await;
    let report = ingestor.tick(CLOCK).await.unwrap();
    assert_eq!(report.admitted_rows, 4_000);
    ingestor.flush_now(CLOCK + 1).await.unwrap();
    let health = ingestor.health();
    assert_eq!(
        (
            health.rows_committed_total,
            health.objects_quarantined_total,
            health.rows_rejected_total
        ),
        (4_000, 0, 0)
    );
    let actual = super::nan4770_ingest_tests::committed_rows(&ingestor, &lab).await;
    assert_eq!(
        actual.len(),
        4_000,
        "published identities are unique and complete"
    );
    let classes = actual
        .values()
        .map(|row| row["class_uid"].as_u64().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(classes, BTreeSet::from([1007, 3002, 4001, 4003]));
    let hosts = actual
        .values()
        .map(|row| {
            row["src_endpoint"]["hostname"]
                .as_str()
                .or_else(|| row["device"]["hostname"].as_str())
                .unwrap()
        })
        .collect::<BTreeSet<_>>();
    assert!(
        hosts.len() > 950,
        "the seed must exercise the thousand-host population"
    );
    let prefix = format!("nan4823-{MYTHOS_SEED:016x}-");
    for (uid, row) in &actual {
        assert!(uid.starts_with(&prefix));
        assert_eq!(
            row["raw_data_size"].as_u64().unwrap(),
            row["raw_data"].as_str().unwrap().len() as u64
        );
    }
}

#[test]
#[ignore = "farm only: 8.9M rows per cap, sudo systemd-run and cgroup v2"]
fn nan4823_seeded_catchup_bench() {
    seeded_cgroups(false);
}

#[test]
#[ignore = "farm only: same-binary legacy-cap control, actual cgroups"]
fn nan4823_seeded_legacy_control() {
    seeded_cgroups(true);
}

fn seeded_cgroups(legacy: bool) {
    // Validate the generator through bronze admission before the long run.
    nan4823_seeded_fixture_is_canonical();
    let cases = if legacy {
        [
            (2_090_000_000_u64, "nan4823_seeded_legacy_mythos"),
            (3_413_114_880, "nan4823_seeded_legacy_fp"),
        ]
    } else {
        [
            (2_090_000_000_u64, "nan4823_seeded_mythos"),
            (3_413_114_880, "nan4823_seeded_fp"),
        ]
    };
    for (cap, case) in cases {
        let temp = std::env::temp_dir();
        let status = std::process::Command::new("sudo")
            .args([
                "-n",
                "systemd-run",
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "-p",
                &format!("MemoryMax={cap}"),
                "-p",
                "MemorySwapMax=0",
                "-p",
                "CPUQuota=400%",
            ])
            .arg(format!("--setenv=TMPDIR={}", temp.display()))
            .arg(std::env::current_exe().unwrap())
            .args([case, "--ignored", "--nocapture", "--test-threads=1"])
            .status()
            .expect("farm cgroup launcher");
        assert!(status.success(), "{case}: actual cgroup bench failed");
    }
}

#[test]
#[ignore = "invoked by nan4823_seeded_catchup_bench in a real cgroup"]
fn nan4823_seeded_mythos() {
    run_seeded(2_090_000_000);
}
#[test]
#[ignore = "invoked by nan4823_seeded_catchup_bench in a real cgroup"]
fn nan4823_seeded_fp() {
    run_seeded(3_413_114_880);
}

#[test]
#[ignore = "invoked by nan4823_seeded_legacy_control in a separate cgroup process"]
fn nan4823_seeded_legacy_mythos() {
    super::super::memory::LEGACY_FLUSH_CAP_FOR_BENCH
        .store(true, std::sync::atomic::Ordering::Relaxed);
    run_seeded(2_090_000_000);
}
#[test]
#[ignore = "invoked by nan4823_seeded_legacy_control in a separate cgroup process"]
fn nan4823_seeded_legacy_fp() {
    super::super::memory::LEGACY_FLUSH_CAP_FOR_BENCH
        .store(true, std::sync::atomic::Ordering::Relaxed);
    run_seeded(3_413_114_880);
}

/// Count actual production signing batches while using the same local
/// cryptographic signer and owner validation as the fixture harness.
struct BenchSigner {
    inner: crate::parts::provenance::LocalPartSigner,
    calls: std::sync::atomic::AtomicU64,
    records: std::sync::atomic::AtomicU64,
}

#[async_trait::async_trait]
impl crate::parts::provenance::PartSigner for BenchSigner {
    fn key_id(&self) -> &str {
        crate::parts::provenance::PartSigner::key_id(&self.inner)
    }

    async fn sign(
        &self,
        tenant: &str,
        records: &[crate::parts::provenance::ProvenanceRecord],
    ) -> anyhow::Result<Vec<crate::parts::provenance::Ed25519Signature>> {
        use std::sync::atomic::Ordering::Relaxed;
        self.calls.fetch_add(1, Relaxed);
        self.records.fetch_add(records.len() as u64, Relaxed);
        crate::parts::provenance::PartSigner::sign(&self.inner, tenant, records).await
    }
}

fn run_seeded(requested: u64) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("nano::ingest::capacity=info")
        .with_ansi(false)
        .without_time()
        .try_init();
    let mode = if super::super::memory::LEGACY_FLUSH_CAP_FOR_BENCH
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        "legacy"
    } else {
        "memory"
    };
    let cgroup = crate::cgroup_memory::for_process();
    let cap = cgroup.limit().expect("real finite memory.max").bytes;
    assert!(cap.abs_diff(requested) < 4096);
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build_global();
    super::super::memory::tune_allocator();
    crate::parts::block_index::set_enabled(true);
    crate::parts::token_counts::set_enabled(true);
    crate::identity_observations::set_enabled(true);
    let generator = MythosGenerator::new();
    let mut lab = Lab::new(cap);
    lab.config.flush_interval_override_ms = None;
    // Measure L0 admission/build/publication independently of the h-merge
    // change (NAN-4818). Production reservation headroom is retained.
    lab.config.max_merges_per_tick = 0;
    let generated = Instant::now();
    for start in (0..MYTHOS_ROWS).step_by(MYTHOS_OBJECT_ROWS) {
        generator.land(&lab, start, MYTHOS_OBJECT_ROWS.min(MYTHOS_ROWS - start));
    }
    drop(generator);
    super::super::memory::release_freed();
    eprintln!("NAN-4823 seeded fixtures: mode={mode} seed={MYTHOS_SEED:#x} cap={cap} rows={MYTHOS_ROWS} objects={} hosts={MYTHOS_HOSTS} offered_eps=10000 setup_seconds={:.1}",
        MYTHOS_ROWS.div_ceil(MYTHOS_OBJECT_ROWS), generated.elapsed().as_secs_f64());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut ingestor = lab.open().await;
        let parts: &'static crate::parts::part_log::LocalObjectStore = Box::leak(Box::new(
            crate::parts::part_log::LocalObjectStore::new(lab.root.join("parts")).unwrap()));
        let signer: &'static BenchSigner = Box::leak(Box::new(BenchSigner {
            inner: crate::parts::provenance::LocalPartSigner::new("lab-signer-nan4749", ed25519_dalek::SigningKey::from_bytes(&[47; 32])).unwrap(),
            calls: Default::default(), records: Default::default(),
        }));
        ingestor.signer = signer;
        ingestor.set_background_store(parts);
        ingestor.set_background_signer(signer);
        let sampler = super::super::catchup_bench::RssSampler::start();
        let base_guard = super::super::merge_lanes::cgroup_memory().map(|entry| entry.0).unwrap_or(0);
        eprintln!("NAN-4823 baseline cap={cap} rss={} guard={base_guard} working={} uid_reserve={} base_reserve={}",
            sampler.take(), ingestor.working_budget(), ingestor.cfg.max_window_uids as u64 * super::super::dedup::WINDOW_BYTES_PER_UID,
            nanosiem_lake_cell::ingest_memory::process_base_reserve(cap));
        let started = Instant::now();
        let mut seals = BTreeSet::new();
        let mut max_rows = 0;
        let mut max_objects = 0;
        let mut completed = Vec::new();
        let mut max_hours = 0;
        let mut last_progress = 0;
        while ingestor.health().rows_committed_total < MYTHOS_ROWS as u64 {
            assert!(started.elapsed().as_secs() < 7200, "catch-up stalled");
            let now = CLOCK + started.elapsed().as_millis() as i64;
            ingestor.tick(now).await.unwrap();
            let health = ingestor.health();
            assert_eq!((health.objects_rejected_total, health.objects_quarantined_total, health.rows_rejected_total), (0, 0, 0));
            for flight in &ingestor.flush_in_flight {
                if seals.insert(flight.sealed_ms) {
                    max_rows = max_rows.max(flight.buffer.rows);
                    max_objects = max_objects.max(flight.buffer.handles.len());
                    let slots = flight.writers;
                    completed.push((flight.progress.clone(), slots));
                    max_hours = max_hours.max(flight.buffer.hours.len());
                }
            }
            if health.rows_committed_total / 1_000_000 > last_progress {
                last_progress = health.rows_committed_total / 1_000_000;
                eprintln!("NAN-4823 seeded progress cap={cap}: rows={} seconds={:.1} parts={} guard_peak={}",
                    health.rows_committed_total, started.elapsed().as_secs_f64(), health.parts_written_total, sampler.guard_peak());
            }
            if ingestor.buffer.rows > 0 && ingestor.flush_in_flight.is_empty() && !ingestor.behind_last_tick {
                ingestor.flush_now(now).await.unwrap();
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        let health = ingestor.health();
        assert_eq!(health.objects_consumed_total, MYTHOS_ROWS.div_ceil(MYTHOS_OBJECT_ROWS) as u64);
        assert_eq!(health.merge_memory_stops_total, 0);
        let peak_used = sampler.guard_peak();
        let elapsed = started.elapsed().as_secs_f64();
        let peak_rss = sampler.take();
        let counts = completed.iter().map(|(progress, slots)| {
            let parts = progress.lock().unwrap().built_part_count().expect("completed flush built parts");
            (parts, (*slots).min(parts))
        }).collect::<Vec<_>>();
        let max_parts = counts.iter().map(|entry| entry.0).max().unwrap_or(0);
        let max_writers = counts.iter().map(|entry| entry.1).max().unwrap_or(0);
        if mode == "memory" {
            let (rows, writers) = if cap < 3_000_000_000 { (50_000, 2) } else { (120_000, 4) };
            assert!(max_rows >= rows, "seeded flush cap misses role acceptance: cap={cap} rows={max_rows}");
            assert!(max_writers >= writers, "seeded flush lost useful writers: cap={cap} writers={max_writers}");
        }
        use crate::parts::part_log::ObjectStore;
        let files = parts.list("").await.unwrap();
        let l0_files = files.iter().filter(|key| key.contains("/parts/l0/")).count();
        let data_files = files.iter().filter(|key| key.contains("/parts/l0/") && key.contains("/data-") && key.ends_with(".parquet")).count();
        use std::sync::atomic::Ordering::Relaxed;
        assert_eq!(signer.records.load(Relaxed), health.parts_written_total);
        eprintln!("NAN-4823 publication mode={mode} cap={cap}: signer_calls={} signed_records={} l0_files={l0_files} data_files={data_files}",
            signer.calls.load(Relaxed), signer.records.load(Relaxed));
        eprintln!("NAN-4823 seeded result mode={mode} seed={MYTHOS_SEED:#x} cap={cap} rows={} seconds={:.3} eps={:.1} total_parts={} sampled_flushes={} max_rows={max_rows} max_objects={max_objects} max_parts={max_parts} max_hours={max_hours} max_writers={max_writers} peak_guard_used={peak_used} peak_rss={} guard_stops={} quarantine={}",
            health.rows_committed_total, elapsed, MYTHOS_ROWS as f64 / elapsed,
            health.parts_written_total, seals.len(), peak_rss, health.merge_memory_stops_total, health.objects_quarantined_total);
        assert!(peak_used > 0, "cgroup peak sampling must be active for both policies");
        if mode == "memory" {
            // The legacy control bypasses the production memory-derived row
            // limit on purpose. Report its peak even when it exceeds the new
            // policy's acceptance boundary; only the production policy must
            // satisfy that boundary. Do not hide a failing policy's metrics.
            assert!(peak_used < (cap as f64 * super::super::merge_quota::MEMORY_GUARD_SHARE) as u64);
        }
    });
}

/// Process-isolated heap calibration of the complete production build.
#[tokio::test]
#[ignore = "manual build-memory calibration; global allocator tracking requires an isolated process"]
async fn nan4823_build_memory_calibration() {
    {
        let _serial = crate::test_heap::MEASUREMENT
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::test_heap::track_all_threads(true);
        crate::parts::block_index::set_enabled(true);
        crate::parts::token_counts::set_enabled(true);
        crate::identity_observations::set_enabled(true);
        for rows in [50_000, 70_000, 120_000] {
            let mut lab = Lab::new(3_413_114_880);
            lab.config.max_merges_per_tick = 0;
            let generator = MythosGenerator::new();
            generator.land(&lab, 0, rows);
            let mut ingestor = lab.open().await;
            let notices = lab.spool.pending(1).await.unwrap();
            ingestor.admit(&notices, CLOCK).await.unwrap();
            assert_eq!(ingestor.buffer.rows, rows);
            for writers in [2, 4] {
                let bytes = ingestor.buffer.bytes;
                let mut plan = ingestor
                    .flush_plan(
                        &ingestor.buffer,
                        ingestor.schema.clone(),
                        None,
                        CLOCK + writers as i64,
                    )
                    .unwrap();
                plan.writers = writers;
                let baseline = crate::test_heap::reset_peak();
                let finished = plan.build().unwrap();
                let peak = crate::test_heap::peak().saturating_sub(baseline);
                let reserved = super::super::memory::flight_bytes(bytes, writers);
                eprintln!("BUILD_CAL rows={rows} arrow_bytes={bytes} writers={writers} additional_heap_peak={peak} peak_per_arrow={:.4} flight_reservation={reserved} parts={}",
                    peak as f64 / bytes as f64, finished.len());
                assert!(
                    peak as u64 <= reserved - bytes,
                    "measured production build exceeds reservation"
                );
                drop(finished);
                super::super::memory::release_freed();
            }
        }
        crate::test_heap::track_all_threads(false);
    }
}

const SMALL_ROLE_BURST_CASES: &[(u64, usize, usize)] = &[
    (256 * 1024 * 1024, 0, 2),
    (256 * 1024 * 1024, 400, 2),
    (256 * 1024 * 1024, 1_000, 2),
    (512 * 1024 * 1024, 0, 2),
    (512 * 1024 * 1024, 400, 2),
    (512 * 1024 * 1024, 1_000, 2),
    (256 * 1024 * 1024, 0, 4),
    (256 * 1024 * 1024, 0, 7),
    (512 * 1024 * 1024, 0, 4),
    (512 * 1024 * 1024, 0, 7),
    (512 * 1024 * 1024, 400, 4),
];

fn small_role_burst_rows(
    padding: usize,
    rows_per_burst: usize,
    burst: usize,
    object: usize,
    now: i64,
) -> Vec<serde_json::Value> {
    (0..10_000).map(|i| {
                    let id = burst * rows_per_burst + object * 10_000 + i;
                    serde_json::json!({"time": chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now - 5_000).unwrap().to_rfc3339(),
                        "class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201, "severity_id": 1,
                        "metadata": {"uid": format!("review4823-{id:08}"), "tenant_uid": TENANT, "version": "1.9.0",
                            "log_source": "WINDOWS_EVENT", "product": {"name": "fixture"}},
                        "raw_data": format!("fixture{}", "x".repeat(padding)), "raw_data_size": 7 + padding,
                        "message": "authentication", "user": {"name": "fixture-user"}, "dst_endpoint": {"ip": "192.0.2.1"}})
    }).collect::<Vec<_>>()
}

/// Compare operation counts in isolated processes so the ignored legacy
/// control cannot affect concurrent production-policy tests.
#[test]
fn nan4823_small_role_low_rate_bursts() {
    compare_small_role_bursts(false);
}

fn compare_small_role_bursts(actual_cgroup: bool) {
    // Bronze is produced by landing, outside an ingest role. Each real-cgroup
    // sample contains one ingestor, not fixture generation or prior test cases.
    let fixtures = actual_cgroup.then(|| tempfile::tempdir().unwrap());
    let mut prepared = Vec::new();
    if let Some(fixtures) = &fixtures {
        for &(cap, padding, objects) in SMALL_ROLE_BURST_CASES {
            for known_size in [false, true] {
                let dir = fixtures.path().join(format!("case-{}", prepared.len()));
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(
                    dir.join("burst-case.json"),
                    serde_json::to_vec(&(cap, padding, objects, known_size)).unwrap(),
                )
                .unwrap();
                let rows_per_burst = objects * 10_000;
                for burst in 0..2 {
                    let now = CLOCK + burst as i64 * rows_per_burst as i64 * 50;
                    for object in 0..objects {
                        let rows =
                            small_role_burst_rows(padding, rows_per_burst, burst, object, now);
                        super::nan4749_ingest_tests::write_bronze(
                            &dir.join(format!("burst-{burst}-{object}.parquet")),
                            &rows,
                        );
                    }
                }
                prepared.push(dir);
            }
        }
    }
    let directories = if actual_cgroup {
        prepared
            .iter()
            .map(|dir| Some(dir.as_path()))
            .collect::<Vec<_>>()
    } else {
        vec![None]
    };
    let mut results = Vec::new();
    for child in ["nan4823_burst_legacy", "nan4823_burst_memory"] {
        let mut counts = Vec::new();
        for directory in &directories {
            // The comparator stays outside the boundary: a production role
            // holds one ingest process, not an extra test-harness process.
            let mut command = if actual_cgroup {
                let mut command = std::process::Command::new("sudo");
                command.args([
                    "-n",
                    "systemd-run",
                    "--quiet",
                    "--wait",
                    "--pipe",
                    "--collect",
                    "-p",
                    "MemoryMax=536870912",
                    "-p",
                    "MemorySwapMax=0",
                    "-p",
                    "CPUQuota=400%",
                    "--setenv=RAYON_NUM_THREADS=4",
                ]);
                command.arg(format!(
                    "--working-directory={}",
                    directory.unwrap().display()
                ));
                command.arg(format!("--setenv=TMPDIR={}", std::env::temp_dir().display()));
                command.arg(std::env::current_exe().unwrap());
                command
            } else {
                std::process::Command::new(std::env::current_exe().unwrap())
            };
            let output = command
                .args([child, "--ignored", "--nocapture", "--test-threads=1"])
                .output()
                .unwrap();
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            eprint!("{text}");
            assert!(output.status.success(), "{child} failed");
            counts.extend(
                text.lines()
                    .filter_map(|line| line.split_once("NAN-4823 burst result "))
                    .map(|(_, result)| serde_json::from_str::<serde_json::Value>(result).unwrap()),
            );
        }
        assert_eq!(counts.len(), 22);
        results.push(counts);
    }
    for (before, after) in results[0].iter().zip(&results[1]) {
        for key in ["cap", "padding", "objects", "known_size"] {
            assert_eq!(before[key], after[key]);
        }
        for key in [
            "parts", "data_files", "l0_files", "signing_calls", "guard_stops",
        ] {
            assert!(
                after[key].as_u64().unwrap() <= before[key].as_u64().unwrap(),
                "low-rate {key} grew: legacy={before} memory={after}"
            );
        }
        if before["cap"] == 512 * 1024 * 1024
            && before["padding"] == 0
            && before["objects"] == 2
            && before["known_size"] == false
        {
            assert_eq!(before["parts"], 2);
            assert_eq!(after["parts"], 2);
            assert_eq!(after["l0_files"], 14);
            assert_eq!(after["signing_calls"], 2);
        }
    }
}

#[tokio::test]
#[ignore = "isolated legacy control invoked by the burst comparison"]
async fn nan4823_burst_legacy() {
    run_small_role_bursts(true).await;
}

#[tokio::test]
#[ignore = "isolated production policy invoked by the burst comparison"]
async fn nan4823_burst_memory() {
    run_small_role_bursts(false).await;
}

/// 20-EPS average tenants delivering two/four/seven-object bursts. Only
/// the limiter/cold-packing control differs; memory/CPU/layout are matched.
async fn run_small_role_bursts(legacy: bool) {
    super::super::memory::LEGACY_FLUSH_CAP_FOR_BENCH
        .store(legacy, std::sync::atomic::Ordering::Relaxed);
    use crate::parts::part_log::ObjectStore;
    super::super::memory::tune_allocator();
    let sampler = super::super::catchup_bench::RssSampler::start();
    crate::parts::block_index::set_enabled(true);
    crate::parts::token_counts::set_enabled(true);
    crate::identity_observations::set_enabled(true);
    let prepared = std::env::current_dir().unwrap();
    let selected = prepared.join("burst-case.json").is_file().then(|| {
        serde_json::from_slice::<(u64, usize, usize, bool)>(
            &std::fs::read(prepared.join("burst-case.json")).unwrap(),
        )
        .unwrap()
    });
    for &(cap, padding, objects) in SMALL_ROLE_BURST_CASES {
        for known_size in [false, true] {
            if selected.is_some_and(|case| case != (cap, padding, objects, known_size)) {
                continue;
            }
            eprintln!("NAN-4823 burst case: cap={cap} padding={padding} objects={objects} known_size={known_size}");
            let mut lab = Lab::new(cap);
            lab.config.flush_interval_override_ms = None;
            lab.config.max_merges_per_tick = 0;
            let signer = BenchSigner {
                inner: crate::parts::provenance::LocalPartSigner::new(
                    "lab-signer-nan4749",
                    ed25519_dalek::SigningKey::from_bytes(&[47; 32]),
                )
                .unwrap(),
                calls: Default::default(),
                records: Default::default(),
            };
            let mut ingestor = lab.open().await;
            ingestor.signer = &signer;
            let rows_per_burst = objects * 10_000;
            let interval_ms = rows_per_burst as i64 * 50; // 20 EPS average.
            for burst in 0..2 {
                let now = CLOCK + burst as i64 * interval_ms;
                for object in 0..objects {
                    let name = format!("burst-{burst}-{object}");
                    let key = format!("bronze/{name}.parquet");
                    let path = lab.root.join("sources").join(&key);
                    if selected.is_some() {
                        std::fs::hard_link(prepared.join(format!("{name}.parquet")), &path)
                            .unwrap();
                    } else {
                        let rows =
                            small_role_burst_rows(padding, rows_per_burst, burst, object, now);
                        super::nan4749_ingest_tests::write_bronze(&path, &rows);
                    }
                    lab.spool
                        .deliver(&SourceNotice {
                            tenant_id: TENANT.into(),
                            key,
                            version: "1".into(),
                            bytes: if known_size {
                                std::fs::metadata(&path).unwrap().len()
                            } else {
                                0
                            },
                            sha256: None,
                            edge_sha256: None,
                            notified_at_ms: now,
                        })
                        .unwrap();
                }
                for tick in 0..=objects as i64 * 35 + 40 {
                    ingestor.tick(now + tick * 1_000).await.unwrap();
                    assert_eq!(
                        (
                            ingestor.health().objects_quarantined_total,
                            ingestor.health().objects_rejected_total,
                            ingestor.health().rows_rejected_total
                        ),
                        (0, 0, 0),
                        "valid burst rejected: cap={cap} padding={padding} known={known_size}"
                    );
                    if ingestor.health().rows_committed_total
                        == (burst as u64 + 1) * rows_per_burst as u64
                    {
                        break;
                    }
                }
                assert_eq!(
                    ingestor.health().rows_committed_total,
                    (burst as u64 + 1) * rows_per_burst as u64,
                    "cap={cap} padding={padding} objects={objects} known={known_size} buffer={} pending={} deferred={} health={:?}",
                    ingestor.buffer.rows, lab.spool.pending(100).await.unwrap().len(), ingestor.admission_deferred, ingestor.health()
                );
            }
            ingestor.tick(CLOCK + 2 * interval_ms).await.unwrap();
            let health = ingestor.health();
            let store =
                crate::parts::part_log::LocalObjectStore::new(lab.root.join("parts")).unwrap();
            let files = store.list("").await.unwrap();
            let l0_files = files
                .iter()
                .filter(|key| key.contains("/parts/l0/"))
                .count();
            let data_files = files
                .iter()
                .filter(|key| {
                    key.contains("/parts/l0/")
                        && key.contains("/data-")
                        && key.ends_with(".parquet")
                })
                .count();
            let signing_calls = signer.calls.load(std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                (health.objects_quarantined_total, health.rows_rejected_total),
                (0, 0)
            );
            eprintln!(
                "NAN-4823 burst result {}",
                serde_json::json!({
                    "cap": cap, "padding": padding, "objects": objects, "known_size": known_size,
                    "parts": health.parts_written_total, "data_files": data_files,
                    "l0_files": l0_files, "signing_calls": signing_calls,
                    "guard_stops": health.merge_memory_stops_total
                })
            );
            assert_eq!(health.parts_written_total as usize, data_files);
            assert_eq!(l0_files, data_files * 7);
        }
    }
    if let Some(limit) = crate::cgroup_memory::for_process().limit() {
        let peak = sampler.guard_peak();
        eprintln!(
            "NAN-4823 burst memory legacy={legacy} case={selected:?} limit={} peak_guard={peak} peak_rss={}",
            limit.bytes,
            sampler.take()
        );
        // This is a cost/non-regression comparison against an unchanged
        // legacy baseline that can itself exceed 85% on these bursts. Keep
        // the hard cgroup boundary and compare guard stops for both policies.
        // Strict <85% safety acceptance belongs to the two seeded role runs.
        assert!(peak > 0, "cgroup peak sampling must be active");
    }
}

/// Qualify burst cost/non-regression under a real small-role boundary too.
#[test]
#[ignore = "farm only: sudo systemd-run and cgroup v2"]
fn nan4823_small_role_burst_cgroup() {
    compare_small_role_bursts(true);
}
