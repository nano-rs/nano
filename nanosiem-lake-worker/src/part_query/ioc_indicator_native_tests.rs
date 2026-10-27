// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4664, native: IOC lookups over synthetic OCSF (no tenant data), the
//! bakeoff's H1 / H2 / H3 / H10 shapes, end-to-end (real ingestor + hour
//! merge, real compiler, planner, chDB).
//!
//! One hour of bench-shaped rows (process / file / auth / network / DNS /
//! HTTP classes, Zipf-free uniform pools) with planted IOCs whose exact
//! answers are known: a SHA-256 in `process.file.hashes` / `file.hashes` and
//! (upper-cased) in `raw_data`, an IP in `dst_endpoint.ip`, and a domain in
//! `dst_endpoint.domain`, `query.hostname` and `http_request.url.hostname`.
//!
//! Every hunt must return exactly the fixture truth in every layout:
//! indicator columns on every part, on none (parts written before
//! NAN-4664), and mixed (an older hour without them, a newer one with).
//! It prints the latency, storage rows / bytes and kept row groups of each
//! hunt (p50 of five warm runs) for the PR's before/after table.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::density::ioc_indicator_native -- --ignored --nocapture --test-threads=1
//! ```

use crate::enrichment::BronzeIngestEnricher;
use crate::executor::{ExecutorMode, NativeExecutor};
use crate::native::NativeChdb;
use crate::part_ingest::ingest::seed_schema;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
use crate::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
use crate::part_query::log_view::PartLogView;
use crate::parts::levels::Level;
use crate::parts::part_log::{LocalObjectStore, ObjectStore};
use crate::parts::provenance::LocalPartSigner;
use crate::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
use chrono::{DateTime, Duration, DurationRound, Utc};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

const TENANT: &str = "6d2c4b1a-9e8f-4a7b-8c6d-5e4f3a2b1c0d";
/// Rows per hour, in `BRONZE_FILES` bronze files.
fn rows_per_hour() -> usize {
    std::env::var("NAN4664_ROWS").ok().and_then(|v| v.parse().ok()).unwrap_or(120_000)
}
const BRONZE_FILES: usize = 6;
const IOC_HASH: &str = "5b7c2e1f0a9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b";
const IOC_IP: &str = "203.0.113.77";
const IOC_DOMAIN: &str = "update-cdn.nan4664-ioc.example";
/// Planted rows per hour (bench `PLANT` counts).
const HASH_PROCESS: usize = 37;
const HASH_FILE: usize = 3;
const IP_EVENTS: usize = 40;
const DOMAIN_NETWORK: usize = 40;
const DOMAIN_DNS: usize = 60;
const DOMAIN_HTTP: usize = 30;

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan4664", ed25519_dalek::SigningKey::from_bytes(&[46; 32])).unwrap()
}

fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn sha(tag: &str, n: u64) -> String {
    hex::encode(<sha2::Sha256 as sha2::Digest>::digest(format!("{tag}-{n}").as_bytes()))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Plant { None, HashProcess, HashFile, Ip, DomainNetwork, DomainDns, DomainHttp }

/// Which planted IOC row `i` of an hour is (planted rows sit in the hour's
/// last 20 minutes, like the bench's).
fn plant(i: usize, rows: usize) -> Plant {
    let start = rows - rows / 3;
    if i < start { return Plant::None; }
    let stride = (rows / 3) / 260;
    if stride == 0 || (i - start) % stride != 0 { return Plant::None; }
    let k = (i - start) / stride;
    let mut acc = 0;
    for (count, kind) in [
        (HASH_PROCESS, Plant::HashProcess), (HASH_FILE, Plant::HashFile), (IP_EVENTS, Plant::Ip),
        (DOMAIN_NETWORK, Plant::DomainNetwork), (DOMAIN_DNS, Plant::DomainDns), (DOMAIN_HTTP, Plant::DomainHttp),
    ] {
        acc += count;
        if k < acc { return kind; }
    }
    Plant::None
}

fn class_of(i: usize, plant: Plant) -> i64 {
    match plant {
        Plant::HashProcess => 1007,
        Plant::HashFile => 1001,
        Plant::Ip | Plant::DomainNetwork => 4001,
        Plant::DomainDns => 4003,
        Plant::DomainHttp => 4002,
        Plant::None => match mix(i as u64 ^ 0xc1a5) % 100 {
            0..=34 => 1007,
            35..=59 => 4001,
            60..=74 => 4003,
            75..=84 => 3002,
            85..=94 => 1001,
            _ => 4002,
        },
    }
}

fn host(r: u64) -> String { format!("ws-{:04}.corp.local", r % 2_500) }
fn user(r: u64) -> String { format!("user{:04}", r % 6_000) }
fn ext_ip(r: u64) -> String { format!("198.51.{}.{}", (r >> 8) % 250, r % 250) }
fn domain(r: u64) -> String { format!("svc{}.cdn{}.example.net", r % 25_000, r % 7) }

/// One synthetic OCSF 1.9 event (`uid-{hour}-{i}`).
fn event(hour_tag: usize, i: usize, rows: usize, time: &str) -> Value {
    let planted = plant(i, rows);
    let class = class_of(i, planted);
    let r = mix(((hour_tag as u64) << 40) ^ i as u64);
    let host = host(r);
    let user = user(r >> 7);
    let mut ev = json!({
        "class_uid": class, "category_uid": class / 1000, "activity_id": 1, "type_uid": class * 100 + 1,
        "severity_id": 1, "time": time, "status": "Success",
        "metadata": {"uid": format!("uid-{hour_tag}-{i:08}"), "version": "1.9.0", "tenant_uid": TENANT},
        "device": {"hostname": host, "ip": format!("10.{}.{}.{}", (r >> 16) % 250, (r >> 8) % 250, r % 250), "type_id": 3},
    });
    let (source, message, raw) = match class {
        1007 => {
            let hash = if planted == Plant::HashProcess { IOC_HASH.to_string() } else { sha("bg-proc", (r >> 3) % 1_200) };
            let name = format!("proc{}.exe", (r >> 3) % 400);
            ev["process"] = json!({"pid": 1000 + r % 60_000, "name": name, "cmd_line": format!("C:\\Program Files\\App\\{name} --job {}", r % 100_000),
                "file": {"name": name, "path": format!("C:\\Program Files\\App\\{name}"), "type_id": 1,
                         "hashes": [{"algorithm_id": 3, "value": hash}]}});
            ev["actor"] = json!({"user": {"name": user}, "process": {"pid": 600, "name": "explorer.exe"}});
            ("windows_sysmon", format!("Process {name} started by {user} on {host}"),
             format!("<Event><EventID>1</EventID><Computer>{host}</Computer><Data Name='Image'>{name}</Data><Data Name='Hashes'>SHA256={}</Data><Data Name='User'>CORP\\{user}</Data></Event>", hash.to_uppercase()))
        }
        1001 => {
            let hash = if planted == Plant::HashFile { IOC_HASH.to_string() } else { sha("bg-rare", r % 200_000) };
            let name = format!("doc_{}.pdf", r % 10_000);
            ev["actor"] = json!({"user": {"name": user}, "process": {"pid": 600, "name": "explorer.exe"}});
            ev["file"] = json!({"name": name, "path": format!("C:\\Users\\{user}\\{name}"), "type_id": 1, "size": r % 5_000_000,
                "hashes": [{"algorithm_id": 3, "value": hash}]});
            ("windows_sysmon", format!("File create: {name} on {host}"),
             format!("<Event><EventID>11</EventID><Computer>{host}</Computer><Data Name='TargetFilename'>{name}</Data><Data Name='Hashes'>SHA256={}</Data></Event>", hash.to_uppercase()))
        }
        3002 => {
            ev["user"] = json!({"name": user, "uid": format!("S-1-5-21-{}", r % 100_000)});
            ev["src_endpoint"] = json!({"ip": ext_ip(r >> 11)});
            ev["dst_endpoint"] = json!({"hostname": host, "ip": "10.0.0.10"});
            ("windows_security", format!("Logon success for {user} on {host}"),
             format!("<Event><EventID>4624</EventID><Computer>{host}</Computer><Data Name='TargetUserName'>{user}</Data><Data Name='IpAddress'>{}</Data></Event>", ext_ip(r >> 11)))
        }
        4001 => {
            let ip = if matches!(planted, Plant::Ip) || (planted == Plant::DomainNetwork && i % 4 == 0) { IOC_IP.to_string() } else { ext_ip(r >> 13) };
            let mut dst = json!({"ip": ip, "port": 443});
            if planted == Plant::DomainNetwork {
                dst["domain"] = json!(IOC_DOMAIN);
            } else if r % 10 < 4 {
                dst["domain"] = json!(domain(r >> 5));
            }
            let dom = dst["domain"].as_str().unwrap_or("").to_string();
            ev["src_endpoint"] = json!({"ip": format!("10.1.{}.{}", (r >> 4) % 250, r % 250), "port": 1024 + r % 60_000, "hostname": host});
            ev["dst_endpoint"] = dst;
            ("panos_traffic", format!("Connection 10.1.x -> {ip}:443"),
             format!("1,TRAFFIC,end,10.1.{}.{},{ip},allow,tcp,{},{dom}", (r >> 4) % 250, r % 250, r % 1_000_000))
        }
        4003 => {
            let q = if planted == Plant::DomainDns { IOC_DOMAIN.to_string() } else { domain(r >> 5) };
            ev["src_endpoint"] = json!({"ip": format!("10.1.{}.{}", (r >> 4) % 250, r % 250), "port": 1024 + r % 60_000});
            ev["dst_endpoint"] = json!({"ip": "10.0.0.53", "port": 53});
            ev["query"] = json!({"hostname": q, "type": "A", "class": "IN"});
            ("windows_dns", format!("DNS query {q} from {host}"), format!("PACKET UDP Rcv 10.1.x Q [0001 D NOERROR] A ({q}) -> {}", ext_ip(r >> 9)))
        }
        _ => {
            let d = if planted == Plant::DomainHttp { IOC_DOMAIN.to_string() } else { domain(r >> 5) };
            ev["src_endpoint"] = json!({"ip": format!("10.1.{}.{}", (r >> 4) % 250, r % 250)});
            ev["dst_endpoint"] = json!({"ip": ext_ip(r >> 13), "port": 443});
            ev["http_request"] = json!({"http_method": "GET", "user_agent": "Mozilla/5.0",
                "url": {"hostname": d, "path": format!("/p/{}", r % 10_000), "scheme": "https", "url_string": format!("https://{d}/p/{}", r % 10_000)}});
            ev["http_response"] = json!({"code": 200});
            ("zscaler_web", format!("GET {d} 200"), format!("{user} GET https://{d}/p/{} 200 \"Mozilla/5.0\"", r % 10_000))
        }
    };
    ev["metadata"]["log_source"] = json!(source);
    ev["metadata"]["product"] = json!({"name": source, "vendor_name": "fixture"});
    if class / 1000 != 1 {
        ev["metadata"]["profiles"] = json!(["host"]);
    }
    ev["message"] = json!(message);
    ev["raw_data_size"] = json!(raw.len());
    ev["raw_data"] = json!(raw);
    ev
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

fn event_time(hour: DateTime<Utc>, i: usize, rows: usize) -> DateTime<Utc> {
    hour + Duration::microseconds((i as i64) * (3_600_000_000 / rows as i64))
}

/// Ingest each hour at its own clock and advance the clock until every
/// hour is one sealed hour part. `indicators[n]` says whether hour `n` is
/// written with indicator columns (false = a part from before NAN-4664).
async fn ingest_and_seal(root: &std::path::Path, hours: &[DateTime<Utc>], indicators: &[bool]) {
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let rows = rows_per_hour();
    for (h, (hour, on)) in hours.iter().zip(indicators).enumerate() {
        crate::parts::indicators::set_write_enabled(*on);
        let mut config = IngestConfig::new(TENANT, root.join(format!("work-{h}")));
        config.flush_interval_override_ms = Some(1_000);
        let hour_ms = hour.timestamp_millis();
        let mut ingestor = Ingestor::open(
            config, &parts, &sources, &spool as &dyn NoticeQueue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), hour_ms,
        )
        .await
        .expect("ingest opens");
        let per = rows / BRONZE_FILES;
        for n in 0..BRONZE_FILES {
            let batch = (n * per..(n + 1) * per)
                .map(|i| event(h, i, rows, &event_time(*hour, i, rows).to_rfc3339()))
                .collect::<Vec<_>>();
            let key = format!("bronze/{h}-{n:04}.parquet");
            write_bronze(&sources_dir.join(&key), &batch);
            crate::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT).expect("bronze admitted");
            let at = event_time(*hour, (n + 1) * per - 1, rows).timestamp_millis();
            spool
                .deliver(&SourceNotice {
                    tenant_id: TENANT.into(), key, version: "1".into(), bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: at,
                })
                .unwrap();
            ingestor.tick(at + 1_000).await.expect("ingest admits");
            ingestor.flush_now(at + 5_000).await.expect("ingest flushes");
        }
        let mut clock = hour_ms + 4 * 3_600_000;
        let mut sealed = false;
        for _ in 0..1_200 {
            ingestor.tick(clock).await.expect("tick");
            clock += 1_000;
            let live = crate::parts::part_log::load_log(&parts, TENANT).await.unwrap();
            if live.parts().count() == h + 1 && live.parts().all(|part| part.level == Level::Hour) {
                sealed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(sealed, "hour {h} never sealed into one hour part");
    }
    crate::parts::indicators::set_write_enabled(true);
}

async fn engine(root: &std::path::Path) -> PartQueryEngine {
    let signer = signer();
    let state = root.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let trusted = signer.trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone()).await.unwrap();
    let bucket = "nan4664-local";
    let cache = ReaderObjectCache::open(
        ReaderObjectCacheSettings {
            root: state.join("cache"),
            max_bytes: 4 << 30,
            query_max_bytes: 2 << 30,
            fetch_concurrency: 4,
            fetch_deadline: std::time::Duration::from_secs(60),
        },
        TENANT,
        bucket,
        &parts_key_prefix(TENANT).unwrap(),
        Arc::new(StoreObjectSource::local(bucket, store.clone(), root.join("parts"))),
    )
    .unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted, cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").expect("NANO_CHDB_LIBRARY_PATH"),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("NANO_CHDB_LIBRARY_SHA256"),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let small = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts", ExecutorMode::ReadOnly, Some(256 << 20))
        .unwrap()
        .with_result_limit(64 << 20);
    let large = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts-large", ExecutorMode::ReadOnly, Some(3 << 29)).unwrap();
    let writer = NativeExecutor::start_with_server_memory_limit(runtime, 1, "parts-rw", ExecutorMode::ReadWrite, Some(3 << 29)).unwrap();
    PartQueryEngine::new(
        EngineSettings {
            tenant_id: TENANT.into(),
            bucket: bucket.into(),
            compiler: std::env::var("NANO_LAKE_COMPILER").expect("NANO_LAKE_COMPILER").into(),
            max_query_bytes: 64 << 30,
            max_memory_bytes: 256 << 20,
            max_execution_seconds: 120,
            threads: 4,
        },
        store,
        view,
        fetcher,
        small,
    )
    .unwrap()
    .with_writer(writer)
    .with_large(large, 3 << 29)
    .with_state_dir(&state)
}

fn request(query: &str, first: DateTime<Utc>, last: DateTime<Utc>) -> BroadNplRequest {
    BroadNplRequest {
        request_id: "nan4664".into(),
        tenant_id: TENANT.into(),
        dataset: "logs".into(),
        query: query.into(),
        start: (first - Duration::minutes(5)).to_rfc3339(),
        end: (last + Duration::hours(1) + Duration::minutes(5)).to_rfc3339(),
        limit: 500,
        offset: 0,
        table_view: true,
        use_cache: false,
        cursor_time: None,
        cursor_event_uid: None,
        anchor_us: None,
        decay: None,
        clear_boundaries: Default::default(),
        watch_weights: Default::default(),
        minimum_clear_revision: None,
        deny_source_types: Default::default(),
    }
}

struct Run {
    answer: Value,
    wall_ms: f64,
}

async fn run(engine: &PartQueryEngine, request: &BroadNplRequest) -> Run {
    engine.clear_locator_cache();
    let started = std::time::Instant::now();
    let answer = crate::query_timing::measure("nan4664", Box::pin(engine.broad_npl(request)))
        .await
        .unwrap_or_else(|error| panic!("{}: {error}", request.query));
    Run { answer, wall_ms: started.elapsed().as_secs_f64() * 1e3 }
}

fn rows(answer: &Value) -> Vec<Value> {
    answer["result"]["rows"].as_array().cloned().unwrap_or_else(|| panic!("no rows in {answer}"))
}

fn uids(rows: &[Value]) -> Vec<String> {
    let mut out = rows
        .iter()
        .map(|row| row.get("metadata.uid").or_else(|| row.pointer("/metadata/uid")).and_then(Value::as_str).unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    out.sort();
    out
}

fn number(value: &Value) -> u64 {
    value.as_u64().or_else(|| value.as_str().and_then(|s| s.parse().ok())).unwrap_or_else(|| panic!("not a count: {value}"))
}

/// The fixture truth for the planted IOCs of `hours` hours.
struct Truth {
    hash_uids: Vec<String>,
    /// `(device.hostname, class_uid)` of every hash row, sorted.
    hash_hosts: Vec<(String, i64)>,
    ip_events: u64,
    ip_hosts: u64,
    domain_by_host: BTreeMap<String, u64>,
}

fn truth(hours: usize) -> Truth {
    let rows = rows_per_hour();
    let mut hash_uids = Vec::new();
    let mut hash_hosts = Vec::new();
    let (mut ip_events, mut ip_hosts) = (0, std::collections::BTreeSet::new());
    let mut domain_by_host = BTreeMap::new();
    for h in 0..hours {
        for i in 0..rows {
            let planted = plant(i, rows);
            let ev = event(h, i, rows, "2026-01-01T00:00:00Z");
            if matches!(planted, Plant::HashProcess | Plant::HashFile) {
                hash_uids.push(ev["metadata"]["uid"].as_str().unwrap().to_string());
                hash_hosts.push((ev["device"]["hostname"].as_str().unwrap().to_string(), ev["class_uid"].as_i64().unwrap()));
            }
            if ev["dst_endpoint"]["ip"] == json!(IOC_IP) {
                ip_events += 1;
                ip_hosts.insert(ev["device"]["hostname"].as_str().unwrap().to_string());
            }
            if ev["dst_endpoint"]["domain"] == json!(IOC_DOMAIN)
                || ev["query"]["hostname"] == json!(IOC_DOMAIN)
                || ev["http_request"]["url"]["hostname"] == json!(IOC_DOMAIN)
            {
                *domain_by_host.entry(ev["device"]["hostname"].as_str().unwrap().to_string()).or_insert(0) += 1;
            }
        }
    }
    hash_uids.sort();
    hash_hosts.sort();
    Truth { hash_uids, hash_hosts, ip_events, ip_hosts: ip_hosts.len() as u64, domain_by_host }
}

/// `(label, truth shape, query)`: the bakeoff hunts, then the typed IOC
/// forms (`hash=`, `domain=`, `ioc=`) that must return the same truth.
fn hunts() -> Vec<(&'static str, &'static str, String)> {
    let stats_by_host = "| stats count as c by device.hostname | sort -c | head 50";
    vec![
        ("H1", "H1", format!("{IOC_HASH} | table time, device.hostname, class_uid | head 100")),
        ("H2", "H2", format!("dst_endpoint.ip={IOC_IP} | stats count as c, dc(device.hostname) as hosts")),
        ("H3", "H3", format!("(dst_endpoint.domain={IOC_DOMAIN} OR query.hostname={IOC_DOMAIN} OR http_request.url.hostname={IOC_DOMAIN}) {stats_by_host}")),
        ("H10", "H10", format!("{} | head 10", IOC_HASH.to_uppercase())),
        ("hash=", "H1", format!("hash={} | table time, device.hostname, class_uid | head 100", IOC_HASH.to_uppercase())),
        ("domain=", "H3", format!("domain={} {stats_by_host}", IOC_DOMAIN.to_uppercase())),
        ("ioc=ip", "H2", format!("ioc={IOC_IP} | stats count as c, dc(device.hostname) as hosts")),
        ("ioc=hash", "H1", format!("ioc={IOC_HASH} | table time, device.hostname, class_uid | head 100")),
    ]
}

/// Exactly the fixture truth (no false negative, no false positive).
fn check(label: &str, layout: &str, answer: &Value, truth: &Truth) {
    let got = rows(answer);
    // NAN-4664: the derived columns never reach a result row.
    for row in &got {
        if let Some(object) = row.as_object() {
            assert!(!object.keys().any(|key| key.starts_with("nano_ioc")), "{layout} {label}: indicator column in {row}");
        }
        assert!(!row.to_string().contains("\"nano_ioc"), "{layout} {label}: indicator column in {row}");
    }
    match label {
        "H1" => {
            let mut hosts = got
                .iter()
                .map(|row| (row["device.hostname"].as_str().unwrap().to_string(), number(&row["class_uid"]) as i64))
                .collect::<Vec<_>>();
            hosts.sort();
            assert_eq!(hosts, truth.hash_hosts, "{layout} {label}: hash rows");
        }
        "H10" => {
            assert_eq!(got.len(), truth.hash_uids.len().min(10), "{layout} {label}");
            for uid in uids(&got) {
                assert!(truth.hash_uids.contains(&uid), "{layout} {label}: {uid} is not a planted row");
            }
        }
        "H2" => {
            assert_eq!(got.len(), 1, "{layout} {label}: {got:?}");
            assert_eq!(number(&got[0]["c"]), truth.ip_events, "{layout} {label}: count");
            assert_eq!(number(&got[0]["hosts"]), truth.ip_hosts, "{layout} {label}: hosts");
        }
        "H3" => {
            // `sort -c | head 50`: the top 50 (ties broken arbitrarily).
            let got = got
                .iter()
                .map(|row| (row["device.hostname"].as_str().unwrap().to_string(), number(&row["c"])))
                .collect::<Vec<_>>();
            assert_eq!(got.len(), truth.domain_by_host.len().min(50), "{layout} {label}: {got:?}");
            assert!(got.windows(2).all(|pair| pair[0].1 >= pair[1].1), "{layout} {label}: not sorted");
            for (host, c) in &got {
                assert_eq!(truth.domain_by_host.get(host), Some(c), "{layout} {label}: {host}");
            }
            let floor = got.last().map_or(0, |(_, c)| *c);
            let above = truth.domain_by_host.values().filter(|c| **c > floor).count();
            assert!(got.iter().filter(|(_, c)| *c > floor).count() == above, "{layout} {label}: missed a top host");
        }
        _ => unreachable!(),
    }
}

fn metric(answer: &Value, key: &str) -> String {
    let planner = &answer["planner"];
    let value = match key {
        "storage_rows" | "storage_bytes" => answer["result"][key].clone(),
        _ => planner[key].clone(),
    };
    if value.is_null() { "-".into() } else { value.to_string() }
}

async fn measure_layout(layout: &str, indicators: &[bool]) {
    let root = tempfile::tempdir().unwrap();
    let base = (Utc::now() - Duration::hours(10)).duration_trunc(Duration::hours(1)).unwrap();
    let hours = (0..indicators.len()).map(|n| base + Duration::hours(n as i64)).collect::<Vec<_>>();
    ingest_and_seal(root.path(), &hours, indicators).await;
    // Storage: the sealed hour parts' data files (one hour part per hour).
    let (mut bytes, mut parts) = (0_u64, std::collections::BTreeSet::new());
    let mut stack = vec![root.path().join("parts")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.to_string_lossy().contains("/parts/h/") && entry.file_name().to_string_lossy().starts_with("data-") {
                bytes += entry.metadata().unwrap().len();
                parts.insert(path.parent().unwrap().to_path_buf());
                // Per indicator column: compressed pages + bloom bytes.
                use parquet::file::reader::FileReader;
                let reader = parquet::file::reader::SerializedFileReader::new(std::fs::File::open(&path).unwrap()).unwrap();
                let mut columns = std::collections::BTreeMap::<String, (i64, i64)>::new();
                for group in reader.metadata().row_groups() {
                    for chunk in group.columns() {
                        let path = chunk.column_path().string();
                        if path.starts_with("nano_ioc_") {
                            let entry = columns.entry(path).or_default();
                            entry.0 += chunk.compressed_size();
                            entry.1 += i64::from(chunk.bloom_filter_length().unwrap_or(0));
                        }
                    }
                }
                for (column, (pages, bloom)) in columns {
                    println!("NAN4664-COLUMN layout={layout} column={column} pages={pages} bloom={bloom}");
                }
            }
        }
    }
    let rows = (rows_per_hour() * hours.len()) as f64;
    println!("NAN4664-BYTES layout={layout} hour_parts={} data_bytes={bytes} bytes_per_row={:.1}", parts.len(), bytes as f64 / rows);
    let engine = engine(root.path()).await;
    let truth = truth(hours.len());
    assert_eq!(truth.hash_uids.len(), (HASH_PROCESS + HASH_FILE) * hours.len());
    let (first, last) = (hours[0], *hours.last().unwrap());
    // Warm the reader cache (every data file local, as on a resident cell).
    let _ = run(&engine, &request("* | stats count", first, last)).await;
    for (label, shape, query) in hunts() {
        let request = request(&query, first, last);
        let warm = run(&engine, &request).await;
        check(shape, layout, &warm.answer, &truth);
        let mut walls = Vec::new();
        let mut last_answer = warm.answer;
        let runs = std::env::var("NAN4664_RUNS").ok().and_then(|v| v.parse().ok()).unwrap_or(5_usize).max(3);
        for _ in 0..runs {
            let timed = run(&engine, &request).await;
            check(shape, layout, &timed.answer, &truth);
            walls.push(timed.wall_ms);
            last_answer = timed.answer;
        }
        walls.sort_by(f64::total_cmp);
        println!(
            "NAN4664 layout={layout} hunt={label} p50_ms={:.1} min_ms={:.1} storage_rows={} storage_bytes={} kept_row_groups={} fetched_files={} statements={}",
            walls[walls.len() / 2], walls[0],
            metric(&last_answer, "storage_rows"), metric(&last_answer, "storage_bytes"),
            metric(&last_answer, "kept_row_groups"), metric(&last_answer, "fetched_files"),
            metric(&last_answer, "successful_native_statements"),
        );
        if std::env::var_os("NAN4664_PLANNER").is_some() {
            println!("NAN4664-PLANNER {layout} {label}: {}", last_answer["planner"]);
        }
    }
}

/// Every hunt returns exactly the truth, and its cost is printed, with
/// indicator columns on every part, on none, and on the newer hour only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn ioc_hunts_are_exact_over_new_old_and_mixed_parts() {
    // The bakeoff cell (`trusted-local init`) writes no 1,024-row blocks;
    // NAN4664_BLOCKS=1 measures with them.
    let blocks = std::env::var("NAN4664_BLOCKS").is_ok_and(|v| v == "1");
    crate::parts::block_index::set_enabled(blocks);
    crate::parts::token_counts::set_enabled(blocks);
    let layouts: Vec<(&str, Vec<bool>)> = match std::env::var("NAN4664_LAYOUTS").ok().as_deref() {
        Some("old") => vec![("old", vec![false])],
        Some("new") => vec![("new", vec![true])],
        Some("old,new") => vec![("old", vec![false]), ("new", vec![true])],
        _ => vec![("new", vec![true]), ("old", vec![false]), ("mixed", vec![false, true])],
    };
    for (layout, indicators) in layouts {
        measure_layout(layout, &indicators).await;
    }
}
