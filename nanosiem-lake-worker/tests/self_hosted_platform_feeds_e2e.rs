// SPDX-License-Identifier: AGPL-3.0-or-later
#![cfg(target_os = "linux")]

//! NAN-4759 regression gate: a self-hosted lean install (open core, and the
//! sovereign single-host install, which runs the same lean cell) stamps
//! IPinfo Lite geo/ASN, Tor and ThreatFox at ingest, and the stamps are
//! searchable with nPL. Before NAN-4759 the cell had no platform bundle or
//! policy mounted, every one of these fields was silently empty, and no test
//! noticed. Every hop is the production one:
//!
//! 1. `nanosiem-lake-cell trusted-local init` (what lean-init runs) renders the
//!    cell's `platform_bundle_dir`, the tenant's `platform_policy_file` and the
//!    all-bundled grants file.
//! 2. The real `lake_platform_feeds serve --once` (the lean-platform-feeds
//!    service) publishes an empty bundle and the tenant's first policy, then
//!    after the import the next policy revision naming the new bundle.
//! 3. The portable bundle is installed through `lean_platform_feeds::import_file`
//!    (the `import --file` backend), including Ed25519 verification and rollback checks.
//! 4. `IngestService::start` and its production loop consume the rendered
//!    assignment and bootstrap secret through the real S3 listing/GET adapter,
//!    select the platform bundle and policy, and write signed parts.
//! 5. Asserted on the parts (always), and through `PartQueryEngine` nPL over
//!    the signed part log with native chDB (`#[ignore]`d unless chDB is set).

use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::ReaderBuilder;
use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use nanosiem_lake_cell::trusted_local::{self, InitArgs};
use nanosiem_lake_worker::enrichment::IocSnapshotInput;
use nanosiem_core::platform_enrichment::portable::{self, FeedEntry, KeyRing};
use nanosiem_lake_worker::lean_platform_bundle::{PlatformBundle, PlatformBundleSource, TenantPlatformPolicy};
use nanosiem_lake_worker::lean_platform_feeds::{self as feeds, ALL_BUNDLED_GRANTS_SCHEMA};
use nanosiem_lake_worker::part_ingest::cell::IngestService;
use nanosiem_lake_cell::contract::Assignment;
use nanosiem_lake_cell::child::{ControlChannel, TenantService};
use nanosiem_lake_worker::parts::format::PartKeys;
use nanosiem_lake_worker::parts::part_log::{load_log, LocalObjectStore, ObjectStore};
use nanosiem_lake_worker::parts::provenance::{LocalPartSigner, SignedProvenance, TenantKeySet};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

/// Public (geo/ASN only).
const PUBLIC_IP: &str = "8.8.4.4";
/// On the Tor exit list.
const TOR_IP: &str = "185.220.101.1";
/// ThreatFox `ip:port` indicator: the destination endpoint's socket.
const THREATFOX_IP: &str = "45.155.205.233";
const THREATFOX_PORT: u16 = 8443;
const PRIVATE_IP: &str = "10.0.0.5";

fn key() -> SigningKey {
    SigningKey::from_bytes(&[47; 32])
}

fn trusted(root: &Path, tenant: &str) -> TenantKeySet {
    let secret: Value = serde_json::from_slice(&std::fs::read(root.join("bootstrap/cell/secret").join(tenant).join("ingest.token")).unwrap()).unwrap();
    let seed: [u8; 32] = hex::decode(secret["lab_signer_seed_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
    LocalPartSigner::new(secret["lab_signer_key_id"].as_str().unwrap(), SigningKey::from_bytes(&seed)).unwrap().trusted()
}

/// A tiny IPinfo Lite MMDB: every IPv4 address is US / AS64500.
fn tiny_mmdb() -> Vec<u8> {
    fn text(s: &str) -> Vec<u8> {
        [vec![0x40 | s.len() as u8], s.as_bytes().to_vec()].concat()
    }
    fn uint(n: u64, kind: u8) -> Vec<u8> {
        let bytes = n.to_be_bytes();
        let i = bytes.iter().position(|b| *b != 0).unwrap_or(7);
        let mut out = if kind < 8 { vec![(kind << 5) | (8 - i) as u8] } else { vec![(8 - i) as u8, kind - 7] };
        out.extend(&bytes[i..]);
        out
    }
    fn map(pairs: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
        let mut out = vec![0xe0 | pairs.len() as u8];
        for (k, v) in pairs {
            out.extend(text(k));
            out.extend(v);
        }
        out
    }
    let us = map(vec![
        ("country", text("United States")),
        ("country_code", text("US")),
        ("continent", text("North America")),
        ("asn", text("AS64500")),
        ("as_name", text("Fixture Net")),
    ]);
    let ca = map(vec![("country", text("Canada")), ("country_code", text("CA")), ("asn", text("AS64501"))]);
    let a = 18_u32;
    let b = a + us.len() as u32;
    let mut bytes = Vec::new();
    for pointer in [1, b, a, b] {
        bytes.extend(&pointer.to_be_bytes()[1..]);
    }
    bytes.extend([0; 16]);
    bytes.extend(us);
    bytes.extend(ca);
    bytes.extend(b"\xab\xcd\xefMaxMind.com");
    bytes.extend(map(vec![
        ("node_count", uint(2, 6)),
        ("record_size", uint(24, 5)),
        ("ip_version", uint(6, 5)),
        ("database_type", text("ipinfo_lite")),
        ("languages", vec![1, 4, 0x42, b'e', b'n']),
        ("binary_format_major_version", uint(2, 5)),
        ("binary_format_minor_version", uint(0, 5)),
        ("build_epoch", uint(1_799_999_000, 9)),
        ("description", map(vec![("en", text("fixture"))])),
    ]));
    bytes
}

fn ioc(feed: &str, ty: &str, value: &str, threat: &str, data: Value) -> IocSnapshotInput {
    IocSnapshotInput {
        ioc_value: value.into(),
        ioc_type: ty.into(),
        source_id: feed.into(),
        enrichment_name: feed.into(),
        threat_type: threat.into(),
        confidence_level: 90,
        data,
        ..Default::default()
    }
}

/// A verified portable bundle (IPinfo Lite, Tor, ThreatFox): the signed
/// descriptor terms and its NANPFB01 payload, staged under `root`.
fn feed_ring() -> KeyRing {
    KeyRing::from_hex(&[("nan4759-fixture", &hex::encode(key().verifying_key().as_bytes()))]).unwrap()
}

fn portable(root: &Path, now: chrono::DateTime<Utc>) -> PathBuf {
    let (produced, expiry) = (now - Duration::hours(2), now + Duration::hours(20));
    let socket = format!("{THREATFOX_IP}:{THREATFOX_PORT}");
    let rows = [
        ioc("tor_exit_nodes", "ip", TOR_IP, "tor_exit", Value::Null),
        ioc("threatfox", "ip:port", &socket, "botnet_cc", json!({"malware": "fixture-rat"})),
    ];
    let revisions = BTreeMap::from([("ipinfo_lite".to_string(), 41), ("threatfox".to_string(), 9), ("tor_exit_nodes".to_string(), 7)]);
    let staged = root.join("portable-payload.nanpfb");
    PlatformBundle::publish_verified(
        &staged,
        Some(&tiny_mmdb()),
        &rows,
        None,
        revisions.clone(),
        revisions.keys().map(|f| (f.clone(), expiry)).collect(),
    )
    .unwrap();
    let entries = revisions.iter().map(|(id, revision)| (id.clone(), FeedEntry {
        revision: *revision,
        license_id: portable::portable_terms(id).unwrap().license_id.into(),
        terms_revision: "2026-10".into(), upstream_at: produced,
        produced_at: produced, hard_expiry: expiry,
        row_count: if id == "ipinfo_lite" { 2 } else { 1 },
        source_sha256: "47".repeat(32),
    })).collect();
    let artifact = root.join("bundle.nanfeed");
    portable::seal(&staged, entries, now.timestamp_millis() as u64, now,
        "nan4759-fixture", &key(), &feed_ring(), &artifact).unwrap();
    artifact
}

fn install_portable(install: &Install, root: &Path, now: chrono::DateTime<Utc>) -> feeds::Receipt {
    let artifact = portable(root, now);
    // The executable has only compiled-in production keys, no environment or
    // file override. A correctly signed fixture from a foreign key is refused
    // without replacing even the empty receipt or creating a policy grant.
    let before = std::fs::read(install.bundle_dir.join("current.json")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_lake_platform_feeds"))
        .args(["import", "--file", artifact.to_str().unwrap()])
        .env("PLATFORM_BUNDLE_DIR", &install.bundle_dir)
        .env("PLATFORM_POLICY_ROOT", &install.policy_root)
        .env("PLATFORM_GRANTS_DIR", &install.grants_dir).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("signer is not trusted"));
    assert_eq!(std::fs::read(install.bundle_dir.join("current.json")).unwrap(), before);
    // Same production import function and verifier as the executable; this
    // test supplies its signer explicitly, without a production trust knob.
    feeds::import_file(&install.bundle_dir, &artifact, &feed_ring(), now).unwrap()
}

#[test]
fn signed_import_refuses_tampering_rollback_and_same_payload_substitution() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let now = Utc::now();
    let artifact = portable(&root, now);
    let bundle_dir = root.join("installed");
    let ring = feed_ring();
    assert!(feeds::import_file(&bundle_dir, &artifact, &KeyRing::production(), now).is_err());
    assert!(!bundle_dir.exists(), "untrusted data creates no mountable payload");
    let first = feeds::import_file(&bundle_dir, &artifact, &ring, now).unwrap();
    assert_eq!(feeds::import_file(&bundle_dir, &artifact, &ring, now).unwrap(), first);
    let verified = portable::verify_file(&artifact, &ring).unwrap();
    let d = verified.descriptor();
    let newer = root.join("newer.nanfeed");
    portable::seal(&root.join("portable-payload.nanpfb"), d.feeds.clone(), d.sequence + 1,
        now + Duration::milliseconds(1), "nan4759-fixture", &key(), &ring, &newer).unwrap();
    let second = feeds::import_file(&bundle_dir, &newer, &ring, now).unwrap();
    assert_eq!(second.bundle_sha256, first.bundle_sha256);
    assert_eq!(second.sequence, Some(d.sequence + 1), "unchanged payload still advances rollback history");
    assert!(feeds::import_file(&bundle_dir, &artifact, &ring, now).is_err());
    let mut terms = d.feeds.clone();
    terms.get_mut("ipinfo_lite").unwrap().terms_revision = "2026-11".into();
    let substitute = root.join("substitute.nanfeed");
    portable::seal(&root.join("portable-payload.nanpfb"), terms, d.sequence + 1,
        now + Duration::milliseconds(1), "nan4759-fixture", &key(), &ring, &substitute).unwrap();
    assert!(feeds::import_file(&bundle_dir, &substitute, &ring, now).is_err());
    let mut bytes = std::fs::read(&newer).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    let corrupt = root.join("corrupt.nanfeed");
    std::fs::write(&corrupt, bytes).unwrap();
    assert!(feeds::import_file(&bundle_dir, &corrupt, &ring, now).is_err());
    assert!(feeds::import_file(&bundle_dir, &newer, &ring, now + Duration::days(1)).is_err());
    assert_eq!(feeds::Receipt::read(&bundle_dir).unwrap().unwrap(), second);
}

fn rewrap(root: &Path, original: &Path, sequence: u64, terms: &str) -> PathBuf {
    let verified = portable::verify_file(original, &feed_ring()).unwrap();
    let mut entries = verified.descriptor().feeds.clone();
    for entry in entries.values_mut() {
        entry.terms_revision = terms.into();
    }
    let out = root.join(format!("rewrapped-{sequence}-{terms}.nanfeed"));
    portable::seal(&root.join("portable-payload.nanpfb"), entries, sequence,
        verified.descriptor().produced_at, "nan4759-fixture", &key(), &feed_ring(), &out).unwrap();
    out
}

#[test]
fn distribution_response_verifies_before_download_and_tracks_descriptor_updates() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let bundle_dir = root.join("installed");
    let now = Utc::now();
    let artifact = portable(&root, now);
    let first = feeds::import_file(&bundle_dir, &artifact, &feed_ring(), now).unwrap();
    let original = portable::verify_file(&artifact, &feed_ring()).unwrap();
    let sequence = original.descriptor().sequence + 1;
    let next = rewrap(&root, &artifact, sequence, "2026-11");
    let next = portable::verify_file(&next, &feed_ring()).unwrap();
    assert_eq!(next.descriptor().payload.sha256, first.bundle_sha256);
    let response = root.join("current.json");
    let url = format!("https://r2.example/feed-bundles/v1/bundles/{sequence}/{}.nanfeed?x=1&y=2", first.bundle_sha256);
    let write_response = |signed: &portable::SignedDescriptor, sha: &str, url: &str| {
        std::fs::write(&response, serde_json::to_vec_pretty(&json!({
            "descriptor": signed, "bundle_sha256": sha, "bundle_url": url,
        })).unwrap()).unwrap();
    };
    write_response(original.signed(), &first.bundle_sha256, &url);
    assert_eq!(feeds::check_current(&bundle_dir, &response, &feed_ring()).unwrap(), None);
    write_response(next.signed(), &first.bundle_sha256, &url);
    assert_eq!(feeds::check_current(&bundle_dir, &response, &feed_ring()).unwrap().as_deref(), Some(url.as_str()));
    assert!(feeds::check_current(&bundle_dir, &response, &KeyRing::production()).is_err());
    let out = Command::new(env!("CARGO_BIN_EXE_lake_platform_feeds"))
        .args(["check-current", "--file", response.to_str().unwrap()])
        .env("PLATFORM_BUNDLE_DIR", &bundle_dir).output().unwrap();
    assert!(!out.status.success() && out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not trusted"));
    let updated = feeds::import_file(&bundle_dir, &root.join(format!("rewrapped-{sequence}-2026-11.nanfeed")), &feed_ring(), now).unwrap();
    assert_eq!(updated.signed_descriptor.as_ref(), Some(next.signed()), "signed state and rollback floor share the atomic receipt");
    assert_eq!(feeds::check_current(&bundle_dir, &response, &feed_ring()).unwrap(), None);
    write_response(next.signed(), &"0".repeat(64), &url);
    assert!(feeds::check_current(&bundle_dir, &response, &feed_ring()).is_err());
    let mut tampered = next.signed().clone();
    tampered.descriptor.sequence += 1;
    write_response(&tampered, &first.bundle_sha256, &url);
    assert!(feeds::check_current(&bundle_dir, &response, &feed_ring()).is_err());
    for invalid in ["http://r2.example/bundle", "https://user:password@r2.example/bundle", "https://r2.example/\n"] {
        write_response(next.signed(), &first.bundle_sha256, invalid);
        assert!(feeds::check_current(&bundle_dir, &response, &feed_ring()).is_err());
    }
}

#[test]
fn concurrent_same_sequence_substitutions_only_install_one_descriptor() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let bundle_dir = root.join("installed");
    let now = Utc::now();
    let artifact = portable(&root, now);
    let first = feeds::import_file(&bundle_dir, &artifact, &feed_ring(), now).unwrap();
    let sequence = first.sequence.unwrap() + 1;
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let threads: Vec<_> = (0..8).map(|i| {
        let file = rewrap(&root, &artifact, sequence, &format!("terms-{i}"));
        let barrier = barrier.clone();
        let bundle_dir = bundle_dir.clone();
        std::thread::spawn(move || {
            barrier.wait();
            feeds::import_file(&bundle_dir, &file, &feed_ring(), now).is_ok()
        })
    }).collect();
    assert_eq!(threads.into_iter().map(|t| usize::from(t.join().unwrap())).sum::<usize>(), 1);
    assert_eq!(feeds::Receipt::read(&bundle_dir).unwrap().unwrap().sequence, Some(sequence));
}

#[test]
fn a_retired_signing_key_does_not_block_the_next_verified_update() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let bundle_dir = root.join("installed");
    let now = Utc::now();
    let artifact = portable(&root, now);
    let first = feeds::import_file(&bundle_dir, &artifact, &feed_ring(), now).unwrap();
    let original = portable::verify_file(&artifact, &feed_ring()).unwrap();
    let rotated = SigningKey::from_bytes(&[48; 32]);
    let ring = KeyRing::from_hex(&[("rotated", &hex::encode(rotated.verifying_key().to_bytes()))]).unwrap();
    let next = root.join("rotated.nanfeed");
    portable::seal(&root.join("portable-payload.nanpfb"), original.descriptor().feeds.clone(), first.sequence.unwrap() + 1,
        now, "rotated", &rotated, &ring, &next).unwrap();
    assert!(portable::verify_file(&artifact, &ring).is_err(), "the release no longer trusts the retired key");
    let updated = feeds::import_file(&bundle_dir, &next, &ring, now).unwrap();
    assert_eq!(updated.signed_descriptor.as_ref().unwrap().descriptor.signer_key_id, "rotated");
    assert!(format!("{:#}", feeds::import_file(&bundle_dir, &artifact, &feed_ring(), now).unwrap_err()).contains("older"));
}

struct Install {
    tenant: String,
    bundle_dir: PathBuf,
    policy_file: PathBuf,
    policy_root: PathBuf,
    grants_dir: PathBuf,
    listener: std::net::TcpListener,
    assignment: Assignment,
    secret: Vec<u8>,
}

/// lean-init: `trusted-local init`, with the feed volumes under `root`.
fn lean_init(root: &Path) -> Install {
    let out = root.join("bootstrap");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let args = InitArgs {
        out: out.clone(),
        bronze_endpoint: format!("http://{}", listener.local_addr().unwrap()),
        cell_data_root: root.join("cell-data"),
        feed_dir: root.join("feeds"),
        policy_root: root.join("policy"),
        chdb_sha256: Some("0".repeat(64)),
        memory_bytes: Some(4 << 30),
        cpus: Some(2),
        ..InitArgs::default()
    };
    let env = |name: &str| match name {
        "NANO_LAKE_ACCESS_KEY_ID" => Some("access".to_string()),
        "NANO_LAKE_SECRET_ACCESS_KEY" => Some("secret".to_string()),
        _ => None,
    };
    let summary = trusted_local::init(&args, &env).unwrap();
    let tenant = summary["tenant_id"].as_str().unwrap().to_string();
    let cell: Value = serde_json::from_slice(&std::fs::read(out.join("cell/cell.json")).unwrap()).unwrap();
    let placement: Value = serde_json::from_slice(&std::fs::read(out.join("cell/placement.json")).unwrap()).unwrap();
    let grants: Value = serde_json::from_slice(&std::fs::read(out.join(format!("platform-grants/{tenant}.json"))).unwrap()).unwrap();
    assert_eq!(grants["schema"], ALL_BUNDLED_GRANTS_SCHEMA, "init and the publisher agree on the grants schema");
    let work = root.join("ingest");
    for path in [work.join("parts"), work.join("state"), work.join("tmp")] {
        std::fs::create_dir_all(path).unwrap();
    }
    // The production constructor receives the exact feed and per-tenant policy
    // paths rendered by trusted-local init, plus the generated bootstrap secret.
    let assignment: Assignment = serde_json::from_value(json!({
        "tenant": tenant, "role": "ingest", "cell_id": "nan4759-cell",
        "tenant_dir": work, "parts_dir": work.join("parts"), "state_dir": work.join("state"), "tmp_dir": work.join("tmp"),
        "feed_dir": cell["feed_dir"], "platform_bundle_dir": cell["platform_bundle_dir"],
        "platform_policy_file": placement["tenants"][0]["platform_policy_file"],
        "memory_cap_bytes": 0, "cpu_millis": 2000, "eps": 300.0,
        "trusted_local": cell["trusted_local"], "ingest_idle_exit": false,
        "ingest_flush": {"min_age_ms": 1000, "max_age_ms": 1000, "target_rows": 1000},
        "jail": {"uid": 0, "gid": 0, "rw_paths": [], "ro_paths": [], "system_ro_paths": [],
            "tcp_connect_ports": [], "cgroup_dir": null, "require_landlock": false, "max_processes": null, "max_open_files": 1024}
    })).unwrap();
    let secret = std::fs::read(out.join("cell/secret").join(&tenant).join("ingest.token")).unwrap();
    Install {
        bundle_dir: cell["platform_bundle_dir"].as_str().unwrap().into(),
        policy_file: placement["tenants"][0]["platform_policy_file"].as_str().unwrap().into(),
        policy_root: root.join("policy"),
        grants_dir: out.join("platform-grants"),
        tenant, listener, assignment, secret,
    }
}

/// The lean-platform-feeds service, one cycle.
fn feeds_cycle(install: &Install) {
    for args in [&["serve", "--once"][..], &["ready"][..]] {
        let out = Command::new(env!("CARGO_BIN_EXE_lake_platform_feeds"))
            .args(args)
            .env("PLATFORM_BUNDLE_DIR", &install.bundle_dir)
            .env("PLATFORM_POLICY_ROOT", &install.policy_root)
            .env("PLATFORM_GRANTS_DIR", &install.grants_dir)
            .output()
            .unwrap();
        assert!(out.status.success(), "lake_platform_feeds {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }
}

fn policy(install: &Install) -> TenantPlatformPolicy {
    TenantPlatformPolicy::read_for_query(&install.policy_file, install.tenant.parse().unwrap()).unwrap()
}

fn event(tenant: &str, uid: &str, time: chrono::DateTime<Utc>, src: &str, dst: &str, dst_port: u16) -> Value {
    let raw = format!("raw {uid}");
    json!({
        "activity_id": 6, "category_uid": 4, "class_uid": 4001, "type_uid": 400106,
        "severity_id": 1, "time": time.to_rfc3339(),
        "message": format!("{src} -> {dst}:{dst_port}"),
        "raw_data": raw, "raw_data_size": raw.len(),
        "metadata": {"log_name": "netflow", "log_source": "fixture_netflow", "uid": uid, "tenant_uid": tenant,
            "version": "1.9.0", "product": {"name": "fixture", "vendor_name": "nano"}},
        "src_endpoint": {"ip": src, "port": 50000},
        "dst_endpoint": {"ip": dst, "port": dst_port}
    })
}

fn write_bronze(path: &Path, events: &[Value]) {
    let mut body = Vec::new();
    for e in events {
        serde_json::to_writer(&mut body, e).unwrap();
        body.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(body.clone()), None).unwrap();
    let reader = ReaderBuilder::new(Arc::new(schema)).build(Cursor::new(body)).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        let w = writer.get_or_insert_with(|| ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap());
        w.write(&batch).unwrap();
    }
    writer.unwrap().close().unwrap();
}

/// The production self-hosted cell constructor and processing loop, with only
/// the external S3 service replaced by a local HTTP fixture. No lab_main,
/// lab_enricher, hand-wired BronzeIngestEnricher or test-only constructor.
async fn ingest(root: &Path, install: &Install, events: &[Value], at_s: i64) {
    use axum::{body::Body, http::{Request, Response, StatusCode}, Router};
    use nanosiem_lake_cell::fdpass::seqpacket_pair;
    let bronze_file = root.join("bronze.parquet");
    write_bronze(&bronze_file, events);
    let data = std::fs::read(bronze_file).unwrap();
    let secret: Value = serde_json::from_slice(&install.secret).unwrap();
    let object = format!("{}/tenant_id={}/{}-netflow.parquet", secret["bronze"]["prefix"].as_str().unwrap(), install.tenant, at_s - 1200);
    let modified = (Utc::now() - Duration::minutes(20)).to_rfc3339();
    let xml = format!("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>nano-lake</Name><IsTruncated>false</IsTruncated><Contents><Key>{object}</Key><LastModified>{modified}</LastModified><ETag>\"fixture\"</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>", data.len());
    let app = Router::new().fallback(move |request: Request<Body>| {
        let data = data.clone(); let xml = xml.clone(); let object = object.clone();
        async move {
            if request.uri().query().is_some_and(|q| q.contains("list-type=2")) {
                Response::builder().header("content-type", "application/xml").body(Body::from(xml)).unwrap()
            } else if request.uri().path().replace("%3D", "=").replace("%3d", "=").ends_with(&object) {
                Response::builder().header("content-length", data.len()).header("etag", "\"fixture\"")
                    .header("last-modified", "Tue, 27 Oct 2026 00:00:00 GMT").body(Body::from(data)).unwrap()
            } else {
                eprintln!("unexpected S3 fixture path: {} {}", request.method(), request.uri().path());
                Response::builder().status(StatusCode::NOT_FOUND).body(Body::empty()).unwrap()
            }
        }
    });
    let listener = tokio::net::TcpListener::from_std(install.listener.try_clone().unwrap()).unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let service = IngestService::start(&install.assignment, zeroize::Zeroizing::new(install.secret.clone())).await
        .unwrap_or_else(|e| panic!("production cell start: {e:#}"));
    let (child, _supervisor) = seqpacket_pair().unwrap();
    let control = ControlChannel::from_fd(child).unwrap();
    let running = service.clone().run(control);
    tokio::pin!(running);
    let parts = LocalObjectStore::new(root.join("ingest/parts")).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        tokio::select! {
            result = &mut running => panic!("production ingest stopped before committing: {result:?}"),
            _ = async {
                loop {
                    let set = load_log(&parts, &install.tenant).await.unwrap();
                    if set.parts().into_iter().next().is_some() { break; }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            } => {}
        }
    }).await.expect("production cell must ingest and flush the bronze fixture");
    service.shutdown(std::time::Duration::from_secs(1)).await;
    server.abort();
}

/// Every written row, by `metadata.uid`, from the verified signed parts.
async fn rows(root: &Path, tenant: &str, bundle: &str) -> BTreeMap<String, Value> {
    let parts = LocalObjectStore::new(root.join("ingest/parts")).unwrap();
    let set = load_log(&parts, tenant).await.unwrap();
    let mut rows = BTreeMap::new();
    for part in set.parts() {
        let keys = PartKeys::new(tenant, part.level, part.event_hour, &part.part_id).unwrap();
        let provenance = parts.get(&keys.provenance()).await.unwrap().unwrap();
        let signed = SignedProvenance::verify_bytes(&provenance, tenant, &trusted(root, tenant)).unwrap();
        let pins = &signed.record.admission.as_ref().unwrap().feed_pins;
        assert_eq!(pins.get("platform_bundle").and_then(|p| p.as_deref()), Some(bundle), "the part pins the installed bundle");
        for index in 0..part.data_files as usize {
            let data = parts.get(&keys.data(index)).await.unwrap().unwrap();
            let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(data)).unwrap().build().unwrap();
            for batch in reader {
                let mut out = arrow_json::LineDelimitedWriter::new(Vec::new());
                out.write(&batch.unwrap()).unwrap();
                out.finish().unwrap();
                for line in out.into_inner().split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                    let row: Value = serde_json::from_slice(line).unwrap();
                    rows.insert(row["metadata"]["uid"].as_str().unwrap().to_string(), row);
                }
            }
        }
    }
    rows
}

/// The platform feed providers stamped on a row (not the tenant's own
/// ingest-time prevalence stamp, provider "nano").
fn providers(row: &Value) -> Vec<String> {
    let mut out: Vec<String> = row["enrichments"].as_array().map(|a| a.iter().filter_map(|e| e["provider"].as_str())
        .filter(|p| p.starts_with("platform/")).map(str::to_string).collect()).unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

/// Steps 1-4; returns the install and the bundle the tenant's policy names.
async fn install_and_ingest(root: &Path, now: chrono::DateTime<Utc>) -> (Install, String) {
    let install = lean_init(root);
    // Before any import: an empty bundle and a grant-less first policy, so
    // ingest can start (and stamps nothing).
    feeds_cycle(&install);
    let first = policy(&install);
    assert!(first.grants.is_empty());
    let receipt = install_portable(&install, root, now);
    feeds_cycle(&install);
    let second = policy(&install);
    assert_eq!(second.revision, first.revision + 1, "the import rotates the policy (the cell re-reads it every 30 s)");
    assert_eq!(second.bundle_sha256, receipt.bundle_sha256);
    assert_eq!(second.grants.keys().cloned().collect::<Vec<_>>(), ["ipinfo_lite", "threatfox", "tor_exit_nodes"], "every bundled feed is granted");
    let verified = portable::verify_file(&root.join("bundle.nanfeed"), &feed_ring()).unwrap();
    let direct = TenantPlatformPolicy::from_portable(install.tenant.parse().unwrap(), &verified).unwrap();
    assert_eq!(direct.bundle_sha256, second.bundle_sha256);
    let terms = |p: &TenantPlatformPolicy| p.grants.iter().map(|(f, g)| (f.clone(), g.feed_revision, g.valid_until, g.premium.is_none())).collect::<Vec<_>>();
    assert_eq!(terms(&second), terms(&direct));
    let status = feeds::status(&install.bundle_dir, now).unwrap();
    assert!(status.installed && status.feeds.iter().all(|f| f.state == feeds::FeedState::Fresh));
    let t = &install.tenant;
    let events = [
        event(t, "e-public", now - Duration::seconds(50), PUBLIC_IP, PRIVATE_IP, 443),
        event(t, "e-tor", now - Duration::seconds(40), TOR_IP, PRIVATE_IP, 22),
        event(t, "e-threatfox", now - Duration::seconds(30), PRIVATE_IP, THREATFOX_IP, THREATFOX_PORT),
        event(t, "e-private", now - Duration::seconds(20), PRIVATE_IP, "10.0.0.6", 445),
    ];
    ingest(root, &install, &events, now.timestamp()).await;
    (install, receipt.bundle_sha256)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_hosted_install_stamps_geo_asn_tor_and_threatfox_at_ingest() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let now = Utc::now();
    let (install, bundle) = install_and_ingest(&root, now).await;
    let rows = rows(&root, &install.tenant, &bundle).await;
    assert_eq!(rows.len(), 4);

    let public = &rows["e-public"];
    assert_eq!(public["src_endpoint"]["location"]["country"], "US", "{public}");
    assert_eq!(public["src_endpoint"]["autonomous_system"]["number"], 64500);
    assert_eq!(public["src_endpoint"]["autonomous_system"]["name"], "Fixture Net");
    assert_eq!(providers(public), ["platform/ipinfo_lite"]);
    assert!(public["dst_endpoint"].get("location").map_or(true, Value::is_null), "a private IP gets no geo");

    let tor = &rows["e-tor"];
    assert_eq!(providers(tor), ["platform/ipinfo_lite", "platform/tor_exit_nodes"], "{tor}");

    let threatfox = &rows["e-threatfox"];
    assert_eq!(providers(threatfox), ["platform/ipinfo_lite", "platform/threatfox"], "{threatfox}");
    let stamp = threatfox["enrichments"].as_array().unwrap().iter().find(|e| e["provider"] == "platform/threatfox").unwrap();
    assert_eq!(stamp["value"], format!("{THREATFOX_IP}:{THREATFOX_PORT}"));
    assert_eq!(stamp["name"], "dst_endpoint.ip");
    assert_eq!(stamp["data"]["feed_revision_id"], 9);

    assert!(providers(&rows["e-private"]).is_empty(), "private traffic stamps nothing");
}

/// Past `hard_expiry` a feed stamps no new event; the policy drops it on the
/// next cycle, and the reader refuses it even before that.
#[test]
fn hard_expiry_stops_new_stamping_only() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let now = Utc::now();
    let install = lean_init(&root);
    feeds_cycle(&install);
    install_portable(&install, &root, now);
    feeds_cycle(&install);
    let policy = policy(&install);
    let bundle = PlatformBundleSource::Dir(install.bundle_dir.clone())
        .open(&policy.bundle_sha256)
        .unwrap();
    let mut stamped = json!({"src_endpoint": {"ip": TOR_IP}}).as_object().unwrap().clone();
    bundle.stamp(&mut stamped, &policy, now).unwrap();
    assert_eq!(stamped["src_endpoint"]["location"]["country"], "US");
    let mut late = json!({"src_endpoint": {"ip": TOR_IP}}).as_object().unwrap().clone();
    bundle.stamp(&mut late, &policy, now + Duration::days(1)).unwrap();
    assert!(late.get("enrichments").is_none() && late["src_endpoint"].get("location").is_none());
    assert_eq!(feeds::status(&install.bundle_dir, now + Duration::days(1)).unwrap().feeds[0].state, feeds::FeedState::Expired);
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256 and NANO_LAKE_COMPILER"]
async fn self_hosted_stamps_are_searchable_with_npl() {
    use nanosiem_lake_worker::executor::{ExecutorMode, NativeExecutor};
    use nanosiem_lake_worker::native::NativeChdb;
    use nanosiem_lake_worker::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
    use nanosiem_lake_worker::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
    use nanosiem_lake_worker::part_query::log_view::PartLogView;
    use nanosiem_lake_worker::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
    use std::collections::BTreeSet;

    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let now = Utc::now();
    let (install, _) = install_and_ingest(&root, now).await;
    let tenant = install.tenant.clone();
    // Expire every grant before searching the already stored rows. Search must
    // return their original stamps even when no new stamp is permitted.
    let layout = feeds::Layout { bundle_dir: install.bundle_dir.clone(),
        policy_root: install.policy_root.clone(), grants_dir: install.grants_dir.clone() };
    layout.cycle(now + Duration::days(1), &mut BTreeMap::new(), Duration::hours(1)).unwrap();
    assert!(policy(&install).grants.is_empty());

    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start_named_with_mode(runtime, 1, "nan4759-native", ExecutorMode::ReadOnly).unwrap();
    let parts = root.join("ingest/parts");
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(&parts).unwrap());
    let view = PartLogView::open(store.as_ref(), &tenant, trusted(&root, &tenant)).await.unwrap();
    let bucket = "nan4759-local-proof";
    let cache = ReaderObjectCache::open(
        ReaderObjectCacheSettings {
            root: root.join("query-cache"), max_bytes: 128 << 20, query_max_bytes: 128 << 20,
            fetch_concurrency: 2, fetch_deadline: std::time::Duration::from_secs(30),
        },
        &tenant, bucket, &parts_key_prefix(&tenant).unwrap(),
        Arc::new(StoreObjectSource::local(bucket, store.clone(), parts.clone())),
    )
    .unwrap();
    let fetcher = PartFetcher::new(&tenant, bucket, store.clone(), trusted(&root, &tenant), cache).unwrap();
    let engine = PartQueryEngine::new(
        EngineSettings {
            tenant_id: tenant.clone(), bucket: bucket.into(),
            compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
            max_query_bytes: 128 << 20, max_memory_bytes: 1 << 30, max_execution_seconds: 30, threads: 1,
        },
        store, view, fetcher, executor,
    )
    .unwrap();
    let count = |query: &str| {
        let request = BroadNplRequest {
            request_id: uuid::Uuid::new_v4().to_string(), tenant_id: tenant.clone(), dataset: "logs".into(), query: query.into(),
            start: (now - Duration::hours(1)).to_rfc3339(), end: (now + Duration::minutes(1)).to_rfc3339(),
            limit: 50, offset: 0, table_view: false, use_cache: false,
            cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
            clear_boundaries: BTreeMap::new(), watch_weights: Default::default(), minimum_clear_revision: None, deny_source_types: BTreeSet::new(),
        };
        let engine = &engine;
        let query = query.to_string();
        async move {
            let result = engine.broad_npl(&request).await.unwrap_or_else(|e| panic!("{query}: {} {e}", e.status()));
            result["result"]["result_rows"].as_u64().unwrap_or_else(|| panic!("{query}: {result}"))
        }
    };
    // Geo/ASN on the public source (3 public sources: plain, Tor, and none on
    // the ThreatFox row whose source is private).
    assert_eq!(count("src_endpoint.location.country=US").await, 2);
    assert_eq!(count("src_endpoint.autonomous_system.number=64500 metadata.uid=\"e-public\"").await, 1);
    assert_eq!(count("dst_endpoint.location.country=US").await, 1, "the ThreatFox destination is public");
    // enrichments[] providers.
    assert_eq!(count("enrichments.provider=\"platform/tor_exit_nodes\"").await, 1);
    assert_eq!(count(&format!("enrichments.provider=\"platform/threatfox\" dst_endpoint.ip=\"{THREATFOX_IP}\"")).await, 1);
    assert_eq!(count("enrichments.provider=\"platform/ipinfo_lite\"").await, 3);
    assert_eq!(count("metadata.uid=\"e-private\" enrichments.provider=\"platform/ipinfo_lite\"").await, 0, "private traffic is not stamped");
    assert_eq!(count("enrichments.provider=\"platform/threatfox\" | stats count by dst_endpoint.ip").await, 1);
}
