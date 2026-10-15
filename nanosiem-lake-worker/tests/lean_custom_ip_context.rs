// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lean custom IP context, end to end: a tenant uploads CIDR context to its
//! lean coordinator, the coordinator publishes a revisioned snapshot under the
//! tenant's R2 enrichment prefix, and the next ingested part is stamped with
//! that tenant's context only.

use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::ReaderBuilder;
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::lean_enrichment_coordinator::{auth_digest, router, LeanCoordinatorState};
use nanosiem_lake_worker::lean_ip_context::LeanIpContextSnapshots;
use nanosiem_lake_worker::part_ingest::ingest::seed_schema;
use nanosiem_lake_worker::part_ingest::{IngestConfig, Ingestor, SourceNotice, SpoolQueue};
use nanosiem_lake_worker::parts::format::PartKeys;
use nanosiem_lake_worker::parts::part_log::{load_log, LocalObjectStore, ObjectStore};
use nanosiem_lake_worker::parts::provenance::{LocalPartSigner, SignedProvenance};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const TENANT_A: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
const TENANT_B: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f01";
const TOKEN_A: &str = "tenant-a-lean-coordinator-bearer-token-0001";
const TOKEN_B: &str = "tenant-b-lean-coordinator-bearer-token-0002";
/// 2026-09-25T00:00:00Z
const DAY0_S: i64 = 1_790_294_400;

/// The object-store root a tenant's `enrichment_reader`/writer credential is
/// scoped to (`lake/enrichment/v1/tenant_id=<T>/`).
fn tenant_prefix(r2: &Path, tenant: &str) -> PathBuf {
    r2.join("lake/enrichment/v1").join(format!("tenant_id={tenant}"))
}

struct Coordinator {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Coordinator {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn coordinator(r2: &Path, scratch: &Path, tenant: &str, token: &str) -> Coordinator {
    let objects: Arc<dyn ObjectStore> =
        Arc::new(LocalObjectStore::new(tenant_prefix(r2, tenant)).unwrap());
    let state = LeanCoordinatorState::new(
        tenant.parse().unwrap(),
        auth_digest(token),
        objects,
        scratch.to_path_buf(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    Coordinator { url, task }
}

fn ndjson(rows: &[Value]) -> Vec<u8> {
    let mut body = Vec::new();
    for row in rows {
        serde_json::to_writer(&mut body, row).unwrap();
        body.push(b'\n');
    }
    body
}

fn cidr(network: &str, country: &str, as_name: &str) -> Value {
    json!({
        "network": network, "source_id": "tenant-cmdb", "country_code": country,
        "asn": "AS64512", "as_name": as_name, "updated_at": "2026-09-27T00:00:00Z"
    })
}

async fn upload(url: &str, token: &str, tenant: &str, body: Vec<u8>) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{url}/v1/ip-context/batch"))
        .bearer_auth(token)
        .header("X-Nano-Tenant-ID", tenant)
        .header("Content-Type", "application/x-ndjson")
        .body(body)
        .send()
        .await
        .unwrap()
}

async fn current(r2: &Path, reader_tenant: &str, store_tenant: &str, scratch: &Path) -> anyhow::Result<Option<String>> {
    let objects = LocalObjectStore::new(tenant_prefix(r2, store_tenant)).unwrap();
    let reader = LeanIpContextSnapshots::new(reader_tenant.parse().unwrap(), &objects, scratch).unwrap();
    Ok(reader.current().await?.map(|pointer| pointer.revision.to_string()))
}

#[tokio::test]
async fn over_cap_upload_is_413_and_publishes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let r2 = dir.path().join("r2");
    let a = coordinator(&r2, &dir.path().join("a"), TENANT_A, TOKEN_A).await;
    // Row cap: 50,001 valid rows.
    let rows = (0..=nanosiem_lake_worker::lean_enrichment_snapshot::TENANT_SNAPSHOT_LIMIT_ROWS)
        .map(|i| cidr(&format!("10.{}.{}.{}/32", (i >> 16) & 255, (i >> 8) & 255, i & 255), "US", "x"))
        .collect::<Vec<_>>();
    let response = upload(&a.url, TOKEN_A, TENANT_A, ndjson(&rows)).await;
    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    // Byte cap: a body over 64 MiB.
    let oversized = vec![b' '; nanosiem_lake_worker::lean_enrichment_snapshot::TENANT_SNAPSHOT_LIMIT_BYTES + 1];
    let response = upload(&a.url, TOKEN_A, TENANT_A, oversized).await;
    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(current(&r2, TENANT_A, TENANT_A, &dir.path().join("check")).await.unwrap(), None);
}

#[tokio::test]
async fn tenant_b_cannot_read_or_affect_tenant_a_context() {
    let dir = tempfile::tempdir().unwrap();
    let r2 = dir.path().join("r2");
    let a = coordinator(&r2, &dir.path().join("a"), TENANT_A, TOKEN_A).await;
    let b = coordinator(&r2, &dir.path().join("b"), TENANT_B, TOKEN_B).await;
    let published = upload(&a.url, TOKEN_A, TENANT_A, ndjson(&[cidr("8.8.8.0/24", "CA", "tenant-a")])).await;
    assert_eq!(published.status(), 200);
    let body: Value = published.json().await.unwrap();
    assert_eq!(body["tenant_id"], TENANT_A);
    let revision_a = body["result"]["snapshot_id"].as_str().unwrap().to_string();

    // B's credential cannot write through A's coordinator, nor can A's be
    // pointed at B's tenant identity.
    let wrong_token = upload(&a.url, TOKEN_B, TENANT_A, ndjson(&[cidr("8.8.8.0/24", "RU", "b")])).await;
    assert_eq!(wrong_token.status(), reqwest::StatusCode::UNAUTHORIZED);
    let wrong_tenant = upload(&a.url, TOKEN_A, TENANT_B, ndjson(&[cidr("8.8.8.0/24", "RU", "b")])).await;
    assert_eq!(wrong_tenant.status(), reqwest::StatusCode::BAD_REQUEST);
    let stats = reqwest::Client::new()
        .get(format!("{}/v1/ip-context/stats", a.url))
        .bearer_auth(TOKEN_B)
        .query(&[("tenant_id", TENANT_A)])
        .send()
        .await
        .unwrap();
    assert_eq!(stats.status(), reqwest::StatusCode::UNAUTHORIZED);
    let delete = reqwest::Client::new()
        .delete(format!("{}/v1/ip-context/sources/tenant-cmdb", b.url))
        .bearer_auth(TOKEN_B)
        .json(&json!({"tenant_id": TENANT_A}))
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), reqwest::StatusCode::BAD_REQUEST);

    // B publishing the same CIDR lands only under B's prefix.
    let published_b = upload(&b.url, TOKEN_B, TENANT_B, ndjson(&[cidr("8.8.8.0/24", "RU", "tenant-b")])).await;
    assert_eq!(published_b.status(), 200);
    let scratch = dir.path().join("readers");
    assert_eq!(current(&r2, TENANT_A, TENANT_A, &scratch.join("a")).await.unwrap(), Some(revision_a.clone()));
    // A process bound to A cannot adopt B's pointer, even given B's prefix.
    assert!(current(&r2, TENANT_A, TENANT_B, &scratch.join("x")).await.is_err());
    assert!(current(&r2, TENANT_B, TENANT_A, &scratch.join("y")).await.is_err());
    // A's pinned snapshot still resolves to A's context.
    let objects = LocalObjectStore::new(tenant_prefix(&r2, TENANT_A)).unwrap();
    let reader = LeanIpContextSnapshots::new(TENANT_A.parse().unwrap(), &objects, &scratch.join("a2")).unwrap();
    let pointer = reader.current().await.unwrap().unwrap();
    let hit = reader.load(&pointer).await.unwrap().lookup("8.8.8.8").unwrap().unwrap();
    assert_eq!(hit.country_code.as_deref(), Some("CA"));
    assert_eq!(hit.as_name.as_deref(), Some("tenant-a"));
    let stats: Value = reqwest::Client::new()
        .get(format!("{}/v1/ip-context/stats", a.url))
        .bearer_auth(TOKEN_A)
        .query(&[("tenant_id", TENANT_A)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stats["result"]["total_networks"], 1);
    assert_eq!(stats["result"]["snapshot_sha256"], pointer.sha256);
}

// --- ingest fixture -------------------------------------------------------

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-ipctx-0001", SigningKey::from_bytes(&[7; 32])).unwrap()
}

fn event(uid: &str, time_s: i64, ip: &str) -> Value {
    // Same OCSF shape as the NAN-2868 ingest fixture.
    let time = chrono::DateTime::from_timestamp(time_s, 0).unwrap();
    let raw = format!("raw {uid} logon");
    json!({
        "activity_id": 1, "activity_name": "Logon",
        "actor": {"user": {"name": "USER1"}},
        "category_name": "Identity & Access Management", "category_uid": 3,
        "class_name": "Authentication", "class_uid": 3002,
        "message": format!("Failed logon for user1 from {ip}"),
        "raw_data": raw, "raw_data_size": raw.len(),
        "metadata": {"log_name": "security", "log_source": "WINDOWS_EVENT",
            "product": {"name": "fixture", "vendor_name": "nano"},
            "tenant_uid": TENANT_A, "uid": uid, "version": "1.9.0"},
        "severity": "Informational", "severity_id": 1,
        "src_endpoint": {"ip": ip, "hostname": "ws-1.corp.local"},
        "dst_endpoint": {"ip": "192.168.1.1"},
        "user": {"name": "user1", "uid": "S-1-5-21-1"},
        "status": "Failure", "status_id": 2, "time": time.to_rfc3339(), "type_uid": 300201
    })
}

fn write_bronze(path: &Path, events: &[Value]) {
    let json = ndjson(events);
    let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(json.clone()), None).unwrap();
    let reader = ReaderBuilder::new(Arc::new(schema)).build(Cursor::new(json)).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        let w = writer.get_or_insert_with(|| {
            ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap()
        });
        w.write(&batch).unwrap();
    }
    writer.unwrap().close().unwrap();
}

fn notice(key: &str, at_s: i64) -> SourceNotice {
    SourceNotice {
        tenant_id: TENANT_A.into(),
        key: key.into(),
        version: "1".into(),
        bytes: 0,
        sha256: None,
        edge_sha256: None,
        notified_at_ms: at_s * 1_000,
    }
}

/// (source_id stamped on src_endpoint.location.provider, country) per uid,
/// plus the `ip_context` feed pin, for every live part.
async fn stamped(parts: &LocalObjectStore, trusted: &nanosiem_lake_worker::parts::provenance::TenantKeySet)
    -> Vec<(Option<String>, Vec<(String, Value)>)> {
    let set = load_log(parts, TENANT_A).await.unwrap();
    let mut out = Vec::new();
    for part in set.parts() {
        let keys = PartKeys::new(TENANT_A, part.level, part.event_hour, &part.part_id).unwrap();
        let provenance = parts.get(&keys.provenance()).await.unwrap().unwrap();
        let signed = SignedProvenance::verify_bytes(&provenance, TENANT_A, trusted).unwrap();
        let pin = signed.record.admission.as_ref().unwrap().feed_pins["ip_context"].clone();
        let mut rows = Vec::new();
        for index in 0..part.data_files as usize {
            let data = parts.get(&keys.data(index)).await.unwrap().unwrap();
            let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(data)).unwrap().build().unwrap();
            for batch in reader {
                let mut json = arrow_json::LineDelimitedWriter::new(Vec::new());
                json.write(&batch.unwrap()).unwrap();
                json.finish().unwrap();
                for line in json.into_inner().split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                    let row: Value = serde_json::from_slice(line).unwrap();
                    rows.push((row["metadata"]["uid"].as_str().unwrap().to_string(), row["src_endpoint"].clone()));
                }
            }
        }
        out.push((pin, rows));
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_then_next_part_is_stamped_with_the_tenant_context() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let r2 = root.join("r2");
    let a = coordinator(&r2, &root.join("coord-a"), TENANT_A, TOKEN_A).await;
    let b = coordinator(&r2, &root.join("coord-b"), TENANT_B, TOKEN_B).await;
    // Tenant B's context for the same address must never reach A's events.
    assert_eq!(upload(&b.url, TOKEN_B, TENANT_B, ndjson(&[cidr("203.0.113.0/24", "RU", "tenant-b")])).await.status(), 200);

    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let first_at = DAY0_S + 2_400;
    let second_at = DAY0_S + 2_460;
    write_bronze(&sources_dir.join("bronze/first.parquet"), &[event("uid-before", first_at - 5, "203.0.113.9")]);
    write_bronze(&sources_dir.join("bronze/second.parquet"), &[event("uid-after", second_at - 5, "203.0.113.9")]);
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT_A).unwrap();
    let signer = signer();
    let trusted = signer.trusted();
    let mut cfg = IngestConfig::new(TENANT_A, root.join("work"));
    cfg.flush_interval_override_ms = Some(10_000);

    // Ingest reads A's prefix with A's identity, as the cell does.
    let enrichment = LocalObjectStore::new(tenant_prefix(&r2, TENANT_A)).unwrap();
    let reader = LeanIpContextSnapshots::new(TENANT_A.parse().unwrap(), &enrichment, &root.join("ingest-cache")).unwrap();
    assert!(reader.current().await.unwrap().is_none(), "B's upload must not create A's pointer");
    let mut ingestor = Ingestor::open(
        cfg, &parts, &sources, &spool, &signer, trusted.clone(),
        BronzeIngestEnricher::new(None, None, None), &seed_schema(), first_at * 1_000,
    ).await.unwrap();
    spool.deliver(&notice("bronze/first.parquet", first_at)).unwrap();
    ingestor.tick(first_at * 1_000).await.unwrap();
    ingestor.flush_now(first_at * 1_000 + 1).await.unwrap();

    // The tenant uploads; the refresh sees a new revision and rotates.
    let response = upload(&a.url, TOKEN_A, TENANT_A, ndjson(&[cidr("203.0.113.0/24", "CA", "tenant-a")])).await;
    assert_eq!(response.status(), 200);
    let pointer = reader.current().await.unwrap().expect("published revision");
    let snapshot = reader.load(&pointer).await.unwrap();
    ingestor.replace_enricher(BronzeIngestEnricher::new(None, None, Some(snapshot)), None, second_at * 1_000).await.unwrap();
    spool.deliver(&notice("bronze/second.parquet", second_at)).unwrap();
    ingestor.tick(second_at * 1_000).await.unwrap();
    ingestor.flush_now(second_at * 1_000 + 1).await.unwrap();

    let parts_seen = stamped(&parts, &trusted).await;
    let mut before = None;
    let mut after = None;
    for (pin, rows) in &parts_seen {
        for (uid, endpoint) in rows {
            match uid.as_str() {
                "uid-before" => before = Some((pin.clone(), endpoint.clone())),
                "uid-after" => after = Some((pin.clone(), endpoint.clone())),
                _ => {}
            }
        }
    }
    let (before_pin, before) = before.expect("first part");
    let (after_pin, after) = after.expect("next part");
    assert_eq!(before_pin, None);
    assert!(before.get("location").is_none() || before["location"].is_null(), "{before}");
    assert_eq!(after_pin.as_deref(), Some(pointer.sha256.as_str()));
    assert_eq!(after["location"]["country"], "CA", "{after}");
    assert_eq!(after["location"]["provider"], "tenant-cmdb", "{after}");
    assert_eq!(after["autonomous_system"]["name"], "tenant-a", "{after}");
}

/// NAN-3009: exercise the app service against the real coordinator and store,
/// with no database connection, environment mutation, or global credential.
#[tokio::test]
async fn request_scoped_service_upload_delete_stats_publish_only_own_prefix() {
    use nanosiem_core::auth::TrustedTenantContext;
    use nanosiem_core::enrichment::lake_ip_context::{LakeIpContextInput, LakeIpContextResolver};
    use nanosiem_core::enrichment::{EnrichmentRepository, EnrichmentService};
    let root = tempfile::tempdir().unwrap();
    let r2 = root.path().join("r2");
    let a = coordinator(&r2, &root.path().join("a"), TENANT_A, TOKEN_A).await;
    let b = coordinator(&r2, &root.path().join("b"), TENANT_B, TOKEN_B).await;
    let token_a = root.path().join("a.token");
    let token_b = root.path().join("b.token");
    std::fs::write(&token_a, TOKEN_A).unwrap();
    std::fs::write(&token_b, TOKEN_B).unwrap();
    let assignments = root.path().join("assignments.json");
    std::fs::write(&assignments, serde_json::to_vec(&json!({
        (TENANT_A): {"internal_endpoint": a.url, "credential_file": token_a, "timeout_secs": 30},
        (TENANT_B): {"internal_endpoint": b.url, "credential_file": token_b, "timeout_secs": 30}
    })).unwrap()).unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://nano:nano@127.0.0.1:1/nano").unwrap();
    let service = EnrichmentService::with_defaults(EnrichmentRepository::new(pool))
        .with_ipinfo_mmdb(root.path().join("absent.mmdb"), None, false).unwrap()
        .with_request_ip_context(LakeIpContextResolver::new(Some(assignments.clone())));
    let who_a = TrustedTenantContext { tenant_id: TENANT_A.parse().unwrap(), tenant_slug: TENANT_B.into() };
    let who_b = TrustedTenantContext { tenant_id: TENANT_B.parse().unwrap(), tenant_slug: TENANT_A.into() };
    let row_a: LakeIpContextInput = serde_json::from_value(cidr("203.0.113.0/24", "CA", "tenant-a")).unwrap();
    let row_b: LakeIpContextInput = serde_json::from_value(cidr("203.0.113.0/24", "RU", "tenant-b")).unwrap();
    assert_eq!(service.upload_ip_context_batch(&who_a, &[row_a.clone()]).await.unwrap(), 1);
    assert!(tenant_prefix(&r2, TENANT_A).join("ip_context/current.json").exists());
    assert!(!tenant_prefix(&r2, TENANT_B).join("ip_context/current.json").exists());
    let pointer_a = std::fs::read(tenant_prefix(&r2, TENANT_A).join("ip_context/current.json")).unwrap();
    assert_eq!(service.upload_ip_context_batch(&who_b, &[row_b]).await.unwrap(), 1);
    assert_eq!(service.ip_context_stats(&who_a).await.unwrap().total_networks, 1);
    assert_eq!(service.ip_context_stats(&who_b).await.unwrap().total_networks, 1);
    let pointer_b = std::fs::read(tenant_prefix(&r2, TENANT_B).join("ip_context/current.json")).unwrap();
    // Request rows have no tenant selector, and unknown tenant fields fail parsing.
    let mut injected = cidr("203.0.113.0/24", "RU", "attacker");
    injected["tenant_id"] = json!(TENANT_B);
    assert!(serde_json::from_value::<LakeIpContextInput>(injected).is_err());
    // A's bearer combined with B's body identity is refused by the coordinator.
    assert_eq!(upload(&a.url, TOKEN_A, TENANT_B, ndjson(&[cidr("203.0.113.0/24", "RU", "attacker")])).await.status(), 400);
    assert_eq!(std::fs::read(tenant_prefix(&r2, TENANT_A).join("ip_context/current.json")).unwrap(), pointer_a);
    service.delete_ip_context_source(&who_a, "tenant-cmdb").await.unwrap();
    assert_eq!(service.ip_context_stats(&who_a).await.unwrap().total_networks, 0);
    assert_eq!(service.ip_context_stats(&who_b).await.unwrap().total_networks, 1);
    assert_eq!(std::fs::read(tenant_prefix(&r2, TENANT_B).join("ip_context/current.json")).unwrap(), pointer_b);
    // Shared lookup is still local MMDB only; it never calls lean /lookup.
    assert!(service.lookup_ip("203.0.113.9").await.unwrap().is_none());
    std::fs::write(&assignments, b"{}").unwrap();
    assert!(service.upload_ip_context_batch(&who_a, &[row_a]).await.is_err());
    assert!(service.delete_ip_context_source(&who_a, "tenant-cmdb").await.is_err());
    assert!(service.ip_context_stats(&who_a).await.is_err());
    assert_eq!(std::fs::read(tenant_prefix(&r2, TENANT_B).join("ip_context/current.json")).unwrap(), pointer_b);
}
