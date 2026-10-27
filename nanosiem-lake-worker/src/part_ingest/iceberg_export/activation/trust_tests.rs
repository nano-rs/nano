// SPDX-License-Identifier: AGPL-3.0-or-later
//! Default lake-worker unit tests: generated PKI, loopback TLS, no credentials.
use super::*;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Ca(CertifiedIssuer<'static, KeyPair>);
impl Ca {
    fn new() -> Self {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        Self(CertifiedIssuer::self_signed(p, KeyPair::generate().unwrap()).unwrap())
    }
    fn trust(&self) -> PlatformTrust {
        PlatformTrust {
            additional_ca: Some(self.0.pem()),
        }
    }
}

struct Server {
    url: String,
    task: tokio::task::JoinHandle<()>,
    status: Arc<std::sync::atomic::AtomicU16>,
    body: Arc<RwLock<String>>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    delay_ms: Arc<std::sync::atomic::AtomicU64>,
    requests: Arc<RwLock<Vec<String>>>,
    /// Request bodies (control POST ops), in arrival order.
    bodies: Arc<RwLock<Vec<String>>>,
}
impl Server {
    /// The `op` of every control POST seen so far.
    fn ops(&self) -> Vec<String> {
        self.bodies
            .read()
            .unwrap()
            .iter()
            .filter_map(|b| serde_json::from_str::<Value>(b).ok())
            .filter_map(|v| v["op"].as_str().map(str::to_string))
            .collect()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn server(ca: &Ca, san: &str, status: u16, body: String) -> Server {
    use std::sync::atomic::Ordering::SeqCst;
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![san.into()])
        .unwrap()
        .signed_by(&key, &ca.0)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let status = Arc::new(std::sync::atomic::AtomicU16::new(status));
    let body = Arc::new(RwLock::new(body));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let delay_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let requests = Arc::new(RwLock::new(Vec::new()));
    let bodies = Arc::new(RwLock::new(Vec::new()));
    let state = (
        status.clone(),
        body.clone(),
        calls.clone(),
        delay_ms.clone(),
        requests.clone(),
        bodies.clone(),
    );
    let task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let (status, body, calls, delay_ms, requests, bodies) = state.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buffer = [0u8; 8192];
                let mut read = Vec::new();
                loop {
                    let Ok(n) = tls.read(&mut buffer).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    read.extend_from_slice(&buffer[..n]);
                    if read.windows(4).any(|b| b == b"\r\n\r\n") {
                        break;
                    }
                    if read.len() > 65536 {
                        return;
                    }
                }
                let head_end = read.windows(4).position(|b| b == b"\r\n\r\n").unwrap() + 4;
                let head = String::from_utf8_lossy(&read[..head_end]).to_string();
                let length = head
                    .lines()
                    .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                    .unwrap_or(0);
                while read.len() < head_end + length {
                    let Ok(n) = tls.read(&mut buffer).await else { return };
                    if n == 0 { break }
                    read.extend_from_slice(&buffer[..n]);
                }
                requests.write().unwrap().push(head.lines().next().unwrap().to_string());
                bodies.write().unwrap().push(String::from_utf8_lossy(&read[head_end..]).to_string());
                calls.fetch_add(1, SeqCst);
                tokio::time::sleep(Duration::from_millis(delay_ms.load(SeqCst))).await;
                let status = status.load(SeqCst);
                let body = body.read().unwrap().clone();
                let location = if status == 302 {
                    "Location: http://127.0.0.1:1/must-not-follow\r\n"
                } else {
                    ""
                };
                let response = format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    Server {
        url,
        task,
        status,
        body,
        calls,
        delay_ms,
        requests,
        bodies,
    }
}
fn body(record: &CatalogActivation) -> String {
    json!({"tenant_id":record.tenant_id,"activation_id":record.activation_id,"verified":true})
        .to_string()
}

fn recovery(
    record: &CatalogActivation,
    dir: &Path,
    server: &Server,
    ca: &Ca,
) -> Arc<super::recovery::CatalogRecovery> {
    Arc::new(
        super::recovery::CatalogRecovery::new(
            record,
            &record.tenant_id,
            dir,
            &server.url,
            "cell-a",
            ca.trust(),
        )
        .unwrap(),
    )
}
async fn elapse(seconds: u64) {
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(seconds)).await;
    tokio::time::resume();
}
async fn calls(server: &Server, expected: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while server.calls.load(std::sync::atomic::Ordering::SeqCst) < expected {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn catalog_attach_recovery_transient_failure_then_one_verified_restart() {
    use std::sync::atomic::Ordering::SeqCst;
    let ca = Ca::new();
    let r = super::tests::record();
    let server = server(
        &ca,
        "localhost",
        503,
        json!({"defaults":{},"overrides":{}}).to_string(),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let recovery = recovery(&r, dir.path(), &server, &ca);
    assert!(!recovery.try_restart().await);
    assert_eq!(
        server.calls.load(SeqCst),
        0,
        "no immediate probe/restart after startup"
    );
    let task = tokio::spawn({
        let recovery = recovery.clone();
        async move { recovery.wait_for_restart().await }
    });
    tokio::task::yield_now().await;
    elapse(299).await;
    assert_eq!(server.calls.load(SeqCst), 0);
    elapse(1).await;
    calls(&server, 1).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !task.is_finished(),
        "503 keeps ingest running in degraded mode"
    );
    server.status.store(200, SeqCst);
    elapse(300).await;
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(server.calls.load(SeqCst), 2);
    elapse(300).await;
    assert!(
        !recovery.try_restart().await,
        "one restart signal per process"
    );
    let requests = server.requests.read().unwrap();
    assert!(requests.iter().all(|line| line.starts_with(&format!(
        "GET /v1/lake/cells/cell-a/agent-catalog/{}/{}/v1/config?warehouse={}_{} ",
        r.tenant_id, r.activation_id, r.account_id, r.bucket
    ))));
    assert_eq!(
        server.calls.load(SeqCst),
        2,
        "no attach, control POST, or provider mutation"
    );
}

#[tokio::test]
async fn catalog_attach_recovery_hung_probe_deadline_and_single_flight() {
    use std::sync::atomic::Ordering::SeqCst;
    let ca = Ca::new();
    let r = super::tests::record();
    let server = server(
        &ca,
        "localhost",
        200,
        json!({"defaults":{},"overrides":{}}).to_string(),
    )
    .await;
    server.delay_ms.store(60_000, SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let recovery = recovery(&r, dir.path(), &server, &ca);
    elapse(300).await;
    let task = tokio::spawn({
        let recovery = recovery.clone();
        async move { recovery.try_restart().await }
    });
    calls(&server, 1).await;
    assert!(
        !recovery.try_restart().await,
        "no concurrent probe can enter"
    );
    elapse(21).await;
    assert!(!tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap());
    assert!(
        !recovery.try_restart().await,
        "timeout retains the five-minute cooldown"
    );
    assert_eq!(server.calls.load(SeqCst), 1);
}

#[tokio::test]
async fn catalog_attach_recovery_rejects_stale_proof_after_credential_refresh() {
    use std::sync::atomic::Ordering::SeqCst;
    let ca = Ca::new();
    let r = super::tests::record();
    let server = server(
        &ca,
        "localhost",
        200,
        json!({"defaults":{},"overrides":{}}).to_string(),
    )
    .await;
    server.delay_ms.store(200, SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let recovery = recovery(&r, dir.path(), &server, &ca);
    elapse(300).await;
    let task = tokio::spawn({
        let recovery = recovery.clone();
        async move { recovery.try_restart().await }
    });
    calls(&server, 1).await;
    let mut fresh = r.clone();
    fresh.control_token = "refreshed-scoped-control-fixture-token".into();
    recovery.refresh(Some(&fresh)).unwrap();
    assert!(
        !task.await.unwrap(),
        "old in-flight proof cannot trigger restart"
    );
    server.delay_ms.store(0, SeqCst);
    elapse(300).await;
    assert!(
        recovery.try_restart().await,
        "fresh credential can qualify a later probe"
    );
}

#[tokio::test]
async fn catalog_attach_recovery_refuses_foreign_expired_or_replaced_bindings_before_io() {
    let ca = Ca::new();
    let r = super::tests::record();
    let server = server(
        &ca,
        "localhost",
        200,
        json!({"defaults":{},"overrides":{}}).to_string(),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let new = |record: &CatalogActivation, tenant: &str| {
        super::recovery::CatalogRecovery::new(
            record,
            tenant,
            dir.path(),
            &server.url,
            "cell-a",
            ca.trust(),
        )
    };
    assert!(new(&r, "00000000-0000-4000-8000-000000000002").is_err());
    let mut expired = r.clone();
    expired.expires_at = 0;
    assert!(new(&expired, &r.tenant_id).is_err());
    let recovery = new(&r, &r.tenant_id).unwrap();
    let mut foreign = r.clone();
    foreign.tenant_id = "00000000-0000-4000-8000-000000000002".into();
    assert!(recovery.refresh(Some(&foreign)).is_err());
    assert!(recovery.refresh(Some(&expired)).is_err());
    let mut changed = r.clone();
    changed.activation_id = uuid::Uuid::new_v4();
    assert!(recovery.refresh(Some(&changed)).is_err());
    changed = r.clone();
    changed.installation_sha256 = "c".repeat(64);
    assert!(recovery.refresh(Some(&changed)).is_err());
    assert!(recovery.refresh(None).is_err());
    assert_eq!(server.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn catalog_attach_recovery_refuses_redirect_untrusted_tls_and_response_drift() {
    use std::sync::atomic::Ordering::SeqCst;
    let ca = Ca::new();
    let r = super::tests::record();
    let server = server(
        &ca,
        "localhost",
        302,
        json!({"defaults":{},"overrides":{}}).to_string(),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let recovery = recovery(&r, dir.path(), &server, &ca);
    elapse(300).await;
    assert!(!recovery.try_restart().await);
    server.status.store(200, SeqCst);
    for invalid in [
        json!({"tenant_id":"foreign","verified":true}).to_string(),
        json!({"defaults":{"token":"must-not-log-fixture-secret"},"overrides":{}}).to_string(),
        "x".repeat(4097),
    ] {
        *server.body.write().unwrap() = invalid;
        elapse(300).await;
        assert!(!recovery.try_restart().await);
    }
    *server.body.write().unwrap() = json!({"defaults":{},"overrides":{}}).to_string();
    let untrusted = super::recovery::CatalogRecovery::new(
        &r,
        &r.tenant_id,
        dir.path(),
        &server.url,
        "cell-a",
        PlatformTrust::default(),
    )
    .unwrap();
    elapse(300).await;
    assert!(!untrusted.try_restart().await);
    assert_eq!(
        server.calls.load(SeqCst),
        4,
        "TLS failure reaches no HTTP handler"
    );
}

#[tokio::test]
async fn catalog_attach_recovery_cancellation_stops_periodic_work() {
    use std::sync::atomic::Ordering::SeqCst;
    let ca = Ca::new();
    let r = super::tests::record();
    let server = server(&ca, "localhost", 503, "{}".into()).await;
    let dir = tempfile::tempdir().unwrap();
    let recovery = recovery(&r, dir.path(), &server, &ca);
    let task = tokio::spawn(async move { recovery.wait_for_restart().await });
    tokio::task::yield_now().await;
    elapse(300).await;
    calls(&server, 1).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    elapse(900).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(server.calls.load(SeqCst), 1);
}

#[test]
fn catalog_attach_recovery_error_classes_are_value_free() {
    assert_eq!(
        attachment_error_class(&anyhow::anyhow!(
            "must-not-log-fixture-secret https://private.invalid"
        )),
        "catalog"
    );
    assert_eq!(
        attachment_error_class(&std::io::Error::from(std::io::ErrorKind::TimedOut).into()),
        "timeout"
    );
    assert_eq!(
        attachment_error_class(
            &rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer).into()
        ),
        "tls"
    );
}

#[tokio::test]
async fn catalog_attach_trust_platform_chain_and_iceberg_transport() {
    let ca = Ca::new();
    let r = super::tests::record();
    let server = server(&ca, "localhost", 200, body(&r)).await;
    let dir = tempfile::tempdir().unwrap();
    // The actual attachment constructor and maintenance request; only public
    // PKI is represented by generated roots instead of the Internet CA set.
    let c = Control::new(
        &r,
        &r.tenant_id,
        dir.path(),
        &server.url,
        "cell-a",
        ca.trust(),
    )
    .unwrap();
    c.verify_manual_maintenance(&iceberg::TableIdent::from_strs(["agent", "events_v1"]).unwrap())
        .await
        .unwrap();
    let response = c
        .tls
        .iceberg_client()
        .unwrap()
        .get(&server.url)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
}

#[tokio::test]
async fn catalog_attach_trust_unrelated_root_and_hostname_are_refused() {
    let ca = Ca::new();
    let other = Ca::new();
    let r = super::tests::record();
    for (san, trust) in [
        ("localhost", other.trust()),
        ("wrong.example.invalid", ca.trust()),
    ] {
        let server = server(&ca, san, 200, body(&r)).await;
        let dir = tempfile::tempdir().unwrap();
        let c = Control::new(&r, &r.tenant_id, dir.path(), &server.url, "cell-a", trust).unwrap();
        assert!(c.call("verify_maintenance").await.is_err());
        assert!(c
            .tls
            .iceberg_client()
            .unwrap()
            .get(&server.url)
            .send()
            .await
            .is_err());
    }
}

#[tokio::test]
async fn catalog_attach_trust_redirect_is_not_followed() {
    let ca = Ca::new();
    let r = super::tests::record();
    let server = server(&ca, "localhost", 302, body(&r)).await;
    let dir = tempfile::tempdir().unwrap();
    let c = Control::new(
        &r,
        &r.tenant_id,
        dir.path(),
        &server.url,
        "cell-a",
        ca.trust(),
    )
    .unwrap();
    assert!(c.call("verify_maintenance").await.is_err());
    assert_eq!(
        c.tls
            .client()
            .get(&server.url)
            .send()
            .await
            .unwrap()
            .status(),
        302
    );
    assert_eq!(
        c.tls
            .iceberg_client()
            .unwrap()
            .get(&server.url)
            .send()
            .await
            .unwrap()
            .status(),
        302
    );
}

#[tokio::test]
async fn catalog_attach_trust_cross_tenant_refused_before_io() {
    let r = super::tests::record();
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("must-not-exist");
    assert!(Control::new(
        &r,
        "00000000-0000-4000-8000-000000000002",
        &work,
        "invalid",
        "cell-a",
        PlatformTrust::default()
    )
    .is_err());
    assert!(!work.exists());
}

#[tokio::test]
async fn catalog_attach_trust_failed_attachment_keeps_ingest_running() {
    use crate::enrichment::BronzeIngestEnricher;
    use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
    use crate::parts::{
        part_log::{load_log, LocalObjectStore},
        provenance::LocalPartSigner,
    };
    let ca = Ca::new();
    let r = super::tests::record();
    let server = server(&ca, "localhost", 200, body(&r)).await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = IngestConfig::new(&r.tenant_id, dir.path().join("ingest"));
    cfg.prevalence_enabled = false;
    cfg.flush_interval_override_ms = Some(1000);
    let mut source = r.metadata.clone();
    source.prefix.clear();
    // Production roots intentionally do not trust this generated platform CA.
    // Failure occurs at maintenance TLS, before any S3/network/live access.
    let attached = attach_for_ingest(
        &mut cfg,
        Some(&r),
        &dir.path().join("catalog"),
        &source,
        &source,
        TenantKeySet::default(),
        &server.url,
        "cell-a",
    )
    .await
    .unwrap();
    assert!(attached.runtime().is_none());
    assert!(
        attached.recovery().is_some(),
        "actual degraded startup schedules recovery"
    );
    assert_eq!(
        cfg.catalog_attachment_failure,
        Some("catalog_attach_failed")
    );
    attached.refresh(Some(&r)).unwrap(); // ordinary refresh cannot respawn it
    let parts = LocalObjectStore::new(dir.path().join("parts")).unwrap();
    let sources = LocalObjectStore::new(dir.path().join("sources")).unwrap();
    let queue = SpoolQueue::new(dir.path().join("spool"), &r.tenant_id).unwrap();
    let signer = LocalPartSigner::new(
        "lab-signer-nan4534",
        ed25519_dalek::SigningKey::from_bytes(&[3; 32]),
    )
    .unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    let mut ingest = Ingestor::open(
        cfg,
        &parts,
        &sources,
        &queue,
        &signer,
        signer.trusted(),
        BronzeIngestEnricher::disabled(),
        &crate::part_ingest::ingest::seed_schema(),
        now,
    )
    .await
    .unwrap();
    let event = json!({
        "time":chrono::Utc::now().to_rfc3339(),"class_uid":3002,"class_name":"Authentication",
        "category_uid":3,"category_name":"Identity & Access Management","activity_id":1,"activity_name":"Logon",
        "type_uid":300201,"severity":"Informational","severity_id":1,"user":{"name":"fixture"},
        "actor":{"user":{"name":"fixture-service"}},"src_endpoint":{"ip":"10.0.0.1"},"dst_endpoint":{"ip":"192.168.1.1"},
        "message":"fixture event","raw_data_size":11,"raw_data":"fixture row","status":"Success","status_id":1,
        "unmapped":{"note":"fixture note"},
        "metadata":{"uid":format!("{}-0-00000",r.tenant_id),"version":"1.9.0","log_name":"security",
            "log_source":"WINDOWS_EVENT","tenant_uid":r.tenant_id,"product":{"name":"fixture","vendor_name":"nano"}}
    });
    let bytes = serde_json::to_vec(&event).unwrap();
    let (schema, _) = arrow_json::reader::infer_json_schema_from_seekable(
        &mut std::io::Cursor::new(bytes.clone()),
        None,
    )
    .unwrap();
    let reader = arrow_json::ReaderBuilder::new(Arc::new(schema))
        .build(std::io::Cursor::new(bytes))
        .unwrap();
    let path = dir.path().join("sources/one.parquet");
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        writer
            .get_or_insert_with(|| {
                parquet::arrow::ArrowWriter::try_new(
                    std::fs::File::create(&path).unwrap(),
                    batch.schema(),
                    None,
                )
                .unwrap()
            })
            .write(&batch)
            .unwrap();
    }
    writer.unwrap().close().unwrap();
    queue
        .deliver(&SourceNotice {
            tenant_id: r.tenant_id.clone(),
            key: "one.parquet".into(),
            version: "1".into(),
            bytes: std::fs::metadata(path).unwrap().len(),
            sha256: None,
            edge_sha256: None,
            notified_at_ms: now,
        })
        .unwrap();
    let gc = Arc::new(GcMustNotRun(std::sync::atomic::AtomicUsize::new(0)));
    ingest.set_part_gc_authority(gc.clone());
    let ledger = Arc::new(ErasureMustNotRun(std::sync::atomic::AtomicUsize::new(0)));
    ingest.set_erasure_ledger_fixed(ledger.clone(), "fixture".into());
    let report = ingest.tick(now + 1000).await.unwrap();
    assert_eq!(
        report.admitted_rows,
        1,
        "report={report:?}; health={:?}",
        ingest.health()
    );
    ingest.flush_now(now + 2000).await.unwrap();
    elapse(300).await;
    assert!(
        !attached.recovery().unwrap().try_restart().await,
        "a failed bounded probe cannot restart ingest"
    );
    ingest.tick(now + 3000).await.unwrap();
    assert!(
        queue.pending(1).await.unwrap().is_empty(),
        "normal source acknowledged"
    );
    assert_eq!(
        load_log(&parts, &r.tenant_id)
            .await
            .unwrap()
            .parts()
            .map(|p| p.rows)
            .sum::<u64>(),
        1
    );
    assert_eq!(
        gc.0.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "catalog failure holds physical GC"
    );
    assert_eq!(
        ledger.0.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "catalog failure holds erasure"
    );
    assert_eq!(
        ingest.health().agent_catalog.as_ref().unwrap()["degraded"],
        true
    );
    assert_eq!(
        ingest.health().agent_catalog.as_ref().unwrap()["converged"],
        false
    );
    assert!(load_log(&parts, &r.tenant_id)
        .await
        .unwrap()
        .head()
        .is_some());
}

struct GcMustNotRun(std::sync::atomic::AtomicUsize);
#[async_trait::async_trait]
impl crate::part_ingest::part_gc_gate::PartGcAuthority for GcMustNotRun {
    async fn decision(&self, _: i64) -> Result<crate::part_ingest::part_gc_gate::PartGcDecision> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        panic!("physical GC must stay held while catalog attachment is degraded")
    }
}
struct ErasureMustNotRun(std::sync::atomic::AtomicUsize);
#[async_trait::async_trait]
impl crate::part_ingest::lean_erasure::ErasureLedger for ErasureMustNotRun {
    async fn claim(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<crate::part_ingest::lean_erasure::LeanErasureOrder>> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        panic!("erasure must stay held while catalog attachment is degraded")
    }
    async fn record_step(
        &self,
        _: &str,
        _: &str,
        _: &crate::part_ingest::lean_erasure::LeanErasureOrder,
        _: &crate::part_ingest::lean_erasure::StepRecord,
    ) -> Result<()> {
        panic!("erasure held")
    }
    async fn complete(
        &self,
        _: &str,
        _: &str,
        _: &crate::part_ingest::lean_erasure::LeanErasureOrder,
    ) -> Result<()> {
        panic!("erasure held")
    }
    async fn fail(
        &self,
        _: &str,
        _: &str,
        _: &crate::part_ingest::lean_erasure::LeanErasureOrder,
        _: Option<&str>,
        _: &str,
    ) -> Result<()> {
        panic!("erasure held")
    }
}

// ---------------------------------------------------------------------------
// NAN-4543: attach() against R2 credentials scoped exactly as the platform
// mints them (`lake-cell-credentials.ts` `lakeCellCredentialScope`, lean
// ingest): `lake_part` = `parts/` + `log/checkpoints/` + `finding-outbox/
// receipts/`; `lake_part_log` = `log/entries/` only; anything else is 403.
// Production constructors throughout; only the wire endpoint is loopback.
// ---------------------------------------------------------------------------
mod scoped {
    use super::*;
    use crate::part_ingest::r2_put::tests::scoped_r2;
    use crate::r2_ops::test_origin::R2_ORIGIN;

    pub(super) const PART_SCOPE: [&str; 3] = ["parts/", "log/checkpoints/", "finding-outbox/receipts/"];

    pub(super) struct Lake {
        pub origin: String,
        pub state: scoped_r2::Shared,
        pub part: S3Location,
        pub log: S3Location,
    }

    pub(super) fn location(r: &CatalogActivation, access: &str) -> S3Location {
        S3Location {
            endpoint: r.metadata.endpoint.clone(),
            region: "auto".into(),
            bucket: r.bucket.clone(),
            prefix: String::new(),
            access_key_id: access.into(),
            secret_access_key: "fixture-secret".into(),
            session_token: Some("fixture-session".into()),
        }
    }

    /// A tenant lake whose part log was written by ingest's own production
    /// store (`R2PartStore::new_split`): genesis with the real OCSF seed
    /// schema plus a snapshot checkpoint, as every live lean tenant has.
    pub(super) async fn lake(r: &CatalogActivation, dir: &Path, log_scope: &str) -> Lake {
        let tenant = &r.tenant_id;
        let bucket = scoped_r2::Bucket {
            scopes: [
                ("part".to_string(), PART_SCOPE.iter().map(|s| s.to_string()).collect()),
                ("log".to_string(), vec!["log/entries/".to_string()]),
            ]
            .into_iter()
            .collect(),
            tenant_root: format!("lake/parts/v1/tenant={tenant}/"),
            ..Default::default()
        };
        let (addr, state) = scoped_r2::serve(bucket).await;
        let origin = format!("http://{addr}");
        let (part, log) = (location(r, "part"), location(r, "log"));
        R2_ORIGIN
            .scope(origin.clone(), async {
                let store = R2PartStore::new_split(&part, &log, tenant, &dir.join("ingest-spill")).unwrap();
                let now = chrono::Utc::now().timestamp_millis();
                let writer = crate::parts::part_log::PartLogWriter::open(
                    &store,
                    tenant,
                    1,
                    &crate::part_ingest::ingest::seed_schema(),
                    now,
                )
                .await
                .unwrap();
                writer.write_checkpoint(now).await.unwrap();
            })
            .await;
        {
            let mut bucket = state.lock().unwrap();
            assert!(
                bucket.objects.keys().any(|k| k.contains("/log/checkpoints/"))
                    && bucket.objects.keys().any(|k| k.contains("/log/entries/")),
                "fixture log has a checkpoint and an entry"
            );
            bucket.seen.clear();
            // Mis-scope the log credential after seeding when asked.
            bucket.scopes.insert("log".into(), vec![log_scope.to_string()]);
        }
        Lake { origin, state, part, log }
    }

    pub(super) async fn attach_scoped(
        r: &CatalogActivation,
        dir: &Path,
        lake: &Lake,
        server: &Server,
        ca: &Ca,
    ) -> (IngestCatalog, crate::part_ingest::IngestConfig) {
        let mut cfg = crate::part_ingest::IngestConfig::new(&r.tenant_id, dir.join("ingest"));
        let attached = R2_ORIGIN
            .scope(
                lake.origin.clone(),
                attach_for_ingest_with(
                    &mut cfg,
                    Some(r),
                    &dir.join("catalog"),
                    &lake.part,
                    &lake.log,
                    TenantKeySet::default(),
                    &server.url,
                    "cell-a",
                    ca.trust(),
                ),
            )
            .await
            .unwrap();
        (attached, cfg)
    }

    /// Every R2 request since seeding: (access key, method, key).
    pub(super) fn seen(lake: &Lake) -> Vec<(String, &'static str, String)> {
        lake.state.lock().unwrap().seen.clone()
    }
}

#[tokio::test]
async fn catalog_attach_scoped_credentials_reach_close_and_drain() {
    let ca = Ca::new();
    let r = super::tests::record();
    let server = server(&ca, "localhost", 200, body(&r)).await;
    let dir = tempfile::tempdir().unwrap();
    let lake = scoped::lake(&r, dir.path(), "log/entries/").await;
    // Two earlier recovery restarts of this installation (PR C back-off).
    let restarts = dir.path().join("catalog/recovery-restarts.json");
    std::fs::create_dir_all(dir.path().join("catalog")).unwrap();
    std::fs::write(&restarts, json!({"activation_id":r.activation_id,"restarts":2}).to_string()).unwrap();
    let (attached, cfg) = scoped::attach_scoped(&r, dir.path(), &lake, &server, &ca).await;
    assert_eq!(attached.failure, None, "attach must not degrade");
    // Only the platform's writer_attached acknowledgment resets the
    // back-off, so a failing report cannot restart every five minutes.
    assert!(restarts.exists(), "attach alone keeps the back-off");
    attached.mark_attached();
    assert!(!restarts.exists(), "acknowledged attachment clears it");
    let runtime = attached.runtime().expect("custody attached");
    assert!(cfg.catalog.is_some() && cfg.catalog_attachment_failure.is_none());
    assert!(attached.recovery().is_none(), "attached: no recovery probe, no restart");
    // Past verify_maintenance, through schema conversion of the real seed
    // schema, serving backend, custody lock and the installation fence.
    assert_eq!(server.ops(), ["verify_maintenance", "close_and_drain"]);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("catalog/installation-id")).unwrap(),
        r.activation_id.to_string()
    );
    assert!(dir.path().join("catalog/custody/writer.lock").exists());
    assert!(dir.path().join("catalog/custody/reads-closed").exists(), "fenced until the first sync reopens reads");
    // Every R2 request used the credential scoped to its key; none was refused.
    let root = format!("lake/parts/v1/tenant={}/", r.tenant_id);
    let seen = scoped::seen(&lake);
    for (access, method, key) in &seen {
        let want = if key.starts_with(&format!("{root}log/entries/")) { "log" } else { "part" };
        assert_eq!(access, want, "{method} {key} used the wrong credential");
        assert!(
            key.starts_with(&format!("{root}log/")),
            "attach reads only the part log ({method} {key})"
        );
    }
    assert!(seen.iter().any(|(a, m, k)| a == "part" && *m == "LIST" && k.ends_with("/log/checkpoints/")));
    assert!(seen.iter().any(|(a, m, k)| a == "part" && *m == "GET" && k.contains("/log/checkpoints/")));
    assert!(seen.iter().any(|(a, m, k)| a == "log" && *m == "GET" && k.contains("/log/entries/")));
    // CF cost (PR body): the whole attach is this many R2 requests.
    eprintln!("NAN-4543 attach R2 requests: {}: {seen:?}", seen.len());
    assert!(seen.len() <= 4, "attach R2 requests stay O(1): {seen:?}");

    // Later steps: the export source stays on ingest's refreshed credentials
    // (they expire at the exchange TTL) and keeps its per-key routing.
    let part_key = format!("{root}parts/l0/fixture/data-00000.parquet");
    {
        let mut bucket = lake.state.lock().unwrap();
        bucket.objects.insert(part_key.clone(), b"part bytes".to_vec());
        bucket.scopes.remove("part");
        bucket.scopes.remove("log");
        bucket.scopes.insert("part2".into(), scoped::PART_SCOPE.iter().map(|s| s.to_string()).collect());
        bucket.scopes.insert("log2".into(), vec!["log/entries/".into()]);
        bucket.seen.clear();
    }
    use crate::parts::part_log::ObjectStore as _;
    let stale = crate::r2_ops::test_origin::R2_ORIGIN
        .scope(lake.origin.clone(), runtime.parts.object_size(&part_key))
        .await;
    assert!(stale.is_err(), "expired credential is refused by the fake");
    let (part2, log2) = (scoped::location(&r, "part2"), scoped::location(&r, "log2"));
    attached.refresh_parts(Some((&part2, &log2))).unwrap();
    lake.state.lock().unwrap().seen.clear();
    let size = crate::r2_ops::test_origin::R2_ORIGIN
        .scope(lake.origin.clone(), runtime.parts.object_size(&part_key))
        .await
        .unwrap();
    assert_eq!(size, Some(10));
    let entries = crate::r2_ops::test_origin::R2_ORIGIN
        .scope(lake.origin.clone(), load_log(runtime.parts.as_ref(), &r.tenant_id))
        .await
        .unwrap();
    assert!(entries.head().is_some(), "refreshed pair still routes per key");
    assert!(scoped::seen(&lake).iter().all(|(a, _, _)| a == "part2" || a == "log2"));
    // A refreshed pair cannot move the source to another bucket or account.
    let mut foreign = part2.clone();
    foreign.bucket = "nano-shared-r2-00000000-0000-4000-8000-000000000002".into();
    assert!(attached.refresh_parts(Some((&foreign, &log2))).is_err());
    let mut foreign = log2.clone();
    foreign.endpoint = format!("https://{}.r2.cloudflarestorage.com", "c".repeat(32));
    assert!(attached.refresh_parts(Some((&part2, &foreign))).is_err());
    assert!(attached.refresh_parts(None).is_err(), "withdrawn part credentials restart ingest");
    // A live writer keeps the custody lock: a second attach in this
    // process life is refused at custody_lock (no double custody).
    let (second, _) = scoped::attach_scoped(&r, dir.path(), &scoped::Lake {
        origin: lake.origin.clone(), state: lake.state.clone(), part: part2.clone(), log: log2.clone(),
    }, &server, &ca).await;
    assert_eq!(second.failure, Some(("custody_lock", "io")));
    // Restarting the same installation (previous process gone) does not re-fence.
    drop(attached);
    drop(cfg);
    let (again, _) = scoped::attach_scoped(&r, dir.path(), &scoped::Lake {
        origin: lake.origin.clone(), state: lake.state.clone(), part: part2.clone(), log: log2.clone(),
    }, &server, &ca).await;
    assert_eq!(again.failure, None);
    assert_eq!(server.ops(), ["verify_maintenance", "close_and_drain", "verify_maintenance", "verify_maintenance"]);
}

/// The large-tenant incident: the old wiring loaded the log through a store on the
/// `lake_part_log` credential alone. Its first request (LIST log/checkpoints/)
/// is a 403 that is never retried; attach must name the stage and class.
#[tokio::test]
async fn catalog_attach_old_log_only_store_fails_at_part_log_load_permission_denied() {
    let ca = Ca::new();
    let r = super::tests::record();
    let dir = tempfile::tempdir().unwrap();
    let lake = scoped::lake(&r, dir.path(), "log/entries/").await;
    let old_wiring = crate::r2_ops::test_origin::R2_ORIGIN
        .scope(lake.origin.clone(), async {
            load_log(&S3ObjectStore::new(&lake.log).unwrap(), &r.tenant_id).await
        })
        .await;
    let Err(error) = old_wiring else { panic!("lake_part_log cannot list checkpoints") };
    assert_eq!(attachment_error_class(&error), "permission_denied");
    assert_eq!(
        scoped::seen(&lake),
        [("log".to_string(), "LIST", format!("lake/parts/v1/tenant={}/log/checkpoints/", r.tenant_id))],
        "one refused LIST, no retry"
    );

    // A log credential refused by storage now degrades with a precise tag,
    // before any custody mutation, and ingest keeps running.
    let server = server(&ca, "localhost", 200, body(&r)).await;
    let denied = scoped::lake(&r, dir.path(), "log/other/").await;
    let (attached, cfg) = scoped::attach_scoped(&r, dir.path(), &denied, &server, &ca).await;
    assert_eq!(attached.failure, Some(("part_log_load", "permission_denied")));
    assert!(attached.runtime().is_none() && attached.recovery().is_some());
    assert_eq!(cfg.catalog_attachment_failure, Some("catalog_attach_failed"));
    assert_eq!(server.ops(), ["verify_maintenance"], "never reached close_and_drain");
    assert!(!dir.path().join("catalog/installation-id").exists());
}

#[tokio::test]
async fn catalog_attach_failure_stage_names_control_refusal() {
    let ca = Ca::new();
    let r = super::tests::record();
    let server = server(&ca, "localhost", 503, body(&r)).await;
    let dir = tempfile::tempdir().unwrap();
    let lake = scoped::lake(&r, dir.path(), "log/entries/").await;
    let (attached, _) = scoped::attach_scoped(&r, dir.path(), &lake, &server, &ca).await;
    assert_eq!(attached.failure, Some(("verify_maintenance", "control_status_5xx")));
    assert!(scoped::seen(&lake).is_empty(), "no storage IO before the platform verifies");
    // close_and_drain refused after a verified maintenance: fence stage.
    let refuse_fence = server_with_ops(&ca, &r, &[("close_and_drain", 409)]).await;
    let (attached, _) = scoped::attach_scoped(&r, dir.path(), &lake, &refuse_fence, &ca).await;
    assert_eq!(attached.failure, Some(("fence_close_and_drain", "control_status_4xx")));
    assert!(!dir.path().join("catalog/installation-id").exists(), "an unfenced installation is retried");
}

/// A TLS control fake that answers `op`s listed in `refuse` with that status.
async fn server_with_ops(ca: &Ca, r: &CatalogActivation, refuse: &[(&'static str, u16)]) -> Server {
    // The generic fake answers every request alike; flip the status as soon
    // as the refused op's request arrives, before the response is written.
    let s = server(ca, "localhost", 200, body(r)).await;
    s.delay_ms.store(50, std::sync::atomic::Ordering::SeqCst);
    let (bodies, status) = (s.bodies.clone(), s.status.clone());
    let refuse = refuse.to_vec();
    tokio::spawn(async move {
        loop {
            let ops: Vec<String> = bodies.read().unwrap().iter()
                .filter_map(|b| serde_json::from_str::<Value>(b).ok())
                .filter_map(|v| v["op"].as_str().map(str::to_string)).collect();
            if let Some(last) = ops.last() {
                if let Some((_, code)) = refuse.iter().find(|(op, _)| op == last) {
                    status.store(*code, std::sync::atomic::Ordering::SeqCst);
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });
    s
}

/// PR C (#7816) recovery after this fix: a persistent attach failure cannot
/// restart ingest every five minutes. Each process life of one installation
/// waits twice as long before its single recovery restart (capped at 6 h);
/// a successful attach or a new installation starts over at five minutes.
#[tokio::test]
async fn catalog_attach_recovery_restarts_back_off_across_process_lives() {
    use std::sync::atomic::Ordering::SeqCst;
    let ca = Ca::new();
    let r = super::tests::record();
    let server = server(&ca, "localhost", 200, json!({"defaults":{},"overrides":{}}).to_string()).await;
    let dir = tempfile::tempdir().unwrap();
    for (life, wait) in [(0u32, 300u64), (1, 600), (2, 1200), (3, 2400)] {
        let recovery = recovery(&r, dir.path(), &server, &ca);
        let before = server.calls.load(SeqCst);
        elapse(wait - 1).await;
        assert!(!recovery.try_restart().await, "life {life}: no restart before {wait}s");
        assert_eq!(server.calls.load(SeqCst), before, "life {life}: no probe during back-off");
        elapse(1).await;
        assert!(recovery.try_restart().await, "life {life}: one verified restart after {wait}s");
        elapse(MAX_BACKOFF_S).await;
        assert!(!recovery.try_restart().await, "life {life}: one restart signal per process");
    }
    // A new installation does not inherit the old installation's back-off.
    let mut rotated = r.clone();
    rotated.activation_id = uuid::Uuid::new_v4();
    let fresh = recovery(&rotated, dir.path(), &server, &ca);
    elapse(300).await;
    assert!(fresh.try_restart().await);
    // An acknowledged attachment clears it (IngestCatalog::mark_attached).
    super::recovery::clear_restarts(dir.path());
    let cleared = recovery(&r, dir.path(), &server, &ca);
    elapse(300).await;
    assert!(cleared.try_restart().await);
    // An unreadable record never resets the back-off to zero.
    std::fs::write(dir.path().join("recovery-restarts.json"), b"{not json").unwrap();
    let unreadable = recovery(&r, dir.path(), &server, &ca);
    elapse(300).await;
    assert!(!unreadable.try_restart().await);
    elapse(300).await;
    assert!(unreadable.try_restart().await);
    assert_eq!(super::recovery::backoff(0), Duration::from_secs(300));
    assert_eq!(super::recovery::backoff(6), Duration::from_secs(300 * 64));
    assert_eq!(super::recovery::backoff(7), Duration::from_secs(6 * 3600));
    assert_eq!(super::recovery::backoff(40), Duration::from_secs(6 * 3600));
}
const MAX_BACKOFF_S: u64 = 6 * 3600;

#[tokio::test]
async fn catalog_attach_recovery_restart_is_not_requested_without_a_durable_record() {
    let ca = Ca::new();
    let r = super::tests::record();
    let server = server(&ca, "localhost", 200, json!({"defaults":{},"overrides":{}}).to_string()).await;
    let dir = tempfile::tempdir().unwrap();
    // The back-off record path is a directory: it cannot be written.
    let work = dir.path().join("catalog");
    std::fs::create_dir_all(work.join("recovery-restarts.json")).unwrap();
    let recovery = recovery(&r, &work, &server, &ca);
    // Unreadable record state counts as one prior restart (10 min).
    elapse(600).await;
    assert!(!recovery.try_restart().await, "no unbounded restart");
    assert_eq!(server.calls.load(std::sync::atomic::Ordering::SeqCst), 1, "the probe passed; only the record failed");
}

#[test]
fn catalog_attach_error_classes_name_storage_kind_and_control_status() {
    let opendal = |kind| anyhow::Error::from(opendal::Error::new(kind, "must-not-log https://private.invalid/key"));
    assert_eq!(attachment_error_class(&opendal(opendal::ErrorKind::PermissionDenied)), "permission_denied");
    assert_eq!(attachment_error_class(&opendal(opendal::ErrorKind::NotFound)), "not_found");
    assert_eq!(attachment_error_class(&opendal(opendal::ErrorKind::RateLimited)), "rate_limited");
    assert_eq!(attachment_error_class(&opendal(opendal::ErrorKind::Unexpected)), "unexpected");
    assert_eq!(
        attachment_error_class(&opendal(opendal::ErrorKind::PermissionDenied).context("wrapped")),
        "permission_denied"
    );
    assert_eq!(attachment_error_class(&ControlRefused(403).into()), "control_status_4xx");
    assert_eq!(attachment_error_class(&ControlRefused(502).into()), "control_status_5xx");
    assert_eq!(attachment_error_class(&ControlRefused(302).into()), "control_status_other");
    for stage in [
        AttachStage::ControlNew, AttachStage::VerifyMaintenance, AttachStage::SourceStore,
        AttachStage::PartLogLoad, AttachStage::PartSchema, AttachStage::CatalogConfig,
        AttachStage::ServingBackend, AttachStage::Uninstall, AttachStage::CustodyLock,
        AttachStage::FenceCloseAndDrain, AttachStage::InstallationMarker,
    ] {
        let tag = stage.as_str();
        assert!(!tag.is_empty() && tag.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'), "{tag}");
    }
}
