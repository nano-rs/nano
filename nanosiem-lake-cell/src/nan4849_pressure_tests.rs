//! Real HTTP router -> supervisor admission -> SCM_RIGHTS RPC, with only
//! the ingest response stubbed. No database, tenant spawn, or sandbox skip.
use super::*;
use crate::config::{CellConfig, Placement, TenantPlacement};
use crate::contract::{Heartbeat, JailSpec};
use crate::disk_ceiling::{DiskLevel, Sample};
use crate::router::{self, Router};
use crate::secrets::StaticKeySource;
use crate::volume_usage::TreeUsage;
use http_body_util::Full;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;

const TOKEN: &str = "nan4849-full-operator-token-01234567890123456789";
const QUERY: &str = "nan4849-query-only-token-012345678901234567890";
const TENANT: &str = "00000000-0000-4000-8000-000000004849";

#[tokio::test]
async fn pressure_keeps_status_readable_without_admitting_writes_or_spawns() {
    check().await;
}

async fn check() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("full.token");
    let query = dir.path().join("query.token");
    std::fs::write(&token, TOKEN).unwrap();
    std::fs::write(&query, QUERY).unwrap();
    std::fs::set_permissions(&query, std::fs::Permissions::from_mode(0o400)).unwrap();
    let cfg: CellConfig = serde_json::from_value(serde_json::json!({
        "cell_id": "cell-test-4849", "mode": "dedicated", "trusted_local": true,
        "data_dir": dir.path().join("data"), "state_dir": dir.path().join("state"),
        "ingest_binary": "/not-spawned", "query_binary": "/not-spawned",
        "listen_tcp": "127.0.0.1:0", "router_token_file": token, "router_query_token_file": query,
        "placement_file": dir.path().join("placement.json"), "dev_key_dir": dir.path(),
        "require_landlock": false, "uid_base": 50000, "uid_slots": 1,
        "isolation": {"cgroup": "off", "watchdog": true},
        "resources": {"tenant_disk": {"mode": "enforce", "allowance_bytes": 1000}}
    }))
    .unwrap();
    let sup = running_supervisor(cfg);
    let tenant = TenantId::new(TENANT).unwrap();
    sup.set_placement(Placement {
        cell_id: sup.cfg.cell_id.clone(),
        revision: 1,
        tenants: vec![TenantPlacement::legacy(tenant.clone(), 20.0)],
    })
    .await
    .unwrap();
    let (parent, child) = fdpass::seqpacket_pair().unwrap();
    let control = Arc::new(AsyncSeqpacket::new(parent).unwrap());
    let child = AsyncSeqpacket::new(child).unwrap();
    let now = Instant::now();
    let process = Arc::new(Proc {
        native: None,
        part_channel: None,
        jail_completed: true,
        cgroup_namespace: false,
        pid: std::process::id(),
        role: Role::Ingest,
        tenant: tenant.clone(),
        uid: 50000,
        landlock: "test".into(),
        jail: JailSpec {
            uid: 50000,
            gid: 50000,
            rw_paths: vec![],
            ro_paths: vec![],
            system_ro_paths: vec![],
            tcp_connect_ports: vec![],
            cgroup_dir: None,
            require_landlock: false,
            max_processes: None,
            max_open_files: 128,
        },
        runs_rules: false,
        memory_cap_bytes: 1024,
        cpu_millis: 100,
        control,
        pidfd: PidFd::open(std::process::id()).unwrap(),
        starttime: 0,
        started: now,
        spawned_unix_ms: 0,
        ingest_hold_eps: None,
        eps: 20.0,
        last_activity: Mutex::new(now),
        heartbeat: Mutex::new((now, Heartbeat::default())),
        last_busy: Mutex::new(now),
        busy_seen: Mutex::new(None),
        stopping: AtomicBool::new(false),
        killed: Mutex::new(None),
        exited: AtomicBool::new(false),
        next_request: AtomicU64::new(1),
        inflight: AtomicU64::new(0),
        pending_finding: Mutex::new(Default::default()),
    });
    let slot = sup.slot(&tenant).unwrap().0;
    slot.procs.lock().unwrap()[role_idx(Role::Ingest)] = Some(process.clone());
    let entries = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let rpc_entries = entries.clone();
    let responder = tokio::spawn(async move {
        while let Some((ToChild::Rpc { .. }, fds)) = child.recv_json::<ToChild>().await.unwrap() {
            let stream = std::os::unix::net::UnixStream::from(fds.into_iter().next().unwrap());
            stream.set_nonblocking(true).unwrap();
            let stream = tokio::net::UnixStream::from_std(stream).unwrap();
            let entries = rpc_entries.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(
                    move |req: Request<hyper::body::Incoming>| {
                        assert!(
                            req.headers().get(hyper::header::AUTHORIZATION).is_none(),
                            "operator credential leaked to tenant"
                        );
                        let entries = entries.lock().unwrap().clone();
                        let body = if req.uri().path().ends_with("bronze-quarantine") {
                            serde_json::json!({"entries": entries})
                        } else {
                            serde_json::json!({"quarantine_objects": entries.len(), "quarantine_mirror_failing_ids": entries.len()})
                        };
                        async move {
                            Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                bytes::Bytes::from(body.to_string()),
                            )))
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let router = Router::new(sup.clone()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let serving = tokio::spawn(router::serve_tcp(router.clone(), listener));
    let client = reqwest::Client::new();
    // Drive the actual pressure evaluator, not just its error response helper.
    sup.disk.record(
        tenant.clone(),
        Sample {
            at: now,
            usage: Ok(TreeUsage {
                bytes: 2500,
                entries: 1,
                complete: true,
            }),
        },
    );
    sup.disk.evaluate(&[(tenant.clone(), 1000)], now);
    assert_eq!(sup.disk.view(&tenant).unwrap().level, DiskLevel::Pressure);
    for nonempty in [false, true] {
        if nonempty {
            entries
                .lock()
                .unwrap()
                .push(serde_json::json!({"id": "a".repeat(64)}));
        }
        for route in ["count-backfill", "bronze-quarantine", "prevalence-restamp"] {
            let url = format!("{origin}/v1/tenants/{TENANT}/admin/{route}");
            let response = client.get(&url).bearer_auth(TOKEN).send().await.unwrap();
            assert_eq!(response.status(), 200, "{route}");
            let body: serde_json::Value = response.json().await.unwrap();
            if route == "bronze-quarantine" {
                assert_eq!(
                    body["entries"].as_array().unwrap().len(),
                    usize::from(nonempty)
                );
            }
            let response = client.get(&url).bearer_auth(QUERY).send().await.unwrap();
            assert_eq!(response.status(), 403);
        }
    }
    for route in [
        "count-backfill",
        "prevalence-restamp",
        "bronze-quarantine/replay",
        "bronze-quarantine/import",
    ] {
        let response = client
            .post(format!("{origin}/v1/tenants/{TENANT}/admin/{route}"))
            .bearer_auth(TOKEN)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 503);
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap()["reason"],
            "tenant_disk_pressure"
        );
    }
    assert!(matches!(
        sup.ensure_running(&tenant, Role::Ingest).await,
        Err(CellError::DiskPressure { .. })
    ));
    assert_eq!(slot.stats.lock().unwrap().spawns[role_idx(Role::Ingest)], 0);
    slot.procs.lock().unwrap()[role_idx(Role::Ingest)] = None;
    let response = client
        .get(format!(
            "{origin}/v1/tenants/{TENANT}/admin/bronze-quarantine"
        ))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        503,
        "status must not spawn ingest under pressure"
    );
    drop(client);
    router.close(Duration::from_secs(2)).await;
    serving.await.unwrap().unwrap();
    responder.abort();
}

// Test-only representation of an already-booted supervisor: boot's root-only
// mount/uid/orphan cleanup is outside this regression. No production admission,
// router, authentication, disk evaluator or RPC implementation is replaced.
fn running_supervisor(cfg: CellConfig) -> Arc<Supervisor> {
    cfg.validate().unwrap();
    std::fs::create_dir_all(&cfg.state_dir).unwrap();
    std::fs::create_dir_all(cfg.data_dir.join("tenants")).unwrap();
    let keys: Arc<dyn KeySource> = Arc::new(StaticKeySource::default());
    let disk = Arc::new(crate::disk_ceiling::DiskCeilings::new(
        cfg.resources.tenant_disk.clone(),
        cfg.mode,
    ));
    let uidmap = UidMap::load(
        &cfg.state_dir.join("uids.json"),
        cfg.uid_base,
        cfg.uid_slots,
    )
    .unwrap();
    let ledger = Arc::new(
        crate::report::LedgerStore::open(&cfg.state_dir.join("purge-ledger.json")).unwrap(),
    );
    let placement = Placement {
        cell_id: cfg.cell_id.clone(),
        revision: 0,
        tenants: vec![],
    };
    let delegation = limits::check_delegation(&cfg.cgroup_mount);
    let identity = crate::identity::check_with_policy(cfg.uid_base, cfg.uid_slots, false, true);
    let capacity = crate::resources::detect_capacity(&cfg.resources, None);
    let monitor = Monitor::new(cfg.resources.clone(), capacity, false);
    Arc::new(Supervisor {
        secret_delivery: Mutex::new(()),
        installation_policy: None,
        cfg,
        keys,
        cgroups: OnceLock::new(),
        mount_method: Mutex::new(None),
        init_pending: Mutex::new(Default::default()),
        delegation_withdrawn: AtomicBool::new(false),
        delegation_reasons: Mutex::new(Vec::new()),
        unenforced: Mutex::new(UnenforcedClock::default()),
        admission_refused: Mutex::new(Default::default()),
        halted: AtomicBool::new(false),
        volume_accountant: OnceLock::new(),
        disk,
        delegation,
        identity,
        monitor: Arc::new(Mutex::new(monitor)),
        cell_events: Mutex::new(VecDeque::new()),
        landlock_abi: 0,
        uidmap: Mutex::new(uidmap),
        placement: RwLock::new(placement),
        tenants: Mutex::new(HashMap::new()),
        stopping_procs: Mutex::new(Vec::new()),
        warm: Mutex::new(HashMap::new()),
        warm_notify: tokio::sync::Notify::new(),
        keeper_notify: tokio::sync::Notify::new(),
        resident_down_since: Mutex::new(HashMap::new()),
        stopping_all: AtomicBool::new(false),
        spawn_failures: AtomicU64::new(0),
        recent_spawn_failures: Mutex::new(VecDeque::new()),
        alert_windows: Mutex::new(AlertWindows::default()),
        signal_debounce: Mutex::new(crate::signals::SignalDebouncer::default()),
        started_at: Instant::now(),
        restarted: false,
        ledger,
        purging: Mutex::new(Default::default()),
        placement_loaded: AtomicBool::new(false),
        purge_notify: tokio::sync::Notify::new(),
        report_notify: Arc::new(tokio::sync::Notify::new()),
        purge_retry: Mutex::new(HashMap::new()),
        purge_failures: AtomicU64::new(0),
        purge_blocked: Mutex::new(HashMap::new()),
        status_pushes: Mutex::new(HashMap::new()),
        handover: None,
        upstream: None,
    })
}
