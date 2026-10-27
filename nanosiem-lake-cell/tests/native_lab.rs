// SPDX-License-Identifier: AGPL-3.0-or-later
//! H02 CP27 LAB-ONLY positive native path on a real delegated-cgroup host.
//!
//! Actual Supervisor::new_with_policy, spawn, NativeAssign, the real native
//! jail (Landlock, native seccomp, cgroup namespace, rlimits), guarded
//! NativeRun, a live guarded byte stream, in-jail AF_INET refusal and the
//! kill on a hostile RefreshSecrets. The installation policy is a TEST
//! projection (not SovereignCellPolicy/C01/C03); the child is the lab
//! protocol child, not the LandingBytesV1 leaf. Run only by the coordinator-
//! granted operator as root inside `systemd-run --scope -p Delegate=yes`.
use async_trait::async_trait;
use nanosiem_lake_cell::{
    config::{CellConfig, Placement, TenantPlacement},
    contract::{JailSpec, NativeChildService, Role, TenantId},
    policy::{ChildIdentity, SupervisorPolicy},
    secrets::KeySource,
    supervisor::Supervisor,
    uidmap::UidMap,
};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

const ROOT: &str = "/cell";
const WORKER: &str = "/cell/workers/ingest/bin/worker";
const MARKER: &str = "/cell/.nano-h02-cp27-lab";
/// The cell's whole uid layout must sit below 65534 (uidmap DETECT_UID_END).
/// base 61000, 8 slots: ingest/query 61000..61015, detect 61016..61023,
/// landing 61024..61031. Every uid this run can use is in LAB_UIDS.
const LAB_UID_BASE: u32 = 61_000;
const LAB_UID_SLOTS: u32 = 8;
const LAB_UIDS: std::ops::Range<u32> = LAB_UID_BASE..LAB_UID_BASE + 4 * LAB_UID_SLOTS;

/// pR CP27 P2-1: processes already running as a lab uid (they would be
/// killed by teardown as if this run created them).
fn lab_uid_processes() -> Vec<u32> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else { continue };
        let uids = status.lines().find_map(|l| l.strip_prefix("Uid:")).unwrap_or("");
        if uids.split_whitespace().filter_map(|u| u.parse::<u32>().ok()).any(|u| LAB_UIDS.contains(&u)) {
            found.push(pid);
        }
    }
    found
}

#[derive(Default)]
struct Policy {
    calls: AtomicUsize,
}
#[async_trait]
impl SupervisorPolicy for Policy {
    async fn preflight(&self, _: &CellConfig) -> anyhow::Result<()> {
        Ok(())
    }
    async fn placement(&self, _: &CellConfig, _: &Placement) -> anyhow::Result<()> {
        Ok(())
    }
    async fn before_secrets(
        &self,
        _: &TenantId,
        role: Role,
        _: &JailSpec,
        child: ChildIdentity<'_>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(role == Role::Landing && child.jail_completed && child.cgroup_namespace);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn native_service(&self, role: Role) -> Option<NativeChildService> {
        (role == Role::Landing).then_some(NativeChildService::LandingBytesV1)
    }
}
#[derive(Default)]
struct Keys(AtomicUsize);
#[async_trait]
impl KeySource for Keys {
    async fn mint(&self, _: &TenantId, _: Role) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("native lab: no credential exists")
    }
}

fn status_field(pid: u32, name: &str) -> String {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}:")))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn stage() -> std::path::PathBuf {
    // Refuse a pre-existing /cell: the run owns everything it creates.
    assert!(
        !Path::new(ROOT).exists(),
        "/cell exists; this run never adopts it"
    );
    assert_eq!(lab_uid_processes(), Vec::<u32>::new(), "a process already runs as a lab uid");
    let child = std::env::var_os("NANO_H02_CP27_CHILD").expect("pinned lab child path");
    let want = std::env::var("NANO_H02_CP27_CHILD_SHA256").expect("pinned lab child sha256");
    let bytes = std::fs::read(&child).unwrap();
    assert_eq!(hex(&Sha256::digest(&bytes)), want, "exact lab child bytes");
    std::fs::create_dir_all("/cell/workers/ingest/bin").unwrap();
    std::fs::write(MARKER, b"nano-h02-cp27-lab\n").unwrap();
    std::fs::write(WORKER, &bytes).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(WORKER, std::fs::Permissions::from_mode(0o555)).unwrap();
    for dir in ["/cell/data", "/cell/state", "/cell/run", "/cell/keys"] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::path::PathBuf::from(ROOT)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn wait_dead(pid: u32, start: u64) -> bool {
    let fd = nanosiem_lake_cell::pidfd::PidFd::open_verified(pid, start);
    let Some(fd) = fd else { return true };
    tokio::time::timeout(Duration::from_secs(5), async {
        while !fd.exited() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

/// The exact lab cell config: shared by the lab run and the offline gate.
fn lab_config() -> CellConfig {
    serde_json::from_value(serde_json::json!({
        "cell_id": "h02-cp27-lab", "mode": "dedicated", "trusted_local": false,
        "require_landlock": true, "isolation": {"cgroup": "require", "watchdog": true},
        "tenzir_landing": true, "uid_base": LAB_UID_BASE, "uid_slots": LAB_UID_SLOTS,
        "data_dir": "/cell/data", "state_dir": "/cell/state",
        "ingest_binary": WORKER, "query_binary": WORKER,
        "listen_unix": "/cell/run/router", "router_token_file": "/cell/run/token",
        "placement_file": "/cell/run/placement", "dev_key_dir": "/cell/keys",
        "spawn_timeout_secs": 10
    }))
    .unwrap()
}
const LAB_TENANT: &str = "h02-cp27-tenant";
fn lab_placement(tenant: &TenantId) -> TenantPlacement {
    let mut placement = TenantPlacement::legacy(tenant.clone(), 1.0);
    placement.landing = true;
    placement
}

/// H02 CP32 offline gate (coordinator rule after the CP30 harness failure):
/// the EXACT lab CellConfig, tenant and placement through UidMap::load, a real
/// CgroupTree whose relative root is absolute (as /proc/self/cgroup reports
/// it inside `systemd-run --scope`), the production
/// `native_landing_preflight` that `Supervisor::assign` calls (jail_spec +
/// native projection + its validation), the NativeAssign wire round trip,
/// and the receiver's own pre-jail check, which is everything up to
/// `jail::apply_native`. Unprivileged; it must pass before any H02 LAB REQUEST.
#[test]
fn h02_native_lab_offline_preflight() {
    use nanosiem_lake_cell::{child::native_receiver_preflight, contract::NativeLandingAssignment, limits::CgroupTree, supervisor::native_landing_preflight};
    let config = lab_config();
    config.validate().expect("lab config validates");
    let tenant = TenantId::new(LAB_TENANT).unwrap();
    let state = tempfile::tempdir().unwrap();
    let ids = UidMap::load(&state.path().join("uids.json"), config.uid_base, config.uid_slots)
        .unwrap()
        .get_or_allocate(&tenant)
        .unwrap();
    let landing_uid = ids.landing_uid.expect("lab map gives landing a uid");
    assert!(ids.uids().iter().all(|u| LAB_UIDS.contains(u)), "tenant uids inside the lab range");
    let cgroupfs = tempfile::tempdir().unwrap();
    std::fs::write(cgroupfs.path().join("cgroup.controllers"), "cpuset cpu io memory pids\n").unwrap();
    std::fs::write(cgroupfs.path().join("cgroup.procs"), format!("{}\n", std::process::id())).unwrap();
    let scope = "/system.slice/run-nano-h02-cp27.scope";
    let tree = CgroupTree::adopt_root(cgroupfs.path().to_path_buf(), scope.into(), vec![], true).unwrap();
    tree.register(&tenant, ids.slot);
    let placement = lab_placement(&tenant);
    let service = nanosiem_lake_cell::contract::NativeChildService::LandingBytesV1;
    let a = native_landing_preflight(&config, &tenant, &ids, Some(&tree), &placement, service)
        .expect("production native projection accepts the lab config");
    let state_dir = Path::new("/cell/data/tenants").join(LAB_TENANT).join("landing");
    assert_eq!(a.state_dir, state_dir);
    assert_eq!(a.jail.rw_paths, vec![state_dir]);
    assert_eq!(a.jail.system_ro_paths, vec![std::path::PathBuf::from("/cell/workers/ingest/bin")]);
    assert_eq!((a.jail.uid, a.jail.gid), (landing_uid, ids.gid));
    let cgroup = a.jail.cgroup_dir.clone().expect("private cgroup leaf");
    assert!(!cgroup.is_absolute(), "receiver form is relative");
    assert_eq!(cgroup, Path::new(&scope[1..]).join(format!("tenants/s{}/landing", ids.slot)));
    // The frame the child decodes, then the child's own check.
    let wire: NativeLandingAssignment = serde_json::from_slice(&serde_json::to_vec(&a).unwrap()).unwrap();
    assert_eq!(wire, a);
    native_receiver_preflight(service, &wire).expect("receiver accepts the lab assignment");
    println!("H02_CP32_OFFLINE_PREFLIGHT ok uid={landing_uid} slot={} cgroup={}", ids.slot, cgroup.display());
}

/// H02 B2 offline gate: native Ingest and Query from a lab config with the
/// production worker layout (/cell/workers/{ingest,query}/bin), through the
/// same production preflight and receiver check as Landing above.
#[test]
fn h02_b2_native_parts_offline_preflight() {
    use nanosiem_lake_cell::{child::native_receiver_preflight, contract::{NativeChildService, NativeLandingAssignment, PartChannelLimits}, limits::CgroupTree, supervisor::native_role_preflight};
    let mut config = lab_config();
    config.query_binary = "/cell/workers/query/bin/worker".into();
    config.validate().expect("lab config validates");
    let tenant = TenantId::new(LAB_TENANT).unwrap();
    let state = tempfile::tempdir().unwrap();
    let ids = UidMap::load(&state.path().join("uids.json"), config.uid_base, config.uid_slots)
        .unwrap()
        .get_or_allocate(&tenant)
        .unwrap();
    let cgroupfs = tempfile::tempdir().unwrap();
    std::fs::write(cgroupfs.path().join("cgroup.controllers"), "cpuset cpu io memory pids\n").unwrap();
    std::fs::write(cgroupfs.path().join("cgroup.procs"), format!("{}\n", std::process::id())).unwrap();
    let tree = CgroupTree::adopt_root(cgroupfs.path().to_path_buf(), "/system.slice/run-nano-h02-b2.scope".into(), vec![], true).unwrap();
    tree.register(&tenant, ids.slot);
    let placement = lab_placement(&tenant);
    for (role, service, worker) in [
        (Role::Ingest, NativeChildService::IngestPartsV1, "/cell/workers/ingest/bin"),
        (Role::Query, NativeChildService::QueryPartsV1, "/cell/workers/query/bin"),
    ] {
        let a = native_role_preflight(&config, &tenant, role, &ids, Some(&tree), &placement, service)
            .expect("production native projection accepts the parts role");
        let state_dir = Path::new("/cell/data/tenants").join(LAB_TENANT).join(role.as_str());
        assert_eq!(a.jail.rw_paths, vec![state_dir.clone()]);
        assert!(a.jail.ro_paths.is_empty() && a.jail.tcp_connect_ports.is_empty());
        assert_eq!(a.jail.system_ro_paths, vec![std::path::PathBuf::from(worker)]);
        assert_eq!((a.jail.uid, a.jail.gid), (ids.uid(role), ids.gid));
        assert_eq!(a.part_channel, Some(PartChannelLimits::DEFAULT));
        let wire: NativeLandingAssignment = serde_json::from_slice(&serde_json::to_vec(&a).unwrap()).unwrap();
        native_receiver_preflight(service, &wire).expect("receiver accepts");
        assert!(native_role_preflight(&config, &tenant, Role::Landing, &ids, Some(&tree), &placement, service).is_err(), "service fixes the role");
        println!("H02_B2_OFFLINE_PREFLIGHT ok role={} uid={} cgroup={}", role.as_str(), a.jail.uid, a.jail.cgroup_dir.unwrap().display());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "LAB ONLY: coordinator-granted root run on a delegated-cgroup host"]
async fn h02_cp27_native_positive_lab() {
    assert_eq!(
        std::env::var("NANO_H02_CP27_LAB").as_deref(),
        Ok("1"),
        "explicit lab run only"
    );
    assert_eq!(unsafe { libc::geteuid() }, 0, "root on the lab host");
    let _root = stage();
    let config = lab_config();
    let tenant = TenantId::new(LAB_TENANT).unwrap();
    let ids = UidMap::load(&config.state_dir.join("uids.json"), LAB_UID_BASE, LAB_UID_SLOTS)
        .unwrap()
        .get_or_allocate(&tenant)
        .unwrap();
    let landing_uid = ids.landing_uid.expect("lab map gives landing a uid");
    assert!(ids.uids().iter().all(|u| LAB_UIDS.contains(u)), "tenant uids inside the lab range");
    println!("H02_CP27_LAB_UIDS {}..{} landing={landing_uid}", LAB_UIDS.start, LAB_UIDS.end);
    let keys = Arc::new(Keys::default());
    let policy = Arc::new(Policy::default());
    let supervisor = Supervisor::new_with_policy(config, keys.clone(), policy.clone())
        .await
        .unwrap();
    let placement = lab_placement(&tenant);
    supervisor
        .set_placement(Placement {
            cell_id: "h02-cp27-lab".into(),
            revision: 1,
            tenants: vec![placement],
        })
        .await
        .unwrap();
    let mut report = serde_json::Map::new();

    // 1. Guarded native start: NativeAssign -> real jail -> one guard -> NativeRun -> Ready.
    let process = supervisor
        .ensure_running(&tenant, Role::Landing)
        .await
        .expect("native start");
    let (pid, start) = (process.pid, process.starttime);
    assert_eq!(keys.0.load(Ordering::SeqCst), 0, "zero KeySource mints");
    assert_eq!(policy.calls.load(Ordering::SeqCst), 1, "one guard, no mint");
    assert_eq!(status_field(pid, "Seccomp"), "2", "seccomp filter mode");
    assert_eq!(status_field(pid, "NoNewPrivs"), "1");
    assert_eq!(status_field(pid, "CapEff"), "0000000000000000");
    assert!(status_field(pid, "Uid")
        .split_whitespace()
        .all(|u| u.parse::<u32>().unwrap() == landing_uid));
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
    report.insert("native_start".into(), serde_json::json!({"mints": 0, "guards": 1, "seccomp": 2, "no_new_privs": 1, "cap_eff_zero": true, "cgroup_line_count": cgroup.lines().count()}));

    // 2. Routed RPCs never reach the native byte service.
    assert!(
        supervisor.open_rpc(&tenant, Role::Landing).await.is_err(),
        "open_rpc refuses native"
    );

    // 3. Live guarded byte stream to the exact process.
    let worker = supervisor
        .current_guarded_landing(&tenant)
        .await
        .expect("guarded handle");
    assert_eq!(worker.process_identity(), (pid, start));
    let (_, mut stream) = worker.open_native_stream().await.expect("native stream");
    stream.write_all(b"ehello-native").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"hello-native");
    worker
        .confirm_current()
        .await
        .expect("still current after the exchange");

    // 4. In the REAL jail, AF_INET socket creation is refused (CP26).
    let (_, mut stream) = worker.open_native_stream().await.expect("native stream");
    stream.write_all(b"n").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut errno = [0u8; 4];
    stream.read_exact(&mut errno).await.unwrap();
    assert_eq!(
        i32::from_le_bytes(errno),
        libc::EPERM,
        "in-jail socket(AF_INET) is EPERM"
    );
    // 4b. NAN-4545: the x32 number is refused too (EPERM from the x32
    // program, or ENOSYS where the kernel has no x32 ABI).
    let (_, mut stream) = worker.open_native_stream().await.expect("native stream");
    stream.write_all(b"x").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut x32 = [0u8; 4];
    stream.read_exact(&mut x32).await.unwrap();
    let x32 = i32::from_le_bytes(x32);
    assert!(x32 == libc::EPERM || x32 == libc::ENOSYS, "in-jail x32 socket refused, errno {x32}");
    report.insert(
        "stream".into(),
        serde_json::json!({"echo": true, "inet_errno": "EPERM", "x32_inet_errno": if x32 == libc::EPERM { "EPERM" } else { "ENOSYS" }}),
    );

    // 5. Hostile RefreshSecrets: exact child killed, still zero mints.
    let (_, mut stream) = worker.open_native_stream().await.expect("native stream");
    stream.write_all(b"r").await.unwrap();
    stream.shutdown().await.unwrap();
    assert!(
        wait_dead(pid, start).await,
        "exact native child killed on refresh request"
    );
    assert_eq!(keys.0.load(Ordering::SeqCst), 0, "refresh minted nothing");
    assert!(
        worker.confirm_current().await.is_err(),
        "killed handle is never current again"
    );
    report.insert(
        "refresh".into(),
        serde_json::json!({"killed": true, "mints": 0}),
    );
    drop(worker);
    drop(process);
    supervisor.shutdown_all();
    supervisor.halt();
    println!("H02_CP27_LAB_RESULT {}", serde_json::Value::Object(report));
}
