// SPDX-License-Identifier: AGPL-3.0-or-later
//! Actual supervisor constructors/assignment/pidfd with a deliberately UNJAILED
//! protocol stub and policy IO fake. This is not native/C04 isolation evidence.
use async_trait::async_trait;
use nanosiem_lake_cell::{
    config::{CellConfig, Placement, TenantPlacement},
    contract::{JailSpec, NativeChildService, Role, TenantId},
    policy::{ChildIdentity, SupervisorPolicy},
    secrets::{KeySource, StaticKeySource},
    supervisor::Supervisor,
    uidmap::UidMap,
};
use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use zeroize::Zeroizing;

const FIXTURE_IMAGE: &str =
    "postgres@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280";

#[derive(Default)]
struct Policy {
    /// Projects LandingBytesV1 for Landing, as the H02 verified plan would.
    native: AtomicBool,
    calls: AtomicUsize,
    deny: AtomicBool,
    hold: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
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
        assert_eq!(role, Role::Landing);
        assert!(child.spawn_start_time_ticks > 0);
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.hold.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        anyhow::ensure!(!self.deny.load(Ordering::SeqCst), "synthetic policy denied");
        Ok(())
    }
    fn native_service(&self, role: Role) -> Option<NativeChildService> {
        (role == Role::Landing && self.native.load(Ordering::SeqCst))
            .then_some(NativeChildService::LandingBytesV1)
    }
}
/// Counts every KeySource mint; the native path must never call it.
#[derive(Default)]
struct CountingKeys(AtomicUsize);
#[async_trait]
impl KeySource for CountingKeys {
    async fn mint(&self, _: &TenantId, _: Role) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Zeroizing::new(b"synthetic-bootstrap".to_vec()))
    }
}
/// Advertises LandingBytesV1; still answers a legacy Assign/Secrets flow so
/// an unprojected policy proves the native advertisement selects nothing.
const NATIVE_CHILD: &str = r#"#!/usr/bin/python3
import os,socket,json,array
s=socket.socket(fileno=3)
def send(x):s.send(json.dumps(x).encode())
send({'type':'hello','pid':os.getpid(),'protocol_version':2,'native_services':['landing_bytes_v1']})
m=json.loads(s.recv(65536));a=m['assignment'];j=a['jail']
os.setgroups([]);os.setresgid(j['gid'],j['gid'],j['gid']);os.setresuid(j['uid'],j['uid'],j['uid'])
send({'type':'jailed','uid':j['uid'],'gid':j['gid'],'landlock':'partial','seccomp':True,'cgroupns':True})
_,anc,_,_=s.recvmsg(65536,socket.CMSG_SPACE(256))
for level,kind,data in anc:
 if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
  f=array.array('i');f.frombytes(data)
  for fd in f:os.close(fd)
send({'type':'ready'})
while True:
 data=s.recv(65536)
 if not data or json.loads(data)['type']=='shutdown':break
"#;
const CHILD: &str = r#"#!/usr/bin/python3
import os,socket,json,array
s=socket.socket(fileno=3)
def send(x):s.send(json.dumps(x).encode())
send({'type':'hello','pid':os.getpid(),'protocol_version':2})
a=json.loads(s.recv(65536))['assignment'];j=a['jail']
os.setgroups([]);os.setresgid(j['gid'],j['gid'],j['gid']);os.setresuid(j['uid'],j['uid'],j['uid'])
# Deliberate fake kernel/jail report. Only credentials actually drop.
send({'type':'jailed','uid':j['uid'],'gid':j['gid'],'landlock':'partial','seccomp':True})
_,anc,_,_=s.recvmsg(65536,socket.CMSG_SPACE(256))
for level,kind,data in anc:
 if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
  f=array.array('i');f.frombytes(data)
  for fd in f:os.close(fd)
send({'type':'ready'})
while True:
 data=s.recv(65536)
 if not data or json.loads(data)['type']=='shutdown':break
"#;
struct Case {
    _home: tempfile::TempDir,
    supervisor: Arc<Supervisor>,
    policy: Arc<Policy>,
    tenant: TenantId,
}
impl Drop for Case {
    fn drop(&mut self) {
        self.supervisor.shutdown_all();
        self.supervisor.halt();
    }
}
async fn case(guarded: bool) -> Case {
    case_with(guarded, false, false).await.0
}
async fn case_with(guarded: bool, native_stub: bool, native_policy: bool) -> (Case, Arc<CountingKeys>) {
    let home = tempfile::tempdir().unwrap();
    let (child, bytes) = if native_stub {
        (std::path::Path::new("/native-worker-stub"), NATIVE_CHILD)
    } else {
        (std::path::Path::new("/guarded-worker-stub"), CHILD)
    };
    assert_eq!(
        std::fs::read(child).unwrap(),
        bytes.as_bytes(),
        "exact read-only protocol stub"
    );
    let config: CellConfig = serde_json::from_value(serde_json::json!({
        "cell_id":"test-cell", "mode":"dedicated", "trusted_local":true,
        "require_landlock":false, "isolation":{"cgroup":"off","watchdog":true},
        "tenzir_landing":true, "uid_base":24000, "uid_slots":8,
        "data_dir":home.path().join("data"),"state_dir":home.path().join("state"),
        "ingest_binary":child,"query_binary":child,"listen_unix":home.path().join("router"),
        "router_token_file":home.path().join("token"),"placement_file":home.path().join("placement"),
        "dev_key_dir":home.path().join("keys"),"spawn_timeout_secs":3
    })).unwrap();
    std::fs::create_dir(&config.state_dir).unwrap();
    let tenant = TenantId::new("fixture-tenant").unwrap();
    UidMap::load(&config.state_dir.join("uids.json"), 24000, 8)
        .unwrap()
        .get_or_allocate(&tenant)
        .unwrap();
    let static_keys =
        Arc::new(StaticKeySource::default().with(&tenant, Role::Landing, b"synthetic-bootstrap"));
    let counting = Arc::new(CountingKeys::default());
    let policy = Arc::new(Policy::default());
    policy.native.store(native_policy, Ordering::SeqCst);
    let supervisor = if guarded && (native_stub || native_policy) {
        Supervisor::new_with_policy(config, counting.clone(), policy.clone())
            .await
            .unwrap()
    } else if guarded {
        Supervisor::new_with_policy(config, static_keys, policy.clone())
            .await
            .unwrap()
    } else {
        Supervisor::new(config, static_keys).unwrap()
    };
    let mut placement = TenantPlacement::legacy(tenant.clone(), 1.0);
    placement.landing = true;
    supervisor
        .set_placement(Placement {
            cell_id: "test-cell".into(),
            revision: 1,
            tenants: vec![placement],
        })
        .await
        .unwrap();
    (
        Case {
            _home: home,
            supervisor,
            policy,
            tenant,
        },
        counting,
    )
}
async fn dead(identity: (u32, u64)) {
    let fd = nanosiem_lake_cell::pidfd::PidFd::open_verified(identity.0, identity.1);
    if let Some(fd) = fd {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !fd.exited() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("exact refused child exits");
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_guarded_process_reader_matrix() {
    // Farm cargo runs as builder uid2000. Run only this finite fixture inside
    // an existing local service image with the five setup caps, private PID/
    // network namespaces, RO root and owned tmpfs. These host-library mounts
    // are TEST infrastructure, never native worker closure evidence.
    if unsafe { libc::geteuid() } != 0 {
        return isolated_matrix("production_guarded_process_reader_matrix");
    }
    // One sequential matrix keeps its deliberate stub UID range exclusive.
    let legacy = case(false).await;
    assert!(
        legacy
            .supervisor
            .current_guarded_landing(&legacy.tenant)
            .await
            .is_err(),
        "legacy cannot create guarded handle"
    );
    assert_eq!(legacy.policy.calls.load(Ordering::SeqCst), 0);
    drop(legacy);
    for fault in [
        "healthy", "missing", "foreign", "policy", "cancel", "halt", "remove", "dead", "timeout",
    ] {
        let c = case(true).await;
        if fault == "missing" {
            assert!(
                c.supervisor
                    .current_guarded_landing(&c.tenant)
                    .await
                    .is_err(),
                "reader must not spawn"
            );
            assert_eq!(c.policy.calls.load(Ordering::SeqCst), 0);
            continue;
        }
        let process = c
            .supervisor
            .ensure_running(&c.tenant, Role::Landing)
            .await
            .expect("production assignment with stub IO");
        let worker = Arc::new(
            c.supervisor
                .current_guarded_landing(&c.tenant)
                .await
                .expect("current guarded process"),
        );
        assert_eq!(worker.process_identity(), (process.pid, process.starttime));
        if fault == "foreign" {
            let before = c.policy.calls.load(Ordering::SeqCst);
            assert!(
                c.supervisor
                    .current_guarded_landing(&TenantId::new("foreign-tenant").unwrap())
                    .await
                    .is_err()
            );
            assert_eq!(
                c.policy.calls.load(Ordering::SeqCst),
                before,
                "foreign tenant denied before policy/child IO"
            );
            worker.confirm_current().await.unwrap();
        } else if fault == "policy" {
            c.policy.deny.store(true, Ordering::SeqCst);
            assert!(worker.confirm_current().await.is_err());
            c.policy.deny.store(false, Ordering::SeqCst);
            assert!(
                worker.confirm_current().await.is_err(),
                "refused handle cannot revive"
            );
            dead(worker.process_identity()).await;
        } else if fault == "dead" {
            let identity = worker.process_identity();
            nanosiem_lake_cell::pidfd::PidFd::open_verified(identity.0, identity.1)
                .unwrap()
                .kill();
            dead(identity).await;
            let before = c.policy.calls.load(Ordering::SeqCst);
            assert!(worker.confirm_current().await.is_err());
            assert_eq!(
                c.policy.calls.load(Ordering::SeqCst),
                before,
                "dead identity denied before policy IO"
            );
        } else if ["cancel", "halt", "remove", "timeout"].contains(&fault) {
            c.policy.hold.store(true, Ordering::SeqCst);
            let w = worker.clone();
            let task = tokio::spawn(async move { w.confirm_current().await });
            c.policy.entered.notified().await;
            if fault == "cancel" {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else if fault == "timeout" {
                assert!(
                    task.await.unwrap().is_err(),
                    "bounded pending policy denies"
                );
            } else {
                if fault == "halt" {
                    c.supervisor.halt();
                } else {
                    c.supervisor
                        .set_placement(Placement {
                            cell_id: "test-cell".into(),
                            revision: 2,
                            tenants: vec![],
                        })
                        .await
                        .unwrap();
                }
                c.policy.hold.store(false, Ordering::SeqCst);
                c.policy.release.notify_one();
                assert!(
                    task.await.unwrap().is_err(),
                    "late local invalidation denies {fault}"
                );
            }
            assert!(
                worker.confirm_current().await.is_err(),
                "invalid {fault} is permanent"
            );
            dead(worker.process_identity()).await;
        } else {
            worker.confirm_current().await.unwrap();
        }
        let identity = worker.process_identity();
        drop(worker);
        drop(c);
        dead(identity).await;
    }
}

/// Actual Supervisor constructor/spawn/assign with an UNJAILED native protocol
/// stub. This fixture has no private cgroup delegation, so a projected native
/// selection must REFUSE before NativeAssign; the positive NativeRun/refresh
/// kill/stream path needs a delegated host and is NOT claimed here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_native_parent_refusal_matrix() {
    if unsafe { libc::geteuid() } != 0 {
        return isolated_matrix("production_native_parent_refusal_matrix");
    }
    // (native stub, native policy): projected selection refuses without the
    // exact Hello or without cgroup delegation; unprojected stays legacy.
    for (native_stub, native_policy) in [(false, true), (true, true), (true, false)] {
        let (c, keys) = case_with(true, native_stub, native_policy).await;
        let result = c.supervisor.ensure_running(&c.tenant, Role::Landing).await;
        if native_policy {
            assert!(result.is_err(), "projected native start refuses ({native_stub})");
            assert_eq!(keys.0.load(Ordering::SeqCst), 0, "zero KeySource mint");
            assert_eq!(c.policy.calls.load(Ordering::SeqCst), 0, "refused before guard");
            assert!(
                c.supervisor.current_guarded_landing(&c.tenant).await.is_err(),
                "no native process is retained"
            );
        } else {
            let process = result.expect("advertisement alone selects legacy flow");
            assert_eq!(keys.0.load(Ordering::SeqCst), 1, "legacy mint unchanged");
            assert_eq!(c.policy.calls.load(Ordering::SeqCst), 2, "legacy guard around mint");
            let identity = (process.pid, process.starttime);
            drop(process);
            drop(c);
            dead(identity).await;
        }
    }
}

fn assert_local_docker() {
    use std::process::Command;
    assert!(
        std::env::var("DOCKER_HOST").map_or(true, |s| s.starts_with("unix://")),
        "local Docker only"
    );
    let context = Command::new("docker")
        .args(["context", "inspect"])
        .output()
        .unwrap();
    assert!(context.status.success());
    let context: serde_json::Value = serde_json::from_slice(&context.stdout).unwrap();
    assert!(
        context[0]["Endpoints"]["docker"]["Host"]
            .as_str()
            .unwrap()
            .starts_with("unix://")
    );
}

fn isolated_matrix(test: &str) {
    use std::process::{Command, Stdio};
    assert_local_docker();
    let name = format!(
        "nano-guarded-work-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
        }
    }
    let cleanup = Cleanup(name.clone());
    let exe = std::env::current_exe().unwrap();
    // Preserve noexec on writable tmpfs. The stub is a sealed test input on
    // a separate read-only bind, as executable package bytes would be.
    let script_home = tempfile::tempdir().unwrap();
    let script = script_home.path().join("stub");
    std::fs::write(&script, CHILD).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o555)).unwrap();
    let native_script = script_home.path().join("native-stub");
    std::fs::write(&native_script, NATIVE_CHILD).unwrap();
    std::fs::set_permissions(&native_script, std::fs::Permissions::from_mode(0o555)).unwrap();
    let mut command = Command::new("timeout");
    command.args([
        "--kill-after=5",
        "90",
        "docker",
        "run",
        "--pull=never",
        "--rm",
        "--name",
        &name,
        "--network=none",
        "--read-only",
        "--user=0:0",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
        "--memory=512m",
        "--cpus=1",
        "--tmpfs=/tmp:rw,nosuid,nodev,mode=1777",
    ]);
    for cap in ["SETUID", "SETGID", "CHOWN", "FOWNER", "KILL"] {
        command.arg("--cap-add").arg(cap);
    }
    for path in ["/usr", "/lib", "/lib64"] {
        command
            .arg("--mount")
            .arg(format!("type=bind,source={path},target={path},readonly"));
    }
    let status = command
        .arg("--mount")
        .arg(format!(
            "type=bind,source={},target=/guarded-worker-stub,readonly",
            script.display()
        ))
        .arg("--mount")
        .arg(format!(
            "type=bind,source={},target=/native-worker-stub,readonly",
            native_script.display()
        ))
        .arg("--mount")
        .arg(format!(
            "type=bind,source={},target=/guarded-work-tests,readonly",
            exe.display()
        ))
        .args([
            "--entrypoint=/guarded-work-tests",
            FIXTURE_IMAGE,
            "--exact",
            test,
            "--nocapture",
            "--test-threads=1",
        ])
        .stdin(Stdio::null())
        .status()
        .unwrap();
    drop(cleanup);
    let absent = Command::new("docker")
        .args(["container", "inspect", &name])
        .output()
        .unwrap();
    assert_eq!(absent.status.code(), Some(1));
    assert_eq!(String::from_utf8_lossy(&absent.stdout).trim(), "[]");
    assert!(
        String::from_utf8_lossy(&absent.stderr)
            .trim()
            .ends_with(&format!("No such container: {name}"))
    );
    assert!(
        status.success(),
        "isolated actual-supervisor matrix failed; no missing-image or privilege skip"
    );
}

/// Explicit operator-only test dependency operation, excluded from ordinary
/// tests. CP21 has ONE coordinator-approved invocation, pending owner review.
/// The external one-use runner stops on farm retry; no retry of this pull.
#[test]
#[ignore = "requires an explicit one-use coordinator fixture download approval"]
fn coordinator_cp21_pinned_fixture_once() {
    use std::{io::Write, process::Command};
    assert_eq!(unsafe { libc::geteuid() }, 2000, "farm builder only");
    assert!(
        std::env::current_dir()
            .unwrap()
            .starts_with("/build/nanosiem"),
        "farm source only"
    );
    assert!(
        std::fs::read_to_string("/sys/class/dmi/id/product_name")
            .unwrap()
            .contains("Google Compute Engine"),
        "disposable farm only"
    );
    assert_local_docker();
    println!("H02_CP21_FIXTURE_PULL_BEGIN {FIXTURE_IMAGE}");
    std::io::stdout().flush().unwrap();
    let status = Command::new("timeout")
        .args(["--kill-after=5", "120", "docker", "pull", FIXTURE_IMAGE])
        .status()
        .unwrap();
    assert!(
        status.success(),
        "one pinned fixture download failed; do not retry"
    );
    let inspected = Command::new("docker")
        .args(["image", "inspect", FIXTURE_IMAGE])
        .output()
        .unwrap();
    assert!(inspected.status.success());
    let value: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert!(
        value[0]["RepoDigests"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d.as_str() == Some(FIXTURE_IMAGE))
    );
    println!(
        "H02_CP21_FIXTURE_PULL_RECEIPT {}",
        serde_json::json!({"image":FIXTURE_IMAGE,"image_id":value[0]["Id"],"pull_count":1,"coordinator_decision_pending_owner_review":true})
    );
    std::io::stdout().flush().unwrap();
    // Actual constructor/assignment/pidfd matrix, not a dependency-only pass.
    production_guarded_process_reader_matrix();
}

/// Explicit operator-only test dependency operation, excluded from ordinary
/// tests. CP25 needs its OWN fresh coordinator grant; CP21 approval is SPENT.
/// The external one-use runner stops on farm retry; no retry of this pull.
#[test]
#[ignore = "requires an explicit one-use coordinator fixture download approval"]
fn coordinator_cp25_pinned_fixture_once() {
    use std::{io::Write, process::Command};
    assert_eq!(unsafe { libc::geteuid() }, 2000, "farm builder only");
    assert!(
        std::env::current_dir()
            .unwrap()
            .starts_with("/build/nanosiem"),
        "farm source only"
    );
    assert!(
        std::fs::read_to_string("/sys/class/dmi/id/product_name")
            .unwrap()
            .contains("Google Compute Engine"),
        "disposable farm only"
    );
    assert_local_docker();
    println!("H02_CP25_FIXTURE_PULL_BEGIN {FIXTURE_IMAGE}");
    std::io::stdout().flush().unwrap();
    let status = Command::new("timeout")
        .args(["--kill-after=5", "120", "docker", "pull", FIXTURE_IMAGE])
        .status()
        .unwrap();
    assert!(
        status.success(),
        "one pinned fixture download failed; do not retry"
    );
    let inspected = Command::new("docker")
        .args(["image", "inspect", FIXTURE_IMAGE])
        .output()
        .unwrap();
    assert!(inspected.status.success());
    let value: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert!(
        value[0]["RepoDigests"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d.as_str() == Some(FIXTURE_IMAGE))
    );
    println!(
        "H02_CP25_FIXTURE_PULL_RECEIPT {}",
        serde_json::json!({"image":FIXTURE_IMAGE,"image_id":value[0]["Id"],"pull_count":1,"coordinator_decision_pending_owner_review":true})
    );
    std::io::stdout().flush().unwrap();
    // Actual constructor/assignment/pidfd matrix, not a dependency-only pass.
    production_guarded_process_reader_matrix();
    production_native_parent_refusal_matrix();
}
