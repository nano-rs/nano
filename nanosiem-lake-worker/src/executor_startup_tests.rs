// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn lane_spawn_preserves_task_across_transient_failures() {
    let executed = Arc::new(AtomicUsize::new(0));
    let task_count = executed.clone();
    let mut attempts = 0;
    let mut waits = Vec::new();
    spawn_lane_with(
        "product-0",
        move || {
            task_count.fetch_add(1, Ordering::SeqCst);
        },
        |name, task| {
            assert_eq!(name, "nano-chdb-product-0");
            attempts += 1;
            if attempts < 4 {
                // Like Builder::spawn, consume and drop the closure on failure.
                drop(task);
                Err(std::io::Error::from_raw_os_error(libc::EAGAIN))
            } else {
                std::thread::Builder::new()
                    .name(name)
                    .spawn(task)
                    .unwrap()
                    .join()
                    .unwrap();
                Ok(())
            }
        },
        |wait| waits.push(wait),
    )
    .unwrap();
    assert_eq!(attempts, 4);
    assert_eq!(executed.load(Ordering::SeqCst), 1);
    assert_eq!(waits, [50, 100, 200].map(Duration::from_millis));
}

#[test]
fn lane_spawn_pressure_is_bounded_and_keeps_os_error() {
    let mut waits = Vec::new();
    let error = spawn_lane_with(
        "product-0",
        || panic!("task must not run"),
        |_, _| Err(std::io::Error::from_raw_os_error(libc::EAGAIN)),
        |wait| waits.push(wait),
    )
    .unwrap_err();
    assert!(
        matches!(error, ExecutorError::ThreadSpawn { attempts: LANE_SPAWN_ATTEMPTS, ref source, .. }
        if source.raw_os_error() == Some(libc::EAGAIN))
    );
    assert_eq!(waits.len(), LANE_SPAWN_ATTEMPTS - 1);
    assert_eq!(
        waits.into_iter().sum::<Duration>(),
        Duration::from_millis(6350)
    );
    assert!(error.to_string().contains("product-0"));
}

#[test]
fn lane_spawn_permanent_errors_fail_immediately() {
    let error = spawn_lane_with(
        "product-0",
        || panic!("task must not run"),
        |_, _| Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        |_| panic!("permanent errors must not sleep"),
    )
    .unwrap_err();
    assert!(
        matches!(error, ExecutorError::ThreadSpawn { attempts: 1, source, .. }
        if source.raw_os_error() == Some(libc::EPERM))
    );
}

/// Real pthread_create EAGAIN at the production executor constructor, in a
/// separate process so the test never changes another test's resource limits.
/// The helper restores the soft limit without replacing this process/role.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires digest-verified native runtime and an unprivileged Linux uid"]
async fn native_executor_startup_recovers_kernel_task_pressure() {
    const CHILD: &str = "NAN4834_STARTUP_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "executor::startup_tests::native_executor_startup_recovers_kernel_task_pressure",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "RLIMIT_NPROC needs an unprivileged test uid"
    );
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    let pid = std::process::id();
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut limits) },
        0
    );
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let restore = std::thread::spawn(move || {
        release_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(180));
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &limits) }, 0);
    });
    let blocked = libc::rlimit {
        rlim_cur: 0,
        rlim_max: limits.rlim_max,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &blocked) }, 0);
    let probe = std::thread::Builder::new().spawn(|| ()).unwrap_err();
    assert_eq!(
        probe.raw_os_error(),
        Some(libc::EAGAIN),
        "must exercise real kernel task pressure"
    );
    release_tx.send(()).unwrap();
    let result = NativeExecutor::start_with_server_memory_limit(
        runtime,
        2,
        "product",
        ExecutorMode::ReadOnly,
        Some(512 << 20),
    );
    restore.join().unwrap();
    let executor = result.expect("same role must recover from transient pthread_create EAGAIN");
    assert_eq!(std::process::id(), pid);
    assert_eq!(executor.connection_count(), 2);
    let output = executor
        .execute_sql("SELECT 42 AS answer".into(), vec![])
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.data).unwrap()["answer"],
        42
    );
}
