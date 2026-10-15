#![cfg(target_os = "linux")]

use std::os::unix::process::ExitStatusExt;
use std::process::Command;

#[test]
fn crash_fixture() {
    let Ok(mode) = std::env::var("NANO_CRASH_TEST_MODE") else {
        return;
    };
    // Never produce a core dump during local tests.
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_CORE, &limit), 0);
    }
    nanosiem_lake_cell::crash_capture::install().unwrap();
    let fault = move || {
        nanosiem_lake_cell::crash_capture::register_thread().unwrap();
        nanosiem_lake_cell::crash_capture::register_thread().unwrap();
        if mode == "abort" {
            unsafe {
                libc::raise(libc::SIGABRT);
            }
        } else {
            // Real synchronous hardware SIGSEGV; never inspect heap/stack data.
            unsafe {
                let page = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                assert_ne!(page, libc::MAP_FAILED);
                std::ptr::write_volatile(page.cast::<u8>(), 1);
            }
        }
    };
    if std::env::var("NANO_CRASH_TEST_THREAD").is_ok() {
        std::thread::spawn(fault).join().unwrap();
    } else {
        fault();
    }
    panic!("fatal signal returned");
}

#[test]
fn native_faults_record_frame_and_maps_then_preserve_signal() {
    for (mode, thread, signal) in [
        ("segv", false, libc::SIGSEGV),
        ("segv", true, libc::SIGSEGV),
        ("abort", false, libc::SIGABRT),
    ] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "crash_fixture", "--nocapture"])
            .env("NANO_CRASH_TEST_MODE", mode);
        if thread {
            command.env("NANO_CRASH_TEST_THREAD", "1");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.signal(), Some(signal));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("lake_native_crash signal="), "{stderr}");
        assert!(stderr.contains(" pc=0x"), "{stderr}");
        assert!(!stderr.contains(" pc=0x0000000000000000"), "{stderr}");
        assert!(
            stderr.contains("alt_stack_flags=0x0000000000000001"),
            "{stderr}"
        );
        assert!(stderr.contains("lake_native_crash maps_begin"), "{stderr}");
        assert!(stderr.contains("r-xp"), "{stderr}");
        assert!(stderr.contains("lake_native_crash maps_end"), "{stderr}");
    }
}

#[test]
fn thread_stack_can_be_registered_and_released_repeatedly() {
    for _ in 0..8 {
        std::thread::spawn(|| {
            nanosiem_lake_cell::crash_capture::register_thread().unwrap();
            nanosiem_lake_cell::crash_capture::register_thread().unwrap();
        })
        .join()
        .unwrap();
    }
}
