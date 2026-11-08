//! NAN-4914 (codex P1-3, P2-6): the operator CLI hardens its own process
//! before doing anything, and never takes credential values on argv.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::Value;

fn exe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nano-connector"))
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn main_hardens_the_host_process_before_anything_else() {
    // Spawned WITHOUT the worker spawn hardening (no rlimits from the
    // parent): whatever the probe sees before its own worker hardening is
    // what `main` applied.
    let out = exe()
        .args(["sandbox-probe", "env", "--seccomp=off"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(out.stdout.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!(v["host_core_limit"], serde_json::json!([0, 0]), "main must disable core dumps: {v}");
    if cfg!(target_os = "linux") {
        assert_eq!(v["host_dumpable"], 0, "main must make the host non-dumpable: {v}");
    }
}

#[test]
fn credential_values_on_argv_are_refused() {
    let secret = "argv-secret-value-123";
    let out = exe()
        .arg("preview")
        .arg(fixtures().join("specs/okta_system_log.yaml"))
        .arg(fixtures().join("recordings/okta_system_log.json"))
        .args(["--cred", &format!("API_TOKEN={secret}")])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--creds-stdin") && stderr.contains("--cred-file"), "{stderr}");
    assert!(!stderr.contains(secret) && !String::from_utf8_lossy(&out.stdout).contains(secret));
}

#[test]
fn credential_files_must_be_private_and_stdin_errors_never_echo_values() {
    use std::os::unix::fs::PermissionsExt;
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let file = dir.join(format!("{}-cred", std::process::id()));
    std::fs::write(&file, "file-secret-value-123").unwrap();
    let preview = |extra: &[&str]| {
        let mut c = exe();
        c.arg("preview")
            .arg(fixtures().join("specs/okta_system_log.yaml"))
            .arg(fixtures().join("recordings/okta_system_log.json"))
            .args(["--config", "OKTA_DOMAIN=acme.okta.com", "--now", "2026-10-10T11:05:00Z"])
            .args(extra);
        c
    };
    let arg = format!("API_TOKEN={}", file.display());
    // World/group readable: refused.
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = preview(&["--cred-file", &arg]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("chmod 600"));
    // Owner-only: accepted, and the preview runs.
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = preview(&["--cred-file", &arg]).output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(v["ok"], true, "{v}");
    let _ = std::fs::remove_file(&file);

    // A malformed stdin line is reported by number, never echoed.
    use std::io::Write;
    let mut child = preview(&["--creds-stdin"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"stdin-secret-without-equals\n").unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("line 1") && !stderr.contains("stdin-secret"), "{stderr}");
}
