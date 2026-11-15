// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5450: "Run retention now" names a full disk instead of failing opaquely.

use super::*;

/// Messages captured from clickhouse-server 26.10.4.207 on a full tmpfs.
const INSERT_243: &str = "Code: 243. DB::Exception: Cannot reserve 24.13 MiB, not enough space. (NOT_ENOUGH_SPACE)";
const DDL_243: &str = "Code: 243. DB::Exception: Cannot reserve 1.00 MiB, not enough space. (NOT_ENOUGH_SPACE)";

#[test]
fn recognises_clickhouse_disk_full_errors() {
    assert!(is_disk_full_error(INSERT_243));
    assert!(is_disk_full_error(DDL_243));
    assert!(is_disk_full_error("write failed: No space left on device (os error 28)"));
    assert!(!is_disk_full_error("Code: 60. DB::Exception: Table nanosiem.x does not exist. (UNKNOWN_TABLE)"));
}

#[test]
fn disk_full_maps_to_disk_full_with_the_runbook() {
    match retention_ch_error("ocsf_logs", DDL_243.to_string()) {
        RetentionError::DiskFull(msg) => {
            assert!(msg.contains("ocsf_logs"));
            assert!(msg.contains("disk-full-recovery.md"));
            assert!(msg.contains("SYSTEM RELOAD"));
        }
        other => panic!("expected DiskFull, got {other:?}"),
    }
    assert!(matches!(
        retention_ch_error("logs", "Code: 60. UNKNOWN_TABLE".into()),
        RetentionError::ClickHouse(m) if m.starts_with("logs: ")
    ));
}

#[test]
fn run_retention_no_longer_issues_optimize_final() {
    let src = include_str!("retention.rs");
    let body = &src[src.find("pub async fn run_retention_now(&self) -> Result<u64").unwrap()..];
    let body = &body[..body.find("\n    }\n").unwrap()];
    assert!(!body.contains("OPTIMIZE TABLE"), "OPTIMIZE FINAL is back in run_retention_now");
    assert!(body.contains("MATERIALIZE TTL"));
}
