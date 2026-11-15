// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5447: the eviction audit archive's copy, verify and read SQL.

use super::*;
use crate::audit::query::{archive_segment, count_sql, rows_sql};

fn src(t: &str) -> String {
    format!("nanosiem.{t}")
}

fn window() -> (DateTime<Utc>, DateTime<Utc>) {
    day_window("20261001").unwrap()
}

#[test]
fn day_window_covers_the_whole_utc_day() {
    let (start, end) = window();
    assert_eq!(start.to_rfc3339(), "2026-10-01T00:00:00+00:00");
    assert_eq!(end.format("%Y-%m-%d %H:%M:%S%.6f").to_string(), "2026-10-01 23:59:59.999999");
    assert!(day_window("2026100").is_none());
    assert!(day_window("20261301").is_none());
    assert!(day_window("2026-10-").is_none());
}

/// UDM: the reader's `logs` read, nothing else.
#[test]
fn udm_copies_what_the_reader_shows() {
    let (start, end) = window();
    let plan = archive_sources(AuditStore::Udm, &["logs"], src, start, end);
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].origin, "logs");
    assert!(plan[0].select.contains("FROM nanosiem.logs WHERE timestamp >= ? AND timestamp <= ? AND source_type = 'audit'"));
    assert_eq!(plan[0].select.matches('?').count(), plan[0].binds.len());
}

/// OCSF: both reader segments, deduplicated exactly like the audit page.
#[test]
fn ocsf_copies_the_deduplicated_union() {
    let (start, end) = window();
    let plan = archive_sources(AuditStore::Ocsf, &["ocsf_logs", "logs"], src, start, end);
    let origins: Vec<_> = plan.iter().map(|s| s.origin).collect();
    assert_eq!(origins, ["ocsf_logs", "logs"]);
    assert!(plan[1].select.contains("GLOBAL NOT IN"), "the logs read skips events with an OCSF copy: {}", plan[1].select);
    for s in &plan {
        assert_eq!(s.select.matches('?').count(), s.binds.len(), "{}", s.select);
    }
    // Only `ocsf_logs` holds the partition: still the full view (the logs
    // read finds nothing, the dedupe still reads the other table).
    assert_eq!(archive_sources(AuditStore::Ocsf, &["ocsf_logs"], src, start, end).len(), 2);
}

/// Audit-bearing tables the reader never shows are archived under their
/// own origin, and stay hidden.
#[test]
fn tables_outside_the_view_are_archived_but_not_shown() {
    let (start, end) = window();
    let plan = archive_sources(AuditStore::Udm, &["logs", "ocsf_logs", "ocsf_logs_legacy_v179"], src, start, end);
    let origins: Vec<_> = plan.iter().map(|s| s.origin).collect();
    assert_eq!(origins, ["logs", "ocsf_logs", "ocsf_logs_legacy_v179"]);
    assert!(plan[2].select.contains("FROM nanosiem.ocsf_logs_legacy_v179 WHERE timestamp >= ? AND timestamp <= ? AND source_type = 'audit'"));
    assert!(!shown_origins(AuditStore::Udm).contains(&"ocsf_logs_legacy_v179"));
    assert!(!shown_origins(AuditStore::Ocsf).contains(&"ocsf_logs_legacy_v179"));
    // A day with no view table: only the extra tables.
    let plan = archive_sources(AuditStore::Ocsf, &["ocsf_logs_legacy_v179"], src, start, end);
    assert_eq!(plan.len(), 1);
}

/// The copy adds only rows not archived yet (a retry is idempotent), and
/// placeholders match the binds.
#[test]
fn insert_is_idempotent_and_bound() {
    let (start, end) = window();
    for s in archive_sources(AuditStore::Ocsf, &["ocsf_logs", "logs", "ocsf_logs_legacy_v179"], src, start, end) {
        let (sql, binds) = insert_sql(&s, "audit_archive", "audit_archive", start, end);
        assert!(sql.starts_with("INSERT INTO audit_archive (origin_table, id, timestamp, `user`, action, source, src_ip, user_agent, status, message, metadata) SELECT '"), "{sql}");
        assert!(sql.contains(&format!(
            "toString(id) GLOBAL NOT IN (SELECT id FROM audit_archive WHERE origin_table = '{}' AND timestamp >= ? AND timestamp <= ?)",
            s.origin
        )), "{sql}");
        assert_eq!(sql.matches('?').count(), binds.len(), "{sql}");
        let (verify, vbinds) = verify_sql(&s, "audit_archive", start, end);
        assert!(verify.contains("AS expected") && verify.contains("AS missing"), "{verify}");
        assert_eq!(verify.matches('?').count(), vbinds.len(), "{verify}");
        assert!(!sql.contains("PREWHERE") && !verify.contains("PREWHERE"));
    }
}

/// The reader's archive segment reads the shown origins in the reader's
/// column shape, unioned with the event tables.
#[test]
fn readers_union_the_archive_of_shown_origins() {
    let (start, end) = window();
    let mut segments = plan_sources(AuditStore::Udm, "nanosiem.logs", "nanosiem.ocsf_logs", start, Some(end));
    segments.push(archive_segment(AuditStore::Udm, "nanosiem.audit_archive", start, Some(end)));
    let (sql, binds) = rows_sql(&segments, &["action = ?"]);
    assert!(sql.contains(
        "UNION ALL SELECT id, timestamp, `user`, action, source, src_ip, user_agent, status, message, metadata \
         FROM nanosiem.audit_archive WHERE timestamp >= ? AND timestamp <= ? AND origin_table IN ('logs')"
    ), "{sql}");
    assert_eq!(sql.matches('?').count(), binds.len() + 3, "{sql}");
    let (count, _) = count_sql(&segments, &[]);
    assert!(count.contains("FROM nanosiem.audit_archive"), "{count}");

    let ocsf = archive_segment(AuditStore::Ocsf, "nanosiem.audit_archive", start, None);
    assert!(ocsf.predicate().ends_with("origin_table IN ('ocsf_logs', 'logs')"), "{}", ocsf.predicate());
}
