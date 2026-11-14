// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5346: the audit readers (Audit page, count, CSV/JSON export and
//! Export all, filter dropdowns, lookup history, API-key usage) read `logs`
//! under UDM and, under OCSF, the union of `ocsf_logs` and `logs` with one
//! row per audit event. No reader
//! emits an explicit PREWHERE (NAN-1412).

use super::*;
use crate::audit::{AuditEvent, AuditSource};

const LOGS: &str = "nanosiem.logs";
const OCSF: &str = "nanosiem.ocsf_logs";

fn every_filter() -> ClickHouseAuditQuery {
    ClickHouseAuditQuery {
        actor_id: Some(Uuid::nil()),
        action: Some("rule_created".into()),
        source: Some("detection".into()),
        resource_type: Some("rule".into()),
        success: Some(false),
        search: Some("probe".into()),
        ..Default::default()
    }
}

fn at(h: u32) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_790_000_000 + i64::from(h) * 3600, 0).unwrap()
}

fn plans() -> Vec<(&'static str, Vec<AuditSegment>)> {
    vec![
        ("udm", plan_sources(AuditStore::Udm, LOGS, OCSF, at(0), Some(at(10)))),
        ("ocsf", plan_sources(AuditStore::Ocsf, LOGS, OCSF, at(0), Some(at(10)))),
        ("ocsf/since", plan_sources(AuditStore::Ocsf, LOGS, OCSF, at(0), None)),
    ]
}

/// Every reader's SQL with its time binds and the number of other values
/// its caller binds after them.
fn readers(segments: &[AuditSegment]) -> Vec<(&'static str, (String, Vec<String>), usize)> {
    let f = resolve_filters(&every_filter());
    let n = f.conditions.len();
    vec![
        ("rows", rows_sql(segments, &f.conditions), n + 2),
        ("rows/unfiltered", rows_sql(segments, &[]), 2),
        ("count", count_sql(segments, &f.conditions), n),
        ("distinct action", distinct_sql(segments, AuditColumn::Action), 0),
        ("distinct source", distinct_sql(segments, AuditColumn::Source), 0),
        ("api key usage", api_key_daily_usage_sql(segments), 1),
    ]
}

#[test]
fn no_reader_emits_prewhere_and_placeholders_match_the_binds() {
    for (plan, segments) in plans() {
        for (name, (sql, time_binds), other) in readers(&segments) {
            assert!(!sql.contains("PREWHERE"), "{plan} {name}: {sql}");
            assert_eq!(sql.matches('?').count(), time_binds.len() + other, "{plan} {name}: {sql}");
            for seg in &segments {
                assert!(sql.contains(&format!("FROM {} WHERE timestamp >= ?", seg.table)), "{plan} {name}: {sql}");
            }
        }
    }
}

/// UDM: one WHERE with the time bounds first, then the audit scope and every
/// filter (CLAUDE.md "Single WHERE, no explicit PREWHERE"); `logs` only, no
/// dedupe.
#[test]
fn udm_readers_use_one_where_over_logs() {
    let segments = plan_sources(AuditStore::Udm, LOGS, OCSF, at(0), Some(at(10)));
    assert_eq!(segments.len(), 1);
    for (name, (sql, _), _) in readers(&segments) {
        assert_eq!(sql.matches("WHERE").count(), 1, "{name}: {sql}");
        assert!(!sql.contains("ocsf_logs") && !sql.contains("UNION") && !sql.contains("NOT IN"), "{name}: {sql}");
    }
    let f = resolve_filters(&every_filter());
    let (sql, binds) = count_sql(&segments, &f.conditions);
    assert!(sql.contains(&format!(
        "FROM {LOGS} WHERE timestamp >= ? AND timestamp <= ? AND source_type = 'audit' AND action = ? AND source = ?"
    )), "{sql}");
    let fmt = crate::sql_hygiene::format_ch_bound_micros;
    assert_eq!(binds, [fmt(&at(0)), fmt(&at(10))]);
}

/// OCSF: both tables over the same window. Sort, limit, offset, count and
/// the filters run over the union; a `logs` row whose event has an OCSF copy
/// in the window is skipped (a dual-written event appears once), and a
/// `logs` row without one (a failed mirror) is kept. NAN-5356: legacy case
/// rows are kept unconditionally on the UDM side, and their legacy OCSF
/// copies are hidden when the original exists (lookback-widened window).
#[test]
fn ocsf_readers_union_both_stores_deduplicated_by_event_id() {
    let segments = plan_sources(AuditStore::Ocsf, LOGS, OCSF, at(0), Some(at(10)));
    assert_eq!(segments.len(), 2);
    let shape = |s: &AuditSegment| (s.store, s.skip_copies_in.clone(), s.legacy_originals_in.clone());
    assert_eq!(shape(&segments[0]), (AuditStore::Ocsf, None, Some(LOGS.to_string())));
    assert_eq!(shape(&segments[1]), (AuditStore::Udm, Some(OCSF.to_string()), None));

    let f = resolve_filters(&every_filter());
    let (sql, binds) = rows_sql(&segments, &f.conditions);
    let time = "timestamp >= ? AND timestamp <= ?";
    let window = format!("{time} AND source_type = 'audit'");
    assert!(sql.contains(&format!(
        "FROM (SELECT {OCSF_AUDIT_PROJECTION} FROM {OCSF} WHERE {window} \
         AND if({OCSF_LEGACY_CASE}, {}, '') GLOBAL NOT IN \
         (SELECT {} FROM {LOGS} WHERE {window} AND {UDM_LEGACY_CASE}) \
         UNION ALL SELECT {UDM_AUDIT_COLUMNS} FROM {LOGS} WHERE {window} \
         AND (({UDM_LEGACY_CASE}) OR {AUDIT_DEDUP_KEY_UDM} GLOBAL NOT IN \
         (SELECT {AUDIT_DEDUP_KEYS_OCSF} FROM {OCSF} WHERE {window}))) \
         WHERE action = ?",
        legacy_copy_key(),
        legacy_original_keys(),
    )), "{sql}");
    assert!(sql.ends_with("ORDER BY timestamp DESC LIMIT ? OFFSET ?"), "{sql}");
    let fmt = crate::sql_hygiene::format_ch_bound_micros;
    let w = [fmt(&at(0)), fmt(&at(10))];
    let lookback = [fmt(&(at(0) - chrono::Duration::seconds(LEGACY_CASE_ORIGINAL_LOOKBACK_SECS))), fmt(&at(10))];
    assert_eq!(
        binds,
        [w.clone(), lookback.clone(), w.clone(), w].concat(),
        "every read is bounded by the window; the legacy-original read starts one lookback earlier"
    );

    let (sql, _) = count_sql(&segments, &f.conditions);
    assert!(sql.starts_with("SELECT count() as count FROM (SELECT"), "{sql}");

    // `since` readers: open-ended on all four reads.
    let segments = plan_sources(AuditStore::Ocsf, LOGS, OCSF, at(0), None);
    let (sql, binds) = distinct_sql(&segments, AuditColumn::Action);
    assert_eq!(binds.len(), 4, "{sql}");
    assert!(!sql.contains("timestamp <= ?"), "{sql}");
}

/// Both copies of an event share its id: the OCSF row `id` and the UDM
/// row's `metadata.event_id`. Older UDM rows (no `event_id`) fall back to
/// (milliseconds, message), which the OCSF row also offers.
#[test]
fn both_copies_carry_the_shared_dedupe_key() {
    let event = AuditEvent::builder(AuditSource::Detection, "rule_created").build();
    assert_eq!(event.metadata_json()["event_id"], event.event_id.to_string());
    let udm = event.to_parsed_log();
    assert_eq!(udm.metadata["event_id"], event.event_id.to_string());
    let ocsf = event.to_ocsf_event(event.occurred_at);
    assert_eq!(ocsf["message"], udm.message, "the fallback key's message matches");
    assert_eq!(ocsf["time"], event.occurred_at.timestamp_millis());
    assert!(AUDIT_DEDUP_KEY_UDM.contains("JSONExtractString(metadata, 'event_id')"));
    assert!(AUDIT_DEDUP_KEYS_OCSF.starts_with("arrayJoin([toString(id), "));
    for key in [AUDIT_DEDUP_KEY_UDM, AUDIT_DEDUP_KEYS_OCSF] {
        assert!(key.contains("concat(toString(toUnixTimestamp64Milli(timestamp)), '|', message)"), "{key}");
        assert!(!key.contains('?'));
    }
}

/// The projection maps every column the readers and `row_to_entry` use from
/// the row `AuditEvent::to_ocsf_event` writes.
#[test]
fn ocsf_projection_reads_the_mirror_row_fields() {
    for (column, from) in [
        ("`user`", "`actor.user.name`"),
        ("action", "`api.operation`"),
        ("source", "`api.service.name`"),
        ("src_ip", "`src_endpoint.ip`"),
        ("user_agent", "`http_request.user_agent`"),
        ("status", "if(status_id = 1, 'success', 'failure')"),
        ("metadata", "toString(unmapped)"),
    ] {
        assert!(
            OCSF_AUDIT_PROJECTION.contains(&format!("{from} AS {column}")),
            "{column} <- {from}: {OCSF_AUDIT_PROJECTION}"
        );
    }
    assert!(!OCSF_AUDIT_PROJECTION.contains('?'));

    // The mirror row carries what the projection reads.
    let event = AuditEvent::builder(AuditSource::Detection, "rule_created")
        .actor(Some(Uuid::nil()), Some("Dan".into()))
        .resource("rule", None, Some("r1".into()))
        .client(Some("10.0.0.1".into()), Some("ua".into()))
        .build();
    let row = event.to_ocsf_event(Utc::now());
    assert_eq!(row["api"]["operation"], "rule_created");
    assert_eq!(row["api"]["service"]["name"], event.source.to_string());
    assert_eq!(row["status_id"], 1);
    assert_eq!(row["unmapped"]["actor_id"], Uuid::nil().to_string());
    assert_eq!(row["unmapped"]["resource_type"], "rule");
    assert_eq!(row["unmapped"]["actor_name"], "Dan");
}

/// NAN-5356: a legacy case copy matches its original by (case fingerprint,
/// lookback bucket). Both sides hash the same fields in the same order; the
/// original offers its bucket and the next, so a copy up to one lookback
/// later matches. Only legacy case rows take part.
#[test]
fn legacy_case_copy_keys_match_the_original_side() {
    let (udm, ocsf) = (case_fingerprint_udm(), case_fingerprint_ocsf());
    for key in CASE_FINGERPRINT_KEYS {
        assert!(udm.contains(&format!("JSONExtractString(metadata, '{key}')")), "{udm}");
        assert!(ocsf.contains(&format!("ifNull(CAST(unmapped.details.{key}, 'Nullable(String)'), '')")), "{ocsf}");
    }
    assert!(udm.starts_with("cityHash64(session_id, action, status, severity, "), "{udm}");
    assert!(ocsf.starts_with(
        "cityHash64(ifNull(CAST(unmapped.resource_id, 'Nullable(String)'), ''), `api.operation`, \
         ifNull(CAST(unmapped.details.status, 'Nullable(String)'), ''), \
         ifNull(CAST(unmapped.details.severity, 'Nullable(String)'), ''), "
    ), "{ocsf}");
    let b = "intDiv(toUnixTimestamp(timestamp), 300)";
    assert_eq!(legacy_copy_key(), format!("concat(toString({ocsf}), '|', toString({b}))"));
    assert_eq!(
        legacy_original_keys(),
        format!("arrayJoin([concat(toString({udm}), '|', toString({b})), concat(toString({udm}), '|', toString({b} + 1))])")
    );
    assert!(UDM_LEGACY_CASE.contains("JSONExtractString(metadata, 'event_id') = ''"));
    assert!(UDM_LEGACY_CASE.contains("NOT JSONHas(metadata, 'resource_type')"));
    assert!(OCSF_LEGACY_CASE.contains("unmapped.details.event_id IS NULL"));
    for frag in [AUDIT_DEDUP_KEY_UDM, AUDIT_DEDUP_KEYS_OCSF, UDM_LEGACY_CASE, OCSF_LEGACY_CASE] {
        assert!(!frag.contains('?'), "{frag}");
    }
    assert!(!legacy_copy_key().contains('?') && !legacy_original_keys().contains('?'));
}
