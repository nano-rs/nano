// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5447: the eviction audit archive (`nanosiem.audit_archive`,
//! `clickhouse/201_audit_archive.sql`).
//!
//! The platform audit trail lives in the event tables (`source_type =
//! 'audit'` rows of `logs` / `ocsf_logs`). When the disk-pressure evictor has
//! to remove a daily partition that holds audit rows, it first copies those
//! rows here, verifies that every one of them arrived, and only then runs the
//! cheap `DROP PARTITION`. A rewrite of the whole partition (`ALTER ...
//! DELETE`) is never needed, so eviction costs the same at 100 GB/day as at
//! 1 GB/day.
//!
//! What is copied is exactly what the audit page showed for that day: the
//! reader's own segments ([`super::query::plan_sources`]), deduplicated across
//! `logs` and `ocsf_logs` the same way, in the reader's column shape. The
//! audit reader ([`super::query::AuditQueryService`]) adds the archive to its
//! reads whenever it holds rows in the window, so the Audit page, exports,
//! filters and API-key usage keep finding evicted days.
//!
//! Rows of an audit-bearing table the active profile's reader never showed
//! (`ocsf_logs` on a UDM install, the frozen OCSF 1.8 store
//! `ocsf_logs_legacy_v179`) are archived too, under their own
//! `origin_table`, and stay hidden from the reader as before
//! ([`shown_origins`]). They are in `nanosiem.audit_archive` for an operator
//! to query directly.

use chrono::{DateTime, NaiveDate, Utc};

use super::query::{plan_sources, AuditSegment, AuditStore, OCSF_AUDIT_PROJECTION};

/// The archive table (local name; on a cluster reads go through
/// `audit_archive_distributed`).
pub const AUDIT_ARCHIVE_TABLE: &str = "audit_archive";

/// Archive columns after `origin_table`, in the audit reader's shape.
const ARCHIVE_COLUMNS: &str =
    "id, timestamp, `user`, action, source, src_ip, user_agent, status, message, metadata";

/// The reader's projection of the archive columns, cast to the archive's
/// String types (UDM columns are `LowCardinality`, OCSF `id` is a UUID).
const ARCHIVE_VALUES: &str = "toString(id), timestamp, toString(`user`), toString(action), \
     toString(source), toString(src_ip), toString(user_agent), toString(status), \
     toString(message), toString(metadata)";

/// The OCSF 1.8 store (`ocsf_logs_legacy_v179`, migration 180) has no
/// promoted `api.*` columns; the action and service stay in `unmapped`,
/// which is archived whole as `metadata`.
const LEGACY_OCSF18_PROJECTION: &str = "id, timestamp, \
     `actor.user.name` AS `user`, '' AS action, '' AS source, \
     `src_endpoint.ip` AS src_ip, `http_request.user_agent` AS user_agent, \
     if(status_id = 1, 'success', 'failure') AS status, message, toString(unmapped) AS metadata";

/// Origin tables whose archived rows the reader shows for `store`: the
/// tables that store's reader reads.
pub(crate) fn shown_origins(store: AuditStore) -> &'static [&'static str] {
    match store {
        AuditStore::Udm => &["logs"],
        AuditStore::Ocsf => &["ocsf_logs", "logs"],
    }
}

/// The audit-bearing tables `store`'s reader reads (the view).
fn view_tables(store: AuditStore) -> &'static [&'static str] {
    shown_origins(store)
}

/// One copy into the archive: the audit rows of one origin table for one day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchiveSource {
    pub(crate) origin: &'static str,
    /// `SELECT <archive columns> FROM ... WHERE <day window> ...`.
    pub(crate) select: String,
    /// Binds of `select`, in order.
    pub(crate) binds: Vec<String>,
}

/// `[00:00:00, 23:59:59.999999]` UTC of the partition value `date`
/// (`YYYYMMDD`), or `None` when it is not a date.
pub(crate) fn day_window(date: &str) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let day = NaiveDate::parse_from_str(date, "%Y%m%d").ok()?;
    let start = day.and_hms_opt(0, 0, 0)?.and_utc();
    let end = day.and_hms_micro_opt(23, 59, 59, 999_999)?.and_utc();
    Some((start, end))
}

fn origin_of(segment: &AuditSegment) -> &'static str {
    match segment.store {
        AuditStore::Udm => "logs",
        AuditStore::Ocsf => "ocsf_logs",
    }
}

/// What to copy for one day.
///
/// * The tables `store`'s reader reads: the reader's own segments over the
///   day, so the archive holds what the audit page showed (one row per
///   event across `logs` and `ocsf_logs`). Planned when any of them holds
///   the partition.
/// * Every other audit-bearing table holding the partition: a plain
///   projection of its audit rows, archived under its own origin.
///
/// `source` maps a local table name to its read source (the table itself on
/// single-node, `cluster(...)` on a cluster). `present` lists the
/// audit-bearing tables that hold the partition.
pub(crate) fn archive_sources(
    store: AuditStore,
    present: &[&str],
    source: impl Fn(&str) -> String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Vec<ArchiveSource> {
    let mut out = Vec::new();
    let view = view_tables(store);
    if present.iter().any(|t| view.contains(t)) {
        for segment in plan_sources(store, &source("logs"), &source("ocsf_logs"), start, Some(end)) {
            out.push(ArchiveSource { origin: origin_of(&segment), select: segment.select(), binds: segment.binds() });
        }
    }
    let bounds = vec![
        crate::sql_hygiene::format_ch_bound_micros(&start),
        crate::sql_hygiene::format_ch_bound_micros(&end),
    ];
    for &table in present {
        if view.contains(&table) {
            continue;
        }
        let (origin, projection) = match table {
            "ocsf_logs" => ("ocsf_logs", OCSF_AUDIT_PROJECTION),
            "ocsf_logs_legacy_v179" => ("ocsf_logs_legacy_v179", LEGACY_OCSF18_PROJECTION),
            // `logs` is in every view.
            _ => continue,
        };
        out.push(ArchiveSource {
            origin,
            select: format!(
                "SELECT {projection} FROM {} WHERE timestamp >= ? AND timestamp <= ? AND source_type = 'audit'",
                source(table)
            ),
            binds: bounds.clone(),
        });
    }
    out
}

/// Rows of `src` not yet in the archive (by origin and id), over the day.
fn not_archived(src: &ArchiveSource, archive_read: &str) -> String {
    format!(
        "FROM ({}) AS s WHERE toString(id) GLOBAL NOT IN \
         (SELECT id FROM {archive_read} WHERE origin_table = '{}' AND timestamp >= ? AND timestamp <= ?)",
        src.select, src.origin
    )
}

fn with_window(src: &ArchiveSource, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<String> {
    let mut binds = src.binds.clone();
    binds.push(crate::sql_hygiene::format_ch_bound_micros(&start));
    binds.push(crate::sql_hygiene::format_ch_bound_micros(&end));
    binds
}

/// `INSERT INTO <archive> SELECT ...` of the rows of `src` that are not in
/// the archive yet: a retry after a partial copy adds only what is missing.
pub(crate) fn insert_sql(
    src: &ArchiveSource,
    archive_write: &str,
    archive_read: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> (String, Vec<String>) {
    (
        format!(
            "INSERT INTO {archive_write} (origin_table, {ARCHIVE_COLUMNS}) SELECT '{}', {ARCHIVE_VALUES} {}",
            src.origin,
            not_archived(src, archive_read)
        ),
        with_window(src, start, end),
    )
}

/// `(rows in src, rows of src missing from the archive)` for the verify step.
pub(crate) fn verify_sql(
    src: &ArchiveSource,
    archive_read: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> (String, Vec<String>) {
    let mut binds = src.binds.clone();
    binds.extend(with_window(src, start, end));
    (
        format!(
            "SELECT (SELECT toUInt64(count()) FROM ({}) AS t) AS expected, (SELECT toUInt64(count()) {}) AS missing",
            src.select,
            not_archived(src, archive_read)
        ),
        binds,
    )
}

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;
