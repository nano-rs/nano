// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-source field census for rule-repository coverage (NAN-5271 #28).
//!
//! Coverage used to store an empty field set for every source type, so a rule
//! that named any field could never be judged against real telemetry. This
//! module records which fields each source actually carries, on both schemas:
//!
//! - **Columns.** Every queryable column of the active ingested-events table
//!   (`logs` under UDM, `ocsf_logs` under OCSF), probed for a non-default value
//!   over a bounded, recent slice of the source's rows.
//! - **Spill keys.** The keys of the profile's spill column (`ext` under UDM,
//!   `unmapped` under OCSF), from the search fields panel's spill scan.
//!
//! Rule fields and census entries meet on a [`census_key`]: the physical column
//! the active profile resolves a name to, or `<spill>:<key>` for a spill key.
//! That is what makes the comparison schema-aware: `src_ip` in a UDM rule and
//! `src_endpoint.ip` in an OCSF rule land on whatever column holds the value on
//! the running schema, through the same resolver search uses.
//!
//! An empty census set means "not known" (no recent rows, or the scan failed),
//! never "this source has no fields". Coverage only reports a field as missing
//! against sources whose census is known.

use std::collections::HashSet;

use chrono::{DateTime, Duration, Utc};

use crate::schema::{FieldResolution, SchemaId, SchemaProfile};
use crate::sql_hygiene::escape_sql_string;

/// The recent window the census reads first.
pub(crate) const CENSUS_RECENT_HOURS: i64 = 24;

/// The wider window read only when the recent one has no rows for the source.
pub(crate) const CENSUS_FALLBACK_DAYS: i64 = 7;

/// Rows per source the census aggregates.
pub(crate) const CENSUS_ROWS_PER_SOURCE: usize = 5_000;

/// Hard cap on rows one census query reads, in `break` mode (a partial
/// result, never an error).
pub(crate) const CENSUS_MAX_ROWS_TO_READ: usize = 2_000_000;

/// Census queries run at most this many at once.
pub(crate) const CENSUS_CONCURRENCY: usize = 4;

/// Columns that are bookkeeping or routing, not fields a rule can lack.
const NON_CENSUS_COLUMNS: &[&str] = &[
    "id",
    "timestamp",
    "source_type",
    "raw_data",
    "event_bytes",
    "ingest_time",
    "namespace",
    "metadata",
    "ext",
    "unmapped",
    "event",
];

/// Spill key recorded when the spill scan failed: every spill key of that
/// source is treated as present rather than reported missing.
pub(crate) const SPILL_UNKNOWN: &str = "*";

/// True when `census` (a KNOWN, non-empty set) carries `key`.
pub(crate) fn census_has(census: &HashSet<String>, spill_column: &str, key: &str) -> bool {
    census.contains(key)
        || (key.starts_with(&format!("{spill_column}:"))
            && census.contains(&spill_key(spill_column, SPILL_UNKNOWN)))
}

/// Census key of a spill-column key.
pub(crate) fn spill_key(spill_column: &str, key: &str) -> String {
    format!("{spill_column}:{key}")
}

/// The census key a field name resolves to on `profile`, or `None` when the
/// census cannot judge it (an OCSF attribute that only lives in the stored
/// `event` object, or an array element). Fields with no key are never reported
/// missing.
pub(crate) fn census_key(profile: &dyn SchemaProfile, field: &str) -> Option<String> {
    let spill = profile.json_tail_column();
    match profile.resolve(field) {
        FieldResolution::ExplicitColumn(col) | FieldResolution::Alias(col) => Some(col),
        FieldResolution::JsonPath { col, path } if col == spill => {
            Some(spill_key(spill, &path.join(".")))
        }
        // UDM: a name outside the column universe IS an `ext` key.
        FieldResolution::Unknown if profile.id() == SchemaId::Udm => {
            let key = field
                .strip_prefix("ext.")
                .unwrap_or(field)
                .to_ascii_lowercase();
            Some(spill_key(spill, &key))
        }
        _ => None,
    }
}

/// The column inventory query: every queryable column of `bare_table`.
/// ALIAS columns are kept, because some UDM-name aliases resolve onto them.
pub(crate) fn build_census_columns_sql(bare_table: &str) -> String {
    let excluded = NON_CENSUS_COLUMNS
        .iter()
        .map(|c| format!("'{c}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "SELECT name FROM system.columns \
         WHERE database = 'nanosiem' \
           AND table = '{}' \
           AND type NOT LIKE '%Map%' \
           AND type NOT LIKE 'JSON%' \
           AND type NOT LIKE 'Object%' \
           AND default_kind != 'EPHEMERAL' \
           AND name NOT LIKE '\\\\_%' \
           AND name NOT LIKE '%\\\\_search' \
           AND name NOT LIKE '%.search' \
           AND name NOT IN ({excluded}) \
         ORDER BY name",
        escape_sql_string(bare_table)
    )
}

/// One bounded scan over `source_type`'s rows in `[start, end]` that returns
/// the columns carrying a value in at least one sampled row. A value counts as
/// present unless it renders as `''`, `0`, `false` or `[]` (the defaults the
/// promoted columns use for "absent"). Single WHERE with the time bounds; no
/// explicit PREWHERE (NAN-1412).
pub(crate) fn build_column_census_sql(
    table: &str,
    columns: &[String],
    source_type: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Option<String> {
    if columns.is_empty() {
        return None;
    }
    let projection = columns
        .iter()
        .enumerate()
        .map(|(i, c)| {
            format!(
                "{} AS __census_{i}",
                crate::query::escape_identifier(c)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let names = columns
        .iter()
        .map(|c| format!("'{}'", escape_sql_string(c)))
        .collect::<Vec<_>>()
        .join(", ");
    let counts = (0..columns.len())
        .map(|i| {
            format!("toUInt64(countIf(toString(__census_{i}) NOT IN ('', '0', 'false', '[]')))")
        })
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "SELECT arrayFilter((n, c) -> c > 0, [{names}], [{counts}]) AS present \
         FROM ( \
             SELECT {projection} \
             FROM {table} \
             WHERE timestamp BETWEEN '{}' AND '{}' \
               AND source_type = '{}' \
             LIMIT {CENSUS_ROWS_PER_SOURCE} \
         ) \
         SETTINGS max_execution_time = 5, timeout_overflow_mode = 'break', \
             max_rows_to_read = {CENSUS_MAX_ROWS_TO_READ}, read_overflow_mode = 'break'",
        start.format("%Y-%m-%d %H:%M:%S"),
        end.format("%Y-%m-%d %H:%M:%S"),
        escape_sql_string(source_type),
    ))
}

/// The predicate the spill-key scan runs under for one source.
pub(crate) fn census_predicate(source_type: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> String {
    format!(
        "timestamp BETWEEN '{}' AND '{}' AND source_type = '{}'",
        start.format("%Y-%m-%d %H:%M:%S"),
        end.format("%Y-%m-%d %H:%M:%S"),
        escape_sql_string(source_type),
    )
}

/// The census windows, recent first.
pub(crate) fn census_windows(now: DateTime<Utc>) -> [(DateTime<Utc>, DateTime<Utc>); 2] {
    [
        (now - Duration::hours(CENSUS_RECENT_HOURS), now),
        (now - Duration::days(CENSUS_FALLBACK_DAYS), now),
    ]
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct PresentRow {
    present: Vec<String>,
}

/// Run the census for one source. Errors and empty windows yield an empty set,
/// which callers read as "census unknown".
pub(crate) async fn census_source(
    client: &clickhouse::Client,
    profile: &dyn SchemaProfile,
    table: &str,
    columns: &[String],
    source_type: &str,
    now: DateTime<Utc>,
) -> HashSet<String> {
    let mut out = HashSet::new();
    for (start, end) in census_windows(now) {
        let Some(sql) = build_column_census_sql(table, columns, source_type, start, end) else {
            break;
        };
        match client.query(&sql).fetch_all::<PresentRow>().await {
            Ok(rows) => {
                for row in rows {
                    out.extend(row.present);
                }
            }
            Err(e) => {
                tracing::warn!(source_type, error = %e, "rule coverage: column census failed");
                return HashSet::new();
            }
        }
        if out.is_empty() {
            continue;
        }
        let spill = profile.json_tail_column();
        match crate::search::service::dynamic_field_names_for_predicate(
            client,
            profile,
            table,
            crate::search::service::DynamicFieldBucket::Spill,
            &census_predicate(source_type, start, end),
        )
        .await
        {
            Ok(keys) => out.extend(keys.iter().map(|k| spill_key(spill, k))),
            Err(e) => {
                // The columns are still a known census; the spill is not, so
                // no spill key may be reported missing for this source.
                tracing::warn!(source_type, error = %e, "rule coverage: spill census failed");
                out.insert(spill_key(spill, SPILL_UNKNOWN));
            }
        }
        break;
    }
    out
}
