// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5839: SIEM Health flags a log source whose clock looks a whole
//! timezone off.
//!
//! A device that logs local time without an offset (PAN-OS `receive_time`,
//! RFC 3164 syslog, Check Point LEA, ...) is read in the log source's timezone
//! setting, UTC by default. The parser marks every event whose time it read
//! that way with `unmapped.nano_time_assumed_tz` = the zone it used
//! (parsers#87). If that zone is wrong, the stored time is off by the
//! device's real UTC offset, so the gap between event time and ingest time
//! sits near a whole hour, a half hour or a 45-minute offset.
//!
//! Per source type and assumed zone, over events INGESTED in the last
//! [`WINDOW_HOURS`] hours, this compares the median of `timestamp` minus
//! `_inserted_at`. A median within [`TOLERANCE_SECS`] of a real offset of at
//! least 30 minutes raises one finding per source ("events from X look N h
//! off; set its timezone"), naming the setting to use. Only marked events are
//! read, so a source that is genuinely delayed (a bucket pull hours behind)
//! is never mistaken for a timezone: its times carry an offset and no marker.

use std::collections::HashMap;

use chrono::{Offset, TimeZone, Utc};
use serde::Deserialize;

use super::types::{AnalysisResult, Recommendation};
use crate::auth::ScopeSet;
use crate::db::TableNames;
use crate::search::service::bind_source_scope;

/// Ingest window the gap is measured over.
pub const WINDOW_HOURS: u32 = 2;
/// A source needs at least this many marked events in the window.
pub const MIN_EVENTS: u64 = 20;
/// The median must be within this many seconds of a real offset. Normal
/// ingest latency (seconds to a minute or two) fits well inside it.
pub const TOLERANCE_SECS: i64 = 300;
/// Smallest offset reported: 30 minutes.
pub const MIN_OFFSET_SECS: i64 = 30 * 60;
/// Largest real UTC offset: 14 hours (+14:00, Line Islands).
pub const MAX_OFFSET_SECS: i64 = 14 * 3600;
/// Rows read back at most.
pub const MAX_ROWS: u32 = 200;

/// Title prefix shared by every finding (the title names the source, so a
/// suppression covers one source; numbers are not part of the signature).
pub const CLOCK_SKEW_TITLE_PREFIX: &str = "Events from ";

#[derive(Debug, Clone, clickhouse::Row, Deserialize, PartialEq, Eq)]
pub struct SkewRow {
    pub source_type: String,
    /// `unmapped.nano_time_assumed_tz`: the zone the parser read the clock in.
    pub assumed_tz: String,
    pub events: u64,
    /// Median of event time minus ingest time, in seconds.
    pub median_gap_secs: i64,
}

/// The query, kept separate so it can be asserted without ClickHouse.
///
/// One time-bounded WHERE, no explicit PREWHERE (NAN-1412). `timestamp` is
/// the partition and sort time; a skewed source's `timestamp` is up to 14
/// hours from its ingest time either way, so the bound is ingest window plus
/// that much on each side (the OCSF lane already clamps anything more than 24
/// hours in the future). `_inserted_at` then keeps the recent ingest window
/// and the marker keeps only clocks read without an offset. Bounded output
/// (LIMIT) and execution time.
pub fn skew_query(is_clustered: bool, scope: &ScopeSet) -> String {
    let table = TableNames::new(is_clustered).read(crate::schema::active_logs_table());
    let source_rows = super::collector::source_rows_predicate(scope);
    let back = WINDOW_HOURS + 15;
    format!(
        "SELECT source_type, \
         toString(unmapped.nano_time_assumed_tz) AS assumed_tz, \
         count() AS events, \
         toInt64(round(median(toUnixTimestamp64Milli(timestamp) - toUnixTimestamp64Milli(_inserted_at)) / 1000)) AS median_gap_secs \
         FROM {table} \
         WHERE timestamp >= now() - INTERVAL {back} HOUR AND timestamp <= now() + INTERVAL 15 HOUR \
         AND _inserted_at >= now() - INTERVAL {WINDOW_HOURS} HOUR \
         AND isNotNull(unmapped.nano_time_assumed_tz) \
         AND {source_rows} \
         GROUP BY source_type, assumed_tz \
         HAVING events >= {MIN_EVENTS} \
         ORDER BY events DESC, source_type, assumed_tz \
         LIMIT {MAX_ROWS} \
         SETTINGS max_execution_time = 60"
    )
}

/// Reads the per-source gaps. OCSF only: the marker lives in `ocsf_logs`.
pub async fn source_clock_skew(
    ch_client: &clickhouse::Client,
    is_clustered: bool,
    scope: &ScopeSet,
) -> Result<Vec<SkewRow>, clickhouse::error::Error> {
    bind_source_scope(ch_client.query(&skew_query(is_clustered, scope)), scope.deny_set())
        .fetch_all::<SkewRow>()
        .await
}

/// The real UTC offset (seconds) a median gap points at, or `None`.
///
/// The gap is rounded to the nearest quarter hour; it must be within
/// [`TOLERANCE_SECS`] of that, at least [`MIN_OFFSET_SECS`] and at most
/// [`MAX_OFFSET_SECS`] away from zero, and a whole hour, half hour or 45
/// minutes past the hour (a :15 offset does not exist).
pub fn offset_for_gap(gap_secs: i64) -> Option<i64> {
    let quarter = 15 * 60;
    let rounded = ((gap_secs as f64) / quarter as f64).round() as i64 * quarter;
    if (gap_secs - rounded).abs() > TOLERANCE_SECS {
        return None;
    }
    let magnitude = rounded.abs();
    if !(MIN_OFFSET_SECS..=MAX_OFFSET_SECS).contains(&magnitude) {
        return None;
    }
    match (magnitude % 3600) / 60 {
        0 | 30 | 45 => Some(rounded),
        _ => None,
    }
}

/// `±HH:MM` for an offset in seconds.
pub fn format_offset(offset_secs: i64) -> String {
    let sign = if offset_secs < 0 { '-' } else { '+' };
    let magnitude = offset_secs.abs();
    format!("{sign}{:02}:{:02}", magnitude / 3600, (magnitude % 3600) / 60)
}

/// `5`, `5.5`, `5.75` (hours, no sign) for the title.
fn format_hours(offset_secs: i64) -> String {
    let hours = offset_secs.abs() as f64 / 3600.0;
    let text = format!("{hours:.2}");
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// The current UTC offset of the zone a parser used, in seconds. `None` for a
/// name chrono-tz does not know (the parser would have used UTC then).
///
/// parsers#87 records a fixed-offset setting verbatim as `±HH:MM` (it reads
/// the clock as UTC and shifts it), an IANA setting as the zone name, and no
/// setting as `UTC`.
pub(crate) fn zone_offset_now(zone: &str) -> Option<i64> {
    if zone.eq_ignore_ascii_case("UTC") {
        return Some(0);
    }
    if let Some(offset) = parse_fixed_offset(zone) {
        return Some(offset);
    }
    let tz: chrono_tz::Tz = zone.parse().ok()?;
    let now = Utc::now().naive_utc();
    Some(tz.offset_from_utc_datetime(&now).fix().local_minus_utc() as i64)
}

/// `±HH:MM` / `±HHMM` in seconds (hours up to 14, minutes up to 59, as the
/// parsers accept), else `None`.
fn parse_fixed_offset(value: &str) -> Option<i64> {
    let sign = match value.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let digits: String = value[1..].chars().filter(|c| *c != ':').collect();
    if digits.len() != 4 || !digits.chars().all(|c| c.is_ascii_digit()) || value.len() > 6 {
        return None;
    }
    let hours: i64 = digits[..2].parse().ok()?;
    let minutes: i64 = digits[2..].parse().ok()?;
    (hours <= 14 && minutes <= 59).then_some(sign * (hours * 3600 + minutes * 60))
}

/// The one zone that runs at a fractional offset (standard or daylight
/// time), so recommending it is unambiguous and DST-correct. Whole-hour
/// offsets are shared by many zones with different DST rules: those get the
/// fixed offset.
fn unambiguous_zone(offset_secs: i64) -> Option<&'static str> {
    Some(match offset_secs {
        -34_200 => "Pacific/Marquesas",            // -09:30
        -12_600 | -9_000 => "America/St_Johns",    // -03:30 / -02:30 (DST)
        12_600 => "Asia/Tehran",                   // +03:30
        16_200 => "Asia/Kabul",                    // +04:30
        19_800 => "Asia/Kolkata",                  // +05:30
        20_700 => "Asia/Kathmandu",                // +05:45
        23_400 => "Asia/Yangon",                   // +06:30
        31_500 => "Australia/Eucla",               // +08:45
        45_900 | 49_500 => "Pacific/Chatham",      // +12:45 / +13:45 (DST)
        _ => return None,
    })
}

/// The value the finding tells the operator to set: one that passes the same
/// validator as the API and appears in the picker, or `None` when the
/// device's offset is not a real one (the finding then says so).
pub(crate) fn recommended_setting(device_offset_secs: i64) -> Option<String> {
    if device_offset_secs == 0 {
        return Some("UTC".to_string());
    }
    if !(-12 * 3600..=14 * 3600).contains(&device_offset_secs) {
        return None;
    }
    let candidate = unambiguous_zone(device_offset_secs)
        .map(str::to_string)
        .unwrap_or_else(|| format_offset(device_offset_secs));
    crate::timezone::normalize_source_timezone(&candidate)
        .ok()
        .filter(|normalized| *normalized == candidate)
}

/// One IANA zone per common whole-hour offset, as an EXAMPLE in the finding
/// text (the recommended value stays the fixed offset).
fn example_zone(offset_secs: i64) -> Option<&'static str> {
    Some(match offset_secs {
        -36_000 => "Pacific/Honolulu",
        -28_800 => "America/Los_Angeles",
        -25_200 => "America/Denver",
        -21_600 => "America/Chicago",
        -18_000 => "America/New_York",
        -14_400 => "America/Halifax",
        -10_800 => "America/Sao_Paulo",
        3_600 => "Europe/Berlin",
        7_200 => "Europe/Helsinki",
        10_800 => "Europe/Moscow",
        14_400 => "Asia/Dubai",
        19_800 => "Asia/Kolkata",
        20_700 => "Asia/Kathmandu",
        25_200 => "Asia/Bangkok",
        28_800 => "Asia/Singapore",
        32_400 => "Asia/Tokyo",
        36_000 => "Australia/Brisbane",
        43_200 => "Pacific/Auckland",
        _ => return None,
    })
}

/// A source that looks a timezone off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockSkew {
    /// What the finding calls the source: its log source name, else the route key.
    pub source: String,
    pub source_type: String,
    pub assumed_tz: String,
    pub events: u64,
    pub median_gap_secs: i64,
    /// The offset the stored times are off by.
    pub skew_secs: i64,
    /// The device's likely UTC offset (assumed zone's offset plus the skew).
    pub device_offset_secs: i64,
}

/// Pure: the rows that look a timezone off, worst first, one per source type
/// (the busiest assumed zone wins). `names` maps a route key to its log
/// source name.
pub fn skewed_sources(rows: &[SkewRow], names: &HashMap<String, String>) -> Vec<ClockSkew> {
    let mut by_source: HashMap<&str, ClockSkew> = HashMap::new();
    for row in rows {
        if row.events < MIN_EVENTS || row.source_type.is_empty() {
            continue;
        }
        let Some(skew) = offset_for_gap(row.median_gap_secs) else {
            continue;
        };
        // An unknown marker zone means the parser fell back to UTC.
        let base = zone_offset_now(&row.assumed_tz).unwrap_or(0);
        let found = ClockSkew {
            source: names
                .get(&row.source_type)
                .cloned()
                .unwrap_or_else(|| row.source_type.clone()),
            source_type: row.source_type.clone(),
            assumed_tz: row.assumed_tz.clone(),
            events: row.events,
            median_gap_secs: row.median_gap_secs,
            skew_secs: skew,
            device_offset_secs: base + skew,
        };
        let busier = by_source
            .get(row.source_type.as_str())
            .is_none_or(|existing| existing.events < row.events);
        if busier {
            by_source.insert(row.source_type.as_str(), found);
        }
    }
    let mut out: Vec<ClockSkew> = by_source.into_values().collect();
    out.sort_by(|a, b| {
        b.skew_secs
            .abs()
            .cmp(&a.skew_secs.abs())
            .then(b.events.cmp(&a.events))
            .then(a.source_type.cmp(&b.source_type))
    });
    out
}

/// The finding title for one source.
pub fn finding_title(skew: &ClockSkew) -> String {
    let action = if skew.assumed_tz.eq_ignore_ascii_case("UTC") {
        "set its timezone"
    } else {
        "check its timezone"
    };
    format!(
        "{CLOCK_SKEW_TITLE_PREFIX}{} look {} h off; {action}",
        skew.source,
        format_hours(skew.skew_secs)
    )
}

fn finding(skew: &ClockSkew) -> Recommendation {
    let direction = if skew.skew_secs < 0 { "behind" } else { "ahead of" };
    let offset = format_offset(skew.device_offset_secs);
    let action = match recommended_setting(skew.device_offset_secs) {
        Some(setting) => {
            let example = if setting.starts_with(['+', '-']) {
                example_zone(skew.device_offset_secs)
                    .map(|zone| {
                        format!(
                            " (or the device's IANA zone if it observes daylight saving time, for example {zone})"
                        )
                    })
                    .unwrap_or_default()
            } else {
                String::new()
            };
            format!("In the log source settings, set Timezone to `{setting}`{example}.")
        }
        None => format!(
            "UTC{offset} is not a real UTC offset, so check the device's clock and set the log source's \
             Timezone to the device's IANA zone."
        ),
    };
    let read_as = if skew.assumed_tz.eq_ignore_ascii_case("UTC") {
        "UTC, because the log source has no timezone set".to_string()
    } else {
        format!("{}, the log source's timezone setting", skew.assumed_tz)
    };
    let source_type = if skew.source == skew.source_type {
        String::new()
    } else {
        format!(" (source type `{}`)", skew.source_type)
    };
    Recommendation {
        title: finding_title(skew),
        description: format!(
            "Over the last {WINDOW_HOURS} hours, {} events from `{}`{source_type} carried a time with no \
             offset, which was read as {read_as}. Their median event time is {} {direction} the time \
             they were ingested, so the device most likely logs local time at UTC{offset}. Searches, \
             timelines and detections see these events {} off. {action} The setting applies only to \
             timestamps without an offset, and only to events ingested after it is saved and deployed.",
            skew.events,
            skew.source,
            format!("{} h", format_hours(skew.skew_secs)),
            format!("{} h", format_hours(skew.skew_secs)),
        ),
        priority: "medium".to_string(),
    }
}

/// Adds one medium-priority finding per skewed source (idempotent by title).
pub fn ensure_clock_skew_findings(
    analysis: &mut AnalysisResult,
    rows: &[SkewRow],
    names: &HashMap<String, String>,
) {
    for skew in skewed_sources(rows, names) {
        let rec = finding(&skew);
        if !analysis.recommendations.iter().any(|r| r.title == rec.title) {
            analysis.recommendations.push(rec);
        }
    }
}

/// Route key → log source name, for the finding text. A read failure leaves
/// the route keys as the names.
pub async fn load_source_names(pool: &sqlx::PgPool) -> HashMap<String, String> {
    let rows: Vec<(String, Option<Vec<String>>)> =
        match sqlx::query_as("SELECT name, match_values FROM log_sources WHERE enabled")
            .fetch_all(pool)
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(%error, "could not read log source names for the clock-skew finding");
                return HashMap::new();
            }
        };
    let mut names = HashMap::new();
    for (name, values) in rows {
        for key in crate::log_sources::health_series::route_keys_for(values.as_deref(), &name) {
            names.entry(key).or_insert_with(|| name.clone());
        }
    }
    names
}

#[cfg(test)]
#[path = "source_clock_skew_tests.rs"]
mod tests;
