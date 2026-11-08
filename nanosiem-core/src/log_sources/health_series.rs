// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-log-source health series on the ClickHouse product (NAN-4922).
//!
//! The chart contract of main's NAN-3207 (`GET /api/log-sources/health-series`):
//! hourly volume against a seasonal expected band. Main computed it from the
//! hosted lake's ingest counters; here it is read from the per-source rollup
//! `logs_per_source_5m_v2` (7-day TTL), summed per hour and keyed by each
//! source's route keys exactly like the connect-state read
//! ([`super::connect::activity_sql`]), with the caller's source scope applied.
//!
//! The detector math (seasonal median, MAD band, bucket assessment, NAN-3246
//! coverage/learning) is main's `enterprise_shared_segment_health` total-series
//! logic, without segments: this rollup carries no segment dimensions, so
//! `segments` is always empty and `segments_available` false.

use std::collections::BTreeMap;

use chrono::{DateTime, Datelike, Duration, DurationRound, Utc, Weekday};
use clickhouse::Client as ClickHouseClient;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::types::LogSource;
use crate::auth::ScopeSet;
use crate::search::service::source_scope_sql_predicate;

/// Same-hour look-back days the baseline draws from.
pub const BASELINE_DAYS: i64 = 7;
/// Largest window a caller may ask for (the rollup keeps 7 days).
pub const MAX_SERIES_HOURS: i64 = 168;
pub const DEFAULT_SERIES_HOURS: i64 = 24;
/// The rollup's retention: nothing older can be read.
const ROLLUP_RETENTION_HOURS: i64 = 7 * 24;

const HOUR: Duration = Duration::hours(1);

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HealthPolicy {
    /// Series whose baseline median is below this many events per hour are not judged.
    pub min_baseline_per_hour: f64,
    /// A bucket is dropped when observed <= (1 - drop_fraction) x baseline.
    pub drop_fraction: f64,
    /// A bucket is normal when observed >= recover_fraction x baseline.
    pub recover_fraction: f64,
    /// Baseline samples required (of the 7 daily look-backs).
    pub min_samples: usize,
    /// An hour is judged once it ended this long ago.
    pub settle_minutes: i64,
}

impl Default for HealthPolicy {
    fn default() -> Self {
        Self {
            min_baseline_per_hour: 30.0,
            drop_fraction: 0.9,
            recover_fraction: 0.5,
            min_samples: 3,
            settle_minutes: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// Series + baseline (pure)
// ---------------------------------------------------------------------------

pub fn hour_floor(at: DateTime<Utc>) -> DateTime<Utc> {
    at.duration_trunc(HOUR).unwrap_or(at)
}

/// Hourly counts known from `covers_from` on (hours before are unknown, not
/// zero; hours inside with no entry are zero).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HourlySeries {
    pub covers_from: Option<DateTime<Utc>>,
    pub counts: BTreeMap<DateTime<Utc>, i64>,
}

impl HourlySeries {
    pub fn first_observed(&self) -> Option<DateTime<Utc>> {
        self.counts.iter().find(|(_, events)| **events > 0).map(|(hour, _)| *hour)
    }

    pub fn covered_lookback_days(&self, hour: DateTime<Utc>) -> usize {
        (1..=BASELINE_DAYS).filter(|days| self.at(hour - Duration::days(*days)).is_some()).count()
    }

    pub fn add(&mut self, hour: DateTime<Utc>, events: i64) {
        let slot = self.counts.entry(hour_floor(hour)).or_default();
        *slot = slot.saturating_add(events);
    }

    pub fn at(&self, hour: DateTime<Utc>) -> Option<i64> {
        match self.covers_from {
            Some(from) if hour >= from => Some(self.counts.get(&hour).copied().unwrap_or(0)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Baseline {
    pub expected: f64,
    pub low: f64,
    pub high: f64,
    pub samples: usize,
}

fn weekend(at: DateTime<Utc>) -> bool {
    matches!(at.weekday(), Weekday::Sat | Weekday::Sun)
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.total_cmp(b));
    let n = values.len();
    if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    }
}

/// Hour-of-day x day-class seasonal median of the previous [`BASELINE_DAYS`];
/// the band is median +- 3 x 1.4826 x MAD (at least +-10 % of the median).
pub fn seasonal_baseline(series: &HourlySeries, hour: DateTime<Utc>, policy: &HealthPolicy) -> Option<Baseline> {
    let samples: Vec<(f64, bool)> = (1..=BASELINE_DAYS)
        .filter_map(|days| {
            let at = hour - Duration::days(days);
            series.at(at).map(|v| (v as f64, weekend(at) == weekend(hour)))
        })
        .collect();
    let same: Vec<f64> = samples.iter().filter(|(_, same)| *same).map(|(v, _)| *v).collect();
    let mut pool: Vec<f64> = if same.len() >= policy.min_samples.max(1) {
        same
    } else {
        samples.iter().map(|(v, _)| *v).collect()
    };
    if pool.len() < policy.min_samples.max(1) {
        return None;
    }
    let expected = median(&mut pool);
    let mut deviations: Vec<f64> = pool.iter().map(|v| (v - expected).abs()).collect();
    let spread = (1.4826 * median(&mut deviations)).max(0.1 * expected);
    Some(Baseline {
        expected,
        low: (expected - 3.0 * spread).max(0.0),
        high: expected + 3.0 * spread,
        samples: pool.len(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BucketAssessment {
    /// No usable baseline (too few samples, or below the volume floor).
    NoBaseline,
    /// The source delivered nothing that hour.
    SourceSilent,
    Dropped,
    /// Below normal but above the drop line.
    Low,
    Normal,
}

pub fn assess(observed: i64, baseline: Option<Baseline>, source_observed: Option<i64>, policy: &HealthPolicy) -> BucketAssessment {
    let Some(baseline) = baseline.filter(|b| b.expected >= policy.min_baseline_per_hour) else {
        return BucketAssessment::NoBaseline;
    };
    if source_observed.unwrap_or(0) <= 0 {
        return BucketAssessment::SourceSilent;
    }
    let observed = observed as f64;
    if observed <= baseline.expected * (1.0 - policy.drop_fraction) {
        BucketAssessment::Dropped
    } else if observed >= baseline.expected * policy.recover_fraction {
        BucketAssessment::Normal
    } else {
        BucketAssessment::Low
    }
}

/// The newest judgeable (settled) hour at `now`.
pub fn newest_judged_hour(now: DateTime<Utc>, policy: &HealthPolicy) -> DateTime<Utc> {
    hour_floor(now - Duration::minutes(policy.settle_minutes.max(0))) - HOUR
}

// ---------------------------------------------------------------------------
// Chart contract (matches main's web `LogSourceHealthSeries`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceHealthState {
    Healthy,
    /// The newest judged hour is below the source's expected band.
    Degraded,
    /// No events in the last hour (or none at all in the window).
    Stale,
    /// A segment is in a confirmed drop (never produced here: no segments).
    SegmentDrop,
    Disabled,
    /// Fewer than `baseline_days_required` same-hour days of history.
    Learning,
    /// Not judgeable for another reason.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SegmentDimension {
    Class,
    Product,
    Region,
    Account,
    Service,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct HealthSeriesPoint {
    /// Hourly, oldest first; the last point is the current (partial) hour.
    pub hour: DateTime<Utc>,
    pub events: i64,
    /// Seasonal median; absent while the baseline is unknown.
    pub expected: Option<f64>,
    pub low: Option<f64>,
    pub high: Option<f64>,
    /// Settled hours only; the current hour is never judged.
    pub assessment: Option<BucketAssessment>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SegmentHealthSeries {
    pub dimension: SegmentDimension,
    pub value: String,
    pub search_field: String,
    pub other: bool,
    pub state: SourceHealthState,
    pub dropped_since: Option<DateTime<Utc>>,
    pub baseline_days: u32,
    pub baseline_days_required: u32,
    pub window_events: i64,
    pub points: Vec<HealthSeriesPoint>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LogSourceHealthSeries {
    #[serde(with = "crate::typeid::log_source")]
    #[schema(value_type = String)]
    pub log_source_id: Uuid,
    pub log_source_name: String,
    /// The route keys (`source_type` values) this source's events carry.
    pub source_slugs: Vec<String>,
    pub state: SourceHealthState,
    pub window_hours: i64,
    pub last_event_at: Option<DateTime<Utc>>,
    /// Same-hour look-back days of history behind the newest judged hour (0..=7).
    pub baseline_days: u32,
    /// Days needed before a baseline exists.
    pub baseline_days_required: u32,
    pub points: Vec<HealthSeriesPoint>,
    /// Always empty on this product (the rollup has no segment dimensions).
    pub segments: Vec<SegmentHealthSeries>,
    /// Always false on this product.
    pub segments_available: bool,
}

/// One rollup row: a route key's events in one hour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HourlyCount {
    pub route_key: String,
    pub hour: DateTime<Utc>,
    pub events: i64,
    pub last_event_at: Option<DateTime<Utc>>,
}

/// The route keys a source's events carry: its match values (lowercased, as
/// the rollup stores them), else its safe name. Same rule as
/// [`super::connect::claimed_route_keys`], per source.
pub fn source_route_keys(source: &LogSource) -> Vec<String> {
    let mut keys: Vec<String> = match source.match_values.as_deref() {
        Some(values) if !values.is_empty() => values
            .iter()
            .map(|v| v.trim().to_lowercase())
            .filter(|v| !v.is_empty())
            .collect(),
        _ => vec![crate::vector_naming::safe_name(&source.name)],
    };
    keys.sort();
    keys.dedup();
    keys
}

/// Pure: one source's series over the last `window_hours` (current hour
/// included). `counts` may hold other sources' keys; only `keys` are summed.
/// `data_start` is the earliest hour the read covered (coverage is clamped to it).
#[allow(clippy::too_many_arguments)]
pub fn build_series(
    id: Uuid,
    name: &str,
    keys: &[String],
    enabled: bool,
    counts: &[HourlyCount],
    data_start: DateTime<Utc>,
    window_hours: i64,
    now: DateTime<Utc>,
    policy: &HealthPolicy,
) -> LogSourceHealthSeries {
    let window_hours = window_hours.clamp(1, MAX_SERIES_HOURS);
    let current = hour_floor(now);
    let hours: Vec<DateTime<Utc>> = (0..window_hours).rev().map(|back| current - Duration::hours(back)).collect();
    let judged_until = newest_judged_hour(now, policy);

    let mut total = HourlySeries::default();
    let mut last_event_at: Option<DateTime<Utc>> = None;
    // Event timestamps are sender-controlled: a bucket after the current hour
    // is ignored (the SQL bounds it too), and a last event in the future is
    // clamped to now, so a 2099-dated event can never keep a source fresh.
    for row in counts
        .iter()
        .filter(|r| r.hour <= current && keys.iter().any(|k| k == &r.route_key))
    {
        total.add(row.hour, row.events);
        if row.events > 0 {
            let at = row.last_event_at.unwrap_or(row.hour).min(now);
            last_event_at = last_event_at.max(Some(at));
        }
    }
    // NAN-3246: coverage starts at the first observed hour (clamped to the read).
    total.covers_from = total.first_observed().map(|first| first.max(hour_floor(data_start)));

    let points: Vec<HealthSeriesPoint> = hours
        .iter()
        .map(|&hour| {
            let events = total.at(hour).unwrap_or(0);
            let baseline = seasonal_baseline(&total, hour, policy);
            HealthSeriesPoint {
                hour,
                events,
                expected: baseline.map(|b| b.expected),
                low: baseline.map(|b| b.low),
                high: baseline.map(|b| b.high),
                // The source total is the observation: an empty hour is `source_silent`.
                assessment: (hour <= judged_until).then(|| assess(events, baseline, Some(events), policy)),
            }
        })
        .collect();

    let required = policy.min_samples.max(1);
    let baseline_days = total.covered_lookback_days(judged_until);
    // The exact last-event age is authoritative (at 12:59 a source last seen at
    // 11:01 is stale even though the 11:00 bucket has events); bucket totals
    // decide only when no timestamp exists.
    let silent = match last_event_at {
        Some(last) => now - last > HOUR,
        None => total.at(current).unwrap_or(0) + total.at(current - HOUR).unwrap_or(0) == 0,
    };
    let state = if !enabled {
        SourceHealthState::Disabled
    } else if silent {
        SourceHealthState::Stale
    } else {
        match points.iter().rev().find(|p| p.assessment.is_some()) {
            Some(HealthSeriesPoint { events, low: Some(low), assessment: Some(a), .. })
                if *a != BucketAssessment::NoBaseline && (*events as f64) < *low =>
            {
                SourceHealthState::Degraded
            }
            _ if baseline_days < required => SourceHealthState::Learning,
            _ if last_event_at.is_some() => SourceHealthState::Healthy,
            _ => SourceHealthState::Unknown,
        }
    };
    LogSourceHealthSeries {
        log_source_id: id,
        log_source_name: name.to_string(),
        source_slugs: keys.to_vec(),
        state,
        window_hours,
        last_event_at,
        baseline_days: baseline_days as u32,
        baseline_days_required: required as u32,
        points,
        segments: Vec::new(),
        segments_available: false,
    }
}

/// Pure: the series for every non-enrichment source, in input order.
pub fn build_all_series(
    sources: &[LogSource],
    counts: &[HourlyCount],
    data_start: DateTime<Utc>,
    window_hours: i64,
    now: DateTime<Utc>,
    policy: &HealthPolicy,
) -> Vec<LogSourceHealthSeries> {
    sources
        .iter()
        .filter(|s| s.kind != "enrichment")
        .map(|s| {
            let keys = source_route_keys(s);
            // Same rule as `connect::connect_state`: `enabled` only matters once a
            // parser is deployed. An undeployed (draft) source receives through
            // its tokens and is judged on its data, never shown as disabled.
            let judged = s.enabled || !s.deployed;
            build_series(s.id, &s.name, &keys, judged, counts, data_start, window_hours, now, policy)
        })
        .collect()
}

/// Hours read: the window plus the baseline look-back, capped at retention.
pub fn read_hours(window_hours: i64) -> i64 {
    (window_hours.clamp(1, MAX_SERIES_HOURS) + BASELINE_DAYS * 24).min(ROLLUP_RETENTION_HOURS + 1)
}

/// One rollup scan for exactly `keys`, hourly, with the caller's deny set
/// applied on the raw scope key (as [`super::connect::activity_sql`]).
pub fn hourly_sql(rollup_table: &str, profile: &str, hours: i64, scope: &ScopeSet, keys: &[String]) -> String {
    let list = keys
        .iter()
        .map(|k| format!("'{}'", crate::sql_hygiene::escape_sql_string(k.trim().to_lowercase())))
        .collect::<Vec<_>>()
        .join(", ");
    let scope_sql = if scope.is_restricted() {
        let predicate = source_scope_sql_predicate("scope_source_type", scope.deny_set())
            .expect("a restricted ScopeSet always renders a predicate");
        format!(" AND scope_source_type_complete = 1 AND {predicate}")
    } else {
        String::new()
    };
    format!(
        "SELECT source_type AS route_key, \
                toUnixTimestamp(toStartOfHour(bucket_start)) AS hour_s, \
                sum(events) AS events, \
                toUnixTimestamp64Milli(max(last_event_at)) AS last_ms \
         FROM {rollup_table} \
         WHERE bucket_start >= toStartOfHour(now()) - INTERVAL {hours} HOUR \
           AND bucket_start < toStartOfHour(now()) + INTERVAL 1 HOUR \
           AND schema_profile = '{profile}'{scope_sql} AND source_type IN ({list}) \
         GROUP BY route_key, hour_s \
         ORDER BY route_key, hour_s",
        profile = crate::sql_hygiene::escape_sql_string(profile),
    )
}

/// Parses the scan's `JSONEachRow` output (UInt64 arrives quoted).
pub fn parse_hourly_rows(body: &str) -> Vec<HourlyCount> {
    fn num(json: &serde_json::Value, key: &str) -> Option<i64> {
        json.get(key).and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_u64().map(|u| u as i64))
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
    }
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|json| {
            Some(HourlyCount {
                route_key: json.get("route_key")?.as_str()?.to_string(),
                hour: DateTime::from_timestamp(num(&json, "hour_s")?, 0)?,
                events: num(&json, "events").unwrap_or(0).max(0),
                last_event_at: num(&json, "last_ms").filter(|ms| *ms > 0).and_then(DateTime::from_timestamp_millis),
            })
        })
        .collect()
}

#[derive(Clone)]
pub struct HealthSeriesReader {
    ch: ClickHouseClient,
    table_names: crate::db::TableNames,
}

impl HealthSeriesReader {
    pub fn new(ch: ClickHouseClient, table_names: crate::db::TableNames) -> Self {
        Self { ch, table_names }
    }

    /// Series for `sources` over `window_hours`, visible to `scope`.
    pub async fn series(
        &self,
        sources: &[LogSource],
        window_hours: i64,
        scope: &ScopeSet,
    ) -> Result<Vec<LogSourceHealthSeries>, String> {
        let window_hours = window_hours.clamp(1, MAX_SERIES_HOURS);
        let now = Utc::now();
        let hours = read_hours(window_hours);
        let data_start = hour_floor(now) - Duration::hours(hours);
        let mut keys: Vec<String> = sources
            .iter()
            .filter(|s| s.kind != "enrichment")
            .flat_map(source_route_keys)
            .collect();
        keys.sort();
        keys.dedup();
        let counts = if keys.is_empty() {
            Vec::new()
        } else {
            self.read(&keys, hours, scope).await?
        };
        Ok(build_all_series(sources, &counts, data_start, window_hours, now, &HealthPolicy::default()))
    }

    async fn read(&self, keys: &[String], hours: i64, scope: &ScopeSet) -> Result<Vec<HourlyCount>, String> {
        let sql = hourly_sql(
            &self.table_names.read("logs_per_source_5m_v2"),
            crate::schema::active_log_telemetry_profile(),
            hours,
            scope,
            keys,
        );
        let mut cursor = self.ch.query(&sql).fetch_bytes("JSONEachRow").map_err(|e| e.to_string())?;
        let mut body = Vec::new();
        while let Some(chunk) = cursor.next().await.map_err(|e| e.to_string())? {
            body.extend_from_slice(&chunk);
        }
        let body = String::from_utf8(body).map_err(|e| e.to_string())?;
        Ok(parse_hourly_rows(&body))
    }
}
