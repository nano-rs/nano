// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daily ingest metering (NAN-5170).
//!
//! Copies per-UTC-day customer ingest totals, by ARRIVAL time, from the
//! ClickHouse `ingest_volume_1h` rollup (clickhouse/194) into PostgreSQL
//! `daily_usage`, which the rollup's 35-day TTL would otherwise forget. A day's
//! total is what nano received that day (the Self-Run Addendum's Daily
//! Ingest), so backfilled history counts on the day it arrives and nothing
//! lands on a day after it ends.
//!
//! The record stays on this deployment: it drives the in-app capacity warning
//! and, in licensed builds, the daily totals reported to nano or exported for
//! an offline renewal. Metering never touches ingest.

use chrono::{DateTime, NaiveDate, Utc};

use super::tier::{TierError, TierSettings};
use crate::log_telemetry::{DailyIngestTotal, LogTelemetryService};

/// Complete days re-metered before today (well inside the rollup's TTL).
pub const METER_LOOKBACK_DAYS: i64 = 5;

/// How often the leader re-meters the window.
pub const METER_INTERVAL_SECS: u64 = 15 * 60;

#[derive(Debug, thiserror::Error)]
pub enum UsageMeterError {
    #[error("rollup read failed: {0}")]
    Telemetry(#[from] crate::log_telemetry::LogTelemetryError),
    #[error("usage write failed: {0}")]
    Store(#[from] TierError),
}

/// The metering window ending today (inclusive), oldest first.
pub fn meter_window(today: NaiveDate) -> (NaiveDate, NaiveDate) {
    (today - chrono::Duration::days(METER_LOOKBACK_DAYS), today)
}

/// Whether arrival metering covered all of `day`. The day the rollup first
/// saw anything was only partly metered (the view started mid-day), so it is
/// never recorded; any day after it, or after a day already recorded, is.
pub fn fully_metered(
    day: NaiveDate,
    meter_start: Option<DateTime<Utc>>,
    earliest_recorded: Option<NaiveDate>,
) -> bool {
    meter_start.is_some_and(|start| start.date_naive() < day)
        || earliest_recorded.is_some_and(|earliest| earliest < day)
}

/// Every fully metered day in `[from, to]`, taking the rollup total where
/// present and an explicit zero otherwise, so a day with no ingest is still
/// recorded.
pub fn days_to_record(
    totals: &[DailyIngestTotal],
    from: NaiveDate,
    to: NaiveDate,
    meter_start: Option<DateTime<Utc>>,
    earliest_recorded: Option<NaiveDate>,
) -> Vec<DailyIngestTotal> {
    from.iter_days()
        .take_while(|day| *day <= to)
        .filter(|day| fully_metered(*day, meter_start, earliest_recorded))
        .map(|day| {
            totals
                .iter()
                .find(|total| total.day == day)
                .cloned()
                .unwrap_or(DailyIngestTotal {
                    day,
                    events: 0,
                    bytes: 0,
                })
        })
        .collect()
}

/// Meter the window ending `today` once. Returns the number of days written.
pub async fn meter_once(
    telemetry: &LogTelemetryService,
    tier: &TierSettings,
    today: NaiveDate,
) -> Result<usize, UsageMeterError> {
    let (from, to) = meter_window(today);
    let meter_start = telemetry.ingest_meter_start().await?;
    let earliest_recorded = tier.earliest_metered_day().await?;
    let totals = telemetry.daily_ingest_totals(from, to).await?;
    let days = days_to_record(&totals, from, to, meter_start, earliest_recorded);
    for day in &days {
        tier.upsert_metered_usage(day.day, day.bytes, day.events)
            .await?;
    }
    Ok(days.len())
}

#[cfg(test)]
#[path = "usage_meter_tests.rs"]
mod tests;
