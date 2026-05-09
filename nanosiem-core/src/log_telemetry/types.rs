// SPDX-License-Identifier: AGPL-3.0-or-later

//! Types returned by the log telemetry rollup repository.

use chrono::{DateTime, Utc};

/// Aggregated per-`source_type` stats for a recent time window.
///
/// All values represent the rollup as observed in the queried window — no
/// extrapolation, no sampling.
#[derive(Debug, Clone, Default)]
pub struct SourceTypeStats {
    /// Lowercased source_type (the rollup MV writes lowercased values).
    pub source_type: String,
    /// Total events in the window.
    pub events: u64,
    /// Sum of `length(message) + length(metadata)` over the window.
    pub bytes: u64,
    /// Most recent event timestamp seen in the window. `None` when the
    /// rollup has no rows for this source_type.
    pub last_event_at: Option<DateTime<Utc>>,
    /// Earliest event timestamp seen in the window.
    pub first_event_at: Option<DateTime<Utc>>,
}

/// A single (source_type, bucket_start, events) row from the rollup,
/// re-aggregated to the caller's requested bucket size. Used by the
/// ingestion-history area chart on the log sources page.
#[derive(Debug, Clone)]
pub struct HourlyPoint {
    pub source_type: String,
    pub bucket_start: DateTime<Utc>,
    pub events: u64,
}

/// Bucket size for `LogTelemetryRepository::buckets`. The rollup's native
/// granularity is 5 minutes; `Hour` re-aggregates server-side via
/// `toStartOfHour(bucket_start)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketSize {
    FiveMin,
    Hour,
}

impl BucketSize {
    /// SQL expression that re-buckets the rollup's `bucket_start` to this size.
    pub fn group_expr(self) -> &'static str {
        match self {
            BucketSize::FiveMin => "bucket_start",
            BucketSize::Hour => "toStartOfHour(bucket_start)",
        }
    }
}
