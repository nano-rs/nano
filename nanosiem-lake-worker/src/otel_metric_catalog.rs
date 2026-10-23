// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-tenant metric-name catalog for the Metrics explorer (NAN-4098).
//!
//! The explorer's dropdown used to run `SELECT DISTINCT metric_name` over the
//! whole native metrics table with no time bound. On a heavy OTLP tenant (ops:
//! ~3.3M metric rows per hour) that read every retained hour partition and took
//! ~59 s, past the UI's 60 s client timeout.
//!
//! The catalog keeps `metric_name -> last_seen` in memory, per service filter,
//! inside the tenant-pinned `lake_otel_ingest` process:
//!
//! * a cold catalog answers from one bounded scan of the last
//!   [`COLD_LOOKBACK`] (hour partitions prune; ~1 s on ops);
//! * later requests reuse it for [`REFRESH_INTERVAL`] and then scan only the
//!   window since the previous scan (plus [`REFRESH_OVERLAP`] for late rows);
//! * a background backfill widens a cold catalog to [`CATALOG_RETENTION`] once;
//! * names not seen for [`CATALOG_RETENTION`] age out, and the catalog never
//!   holds more than [`MAX_CATALOG_NAMES`] names.
//!
//! The logic here is pure (no I/O) so the window arithmetic is unit tested; the
//! binary owns locking and query execution.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};

/// How long a name stays in the catalog after its last sample.
pub const CATALOG_RETENTION: Duration = Duration::hours(24);
/// Window a cold catalog scans before answering.
pub const COLD_LOOKBACK: Duration = Duration::hours(1);
/// A warm catalog is reused this long before an incremental scan.
pub const REFRESH_INTERVAL: Duration = Duration::seconds(60);
/// Incremental scans re-read this much before the last scan end (late rows).
pub const REFRESH_OVERLAP: Duration = Duration::minutes(5);
/// Upper bound on names held (and returned) per catalog.
pub const MAX_CATALOG_NAMES: usize = 10_000;
/// Upper bound on distinct service filters cached; others query uncached.
pub const MAX_CATALOG_KEYS: usize = 64;
/// Widest explicit window a direct (uncached) inventory query accepts.
pub const MAX_DIRECT_WINDOW: Duration = Duration::days(7);
/// After a failed backfill, wait this long before trying again.
pub const BACKFILL_RETRY: Duration = Duration::minutes(10);

/// A half-open scan window `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backfill {
    Pending,
    Running,
    Done,
    FailedAt(DateTime<Utc>),
}

/// One service filter's catalog.
#[derive(Debug, Clone)]
pub struct MetricNameCatalog {
    names: HashMap<String, DateTime<Utc>>,
    /// Earliest instant the catalog has scanned from.
    covered_from: Option<DateTime<Utc>>,
    /// End of the latest scan.
    covered_until: Option<DateTime<Utc>>,
    backfill: Backfill,
}

impl Default for MetricNameCatalog {
    fn default() -> Self {
        Self {
            names: HashMap::new(),
            covered_from: None,
            covered_until: None,
            backfill: Backfill::Pending,
        }
    }
}

impl MetricNameCatalog {
    /// The scan needed before answering at `now`, or `None` when the catalog
    /// is fresh enough to serve as is.
    pub fn refresh_window(&self, now: DateTime<Utc>) -> Option<ScanWindow> {
        match self.covered_until {
            None => Some(ScanWindow {
                start: now - COLD_LOOKBACK,
                end: now,
            }),
            Some(until) if now - until < REFRESH_INTERVAL => None,
            Some(until) => Some(ScanWindow {
                // Never re-read further back than the cold lookback, even after
                // a long idle gap: the backfill owns older history.
                start: (until - REFRESH_OVERLAP).max(now - COLD_LOOKBACK),
                end: now,
            }),
        }
    }

    /// Merge one scan's `(metric_name, last_seen)` rows, then age out and cap.
    pub fn apply_scan(
        &mut self,
        window: ScanWindow,
        rows: impl IntoIterator<Item = (String, DateTime<Utc>)>,
        now: DateTime<Utc>,
    ) {
        for (name, seen) in rows {
            if name.is_empty() {
                continue;
            }
            let entry = self.names.entry(name).or_insert(seen);
            if seen > *entry {
                *entry = seen;
            }
        }
        self.covered_from = Some(match self.covered_from {
            Some(from) => from.min(window.start),
            None => window.start,
        });
        // A backfill ends where coverage already began; only a live scan moves
        // the high-water mark forward.
        if self.covered_until.is_none_or(|until| window.end > until) {
            self.covered_until = Some(window.end);
        }
        self.prune(now);
    }

    fn prune(&mut self, now: DateTime<Utc>) {
        let horizon = now - CATALOG_RETENTION;
        self.names.retain(|_, seen| *seen >= horizon);
        if self.names.len() > MAX_CATALOG_NAMES {
            // Keep the most recently seen names.
            let mut by_recency: Vec<_> = self.names.drain().collect();
            by_recency.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            by_recency.truncate(MAX_CATALOG_NAMES);
            self.names = by_recency.into_iter().collect();
        }
    }

    /// Name-ordered names seen within the retention horizon.
    pub fn names(&self, now: DateTime<Utc>) -> Vec<String> {
        let horizon = now - CATALOG_RETENTION;
        let mut names: Vec<String> = self
            .names
            .iter()
            .filter(|(_, seen)| **seen >= horizon)
            .map(|(name, _)| name.clone())
            .collect();
        names.sort_unstable();
        names
    }

    /// Start of the window the returned names cover.
    pub fn window_start(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        let horizon = now - CATALOG_RETENTION;
        self.covered_from.map_or(now, |from| from.max(horizon))
    }

    /// True until the backfill has widened the catalog to the full retention.
    pub fn is_partial(&self) -> bool {
        self.backfill != Backfill::Done
    }

    /// Claim the backfill: returns its window and marks it running, or `None`
    /// when it is done, already running, recently failed, or not needed yet.
    pub fn claim_backfill(&mut self, now: DateTime<Utc>) -> Option<ScanWindow> {
        match self.backfill {
            Backfill::Done | Backfill::Running => return None,
            Backfill::FailedAt(at) if now - at < BACKFILL_RETRY => return None,
            Backfill::Pending | Backfill::FailedAt(_) => {}
        }
        let from = self.covered_from?;
        let start = now - CATALOG_RETENTION;
        if from <= start {
            self.backfill = Backfill::Done;
            return None;
        }
        self.backfill = Backfill::Running;
        Some(ScanWindow { start, end: from })
    }

    /// Record the backfill's outcome (apply its rows first on success).
    pub fn finish_backfill(&mut self, ok: bool, now: DateTime<Utc>) {
        self.backfill = if ok {
            Backfill::Done
        } else {
            Backfill::FailedAt(now)
        };
    }
}

/// Validate an explicit inventory window (`start < end`, at most
/// [`MAX_DIRECT_WINDOW`] wide).
pub fn validate_direct_window(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<(), String> {
    if start >= end {
        return Err("metric inventory window must have start < end".to_string());
    }
    if end - start > MAX_DIRECT_WINDOW {
        return Err("metric inventory window must be at most 7 days".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn cold_catalog_scans_only_the_cold_lookback() {
        let now = t("2026-10-18T23:00:00Z");
        let catalog = MetricNameCatalog::default();
        let window = catalog.refresh_window(now).unwrap();
        assert_eq!(window.end, now);
        assert_eq!(window.end - window.start, COLD_LOOKBACK);
        assert!(catalog.is_partial());
    }

    #[test]
    fn warm_catalog_is_reused_then_scanned_incrementally() {
        let now = t("2026-10-18T23:00:00Z");
        let mut catalog = MetricNameCatalog::default();
        let w = catalog.refresh_window(now).unwrap();
        catalog.apply_scan(w, [("a".to_string(), now)], now);

        // Within the refresh interval: served from memory.
        assert_eq!(catalog.refresh_window(now + Duration::seconds(30)), None);

        // After it: only the delta since the last scan, plus the overlap.
        let later = now + Duration::minutes(3);
        let delta = catalog.refresh_window(later).unwrap();
        assert_eq!(delta.start, now - REFRESH_OVERLAP);
        assert_eq!(delta.end, later);

        // After a long idle gap the scan is still capped at the cold lookback.
        let idle = now + Duration::hours(6);
        let capped = catalog.refresh_window(idle).unwrap();
        assert_eq!(capped.end - capped.start, COLD_LOOKBACK);
    }

    #[test]
    fn names_merge_age_out_and_sort() {
        let now = t("2026-10-18T23:00:00Z");
        let mut catalog = MetricNameCatalog::default();
        let w = ScanWindow {
            start: now - Duration::hours(1),
            end: now,
        };
        catalog.apply_scan(
            w,
            [
                ("zeta".to_string(), now - Duration::minutes(5)),
                ("alpha".to_string(), now - Duration::minutes(50)),
                (String::new(), now),
            ],
            now,
        );
        assert_eq!(catalog.names(now), vec!["alpha", "zeta"]);

        // "alpha" is not seen again; 24 h after its last sample it ages out.
        let later = now - Duration::minutes(50) + CATALOG_RETENTION + Duration::seconds(1);
        let w2 = ScanWindow {
            start: later - Duration::minutes(5),
            end: later,
        };
        catalog.apply_scan(w2, [("zeta".to_string(), later)], later);
        assert_eq!(catalog.names(later), vec!["zeta"]);
    }

    #[test]
    fn catalog_is_capped_keeping_the_most_recent_names() {
        let now = t("2026-10-18T23:00:00Z");
        let mut catalog = MetricNameCatalog::default();
        let rows = (0..MAX_CATALOG_NAMES + 5).map(|i| {
            (
                format!("m{i:05}"),
                now - Duration::seconds((MAX_CATALOG_NAMES + 5 - i) as i64),
            )
        });
        catalog.apply_scan(
            ScanWindow {
                start: now - COLD_LOOKBACK,
                end: now,
            },
            rows,
            now,
        );
        let names = catalog.names(now);
        assert_eq!(names.len(), MAX_CATALOG_NAMES);
        // The five oldest were dropped.
        assert!(!names.contains(&"m00000".to_string()));
        assert!(names.contains(&format!("m{:05}", MAX_CATALOG_NAMES + 4)));
    }

    #[test]
    fn backfill_widens_to_retention_once() {
        let now = t("2026-10-18T23:00:00Z");
        let mut catalog = MetricNameCatalog::default();
        // No coverage yet: nothing to backfill behind.
        assert_eq!(catalog.claim_backfill(now), None);

        let w = catalog.refresh_window(now).unwrap();
        catalog.apply_scan(w, [("live".to_string(), now)], now);
        let backfill = catalog.claim_backfill(now).unwrap();
        assert_eq!(backfill.start, now - CATALOG_RETENTION);
        assert_eq!(backfill.end, now - COLD_LOOKBACK);
        // Single flight: a second claim while running gets nothing.
        assert_eq!(catalog.claim_backfill(now), None);

        catalog.apply_scan(
            backfill,
            [("old".to_string(), now - Duration::hours(20))],
            now,
        );
        catalog.finish_backfill(true, now);
        assert!(!catalog.is_partial());
        assert_eq!(catalog.names(now), vec!["live", "old"]);
        assert_eq!(catalog.window_start(now), now - CATALOG_RETENTION);
        // The backfill did not move the live high-water mark backwards.
        assert_eq!(catalog.refresh_window(now + Duration::seconds(10)), None);
        assert_eq!(catalog.claim_backfill(now), None);
    }

    #[test]
    fn failed_backfill_retries_after_a_pause() {
        let now = t("2026-10-18T23:00:00Z");
        let mut catalog = MetricNameCatalog::default();
        let w = catalog.refresh_window(now).unwrap();
        catalog.apply_scan(w, [("live".to_string(), now)], now);
        assert!(catalog.claim_backfill(now).is_some());
        catalog.finish_backfill(false, now);
        assert_eq!(catalog.claim_backfill(now + Duration::minutes(1)), None);
        assert!(catalog
            .claim_backfill(now + BACKFILL_RETRY + Duration::seconds(1))
            .is_some());
    }

    #[test]
    fn direct_windows_are_bounded() {
        let end = t("2026-10-18T23:00:00Z");
        assert!(validate_direct_window(end - Duration::hours(24), end).is_ok());
        assert!(validate_direct_window(end, end).is_err());
        assert!(validate_direct_window(end - Duration::days(8), end).is_err());
    }
}
