// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5976: ClickHouse errors the upgrade's own rollout caused.
//!
//! `scripts/nano upgrade` restarts ClickHouse and the app services. A
//! dictionary reload or an insert flush during that restart can hit the memory
//! limit once (`MEMORY_LIMIT_EXCEEDED`). The upgrade's SIEM Health gate
//! (NAN-5528 / NAN-5958) already calls such an error an "upgrade rollout
//! transient", but SIEM Health reads `system.errors` over 24 hours, so it kept
//! counting it: the score dropped and the report showed CRITICAL for a day
//! after a clean upgrade.
//!
//! The upgrade now records its rollout windows and its pre-upgrade error
//! baseline in `upgrade_rollout_windows` (migration 405). This module applies
//! the gate's own rule to them and is fail-closed by construction: a health
//! check that hides a real error is worse than a false CRITICAL, so anything
//! unknown excuses nothing. An error counter is set aside only when ALL hold:
//!
//! * recorded windows were read, and the runs they belong to are not frozen;
//! * every ClickHouse node reporting the counter has a known
//!   `last_error_time` inside a window shrunk by [`WINDOW_MARGIN_SECS`] at both
//!   ends, and the per-node values add up to the scored count;
//! * that window has a baseline showing no occurrence in the 24 hours before
//!   the upgrade;
//! * every such node returned `system.dictionaries` rows, none unhealthy, and
//!   no logs-table dictionary is failing.
//!
//! Clocks: the upgrade stores the window bounds on ClickHouse's clock (it
//! converts its own times with ClickHouse's `now()`), and SIEM Health compares
//! them with each node's own `last_error_time`, read in the same query as the
//! counter. No app-host, coordinator or PostgreSQL clock enters it.
//!
//! Freezing: once a report scores one of these counters while windows are
//! recorded, [`freeze_runs_if_an_error_is_scored`] stamps those runs
//! (`error_scored_at`). The upgrade never adds to or replaces a stamped run's
//! windows, and windows recorded after the stamp are ignored here.

use chrono::{DateTime, Duration, TimeZone, Utc};
use serde::Deserialize;
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::warn;

use super::types::{InsertIntegrityMetrics, UpgradeTransientError};

/// Windows that ended longer ago than this cannot hold an error the 24 h
/// `system.errors` probe still sees.
const LOOKBACK_HOURS: i64 = 25;

/// Each recorded window is shrunk by this much at both ends before an error is
/// matched against it, so the seconds between the upgrade reading ClickHouse's
/// clock and its own, and any skew between ClickHouse nodes, can only ever make
/// SIEM Health count more, never excuse more.
pub const WINDOW_MARGIN_SECS: i64 = 30;

/// One recorded rollout window of one upgrade run, on ClickHouse's clock.
#[derive(Debug, Clone)]
pub struct UpgradeRolloutWindow {
    pub run_id: String,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    /// `system.errors` before the upgrade, as the upgrade gate captured it.
    pub baseline: Option<ErrorBaseline>,
}

/// The usable recorded windows (frozen runs' later windows already dropped).
#[derive(Debug, Clone, Default)]
pub struct RecordedWindows {
    pub windows: Vec<UpgradeRolloutWindow>,
}

/// The gate's pre-upgrade `system.errors` snapshot (`clickhouse_errors_before`).
#[derive(Debug, Clone, Deserialize)]
pub struct ErrorBaseline {
    pub captured_at: DateTime<Utc>,
    #[serde(default)]
    pub errors: HashMap<String, BaselineError>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BaselineError {
    #[serde(default)]
    pub last_at: Option<DateTime<Utc>>,
}

impl ErrorBaseline {
    /// True when `name` occurred in the 24 hours before the baseline was taken
    /// (it was already happening), or when that cannot be told.
    fn was_active_or_unknown(&self, name: &str) -> bool {
        match self.errors.get(name) {
            None => false,
            Some(entry) => match entry.last_at {
                Some(last) => self.captured_at - last <= Duration::hours(24),
                // An entry with no time: unknown, so treat it as active.
                None => true,
            },
        }
    }
}

/// The recorded window that excuses an error counter whose last occurrence on
/// one node was `last_at` (ClickHouse clock), if any. `None` means it counts.
pub fn excusing_window<'a>(
    name: &str,
    last_at: DateTime<Utc>,
    windows: &'a [UpgradeRolloutWindow],
) -> Option<&'a UpgradeRolloutWindow> {
    let margin = Duration::seconds(WINDOW_MARGIN_SECS);
    windows.iter().find(|w| {
        w.starts_at + margin <= last_at
            && last_at <= w.ends_at - margin
            && w.baseline.as_ref().is_some_and(|b| !b.was_active_or_unknown(name))
    })
}

/// Move upgrade-transient error counters out of the scored fields (see the
/// module docs for the rule). One unknown or one node outside every window
/// keeps the whole counter scored.
pub fn set_aside_upgrade_transients(ii: &mut InsertIntegrityMetrics, recorded: &RecordedWindows) {
    if recorded.windows.is_empty() || !ii.failed_logs_dictionaries.is_empty() {
        return;
    }
    let Some(dictionaries) = ii.dictionary_check.as_ref() else {
        return;
    };
    if dictionaries.unhealthy != 0 {
        return;
    }
    let checked_hosts = dictionaries.hosts.clone();
    for name in ["MEMORY_LIMIT_EXCEEDED", "CACHE_DICTIONARY_UPDATE_FAIL"] {
        let count = match name {
            "MEMORY_LIMIT_EXCEEDED" => ii.memory_limit_errors,
            _ => ii.cache_dictionary_update_fails,
        };
        if count == 0 {
            continue;
        }
        let samples: Vec<_> = ii
            .error_counter_samples
            .iter()
            .filter(|s| s.name == name)
            .collect();
        // Every node's value must be judged: no unaccounted remainder.
        if samples.is_empty() || samples.iter().map(|s| s.value).sum::<u64>() != count {
            continue;
        }
        let mut latest: Option<(DateTime<Utc>, &UpgradeRolloutWindow)> = None;
        let mut all_excused = true;
        for sample in &samples {
            let last_at = (sample.last_error_unix > 0)
                .then(|| i64::try_from(sample.last_error_unix).ok())
                .flatten()
                .and_then(|secs| Utc.timestamp_opt(secs, 0).single());
            let window = match last_at {
                Some(at) if checked_hosts.contains(&sample.host) => {
                    excusing_window(name, at, &recorded.windows).map(|w| (at, w))
                }
                // Unknown time, or a node whose dictionaries were not visible.
                _ => None,
            };
            match window {
                Some((at, w)) => {
                    if latest.is_none_or(|(prev, _)| at > prev) {
                        latest = Some((at, w));
                    }
                }
                None => {
                    all_excused = false;
                    break;
                }
            }
        }
        let Some((last_at, window)) = latest.filter(|_| all_excused) else {
            continue;
        };
        ii.upgrade_transient_errors.push(UpgradeTransientError {
            name: name.to_string(),
            count,
            last_at,
            upgrade_run_id: window.run_id.clone(),
        });
        match name {
            "MEMORY_LIMIT_EXCEEDED" => ii.memory_limit_errors = 0,
            _ => ii.cache_dictionary_update_fails = 0,
        }
    }
}

/// The runs to freeze: every recorded run, when the report still scores one of
/// the two error counters after [`set_aside_upgrade_transients`].
pub fn runs_to_freeze(ii: &InsertIntegrityMetrics, recorded: &RecordedWindows) -> Vec<String> {
    if ii.memory_limit_errors == 0 && ii.cache_dictionary_update_fails == 0 {
        return Vec::new();
    }
    let mut runs: Vec<String> = recorded.windows.iter().map(|w| w.run_id.clone()).collect();
    runs.sort();
    runs.dedup();
    runs
}

/// Stamp `error_scored_at` on the recorded runs when this report scores an
/// error counter, so no window the upgrade adds later can excuse it.
pub async fn freeze_runs_if_an_error_is_scored(
    pool: &PgPool,
    ii: &InsertIntegrityMetrics,
    recorded: &RecordedWindows,
) {
    let runs = runs_to_freeze(ii, recorded);
    if runs.is_empty() {
        return;
    }
    if let Err(e) = sqlx::query(
        "UPDATE upgrade_rollout_windows SET error_scored_at = now() \
         WHERE run_id = ANY($1) AND error_scored_at IS NULL",
    )
    .bind(&runs)
    .execute(pool)
    .await
    {
        warn!(?runs, "SIEM Health: could not freeze upgrade rollout windows: {e}");
    }
}

/// Recent usable windows. Best effort: a missing table (a database the
/// migration has not reached) or a read error yields none, so every error
/// counts exactly as it did before NAN-5976. A window recorded after its run
/// was frozen is never returned.
pub async fn load_recent(pool: &PgPool) -> RecordedWindows {
    let rows = sqlx::query_as::<_, (String, DateTime<Utc>, DateTime<Utc>, Option<serde_json::Value>)>(
        "SELECT w.run_id, w.starts_at, w.ends_at, w.clickhouse_errors_before \
         FROM upgrade_rollout_windows w \
         WHERE w.ends_at >= now() - make_interval(hours => $1::int) \
           AND NOT EXISTS ( \
             SELECT 1 FROM upgrade_rollout_windows f \
             WHERE f.run_id = w.run_id AND f.error_scored_at IS NOT NULL \
               AND f.error_scored_at <= w.recorded_at) \
         ORDER BY w.starts_at",
    )
    .bind(LOOKBACK_HOURS as i32)
    .fetch_all(pool)
    .await;
    match rows {
        Ok(rows) => RecordedWindows {
            windows: rows
                .into_iter()
                .map(|(run_id, starts_at, ends_at, baseline)| UpgradeRolloutWindow {
                    baseline: baseline.and_then(|value| parse_baseline(&run_id, value)),
                    run_id,
                    starts_at,
                    ends_at,
                })
                .collect(),
        },
        Err(e) => {
            warn!("SIEM Health: upgrade rollout windows unavailable, counting every ClickHouse error: {e}");
            RecordedWindows::default()
        }
    }
}

fn parse_baseline(run_id: &str, value: serde_json::Value) -> Option<ErrorBaseline> {
    match serde_json::from_value::<ErrorBaseline>(value) {
        Ok(baseline) => Some(baseline),
        Err(e) => {
            // A window without a usable baseline never excuses anything.
            warn!(run_id, "SIEM Health: upgrade error baseline is invalid: {e}");
            None
        }
    }
}

#[cfg(test)]
#[path = "upgrade_transients_tests.rs"]
mod tests;
