// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5345: prevalence `*_final_refresh` cadence from the planned-volume tier.
//!
//! The three `*_prevalence_final_refresh` refreshable views (ClickHouse 160)
//! run `REFRESH EVERY 10 MINUTE APPEND` on every node and re-finalize every
//! entity seen in the last 40 minutes. At volume each run scans a large recent
//! working set; a 20 TB/day reference freed 8-12 cores per node by cutting
//! refresh work. The installer's sizing emits `NANO_PREVALENCE_REFRESH_MINUTES`
//! for a declared planned volume (10 below ~1 TB/day, 30 at ~1 TB/day, 60 at
//! >=10 TB/day); Helm sets it from `migrations.prevalenceRefreshMinutes`.
//!
//! Unset means the shipped default, 10 minutes. Every step is read back from
//! the live catalog and idempotent, so an install that never had a planned
//! volume (views already at 10 / 40) gets no ALTER at all, while one that
//! drops back from a large tier (volume cleared, a smaller preset) is reset
//! to 10 / 40 instead of keeping 30 or 60.
//!
//! Two coupled edits per view:
//!
//! * the recency window (`last_seen >= now64(6) - INTERVAL n MINUTE`) becomes
//!   `cadence + 30` minutes (the shipped 10 / 40 pair), so no entity active
//!   between two refreshes is skipped. `MODIFY QUERY` keeps the rest of the
//!   body verbatim, including the distributed repoint and result-cap settings
//!   applied just before this step;
//! * `MODIFY REFRESH EVERY <cadence> MINUTE APPEND` (ClickHouse refuses a
//!   MODIFY REFRESH that drops APPEND on an APPEND view).
//!
//! The cadence only moves together with a window this step recognised: a
//! body whose window cannot be found is left entirely alone (and logged), so
//! the cadence can never outgrow the window.

use regex::Regex;
use std::sync::LazyLock;

use super::{ClickHouseMigrateError, ClickHouseMigrator};

/// The refreshable views this step reschedules.
pub(super) const PREVALENCE_FINAL_REFRESH_MVS: [&str; 3] = [
    "hash_prevalence_final_refresh",
    "domain_prevalence_final_refresh",
    "ip_prevalence_final_refresh",
];

/// Minutes the recency window exceeds the cadence (the shipped 10 -> 40).
pub(super) const WINDOW_MARGIN_MINUTES: u32 = 30;
/// The shipped cadence (ClickHouse 160), applied when no tier sets one.
pub const DEFAULT_CADENCE_MINUTES: u32 = 10;
/// Accepted cadence range. Below 10 is never an improvement on the shipped
/// default; above a day the rare / new lists would lag a working day.
pub(super) const MIN_CADENCE_MINUTES: u32 = 10;
pub(super) const MAX_CADENCE_MINUTES: u32 = 1440;

/// `NANO_PREVALENCE_REFRESH_MINUTES`: the cadence to converge on. Unset or
/// empty is the shipped 10 minutes (a no-op on views already there); anything
/// outside 10..=1440 is an error.
pub fn prevalence_refresh_minutes_from_env(
    value: Option<&str>,
) -> Result<u32, ClickHouseMigrateError> {
    let Some(raw) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(DEFAULT_CADENCE_MINUTES);
    };
    match raw.parse::<u32>() {
        Ok(m) if (MIN_CADENCE_MINUTES..=MAX_CADENCE_MINUTES).contains(&m) => Ok(m),
        _ => Err(ClickHouseMigrateError::ClickHouse(format!(
            "NANO_PREVALENCE_REFRESH_MINUTES must be a whole number of minutes from \
             {MIN_CADENCE_MINUTES} to {MAX_CADENCE_MINUTES} (got '{raw}')"
        ))),
    }
}

static WINDOW_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"now64\(6\) - toIntervalMinute\((\d+)\)").expect("static regex"));
static REFRESH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"REFRESH EVERY (\d+) (SECOND|MINUTE|HOUR|DAY|WEEK)").expect("static regex")
});

/// What the recency window of a view body needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WindowRewrite {
    /// The window is already the wanted length.
    AlreadySet,
    /// The body with the window set to the wanted length.
    Rewrite(String),
    /// No recognisable window: never guess at a foreign body.
    Unrecognized,
}

/// Set the body's recency window to `window` minutes.
pub(super) fn retime_recency_window(body: &str, window: u32) -> WindowRewrite {
    let current: Vec<u32> = WINDOW_RE
        .captures_iter(body)
        .filter_map(|c| c[1].parse().ok())
        .collect();
    if current.is_empty() {
        return WindowRewrite::Unrecognized;
    }
    if current.iter().all(|&m| m == window) {
        return WindowRewrite::AlreadySet;
    }
    let replacement = format!("now64(6) - toIntervalMinute({window})");
    WindowRewrite::Rewrite(WINDOW_RE.replace_all(body, replacement.as_str()).into_owned())
}

/// The `REFRESH EVERY n <unit>` cadence in a view's `create_table_query`, in
/// minutes. ClickHouse normalizes the unit (`EVERY 60 MINUTE` reads back as
/// `EVERY 1 HOUR`), so every unit is understood; `None` for sub-minute or
/// unparsable schedules.
pub(super) fn current_cadence_minutes(create_table_query: &str) -> Option<u32> {
    let caps = REFRESH_RE.captures(create_table_query)?;
    let n: u32 = caps[1].parse().ok()?;
    let per = match &caps[2] {
        "MINUTE" => 1,
        "HOUR" => 60,
        "DAY" => 1440,
        "WEEK" => 10080,
        _ => return (n % 60 == 0).then_some(n / 60),
    };
    n.checked_mul(per)
}

/// The ALTERs one view needs to reach `minutes`, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CadencePlan {
    /// Window and cadence already match.
    InPlace,
    /// `MODIFY QUERY` with this body (when `Some`) and `MODIFY REFRESH` (when
    /// `refresh`). Ordered so the window always covers the cadence: widening
    /// changes the window first; narrowing (`refresh_first`) shortens the
    /// cadence first and keeps the wide window if that fails.
    Alter { query: Option<String>, refresh: bool, refresh_first: bool },
    /// The window is not recognisable: change nothing on this view.
    Skip,
}

/// Pure planning for one view, from its live `as_select` and
/// `create_table_query`.
pub(super) fn plan_view(body: &str, create_table_query: &str, minutes: u32) -> CadencePlan {
    let body = body.trim().trim_end_matches(';');
    let query = match retime_recency_window(body, minutes + WINDOW_MARGIN_MINUTES) {
        WindowRewrite::Unrecognized => return CadencePlan::Skip,
        WindowRewrite::AlreadySet => None,
        WindowRewrite::Rewrite(new_body) => Some(new_body),
    };
    let current = current_cadence_minutes(create_table_query);
    let refresh = current != Some(minutes);
    if query.is_none() && !refresh {
        CadencePlan::InPlace
    } else {
        let refresh_first = refresh && current.is_some_and(|c| c > minutes);
        CadencePlan::Alter { query, refresh, refresh_first }
    }
}

impl ClickHouseMigrator {
    /// Converge the prevalence refresh views on `minutes` (the shipped 10 when
    /// no tier sets one). Runs after `repoint_dict_refresh_mvs_distributed`.
    /// Non-fatal per view, like the sibling reconcile steps. Returns the
    /// number of ALTERs issued (0 on views already in place).
    pub async fn apply_prevalence_refresh_cadence(
        &mut self,
        minutes: u32,
    ) -> Result<usize, ClickHouseMigrateError> {
        if !(MIN_CADENCE_MINUTES..=MAX_CADENCE_MINUTES).contains(&minutes) {
            return Err(ClickHouseMigrateError::ClickHouse(format!(
                "prevalence refresh cadence {minutes} min is outside \
                 {MIN_CADENCE_MINUTES}..={MAX_CADENCE_MINUTES}"
            )));
        }
        let window = minutes + WINDOW_MARGIN_MINUTES;
        let mut on_cluster: Option<String> = None;
        let mut altered = 0;
        for mv in PREVALENCE_FINAL_REFRESH_MVS {
            let row: Option<(String, String)> = self
                .client
                .query(&format!(
                    "SELECT as_select, create_table_query FROM system.tables \
                     WHERE database = '{}' AND name = '{}'",
                    self.database, mv
                ))
                .fetch_all::<(String, String)>()
                .await
                .map_err(|e| ClickHouseMigrateError::ClickHouse(e.to_string()))?
                .into_iter()
                .next();
            let Some((body, create)) = row else {
                tracing::debug!("prevalence refresh view {}.{} not present", self.database, mv);
                continue;
            };
            let (query, refresh, refresh_first) = match plan_view(&body, &create, minutes) {
                CadencePlan::InPlace => continue,
                CadencePlan::Skip => {
                    tracing::warn!(
                        "NAN-5345: {}.{} has no recognisable recency window; its refresh \
                         cadence is left unchanged (wanted every {} min)",
                        self.database, mv, minutes
                    );
                    continue;
                }
                CadencePlan::Alter { query, refresh, refresh_first } => (query, refresh, refresh_first),
            };
            if on_cluster.is_none() {
                on_cluster = Some(match self.detect_cluster().await? {
                    Some(name) if name != self.database => format!(" ON CLUSTER '{name}'"),
                    _ => String::new(),
                });
            }
            let on_cluster = on_cluster.clone().unwrap_or_default();
            let refresh_sql = refresh.then(|| {
                format!(
                    "ALTER TABLE {}.{}{} MODIFY REFRESH EVERY {} MINUTE APPEND",
                    self.database, mv, on_cluster, minutes
                )
            });
            let query_sql = query.map(|new_body| {
                format!("ALTER TABLE {}.{}{} MODIFY QUERY {}", self.database, mv, on_cluster, new_body)
            });
            let (first, second) = if refresh_first {
                (refresh_sql, query_sql)
            } else {
                (query_sql, refresh_sql)
            };
            // The second ALTER runs only after the first succeeded, so a
            // failure never leaves a cadence longer than its window.
            for sql in [first, second].into_iter().flatten() {
                if let Err(e) = self.client.query(&sql).execute().await {
                    tracing::warn!(
                        "NAN-5345: could not move {}.{} to every {} min over a {} min window: {}",
                        self.database, mv, minutes, window, e
                    );
                    break;
                }
                altered += 1;
            }
        }
        if altered > 0 {
            tracing::info!(
                "NAN-5345: prevalence refresh views now run every {} min over a {} min window",
                minutes,
                window
            );
        }
        Ok(altered)
    }
}
