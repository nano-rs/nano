// SPDX-License-Identifier: AGPL-3.0-or-later

//! Entity risk score over time (NAN-3225).
//!
//! Readers return findings pre-aggregated into ANCHOR-ALIGNED hour buckets
//! per rule: bucket `h` holds the fires with `timestamp ∈ [anchor-(h+1)h,
//! anchor-h·h)`. Because every decay band edge (24h, 72h, 120h, 168h) is a
//! whole number of hours, every finding in a bucket sits in the same band at
//! every hourly evaluation instant `anchor - j·h`. The series computed here is
//! therefore EXACT — the same decay step function and banker's rounding as the
//! headline `decayed_score_7d` — not an approximation, and the `j = 0` point
//! equals the sum of the per-rule contributions at the anchor.
//!
//! Source visibility is applied by the readers (the same deny predicate as
//! every other risk read); this module only folds what they return.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::types::{EntityRuleContribution, RiskDecayConfig};

/// One evaluation step (hour), in seconds.
pub const TIMELINE_STEP_SECONDS: i64 = 3_600;
/// Displayed window: 7 days of hourly points.
pub const TIMELINE_WINDOW_HOURS: u32 = 168;
/// Buckets the readers must return: the window plus one full 7d decay horizon
/// before its first point.
pub const TIMELINE_LOOKBACK_HOURS: u32 = 2 * TIMELINE_WINDOW_HOURS;
/// [`TIMELINE_LOOKBACK_HOURS`] in days (lake `lookback_days`).
pub const TIMELINE_LOOKBACK_DAYS: i64 = 14;
/// Bucket-row cap shared by every reader. Rows are ordered newest bucket
/// first, so a capped read drops the OLDEST buckets.
pub const TIMELINE_MAX_BUCKET_ROWS: usize = 10_000;
/// How far back a caller may anchor the series (e.g. an old notable). The lake
/// reader bounds lookbacks at 28 days.
pub const TIMELINE_MAX_ANCHOR_AGE_DAYS: i64 = 14;
/// Same cap as the contributions reader (`LIMIT 50`).
const MAX_CONTRIBUTIONS: usize = 50;

/// One `(hour bucket, rule)` aggregate from a reader.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskTimelineBucket {
    /// 0 = `[anchor-1h, anchor)`.
    pub hours_ago: u32,
    pub rule_id: String,
    pub rule_name: String,
    /// Severity of the bucket's latest fire.
    pub severity: String,
    pub fires: u64,
    /// Undecayed per-fire score sum.
    pub score_sum: i64,
    pub last_fire_us: i64,
    pub last_fire_score: i32,
    /// Tactics stamped on the bucket's findings (fire-time view).
    #[serde(default)]
    pub mitre_tactics: Vec<String>,
}

/// One hourly point of the decayed 7d score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EntityRiskTimelinePoint {
    pub t: DateTime<Utc>,
    pub score: i64,
}

/// One rule's fires inside one hour bucket of the displayed window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EntityRiskTimelineMarker {
    /// Bucket start.
    pub t: DateTime<Utc>,
    pub last_fire_at: DateTime<Utc>,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub fires: i64,
    /// Undecayed per-fire score sum inside the bucket.
    pub score: i64,
    pub mitre_tactics: Vec<String>,
}

/// The folded series.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EntityRiskTimeline {
    pub anchor: DateTime<Utc>,
    pub step_seconds: i64,
    pub window_hours: u32,
    /// `window_hours + 1` points, oldest first; the last is `anchor`.
    pub points: Vec<EntityRiskTimelinePoint>,
    /// Oldest first.
    pub markers: Vec<EntityRiskTimelineMarker>,
    /// Per-rule contributions AT `anchor`, heaviest first (same semantics as
    /// the context endpoint's `rule_contributions`).
    pub contributions: Vec<EntityRuleContribution>,
    /// The reader hit [`TIMELINE_MAX_BUCKET_ROWS`]; the oldest buckets are missing.
    pub truncated: bool,
    /// Watchlist weight applied to `points`: each point is the
    /// effective score `base x (1 + watch_weight)`. `contributions` stay the
    /// unweighted per-rule shares, so they sum to the base score. Only for
    /// callers holding `risk:watchlists`: for everyone else this is
    /// omitted and `contributions` are scaled to the effective score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watch_weight: Option<f64>,
}

impl EntityRiskTimeline {
    /// The shape for a reader that has nothing to say (pending / failed).
    pub fn empty(anchor: DateTime<Utc>) -> Self {
        Self {
            anchor,
            step_seconds: TIMELINE_STEP_SECONDS,
            window_hours: TIMELINE_WINDOW_HOURS,
            points: Vec::new(),
            markers: Vec::new(),
            contributions: Vec::new(),
            truncated: false,
            watch_weight: None,
        }
    }

    /// Amplify the series by the entity's watchlist weight (NAN-3228), the
    /// same `round_half_even(base x (1 + w))` every other score read applies.
    /// The weight is the CURRENT one (applied retroactively to the window,
    /// like the headline score), not a history of membership changes.
    pub fn apply_watch_weight(&mut self, weight: f64) {
        if !weight.is_finite() || weight <= 0.0 {
            return;
        }
        for point in &mut self.points {
            point.score = super::watchlist::effective_score(point.score, weight);
        }
        self.watch_weight = Some(weight);
    }

    /// For a caller without `risk:watchlists` (NAN-3232): keep the effective
    /// points, drop `watch_weight`, and scale `contributions` to the effective
    /// scale so they do not reveal the base score.
    pub fn hide_watch(&mut self) {
        let weight = self.watch_weight.take();
        super::watchlist::scale_contributions_to_effective(&mut self.contributions, weight);
    }
}

/// Decay weight of a finding `age_hours` old (whole hours since its bucket
/// end; `0` = the newest hour). Mirrors the readers' `multiIf`.
pub fn decay_factor(age_hours: u32, decay: &RiskDecayConfig) -> f64 {
    match age_hours {
        0..=23 => decay.decay_0_24h,
        24..=71 => decay.decay_1_3d,
        72..=119 => decay.decay_3_5d,
        120..=167 => decay.decay_5_7d,
        _ => 0.0,
    }
}

/// ClickHouse `round()` on Float64 is round-half-to-even.
fn round_score(value: f64) -> i64 {
    value.round_ties_even() as i64
}

/// Clamp a caller-supplied anchor into `[now - MAX_ANCHOR_AGE, now]`.
pub fn clamp_anchor(requested: Option<DateTime<Utc>>, now: DateTime<Utc>) -> DateTime<Utc> {
    let floor = now - Duration::days(TIMELINE_MAX_ANCHOR_AGE_DAYS);
    requested.map_or(now, |at| at.clamp(floor, now))
}

/// Fold reader buckets into the hourly series, the window's markers and the
/// per-rule contributions at `anchor`.
pub fn build_timeline(
    anchor: DateTime<Utc>,
    decay: &RiskDecayConfig,
    buckets: &[RiskTimelineBucket],
    truncated: bool,
) -> EntityRiskTimeline {
    let window = TIMELINE_WINDOW_HOURS;
    let hour = Duration::seconds(TIMELINE_STEP_SECONDS);
    let at_us = |us: i64| DateTime::from_timestamp_micros(us).unwrap_or(anchor);

    let points = (0..=window)
        .rev()
        .map(|j| {
            let sum: f64 = buckets
                .iter()
                .filter(|b| b.hours_ago >= j && b.hours_ago - j < window)
                .map(|b| b.score_sum as f64 * decay_factor(b.hours_ago - j, decay))
                .sum();
            EntityRiskTimelinePoint {
                t: anchor - hour * j as i32,
                score: round_score(sum),
            }
        })
        .collect();

    let mut markers: Vec<EntityRiskTimelineMarker> = buckets
        .iter()
        .filter(|b| b.hours_ago < window)
        .map(|b| EntityRiskTimelineMarker {
            t: anchor - hour * (b.hours_ago as i32 + 1),
            last_fire_at: at_us(b.last_fire_us),
            rule_id: b.rule_id.clone(),
            rule_name: b.rule_name.clone(),
            severity: b.severity.clone(),
            fires: b.fires.min(i64::MAX as u64) as i64,
            score: b.score_sum,
            mitre_tactics: b.mitre_tactics.clone(),
        })
        .collect();
    markers.sort_by(|a, b| a.t.cmp(&b.t).then_with(|| a.rule_id.cmp(&b.rule_id)));

    struct Acc<'a> {
        latest: &'a RiskTimelineBucket,
        fires_24h: u64,
        fires_7d: u64,
        decayed_24h: f64,
        decayed_7d: f64,
    }
    let mut by_rule: BTreeMap<&str, Acc> = BTreeMap::new();
    for b in buckets.iter().filter(|b| b.hours_ago < window) {
        let weighted = b.score_sum as f64 * decay_factor(b.hours_ago, decay);
        let acc = by_rule.entry(b.rule_id.as_str()).or_insert(Acc {
            latest: b,
            fires_24h: 0,
            fires_7d: 0,
            decayed_24h: 0.0,
            decayed_7d: 0.0,
        });
        if b.last_fire_us > acc.latest.last_fire_us {
            acc.latest = b;
        }
        acc.fires_7d += b.fires;
        acc.decayed_7d += weighted;
        if b.hours_ago < 24 {
            acc.fires_24h += b.fires;
            acc.decayed_24h += weighted;
        }
    }
    let mut contributions: Vec<EntityRuleContribution> = by_rule
        .into_iter()
        .map(|(rule_id, acc)| EntityRuleContribution {
            rule_id: rule_id.to_string(),
            rule_name: acc.latest.rule_name.clone(),
            severity: acc.latest.severity.clone(),
            fires_24h: acc.fires_24h.min(i64::MAX as u64) as i64,
            fires_7d: acc.fires_7d.min(i64::MAX as u64) as i64,
            decayed_contribution_24h: round_score(acc.decayed_24h),
            decayed_contribution_7d: round_score(acc.decayed_7d),
            last_fire_at: at_us(acc.latest.last_fire_us),
            last_fire_score: acc.latest.last_fire_score,
            mitre_tactics: Vec::new(),
            mitre_techniques: Vec::new(),
        })
        .collect();
    contributions.sort_by(|a, b| {
        b.decayed_contribution_7d
            .cmp(&a.decayed_contribution_7d)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    contributions.truncate(MAX_CONTRIBUTIONS);

    EntityRiskTimeline {
        anchor,
        step_seconds: TIMELINE_STEP_SECONDS,
        window_hours: window,
        points,
        markers,
        contributions,
        truncated,
        watch_weight: None,
    }
}

/// Copy rule MITRE metadata onto contributions by rule id (NAN-3225).
/// Contributions are already source-scoped; this only decorates the rules
/// they name, so it cannot surface a hidden rule.
pub fn attach_rule_mitre(
    contributions: &mut [EntityRuleContribution],
    mitre: &std::collections::HashMap<String, (Vec<String>, Vec<String>)>,
) {
    for contribution in contributions {
        if let Some((tactics, techniques)) = mitre.get(&contribution.rule_id) {
            contribution.mitre_tactics = tactics.clone();
            contribution.mitre_techniques = techniques.clone();
        }
    }
}

/// The distinct, parseable rule UUIDs among `contributions` (ad-hoc findings
/// carry an empty or non-UUID rule id and get no MITRE).
pub fn contribution_rule_ids(contributions: &[EntityRuleContribution]) -> Vec<uuid::Uuid> {
    let mut ids: Vec<uuid::Uuid> = contributions
        .iter()
        .filter_map(|c| uuid::Uuid::parse_str(&c.rule_id).ok())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

#[cfg(test)]
#[path = "timeline_tests.rs"]
mod timeline_tests;
